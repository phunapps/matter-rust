//! matter.js byte-parity tests for the `im` module.
//!
//! Fixtures live under `test-vectors/commissioning/im/<kind>/*.json`.
//! Each fixture provides the inputs and the matter.js-captured expected
//! IM message bytes (base64). Tests SKIP (not fail) when fixtures are
//! absent, matching the established M6.x pattern — fixtures are captured
//! by `cargo xtask capture-im` (xtask/scripts/capture-im).

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::doc_markdown
)] // Test-code carve-out: see CLAUDE.md.
#![allow(unreachable_pub)]

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
// Deep submodule paths used intentionally to confirm the submodules are directly accessible (flat re-exports also exist at the crate root).
use matter_interaction::invoke::build_invoke_request;
use matter_interaction::path::AttributePath;
use matter_interaction::read::build_read_request;
use matter_interaction::CommandPath;
use serde::Deserialize;
use std::{fs, path::PathBuf};

fn fixtures_root() -> PathBuf {
    let mut p: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    p.push("..");
    p.push("..");
    p.push("test-vectors");
    p.push("commissioning");
    p.push("im");
    p
}

fn list_jsons(sub: &str) -> Vec<PathBuf> {
    let dir = fixtures_root().join(sub);
    if !dir.exists() {
        return Vec::new();
    }
    let mut out: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    out.sort();
    out
}

#[derive(Deserialize)]
struct InvokeFixture {
    endpoint: u16,
    cluster: u32,
    command: u32,
    command_fields_b64: String,
    expected_message_b64: String,
}

#[derive(Deserialize)]
struct ReadFixture {
    paths: Vec<ReadPathFixture>,
    expected_message_b64: String,
}

#[derive(Deserialize)]
struct ReadPathFixture {
    endpoint: u16,
    cluster: u32,
    attribute: u32,
}

#[test]
fn invoke_request_matches_matter_js() {
    let paths = list_jsons("invoke");
    if paths.is_empty() {
        eprintln!("skipping: no invoke fixtures (run `cargo xtask capture-im`)");
        return;
    }
    for path in paths {
        let bytes = fs::read(&path).unwrap();
        let f: InvokeFixture = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("{path:?}: not an invoke fixture — skipping");
                continue;
            }
        };
        let fields = B64.decode(&f.command_fields_b64).unwrap();
        let ours = build_invoke_request(
            CommandPath {
                endpoint: f.endpoint,
                cluster: f.cluster,
                command: f.command,
            },
            &fields,
        );
        let theirs = B64.decode(&f.expected_message_b64).unwrap();
        assert_eq!(ours, theirs, "InvokeRequest mismatch for {path:?}");
    }
}

#[test]
fn read_request_matches_matter_js() {
    let paths = list_jsons("read");
    if paths.is_empty() {
        eprintln!("skipping: no read fixtures (run `cargo xtask capture-im`)");
        return;
    }
    for path in paths {
        let bytes = fs::read(&path).unwrap();
        let f: ReadFixture = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("{path:?}: not a read fixture — skipping");
                continue;
            }
        };
        let our_paths: Vec<AttributePath> = f
            .paths
            .iter()
            .map(|p| AttributePath {
                endpoint: p.endpoint,
                cluster: p.cluster,
                attribute: p.attribute,
            })
            .collect();
        let ours = build_read_request(&our_paths);
        let theirs = B64.decode(&f.expected_message_b64).unwrap();
        assert_eq!(ours, theirs, "ReadRequest mismatch for {path:?}");
    }
}

#[derive(Deserialize)]
struct WriteFixture {
    writes: Vec<WriteEntryFixture>,
    expected_message_b64: String,
}

#[derive(Deserialize)]
struct WriteEntryFixture {
    endpoint: u16,
    cluster: u32,
    attribute: u32,
    value_tlv_b64: String,
}

#[derive(Deserialize)]
struct WriteResponseFixture {
    response_message_b64: String,
    expected: Vec<WriteStatusFixture>,
}

#[derive(Deserialize)]
struct WriteStatusFixture {
    endpoint: u16,
    cluster: u32,
    attribute: u32,
    status: u8,
}

#[test]
fn write_request_matches_matter_js() {
    use matter_interaction::write::{build_write_request, AttributeWriteRequest};

    let paths = list_jsons("write");
    if paths.is_empty() {
        eprintln!("skipping: no write fixtures (run `cargo xtask capture-im`)");
        return;
    }
    let mut asserted = 0;
    for path in paths {
        let bytes = fs::read(&path).unwrap();
        let f: WriteFixture = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => continue, // response fixtures live in the same dir
        };
        let writes: Vec<AttributeWriteRequest> = f
            .writes
            .iter()
            .map(|w| AttributeWriteRequest {
                path: AttributePath {
                    endpoint: w.endpoint,
                    cluster: w.cluster,
                    attribute: w.attribute,
                },
                value_tlv: B64.decode(&w.value_tlv_b64).unwrap(),
            })
            .collect();
        let ours = build_write_request(&writes);
        let theirs = B64.decode(&f.expected_message_b64).unwrap();
        assert_eq!(
            ours,
            theirs,
            "WriteRequest mismatch for {path:?}\n  ours:   {}\n  theirs: {}",
            hex::encode(&ours),
            hex::encode(&theirs)
        );
        asserted += 1;
    }
    assert!(asserted > 0, "no write-request fixtures parsed");
}

#[test]
fn write_response_parses_matter_js() {
    use matter_interaction::write::parse_write_response;
    use matter_interaction::ImStatus;

    let paths = list_jsons("write");
    if paths.is_empty() {
        eprintln!("skipping: no write fixtures (run `cargo xtask capture-im`)");
        return;
    }
    let mut asserted = 0;
    for path in paths {
        let bytes = fs::read(&path).unwrap();
        let f: WriteResponseFixture = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => continue, // request fixtures live in the same dir
        };
        let msg = B64.decode(&f.response_message_b64).unwrap();
        let statuses = parse_write_response(&msg).unwrap();
        assert_eq!(
            statuses.len(),
            f.expected.len(),
            "count mismatch for {path:?}"
        );
        for (got, want) in statuses.iter().zip(&f.expected) {
            assert_eq!(got.0.endpoint, want.endpoint);
            assert_eq!(got.0.cluster, want.cluster);
            assert_eq!(got.0.attribute, want.attribute);
            assert_eq!(got.1, ImStatus::from_u8(want.status));
        }
        asserted += 1;
    }
    assert!(asserted > 0, "no write-response fixtures parsed");
}
