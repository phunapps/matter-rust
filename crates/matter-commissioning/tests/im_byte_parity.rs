//! matter.js byte-parity tests for the `im` module.
//!
//! Fixtures live under `test-vectors/commissioning/im/<kind>/*.json`.
//! Each fixture provides the inputs and the matter.js-captured expected
//! IM message bytes (base64). Tests SKIP (not fail) when fixtures are
//! absent, matching the established M6.x pattern — fixtures are captured
//! by a later `cargo xtask capture-im` operator step.

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
use matter_commissioning::im::invoke::build_invoke_request;
use matter_commissioning::im::read::{build_read_request, AttributePath};
use matter_commissioning::im::CommandPath;
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
