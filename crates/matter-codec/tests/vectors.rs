//! Cross-verifies `matter-codec` against the captured TLV vectors.
//!
//! Loads `test-vectors/tlv/manifest.toml` (shipped in M0), iterates every
//! entry, encodes the structured `encode` block via [`TlvWriter`], asserts
//! byte equality with the matching `.bin`, then decodes the `.bin` via
//! [`TlvReader::read_value`] and asserts structural equality with the
//! constructed value.
//!
//! Vectors whose `encode` block uses kinds not yet implemented (strings,
//! bytes, containers, non-{anonymous,context} tags) are filtered out at
//! load time and counted as "skipped". Phase 2 and beyond will widen the
//! filter.

// CLAUDE.md test-code carve-out: unwrap / expect with documented justification.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use matter_codec::{Tag, TlvReader, TlvWriter, Value};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    vector: Vec<VectorEntry>,
}

#[derive(Debug, Deserialize)]
struct VectorEntry {
    id: String,
    #[allow(dead_code)]
    description: String,
    source: String,
    file: String,
    encode: Encode,
}

#[derive(Debug, Deserialize)]
struct Encode {
    tag: TagDesc,
    value: ValueDesc,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TagDesc {
    Anonymous,
    Context {
        number: u8,
    },
    CommonProfile {
        #[allow(dead_code)]
        number: u32,
    },
    ImplicitProfile {
        #[allow(dead_code)]
        number: u32,
    },
    FullyQualified {
        #[allow(dead_code)]
        vendor: u16,
        #[allow(dead_code)]
        profile: u16,
        #[allow(dead_code)]
        tag: u32,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ValueDesc {
    Bool {
        value: bool,
    },
    Null,
    Uint {
        #[allow(dead_code)]
        width: u8,
        value: UintLit,
    },
    Int {
        #[allow(dead_code)]
        width: u8,
        value: IntLit,
    },
    Float {
        width: u8,
        value: String,
    },
    Utf8 {
        #[allow(dead_code)]
        value: String,
    },
    Bytes {
        #[allow(dead_code)]
        value: String,
    },
    Structure {
        #[allow(dead_code)]
        members: Vec<MemberDesc>,
    },
    Array {
        #[allow(dead_code)]
        elements: Vec<ElementDesc>,
    },
    List {
        #[allow(dead_code)]
        members: Vec<MemberDesc>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum UintLit {
    Direct(u64),
    Hex(String),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IntLit {
    Direct(i64),
    Str(String),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct MemberDesc {
    tag: TagDesc,
    value: ValueDesc,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ElementDesc {
    tag: TagDesc,
    value: ValueDesc,
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/matter-codec; go up two levels.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace")
        .to_path_buf()
}

fn load_manifest() -> Manifest {
    let path = workspace_root().join("test-vectors/tlv/manifest.toml");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    toml::from_str(&text).expect("parse manifest.toml")
}

fn load_bin(file: &str) -> Vec<u8> {
    let path = workspace_root().join("test-vectors/tlv").join(file);
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn build_tag(desc: &TagDesc) -> Result<Tag, &'static str> {
    match desc {
        TagDesc::Anonymous => Ok(Tag::Anonymous),
        TagDesc::Context { number } => Ok(Tag::Context(*number)),
        TagDesc::CommonProfile { .. } => Err("common_profile tag (phase 2)"),
        TagDesc::ImplicitProfile { .. } => Err("implicit_profile tag (phase 2)"),
        TagDesc::FullyQualified { .. } => Err("fully_qualified tag (phase 2)"),
    }
}

fn parse_uint(lit: &UintLit) -> u64 {
    match lit {
        UintLit::Direct(n) => *n,
        UintLit::Hex(s) => {
            let s = s.trim_start_matches("0x");
            u64::from_str_radix(s, 16).expect("hex uint literal")
        }
    }
}

fn parse_int(lit: &IntLit) -> i64 {
    match lit {
        IntLit::Direct(n) => *n,
        IntLit::Str(s) => s.parse::<i64>().expect("decimal i64 literal"),
    }
}

// Harness intentionally narrows f64 -> f32 for vectors that declared width = 4.
#[allow(clippy::cast_possible_truncation)]
fn build_value(desc: &ValueDesc) -> Result<Value, &'static str> {
    match desc {
        ValueDesc::Bool { value } => Ok(Value::Bool(*value)),
        ValueDesc::Null => Ok(Value::Null),
        ValueDesc::Uint { value, .. } => Ok(Value::Uint(parse_uint(value))),
        ValueDesc::Int { value, .. } => Ok(Value::Int(parse_int(value))),
        ValueDesc::Float { width, value } => {
            let parsed: f64 = value.parse().expect("float literal");
            match width {
                4 => Ok(Value::Float(parsed as f32)),
                8 => Ok(Value::Double(parsed)),
                _ => Err("float width != 4 or 8"),
            }
        }
        ValueDesc::Utf8 { .. } => Err("utf8 (phase 2)"),
        ValueDesc::Bytes { .. } => Err("bytes (phase 2)"),
        ValueDesc::Structure { .. } => Err("structure (phase 3)"),
        ValueDesc::Array { .. } => Err("array (phase 3)"),
        ValueDesc::List { .. } => Err("list (phase 3)"),
    }
}

#[test]
fn all_phase_1_vectors_encode_and_decode_correctly() {
    let manifest = load_manifest();
    let mut processed = 0;
    let mut skipped = Vec::new();

    for entry in &manifest.vector {
        let tag = match build_tag(&entry.encode.tag) {
            Ok(t) => t,
            Err(reason) => {
                skipped.push((entry.id.clone(), reason));
                continue;
            }
        };
        let value = match build_value(&entry.encode.value) {
            Ok(v) => v,
            Err(reason) => {
                skipped.push((entry.id.clone(), reason));
                continue;
            }
        };

        let expected = load_bin(&entry.file);

        // Encode side
        let mut buf = Vec::with_capacity(expected.len());
        let mut w = TlvWriter::new(&mut buf);
        w.write_value(tag, &value).unwrap_or_else(|e| {
            panic!(
                "encode failed for {}: {e}\n  source: {}",
                entry.id, entry.source
            )
        });
        assert_eq!(
            buf, expected,
            "encode bytes differ for {} ({})\n  expected: {:02x?}\n  actual:   {:02x?}",
            entry.id, entry.source, expected, buf,
        );

        // Decode side
        let mut r = TlvReader::new(&expected);
        let (decoded_tag, decoded_value) = r
            .read_value()
            .unwrap_or_else(|e| panic!("decode failed for {}: {e}", entry.id));
        assert_eq!(decoded_tag, tag, "decoded tag differs for {}", entry.id);
        assert_eq!(
            decoded_value, value,
            "decoded value differs for {}",
            entry.id
        );
        assert!(
            r.is_empty(),
            "decoder did not consume all bytes for {}",
            entry.id
        );

        processed += 1;
    }

    // Sanity: we must have processed *some* vectors. M0 shipped 23; phase 1
    // should handle at least 14 (booleans + uints + ints + float + double,
    // all anonymous tag). If this assertion fails we are either silently
    // skipping vectors we should handle, or the manifest is empty.
    assert!(
        processed >= 14,
        "expected at least 14 vectors to be processed, got {processed}; skipped = {skipped:?}"
    );

    eprintln!(
        "processed {processed} vector(s); skipped {} (later phases):",
        skipped.len()
    );
    for (id, reason) in &skipped {
        eprintln!("  {id}: {reason}");
    }
}
