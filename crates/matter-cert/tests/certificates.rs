//! Integration test: every certificate in `test-vectors/certs/manifest.toml`
//! parses successfully and round-trips through `from_tlv` → `to_tlv`
//! byte-for-byte.
//!
//! The manifest carries no `expected` field-assertion annotations for the
//! committed snapshot — those can be added in a future task. The test
//! therefore exercises: (1) every captured cert parses without error,
//! (2) re-serialisation produces byte-for-byte identical output, and
//! (3) the manifest is non-empty (regression guard against an empty capture).

// CLAUDE.md test-code carve-out: unwrap / expect are allowed in test code
// provided there is a documented justification. Here they are used to fail
// the test with a clear message that names the offending cert ID.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use matter_cert::MatterCertificate;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Manifest schema — must match `test-vectors/certs/manifest.toml` exactly.
// The `kind` field ("rcac" | "icac" | "noc") is present but only used for
// the `#[allow(dead_code)]` display; the round-trip test is kind-agnostic.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Manifest {
    certificate: Vec<CertificateEntry>,
}

#[derive(Debug, Deserialize)]
struct CertificateEntry {
    id: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    source: String,
    file: String,
    #[allow(dead_code)]
    kind: String,
    /// Whether this cert is self-signed (root). Currently unused — the
    /// manifest annotation is preserved for future X.509-based
    /// signature verification (matter-cert needs Matter-TLV → X.509-DER
    /// conversion before `verify_signed_by` can work on real certs).
    #[allow(dead_code)]
    #[serde(default)]
    is_self_signed: bool,
    /// `id` of the cert whose public key signed this one. Same future-
    /// use rationale as `is_self_signed`.
    #[allow(dead_code)]
    #[serde(default)]
    signed_by_id: Option<String>,
    /// Path (relative to test-vectors/certs/) of matter.js's
    /// `asUnsignedDer()` output for this cert. The bytes whose
    /// signature should verify against this cert's signature.
    /// Consumed by Task 10's byte-parity integration test.
    // Allow unused until Task 10 adds the byte-parity test that reads this.
    #[allow(dead_code)]
    #[serde(default)]
    tbs_file: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR resolves to `crates/matter-cert` at test time.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ directory must exist")
        .parent()
        .expect("workspace root must exist")
        .to_path_buf()
}

fn load_manifest() -> Manifest {
    let path = workspace_root().join("test-vectors/certs/manifest.toml");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read manifest at {}: {e}", path.display()));
    toml::from_str(&text).expect("manifest.toml must be valid TOML matching the Manifest schema")
}

fn load_bin(file: &str) -> Vec<u8> {
    let path = workspace_root().join("test-vectors/certs").join(file);
    fs::read(&path).unwrap_or_else(|e| panic!("failed to read cert file {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn every_certificate_parses_and_round_trips() {
    let manifest = load_manifest();
    assert!(
        !manifest.certificate.is_empty(),
        "manifest contains no certificates — capture must have failed or the file is empty",
    );

    let mut processed = 0usize;
    for entry in &manifest.certificate {
        let bytes = load_bin(&entry.file);

        // Step 1: parse.
        let cert = MatterCertificate::from_tlv(&bytes).unwrap_or_else(|e| {
            panic!(
                "MatterCertificate::from_tlv failed for cert '{}' (file: {}): {e}",
                entry.id, entry.file,
            );
        });

        // Step 2: re-serialise and assert byte-for-byte equality.
        let re_serialised = cert.to_tlv().unwrap_or_else(|e| {
            panic!(
                "MatterCertificate::to_tlv failed for cert '{}': {e}",
                entry.id,
            );
        });
        assert_eq!(
            re_serialised, bytes,
            "cert '{}' parsed successfully but re-serialised to different bytes \
             (check for missed fields or wrong emission order in to_tlv)",
            entry.id,
        );

        processed += 1;
    }

    eprintln!("processed {processed} certificate(s) — all parsed and round-tripped");
}
