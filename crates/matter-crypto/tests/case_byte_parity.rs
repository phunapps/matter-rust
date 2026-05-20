//! matter.js byte-parity tests for CASE.
//!
//! Each test loads a captured handshake JSON fixture from
//! `test-vectors/case/` and replays it through our state machines,
//! asserting byte-identical message output at every step.
//!
//! Fixtures produced by `cargo xtask capture-case` (M4.3 Task 3).
//! Tests will fail with "fixture not found" until Task 3 lands.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::doc_markdown)] // test module docs need not link every identifier
#![allow(clippy::struct_field_names)] // fixture field names must match JSON keys verbatim

use std::fs;
use std::path::PathBuf;

use matter_cert::{MatterCertificate, TrustAnchor, TrustedRoots};
use matter_crypto::{
    test_support::{
        case_initiator_with_eph_key, case_initiator_with_resumption_eph_key,
        case_responder_with_eph_key,
    },
    CaseCredentials, PeerInfo, ResumptionId, ResumptionRecord, RingSigner, Sigma1Outcome,
};
use serde::Deserialize;

// =============================================================================
// Fixture types — field names match the JSON produced by the capture script
// =============================================================================

#[derive(Debug, Deserialize)]
struct Fixture {
    inputs: FixtureInputs,
    messages: FixtureMessages,
}

#[derive(Debug, Deserialize)]
struct FixtureInputs {
    fabric_id: u64,
    initiator_node_id: u64,
    responder_node_id: u64,
    /// Hex-encoded 16-byte Identity Protection Key.
    ipk: String,
    /// Hex-encoded RCAC certificate TLV bytes.
    rcac_noc: String,
    /// Hex-encoded 65-byte SEC1-uncompressed RCAC public key.
    rcac_public_key: String,
    /// Hex-encoded initiator NOC TLV bytes.
    initiator_noc: String,
    /// Hex-encoded PKCS#8 DER for the initiator's NOC private key.
    initiator_pkcs8: String,
    /// Hex-encoded responder NOC TLV bytes.
    responder_noc: String,
    /// Hex-encoded PKCS#8 DER for the responder's NOC private key.
    responder_pkcs8: String,
    /// Hex-encoded 32-byte initiator ephemeral private key scalar.
    initiator_eph_priv: String,
    /// Hex-encoded 32-byte initiator random.
    initiator_random: String,
    /// Hex-encoded 32-byte responder ephemeral private key scalar.
    responder_eph_priv: String,
    /// Hex-encoded 32-byte responder random.
    responder_random: String,
    // Resumption-only fields (optional in new-session fixtures):
    #[serde(default)]
    resumption_id: Option<String>,
    #[serde(default)]
    resumption_shared_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureMessages {
    /// Hex-encoded Sigma1 bytes.
    sigma1: String,
    /// Hex-encoded Sigma2 bytes (new-session path and resumption-declined path).
    #[serde(default)]
    sigma2: Option<String>,
    /// Hex-encoded Sigma2_Resume bytes (resumption-accepted path).
    #[serde(default)]
    sigma2_resume: Option<String>,
    /// Hex-encoded Sigma3 bytes (new-session path and resumption-declined path).
    #[serde(default)]
    sigma3: Option<String>,
}

// =============================================================================
// Helpers
// =============================================================================

fn load_fixture(scenario: &str) -> Fixture {
    let path = PathBuf::from("../../test-vectors/case").join(format!("{scenario}.json"));
    let bytes = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "fixture {} not found — run `cargo xtask capture-case` to regenerate",
            path.display()
        )
    });
    serde_json::from_str(&bytes)
        .unwrap_or_else(|e| panic!("malformed fixture {}: {}", path.display(), e))
}

fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
    let bytes = hex::decode(s).expect("valid hex");
    assert_eq!(bytes.len(), N, "expected {N} bytes, got {}", bytes.len());
    bytes.try_into().unwrap()
}

fn build_credentials_from_fixture(
    noc_hex: &str,
    pkcs8_hex: &str,
    fabric_id: u64,
    node_id: u64,
    ipk: [u8; 16],
    rcac_public_key: [u8; 65],
) -> CaseCredentials {
    let noc = MatterCertificate::from_tlv(&hex::decode(noc_hex).unwrap()).expect("parse NOC");
    let signer = RingSigner::from_pkcs8(&hex::decode(pkcs8_hex).unwrap()).expect("load signer");
    CaseCredentials {
        noc,
        icac: None,
        signer: Box::new(signer),
        fabric_id,
        node_id,
        ipk,
        rcac_public_key,
    }
}

fn build_trusted_roots(rcac_noc_hex: &str) -> TrustedRoots {
    let rcac =
        MatterCertificate::from_tlv(&hex::decode(rcac_noc_hex).unwrap()).expect("parse RCAC");
    let mut roots = TrustedRoots::new();
    roots.add(TrustAnchor::from_root_cert(&rcac));
    roots
}

// =============================================================================
// Test scenarios
// =============================================================================

/// New-session CASE handshake: Sigma1 → Sigma2 → Sigma3.
///
/// Loads `test-vectors/case/handshake-new-session.json`, replays the full
/// three-message exchange through our state machines, and asserts byte-identical
/// output at every step. Also verifies that both sides derive identical session
/// keys.
///
/// Requires fixtures from `cargo xtask capture-case` (M4.3 Task 3).
/// Remove `#[ignore]` once fixtures are committed.
#[test]
#[ignore = "fixture not yet committed — run `cargo xtask capture-case` first"]
fn matter_js_byte_parity_new_session() {
    let fx = load_fixture("handshake-new-session");
    let ipk = hex_to_array::<16>(&fx.inputs.ipk);
    let rcac_pub = hex_to_array::<65>(&fx.inputs.rcac_public_key);
    let roots = build_trusted_roots(&fx.inputs.rcac_noc);

    let initiator_creds = build_credentials_from_fixture(
        &fx.inputs.initiator_noc,
        &fx.inputs.initiator_pkcs8,
        fx.inputs.fabric_id,
        fx.inputs.initiator_node_id,
        ipk,
        rcac_pub,
    );
    let responder_creds = build_credentials_from_fixture(
        &fx.inputs.responder_noc,
        &fx.inputs.responder_pkcs8,
        fx.inputs.fabric_id,
        fx.inputs.responder_node_id,
        ipk,
        rcac_pub,
    );

    let mut initiator = case_initiator_with_eph_key(
        initiator_creds,
        roots.clone(),
        fx.inputs.responder_node_id,
        fx.inputs.fabric_id,
        hex_to_array::<32>(&fx.inputs.initiator_eph_priv),
        hex_to_array::<32>(&fx.inputs.initiator_random),
    )
    .unwrap();
    let mut responder = case_responder_with_eph_key(
        responder_creds,
        roots,
        hex_to_array::<32>(&fx.inputs.responder_eph_priv),
        hex_to_array::<32>(&fx.inputs.responder_random),
    )
    .unwrap();

    // ── Sigma1 ────────────────────────────────────────────────────────────
    let our_sigma1 = initiator.start().unwrap();
    assert_eq!(
        hex::encode(&our_sigma1),
        fx.messages.sigma1,
        "Sigma1 byte parity"
    );

    // ── Sigma2 ────────────────────────────────────────────────────────────
    let outcome = responder.handle_sigma1(&our_sigma1).unwrap();
    assert!(
        matches!(outcome, Sigma1Outcome::NewSession),
        "expected NewSession outcome"
    );
    let our_sigma2 = responder.next_message().unwrap();
    assert_eq!(
        hex::encode(&our_sigma2),
        fx.messages.sigma2.as_deref().expect("fixture has sigma2"),
        "Sigma2 byte parity"
    );

    // ── Sigma3 ────────────────────────────────────────────────────────────
    initiator.handle_sigma2(&our_sigma2).unwrap();
    let our_sigma3 = initiator.next_message().unwrap();
    assert_eq!(
        hex::encode(&our_sigma3),
        fx.messages.sigma3.as_deref().expect("fixture has sigma3"),
        "Sigma3 byte parity"
    );

    responder.handle_sigma3(&our_sigma3).unwrap();

    // ── Session key agreement ─────────────────────────────────────────────
    let init_out = initiator.finish().unwrap();
    let resp_out = responder.finish().unwrap();
    assert_eq!(
        init_out.keys.i2r_key, resp_out.keys.i2r_key,
        "i2r session keys must agree"
    );
    assert_eq!(
        init_out.keys.r2i_key, resp_out.keys.r2i_key,
        "r2i session keys must agree"
    );
    assert_eq!(init_out.peer.node_id, fx.inputs.responder_node_id);
    assert_eq!(resp_out.peer.node_id, fx.inputs.initiator_node_id);
}

/// Resumption-accepted path: Sigma1 (with resumption fields) → Sigma2_Resume.
///
/// Loads `test-vectors/case/handshake-resumption-accepted.json`, replays the
/// two-message exchange, and asserts byte-identical output. The shared_secret
/// and resumption_id in the fixture are used to seed the `ResumptionRecord`.
///
/// Requires fixtures from `cargo xtask capture-case` (M4.3 Task 3).
/// Remove `#[ignore]` once fixtures are committed.
#[test]
#[ignore = "fixture not yet committed — run `cargo xtask capture-case` first"]
fn matter_js_byte_parity_resumption_accepted() {
    let fx = load_fixture("handshake-resumption-accepted");
    let ipk = hex_to_array::<16>(&fx.inputs.ipk);
    let rcac_pub = hex_to_array::<65>(&fx.inputs.rcac_public_key);
    let roots = build_trusted_roots(&fx.inputs.rcac_noc);

    let resumption_id = ResumptionId(hex_to_array::<16>(
        fx.inputs
            .resumption_id
            .as_deref()
            .expect("fixture has resumption_id"),
    ));
    let shared_secret = hex_to_array::<16>(
        fx.inputs
            .resumption_shared_secret
            .as_deref()
            .expect("fixture has resumption_shared_secret"),
    );

    let initiator_creds = build_credentials_from_fixture(
        &fx.inputs.initiator_noc,
        &fx.inputs.initiator_pkcs8,
        fx.inputs.fabric_id,
        fx.inputs.initiator_node_id,
        ipk,
        rcac_pub,
    );
    let responder_creds = build_credentials_from_fixture(
        &fx.inputs.responder_noc,
        &fx.inputs.responder_pkcs8,
        fx.inputs.fabric_id,
        fx.inputs.responder_node_id,
        ipk,
        rcac_pub,
    );

    // Build a ResumptionRecord. The peer identity uses the responder's NOC
    // verbatim — on the resumption path this is what the record would have
    // stored from the original session.
    let responder_noc_for_peer =
        MatterCertificate::from_tlv(&hex::decode(&fx.inputs.responder_noc).unwrap()).unwrap();
    let record = ResumptionRecord {
        id: resumption_id,
        shared_secret,
        peer: PeerInfo {
            node_id: fx.inputs.responder_node_id,
            fabric_id: fx.inputs.fabric_id,
            noc: responder_noc_for_peer,
            session_id: 0,
        },
        expires_at: None,
    };

    let mut initiator = case_initiator_with_resumption_eph_key(
        initiator_creds,
        roots.clone(),
        fx.inputs.responder_node_id,
        fx.inputs.fabric_id,
        record.clone(),
        hex_to_array::<32>(&fx.inputs.initiator_eph_priv),
        hex_to_array::<32>(&fx.inputs.initiator_random),
    )
    .unwrap();
    let mut responder = case_responder_with_eph_key(
        responder_creds,
        roots,
        hex_to_array::<32>(&fx.inputs.responder_eph_priv),
        hex_to_array::<32>(&fx.inputs.responder_random),
    )
    .unwrap();

    // ── Sigma1 (with resumption fields) ──────────────────────────────────
    let our_sigma1 = initiator.start().unwrap();
    assert_eq!(
        hex::encode(&our_sigma1),
        fx.messages.sigma1,
        "Sigma1 (resumption) byte parity"
    );

    // ── Responder decides to accept resumption ────────────────────────────
    let outcome = responder.handle_sigma1(&our_sigma1).unwrap();
    let presented_id = match outcome {
        Sigma1Outcome::ResumptionRequested { id } => id,
        Sigma1Outcome::NewSession => panic!("expected ResumptionRequested"),
    };
    assert_eq!(
        presented_id, resumption_id,
        "presented resumption_id must match fixture"
    );

    responder.accept_resumption(record).unwrap();

    // ── Sigma2_Resume ─────────────────────────────────────────────────────
    let our_sigma2_resume = responder.next_message().unwrap();
    assert_eq!(
        hex::encode(&our_sigma2_resume),
        fx.messages
            .sigma2_resume
            .as_deref()
            .expect("fixture has sigma2_resume"),
        "Sigma2_Resume byte parity"
    );

    // ── Initiator processes Sigma2_Resume — no Sigma3 on resumption ───────
    initiator.handle_sigma2_resume(&our_sigma2_resume).unwrap();
    let init_out = initiator.finish().unwrap();
    let resp_out = responder.finish().unwrap();
    assert_eq!(
        init_out.keys.i2r_key, resp_out.keys.i2r_key,
        "resumed i2r keys must agree"
    );
    assert_eq!(
        init_out.keys.r2i_key, resp_out.keys.r2i_key,
        "resumed r2i keys must agree"
    );
}

/// Resumption-declined path: initiator presents a resumption ID the responder
/// doesn't recognise; responder falls back to the full new-session path.
///
/// Loads `test-vectors/case/handshake-resumption-declined.json` and replays
/// the full Sigma1 → Sigma2 → Sigma3 exchange that results when the responder
/// calls `reject_resumption()`.
///
/// Requires fixtures from `cargo xtask capture-case` (M4.3 Task 3).
/// Remove `#[ignore]` once fixtures are committed.
#[test]
#[ignore = "fixture not yet committed — run `cargo xtask capture-case` first"]
fn matter_js_byte_parity_resumption_declined() {
    let fx = load_fixture("handshake-resumption-declined");
    let ipk = hex_to_array::<16>(&fx.inputs.ipk);
    let rcac_pub = hex_to_array::<65>(&fx.inputs.rcac_public_key);
    let roots = build_trusted_roots(&fx.inputs.rcac_noc);

    let initiator_creds = build_credentials_from_fixture(
        &fx.inputs.initiator_noc,
        &fx.inputs.initiator_pkcs8,
        fx.inputs.fabric_id,
        fx.inputs.initiator_node_id,
        ipk,
        rcac_pub,
    );
    let responder_creds = build_credentials_from_fixture(
        &fx.inputs.responder_noc,
        &fx.inputs.responder_pkcs8,
        fx.inputs.fabric_id,
        fx.inputs.responder_node_id,
        ipk,
        rcac_pub,
    );

    // Build a bogus ResumptionRecord. The responder will decline because it
    // has no record for this ID, so the specific contents don't matter for
    // the byte-parity assertion. We still need a syntactically valid record
    // so the initiator can populate the Sigma1 resumption fields.
    let bogus_id = ResumptionId(hex_to_array::<16>(
        fx.inputs
            .resumption_id
            .as_deref()
            .expect("bogus resumption_id in fixture"),
    ));
    let responder_noc_for_peer =
        MatterCertificate::from_tlv(&hex::decode(&fx.inputs.responder_noc).unwrap()).unwrap();
    let bogus_record = ResumptionRecord {
        id: bogus_id,
        shared_secret: [0xCC; 16],
        peer: PeerInfo {
            node_id: fx.inputs.responder_node_id,
            fabric_id: fx.inputs.fabric_id,
            noc: responder_noc_for_peer,
            session_id: 0,
        },
        expires_at: None,
    };

    let mut initiator = case_initiator_with_resumption_eph_key(
        initiator_creds,
        roots.clone(),
        fx.inputs.responder_node_id,
        fx.inputs.fabric_id,
        bogus_record,
        hex_to_array::<32>(&fx.inputs.initiator_eph_priv),
        hex_to_array::<32>(&fx.inputs.initiator_random),
    )
    .unwrap();
    let mut responder = case_responder_with_eph_key(
        responder_creds,
        roots,
        hex_to_array::<32>(&fx.inputs.responder_eph_priv),
        hex_to_array::<32>(&fx.inputs.responder_random),
    )
    .unwrap();

    // ── Sigma1 (with resumption fields) ──────────────────────────────────
    let our_sigma1 = initiator.start().unwrap();
    assert_eq!(
        hex::encode(&our_sigma1),
        fx.messages.sigma1,
        "Sigma1 (declined resumption) byte parity"
    );

    // ── Responder declines — falls back to new-session Sigma2 ─────────────
    responder.handle_sigma1(&our_sigma1).unwrap();
    responder.reject_resumption().unwrap();

    // ── Sigma2 (new-session fallback) ─────────────────────────────────────
    let our_sigma2 = responder.next_message().unwrap();
    assert_eq!(
        hex::encode(&our_sigma2),
        fx.messages
            .sigma2
            .as_deref()
            .expect("fixture has sigma2 (fallback path)"),
        "Sigma2 (fallback) byte parity"
    );

    // ── Sigma3 ────────────────────────────────────────────────────────────
    initiator.handle_sigma2(&our_sigma2).unwrap();
    let our_sigma3 = initiator.next_message().unwrap();
    assert_eq!(
        hex::encode(&our_sigma3),
        fx.messages
            .sigma3
            .as_deref()
            .expect("fixture has sigma3 (fallback path)"),
        "Sigma3 (fallback) byte parity"
    );

    responder.handle_sigma3(&our_sigma3).unwrap();

    // ── Session key agreement ─────────────────────────────────────────────
    let init_out = initiator.finish().unwrap();
    let resp_out = responder.finish().unwrap();
    assert_eq!(
        init_out.keys.i2r_key, resp_out.keys.i2r_key,
        "i2r session keys must agree on declined-resumption path"
    );
    assert_eq!(
        init_out.keys.r2i_key, resp_out.keys.r2i_key,
        "r2i session keys must agree on declined-resumption path"
    );
}
