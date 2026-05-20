//! Local CASE roundtrip tests — drive [`CaseInitiator`] and [`CaseResponder`]
//! against each other and confirm shared session output.
//!
//! This file is the M4.1 correctness gate. If it passes, the two
//! state machines agree on:
//!   - The full 3-message Sigma1/2/3 handshake.
//!   - Derived session keys (`i2r_key`, `r2i_key`, `attestation_challenge`).
//!   - Peer identity (`NodeId`, `FabricId`, NOC).
//!
//! Session resumption is M4.2; matter.js byte-parity is M4.3.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use matter_cert::test_support::{build_unsigned, with_signature, TestCertFields};
use matter_cert::{
    BasicConstraints, DistinguishedName, DnAttribute, Extensions, KeyIdentifier, KeyUsage,
    MatterCertificate, MatterTime, PublicKey, Signature, TrustAnchor, TrustedRoots,
};
use matter_crypto::{
    CaseCredentials, CaseInitiator, CaseResponder, CaseSigner, RingSigner, Sigma1Outcome,
};

const TEST_FABRIC_ID: u64 = 0x4242_4242_4242_4242;
const INITIATOR_NODE_ID: u64 = 0xDEAD_BEEF_CAFE_F00D;
const RESPONDER_NODE_ID: u64 = 0xBABE_FEED_1234_5678;
const IPK: [u8; 16] = [0x77; 16];

// Shared SKI/AKI value used for both the RCAC and the NOC's AKI field.
// When TrustAnchor::from_root_cert extracts the RCAC's SKI and the NOC
// carries a matching AKI, the SKI gate in CertificateChain::validate passes.
const TEST_SKI: [u8; 20] = [0x01; 20];
const NOC_SKI: [u8; 20] = [0x02; 20];

/// Build a self-signed RCAC for the test fabric.
///
/// Returns the RCAC, its `RingSigner` (needed to sign NOCs), a `TrustedRoots`
/// set containing that RCAC, and the raw 65-byte RCAC public key (needed for
/// `DestinationId` computation in `CaseCredentials`).
fn build_test_rcac() -> (MatterCertificate, RingSigner, TrustedRoots, [u8; 65]) {
    // 1. Generate RCAC keypair via RingSigner::generate.
    let (rcac_signer, _pkcs8) = RingSigner::generate().expect("rcac signer");
    let rcac_pub = *rcac_signer.public_key().as_bytes();

    // 2. Build RCAC subject DN with RcacId attribute.
    //    The NOC issuer DN must equal this DN for chain validation to succeed.
    let rcac_dn = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);

    let extensions = Extensions {
        basic_constraints: Some(BasicConstraints {
            is_ca: true,
            path_len_constraint: Some(1),
        }),
        key_usage: Some(KeyUsage::KEY_CERT_SIGN),
        extended_key_usage: None,
        subject_key_identifier: Some(KeyIdentifier(TEST_SKI)),
        // Self-signed: AKI == SKI.
        authority_key_identifier: Some(KeyIdentifier(TEST_SKI)),
    };

    let fields = TestCertFields {
        serial: vec![0x01],
        issuer: rcac_dn.clone(),
        not_before: MatterTime::from_unix_secs(1_700_000_000),
        not_after: MatterTime::from_unix_secs(2_500_000_000),
        subject: rcac_dn,
        public_key: PublicKey::new(rcac_pub).expect("rcac pub key"),
        extensions,
        signature: Signature::new([0u8; 64]),
    };
    let unsigned = build_unsigned(fields);

    // 3. Sign the X.509 TBS with the RCAC's own key.
    let tbs = unsigned.to_x509_tbs_der().expect("rcac tbs");
    let sig_bytes = rcac_signer.sign_p256_sha256(&tbs).expect("rcac sign self");
    let rcac = with_signature(&unsigned, Signature::new(sig_bytes));

    // 4. TrustedRoots containing this RCAC as a trust anchor.
    let mut roots = TrustedRoots::new();
    roots.add(TrustAnchor::from_root_cert(&rcac));

    (rcac, rcac_signer, roots, rcac_pub)
}

/// Build a NOC signed by the given RCAC signer.
///
/// The NOC subject carries `FabricId` and `NodeId` attributes per Matter
/// spec §6.5.6. The issuer DN matches the RCAC subject so that
/// `CertificateChain::validate` succeeds. The NOC's AKI matches the
/// RCAC's SKI so the asymmetric SKI gate in chain validation passes.
fn build_test_noc(
    rcac_signer: &RingSigner,
    fabric_id: u64,
    node_id: u64,
) -> (MatterCertificate, RingSigner) {
    let (noc_signer, _) = RingSigner::generate().expect("noc signer");
    let noc_pub = *noc_signer.public_key().as_bytes();

    let subject_dn = DistinguishedName::new(vec![
        DnAttribute::FabricId(fabric_id),
        DnAttribute::NodeId(node_id),
    ]);
    // Issuer DN must match the RCAC subject DN.
    let issuer_dn = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);

    let extensions = Extensions {
        basic_constraints: Some(BasicConstraints {
            is_ca: false,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage::DIGITAL_SIGNATURE),
        extended_key_usage: None,
        subject_key_identifier: Some(KeyIdentifier(NOC_SKI)),
        // AKI must match the RCAC's SKI to pass the SKI gate.
        authority_key_identifier: Some(KeyIdentifier(TEST_SKI)),
    };

    let fields = TestCertFields {
        serial: vec![0x02],
        issuer: issuer_dn,
        not_before: MatterTime::from_unix_secs(1_700_000_000),
        not_after: MatterTime::from_unix_secs(2_500_000_000),
        subject: subject_dn,
        public_key: PublicKey::new(noc_pub).expect("noc pub key"),
        extensions,
        signature: Signature::new([0u8; 64]),
    };
    let unsigned = build_unsigned(fields);

    let tbs = unsigned.to_x509_tbs_der().expect("noc tbs");
    let sig_bytes = rcac_signer.sign_p256_sha256(&tbs).expect("rcac sign noc");
    let noc = with_signature(&unsigned, Signature::new(sig_bytes));

    (noc, noc_signer)
}

/// Assemble a `CaseCredentials` from its components.
fn build_credentials(
    noc: MatterCertificate,
    signer: RingSigner,
    fabric_id: u64,
    node_id: u64,
    ipk: [u8; 16],
    rcac_public_key: [u8; 65],
) -> CaseCredentials {
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

// ---------------------------------------------------------------------------
// Test: full new-session roundtrip
// ---------------------------------------------------------------------------

#[test]
fn case_roundtrip_new_session() {
    let (_rcac, rcac_signer, trusted_roots, rcac_pub) = build_test_rcac();

    let (initiator_noc, initiator_signer) =
        build_test_noc(&rcac_signer, TEST_FABRIC_ID, INITIATOR_NODE_ID);
    let (responder_noc, responder_signer) =
        build_test_noc(&rcac_signer, TEST_FABRIC_ID, RESPONDER_NODE_ID);

    let initiator_creds = build_credentials(
        initiator_noc,
        initiator_signer,
        TEST_FABRIC_ID,
        INITIATOR_NODE_ID,
        IPK,
        rcac_pub,
    );
    let responder_creds = build_credentials(
        responder_noc,
        responder_signer,
        TEST_FABRIC_ID,
        RESPONDER_NODE_ID,
        IPK,
        rcac_pub,
    );

    let mut initiator = CaseInitiator::new(
        initiator_creds,
        trusted_roots.clone(),
        RESPONDER_NODE_ID,
        TEST_FABRIC_ID,
    )
    .expect("initiator construction");
    let mut responder =
        CaseResponder::new(responder_creds, trusted_roots).expect("responder construction");

    // --- Sigma1 ---
    let sigma1 = initiator.start().expect("sigma1");
    let outcome = responder.handle_sigma1(&sigma1).expect("handle sigma1");
    assert!(
        matches!(outcome, Sigma1Outcome::NewSession),
        "expected NewSession outcome from Sigma1"
    );

    // --- Sigma2 ---
    let sigma2 = responder.next_message().expect("sigma2");
    initiator.handle_sigma2(&sigma2).expect("handle sigma2");

    // --- Sigma3 ---
    let sigma3 = initiator.next_message().expect("sigma3");
    responder.handle_sigma3(&sigma3).expect("handle sigma3");

    // --- Collect session outputs ---
    let init_output = initiator.finish().expect("initiator finish");
    let resp_output = responder.finish().expect("responder finish");

    // --- Session key parity ---
    // Both sides derive the same 48-byte HKDF output from the same inputs.
    // Both assign i2r_key = keys[0..16] and r2i_key = keys[16..32] (see
    // NodeSession.ts comments in initiator.rs and responder.rs).
    // The semantic name (who "encrypts" vs who "decrypts") flips per role,
    // but the raw bytes in each field are identical on both sides.
    assert_eq!(
        init_output.keys.i2r_key, resp_output.keys.i2r_key,
        "i2r_key must match on both sides"
    );
    assert_eq!(
        init_output.keys.r2i_key, resp_output.keys.r2i_key,
        "r2i_key must match on both sides"
    );
    assert_eq!(
        init_output.keys.attestation_challenge, resp_output.keys.attestation_challenge,
        "attestation_challenge must match on both sides"
    );

    // --- Peer identity (initiator side) ---
    assert_eq!(
        init_output.peer.node_id, RESPONDER_NODE_ID,
        "initiator must see responder's node_id"
    );
    assert_eq!(
        init_output.peer.fabric_id, TEST_FABRIC_ID,
        "initiator must see correct fabric_id for peer"
    );

    // --- Peer identity (responder side) ---
    assert_eq!(
        resp_output.peer.node_id, INITIATOR_NODE_ID,
        "responder must see initiator's node_id"
    );
    assert_eq!(
        resp_output.peer.fabric_id, TEST_FABRIC_ID,
        "responder must see correct fabric_id for peer"
    );

    // --- Local identity ---
    assert_eq!(
        init_output.local.node_id, INITIATOR_NODE_ID,
        "initiator's local node_id must be correct"
    );
    assert_eq!(
        init_output.local.fabric_id, TEST_FABRIC_ID,
        "initiator's local fabric_id must be correct"
    );
    assert_eq!(
        resp_output.local.node_id, RESPONDER_NODE_ID,
        "responder's local node_id must be correct"
    );
    assert_eq!(
        resp_output.local.fabric_id, TEST_FABRIC_ID,
        "responder's local fabric_id must be correct"
    );
}

// ---------------------------------------------------------------------------
// Test: wrong-fabric handshake must fail
// ---------------------------------------------------------------------------

// Fabric ID that deliberately mismatches TEST_FABRIC_ID; used by
// `case_roundtrip_wrong_fabric_returns_fabric_mismatch`.
const WRONG_FABRIC: u64 = 0x9999_9999_9999_9999;

#[test]
fn case_roundtrip_wrong_fabric_returns_fabric_mismatch() {
    let (_rcac, rcac_signer, trusted_roots, rcac_pub) = build_test_rcac();

    let (initiator_noc, initiator_signer) =
        build_test_noc(&rcac_signer, TEST_FABRIC_ID, INITIATOR_NODE_ID);
    let (responder_noc, responder_signer) =
        build_test_noc(&rcac_signer, WRONG_FABRIC, RESPONDER_NODE_ID);

    let initiator_creds = build_credentials(
        initiator_noc,
        initiator_signer,
        TEST_FABRIC_ID,
        INITIATOR_NODE_ID,
        IPK,
        rcac_pub,
    );
    let responder_creds = build_credentials(
        responder_noc,
        responder_signer,
        WRONG_FABRIC,
        RESPONDER_NODE_ID,
        IPK,
        rcac_pub,
    );

    let mut initiator = CaseInitiator::new(
        initiator_creds,
        trusted_roots.clone(),
        RESPONDER_NODE_ID,
        TEST_FABRIC_ID,
    )
    .unwrap();
    let mut responder = CaseResponder::new(responder_creds, trusted_roots).unwrap();

    // Sigma1: computed dest_id is HMAC(IPK, random || rcacPub || initiatorFabricId || responderNodeId).
    // The responder recomputes using WRONG_FABRIC — so dest_id will mismatch immediately.
    // In that case handle_sigma1 returns Error::InvalidParameter and we never get to Sigma2.
    // If handle_sigma1 somehow passes (dest_id happened to match), we expect an error before
    // or during Sigma2 processing (FabricIdMismatch). Either way: not Ok.
    let result = responder
        .handle_sigma1(&initiator.start().unwrap())
        .and_then(|_| {
            let sigma2 = responder.next_message()?;
            initiator.handle_sigma2(&sigma2)?;
            Ok(())
        });
    assert!(
        result.is_err(),
        "handshake must fail when fabric IDs mismatch"
    );
}

// ---------------------------------------------------------------------------
// Resumption helpers
// ---------------------------------------------------------------------------

/// Drive a fresh new-session handshake to completion and return the outputs
/// from both sides.
///
/// Re-builds credentials from scratch (all inputs generated fresh inside this
/// function), so each call is independent.  Also returns the RCAC signer and
/// the raw RCAC public key so the caller can build fresh credentials for the
/// resumption round without regenerating the root.
fn drive_new_session_handshake() -> (
    matter_crypto::CaseSessionOutput,
    matter_crypto::CaseSessionOutput,
) {
    let (_rcac, rcac_signer, trusted_roots, rcac_pub) = build_test_rcac();
    let (initiator_noc, initiator_signer) =
        build_test_noc(&rcac_signer, TEST_FABRIC_ID, INITIATOR_NODE_ID);
    let (responder_noc, responder_signer) =
        build_test_noc(&rcac_signer, TEST_FABRIC_ID, RESPONDER_NODE_ID);
    let initiator_creds = build_credentials(
        initiator_noc,
        initiator_signer,
        TEST_FABRIC_ID,
        INITIATOR_NODE_ID,
        IPK,
        rcac_pub,
    );
    let responder_creds = build_credentials(
        responder_noc,
        responder_signer,
        TEST_FABRIC_ID,
        RESPONDER_NODE_ID,
        IPK,
        rcac_pub,
    );

    let mut initiator = CaseInitiator::new(
        initiator_creds,
        trusted_roots.clone(),
        RESPONDER_NODE_ID,
        TEST_FABRIC_ID,
    )
    .expect("initiator");
    let mut responder = CaseResponder::new(responder_creds, trusted_roots).expect("responder");

    let sigma1 = initiator.start().expect("sigma1");
    let outcome = responder.handle_sigma1(&sigma1).expect("handle sigma1");
    assert!(
        matches!(outcome, Sigma1Outcome::NewSession),
        "expected NewSession from fresh handshake"
    );
    let sigma2 = responder.next_message().expect("sigma2");
    initiator.handle_sigma2(&sigma2).expect("handle sigma2");
    let sigma3 = initiator.next_message().expect("sigma3");
    responder.handle_sigma3(&sigma3).expect("handle sigma3");

    let init_out = initiator.finish().expect("initiator finish");
    let resp_out = responder.finish().expect("responder finish");
    (init_out, resp_out)
}

// ---------------------------------------------------------------------------
// Test: resumption accepted — 2-message fast path
// ---------------------------------------------------------------------------

/// Drive a fresh handshake; build synthetic resumption records; drive a
/// second handshake via [`CaseInitiator::new_with_resumption`] +
/// [`CaseResponder::accept_resumption`].  Both sides must agree on the
/// resumed session keys and produce a new [`ResumptionRecord`].
// The test necessarily covers many sequential steps: fresh handshake,
// record construction, resumption round, key-agreement assertions, and
// record refresh.  Splitting it would make it harder to follow the protocol
// flow, so the line-count lint is suppressed here.
#[allow(clippy::too_many_lines)]
#[test]
fn case_resumption_roundtrip_accepted() {
    // Step 1: Drive an initial new-session handshake.  We only need the
    // peer NOCs captured by the session outputs (stored in peer.noc) so we
    // can build valid PeerInfo structs for the synthetic records.
    let (initiator_out_1, _responder_out_1) = drive_new_session_handshake();

    // The new-session path does NOT populate resumption_record (per M4.2
    // design; M6 commissioning fills it).  We synthesise records manually
    // using a known shared_secret and id to drive the resumption path.
    let resumption_id = matter_crypto::ResumptionId([0x42; 16]);
    let shared_secret = [0x77u8; 16];

    // Step 2: Build fresh credentials for the resumption round (the first
    // round's credentials were consumed by drive_new_session_handshake).
    let (_rcac2, rcac_signer2, trusted_roots2, rcac_pub2) = build_test_rcac();
    let (initiator_noc2, initiator_signer2) =
        build_test_noc(&rcac_signer2, TEST_FABRIC_ID, INITIATOR_NODE_ID);
    let (responder_noc2, responder_signer2) =
        build_test_noc(&rcac_signer2, TEST_FABRIC_ID, RESPONDER_NODE_ID);

    // From the initiator's perspective its peer is the RESPONDER, so
    // peer.noc must be a valid responder NOC.  We use the fresh responder_noc2
    // (which is validly signed by rcac_signer2, matching trusted_roots2).
    let initiator_peer_info = matter_crypto::PeerInfo {
        node_id: RESPONDER_NODE_ID,
        fabric_id: TEST_FABRIC_ID,
        noc: responder_noc2.clone(),
        session_id: 0,
    };
    // The initiator's record: id = the OLD id it will present in Sigma1.
    let record_for_initiator = matter_crypto::ResumptionRecord {
        id: resumption_id,
        shared_secret,
        peer: initiator_peer_info,
        expires_at: None,
    };

    // From the responder's perspective its peer is the INITIATOR.
    let responder_peer_info = matter_crypto::PeerInfo {
        node_id: INITIATOR_NODE_ID,
        fabric_id: TEST_FABRIC_ID,
        noc: initiator_noc2.clone(),
        session_id: 0,
    };
    // The responder's record: id must match what the initiator presents (same OLD id).
    let record_for_responder = matter_crypto::ResumptionRecord {
        id: resumption_id, // same id — accept_resumption checks equality
        shared_secret,
        peer: responder_peer_info,
        expires_at: None,
    };

    let initiator_creds2 = build_credentials(
        initiator_noc2,
        initiator_signer2,
        TEST_FABRIC_ID,
        INITIATOR_NODE_ID,
        IPK,
        rcac_pub2,
    );
    let responder_creds2 = build_credentials(
        responder_noc2,
        responder_signer2,
        TEST_FABRIC_ID,
        RESPONDER_NODE_ID,
        IPK,
        rcac_pub2,
    );

    // Step 3: Initiator with resumption record.
    let mut initiator2 = CaseInitiator::new_with_resumption(
        initiator_creds2,
        trusted_roots2.clone(),
        RESPONDER_NODE_ID,
        TEST_FABRIC_ID,
        record_for_initiator,
    )
    .expect("initiator2 with resumption");
    let mut responder2 = CaseResponder::new(responder_creds2, trusted_roots2).expect("responder2");

    // Step 4: Drive the 2-message resumption handshake.
    let sigma1_r = initiator2.start().expect("sigma1 (resumption)");

    let outcome2 = responder2
        .handle_sigma1(&sigma1_r)
        .expect("handle sigma1 (resumption)");
    let presented_id = match outcome2 {
        Sigma1Outcome::ResumptionRequested { id } => id,
        Sigma1Outcome::NewSession => panic!("expected ResumptionRequested, got NewSession"),
    };
    assert_eq!(
        presented_id, resumption_id,
        "responder must see the resumption_id the initiator embedded in Sigma1"
    );

    // Responder accepts with the matching record.
    responder2
        .accept_resumption(record_for_responder)
        .expect("accept_resumption");

    // Responder emits Sigma2_Resume (the 2nd and final protocol message).
    let sigma2_resume = responder2.next_message().expect("sigma2_resume");

    // Initiator verifies the MIC and derives resumed session keys.
    initiator2
        .handle_sigma2_resume(&sigma2_resume)
        .expect("handle_sigma2_resume");

    // Step 5: Both sides agree on resumed session keys.
    let init_out2 = initiator2.finish().expect("initiator2 finish");
    let resp_out2 = responder2.finish().expect("responder2 finish");

    assert_eq!(
        init_out2.keys.i2r_key, resp_out2.keys.i2r_key,
        "both sides must derive matching i2r_key via resumption"
    );
    assert_eq!(
        init_out2.keys.r2i_key, resp_out2.keys.r2i_key,
        "both sides must derive matching r2i_key via resumption"
    );
    assert_eq!(
        init_out2.keys.attestation_challenge, resp_out2.keys.attestation_challenge,
        "both sides must agree on attestation_challenge via resumption"
    );

    // Resumed session keys MUST differ from the original new-session keys
    // (different HKDF inputs: shared_secret, salt=initiatorRandom||OLD_id).
    assert_ne!(
        init_out2.keys.i2r_key, initiator_out_1.keys.i2r_key,
        "resumed session keys must differ from original new-session keys"
    );

    // Peer identity is carried from the resumption record (no fresh NOC exchange).
    assert_eq!(
        init_out2.peer.node_id, RESPONDER_NODE_ID,
        "initiator sees responder's node_id after resumption"
    );
    assert_eq!(
        resp_out2.peer.node_id, INITIATOR_NODE_ID,
        "responder sees initiator's node_id after resumption"
    );

    // Both sides receive a fresh ResumptionRecord for the next session.
    let init_next = init_out2
        .resumption_record
        .expect("initiator gets a fresh resumption record");
    let resp_next = resp_out2
        .resumption_record
        .expect("responder gets a fresh resumption record");
    assert_eq!(
        init_next.id, resp_next.id,
        "both sides agree on the new resumption_id for the next session"
    );
    assert_ne!(
        init_next.id, resumption_id,
        "new resumption_id differs from the one we just used (responder generates fresh)"
    );
}

// ---------------------------------------------------------------------------
// Test: resumption declined → falls back to full Sigma1/2/3
// ---------------------------------------------------------------------------

/// Initiator presents a resumption record; responder calls
/// [`CaseResponder::reject_resumption`]; handshake falls back to the normal
/// new-session 3-message path and completes successfully.
#[test]
fn case_resumption_declined_falls_back_to_new_session() {
    let (_rcac, rcac_signer, trusted_roots, rcac_pub) = build_test_rcac();
    let (initiator_noc, initiator_signer) =
        build_test_noc(&rcac_signer, TEST_FABRIC_ID, INITIATOR_NODE_ID);
    let (responder_noc, responder_signer) =
        build_test_noc(&rcac_signer, TEST_FABRIC_ID, RESPONDER_NODE_ID);

    let initiator_creds = build_credentials(
        initiator_noc,
        initiator_signer,
        TEST_FABRIC_ID,
        INITIATOR_NODE_ID,
        IPK,
        rcac_pub,
    );
    let responder_creds = build_credentials(
        responder_noc.clone(),
        responder_signer,
        TEST_FABRIC_ID,
        RESPONDER_NODE_ID,
        IPK,
        rcac_pub,
    );

    // Initiator presents a (bogus) resumption_id; responder has no matching record
    // and will call reject_resumption.
    let bogus_peer_info = matter_crypto::PeerInfo {
        node_id: RESPONDER_NODE_ID,
        fabric_id: TEST_FABRIC_ID,
        noc: responder_noc,
        session_id: 0,
    };
    let bogus_record = matter_crypto::ResumptionRecord {
        id: matter_crypto::ResumptionId([0x99; 16]),
        shared_secret: [0xCC; 16],
        peer: bogus_peer_info,
        expires_at: None,
    };

    let mut initiator = CaseInitiator::new_with_resumption(
        initiator_creds,
        trusted_roots.clone(),
        RESPONDER_NODE_ID,
        TEST_FABRIC_ID,
        bogus_record,
    )
    .expect("initiator with resumption");
    let mut responder = CaseResponder::new(responder_creds, trusted_roots).expect("responder");

    let sigma1 = initiator.start().expect("sigma1");
    let outcome = responder.handle_sigma1(&sigma1).expect("handle sigma1");
    assert!(
        matches!(outcome, Sigma1Outcome::ResumptionRequested { .. }),
        "responder must surface ResumptionRequested when Sigma1 has resumption fields"
    );

    // Responder has no matching record — declines and falls back.
    responder.reject_resumption().expect("reject_resumption");

    // next_message() now returns a regular Sigma2, not Sigma2_Resume.
    let sigma2 = responder.next_message().expect("sigma2 (fallback)");

    // Initiator's handle_sigma2 takes the fallback new-session path.
    initiator
        .handle_sigma2(&sigma2)
        .expect("handle sigma2 (fallback)");
    let sigma3 = initiator.next_message().expect("sigma3 (fallback)");
    responder
        .handle_sigma3(&sigma3)
        .expect("handle sigma3 (fallback)");

    // Both sides must agree on session keys via the full new-session path.
    let init_out = initiator.finish().expect("initiator finish (fallback)");
    let resp_out = responder.finish().expect("responder finish (fallback)");
    assert_eq!(
        init_out.keys.i2r_key, resp_out.keys.i2r_key,
        "i2r_key must match after fallback to new-session"
    );
    assert_eq!(
        init_out.keys.r2i_key, resp_out.keys.r2i_key,
        "r2i_key must match after fallback to new-session"
    );
    assert_eq!(
        init_out.keys.attestation_challenge, resp_out.keys.attestation_challenge,
        "attestation_challenge must match after fallback to new-session"
    );
}

// ---------------------------------------------------------------------------
// Test: accept_resumption with mismatching id → InvalidParameter
// ---------------------------------------------------------------------------

/// If the caller supplies a [`ResumptionRecord`] whose `id` does not match
/// the `resumption_id` the initiator presented in Sigma1,
/// [`CaseResponder::accept_resumption`] must return
/// [`matter_crypto::Error::InvalidParameter`].
#[test]
fn case_resumption_wrong_id_returns_invalid_parameter() {
    let (_rcac, rcac_signer, trusted_roots, rcac_pub) = build_test_rcac();
    let (initiator_noc, initiator_signer) =
        build_test_noc(&rcac_signer, TEST_FABRIC_ID, INITIATOR_NODE_ID);
    let (responder_noc, responder_signer) =
        build_test_noc(&rcac_signer, TEST_FABRIC_ID, RESPONDER_NODE_ID);

    let initiator_creds = build_credentials(
        initiator_noc.clone(),
        initiator_signer,
        TEST_FABRIC_ID,
        INITIATOR_NODE_ID,
        IPK,
        rcac_pub,
    );
    let responder_creds = build_credentials(
        responder_noc.clone(),
        responder_signer,
        TEST_FABRIC_ID,
        RESPONDER_NODE_ID,
        IPK,
        rcac_pub,
    );

    // Initiator presents id = [0x42; 16].
    let presented_id = matter_crypto::ResumptionId([0x42; 16]);
    let initiator_record = matter_crypto::ResumptionRecord {
        id: presented_id,
        shared_secret: [0x77; 16],
        peer: matter_crypto::PeerInfo {
            node_id: RESPONDER_NODE_ID,
            fabric_id: TEST_FABRIC_ID,
            noc: responder_noc,
            session_id: 0,
        },
        expires_at: None,
    };

    // Responder's store has a record with a DIFFERENT id ([0x99; 16]).
    // accept_resumption must detect the mismatch and return InvalidParameter.
    let responder_record_wrong_id = matter_crypto::ResumptionRecord {
        id: matter_crypto::ResumptionId([0x99; 16]), // DIFFERENT from presented_id
        shared_secret: [0x77; 16],
        peer: matter_crypto::PeerInfo {
            node_id: INITIATOR_NODE_ID,
            fabric_id: TEST_FABRIC_ID,
            noc: initiator_noc,
            session_id: 0,
        },
        expires_at: None,
    };

    let mut initiator = CaseInitiator::new_with_resumption(
        initiator_creds,
        trusted_roots.clone(),
        RESPONDER_NODE_ID,
        TEST_FABRIC_ID,
        initiator_record,
    )
    .expect("initiator with resumption");
    let mut responder = CaseResponder::new(responder_creds, trusted_roots).expect("responder");

    let sigma1 = initiator.start().expect("sigma1");
    let outcome = responder.handle_sigma1(&sigma1).expect("handle sigma1");
    assert!(
        matches!(outcome, Sigma1Outcome::ResumptionRequested { .. }),
        "expected ResumptionRequested"
    );

    // accept_resumption with the WRONG id must return InvalidParameter.
    let err = responder
        .accept_resumption(responder_record_wrong_id)
        .expect_err("accept_resumption with wrong id must fail");
    assert!(
        matches!(err, matter_crypto::Error::InvalidParameter),
        "expected InvalidParameter, got {err:?}"
    );
}
