//! CASE certificate temporal-validity tests (audit finding H1).
//!
//! The live SIGMA handshake must enforce the peer operational certificate's
//! `not_before`/`not_after` window against an injected validation clock — not a
//! hardcoded constant. These tests drive a Sigma1→Sigma2 exchange (the initiator
//! verifying the responder's NOC inside `process_sigma2`) with the responder's
//! NOC deliberately placed outside, then inside, a chosen `validation_time`.
//!
//! Before the H1 fix the initiator validated peer chains at a fixed Unix
//! `2_000_000_000` (≈2033-05-18) stub, so an expired-but-chain-valid NOC was
//! wrongly accepted — `case_initiator_rejects_expired_peer_noc` fails until the
//! clock is actually threaded through.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use matter_cert::test_support::{build_unsigned, with_signature, TestCertFields};
use matter_cert::{
    BasicConstraints, DistinguishedName, DnAttribute, Extensions, KeyIdentifier, KeyUsage,
    MatterCertificate, MatterTime, PublicKey, Signature, TrustAnchor, TrustedRoots,
};
use matter_crypto::{CaseCredentials, CaseInitiator, CaseResponder, CaseSigner, Error, RingSigner};

const TEST_FABRIC_ID: u64 = 0x4242_4242_4242_4242;
const INITIATOR_NODE_ID: u64 = 0xDEAD_BEEF_CAFE_F00D;
const RESPONDER_NODE_ID: u64 = 0xBABE_FEED_1234_5678;
const IPK: [u8; 16] = [0x77; 16];

const TEST_SKI: [u8; 20] = [0x01; 20];
const NOC_SKI: [u8; 20] = [0x02; 20];

// Validity window endpoints (Unix seconds). The RCAC spans a wide window so it
// is always valid; only the responder NOC's window is varied per test.
const NOC_NOT_BEFORE_UNIX: u64 = 1_700_000_000; // 2023-11-14
const NOC_NOT_AFTER_UNIX: u64 = 1_800_000_000; // 2027-01-15

// A validation time strictly AFTER the responder NOC's not_after — the NOC is
// expired relative to this clock.
const AFTER_EXPIRY_UNIX: u64 = 1_900_000_000; // 2030-03-17
                                              // A validation time INSIDE the responder NOC's window.
const IN_VALIDITY_UNIX: u64 = 1_750_000_000; // 2025-06-15

/// Build a self-signed RCAC with a wide validity window that always covers the
/// chosen validation times.
fn build_test_rcac() -> (RingSigner, TrustedRoots, [u8; 65]) {
    let (rcac_signer, _pkcs8) = RingSigner::generate().expect("rcac signer");
    let rcac_pub = *rcac_signer.public_key().as_bytes();

    let rcac_dn = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);

    let extensions = Extensions {
        basic_constraints: Some(BasicConstraints {
            is_ca: true,
            path_len_constraint: Some(1),
        }),
        key_usage: Some(KeyUsage::KEY_CERT_SIGN),
        extended_key_usage: None,
        subject_key_identifier: Some(KeyIdentifier(TEST_SKI)),
        authority_key_identifier: Some(KeyIdentifier(TEST_SKI)),
    };

    let fields = TestCertFields {
        serial: vec![0x01],
        issuer: rcac_dn.clone(),
        not_before: MatterTime::from_unix_secs(1_600_000_000),
        not_after: MatterTime::from_unix_secs(2_500_000_000),
        subject: rcac_dn,
        public_key: PublicKey::new(rcac_pub).expect("rcac pub key"),
        extensions,
        signature: Signature::new([0u8; 64]),
    };
    let unsigned = build_unsigned(fields);

    let tbs = unsigned.to_x509_tbs_der().expect("rcac tbs");
    let sig_bytes = rcac_signer.sign_p256_sha256(&tbs).expect("rcac sign self");
    let rcac = with_signature(&unsigned, Signature::new(sig_bytes));

    let mut roots = TrustedRoots::new();
    roots.add(TrustAnchor::from_root_cert(&rcac));

    (rcac_signer, roots, rcac_pub)
}

/// Build a NOC signed by the RCAC with the given temporal validity window.
fn build_test_noc(
    rcac_signer: &RingSigner,
    fabric_id: u64,
    node_id: u64,
    not_before_unix: u64,
    not_after_unix: u64,
) -> (MatterCertificate, RingSigner) {
    let (noc_signer, _) = RingSigner::generate().expect("noc signer");
    let noc_pub = *noc_signer.public_key().as_bytes();

    let subject_dn = DistinguishedName::new(vec![
        DnAttribute::FabricId(fabric_id),
        DnAttribute::NodeId(node_id),
    ]);
    let issuer_dn = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);

    let extensions = Extensions {
        basic_constraints: Some(BasicConstraints {
            is_ca: false,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage::DIGITAL_SIGNATURE),
        extended_key_usage: None,
        subject_key_identifier: Some(KeyIdentifier(NOC_SKI)),
        authority_key_identifier: Some(KeyIdentifier(TEST_SKI)),
    };

    let fields = TestCertFields {
        serial: vec![0x02],
        issuer: issuer_dn,
        not_before: MatterTime::from_unix_secs(not_before_unix),
        not_after: MatterTime::from_unix_secs(not_after_unix),
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

/// Drive Sigma1→Sigma2 with the initiator constructed at `init_validation_time`
/// and the responder's NOC spanning `[NOC_NOT_BEFORE_UNIX, NOC_NOT_AFTER_UNIX]`.
/// Returns the result of `handle_sigma2` (the call inside which the initiator
/// validates the peer NOC chain at its injected clock).
fn run_sigma1_sigma2(init_validation_time: MatterTime) -> Result<(), Error> {
    let (rcac_signer, trusted_roots, rcac_pub) = build_test_rcac();

    let (initiator_noc, initiator_signer) = build_test_noc(
        &rcac_signer,
        TEST_FABRIC_ID,
        INITIATOR_NODE_ID,
        NOC_NOT_BEFORE_UNIX,
        NOC_NOT_AFTER_UNIX,
    );
    let (responder_noc, responder_signer) = build_test_noc(
        &rcac_signer,
        TEST_FABRIC_ID,
        RESPONDER_NODE_ID,
        NOC_NOT_BEFORE_UNIX,
        NOC_NOT_AFTER_UNIX,
    );

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

    // The responder's validation clock is held inside the NOC window so that
    // its handling of Sigma1 never fails; only the initiator's clock varies.
    let responder_validation_time = MatterTime::from_unix_secs(IN_VALIDITY_UNIX);

    let mut initiator = CaseInitiator::new(
        initiator_creds,
        trusted_roots.clone(),
        RESPONDER_NODE_ID,
        TEST_FABRIC_ID,
        0x0001,
        init_validation_time,
    )
    .expect("initiator construction");
    let mut responder = CaseResponder::new(
        responder_creds,
        trusted_roots,
        0x0002,
        responder_validation_time,
    )
    .expect("responder construction");

    let sigma1 = initiator.start().expect("sigma1");
    responder.handle_sigma1(&sigma1).expect("handle sigma1");
    let sigma2 = responder.next_message().expect("sigma2");
    initiator.handle_sigma2(&sigma2)
}

/// An expired peer NOC (`validation_time` strictly after its `not_after`) must be
/// rejected on the live handshake path with [`Error::InvalidPeerNocChain`].
#[test]
fn case_initiator_rejects_expired_peer_noc() {
    let result = run_sigma1_sigma2(MatterTime::from_unix_secs(AFTER_EXPIRY_UNIX));
    assert!(
        matches!(result, Err(Error::InvalidPeerNocChain(_))),
        "expired peer NOC must be rejected, got {result:?}"
    );
}

/// A peer NOC valid at the injected `validation_time` must complete Sigma2.
#[test]
fn case_initiator_accepts_in_validity_peer_noc() {
    let result = run_sigma1_sigma2(MatterTime::from_unix_secs(IN_VALIDITY_UNIX));
    assert!(
        result.is_ok(),
        "in-validity peer NOC must be accepted, got {result:?}"
    );
}
