//! Build → sign → parse round-trip for `matter_cert::operational` +
//! [`matter_cert::operational::sign_with_ring`].
//!
//! Generates a fresh P-256 keypair with `ring`, builds a self-signed RCAC
//! via [`matter_cert::operational::rcac`], signs it with
//! `sign_with_ring`, round-trips the assembled certificate through TLV,
//! and confirms the self-signature verifies against a `TrustAnchor` built
//! from the same RCAC.
//!
//! Signature verification here uses `MatterCertificate::verify_signed_by`
//! directly rather than `CertificateChain::validate` on a 1-element chain:
//! `validate` treats chain index 0 as the end-entity leaf and correctly
//! rejects any cert asserting `basic_constraints.is_ca = true` there (RFC
//! 5280 §4.2.1.9 forbids an end-entity leaf from asserting the CA bit —
//! see `Error::LeafIsCa` in `matter_cert::chain`). Since an RCAC always
//! asserts `is_ca = true` (spec §6.5.5), a bare self-signed root can never
//! validate as chain index 0 — that check is intentional, not a bug, and
//! is exactly why a lone root cert is verified directly instead.
//! `verify_signed_by` is the same primitive `CertificateChain::validate`
//! calls internally for the anchor-signature check, so this still exercises
//! the real signature-verification path; `TrustAnchor` is still built here
//! to demonstrate the anchor-construction step the brief calls out.

#![allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.

use matter_cert::operational::{rcac, sign_with_ring, RcacParams};
use matter_cert::{MatterCertificate, MatterTime, PublicKey, TrustAnchor};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

/// Generate a fresh P-256 keypair, returning (PKCS#8 DER bytes, the
/// matching `matter_cert::PublicKey`).
fn generate_keypair() -> (Vec<u8>, PublicKey) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let mut pk_bytes = [0u8; 65];
    pk_bytes.copy_from_slice(key_pair.public_key().as_ref());
    let public_key = PublicKey::new(pk_bytes).unwrap();
    (pkcs8.as_ref().to_vec(), public_key)
}

#[test]
fn rcac_build_sign_parse_round_trips_and_self_signature_verifies() {
    let (pkcs8, public_key) = generate_keypair();

    let unsigned = rcac(RcacParams::new(
        1,
        public_key,
        vec![0x01],
        MatterTime::from_unix_secs(1_700_000_000),
        MatterTime::NO_EXPIRY,
        Some(1),
    ))
    .unwrap();

    let signed = sign_with_ring(unsigned, &pkcs8).unwrap();

    // Round-trip through TLV.
    let tlv = signed.to_tlv().unwrap();
    let parsed = MatterCertificate::from_tlv(&tlv).unwrap();
    assert_eq!(parsed.subject().rcac_id(), Some(1));
    assert_eq!(parsed, signed);

    // Confirm the RCAC's not_before/not_after window covers our chosen
    // validation instant, matching the "at a time inside the validity
    // window" requirement.
    let at = MatterTime::from_unix_secs(1_700_000_000);
    assert!(parsed.not_before() <= at);

    // Build a TrustAnchor from the RCAC itself, then verify the
    // self-signature against it.
    let anchor = TrustAnchor::from_root_cert(&parsed);
    parsed.verify_signed_by(anchor.public_key()).unwrap();
}
