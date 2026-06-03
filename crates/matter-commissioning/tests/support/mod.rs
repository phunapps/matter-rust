//! Shared integration-test infrastructure for the M6.6.4 commission-loopback
//! test suite.
//!
//! This module is compiled as part of the `tests/` tree. It is declared from
//! each loopback test file via `mod support;`. Production code must never
//! depend on anything in this module.
//!
//! # Contents (grows across Tasks 7b-11)
//!
//! - **Task 7b** (this file): [`build_mock_device_pki`] – synthetic PAA/PAI/DAC
//!   chain accepted by the Commissioner's real `verify_chain`.
//!
//! # Key PKCS#8 compatibility note
//!
//! [`matter_crypto::RingSigner::generate`] generates keys via
//! `ring::signature::EcdsaKeyPair::generate_pkcs8` with
//! `ECDSA_P256_SHA256_FIXED_SIGNING`. The [`matter_cert::test_support::build_x509_der`]
//! helper loads the issuer PKCS#8 with `ECDSA_P256_SHA256_ASN1_SIGNING`. Both
//! signing variants share the same PKCS#8 v1 DER key format for P-256 — only
//! the *output* encoding of the signature differs (fixed/IEEE-P1363 vs.
//! ASN.1/DER). Cross-loading the PKCS#8 therefore works without any conversion.
//! This was verified empirically by the Task 7b gate test in `mock_pki.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// Domain acronyms (PAA, PAI, DAC, VID, PID, EKU, PKCS#8) are prose, not code items.
#![allow(clippy::doc_markdown)]
// paa_pkcs8 / pai_pkcs8 are intentionally paired names.
#![allow(clippy::similar_names)]
// `pub` items in test support modules are used by sibling test binaries
// (commission_loopback.rs in Task 12). Clippy sees this module in isolation
// and thinks they're unreachable; they're not.
#![allow(dead_code, unreachable_pub)]

use matter_cert::test_support::{build_x509_der, TestCertFields};
use matter_cert::{
    BasicConstraints, DistinguishedName, DnAttribute, Extensions, KeyUsage, MatterTime, Signature,
};
use matter_commissioning::attestation::{Paa, PaaTrustStore};
use matter_crypto::{CaseSigner as _, RingSigner};

// ── Constants ────────────────────────────────────────────────────────────────

/// Vendor ID used for the mock device's DAC/PAI (and PAA for completeness).
///
/// 0xFFF1 is the CSA test-fixture VID. MUST match the Certification Declaration
/// fixture used in Task 8's CD verification step.
pub const VID: u16 = 0xFFF1;

/// Product ID encoded in the mock device's DAC.
///
/// MUST match the Certification Declaration fixture used in Task 8.
pub const PID: u16 = 0x8001;

/// EKU compact integer for `id-kp-clientAuth` (OID 1.3.6.1.5.5.7.3.2).
///
/// The `matter-cert` X.509 encoder maps integer `2` to the clientAuth EKU
/// in the `ExtendedKeyUsage` extension. See `x509_builder_gate.rs`.
const EKU_CLIENT_AUTH: u32 = 2;

// ── MockDevicePki ─────────────────────────────────────────────────────────────

/// Synthetic PAA → PAI → DAC chain for use in loopback tests.
///
/// Built by [`build_mock_device_pki`] and validated against the Commissioner's
/// real `verify_chain` before being wired into the mock responder (Task 9).
///
/// The chain uses VID [`VID`] (0xFFF1) and PID [`PID`] (0x8001), matching the
/// CSA Certification Declaration fixture used in Task 8's CD verification.
pub struct MockDevicePki {
    /// The DAC's private key. Used by the mock device to sign
    /// `AttestationElements` (Task 8) and the NOCSR (Task 9). This is what
    /// proves device identity during commissioning.
    pub dac_signer: RingSigner,
    /// DER-encoded Device Attestation Certificate (leaf, not CA).
    ///
    /// Carry this in the `AttestationResponse` TLV (`dac_der` field).
    pub dac_der: Vec<u8>,
    /// DER-encoded Product Attestation Intermediate certificate (CA, pathLen 0).
    ///
    /// Carry this in the `AttestationResponse` TLV (`pai_der` field).
    pub pai_der: Vec<u8>,
    /// DER-encoded Product Attestation Authority certificate (self-signed root).
    ///
    /// Pre-loaded into [`paa_trust_store`](Self::paa_trust_store). Exposed here
    /// so tests can inspect the raw DER if needed.
    pub paa_der: Vec<u8>,
    /// A [`PaaTrustStore`] pre-seeded with the synthetic PAA.
    ///
    /// Pass this to `attestation::chain::verify_chain` (or the Commissioner's
    /// attestation verifier in Task 9) so the chain validates.
    pub paa_trust_store: PaaTrustStore,
}

// ── Chain builder ─────────────────────────────────────────────────────────────

/// Build a synthetic PAA → PAI → DAC chain anchored at `now`.
///
/// All three certificates are generated fresh for each call (new key pairs via
/// [`RingSigner::generate`]). The validity windows bracket `now`:
///
/// - PAA: `now - 365 days` … `now + 3650 days`
/// - PAI: `now - 180 days` … `now + 1825 days`
/// - DAC: `now - 30 days`  … `now + 365 days`
///
/// The extension recipe follows `x509_builder_gate.rs` and the CSA
/// `gen-negative-fixtures.py` reference:
/// - PAA: `BasicConstraints CA:true, pathLen:1` (critical); `KeyUsage keyCertSign+cRLSign` (critical)
/// - PAI: `BasicConstraints CA:true, pathLen:0` (critical); `KeyUsage keyCertSign+cRLSign` (critical); subject VID 0xFFF1
/// - DAC: `BasicConstraints CA:false` (critical); `KeyUsage digitalSignature` (critical); `ExtendedKeyUsage clientAuth` (non-critical); subject VID 0xFFF1 + PID 0x8001
///
/// # Panics
///
/// Panics on any key-generation or DER-encoding failure. These would indicate
/// a broken environment (OS RNG failure, ring/p256 API regression) rather than
/// a test logic error.
pub fn build_mock_device_pki(now: MatterTime) -> MockDevicePki {
    let now_unix = now.to_unix_secs();

    // ── PAA: self-signed root ────────────────────────────────────────────────
    let (paa_signer, paa_pkcs8) = RingSigner::generate().expect("PAA key generation");
    let paa_pk = paa_signer.public_key().clone();

    let paa_dn = DistinguishedName::new(vec![
        DnAttribute::CommonName("Matter Test PAA (mock-device)".into()),
        DnAttribute::VendorId(VID),
    ]);
    let paa_der = build_x509_der(
        TestCertFields {
            serial: vec![0x01],
            issuer: paa_dn.clone(), // self-signed: issuer == subject
            not_before: MatterTime::from_unix_secs(now_unix.saturating_sub(365 * 86_400)),
            not_after: MatterTime::from_unix_secs(now_unix.saturating_add(3650 * 86_400)),
            subject: paa_dn.clone(),
            public_key: paa_pk,
            extensions: Extensions {
                basic_constraints: Some(BasicConstraints {
                    is_ca: true,
                    path_len_constraint: Some(1),
                }),
                key_usage: Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN),
                ..Default::default()
            },
            signature: Signature::new([0u8; 64]),
        },
        &paa_pkcs8, // self-signed
    )
    .expect("PAA DER build");

    // ── PAI: signed by PAA, VID-scoped ───────────────────────────────────────
    let (pai_signer, pai_pkcs8) = RingSigner::generate().expect("PAI key generation");
    let pai_pk = pai_signer.public_key().clone();

    let pai_dn = DistinguishedName::new(vec![
        DnAttribute::CommonName("Matter Test PAI (mock-device)".into()),
        DnAttribute::VendorId(VID),
    ]);
    let pai_der = build_x509_der(
        TestCertFields {
            serial: vec![0x02],
            issuer: paa_dn, // byte-for-byte == PAA subject
            not_before: MatterTime::from_unix_secs(now_unix.saturating_sub(180 * 86_400)),
            not_after: MatterTime::from_unix_secs(now_unix.saturating_add(1825 * 86_400)),
            subject: pai_dn.clone(),
            public_key: pai_pk,
            extensions: Extensions {
                basic_constraints: Some(BasicConstraints {
                    is_ca: true,
                    path_len_constraint: Some(0),
                }),
                key_usage: Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN),
                ..Default::default()
            },
            signature: Signature::new([0u8; 64]),
        },
        &paa_pkcs8, // signed by PAA
    )
    .expect("PAI DER build");

    // The PAI signer is not returned (only the PAA signer was used for signing
    // the PAI cert, and the PAI private key signs the DAC). Suppress the warning.
    let _ = pai_signer;

    // ── DAC: leaf, signed by PAI, VID + PID, clientAuth EKU ─────────────────
    let (dac_signer, _dac_pkcs8) = RingSigner::generate().expect("DAC key generation");
    let dac_pk = dac_signer.public_key().clone();

    let dac_dn = DistinguishedName::new(vec![
        DnAttribute::CommonName("Matter Test DAC (mock-device)".into()),
        DnAttribute::VendorId(VID),
        DnAttribute::ProductId(PID),
    ]);
    let dac_der = build_x509_der(
        TestCertFields {
            serial: vec![0x03],
            issuer: pai_dn, // byte-for-byte == PAI subject
            not_before: MatterTime::from_unix_secs(now_unix.saturating_sub(30 * 86_400)),
            not_after: MatterTime::from_unix_secs(now_unix.saturating_add(365 * 86_400)),
            subject: dac_dn,
            public_key: dac_pk,
            extensions: Extensions {
                basic_constraints: Some(BasicConstraints {
                    is_ca: false,
                    path_len_constraint: None,
                }),
                key_usage: Some(KeyUsage::DIGITAL_SIGNATURE),
                extended_key_usage: Some(vec![EKU_CLIENT_AUTH]),
                ..Default::default()
            },
            signature: Signature::new([0u8; 64]),
        },
        &pai_pkcs8, // DAC is signed by PAI
    )
    .expect("DAC DER build");

    // ── Trust store ───────────────────────────────────────────────────────────
    let mut paa_trust_store = PaaTrustStore::empty();
    paa_trust_store.add(Paa::from_der(&paa_der).expect("PAA parses back"));

    MockDevicePki {
        dac_signer,
        dac_der,
        pai_der,
        paa_der,
        paa_trust_store,
    }
}
