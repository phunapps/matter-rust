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
//! - **Task 8** (this file): [`build_attestation_response`], [`build_csr_response`],
//!   [`load_cd_fixture`] – mock-device builders whose outputs the Commissioner's
//!   real verifiers accept.
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
// The verbatim-copied DER helpers from src/noc/csr.rs use intentional
// truncating casts and panic-in-if (matching the source's allow list).
#![allow(clippy::cast_possible_truncation, clippy::manual_assert)]

use std::path::PathBuf;

use base64::Engine;
use matter_cert::test_support::{build_x509_der, TestCertFields};
use matter_cert::{
    BasicConstraints, DistinguishedName, DnAttribute, Extensions, KeyUsage, MatterTime, Signature,
};
use matter_commissioning::attestation::{AttestationResponse, Paa, PaaTrustStore};
use matter_commissioning::CsrResponse;
use matter_crypto::{CaseSigner as _, RingSigner};
use serde::Deserialize;

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

// ── Task 8: mock-device attestation + CSR response builders ──────────────────

// ── Verbatim copy of DER / PKCS#10 helpers from src/noc/csr.rs #[cfg(test)]  ─
//
// These functions are self-contained test helpers originally defined in the
// `#[cfg(test)] mod tests` block inside `crates/matter-commissioning/src/noc/csr.rs`.
// They are copied verbatim here (with visibility adjusted to module-private) so
// `build_csr_response` can produce a well-formed, self-signed PKCS#10 CSR that
// `verify_csr_response` accepts.  Do NOT "improve" them — correctness parity with
// the source matters more than style.

/// Mint a synthetic PKCS#10 CSR for testing. Returns `(csr_der, public_key_bytes)`.
///
/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn mint_pkcs10_csr(seed: u8) -> (Vec<u8>, [u8; 65]) {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    // Deterministic 32-byte big-endian scalar.
    let mut scalar = [0u8; 32];
    scalar[0] = seed;
    let signing_key = SigningKey::from_slice(&scalar).unwrap();
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let mut public_key = [0u8; 65];
    public_key.copy_from_slice(encoded.as_bytes());

    let tbs_csr_info = build_pkcs10_csr_info(&public_key);
    let signature: Signature = signing_key.sign(&tbs_csr_info);
    let sig_der = signature.to_der().as_bytes().to_vec();

    let csr_der = wrap_pkcs10_csr(&tbs_csr_info, &sig_der);
    (csr_der, public_key)
}

/// Encode CertificationRequestInfo for a P-256 public key with an
/// empty subject and empty attribute set.
///
/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn build_pkcs10_csr_info(public_key_sec1: &[u8; 65]) -> Vec<u8> {
    let alg_id = encode_der_sequence(&[
        &encode_der_oid(&[1, 2, 840, 10045, 2, 1]),
        &encode_der_oid(&[1, 2, 840, 10045, 3, 1, 7]),
    ]);
    let pk_bit_string = encode_der_bit_string(public_key_sec1);
    let subject_pk_info = encode_der_sequence(&[&alg_id, &pk_bit_string]);
    let subject = encode_der_sequence(&[]);
    let version = encode_der_integer_zero();
    let attributes = encode_der_context_implicit_set(0, &[]);
    encode_der_sequence(&[&version, &subject, &subject_pk_info, &attributes])
}

/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn wrap_pkcs10_csr(tbs: &[u8], signature_der: &[u8]) -> Vec<u8> {
    let alg_id = encode_der_sequence(&[&encode_der_oid(&[1, 2, 840, 10045, 4, 3, 2])]);
    let sig_bit_string = encode_der_bit_string(signature_der);
    encode_der_sequence(&[tbs, &alg_id, &sig_bit_string])
}

/// Compose a synthetic NOCSR TLV blob from raw fields.
///
/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn write_nocsr(
    csr_der: &[u8],
    nonce: &[u8; 32],
    vr1: Option<&[u8]>,
    vr2: Option<&[u8]>,
    vr3: Option<&[u8]>,
) -> Vec<u8> {
    use matter_codec::{Tag, TlvWriter};
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).unwrap();
    w.put_bytes(Tag::Context(1), csr_der).unwrap();
    w.put_bytes(Tag::Context(2), nonce).unwrap();
    if let Some(b) = vr1 {
        w.put_bytes(Tag::Context(3), b).unwrap();
    }
    if let Some(b) = vr2 {
        w.put_bytes(Tag::Context(4), b).unwrap();
    }
    if let Some(b) = vr3 {
        w.put_bytes(Tag::Context(5), b).unwrap();
    }
    w.end_container().unwrap();
    buf
}

/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn encode_der_length(body_len: usize) -> Vec<u8> {
    if body_len < 0x80 {
        vec![body_len as u8]
    } else if body_len <= 0xff {
        vec![0x81, body_len as u8]
    } else if body_len <= 0xffff {
        vec![0x82, (body_len >> 8) as u8, body_len as u8]
    } else {
        panic!("test helper: length too big");
    }
}

/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn encode_der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_der_length(body.len()));
    out.extend_from_slice(body);
    out
}

/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn encode_der_sequence(parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for p in parts {
        body.extend_from_slice(p);
    }
    encode_der_tlv(0x30, &body)
}

/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn encode_der_integer_zero() -> Vec<u8> {
    encode_der_tlv(0x02, &[0x00])
}

/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn encode_der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes.len() + 1);
    body.push(0x00);
    body.extend_from_slice(bytes);
    encode_der_tlv(0x03, &body)
}

/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn encode_der_context_implicit_set(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for p in parts {
        body.extend_from_slice(p);
    }
    encode_der_tlv(0xA0 | tag, &body)
}

/// Copied verbatim from `src/noc/csr.rs` `#[cfg(test)] mod tests`.
fn encode_der_oid(arcs: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    if arcs.len() < 2 {
        panic!("OID needs at least two arcs");
    }
    body.push((arcs[0] * 40 + arcs[1]) as u8);
    for arc in &arcs[2..] {
        let mut a = *arc;
        let mut digits = Vec::new();
        digits.push((a & 0x7f) as u8);
        a >>= 7;
        while a > 0 {
            digits.push(((a & 0x7f) | 0x80) as u8);
            a >>= 7;
        }
        digits.reverse();
        body.extend_from_slice(&digits);
    }
    encode_der_tlv(0x06, &body)
}

// ── CD fixture loading ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CdFixture {
    cd_b64: String,
}

/// Load the Certification Declaration bytes from
/// `test-vectors/commissioning/cd/happy-path.json`.
///
/// The fixture contains a `cd_b64` field with a standard base64-encoded
/// CMS/PKCS#7 `SignedData` blob.  The encoded CD covers VID 0xFFF1 and
/// PID 0x8001 — matching [`VID`] and [`PID`] in the mock PKI.
///
/// # Panics
///
/// Panics if the fixture file is missing or the JSON/base64 is malformed.
/// These would indicate a broken test environment, not a test logic error.
pub fn load_cd_fixture() -> Vec<u8> {
    let mut path: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    path.push("..");
    path.push("..");
    path.push("test-vectors");
    path.push("commissioning");
    path.push("cd");
    path.push("happy-path.json");

    let raw = std::fs::read_to_string(&path).expect("CD fixture file present");
    let f: CdFixture = serde_json::from_str(&raw).expect("CD fixture parses as JSON");
    base64::engine::general_purpose::STANDARD
        .decode(f.cd_b64.as_bytes())
        .expect("cd_b64 is valid base64")
}

// ── Attestation response builder ──────────────────────────────────────────────

/// Fixed timestamp used in `attestation_elements` (seconds since Matter epoch
/// `2000-01-01T00:00:00Z`).  Matches the `AT_UNIX` anchor in `mock_pki.rs`
/// (Unix time 1_800_000_000 ≈ 2027-01-15T08:00:00Z) converted to Matter epoch
/// by subtracting `MATTER_EPOCH_UNIX_SECS` = 946_684_800.
///
/// The `extract_attestation_elements_fields` verifier does not range-check the
/// timestamp, so any fixed value is acceptable.
const AT_MATTER_EPOCH_SECS: u64 = 1_800_000_000u64.saturating_sub(946_684_800);

/// Build a mock-device `AttestationResponse` for use in loopback tests.
///
/// Wire layout of `attestation_elements` (Matter Core Spec §6.2.4, anonymous
/// TLV structure):
/// - Context tag 1: `certification_declaration` (octet string — the CD bytes).
/// - Context tag 2: `attestation_nonce` (32-byte octet string).
/// - Context tag 3: `timestamp` (u64, Matter-epoch seconds).
///
/// The `signature` field is the DAC private key's ECDSA-P256-SHA256 (IEEE P1363
/// fixed-width, 64 bytes) over `attestation_elements || attestation_challenge`.
///
/// # Panics
///
/// Panics if signing fails (not expected for a valid `RingSigner`).
pub fn build_attestation_response(
    cd_bytes: &[u8],
    nonce: [u8; 32],
    challenge: [u8; 16],
    dac_signer: &RingSigner,
) -> AttestationResponse {
    use matter_codec::{Tag, TlvWriter};

    // Build attestation_elements TLV:
    //   { 1: cd_bytes, 2: nonce, 3: timestamp }
    let mut elements = Vec::new();
    {
        let mut w = TlvWriter::new(&mut elements);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bytes(Tag::Context(1), cd_bytes).unwrap();
        w.put_bytes(Tag::Context(2), &nonce).unwrap();
        w.put_uint(Tag::Context(3), AT_MATTER_EPOCH_SECS).unwrap();
        w.end_container().unwrap();
    }

    // Sign over elements || challenge.
    let mut tbs = Vec::with_capacity(elements.len() + challenge.len());
    tbs.extend_from_slice(&elements);
    tbs.extend_from_slice(&challenge);
    let signature = dac_signer
        .sign_p256_sha256(&tbs)
        .expect("DAC signing must not fail");

    AttestationResponse {
        attestation_elements: elements,
        signature,
    }
}

// ── CSR response builder ──────────────────────────────────────────────────────

/// Build a mock-device `CSRResponse` for use in loopback tests.
///
/// Wire layout of `nocsr_elements` (Matter Core Spec §11.18.5.6, anonymous
/// TLV structure):
/// - Context tag 1: `csr` (PKCS#10 DER, self-signed with a fresh operational key).
/// - Context tag 2: `csr_nonce` (32-byte octet string — echoes the commissioner's nonce).
///
/// The `attestation_signature` field is the DAC private key's ECDSA-P256-SHA256
/// (IEEE P1363 fixed-width, 64 bytes) over `nocsr_elements || attestation_challenge`.
///
/// The embedded PKCS#10 CSR is generated with `seed=0x42` (deterministic).
/// Task 10/11 only need the CSR's public key to issue a NOC; the exact
/// operational key does not matter for the loopback gate.
///
/// # Panics
///
/// Panics if signing fails (not expected for a valid `RingSigner`).
pub fn build_csr_response(
    csr_nonce: [u8; 32],
    challenge: [u8; 16],
    dac_signer: &RingSigner,
) -> CsrResponse {
    // Mint a synthetic PKCS#10 CSR (self-signed with seed 0x42).
    let (csr_der, _csr_pubkey) = mint_pkcs10_csr(0x42);

    // Build nocsr_elements TLV: { 1: csr_der, 2: csr_nonce }.
    let nocsr_elements = write_nocsr(&csr_der, &csr_nonce, None, None, None);

    // Sign over nocsr_elements || challenge.
    let mut tbs = Vec::with_capacity(nocsr_elements.len() + challenge.len());
    tbs.extend_from_slice(&nocsr_elements);
    tbs.extend_from_slice(&challenge);
    let attestation_signature = dac_signer
        .sign_p256_sha256(&tbs)
        .expect("DAC signing must not fail");

    CsrResponse {
        nocsr_elements,
        attestation_signature,
    }
}
