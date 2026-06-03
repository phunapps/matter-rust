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

// ── Task 9: device-side Interaction Model codec ───────────────────────────────
//
// The mock device's responder loop (Task 11) needs to:
//   1. Receive the controller's IM request bytes.
//   2. `parse_invoke_request` / `parse_read_request` — device decodes what
//      the controller sent.
//   3. Compute a response.
//   4. `build_invoke_response` / `build_report_data` — device encodes the reply.
//
// These four functions are the **exact inverse** of the controller-side `im`
// codec in `crates/matter-commissioning/src/im/`. Tag layouts are derived
// directly from `im/invoke.rs` and `im/read.rs` — see the cross-references in
// each function's doc comment.

// ── Private TLV helpers ───────────────────────────────────────────────────────
//
// The production `im` module exports `expect_message_struct`, `read_container_members`,
// `read_container_value`, and `skip_container` as `pub(crate)`, which is not
// accessible from integration tests. We re-implement minimal equivalents here.

/// Skip a container that has already been opened (reader positioned just
/// after the `ContainerStart`). Panics on malformed input.
fn tlv_skip_container(r: &mut matter_codec::TlvReader<'_>) {
    use matter_codec::Element;
    let mut depth = 1usize;
    loop {
        match r.next().expect("tlv_skip_container: unexpected EOF") {
            Some(Element::ContainerEnd) => {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            }
            Some(Element::ContainerStart { .. }) => depth += 1,
            None => panic!("tlv_skip_container: stream ended before container closed"),
            Some(_) => {}
        }
    }
}

/// Collect all members of an already-opened container (reader positioned just
/// after the `ContainerStart`) as `(Tag, Value)` pairs. Panics on malformed input.
fn tlv_read_members(
    r: &mut matter_codec::TlvReader<'_>,
) -> Vec<(matter_codec::Tag, matter_codec::Value)> {
    use matter_codec::Element;
    let mut out = Vec::new();
    loop {
        match r.next().expect("tlv_read_members: unexpected EOF") {
            Some(Element::ContainerEnd) => return out,
            None => panic!("tlv_read_members: stream ended before container closed"),
            Some(Element::Scalar { tag, value }) => out.push((tag, value)),
            Some(Element::ContainerStart { tag, kind }) => {
                let v = tlv_read_container_value(r, kind);
                out.push((tag, v));
            }
            Some(_) => {}
        }
    }
}

/// Read the body of an already-opened container of `kind` into a [`matter_codec::Value`].
fn tlv_read_container_value(
    r: &mut matter_codec::TlvReader<'_>,
    kind: matter_codec::ContainerKind,
) -> matter_codec::Value {
    let members = tlv_read_members(r);
    match kind {
        matter_codec::ContainerKind::Structure => matter_codec::Value::Structure(members),
        matter_codec::ContainerKind::Array => {
            matter_codec::Value::Array(members.into_iter().map(|(_, v)| v).collect())
        }
        _ => matter_codec::Value::List(members),
    }
}

/// Parsed single-command `InvokeRequestMessage` (device perspective).
///
/// `fields_tlv` is the `CommandFields` struct re-encoded with an **anonymous**
/// tag, matching the convention used by the production `im::parse_invoke_response`.
pub struct InvokeRequestDecoded {
    /// Path of the incoming command.
    pub path: matter_commissioning::im::CommandPath,
    /// The command-fields struct, re-encoded with an anonymous tag.
    pub fields_tlv: Vec<u8>,
}

/// Parse a single-command `InvokeRequestMessage` produced by
/// [`matter_commissioning::im::build_invoke_request`] (device side).
///
/// Wire layout consumed (derived from `im/invoke.rs::build_invoke_request`):
/// ```text
/// anon struct {
///   ctx(0): bool  SuppressResponse
///   ctx(1): bool  TimedRequest
///   ctx(2): array InvokeRequests [
///     anon struct CommandDataIB {
///       ctx(0): list  CommandPathIB { ctx(0): endpoint, ctx(1): cluster, ctx(2): command }
///       ctx(1): struct CommandFields  (pre-encoded anonymous struct)
///     }
///   ]
///   ctx(0xFF): uint InteractionModelRevision
/// }
/// ```
///
/// Returns `(path, anonymous-tagged CommandFields bytes)`.
///
/// # Panics
///
/// Panics if `bytes` is not a valid `InvokeRequestMessage`. Acceptable in test
/// support code where the input is always controller-generated.
pub fn parse_invoke_request(bytes: &[u8]) -> InvokeRequestDecoded {
    use matter_codec::{ContainerKind, Element, Tag, TlvReader, Value};
    use matter_commissioning::im::CommandPath;

    let mut r = TlvReader::new(bytes);

    // Consume top-level anonymous struct start.
    match r.next().expect("InvokeRequest: first element") {
        Some(Element::ContainerStart {
            tag: Tag::Anonymous,
            kind: ContainerKind::Structure,
        }) => {}
        other => panic!("InvokeRequest: expected anon struct, got {other:?}"),
    }

    // Scan forward to ctx(2) = InvokeRequests array.
    loop {
        match r.next().expect("InvokeRequest: scan for InvokeRequests") {
            Some(Element::ContainerStart {
                tag: Tag::Context(2),
                kind: ContainerKind::Array,
            }) => break,
            Some(Element::ContainerEnd) | None => {
                panic!("InvokeRequest: missing InvokeRequests array")
            }
            Some(Element::ContainerStart { .. }) => {
                // Skip any unknown container (e.g. SuppressResponse is a scalar, but be safe).
                tlv_skip_container(&mut r);
            }
            Some(_) => {}
        }
    }

    // Expect the first CommandDataIB (anonymous struct).
    match r.next().expect("InvokeRequest: first CommandDataIB") {
        Some(Element::ContainerStart {
            kind: ContainerKind::Structure,
            ..
        }) => {}
        _ => panic!("InvokeRequest: missing CommandDataIB struct"),
    }

    // Parse CommandDataIB body: scan for CommandPathIB (ctx 0) and CommandFields (ctx 1).
    let mut path: Option<CommandPath> = None;
    let mut fields_tlv: Vec<u8> = Vec::new();
    loop {
        match r.next().expect("InvokeRequest: scan CommandDataIB members") {
            None => panic!("InvokeRequest: CommandDataIB body ended without end-of-container"),
            Some(Element::ContainerEnd) => break,
            // CommandPathIB list at context tag 0 (matches build_invoke_request → write_command_path).
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::List,
            }) => {
                let members = tlv_read_members(&mut r);
                let mut endpoint = None;
                let mut cluster = None;
                let mut command = None;
                for (tag, v) in members {
                    match (tag, v) {
                        (Tag::Context(0), Value::Uint(n)) => {
                            endpoint = Some(u16::try_from(n).expect("endpoint fits u16"));
                        }
                        (Tag::Context(1), Value::Uint(n)) => {
                            cluster = Some(u32::try_from(n).expect("cluster fits u32"));
                        }
                        (Tag::Context(2), Value::Uint(n)) => {
                            command = Some(u32::try_from(n).expect("command fits u32"));
                        }
                        _ => {}
                    }
                }
                path = Some(CommandPath {
                    endpoint: endpoint.expect("CommandPath.endpoint present"),
                    cluster: cluster.expect("CommandPath.cluster present"),
                    command: command.expect("CommandPath.command present"),
                });
            }
            // CommandFields struct at context tag 1 — re-encode as anonymous-tagged blob.
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind,
            }) => {
                let v = tlv_read_container_value(&mut r, kind);
                let mut buf = Vec::new();
                let mut w = matter_codec::TlvWriter::new(&mut buf);
                w.write_value(Tag::Anonymous, &v)
                    .expect("InvokeRequest: re-encode CommandFields");
                fields_tlv = buf;
            }
            Some(Element::ContainerStart { .. }) => tlv_skip_container(&mut r),
            Some(_) => {}
        }
    }

    // No CommandFields → canonicalize to an anonymous empty struct (matches
    // the same convention in `im/invoke.rs::parse_command_data`).
    if fields_tlv.is_empty() {
        let mut buf = Vec::new();
        let mut w = matter_codec::TlvWriter::new(&mut buf);
        w.write_value(Tag::Anonymous, &Value::Structure(Vec::new()))
            .expect("encode empty struct");
        fields_tlv = buf;
    }

    InvokeRequestDecoded {
        path: path.expect("CommandDataIB.CommandPath present"),
        fields_tlv,
    }
}

/// Build an `InvokeResponseMessage` carrying a single `CommandDataIB`.
///
/// Produces bytes that [`matter_commissioning::im::parse_invoke_response`]
/// decodes to `InvokeResponse::Command { path, fields_tlv }`.
///
/// Wire layout produced (derived from `im/invoke.rs::parse_invoke_response`
/// and the proven `build_canned_invoke_response` template in
/// `src/driver/commission.rs`):
/// ```text
/// anon struct {
///   ctx(0): bool  SuppressResponse  (false)
///   ctx(1): array InvokeResponses [
///     anon struct InvokeResponseIB {
///       ctx(0): struct CommandDataIB {
///         ctx(0): list  CommandPathIB { ctx(0): ep, ctx(1): cluster, ctx(2): cmd }
///         ctx(1): struct CommandFields  (re-tagged from anonymous via put_preencoded)
///       }
///     }
///   ]
///   ctx(0xFF): uint InteractionModelRevision
/// }
/// ```
///
/// `fields_tlv` must be an anonymous-tagged TLV struct (e.g. `[0x15, 0x18]`
/// for an empty struct). `put_preencoded` re-tags it to context tag 1.
///
/// # Panics
///
/// Panics if `fields_tlv` is not a valid anonymous-tagged TLV struct. Acceptable
/// in test support code where the input is always codec-generated.
pub fn build_invoke_response(
    path: matter_commissioning::im::CommandPath,
    fields_tlv: &[u8],
) -> Vec<u8> {
    use matter_codec::{Tag, TlvWriter};

    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseMessage
    w.put_bool(Tag::Context(0), false).unwrap(); // SuppressResponse
    w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
    {
        w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
        w.start_structure(Tag::Context(0)).unwrap(); // Command = CommandDataIB
                                                     // CommandPathIB list at ctx(0).
        w.start_list(Tag::Context(0)).unwrap();
        w.put_uint(Tag::Context(0), u64::from(path.endpoint))
            .unwrap();
        w.put_uint(Tag::Context(1), u64::from(path.cluster))
            .unwrap();
        w.put_uint(Tag::Context(2), u64::from(path.command))
            .unwrap();
        w.end_container().unwrap(); // CommandPathIB
                                    // CommandFields at ctx(1): splice the anonymous struct blob under context tag 1.
        w.put_preencoded(Tag::Context(1), fields_tlv).unwrap();
        w.end_container().unwrap(); // CommandDataIB
        w.end_container().unwrap(); // InvokeResponseIB
    }
    w.end_container().unwrap(); // InvokeResponses
    w.put_uint(
        Tag::Context(0xFF),
        u64::from(matter_commissioning::im::IM_REVISION),
    )
    .unwrap();
    w.end_container().unwrap(); // InvokeResponseMessage
    buf
}

/// Build an `InvokeResponseMessage` carrying a bare `CommandStatusIB` (status only,
/// no command data). Produces bytes that
/// [`matter_commissioning::im::parse_invoke_response`] decodes to
/// `InvokeResponse::Status(status)`.
///
/// Wire layout produced (derived from `im/invoke.rs::parse_command_status` and the
/// `parses_status_response` test in `im/invoke.rs`):
/// ```text
/// anon struct {
///   ctx(0): bool  SuppressResponse  (false)
///   ctx(1): array InvokeResponses [
///     anon struct InvokeResponseIB {
///       ctx(1): struct CommandStatusIB {           ← Status variant (not Command)
///         ctx(0): list  CommandPathIB { ctx(0): ep, ctx(1): cluster, ctx(2): cmd }
///         ctx(1): struct StatusIB { ctx(0): Status u8 }
///       }
///     }
///   ]
///   ctx(0xFF): uint InteractionModelRevision
/// }
/// ```
///
/// `status_code` is the raw `ImStatus` byte (0x00 = Success).
/// The `path` parameter is required by the `CommandStatusIB` wire format even for
/// success responses.
///
/// # Panics
///
/// Vec-backed `TlvWriter` is infallible; panics indicate a logic error.
pub fn build_invoke_status_response(
    path: matter_commissioning::im::CommandPath,
    status_code: u8,
) -> Vec<u8> {
    use matter_codec::{Tag, TlvWriter};

    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseMessage
    w.put_bool(Tag::Context(0), false).unwrap(); // SuppressResponse
    w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
    {
        w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
        w.start_structure(Tag::Context(1)).unwrap(); // Status = CommandStatusIB
                                                     // CommandPathIB list at ctx(0).
        w.start_list(Tag::Context(0)).unwrap();
        w.put_uint(Tag::Context(0), u64::from(path.endpoint))
            .unwrap();
        w.put_uint(Tag::Context(1), u64::from(path.cluster))
            .unwrap();
        w.put_uint(Tag::Context(2), u64::from(path.command))
            .unwrap();
        w.end_container().unwrap(); // CommandPathIB
                                    // StatusIB struct at ctx(1): { ctx(0): Status u8 }
        w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
        w.put_uint(Tag::Context(0), u64::from(status_code)).unwrap(); // Status
        w.end_container().unwrap(); // StatusIB
        w.end_container().unwrap(); // CommandStatusIB
        w.end_container().unwrap(); // InvokeResponseIB
    }
    w.end_container().unwrap(); // InvokeResponses
    w.put_uint(
        Tag::Context(0xFF),
        u64::from(matter_commissioning::im::IM_REVISION),
    )
    .unwrap();
    w.end_container().unwrap(); // InvokeResponseMessage
    buf
}

/// Parse a `ReadRequestMessage` produced by
/// [`matter_commissioning::im::build_read_request`] (device side).
///
/// Wire layout consumed (derived from `im/read.rs::build_read_request`):
/// ```text
/// anon struct {
///   ctx(0): array AttributeRequests [
///     anon list AttributePathIB { ctx(2): endpoint, ctx(3): cluster, ctx(4): attribute }
///   ]
///   ctx(3): bool  FabricFiltered  (false)
///   ctx(0xFF): uint InteractionModelRevision
/// }
/// ```
///
/// Returns a `Vec<AttributePath>` with one entry per `AttributePathIB` in
/// the request.
///
/// # Panics
///
/// Panics if `bytes` is not a valid `ReadRequestMessage`. Acceptable in test
/// support code where the input is always controller-generated.
pub fn parse_read_request(bytes: &[u8]) -> Vec<matter_commissioning::im::AttributePath> {
    use matter_codec::{ContainerKind, Element, Tag, TlvReader, Value};
    use matter_commissioning::im::AttributePath;

    let mut r = TlvReader::new(bytes);

    // Consume top-level anonymous struct start.
    match r.next().expect("ReadRequest: first element") {
        Some(Element::ContainerStart {
            tag: Tag::Anonymous,
            kind: ContainerKind::Structure,
        }) => {}
        other => panic!("ReadRequest: expected anon struct, got {other:?}"),
    }

    // Scan forward to ctx(0) = AttributeRequests array.
    loop {
        match r.next().expect("ReadRequest: scan for AttributeRequests") {
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::Array,
            }) => break,
            Some(Element::ContainerEnd) | None => {
                panic!("ReadRequest: missing AttributeRequests array")
            }
            Some(Element::ContainerStart { .. }) => tlv_skip_container(&mut r),
            Some(_) => {}
        }
    }

    // Iterate over AttributePathIB list entries in the array.
    let mut paths = Vec::new();
    loop {
        match r.next().expect("ReadRequest: iterate AttributeRequests") {
            Some(Element::ContainerEnd) => break, // end of AttributeRequests array
            None => panic!("ReadRequest: AttributeRequests array not closed"),
            // Each entry is an anonymous list (AttributePathIB).
            Some(Element::ContainerStart {
                kind: ContainerKind::List,
                ..
            }) => {
                let members = tlv_read_members(&mut r);
                let mut endpoint = None;
                let mut cluster = None;
                let mut attribute = None;
                for (tag, v) in members {
                    match (tag, v) {
                        // ctx(2) = endpoint (matches build_read_request / attribute_path_from_value)
                        (Tag::Context(2), Value::Uint(n)) => {
                            endpoint = Some(u16::try_from(n).expect("endpoint fits u16"));
                        }
                        // ctx(3) = cluster
                        (Tag::Context(3), Value::Uint(n)) => {
                            cluster = Some(u32::try_from(n).expect("cluster fits u32"));
                        }
                        // ctx(4) = attribute
                        (Tag::Context(4), Value::Uint(n)) => {
                            attribute = Some(u32::try_from(n).expect("attribute fits u32"));
                        }
                        _ => {}
                    }
                }
                paths.push(AttributePath {
                    endpoint: endpoint.expect("AttributePath.endpoint present"),
                    cluster: cluster.expect("AttributePath.cluster present"),
                    attribute: attribute.expect("AttributePath.attribute present"),
                });
            }
            Some(Element::ContainerStart { .. }) => tlv_skip_container(&mut r),
            Some(_) => {}
        }
    }

    paths
}

/// Build a `ReportDataMessage` carrying one or more `(AttributePath, value_tlv)` pairs.
///
/// Produces bytes that [`matter_commissioning::im::parse_report_data`] decodes
/// to `ReportData { attributes }`.
///
/// `value_tlv` for each entry must be an anonymous-tagged TLV element (scalar
/// or container). `put_preencoded` re-tags it to context tag 2 inside
/// `AttributeData`.
///
/// Wire layout produced (derived from `im/read.rs::parse_report_data` and the
/// proven `build_canned_report_data` template in `src/driver/commission.rs`):
/// ```text
/// anon struct {
///   ctx(1): array AttributeReports [
///     anon struct AttributeReportIB {
///       ctx(1): struct AttributeData {
///         ctx(1): list  AttributePathIB { ctx(2): ep, ctx(3): cluster, ctx(4): attr }
///         ctx(2): <value>   (pre-encoded anonymous element re-tagged to ctx(2))
///       }
///     }
///   ]
///   ctx(0xFF): uint InteractionModelRevision
/// }
/// ```
///
/// # Panics
///
/// Panics if any `value_tlv` entry is not a valid anonymous-tagged TLV element.
/// Acceptable in test support code where values are always codec-generated.
pub fn build_report_data(reports: &[(matter_commissioning::im::AttributePath, &[u8])]) -> Vec<u8> {
    use matter_codec::{Tag, TlvWriter};

    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).unwrap(); // ReportDataMessage
    w.start_array(Tag::Context(1)).unwrap(); // AttributeReports
    for (path, value_tlv) in reports {
        w.start_structure(Tag::Anonymous).unwrap(); // AttributeReportIB
        w.start_structure(Tag::Context(1)).unwrap(); // AttributeData
                                                     // AttributePathIB list at ctx(1) inside AttributeData.
        w.start_list(Tag::Context(1)).unwrap();
        w.put_uint(Tag::Context(2), u64::from(path.endpoint))
            .unwrap();
        w.put_uint(Tag::Context(3), u64::from(path.cluster))
            .unwrap();
        w.put_uint(Tag::Context(4), u64::from(path.attribute))
            .unwrap();
        w.end_container().unwrap(); // AttributePathIB
                                    // Data at ctx(2): splice the anonymous TLV element under context tag 2.
        w.put_preencoded(Tag::Context(2), value_tlv).unwrap();
        w.end_container().unwrap(); // AttributeData
        w.end_container().unwrap(); // AttributeReportIB
    }
    w.end_container().unwrap(); // AttributeReports
    w.put_uint(
        Tag::Context(0xFF),
        u64::from(matter_commissioning::im::IM_REVISION),
    )
    .unwrap();
    w.end_container().unwrap(); // ReportDataMessage
    buf
}

// ── Task 10: mock-device per-stage response table (Ethernet path) ─────────────

/// Reply from the mock device for one IM round-trip.
///
/// `Command(fields_tlv)` carries the anonymous-tagged command-fields TLV blob
/// that Task 11's responder loop passes to [`build_invoke_response`]. The
/// blob is what the Commissioner's per-`Expectation` decoder in
/// `handle_response` reads (e.g. `decode_arm_fail_safe_response`,
/// `decode_noc_response`, etc.).
///
/// `Status(status_code)` signals that the device should reply with a bare
/// `CommandStatusIB` (no payload). Task 11 calls [`build_invoke_status_response`]
/// for this variant. `AddTrustedRootCertificate` (0x003E/0x0B) uses this because
/// the Commissioner's `Expectation::AddTrustedRootResponse` handler checks
/// `payload.first() == Some(&0u8)` — a single 0-byte "signal", not a TLV struct.
///
/// `StatusSignal(byte)` is reserved for the AddTrustedRoot fast path where
/// `on_response(Expectation::AddTrustedRootResponse, &[0x00])` is called
/// directly with a 1-byte sentinel rather than a full IM message. See Task 11
/// for the dispatch.
pub enum DeviceReply {
    /// Anonymous-tagged command-fields TLV. Wrap with [`build_invoke_response`].
    Command(Vec<u8>),
    /// Bare IM status code (0 = Success). Wrap with [`build_invoke_status_response`].
    Status(u8),
}

/// Map a single incoming `InvokeRequest` to the mock device's Ethernet-path reply.
///
/// The returned [`DeviceReply`] is what Task 11's responder loop uses to build
/// the outgoing `InvokeResponseMessage`.
///
/// # Cluster / command coverage (Ethernet happy path)
///
/// | Cluster | Command | Description                               | Reply variant        |
/// |---------|---------|-------------------------------------------|----------------------|
/// | 0x0030  | 0x00    | ArmFailSafe                               | `Command({0:0, 1:""})` |
/// | 0x0030  | 0x02    | SetRegulatoryConfig                       | `Command({0:0, 1:""})` |
/// | 0x0030  | 0x04    | CommissioningComplete                     | `Command({0:0, 1:""})` |
/// | 0x003E  | 0x00    | AttestationRequest                        | `Command({0:elements, 1:sig})` |
/// | 0x003E  | 0x02    | CertificateChainRequest (DAC=1 / PAI=2)   | `Command({0:cert_der})` |
/// | 0x003E  | 0x04    | CSRRequest                                | `Command({0:nocsr, 1:sig})` |
/// | 0x003E  | 0x06    | AddNOC                                    | `Command({0:0, 1:1})` |
/// | 0x003E  | 0x0B    | AddTrustedRootCertificate                 | `Status(0)` |
///
/// The `challenge` is the PASE attestation challenge (16 bytes). `pki` gives
/// access to `dac_signer`, `dac_der`, and `pai_der`.
///
/// # Panics
///
/// Panics on unrecognised `(cluster, command)` pairs — acceptable in test
/// support code where the input is always commissioner-generated.
// The function is long by necessity: one arm per commissioning command, each with
// its own nonce-parsing and TLV-building logic. Collapsing into sub-functions
// would obscure the cluster/command mapping. Suppress the too-many-lines lint.
#[allow(clippy::too_many_lines)]
// The three GeneralCommissioning response arms (ArmFailSafe / SetRegulatoryConfig /
// CommissioningComplete) all call ok_commissioning_response() and are intentionally
// identical — they are distinct commands that happen to share the same response shape.
#[allow(clippy::match_same_arms)]
pub fn respond(
    path: matter_commissioning::im::CommandPath,
    fields_tlv: &[u8],
    challenge: [u8; 16],
    pki: &MockDevicePki,
) -> DeviceReply {
    use matter_codec::{Tag, TlvWriter};

    // Helper: encode the shared {ctx(0): error_code=0, ctx(1): debug_text=""} shape
    // used by ArmFailSafeResponse, SetRegulatoryConfigResponse, and
    // CommissioningCompleteResponse. Matches decode_commissioning_error_response:
    //   ctx(0) = CommissioningErrorEnum (u8), ctx(1) = DebugText (utf8).
    let ok_commissioning_response = || -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap(); // anonymous struct (command-fields)
        w.put_uint(Tag::Context(0), 0_u64).unwrap(); // ctx(0): ErrorCode = 0 (OK)
        w.put_utf8(Tag::Context(1), "").unwrap(); // ctx(1): DebugText = ""
        w.end_container().unwrap();
        buf
    };

    match (path.cluster, path.command) {
        // ── GeneralCommissioning cluster (0x0030) ─────────────────────────────

        // ArmFailSafe (0x0030/0x00) → ArmFailSafeResponse (0x0030/0x01)
        // Commissioner decoder: decode_arm_fail_safe_response → decode_commissioning_error_response
        //   expects: anonymous struct { ctx(0): ErrorCode u8, ctx(1): DebugText utf8? }
        (0x0030, 0x00) => DeviceReply::Command(ok_commissioning_response()),

        // SetRegulatoryConfig (0x0030/0x02) → SetRegulatoryConfigResponse (0x0030/0x03)
        // Commissioner decoder: decode_set_regulatory_config_response → decode_commissioning_error_response
        //   expects: same {ctx(0): ErrorCode, ctx(1): DebugText} shape
        (0x0030, 0x02) => DeviceReply::Command(ok_commissioning_response()),

        // CommissioningComplete (0x0030/0x04) → CommissioningCompleteResponse (0x0030/0x05)
        // Commissioner decoder: decode_commissioning_error_response(Stage::SendComplete, ...)
        //   expects: same {ctx(0): ErrorCode, ctx(1): DebugText} shape
        (0x0030, 0x04) => DeviceReply::Command(ok_commissioning_response()),

        // ── OperationalCredentials cluster (0x003E) ───────────────────────────

        // AttestationRequest (0x003E/0x00) → AttestationResponse (0x003E/0x01)
        // Commissioner decoder: decode_attestation_response
        //   expects: anonymous struct { ctx(0): AttestationElements bytes, ctx(1): Signature bytes[64] }
        //
        // Parse the AttestationNonce from the incoming fields (ctx(0): 32-byte nonce).
        (0x003E, 0x00) => {
            use matter_codec::{Element, Tag as CTag, TlvReader, Value};
            // Parse the 32-byte AttestationNonce from request fields (ctx tag 0).
            let mut reader = TlvReader::new(fields_tlv);
            // Skip anonymous struct start.
            let _ = reader.next().expect("AttestationRequest: struct start");
            let mut att_nonce: Option<[u8; 32]> = None;
            loop {
                match reader.next().expect("AttestationRequest: field scan") {
                    Some(Element::ContainerEnd) | None => break,
                    Some(Element::Scalar {
                        tag: CTag::Context(0),
                        value: Value::Bytes(b),
                    }) => {
                        let arr: [u8; 32] = b.as_slice().try_into().expect("32-byte nonce");
                        att_nonce = Some(arr);
                    }
                    Some(_) => {}
                }
            }
            let nonce = att_nonce.expect("AttestationRequest: nonce at ctx(0)");
            let cd = load_cd_fixture();
            let att_resp = build_attestation_response(&cd, nonce, challenge, &pki.dac_signer);
            // Encode as command-fields: { ctx(0): elements bytes, ctx(1): signature bytes }
            // Matches decode_attestation_response field map exactly.
            let mut buf = Vec::new();
            {
                let mut w = TlvWriter::new(&mut buf);
                w.start_structure(Tag::Anonymous).unwrap();
                w.put_bytes(Tag::Context(0), &att_resp.attestation_elements)
                    .unwrap(); // ctx(0): AttestationElements
                w.put_bytes(Tag::Context(1), &att_resp.signature).unwrap(); // ctx(1): Signature (64 bytes)
                w.end_container().unwrap();
            }
            DeviceReply::Command(buf)
        }

        // CertificateChainRequest (0x003E/0x02) → CertificateChainResponse (0x003E/0x03)
        // Commissioner decoder: decode_certificate_chain_response
        //   expects: anonymous struct { ctx(0): Certificate bytes }
        //
        // Request carries ctx(0): CertificateChainTypeEnum — 0x01 = PAI, 0x02 = DAC.
        // Confirmed from CertChainType { Pai = 0x01, Dac = 0x02 } and from the wire
        // payloads: encode_certificate_chain_request(Pai) = [0x15, 0x24, 0x00, 0x01, 0x18]
        //                                               (Dac) = [0x15, 0x24, 0x00, 0x02, 0x18].
        (0x003E, 0x02) => {
            use matter_codec::{Element, Tag as CTag, TlvReader, Value};
            let mut reader = TlvReader::new(fields_tlv);
            let _ = reader.next().expect("CertChainRequest: struct start");
            let mut cert_type: Option<u8> = None;
            loop {
                match reader.next().expect("CertChainRequest: field scan") {
                    Some(Element::ContainerEnd) | None => break,
                    Some(Element::Scalar {
                        tag: CTag::Context(0),
                        value: Value::Uint(n),
                    }) => {
                        cert_type = Some(u8::try_from(n).expect("CertChainType fits u8"));
                    }
                    Some(_) => {}
                }
            }
            let cert_der = match cert_type.expect("CertificateChainRequest: type at ctx(0)") {
                0x01 => pki.pai_der.clone(), // PAI = 0x01
                0x02 => pki.dac_der.clone(), // DAC = 0x02
                other => panic!(
                    "CertificateChainRequest: unknown CertChainType 0x{other:02X} (expected 0x01=PAI or 0x02=DAC)"
                ),
            };
            // Encode as { ctx(0): cert_der bytes }.
            let mut buf = Vec::new();
            {
                let mut w = TlvWriter::new(&mut buf);
                w.start_structure(Tag::Anonymous).unwrap();
                w.put_bytes(Tag::Context(0), &cert_der).unwrap(); // ctx(0): Certificate
                w.end_container().unwrap();
            }
            DeviceReply::Command(buf)
        }

        // CSRRequest (0x003E/0x04) → CSRResponse (0x003E/0x05)
        // Commissioner decoder: decode_csr_response
        //   expects: anonymous struct { ctx(0): NOCSRElements bytes, ctx(1): Signature bytes[64] }
        //
        // Parse the 32-byte CSRNonce from request fields (ctx tag 0).
        (0x003E, 0x04) => {
            use matter_codec::{Element, Tag as CTag, TlvReader, Value};
            let mut reader = TlvReader::new(fields_tlv);
            let _ = reader.next().expect("CSRRequest: struct start");
            let mut csr_nonce: Option<[u8; 32]> = None;
            loop {
                match reader.next().expect("CSRRequest: field scan") {
                    Some(Element::ContainerEnd) | None => break,
                    Some(Element::Scalar {
                        tag: CTag::Context(0),
                        value: Value::Bytes(b),
                    }) => {
                        let arr: [u8; 32] = b.as_slice().try_into().expect("32-byte CSRNonce");
                        csr_nonce = Some(arr);
                    }
                    Some(_) => {}
                }
            }
            let nonce = csr_nonce.expect("CSRRequest: nonce at ctx(0)");
            let csr_resp = build_csr_response(nonce, challenge, &pki.dac_signer);
            // Encode as { ctx(0): nocsr_elements bytes, ctx(1): attestation_signature bytes }.
            // Matches decode_csr_response field map exactly.
            let mut buf = Vec::new();
            {
                let mut w = TlvWriter::new(&mut buf);
                w.start_structure(Tag::Anonymous).unwrap();
                w.put_bytes(Tag::Context(0), &csr_resp.nocsr_elements)
                    .unwrap(); // ctx(0): NOCSRElements
                w.put_bytes(Tag::Context(1), &csr_resp.attestation_signature)
                    .unwrap(); // ctx(1): AttestationSignature (64 bytes)
                w.end_container().unwrap();
            }
            DeviceReply::Command(buf)
        }

        // AddNOC (0x003E/0x06) → NOCResponse (0x003E/0x08)
        // Commissioner decoder: decode_noc_response
        //   expects: anonymous struct { ctx(0): StatusCode u8, ctx(1): FabricIndex u8, ctx(2)?: DebugText utf8 }
        //   On success: status=0, fabric_index=1.
        (0x003E, 0x06) => {
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), 0_u64).unwrap(); // ctx(0): StatusCode = 0 (OK)
            w.put_uint(Tag::Context(1), 1_u64).unwrap(); // ctx(1): FabricIndex = 1
            w.end_container().unwrap();
            DeviceReply::Command(buf)
        }

        // AddTrustedRootCertificate (0x003E/0x0B) → bare IM status (no response command)
        // Commissioner handler (Expectation::AddTrustedRootResponse):
        //   checks: payload.first() == Some(&0u8)  — the driver passes &[0x00] for success.
        //   Task 11 sees Status(0) and calls build_invoke_status_response + then signals
        //   on_response(AddTrustedRootResponse, &[0x00]).
        (0x003E, 0x0B) => DeviceReply::Status(0),

        (c, cmd) => panic!(
            "respond: unrecognised (cluster=0x{c:04X}, command=0x{cmd:02X}) — not in Ethernet happy path"
        ),
    }
}

/// Map a single incoming `ReadRequest` attribute path to the mock device's
/// Ethernet-path attribute value TLV.
///
/// The returned `Vec<u8>` is an **anonymous-tagged** TLV element (scalar or
/// struct) that Task 11 passes to [`build_report_data`] as the `value_tlv`
/// entry.  The driver's `extract_read_payload` re-encodes the value into the
/// format `Commissioner::on_response` expects for each `Expectation`.
///
/// # Attribute coverage
///
/// | Cluster | Attr ID | Description                   | Value TLV                           |
/// |---------|---------|-------------------------------|-------------------------------------|
/// | 0x0030  | 0x0000  | RegulatoryConfig              | anonymous uint 0 (IndoorOutdoor)    |
/// | 0x0030  | 0x0001  | LocationCapability            | anonymous uint 2 (IndoorOutdoor)    |
/// | 0x0030  | 0x0002  | SupportsConcurrentConnection  | anonymous bool true                 |
/// | 0x0030  | 0x0004  | BasicCommissioningInfo        | anonymous struct {ctx(0):60, ctx(1):900} |
/// | 0x0031  | 0xFFFC  | FeatureMap (NetworkComm.)     | anonymous uint 4 (ETHERNET only)   |
///
/// The `CommissioningInfo` struct (attr 0x0004) is what the driver scans for
/// and re-encodes via `write_value(Tag::Anonymous, struct_val)`. The anonymous
/// struct here carries `ctx(0)=failsafe_expiry_length_seconds=60` and
/// `ctx(1)=max_cumulative_failsafe_seconds=900`, matching `BasicCommissioningInfo`.
///
/// The `NetworkCommissioningInfo` value (`0x0031/0xFFFC`) is an anonymous uint
/// with **only** `NetworkCommissioningFeature::ETHERNET` set (bit 2, value 4).
/// This causes the Commissioner to skip the Wi-Fi path and go straight to
/// `Stage::EvictPreviousCaseSessions`.
///
/// # Panics
///
/// Panics on unrecognised `(cluster, attribute)` pairs — acceptable in test
/// support code where the input is always commissioner-generated.
pub fn respond_read_attribute(attr_path: matter_commissioning::im::AttributePath) -> Vec<u8> {
    use matter_codec::{Tag, TlvWriter};

    match (attr_path.cluster, attr_path.attribute) {
        // ── GeneralCommissioning cluster (0x0030) ─────────────────────────────

        // RegulatoryConfig (0x0030/0x0000): current regulatory location.
        // Type: u8 enum RegulatoryLocationTypeEnum. 2 = IndoorOutdoor.
        (0x0030, 0x0000) => {
            let mut buf = Vec::new();
            TlvWriter::new(&mut buf)
                .put_uint(Tag::Anonymous, 2)
                .unwrap(); // IndoorOutdoor
            buf
        }

        // LocationCapability (0x0030/0x0001): device's supported regulatory
        // location types. 2 = IndoorOutdoor.
        (0x0030, 0x0001) => {
            let mut buf = Vec::new();
            TlvWriter::new(&mut buf)
                .put_uint(Tag::Anonymous, 2)
                .unwrap();
            buf
        }

        // SupportsConcurrentConnection (0x0030/0x0002): whether the device
        // supports concurrent commissioning connections. true for Ethernet.
        (0x0030, 0x0002) => {
            let mut buf = Vec::new();
            TlvWriter::new(&mut buf)
                .put_bool(Tag::Anonymous, true)
                .unwrap();
            buf
        }

        // BasicCommissioningInfo (0x0030/0x0004): the struct the driver scans for.
        // Wire shape after extract_read_payload re-encoding:
        //   anonymous struct { ctx(0): failsafe_expiry_length_seconds u16,
        //                      ctx(1): max_cumulative_failsafe_seconds u16 }
        // decode_basic_commissioning_info reads ctx(0) and ctx(1) from an anonymous struct.
        // The driver's extract_read_payload re-encodes the Value::Structure via
        //   w.write_value(Tag::Anonymous, struct_val).
        // So we emit an anonymous struct here that round-trips through the
        //   build_report_data → parse_report_data → extract_read_payload pipeline.
        (0x0030, 0x0004) => {
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), 60_u64).unwrap(); // failsafe_expiry_length_seconds = 60 s
            w.put_uint(Tag::Context(1), 900_u64).unwrap(); // max_cumulative_failsafe_seconds = 900 s
            w.end_container().unwrap();
            buf
        }

        // ── NetworkCommissioning cluster (0x0031) ─────────────────────────────

        // FeatureMap (0x0031/0xFFFC): which network interfaces the device exposes.
        // Wire shape after extract_read_payload re-encoding:
        //   anonymous uint (what decode_feature_map expects).
        // ETHERNET only = bit 2 = value 4. No WIFI (bit 0) or THREAD (bit 1) bits.
        // With only ETHERNET set, the Commissioner skips Stage::WiFiNetworkSetup.
        (0x0031, 0xFFFC) => {
            let ethernet_feature: u32 =
                matter_commissioning::clusters::network_commissioning::NetworkCommissioningFeature::ETHERNET
                    .bits();
            let mut buf = Vec::new();
            TlvWriter::new(&mut buf)
                .put_uint(Tag::Anonymous, u64::from(ethernet_feature))
                .unwrap();
            buf
        }

        (c, a) => {
            panic!("respond_read_attribute: unrecognised (cluster=0x{c:04X}, attribute=0x{a:04X})")
        }
    }
}

// ── Task 10: Step 2 tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod mock_device_response_table {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::items_after_statements
    )]

    use matter_cert::time::MatterTime;
    use matter_codec::{Tag, TlvWriter};
    use matter_commissioning::clusters::network_commissioning::NetworkCommissioningFeature;
    use matter_commissioning::im::{AttributePath, CommandPath};
    use matter_commissioning::noc::{
        decode_attestation_response, decode_certificate_chain_response,
    };
    use matter_commissioning::state_machine::Expectation;

    use super::{build_mock_device_pki, respond, respond_read_attribute, DeviceReply};

    fn now() -> MatterTime {
        MatterTime::from_unix_secs(1_800_000_000)
    }

    /// Helper: build a `CommissioningErrorEnum`-shaped request fields TLV (ArmFailSafe
    /// has ctx(0)=expiry, ctx(1)=breadcrumb — we build the minimal form and call respond).
    fn arm_fail_safe_fields() -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 60_u64).unwrap(); // ExpiryLengthSeconds
        w.put_uint(Tag::Context(1), 1_u64).unwrap(); // Breadcrumb
        w.end_container().unwrap();
        buf
    }

    /// Helper: build a CertificateChainRequest fields TLV with the given type byte.
    fn cert_chain_request_fields(cert_type: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), u64::from(cert_type)).unwrap();
        w.end_container().unwrap();
        buf
    }

    /// Helper: build an AttestationRequest fields TLV with a fixed nonce.
    fn attestation_request_fields(nonce: [u8; 32]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bytes(Tag::Context(0), &nonce).unwrap();
        w.end_container().unwrap();
        buf
    }

    /// Helper: build a CSRRequest fields TLV with a fixed nonce.
    fn csr_request_fields(nonce: [u8; 32]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bytes(Tag::Context(0), &nonce).unwrap();
        w.end_container().unwrap();
        buf
    }

    // ── ArmFailSafe ───────────────────────────────────────────────────────────

    /// respond(0x0030/0x00) produces command-fields the Commissioner's
    /// `decode_arm_fail_safe_response` decodes as `error_code=0, debug_text=Some("")`.
    #[test]
    fn arm_fail_safe_returns_ok_response_accepted_by_commissioner_decoder() {
        let pki = build_mock_device_pki(now());
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x0030,
            command: 0x00,
        };
        let fields = arm_fail_safe_fields();
        let challenge = [0u8; 16];

        let reply = respond(path, &fields, challenge, &pki);
        let fields_tlv = match reply {
            DeviceReply::Command(v) => v,
            DeviceReply::Status(s) => panic!("expected Command, got Status({s})"),
        };

        // Feed the fields_tlv directly to the Commissioner's decoder.
        use matter_commissioning::clusters::general_commissioning::decode_arm_fail_safe_response;
        let decoded =
            decode_arm_fail_safe_response(&fields_tlv).expect("ArmFailSafeResponse decodes");
        assert_eq!(decoded.error_code, 0, "error_code must be 0 (OK)");
        // debug_text is allowed to be Some("") or None; both are success.
        let text = decoded.debug_text.as_deref().unwrap_or("");
        assert_eq!(text, "", "debug_text must be empty on success");
    }

    /// The same fields_tlv round-trips through the Commissioner's full
    /// `on_response(Expectation::ArmFailsafeResponse, …)` without error.
    #[test]
    fn arm_fail_safe_fields_accepted_by_on_response() {
        use std::sync::Arc;

        use matter_cert::time::MatterTime;
        use matter_commissioning::attestation::CdSigningRoots;
        use matter_commissioning::noc::{FabricRecord, NocRng, SystemNocRng};
        use matter_commissioning::setup::{
            CommissioningFlow, DiscoveryCapabilities, Discriminator, Passcode, SetupPayload,
        };
        use matter_commissioning::state_machine::CommissionerConfig;
        use matter_crypto::{RingSigner, Signer};

        let pki = build_mock_device_pki(now());

        // Build a minimal Commissioner (same pattern as commissioner.rs unit tests).
        let (signer, _) = RingSigner::generate().unwrap();
        let signer: Arc<dyn Signer> = Arc::new(signer);
        let fabric = FabricRecord::new_root_only(
            0x0000_0000_0000_0001,
            signer,
            MatterTime::from_unix_secs(1_704_067_200),
            MatterTime::from_unix_secs(1_735_689_600),
            42,
            &SystemNocRng,
        )
        .unwrap();

        let setup = SetupPayload {
            version: 0,
            vendor_id: Some(super::VID),
            product_id: Some(super::PID),
            commissioning_flow: CommissioningFlow::Standard,
            discovery_capabilities: DiscoveryCapabilities::ON_NETWORK,
            discriminator: Discriminator::new(0x0F00).unwrap(),
            passcode: Passcode::new(20_202_021).unwrap(),
        };
        let paa = pki.paa_trust_store.clone();
        let cd = CdSigningRoots::with_csa_test_roots();
        let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);

        let mut sm = matter_commissioning::state_machine::Commissioner::new(CommissionerConfig {
            pase_attestation_challenge: [0u8; 16],
            fabric: &fabric,
            setup_payload: &setup,
            paa_trust_store: &paa,
            cd_signing_roots: &cd,
            commissioner_node_id: 0x1,
            assigned_node_id: 0x2,
            ipk_epoch_key: [0x42_u8; 16],
            case_admin_subject: 0x1,
            admin_vendor_id: 0xFFF1,
            now: MatterTime::from_unix_secs(1_800_000_000),
            rng,
            wifi_credentials: None,
        })
        .unwrap();

        // Drive to ArmFailsafe: poll (ReadCommissioningInfo) → respond CommissioningInfo
        // → poll (ArmFailSafe) → feed our mock device's ArmFailSafeResponse.
        let _ = sm.poll().unwrap(); // ReadCommissioningInfo

        // Provide a minimal well-formed CommissioningInfo response.
        let commissioning_info_tlv = respond_read_attribute(AttributePath {
            endpoint: 0,
            cluster: 0x0030,
            attribute: 0x0004,
        });
        // The driver re-encodes the struct value; simulate by building a
        // well-formed anonymous struct directly (the state machine's CommissioningInfo
        // handler calls decode_basic_commissioning_info which is best-effort).
        sm.on_response(Expectation::CommissioningInfo, &commissioning_info_tlv)
            .expect("CommissioningInfo accepted");

        let _ = sm.poll().unwrap(); // ArmFailSafe

        // Now feed the mock device's ArmFailSafeResponse.
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x0030,
            command: 0x00,
        };
        let fields = arm_fail_safe_fields();
        let reply = respond(path, &fields, [0u8; 16], &pki);
        let fields_tlv = match reply {
            DeviceReply::Command(v) => v,
            DeviceReply::Status(s) => panic!("expected Command, got Status({s})"),
        };

        sm.on_response(Expectation::ArmFailsafeResponse, &fields_tlv)
            .expect("Commissioner accepts ArmFailSafeResponse from mock device");
        assert_eq!(
            sm.stage(),
            matter_commissioning::state_machine::Stage::ConfigRegulatory,
            "state machine advanced past ArmFailsafe"
        );
    }

    // ── AttestationRequest ────────────────────────────────────────────────────

    /// respond(0x003E/0x00) produces command-fields the Commissioner's
    /// `decode_attestation_response` decodes correctly (elements present, sig 64 bytes).
    #[test]
    fn attestation_request_returns_fields_accepted_by_noc_decoder() {
        let pki = build_mock_device_pki(now());
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x003E,
            command: 0x00,
        };
        let nonce = [0xAB_u8; 32];
        let challenge = [0x01_u8; 16];
        let fields = attestation_request_fields(nonce);

        let reply = respond(path, &fields, challenge, &pki);
        let fields_tlv = match reply {
            DeviceReply::Command(v) => v,
            DeviceReply::Status(s) => panic!("expected Command, got Status({s})"),
        };

        // Feed to the Commissioner's decoder (noc::decode_attestation_response).
        let decoded =
            decode_attestation_response(&fields_tlv).expect("AttestationResponse decodes");
        assert_eq!(
            decoded.signature.len(),
            64,
            "ECDSA signature must be 64 bytes (IEEE P1363)"
        );
        assert!(
            !decoded.attestation_elements.is_empty(),
            "attestation_elements must be non-empty"
        );
    }

    /// respond(0x003E/0x00) nonce echo: the emitted AttestationElements
    /// contain the nonce we sent (verified via extract_attestation_elements_fields).
    #[test]
    fn attestation_response_elements_echo_the_nonce() {
        use matter_commissioning::attestation::extract_attestation_elements_fields;

        let pki = build_mock_device_pki(now());
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x003E,
            command: 0x00,
        };
        let nonce = [0xCC_u8; 32];
        let challenge = [0x02_u8; 16];
        let fields = attestation_request_fields(nonce);

        let reply = respond(path, &fields, challenge, &pki);
        let DeviceReply::Command(fields_tlv) = reply else {
            panic!("expected Command");
        };

        let att_resp = decode_attestation_response(&fields_tlv).unwrap();
        let att_fields = extract_attestation_elements_fields(&att_resp.attestation_elements)
            .expect("elements parse");
        assert_eq!(
            att_fields.attestation_nonce, nonce,
            "nonce must be echoed back"
        );
    }

    // ── CertificateChainRequest ────────────────────────────────────────────────

    /// respond(0x003E/0x02) with type=PAI (0x01) returns pai_der.
    #[test]
    fn cert_chain_request_pai_returns_pai_der() {
        let pki = build_mock_device_pki(now());
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x003E,
            command: 0x02,
        };
        let fields = cert_chain_request_fields(0x01); // PAI
        let reply = respond(path, &fields, [0u8; 16], &pki);
        let fields_tlv = match reply {
            DeviceReply::Command(v) => v,
            DeviceReply::Status(s) => panic!("expected Command, got Status({s})"),
        };

        let decoded =
            decode_certificate_chain_response(&fields_tlv).expect("CertChainResponse decodes");
        assert_eq!(decoded.certificate, pki.pai_der, "PAI DER mismatch");
    }

    /// respond(0x003E/0x02) with type=DAC (0x02) returns dac_der.
    #[test]
    fn cert_chain_request_dac_returns_dac_der() {
        let pki = build_mock_device_pki(now());
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x003E,
            command: 0x02,
        };
        let fields = cert_chain_request_fields(0x02); // DAC
        let reply = respond(path, &fields, [0u8; 16], &pki);
        let fields_tlv = match reply {
            DeviceReply::Command(v) => v,
            DeviceReply::Status(s) => panic!("expected Command, got Status({s})"),
        };

        let decoded =
            decode_certificate_chain_response(&fields_tlv).expect("CertChainResponse decodes");
        assert_eq!(decoded.certificate, pki.dac_der, "DAC DER mismatch");
    }

    // ── AddTrustedRoot ─────────────────────────────────────────────────────────

    /// respond(0x003E/0x0B) emits Status(0) so Task 11 uses build_invoke_status_response.
    #[test]
    fn add_trusted_root_emits_status_zero() {
        let pki = build_mock_device_pki(now());
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x003E,
            command: 0x0B,
        };
        let fields = vec![0x15u8, 0x18]; // empty anonymous struct
        let reply = respond(path, &fields, [0u8; 16], &pki);
        match reply {
            DeviceReply::Status(0) => {}
            DeviceReply::Status(s) => panic!("expected Status(0), got Status({s})"),
            DeviceReply::Command(_) => panic!("expected Status, got Command"),
        }
    }

    // ── NetworkCommissioning FeatureMap read ──────────────────────────────────

    /// respond_read_attribute(0x0031/0xFFFC) returns ETHERNET-only FeatureMap (value=4).
    /// This causes the Commissioner to skip the Wi-Fi path (Stage::EvictPreviousCaseSessions).
    #[test]
    fn feature_map_is_ethernet_only() {
        use matter_commissioning::clusters::network_commissioning::decode_feature_map;

        let value_tlv = respond_read_attribute(AttributePath {
            endpoint: 0,
            cluster: 0x0031,
            attribute: 0xFFFC,
        });
        let features = decode_feature_map(&value_tlv).expect("FeatureMap decodes");
        assert!(
            features.contains(NetworkCommissioningFeature::ETHERNET),
            "ETHERNET bit must be set"
        );
        assert!(
            !features.contains(NetworkCommissioningFeature::WIFI),
            "WIFI bit must NOT be set (Ethernet path)"
        );
        assert!(
            !features.contains(NetworkCommissioningFeature::THREAD),
            "THREAD bit must NOT be set (Ethernet path)"
        );
    }

    // ── BasicCommissioningInfo read ────────────────────────────────────────────

    /// respond_read_attribute(0x0030/0x0004) returns an anonymous struct that
    /// decode_basic_commissioning_info parses as failsafe=60, max_cumulative=900.
    #[test]
    fn basic_commissioning_info_decodes_correctly() {
        use matter_commissioning::clusters::general_commissioning::decode_basic_commissioning_info;

        let value_tlv = respond_read_attribute(AttributePath {
            endpoint: 0,
            cluster: 0x0030,
            attribute: 0x0004,
        });
        let info =
            decode_basic_commissioning_info(&value_tlv).expect("BasicCommissioningInfo decodes");
        assert_eq!(
            info.failsafe_expiry_length_seconds, 60,
            "failsafe_expiry_length_seconds must be 60"
        );
        assert_eq!(
            info.max_cumulative_failsafe_seconds, 900,
            "max_cumulative_failsafe_seconds must be 900"
        );
    }

    // ── CSRRequest ────────────────────────────────────────────────────────────

    /// respond(0x003E/0x04) produces command-fields the Commissioner's
    /// `decode_csr_response` decodes correctly (nocsr_elements present, sig 64 bytes).
    #[test]
    fn csr_request_returns_fields_accepted_by_noc_decoder() {
        use matter_commissioning::noc::decode_csr_response;

        let pki = build_mock_device_pki(now());
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x003E,
            command: 0x04,
        };
        let nonce = [0xDD_u8; 32];
        let fields = csr_request_fields(nonce);
        let reply = respond(path, &fields, [0u8; 16], &pki);
        let fields_tlv = match reply {
            DeviceReply::Command(v) => v,
            DeviceReply::Status(s) => panic!("expected Command, got Status({s})"),
        };

        let decoded = decode_csr_response(&fields_tlv).expect("CSRResponse decodes");
        assert_eq!(decoded.attestation_signature.len(), 64);
        assert!(!decoded.nocsr_elements.is_empty());
    }

    // ── NOCResponse ───────────────────────────────────────────────────────────

    /// respond(0x003E/0x06) produces fields decode_noc_response parses as status=0, fabric_index=1.
    #[test]
    fn add_noc_returns_success_noc_response() {
        use matter_commissioning::noc::decode_noc_response;

        let pki = build_mock_device_pki(now());
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x003E,
            command: 0x06,
        };
        let fields = vec![0x15u8, 0x18]; // AddNOC payload is opaque to mock device
        let reply = respond(path, &fields, [0u8; 16], &pki);
        let fields_tlv = match reply {
            DeviceReply::Command(v) => v,
            DeviceReply::Status(s) => panic!("expected Command, got Status({s})"),
        };

        let decoded = decode_noc_response(&fields_tlv).expect("NOCResponse decodes");
        assert_eq!(decoded.status, 0, "status must be 0 (OK)");
        assert_eq!(decoded.fabric_index, Some(1), "fabric_index must be 1");
    }
}

// ── Task 9: roundtrip tests ───────────────────────────────────────────────────

#[cfg(test)]
mod device_im_roundtrip {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use matter_codec::{Tag, TlvWriter, Value};
    use matter_commissioning::im::{
        build_invoke_request, build_read_request, parse_invoke_response, parse_report_data,
        AttributePath, CommandPath, InvokeResponse,
    };

    use super::{
        build_invoke_response, build_invoke_status_response, build_report_data,
        parse_invoke_request, parse_read_request,
    };

    /// (a) Controller builds InvokeRequest → device parses it back.
    #[test]
    fn parse_invoke_request_is_inverse_of_build_invoke_request() {
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x0030,
            command: 0x00,
        };
        // ArmFailSafe fields: { ctx(0): 60u16, ctx(1): 1u64 }
        let mut fields_buf = Vec::new();
        {
            let mut w = TlvWriter::new(&mut fields_buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), 60).unwrap(); // ExpiryLengthSeconds
            w.put_uint(Tag::Context(1), 1).unwrap(); // Breadcrumb
            w.end_container().unwrap();
        }

        let request_bytes = build_invoke_request(path, &fields_buf);
        let decoded = parse_invoke_request(&request_bytes);

        assert_eq!(decoded.path, path);
        assert_eq!(
            decoded.fields_tlv, fields_buf,
            "fields_tlv mismatch: got {:02X?}, expected {fields_buf:02X?}",
            decoded.fields_tlv
        );
    }

    /// (b) Device builds InvokeResponse → controller's im::parse_invoke_response recovers it.
    #[test]
    fn parse_invoke_response_accepts_build_invoke_response() {
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x0030,
            command: 0x01, // ArmFailSafeResponse
        };
        // ArmFailSafeResponse fields: { ctx(0): 0u8 (errorCode = OK) }
        let mut fields_buf = Vec::new();
        {
            let mut w = TlvWriter::new(&mut fields_buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), 0).unwrap(); // errorCode = OK
            w.end_container().unwrap();
        }

        let response_bytes = build_invoke_response(path, &fields_buf);
        let parsed = parse_invoke_response(&response_bytes).unwrap();

        match parsed {
            InvokeResponse::Command {
                path: p,
                fields_tlv,
            } => {
                assert_eq!(p, path);
                assert_eq!(
                    fields_tlv, fields_buf,
                    "fields_tlv mismatch: got {fields_tlv:02X?}, expected {fields_buf:02X?}",
                );
            }
            InvokeResponse::Status(s) => panic!("expected Command, got Status({s:?})"),
        }
    }

    /// (b-status) Device builds InvokeStatusResponse → controller's
    /// im::parse_invoke_response decodes it as InvokeResponse::Status.
    #[test]
    fn parse_invoke_response_accepts_build_invoke_status_response() {
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x003E, // OperationalCredentials
            command: 0x0B,   // AddTrustedRootCertificate (no command response, only status)
        };

        let response_bytes = build_invoke_status_response(path, 0x00); // 0x00 = Success
        let parsed = parse_invoke_response(&response_bytes).unwrap();

        assert!(
            matches!(parsed, InvokeResponse::Status(_)),
            "expected Status, got {parsed:?}"
        );
        if let InvokeResponse::Status(status) = parsed {
            // ImStatus::Success maps from 0x00; confirm it does not carry a failure code.
            let status_name = format!("{status:?}");
            assert!(
                status_name.contains("Success") || status_name.contains('0'),
                "expected Success status, got {status_name}"
            );
        }
    }

    /// (c) Controller builds ReadRequest → device parses it back.
    #[test]
    fn parse_read_request_is_inverse_of_build_read_request() {
        let paths = vec![
            AttributePath {
                endpoint: 0,
                cluster: 0x0030,
                attribute: 0x0004, // BasicCommissioningInfo
            },
            AttributePath {
                endpoint: 0,
                cluster: 0x0031,
                attribute: 0xFFFC, // FeatureMap
            },
        ];

        let request_bytes = build_read_request(&paths);
        let decoded = parse_read_request(&request_bytes);

        assert_eq!(decoded.len(), paths.len());
        assert_eq!(decoded, paths);
    }

    /// (d) Device builds ReportData → controller's im::parse_report_data recovers it.
    #[test]
    fn parse_report_data_accepts_build_report_data() {
        let path1 = AttributePath {
            endpoint: 0,
            cluster: 0x0030,
            attribute: 0x0004,
        };
        // Value: a u64 scalar (FeatureMap style).
        let mut val1_buf = Vec::new();
        {
            let mut w = TlvWriter::new(&mut val1_buf);
            w.put_uint(Tag::Anonymous, 0x01).unwrap();
        }

        let path2 = AttributePath {
            endpoint: 0,
            cluster: 0x0031,
            attribute: 0xFFFC,
        };
        // Value: a u64 scalar = 3 (WIFI | THREAD).
        let mut val2_buf = Vec::new();
        {
            let mut w = TlvWriter::new(&mut val2_buf);
            w.put_uint(Tag::Anonymous, 3).unwrap();
        }

        let report_bytes =
            build_report_data(&[(path1, val1_buf.as_slice()), (path2, val2_buf.as_slice())]);
        let parsed = parse_report_data(&report_bytes).unwrap();

        assert_eq!(parsed.attributes.len(), 2);

        let (p0, v0) = &parsed.attributes[0];
        assert_eq!(*p0, path1);
        assert_eq!(*v0, Value::Uint(0x01));

        let (p1, v1) = &parsed.attributes[1];
        assert_eq!(*p1, path2);
        assert_eq!(*v1, Value::Uint(3));
    }

    /// Edge case: roundtrip with an empty anonymous struct as CommandFields.
    #[test]
    fn roundtrip_empty_command_fields() {
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x003E,
            command: 0x0B, // AddTrustedRootCertificate (fields is just an empty struct)
        };
        // Empty anonymous struct: [0x15, 0x18]
        let empty_fields = vec![0x15u8, 0x18];

        // (a) build→parse direction.
        let req = build_invoke_request(path, &empty_fields);
        let decoded = parse_invoke_request(&req);
        assert_eq!(decoded.path, path);
        assert_eq!(decoded.fields_tlv, empty_fields);

        // (b) build-response→parse direction.
        let resp = build_invoke_response(path, &empty_fields);
        match parse_invoke_response(&resp).unwrap() {
            InvokeResponse::Command {
                path: p,
                fields_tlv,
            } => {
                assert_eq!(p, path);
                assert_eq!(fields_tlv, empty_fields);
            }
            InvokeResponse::Status(s) => panic!("expected Command, got {s:?}"),
        }
    }
}
