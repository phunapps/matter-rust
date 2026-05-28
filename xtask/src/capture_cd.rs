//! `xtask capture-cd` — generate a synthetic CSA-test CD signing root
//! and matching Certification Declaration (CD) fixtures under
//! `test-vectors/commissioning/cd/`.
//!
//! The Certification Declaration (Matter Core Spec §6.3.1) is a CMS /
//! PKCS#7 `SignedData` blob carrying the device's declared VID + PID
//! list plus format/security metadata. Real CSA-signed CDs are not
//! publicly distributable, so M6.4.3 builds a synthetic test root +
//! signs a CD against it for unit and integration testing.
//!
//! The verifier (`attestation::cd::verify_certification_declaration`,
//! M6.4.3 T28+) accepts both real and synthetic CDs equivalently — it
//! checks against whatever trust store the caller supplies. Production
//! callers supply CSA-published roots via `CdSigningRoots::from_pem`;
//! tests use the bundled synthetic root via
//! `CdSigningRoots::with_csa_test_roots()`.
//!
//! ## Output layout
//!
//! ```text
//! test-vectors/commissioning/cd/
//!   csa-test-cd-signing-root.pem            (SubjectPublicKeyInfo PEM)
//!   csa-test-cd-signing-root.pkcs8.der      (PKCS#8 private key)
//!   happy-path.json                         (valid CD, vid=0xFFF1, pid=0x8001)
//!   tampered-signature.json                 (last byte of signature flipped)
//!   wrong-vid.json                          (same VID/PID; tests pass mismatched expected_vid)
//! ```
//!
//! Plus a copy of the public-key PEM bundled inside the crate at
//! `crates/matter-commissioning/src/attestation/cd/csa_cd_signing_roots/`
//! so production callers don't need the test-vectors directory at
//! runtime.
//!
//! ## CMS shape
//!
//! Per RFC 5652 §5.4, when `signedAttrs` is absent from a `SignerInfo`
//! the signature value is computed directly over the eContent's value
//! (i.e. the inner CD TLV bytes). We emit exactly that shape:
//!
//! - `SignerInfo.version = 1` (per §5.3, version MUST be 1 when sid is
//!   `issuerAndSerialNumber`),
//! - `sid = issuerAndSerialNumber` with placeholder issuer/serial (the
//!   M6.4.3 verifier does not enforce sid — it tries every trusted
//!   root's public key in turn),
//! - `signedAttrs = None`,
//! - `signatureAlgorithm = ecdsa-with-SHA256`,
//! - `signature = <ECDSA-P256/SHA-256 over eContent value>`.
//!
//! Real CSA-issued CDs use the same `ecdsa-with-SHA256` algorithm and
//! the same `id-data` eContentType, so the verifier handles both
//! shapes uniformly.
//!
//! Re-run only when refreshing the synthetic fixture set — the
//! generated outputs are committed so CI doesn't need to regenerate.

#![forbid(unsafe_code)]
// xtask is build tooling, not library code; the CLAUDE.md no-unwrap
// rule is for library code only. The existing capture-* modules apply
// the same allow.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use base64::Engine;
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, AnyRef, OctetString, SetOfVec};
use der::{Encode, Tag as DerTag};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use spki::AlgorithmIdentifierOwned;
use x509_cert::name::RdnSequence;
use x509_cert::serial_number::SerialNumber;

use matter_codec::{Tag as TlvTag, TlvWriter};

/// PKCS#1 OID for `id-data` (`1.2.840.113549.1.7.1`) — eContentType for
/// the inner CD TLV bytes.
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// PKCS#7 OID for `id-signedData` (`1.2.840.113549.1.7.2`) — the
/// contentType wrapping `SignedData` inside `ContentInfo`.
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// RFC 5912 OID for `id-sha256` (`2.16.840.1.101.3.4.2.1`).
const ID_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// RFC 5912 OID for `ecdsa-with-SHA256` (`1.2.840.10045.4.3.2`).
const ECDSA_WITH_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Entry point invoked from xtask main.
///
/// # Errors
///
/// Returns a descriptive string on any filesystem, key-generation, or
/// DER-encoding failure. The xtask `main` surfaces the message via
/// `eprintln!` and exits non-zero.
pub(crate) fn run() -> Result<(), String> {
    let out_dir = PathBuf::from("test-vectors/commissioning/cd");
    fs::create_dir_all(&out_dir)
        .map_err(|e| format!("create_dir_all({}): {e}", out_dir.display()))?;

    // 1. Generate a P-256 keypair for the synthetic signing root.
    let (spki_pem, pkcs8_der) = generate_p256_keypair()?;
    fs::write(out_dir.join("csa-test-cd-signing-root.pem"), &spki_pem)
        .map_err(|e| format!("write spki pem: {e}"))?;
    fs::write(
        out_dir.join("csa-test-cd-signing-root.pkcs8.der"),
        &pkcs8_der,
    )
    .map_err(|e| format!("write pkcs8 der: {e}"))?;

    // Also bundle the PEM inside the crate so production callers do
    // not need the test-vectors directory at runtime.
    let crate_bundle =
        PathBuf::from("crates/matter-commissioning/src/attestation/cd/csa_cd_signing_roots");
    fs::create_dir_all(&crate_bundle)
        .map_err(|e| format!("create_dir_all({}): {e}", crate_bundle.display()))?;
    fs::write(crate_bundle.join("csa-test-cd-signing-root.pem"), &spki_pem)
        .map_err(|e| format!("write bundled spki pem: {e}"))?;

    // 2-4. For each scenario, build the inner CD TLV, sign it, wrap in
    //      CMS SignedData, and write the JSON fixture.
    //
    // The third scenario uses the same VID/PID as the happy path; the
    // "wrong VID" semantics live in the consuming test (passing a
    // different `expected_vid` to `verify_certification_declaration`).
    // We keep a dedicated fixture so the negative test reads naturally.
    let scenarios: [(&str, u16, u16, bool); 3] = [
        ("happy-path.json", 0xFFF1, 0x8001, false),
        ("tampered-signature.json", 0xFFF1, 0x8001, true),
        ("wrong-vid.json", 0xFFF1, 0x8001, false),
    ];

    for (name, vid, pid, tamper) in scenarios {
        let cd_tlv = build_inner_cd_tlv(vid, pid);
        let mut signed = sign_into_cms(&cd_tlv, &pkcs8_der)?;
        if tamper {
            // Flip one bit in the very last byte of the encoded blob.
            // The last byte sits inside the SignatureValue OCTET STRING
            // (signerInfo is the last field of SignedData and
            // signature is the last required field of SignerInfo when
            // unsignedAttrs is absent), so the flip lands in the
            // signature region — verification must fail.
            let last = signed.len().saturating_sub(1);
            signed[last] ^= 0x01;
        }
        let fixture = serde_json::json!({
            "cd_b64": base64::engine::general_purpose::STANDARD.encode(&signed),
            "expected_vid": vid,
            "expected_pid": pid,
        });
        let pretty =
            serde_json::to_string_pretty(&fixture).map_err(|e| format!("serde_json: {e}"))?;
        fs::write(out_dir.join(name), pretty).map_err(|e| format!("write {name}: {e}"))?;
    }

    println!(
        "OK: wrote {} + 3 JSON fixtures and the bundled root PEM",
        out_dir.display()
    );
    Ok(())
}

/// Generate a P-256 keypair via `ring` and return
/// `(SubjectPublicKeyInfo PEM, PKCS#8 private key DER)`.
fn generate_p256_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|e| format!("EcdsaKeyPair::generate_pkcs8: {e}"))?;
    let pkcs8_bytes = pkcs8.as_ref().to_vec();

    // Re-parse so we can extract the SubjectPublicKeyInfo.
    let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
        .map_err(|e| format!("EcdsaKeyPair::from_pkcs8: {e}"))?;
    // SEC1 uncompressed point: 65 bytes (0x04 || X || Y).
    let sec1 = keypair.public_key().as_ref().to_vec();

    let spki_der = wrap_sec1_in_subject_public_key_info(&sec1);

    // PEM encode the SPKI DER.
    let b64 = base64::engine::general_purpose::STANDARD.encode(&spki_der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        let chunk_str =
            std::str::from_utf8(line).map_err(|e| format!("utf8 (base64 chunk): {e}"))?;
        pem.push_str(chunk_str);
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");

    Ok((pem.into_bytes(), pkcs8_bytes))
}

/// Hand-roll the 91-byte `SubjectPublicKeyInfo` DER for a P-256
/// uncompressed public key.
///
/// Structure (RFC 5280 §4.1.2.7):
///
/// ```text
/// SubjectPublicKeyInfo SEQUENCE (89 bytes) {
///   algorithm SEQUENCE (19 bytes) {
///     algorithm OID (7 bytes) = ecPublicKey (1.2.840.10045.2.1)
///     parameters OID (8 bytes) = prime256v1 (1.2.840.10045.3.1.7)
///   }
///   subjectPublicKey BIT STRING (66 bytes) = 0x00 || <sec1 point (65 bytes)>
/// }
/// ```
///
/// Total: 2-byte SEQUENCE tag+len + 89 bytes content = 91 bytes.
fn wrap_sec1_in_subject_public_key_info(sec1: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(91);
    out.extend_from_slice(&[
        0x30, 0x59, // SEQUENCE, 89 bytes
        0x30, 0x13, // SEQUENCE, 19 bytes (algorithm identifier)
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID prime256v1
        0x03, 0x42, 0x00, // BIT STRING, 66 bytes, 0 unused bits
    ]);
    out.extend_from_slice(sec1);
    out
}

/// Build the inner CD TLV per Matter Core Spec §6.3.1.
///
/// Anonymous outer structure with context-tagged fields:
///
/// - tag 0: `format_version`     (u8)  = 1
/// - tag 1: `vendor_id`          (u16) = `vendor_id`
/// - tag 2: `product_id_array`   (array of u16)
/// - tag 3: `device_type_id`     (u32) = 0x0100
/// - tag 4: `certificate_id`     (utf8) = "CSA00000000000000"
/// - tag 5: `security_level`     (u8) = 0
/// - tag 6: `security_information` (u16) = 0
/// - tag 7: `version_number`     (u16) = 1
/// - tag 8: `certification_type` (u8) = 0
///
/// The remaining optional fields (tags 9, 10) are omitted — they're
/// only required for PAA-/PAI-issued device-scoped CDs which the
/// synthetic CSA-test root does not exercise.
fn build_inner_cd_tlv(vendor_id: u16, product_id: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(TlvTag::Anonymous).unwrap();
        w.put_uint(TlvTag::Context(0), 1).unwrap();
        w.put_uint(TlvTag::Context(1), u64::from(vendor_id))
            .unwrap();
        w.start_array(TlvTag::Context(2)).unwrap();
        w.put_uint(TlvTag::Anonymous, u64::from(product_id))
            .unwrap();
        w.end_container().unwrap(); // close array
        w.put_uint(TlvTag::Context(3), 0x0100).unwrap();
        w.put_utf8(TlvTag::Context(4), "CSA00000000000000").unwrap();
        w.put_uint(TlvTag::Context(5), 0).unwrap();
        w.put_uint(TlvTag::Context(6), 0).unwrap();
        w.put_uint(TlvTag::Context(7), 1).unwrap();
        w.put_uint(TlvTag::Context(8), 0).unwrap();
        w.end_container().unwrap(); // close struct
    }
    buf
}

/// Sign the inner CD TLV with the synthetic root key and wrap the
/// result in a CMS `SignedData` `ContentInfo` blob.
///
/// We use the no-`signedAttrs` shape per RFC 5652 §5.4: the signature
/// is computed directly over the eContent value (the inner CD TLV
/// bytes), which is exactly what
/// `attestation::cd::verify_certification_declaration` verifies.
fn sign_into_cms(content: &[u8], signing_key_pkcs8: &[u8]) -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, signing_key_pkcs8, &rng)
        .map_err(|e| format!("EcdsaKeyPair::from_pkcs8 (sign): {e}"))?;

    // Sign the raw eContent bytes (no signed attributes).
    let signature = key
        .sign(&rng, content)
        .map_err(|e| format!("EcdsaKeyPair::sign: {e}"))?;
    let sig_bytes = signature.as_ref().to_vec();

    // ---- Build the SignedData via the cms crate's typed structs ----

    // EncapsulatedContentInfo wraps the eContent OCTET STRING in an
    // `Any` (the cms crate types `eContent` as `[0] EXPLICIT OCTET
    // STRING`, with `Option<Any>` as the storage). We hand the OCTET
    // STRING's value (the inner CD TLV bytes) plus an OctetString tag.
    let econtent_any = Any::new(DerTag::OctetString, content.to_vec())
        .map_err(|e| format!("Any::new(OctetString, content): {e}"))?;
    let encap = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: Some(econtent_any),
    };

    // digestAlgorithms SET — SHA-256 with absent parameters.
    let sha256 = AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    };
    let digest_algorithms = SetOfVec::try_from(vec![sha256.clone()])
        .map_err(|e| format!("digest_algorithms SetOfVec: {e}"))?;

    // SignerInfo: version=1, sid=issuerAndSerialNumber (placeholder
    // empty RDN + serial 0x01), no signedAttrs, signatureAlgorithm =
    // ecdsa-with-SHA256, signature = raw fixed-size ECDSA-P256 sig.
    //
    // We use IssuerAndSerialNumber (rather than SubjectKeyIdentifier)
    // so SignerInfo.version=1 per RFC 5652 §5.3 ("If the
    // SignerIdentifier is issuerAndSerialNumber, then version MUST be
    // 1; if it is subjectKeyIdentifier, version MUST be 3"). The
    // M6.4.3 verifier does not enforce the sid contents — it tries
    // every trusted root in the supplied trust store.
    let serial = SerialNumber::new(&[0x01]).map_err(|e| format!("SerialNumber::new: {e}"))?;
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: RdnSequence::default(),
        serial_number: serial,
    });
    let signature_octets =
        OctetString::new(sig_bytes).map_err(|e| format!("OctetString(signature): {e}"))?;
    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid,
        digest_alg: sha256,
        signed_attrs: None,
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA_256,
            parameters: None,
        },
        signature: signature_octets,
        unsigned_attrs: None,
    };
    let signer_infos_set =
        SetOfVec::try_from(vec![signer_info]).map_err(|e| format!("signer_infos SetOfVec: {e}"))?;
    let signer_infos = SignerInfos(signer_infos_set);

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info: encap,
        certificates: None,
        crls: None,
        signer_infos,
    };

    // Wrap SignedData into ContentInfo.
    let signed_data_der = signed_data
        .to_der()
        .map_err(|e| format!("SignedData::to_der: {e}"))?;
    let signed_data_any = Any::from(
        AnyRef::try_from(signed_data_der.as_slice())
            .map_err(|e| format!("AnyRef::try_from(signed_data_der): {e}"))?,
    );
    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: signed_data_any,
    };

    content_info
        .to_der()
        .map_err(|e| format!("ContentInfo::to_der: {e}"))
}
