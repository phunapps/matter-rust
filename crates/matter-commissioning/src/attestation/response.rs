//! Matter device attestation response signature verification.
//!
//! This is the second half of Matter Core Spec §6.2 commissioner-side
//! attestation. The first half ([`verify_chain`] in
//! [`crate::attestation::chain`]) proves the DAC chains to a trusted
//! root. This module proves the device *holds the DAC private key*
//! for the current commissioning session by verifying its ECDSA
//! signature over
//! `attestation_elements || attestation_challenge`.
//!
//! Pure sans-I/O — no network, no clock, no internal state. Callers
//! supply the `attestation_challenge` from the active PASE/CASE
//! session — a 16-byte field at offset `[32..48]` of the 48-byte HKDF
//! key blob (Matter §3.5). In our `matter-crypto` API this is exposed
//! as [`matter_crypto::CaseSessionKeys::attestation_challenge`] on the
//! CASE side and [`matter_crypto::PaseSessionKeys::attestation_key`]
//! on the PASE side — both are the same 16-byte slice; only the field
//! name differs.
//!
//! [`verify_chain`]: crate::attestation::verify_chain

#![forbid(unsafe_code)]

use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

use crate::attestation::error::AttestationError;

/// The decoded attestation-response payload a commissioner receives
/// from a device's `AttestationRequest` cluster response.
///
/// Two fields:
///
/// - `attestation_elements`: an opaque TLV blob whose contents
///   (certification declaration, attestation nonce, timestamp, optional
///   firmware info) M6.2.3 does not parse. M6.4.x will parse it to
///   verify the embedded Certification Declaration. For signature
///   verification, these bytes are simply the first half of the
///   signed input.
/// - `signature`: the device's ECDSA P-256 / SHA-256 signature over
///   `attestation_elements || attestation_challenge`, in raw IEEE P1363
///   fixed-width form (32-byte big-endian `r` || 32-byte big-endian
///   `s`, 64 bytes total). Not ASN.1 DER. This matches Matter Core
///   Spec §3.5.3 ("ECDSA signatures are encoded as fixed-width
///   representations of r and s") and matter.js's
///   `Crypto.signEcdsa` output format.
#[derive(Debug, Clone)]
pub struct AttestationResponse {
    /// Opaque attestation-elements bytes (TLV-encoded by the device;
    /// not parsed by M6.2.3).
    pub attestation_elements: Vec<u8>,
    /// Raw ECDSA P-256 signature, 32-byte `r` followed by 32-byte `s`
    /// (Matter §3.5.3 fixed-width encoding; 64 bytes total).
    pub signature: [u8; 64],
}

/// Verify that `response.signature` is the device's ECDSA P-256 /
/// SHA-256 signature over `response.attestation_elements ||
/// attestation_challenge`, produced by the private key matching
/// `dac_public_key`.
///
/// This is a pure function — no clock reads, no network, no internal
/// state. The caller is responsible for:
///
/// 1. Supplying `attestation_challenge` from the PASE or CASE session
///    that this commissioning exchange is bound to. The challenge is
///    the 16-byte tail of the session-key derivation (`keys[32..48]`,
///    per Matter Core Spec §3.5 and the byte-parity-verified CASE
///    implementation in `matter-crypto`).
/// 2. Supplying `dac_public_key` as the raw SEC1 uncompressed P-256
///    encoding — 65 bytes, leading `0x04`, then 32-byte X and 32-byte
///    Y. This is exactly the byte layout
///    [`crate::attestation::Dac::public_key`] returns and
///    [`crate::attestation::ChainVerification::dac_public_key`]
///    surfaces.
///
/// # Errors
///
/// Returns [`AttestationError::BadResponseSignature`] on any
/// verification failure — corrupt signature, wrong key, wrong
/// challenge, tampered elements, or malformed public-key bytes.
/// The variant is deliberately coarse; see the variant's rustdoc.
pub fn verify_attestation_response(
    response: &AttestationResponse,
    attestation_challenge: &[u8; 16],
    dac_public_key: &[u8],
) -> Result<(), AttestationError> {
    // Compose the to-be-verified blob exactly as the device composed
    // it before signing: attestation_elements concatenated with the
    // raw challenge bytes. Length-prefixing or framing would diverge
    // from matter.js and the C++ reference; do not add any.
    let mut tbs =
        Vec::with_capacity(response.attestation_elements.len() + attestation_challenge.len());
    tbs.extend_from_slice(&response.attestation_elements);
    tbs.extend_from_slice(attestation_challenge);

    // `ring` consumes the public key as raw SEC1 uncompressed bytes
    // for the `ECDSA_P256_SHA256_FIXED` algorithm; this matches what
    // `Dac::public_key` (M6.2.1) returns. Any failure (bad key bytes,
    // bad signature length, bad signature math) collapses into our
    // single coarse variant — the design explicitly trades granularity
    // for information-leakage hardening (see error.rs's
    // BadResponseSignature rustdoc).
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, dac_public_key);
    key.verify(&tbs, &response.signature)
        .map_err(|_| AttestationError::BadResponseSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_struct_is_constructible() {
        let r = AttestationResponse {
            attestation_elements: vec![0u8; 0],
            signature: [0u8; 64],
        };
        // Exercise the accessors so they don't dead-code-warn.
        assert_eq!(r.attestation_elements.len(), 0);
        assert_eq!(r.signature.len(), 64);
    }

    use p256::ecdsa::{signature::Signer, SigningKey, Signature};

    /// Mint a fresh P-256 keypair and return (raw SEC1 uncompressed
    /// pubkey, signature over `elements || challenge`).
    ///
    /// This helper exists so each test owns its own deterministic
    /// keypair — no shared global state, no per-test signing-key
    /// fixture file.
    #[allow(clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
    fn mint_signed(
        elements: &[u8],
        challenge: &[u8; 16],
        seed: u8,
    ) -> ([u8; 65], [u8; 64]) {
        // Deterministic 32-byte scalar so test failures repro byte-
        // identically. P-256 scalars are big-endian; placing `seed` at
        // index 0 (most-significant byte) yields a scalar around
        // `seed * 2^248`, well below the curve order for any
        // `seed <= 0xfe` and far from the pathological scalar 1
        // (which is what `scalar[31] = seed` with `seed == 1` would
        // produce). Any non-zero such scalar is a valid signing key.
        let mut scalar = [0u8; 32];
        scalar[0] = seed;
        let signing_key = SigningKey::from_slice(&scalar)
            .expect("non-zero 32-byte scalar is a valid P-256 scalar");
        let verifying_key = signing_key.verifying_key();
        let pubkey_point = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey_point.as_bytes();
        let mut pubkey_arr = [0u8; 65];
        pubkey_arr.copy_from_slice(pubkey_bytes);

        let mut tbs = Vec::with_capacity(elements.len() + 16);
        tbs.extend_from_slice(elements);
        tbs.extend_from_slice(challenge);
        let sig: Signature = signing_key.sign(&tbs);
        let sig_bytes = sig.to_bytes();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        (pubkey_arr, sig_arr)
    }

    #[test]
    #[allow(clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
    fn verify_attestation_response_accepts_valid_signature() {
        let elements = b"opaque attestation_elements TLV blob".to_vec();
        let challenge = [0x42u8; 16];
        let (pubkey, sig) = mint_signed(&elements, &challenge, 0x01);
        let response = AttestationResponse {
            attestation_elements: elements,
            signature: sig,
        };
        verify_attestation_response(&response, &challenge, &pubkey)
            .expect("valid signature must verify");
    }
}
