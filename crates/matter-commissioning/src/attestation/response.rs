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
}
