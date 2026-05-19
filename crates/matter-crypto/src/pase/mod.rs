//! Matter PASE (Password Authenticated Session Establishment).
//!
//! Implementation lands across phases:
//! - M3.1 (current): math + KDF primitives in submodules.
//! - M3.2: wire-format messages + PaseProver/PaseVerifier state machines.
//! - M3.3: matter.js byte-parity verification + readiness markers.

pub(crate) mod kdf;
pub(crate) mod messages;
pub(crate) mod prover;
pub(crate) mod spake2plus;

pub use prover::PaseProver;

/// Identifies one of the 5 PASE message types. Used by
/// [`crate::Error::UnexpectedMessage`] and `expected_inbound()` accessors
/// on the state machines (added in M3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaseMessageKind {
    /// Commissioner -> verifier, negotiation path.
    PbkdfParamRequest,
    /// Verifier -> commissioner, negotiation path.
    PbkdfParamResponse,
    /// Commissioner -> verifier, X point.
    Pake1,
    /// Verifier -> commissioner, Y point + cB confirmation.
    Pake2,
    /// Commissioner -> verifier, cA confirmation.
    Pake3,
}

/// Negotiable PASE PBKDF parameters (Matter spec §3.10.3).
///
/// Produced by decoding a `PbkdfParamResponse` and consumed by both
/// `PaseProver` and `PaseVerifier` state machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasePbkdfParams {
    /// PBKDF2 iteration count. Matter spec §3.10.3 requires ≥ 1000.
    pub iterations: u32,
    /// PBKDF2 salt. Matter spec §3.10.3 requires 16–32 bytes.
    pub salt: Vec<u8>,
}

/// Session keys produced by a completed PASE handshake (spec §3.10.7).
///
/// Contains the 16-byte shared secret `Ke` (`TT_HASH`\[16..32\]) and the
/// three per-session keys derived from it via HKDF `"SessionKeys"`.
///
/// # Key layout (matter.js `NodeSession.ts`, commissioner = initiator)
///
/// ```text
/// blob = HKDF-SHA256(Ke, salt=[], "SessionKeys", 48)
/// i2r_key  = blob[0..16]   (initiator→responder; encrypt for commissioner)
/// r2i_key  = blob[16..32]  (responder→initiator; decrypt for commissioner)
/// attestation_key = blob[32..48]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaseSessionKeys {
    /// Shared symmetric secret (`Ke`): `TT_HASH`\[16..32\].
    ///
    /// This is the raw SPAKE2+ session secret. Higher layers can re-derive
    /// `i2r_key`, `r2i_key`, and `attestation_key` from this alone.
    pub ke: [u8; 16],
    /// Initiator-to-responder (commissioner → device) encryption key.
    pub i2r_key: [u8; 16],
    /// Responder-to-initiator (device → commissioner) decryption key.
    pub r2i_key: [u8; 16],
    /// Attestation challenge key (used for device attestation in commissioning).
    pub attestation_key: [u8; 16],
}
