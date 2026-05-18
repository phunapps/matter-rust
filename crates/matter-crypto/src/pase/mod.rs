//! Matter PASE (Password Authenticated Session Establishment).
//!
//! Implementation lands across phases:
//! - M3.1 (current): math + KDF primitives in submodules.
//! - M3.2: wire-format messages + PaseProver/PaseVerifier state machines.
//! - M3.3: matter.js byte-parity verification + readiness markers.

pub(crate) mod kdf;
pub(crate) mod messages;
pub(crate) mod spake2plus;

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
