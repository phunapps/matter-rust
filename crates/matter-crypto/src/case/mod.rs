//! Matter CASE (Certificate Authenticated Session Establishment) via SIGMA-I.
//!
//! Implementation lands across phases:
//! - M4.1 (current): math + Sigma1/2/3 state machines + new-session wire messages.
//! - M4.2: session resumption (`Sigma2_Resume`, `Sigma3_Resume`).
//! - M4.3: matter.js byte-parity verification + readiness markers.
//!
//! See Matter Core Specification §4.13 and
//! `docs/superpowers/specs/2026-05-19-matter-crypto-case-design.md`.

pub(crate) mod initiator;
pub(crate) mod messages;
pub(crate) mod responder;
pub(crate) mod sigma;
pub(crate) mod signer;

/// Identifies one of the 5 CASE message types. Used by
/// [`crate::Error::UnexpectedMessage`] and `expected_inbound()` accessors
/// on the state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaseMessageKind {
    /// The first CASE message sent by the initiator (new-session path).
    Sigma1,
    /// The responder's reply to `Sigma1` (new-session path).
    Sigma2,
    /// The initiator's final message completing the handshake (new-session path).
    Sigma3,
    /// Resumption response (M4.2).
    Sigma2Resume,
    /// Resumption finish (M4.2).
    Sigma3Resume,
}
