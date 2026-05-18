//! Error type for `matter-crypto`.

use thiserror::Error;

use crate::pase::PaseMessageKind;

/// All errors `matter-crypto` can produce in M3 (PASE). M4 (CASE) will
/// extend this enum; `#[non_exhaustive]` keeps that addition non-breaking.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    // --- Spec-defined PASE status codes — transmissible on the wire. ---
    /// Spec §3.10.5 status code: peer's parameter was malformed or out of range.
    #[error("PASE: invalid parameter")]
    InvalidParameter,

    /// Spec §3.10.5 status code: peer's signature or confirmation tag did not validate.
    #[error("PASE: invalid signature or tag")]
    InvalidSignatureOrTag,

    /// Spec §3.10.5 status code: referenced session does not exist.
    #[error("PASE: session not found")]
    SessionNotFound,

    /// Spec §3.10.5 status code: referenced session has expired.
    #[error("PASE: session expired")]
    SessionExpired,

    /// Spec §3.10.5 status code: peer is busy.
    #[error("PASE: busy")]
    Busy,

    // --- Internal errors — never on the wire. ---
    /// TLV codec error propagated from `matter-codec`.
    #[error("TLV codec error: {0}")]
    Codec(#[from] matter_codec::Error),

    /// SPAKE2+ scalar was zero or out of range after sampling/reduction.
    #[error("invalid SPAKE2+ scalar (out of range or all-zero)")]
    InvalidScalar,

    /// Confirmation tag did not match in constant-time compare.
    ///
    /// We never tell the peer which tag failed — that itself would be
    /// a side-channel. Local-only abort.
    #[error("confirmation tag did not match (constant-time compare)")]
    ConfirmationTagMismatch,

    /// Caller invoked a state-machine method that doesn't match the
    /// current expected message (e.g., `handle_pake3` before `handle_pake2`).
    #[error("unexpected PASE message: expected {expected:?}, got {got:?}")]
    UnexpectedMessage {
        /// The next message kind the state machine was expecting.
        expected: PaseMessageKind,
        /// The kind the caller tried to feed.
        got: PaseMessageKind,
    },

    /// PIN-to-w0/w1 derivation failed.
    #[error("PIN derivation failed")]
    PinDerivationFailed,

    /// PBKDF iteration count below the Matter spec minimum (1000).
    #[error("PBKDF iteration count {0} below spec minimum 1000")]
    PbkdfIterationsTooLow(u32),

    /// PBKDF salt length outside [16, 32] bytes per Matter spec §3.10.3.
    #[error("PBKDF salt length {0} not in [16, 32]")]
    PbkdfSaltLengthInvalid(usize),

    /// `finish()` called before the handshake completed all phases.
    #[error("`finish` called before handshake complete")]
    HandshakeIncomplete,
}

/// `Result<T, Error>` for convenience.
pub type Result<T> = core::result::Result<T, Error>;
