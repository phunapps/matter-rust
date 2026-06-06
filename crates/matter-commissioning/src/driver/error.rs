//! The IO-layer error type for the commissioning driver (M6.6).
//!
//! `DriverError` sits *above* the sans-IO errors: it wraps transport,
//! crypto-handshake, Interaction-Model-framing, and state-machine errors as
//! they surface while driving real IO, and adds the few failures that only
//! exist at the IO layer (datagram I/O, discovery, MRP retransmit exhaustion,
//! an unexpected secured message where an unsecured one was required).

/// Error returned by the commissioning driver's IO layer.
///
/// `#[non_exhaustive]` so later M6.6 slices can add variants (e.g. discovery
/// detail, abort/rollback context) without a breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DriverError {
    /// Datagram send/recv failed at the socket layer.
    #[error("datagram I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// `matter-transport` rejected a frame, session, or MRP operation.
    #[error("transport/session error: {0}")]
    Transport(#[from] matter_transport::Error),

    /// A PASE/CASE handshake step failed.
    #[error("crypto handshake error: {0}")]
    Crypto(#[from] matter_crypto::Error),

    /// Building or parsing an Interaction Model envelope failed.
    #[error("interaction-model framing error: {0}")]
    Im(#[from] crate::im::ImError),

    /// The sans-IO commissioning state machine reported a failure.
    #[error("commissioning state-machine error: {0}")]
    Commissioning(#[from] crate::CommissioningError),

    /// Device discovery (mDNS / direct address) failed. M6.6.3+ fills detail.
    #[error("device discovery failed: {0}")]
    Discovery(String),

    /// MRP exhausted its retransmit budget on an exchange before a response
    /// arrived.
    #[error("retransmit budget exhausted on exchange {exchange_id}")]
    Timeout {
        /// The exchange id that timed out.
        exchange_id: u16,
    },

    /// A handshake invariant was violated while driving PASE/CASE (e.g. PASE
    /// negotiation produced no responder session id).
    #[error("handshake protocol error: {0}")]
    Handshake(&'static str),

    /// A frame arrived on a secured session (non-zero session id) where the
    /// unsecured PASE path expected session id 0.
    #[error("expected unsecured (session-id 0) message, got session id {0}")]
    UnexpectedSecuredMessage(u16),

    /// The peer rejected PASE/CASE session establishment with a
    /// `SecureChannel` `StatusReport` (spec §4.10.1.1) — e.g. wrong passcode
    /// or too many failed attempts.
    #[error(
        "session establishment rejected: general code {general_code}, \
         protocol code {protocol_code:#06x}"
    )]
    SessionEstablishmentFailed {
        /// `StatusReport` general code (0 = SUCCESS; 1 = FAILURE, …).
        general_code: u16,
        /// `SecureChannel` protocol-specific code (e.g. `0x0002`
        /// `InvalidParameter`).
        protocol_code: u16,
    },

    /// The commissioning state machine emitted [`crate::Action::Abort`]:
    /// the device returned an error (attestation failure, bad NOC, device
    /// policy rejection, etc.) and the run was halted. `reason` is the
    /// human-readable summary surfaced by the state machine.
    #[error("commissioning aborted: {0}")]
    Aborted(String),
}
