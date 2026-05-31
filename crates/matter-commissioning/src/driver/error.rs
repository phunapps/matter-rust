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

    /// A frame arrived on a secured session (non-zero session id) where the
    /// unsecured PASE path expected session id 0.
    #[error("expected unsecured (session-id 0) message, got session id {0}")]
    UnexpectedSecuredMessage(u16),
}
