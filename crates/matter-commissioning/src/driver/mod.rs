//! Async Tokio commissioning driver (M6.6) — the IO layer beneath the sans-IO
//! [`Commissioner`](crate::Commissioner).
//!
//! Gated behind the `driver` feature. M6.6.2 ships the foundation only:
//! the [`AsyncDatagram`] transport seam, the secured-exchange round-trip
//! helper, and the unsecured (session-id 0) framing the PASE handshake uses.
//! The PASE/CASE bridges (M6.6.3) and the `commission()` orchestration
//! (M6.6.4) build on top of these in later slices.

mod case;
mod commission;
mod datagram;
mod error;
mod exchange;
mod pase;
mod unsecured;

pub use case::{operational_instance_name, resolve_operational, run_case, run_case_establish};
pub use commission::{commission, resolve_commissionable, DriverConfig};
pub use datagram::{AsyncDatagram, InMemoryDatagram};
pub use error::DriverError;
pub use exchange::{
    secured_read, secured_round_trip, SecuredResponse, MAX_READ_BYTES, MAX_READ_CHUNKS,
    MAX_READ_CHUNK_BYTES,
};
pub use pase::run_pase;
pub use unsecured::{
    decode_unsecured, encode_unsecured, encode_unsecured_reply, parse_status_report,
    require_handshake_opcode, SecureChannelStatus, UnsecuredExchange, UnsecuredMessage,
};
