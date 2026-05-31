//! Async Tokio commissioning driver (M6.6) — the IO layer beneath the sans-IO
//! [`Commissioner`](crate::Commissioner).
//!
//! Gated behind the `driver` feature. M6.6.2 ships the foundation only:
//! the [`AsyncDatagram`] transport seam, the secured-exchange round-trip
//! helper, and the unsecured (session-id 0) framing the PASE handshake uses.
//! The PASE/CASE bridges (M6.6.3) and the `commission()` orchestration
//! (M6.6.4) build on top of these in later slices.

mod datagram;
mod error;
mod exchange;
mod unsecured;

pub use error::DriverError;
pub use datagram::{AsyncDatagram, InMemoryDatagram};
// TODO(M6.6.2): re-enable as each submodule lands in its own task.
pub use exchange::{secured_round_trip, SecuredResponse};
pub use unsecured::{decode_unsecured, encode_unsecured, UnsecuredExchange, UnsecuredMessage};
