//! Matter network transport.
//!
//! This is Milestone 5 of the `matter-rust` roadmap. The crate is currently a
//! placeholder.
//!
//! # Scope
//!
//! - [`udp`]: IPv6 UDP transport with link-local address handling.
//! - [`mdns`]: discovery of commissionable and operational Matter devices
//!   (wraps `mdns-sd`).
//! - [`framing`]: the Matter secured-message format and reception state
//!   machine (replay protection).
//! - [`mrp`]: the Message Reliability Protocol (Matter's transport-layer
//!   reliability over unreliable UDP).
//! - [`error`]: the crate error type.

#![forbid(unsafe_code)]

pub mod error;
pub mod framing;
pub mod mdns;
pub mod mrp;
pub mod udp;
