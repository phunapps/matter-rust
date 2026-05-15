//! Matter commissioning state machine.
//!
//! This is Milestone 6 of the `matter-rust` roadmap. The crate is currently a
//! placeholder.
//!
//! # Scope
//!
//! - [`setup`]: setup payload parsing (QR codes and manual codes).
//! - [`state_machine`]: the ten-stage commissioning state machine.
//! - [`attestation`]: device attestation verification (DAC → PAI → PAA).
//! - [`noc`]: Node Operational Certificate issuance from a trust root.
//! - [`error`]: the crate error type.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod error;
pub mod noc;
pub mod setup;
pub mod state_machine;
