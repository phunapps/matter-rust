//! Matter commissioning state machine.
//!
//! This is Milestone 6 of the `matter-rust` roadmap. The crate is currently
//! shipping in phases:
//!
//! - **M6.1 (current):** setup payload codec — see [`setup`].
//! - **M6.2:** device attestation verification — see [`attestation`].
//! - **M6.3:** Node Operational Certificate issuance — see [`noc`].
//! - **M6.4:** ten-stage commissioning state machine — see [`state_machine`].
//! - **M6.5:** Wi-Fi network commissioning.
//! - **M6.6:** Tokio driver + first real-device commission.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod error;
pub mod noc;
pub mod setup;
pub mod state_machine;
