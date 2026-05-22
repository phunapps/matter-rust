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
//!
//! ## Quick-start (M6.1 only)
//!
//! ```
//! use matter_commissioning::setup::{parse_qr, parse_manual_code};
//! # fn run() -> Result<(), matter_commissioning::setup::Error> {
//! let from_qr = parse_qr("MT:Y.K90AFN00KA0648G00")?;
//! let from_manual = parse_manual_code("11693312331")?;
//! assert_eq!(from_qr.vendor_id, Some(0xFFF1));
//! assert_eq!(from_manual.passcode.as_u32(), 20_202_021);
//! # Ok(())
//! # }
//! # let _ = run;
//! ```
//!
//! Replace the QR string + manual code above with values captured for
//! your own devices via `cargo xtask capture-setup` if you change the
//! fixture set.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod error;
pub mod noc;
pub mod setup;
pub mod state_machine;

pub use setup::{
    encode_manual_code, encode_qr, parse_manual_code, parse_qr,
    CommissioningFlow, Discriminator, DiscoveryCapabilities, Error as SetupError, Passcode,
    SetupPayload,
};
