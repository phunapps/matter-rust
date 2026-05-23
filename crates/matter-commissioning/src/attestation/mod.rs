//! Matter device attestation verification.
//!
//! This module implements the commissioner-side checks of Matter Core
//! Spec §6.2 — verifying that a device's Device Attestation Certificate
//! (DAC) chains to a trusted Product Attestation Authority (PAA) root,
//! and that the device holds the DAC private key for the current
//! commissioning session.
//!
//! # Phase status
//!
//! - **M6.2.1 (current):** typed [`Dac`], [`Pai`], [`Paa`] wrappers
//!   around X.509 DER; [`PaaTrustStore`] with bundled CSA test roots
//!   via `PaaTrustStore::with_csa_test_roots()`; [`VendorId`] and
//!   [`ProductId`] newtypes. Parsing only — no chain validation,
//!   no `AttestationResponse`.
//! - **M6.2.2:** `verify_chain` (path validation via `rustls-webpki`
//!   plus a Matter-specific VID/PID overlay).
//! - **M6.2.3:** `verify_attestation_response` and matter.js
//!   byte-parity capture.
//!
//! # Trust scope
//!
//! [`PaaTrustStore`]'s `with_csa_test_roots()` constructor embeds
//! **test** roots only. Production callers must build their own
//! store via `PaaTrustStore::empty()` + `PaaTrustStore::add()`.

#![forbid(unsafe_code)]

pub mod error;
pub mod extensions;
pub mod trust_store;
pub mod x509;

pub use error::AttestationError;
pub use extensions::{ProductId, VendorId};
pub use trust_store::PaaTrustStore;
pub use x509::{Dac, Pai, Paa};
