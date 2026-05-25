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
//! - **M6.2.1:** typed [`Dac`], [`Pai`], [`Paa`] wrappers around
//!   X.509 DER; [`PaaTrustStore`] with bundled CSA test roots;
//!   [`VendorId`] and [`ProductId`] newtypes. Parsing only.
//! - **M6.2.2 (current):** [`verify_chain`] — `rustls-webpki` 0.103
//!   path validation with `KeyUsage::client_auth()`, plus a Matter
//!   VID/PID equality overlay. Six new [`AttestationError`] variants:
//!   [`AttestationError::InvalidChain`],
//!   [`AttestationError::TimeBoundsViolation`],
//!   [`AttestationError::BasicConstraintsViolation`],
//!   [`AttestationError::UntrustedRoot`],
//!   [`AttestationError::VidMismatch`],
//!   [`AttestationError::PaiVidNotAuthorized`].
//!   Coverage: happy-path test against the bundled CSA chain, 7
//!   directed mapping tests on `webpki::Error` -> typed variant, an
//!   8-row negative-fixture integration matrix, and a libfuzzer
//!   target on [`Dac::from_der`].
//! - **M6.2.3:** `verify_attestation_response` and matter.js
//!   byte-parity capture.
//!
//! # Trust scope
//!
//! [`PaaTrustStore`]'s `with_csa_test_roots()` constructor embeds
//! **test** roots only. Production callers must build their own
//! store via `PaaTrustStore::empty()` + `PaaTrustStore::add()`.

#![forbid(unsafe_code)]

pub mod chain;
pub mod error;
pub mod extensions;
pub mod response;
pub mod trust_store;
pub mod x509;

pub use chain::{verify_chain, ChainVerification};
pub use error::AttestationError;
pub use extensions::{ProductId, VendorId};
pub use response::{verify_attestation_response, AttestationResponse};
pub use trust_store::PaaTrustStore;
pub use x509::{Dac, Paa, Pai};
