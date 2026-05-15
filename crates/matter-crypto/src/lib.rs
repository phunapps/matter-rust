//! Matter session-establishment protocols.
//!
//! Milestones 3 (PASE / SPAKE2+) and 4 (CASE / SIGMA) of the `matter-rust`
//! roadmap. The crate is currently a placeholder.
//!
//! # Scope
//!
//! - [`pase`]: Password Authenticated Session Establishment (SPAKE2+).
//!   Used during commissioning.
//! - [`case`]: Certificate Authenticated Session Establishment (SIGMA-I).
//!   Used after commissioning for all operational traffic.
//! - [`error`]: the crate error type.
//!
//! # Cryptographic discipline
//!
//! This crate never implements primitives. AES, ECDH, ECDSA, SHA, HKDF, and
//! HMAC come from `ring`. We implement only the Matter-defined protocols on
//! top of those primitives.
//!
//! Releases that change anything in this crate require external cryptographic
//! review before publishing. See `CONTRIBUTING.md`.

#![forbid(unsafe_code)]

pub mod case;
pub mod error;
pub mod pase;
