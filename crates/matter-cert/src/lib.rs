//! Matter certificate format — parsing, serialisation, and chain validation.
//!
//! This is Milestone 2 of the `matter-rust` roadmap. The crate is currently a
//! placeholder.
//!
//! # Scope
//!
//! - [`certificate`]: the Matter TLV-encoded variant of X.509 certificates.
//! - [`chain`]: chain validation against trusted roots (PAA, RCAC, ICAC, NOC).
//! - [`name`]: Matter Distinguished Name handling.
//! - [`error`]: the crate error type.
//!
//! Cryptographic verification of signatures is delegated to `ring`. This crate
//! never implements the underlying maths.

#![forbid(unsafe_code)]

pub mod certificate;
pub mod chain;
pub mod error;
pub mod name;
