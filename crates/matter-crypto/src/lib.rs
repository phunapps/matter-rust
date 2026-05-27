//! Matter session-establishment protocols.
//!
//! Milestones 3 (PASE / SPAKE2+) and 4 (CASE / SIGMA) of the `matter-rust`
//! roadmap.
//!
//! # Scope
//!
//! - [`pase`]: Password Authenticated Session Establishment (SPAKE2+).
//!   M3.1 (current): math + KDF primitives. M3.2: state machines.
//!   M3.3: matter.js byte-parity verification.
//! - [`case`]: Certificate Authenticated Session Establishment (SIGMA-I).
//!   Placeholder; M4 territory.
//! - [`error`]: the crate error type.
//!
//! # Cryptographic discipline
//!
//! This crate never implements primitives. AES, ECDH, ECDSA, SHA, HKDF, and
//! HMAC come from `ring`. EC scalar/point arithmetic (which ring deliberately
//! doesn't expose) comes from `p256`. We implement only the Matter-defined
//! protocols on top of those primitives.
//!
//! Releases that change anything in this crate require external cryptographic
//! review before publishing. See `CONTRIBUTING.md`.

#![forbid(unsafe_code)]

pub mod aead;
pub mod case;
pub mod error;
pub mod pase;

#[cfg(feature = "test-support")]
pub mod test_support;

pub use case::initiator::CaseInitiator;
pub use case::responder::CaseResponder;
pub use case::signer::{CaseSigner, RingSigner, SignerError};

/// Canonical name for the ECDSA-P256-SHA256 signer trait outside CASE.
///
/// `CaseSigner` is the original name (introduced in M4.1). Outside the
/// CASE handshake, callers should import this re-export — the trait
/// itself is identical.
pub use case::signer::CaseSigner as Signer;
pub use case::{
    CaseCredentials, CaseMessageKind, CaseSessionKeys, CaseSessionOutput, LocalInfo, PeerInfo,
    ResumptionId, ResumptionRecord, Sigma1Outcome,
};
pub use error::{Error, Result};
pub use pase::{PaseMessageKind, PasePbkdfParams, PaseProver, PaseSessionKeys, PaseVerifier};
