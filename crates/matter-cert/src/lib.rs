//! Matter protocol certificate format — parsing and serialisation.
//!
//! Implements Matter Core Specification §6.5: a TLV-encoded variant of
//! X.509 used for both attestation chains (DAC → PAI → PAA) and
//! operational chains (NOC → ICAC → RCAC).
//!
//! # Scope
//!
//! M2.1: types, TLV parser, TLV serialiser. Byte-for-byte round-trip
//! is enforced by the integration test against captured CSA test
//! certificates.
//!
//! M2.2: public-key extraction + ECDSA-P256-SHA256 signature verification
//! primitive via `ring`.
//!
//! M2.3: Matter-TLV → X.509-DER `TBSCertificate` conversion that
//! lets `MatterCertificate::verify_signed_by` work on signatures
//! produced by matter.js (and the broader Matter ecosystem). Byte parity
//! against matter.js's `asUnsignedDer()` is the correctness gate.
//!
//! M2.4 (current): `CertificateChain::validate` against trusted roots,
//! plus `TrustAnchor` / `TrustedRoots`. Per-cert checks: time bounds,
//! CA bit (above the leaf), DN linkage, path-length constraint, and
//! signature verification via M2.3's `verify_signed_by`.
//!
//! crates.io publish remains user-driven (the crate is feature-complete
//! at `0.1.0-pre` after M2.4).
//!
//! Cryptographic verification is delegated to `ring`. This crate
//! never implements the underlying maths.

#![forbid(unsafe_code)]

mod tlv_tags;
mod x509;

pub mod builder;
pub mod certificate;
pub mod chain;
pub mod error;
pub mod extensions;
pub mod name;
pub mod public_key;
pub mod signature;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod time;

pub use builder::{Builder, UnsignedCertificate};
pub use certificate::MatterCertificate;
pub use chain::{CertificateChain, TrustAnchor, TrustedRoots};
pub use error::{Error, Result};
pub use extensions::{BasicConstraints, Extensions, KeyIdentifier, KeyUsage};
pub use name::{DistinguishedName, DnAttribute, DnAttributeValue};
pub use public_key::PublicKey;
pub use signature::Signature;
pub use time::MatterTime;
