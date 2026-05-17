//! Matter protocol certificate format — parsing and serialisation.
//!
//! Implements Matter Core Specification §6.5: a TLV-encoded variant of
//! X.509 used for both attestation chains (DAC → PAI → PAA) and
//! operational chains (NOC → ICAC → RCAC).
//!
//! # Scope
//!
//! M2.1 (current): types, TLV parser, TLV serialiser. Byte-for-byte
//! round-trip is enforced by the integration test against captured
//! CSA test certificates.
//!
//! M2.2 adds public-key extraction + ECDSA-P256-SHA256 signature
//! verification via `ring`. M2.3 adds `CertificateChain::validate`
//! against trusted roots plus the first `0.1.0` crates.io release.
//!
//! Cryptographic verification is delegated to `ring`. This crate
//! never implements the underlying maths.

#![forbid(unsafe_code)]

mod tlv_tags;

pub mod certificate;
pub mod error;
pub mod extensions;
pub mod name;
pub mod public_key;
pub mod signature;
pub mod time;

pub use certificate::MatterCertificate;
pub use error::{Error, Result};
pub use extensions::{BasicConstraints, Extensions, KeyIdentifier, KeyUsage};
pub use name::{DistinguishedName, DnAttribute, DnAttributeValue};
pub use public_key::PublicKey;
pub use signature::Signature;
pub use time::MatterTime;
