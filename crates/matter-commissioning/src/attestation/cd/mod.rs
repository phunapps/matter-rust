//! Certification Declaration (CD) verification (M6.4.3).
//!
//! Matter Core Spec §6.3.1: the Certification Declaration is a CMS /
//! PKCS#7 `SignedData` blob signed by a CSA-controlled signing root,
//! declaring the device's vendor ID, product ID list, format
//! version, security level, security information, version number, and
//! certification type.
//!
//! The commissioner verifies the CD's signature against a trusted
//! root and cross-checks the declared VID + PID against the verified
//! DAC subject before accepting the device's claimed identity.
//! Without this step, a genuine DAC for product X could fraudulently
//! claim to commission product Y.
//!
//! # Phase status
//!
//! - **M6.4.3 T28 (this module):** skeleton wiring — [`CdSigningRoots`]
//!   trust store, [`verify_certification_declaration`] flow with full
//!   CMS / signature / VID / PID checks, plus placeholder
//!   `parse_pem_public_key` and `parse_inner_cd_tlv` helpers that
//!   T29 and T30 fill in. Five new
//!   [`crate::attestation::AttestationError`] variants are exposed.
//! - **M6.4.3 T29:** PEM `SubjectPublicKeyInfo` parser — enables the
//!   bundled CSA-test root to load.
//! - **M6.4.3 T30:** inner CD TLV parser — exposes `vendor_id` and
//!   `product_ids` for the VID / PID cross-check.

#![forbid(unsafe_code)]

mod verifier;

pub use verifier::{
    verify_certification_declaration, verify_certification_declaration_with_paa, CdSigningRoots,
};
