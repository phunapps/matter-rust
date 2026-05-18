//! Test-only certificate construction helpers.
//!
//! Available only when the `test-support` Cargo feature is enabled.
//! Used by this crate's own `tests/*` files to synthesise certificates
//! for negative testing and property-based testing. Not part of the
//! stable public API; production callers must not enable this feature.
//!
//! The intended flow:
//!
//! 1. Populate a [`TestCertFields`] with the cert's intended shape and
//!    a placeholder all-zero [`crate::Signature`].
//! 2. Call [`build_unsigned`] to produce a [`crate::MatterCertificate`]
//!    with the placeholder signature.
//! 3. Compute its X.509 TBS bytes via
//!    [`crate::MatterCertificate::to_x509_tbs_der`].
//! 4. Sign the TBS with `ring::signature::EcdsaKeyPair::sign` and the
//!    issuer's key pair.
//! 5. Attach the real signature via [`with_signature`].

use crate::{DistinguishedName, Extensions, MatterCertificate, MatterTime, PublicKey, Signature};

/// Field values for a synthesised certificate.
///
/// All fields are exposed publicly so test code can mutate them before
/// building the cert. Convenience templates are provided by the
/// `tests/common/mod.rs` helpers, which build on top of this module.
#[derive(Debug, Clone)]
pub struct TestCertFields {
    /// Serial number as raw bytes.
    pub serial: Vec<u8>,
    /// Issuer distinguished name.
    pub issuer: DistinguishedName,
    /// Beginning of the validity period.
    pub not_before: MatterTime,
    /// End of the validity period (`MatterTime::NO_EXPIRY` means no expiry).
    pub not_after: MatterTime,
    /// Subject distinguished name.
    pub subject: DistinguishedName,
    /// EC public key (P-256, 65-byte uncompressed).
    pub public_key: PublicKey,
    /// Parsed certificate extensions.
    pub extensions: Extensions,
    /// ECDSA-P256 signature over the X.509 TBS.
    ///
    /// Pass `Signature::new([0u8; 64])` as a placeholder; replace later
    /// with the real value using [`with_signature`].
    pub signature: Signature,
}

/// Build a [`MatterCertificate`] from the field values verbatim.
///
/// Use this when you have already computed the signature externally
/// (e.g., signed the X.509 TBS with `ring`), or when you want a
/// placeholder-signed cert for TBS extraction.
#[must_use]
pub fn build_unsigned(fields: TestCertFields) -> MatterCertificate {
    MatterCertificate::from_fields(
        fields.serial,
        fields.issuer,
        fields.not_before,
        fields.not_after,
        fields.subject,
        fields.public_key,
        fields.extensions,
        fields.signature,
    )
}

/// Replace the signature on an already-built cert, returning a new cert.
///
/// Used in the sign-then-replace flow: build with a placeholder signature,
/// compute the X.509 TBS, sign with `ring`, then call this helper with
/// the real 64-byte signature.
#[must_use]
pub fn with_signature(cert: &MatterCertificate, signature: Signature) -> MatterCertificate {
    MatterCertificate::from_fields(
        cert.serial().to_vec(),
        cert.issuer().clone(),
        cert.not_before(),
        cert.not_after(),
        cert.subject().clone(),
        cert.public_key().clone(),
        cert.extensions().clone(),
        signature,
    )
}
