//! Error type for `matter-cert`.

use thiserror::Error;

use crate::time::MatterTime;

/// All errors `matter-cert` can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// TLV decoding or encoding failed inside `matter-codec`.
    #[error("TLV codec error: {0}")]
    Codec(#[from] matter_codec::Error),

    /// A required certificate field was missing.
    #[error("missing required certificate field (context tag {0})")]
    MissingField(u8),

    /// A certificate field appeared more than once.
    #[error("duplicate certificate field (context tag {0})")]
    DuplicateField(u8),

    /// A certificate field had an unexpected element type.
    #[error("invalid TLV element type for certificate field (context tag {0})")]
    WrongFieldType(u8),

    /// A certificate field's value was outside the spec-defined range.
    #[error("certificate field value out of range (context tag {tag})")]
    FieldValueOutOfRange {
        /// Context tag of the offending field.
        tag: u8,
    },

    /// Signature algorithm identifier was not `ecdsa-with-sha256` (1).
    #[error("certificate signature algorithm {0} is not supported")]
    UnsupportedSignatureAlgorithm(u8),

    /// Public-key algorithm identifier was not `ec-public-key` (1).
    #[error("certificate public-key algorithm {0} is not supported")]
    UnsupportedPublicKeyAlgorithm(u8),

    /// EC curve identifier was not `prime256v1` (1).
    #[error("certificate EC curve {0} is not supported")]
    UnsupportedEcCurve(u8),

    /// Public-key bytes had wrong length.
    #[error("public-key bytes have wrong length: expected 65, got {0}")]
    WrongPublicKeyLength(usize),

    /// Public-key bytes did not start with the uncompressed-point marker (0x04).
    #[error("public-key bytes do not have the uncompressed-point prefix (0x04)")]
    BadPublicKeyPrefix,

    /// Signature bytes had wrong length.
    #[error("signature bytes have wrong length: expected 64, got {0}")]
    WrongSignatureLength(usize),

    /// A distinguished-name attribute used a context tag not defined by the spec.
    #[error("invalid distinguished-name attribute (tag {0})")]
    InvalidDnAttribute(u8),

    /// A distinguished-name attribute's value had the wrong TLV element type.
    #[error("invalid TLV type for DN attribute (tag {0})")]
    InvalidDnAttributeType(u8),

    /// A key identifier had the wrong length (must be 20 bytes).
    #[error("key identifier has wrong length: expected 20, got {0}")]
    WrongKeyIdentifierLength(usize),

    /// A Matter DN attribute had no defined X.509 OID mapping.
    ///
    /// Occurs when a [`crate::DnAttribute::Other`] is encountered during
    /// X.509 conversion. We cannot invent an X.509 OID, and matter.js
    /// wouldn't have signed against one we made up.
    #[error("Matter DN attribute (tag {0}) has no defined X.509 OID mapping")]
    DnAttributeHasNoX509Oid(u8),

    /// A DN attribute's value cannot be encoded in its X.509 ASN.1
    /// string type.
    ///
    /// E.g., a `CountryName` containing non-printable bytes cannot
    /// be encoded as `PrintableString`.
    #[error("DN attribute value cannot be encoded as X.509 {asn1_type}: {reason}")]
    InvalidDnAttributeForX509 {
        /// The ASN.1 string type that the encoding attempt targeted.
        asn1_type: &'static str,
        /// Why the value did not fit.
        reason: &'static str,
    },

    /// Signature verification failed.
    ///
    /// Reserved for M2.2; not produced by phase 1.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// A certificate's `not_before` is in the future.
    ///
    /// Reserved for M2.3; not produced by phase 1.
    #[error("certificate is not yet valid (not_before={not_before:?}, at={at:?})")]
    NotYetValid {
        /// The certificate's `not_before` timestamp.
        not_before: MatterTime,
        /// The time at which validation was attempted.
        at: MatterTime,
    },

    /// A certificate's `not_after` is in the past.
    ///
    /// Reserved for M2.3; not produced by phase 1.
    #[error("certificate has expired (not_after={not_after:?}, at={at:?})")]
    Expired {
        /// The certificate's `not_after` timestamp.
        not_after: MatterTime,
        /// The time at which validation was attempted.
        at: MatterTime,
    },

    /// A certificate chain did not terminate at a trusted root.
    ///
    /// Reserved for M2.3.
    #[error("certificate chain does not reach a trusted root")]
    UntrustedRoot,

    /// A cert's `issuer` did not match the next cert's `subject`.
    ///
    /// Reserved for M2.3.
    #[error("issuer DN does not match next cert's subject DN")]
    IssuerSubjectMismatch,

    /// A non-leaf certificate did not have `basic_constraints.is_ca = true`.
    ///
    /// Reserved for M2.3.
    #[error("non-leaf certificate is not a CA (basic_constraints.is_ca = false)")]
    NotACa,

    /// Chain length exceeded a cert's `path_len_constraint`.
    ///
    /// Reserved for M2.3.
    #[error("chain length exceeds a path-length constraint")]
    PathLengthExceeded,
}

/// `Result<T, Error>` for convenience.
pub type Result<T> = core::result::Result<T, Error>;
