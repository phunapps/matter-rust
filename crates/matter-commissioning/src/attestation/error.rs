//! Error type for the attestation module.
//!
//! M6.2.1 shipped only the [`AttestationError::Parse`] variant.
//! M6.2.2 adds the six chain-validation outcomes. The
//! signature-related variant (`BadResponseSignature`) lands in M6.2.3.

use thiserror::Error;

use crate::attestation::extensions::VendorId;

/// Errors produced by device attestation verification.
///
/// `#[non_exhaustive]` so future phases can add variants without a
/// breaking change.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// The DER bytes passed to one of [`crate::attestation::x509::Dac`],
    /// [`crate::attestation::x509::Pai`], or
    /// [`crate::attestation::x509::Paa`]'s `from_der` constructor failed
    /// to parse, or failed a Matter-specific subject-DN structural check
    /// (missing required VID/PID attribute, or — for
    /// [`crate::attestation::x509::Paa`] — a forbidden PID attribute).
    #[error("X.509 parse failure")]
    Parse(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Path validation rejected the chain for a reason not captured by
    /// a more specific variant. Sources a boxed `webpki::Error`
    /// (downcastable via `Error::downcast_ref` on the trait object
    /// returned by `source()`) so callers who care about the
    /// underlying webpki kind can still inspect it without our
    /// public API mentioning webpki by type.
    #[error("certificate chain validation failed")]
    InvalidChain(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// One of the certs in the chain was outside its validity window
    /// at the supplied [`matter_cert::time::MatterTime`].
    #[error("certificate expired or not yet valid")]
    TimeBoundsViolation,

    /// A non-CA cert was marked `BasicConstraints.cA = true`, or the
    /// path-length-constraint was violated.
    #[error("BasicConstraints violation")]
    BasicConstraintsViolation,

    /// No PAA in the supplied [`crate::attestation::PaaTrustStore`]
    /// matched the PAI's issuer.
    #[error("PAA not in trust store")]
    UntrustedRoot,

    /// DAC subject [`VendorId`] did not equal PAI subject [`VendorId`]
    /// (Matter §6.2.3 requires equality).
    #[error("VID mismatch: DAC={dac:?} PAI={pai:?}")]
    VidMismatch {
        /// [`VendorId`] observed on the DAC subject.
        dac: VendorId,
        /// [`VendorId`] observed on the PAI subject.
        pai: VendorId,
    },

    /// PAI is product-scoped (`subject_pid` is `Some`) and its
    /// [`crate::attestation::ProductId`] differs from the DAC's.
    /// Matter §6.2.3: a scoped PAI authorises only the matching
    /// product.
    #[error("PAI is not authorized for DAC's product")]
    PaiVidNotAuthorized,
}

/// Map a [`webpki::Error`] kind to our typed [`AttestationError`].
///
/// Spec-mandated mapping (see the M6.2 design doc, §Error type —
/// "Well-known [`webpki::Error`] kinds"), adapted to `webpki 0.103`'s
/// actual variant set:
///
/// | [`webpki::Error`] kind                                                              | [`AttestationError`]          |
/// |-------------------------------------------------------------------------------------|-------------------------------|
/// | `CertExpired{..}`, `CertNotValidYet{..}`, `InvalidCertValidity`                     | `TimeBoundsViolation`         |
/// | `PathLenConstraintViolated`, `EndEntityUsedAsCa`, `CaUsedAsEndEntity`               | `BasicConstraintsViolation`   |
/// | `UnknownIssuer`                                                                     | `UntrustedRoot`               |
/// | (any other kind)                                                                    | `InvalidChain(boxed)`         |
///
/// [`AttestationError::BasicConstraintsViolation`] covers three
/// distinct `BasicConstraints`-extension errors webpki distinguishes:
/// - `EndEntityUsedAsCa` — a CA-marked cert was relied on as a leaf
///   (this is what fires when a DAC has `cA = true`, since webpki then
///   refuses to use it as the end-entity).
/// - `CaUsedAsEndEntity` — same family of bug from the other direction.
/// - `PathLenConstraintViolated` — chain too long for the intermediate's
///   declared `pathLenConstraint`.
///
/// All three are `BasicConstraints` extension semantics per RFC 5280
/// §4.2.1.9, so they fold into our single typed variant.
//
// pub(crate) because the only legitimate caller is chain.rs::verify_chain.
// Directed tests in chain.rs / this file cover every row of the table.
pub(crate) fn map_webpki_error(err: webpki::Error) -> AttestationError {
    use webpki::Error as W;
    match err {
        W::CertExpired { .. }
        | W::CertNotValidYet { .. }
        | W::InvalidCertValidity => AttestationError::TimeBoundsViolation,
        W::PathLenConstraintViolated
        | W::EndEntityUsedAsCa
        | W::CaUsedAsEndEntity => AttestationError::BasicConstraintsViolation,
        W::UnknownIssuer => AttestationError::UntrustedRoot,
        other => AttestationError::InvalidChain(Box::new(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;
    use rustls_pki_types::UnixTime;

    fn epoch() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(0))
    }

    #[test]
    fn maps_cert_expired_to_time_bounds_violation() {
        let err = map_webpki_error(webpki::Error::CertExpired {
            time: epoch(),
            not_after: epoch(),
        });
        assert!(matches!(err, AttestationError::TimeBoundsViolation));
    }

    #[test]
    fn maps_cert_not_valid_yet_to_time_bounds_violation() {
        let err = map_webpki_error(webpki::Error::CertNotValidYet {
            time: epoch(),
            not_before: epoch(),
        });
        assert!(matches!(err, AttestationError::TimeBoundsViolation));
    }

    #[test]
    fn maps_invalid_cert_validity_to_time_bounds_violation() {
        let err = map_webpki_error(webpki::Error::InvalidCertValidity);
        assert!(matches!(err, AttestationError::TimeBoundsViolation));
    }

    #[test]
    fn maps_path_len_constraint_violated_to_basic_constraints_violation() {
        let err = map_webpki_error(webpki::Error::PathLenConstraintViolated);
        assert!(matches!(err, AttestationError::BasicConstraintsViolation));
    }

    #[test]
    fn maps_end_entity_used_as_ca_to_basic_constraints_violation() {
        let err = map_webpki_error(webpki::Error::EndEntityUsedAsCa);
        assert!(matches!(err, AttestationError::BasicConstraintsViolation));
    }

    #[test]
    fn maps_ca_used_as_end_entity_to_basic_constraints_violation() {
        let err = map_webpki_error(webpki::Error::CaUsedAsEndEntity);
        assert!(matches!(err, AttestationError::BasicConstraintsViolation));
    }

    #[test]
    fn maps_unknown_issuer_to_untrusted_root() {
        let err = map_webpki_error(webpki::Error::UnknownIssuer);
        assert!(matches!(err, AttestationError::UntrustedRoot));
    }

    #[test]
    fn maps_long_tail_to_invalid_chain() {
        // Pick a kind that's NOT in the mapping table — signature
        // failure is a representative member of the "everything else"
        // bucket.
        let err = map_webpki_error(webpki::Error::InvalidSignatureForPublicKey);
        assert!(matches!(err, AttestationError::InvalidChain(_)));
    }
}
