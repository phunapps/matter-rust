//! Error type for the attestation module.
//!
//! M6.2.1 ships only the [`AttestationError::Parse`] variant; the
//! validation- and signature-related variants are added in M6.2.2 and
//! M6.2.3 when there is code to emit them.

use thiserror::Error;

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
}
