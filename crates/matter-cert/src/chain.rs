//! Matter certificate chain validation.
//!
//! Walks an ordered slice of [`MatterCertificate`]s (leaf to topmost
//! intermediate) and verifies that the chain anchors against a known
//! trusted root. Per-cert checks: time bounds, CA bit (above the leaf),
//! issuer/subject linkage (structural DN equality), path-length
//! constraint, and signature verification (via M2.3's
//! [`crate::MatterCertificate::verify_signed_by`]).
//!
//! See `docs/superpowers/specs/2026-05-18-matter-cert-chain-validation-design.md`
//! for the full design.

use crate::certificate::MatterCertificate;
use crate::error::{Error, Result};
use crate::extensions::KeyIdentifier;
use crate::name::DistinguishedName;
use crate::public_key::PublicKey;
use crate::time::MatterTime;

/// A trust anchor — a known-good public key paired with the DN under
/// which it was certified and, optionally, its subject-key-identifier
/// for the X.509-style AKI/SKI link check.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    subject: DistinguishedName,
    public_key: PublicKey,
    subject_key_identifier: Option<KeyIdentifier>,
}

impl TrustAnchor {
    /// Build an anchor from a known-good root certificate.
    ///
    /// Extracts subject, public key, and (if present) SKI from the cert.
    /// When the cert lacks a `SubjectKeyIdentifier` extension, the
    /// anchor matches by DN only.
    #[must_use]
    pub fn from_root_cert(root: &MatterCertificate) -> Self {
        Self {
            subject: root.subject().clone(),
            public_key: root.public_key().clone(),
            subject_key_identifier: root.extensions().subject_key_identifier,
        }
    }

    /// Build an anchor from raw fields.
    ///
    /// `subject_key_identifier` is optional — when `None`, this anchor
    /// matches by DN only (the SKI gate is skipped for this anchor).
    #[must_use]
    pub fn from_raw(
        subject: DistinguishedName,
        public_key: PublicKey,
        subject_key_identifier: Option<KeyIdentifier>,
    ) -> Self {
        Self {
            subject,
            public_key,
            subject_key_identifier,
        }
    }

    /// Returns the subject DN of this trust anchor.
    #[must_use]
    pub fn subject(&self) -> &DistinguishedName {
        &self.subject
    }

    /// Returns the public key of this trust anchor.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the subject key identifier of this trust anchor, if present.
    #[must_use]
    pub fn subject_key_identifier(&self) -> Option<&KeyIdentifier> {
        self.subject_key_identifier.as_ref()
    }
}

/// A collection of trusted roots.
///
/// Validation succeeds only if the chain anchors against at least
/// one entry here.
#[derive(Debug, Clone, Default)]
pub struct TrustedRoots {
    anchors: Vec<TrustAnchor>,
}

impl TrustedRoots {
    /// Create an empty set of trusted roots.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trust anchor to this set.
    pub fn add(&mut self, anchor: TrustAnchor) {
        self.anchors.push(anchor);
    }

    /// Iterate over all trust anchors in this set.
    pub fn iter(&self) -> impl Iterator<Item = &TrustAnchor> {
        self.anchors.iter()
    }

    /// Returns the number of trust anchors in this set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Returns `true` if this set contains no trust anchors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// A chain of Matter certificates, ordered from leaf to topmost
/// intermediate. The root itself is supplied separately via
/// [`TrustedRoots`].
#[derive(Debug, Clone, Copy)]
pub struct CertificateChain<'a> {
    certs: &'a [MatterCertificate],
}

impl<'a> CertificateChain<'a> {
    /// Wrap a slice of certs as a chain.
    ///
    /// Empty slices are accepted here — [`Self::validate`] is what
    /// rejects them (with [`Error::UntrustedRoot`]).
    #[must_use]
    pub fn new(certs: &'a [MatterCertificate]) -> Self {
        Self { certs }
    }

    /// Returns the number of certificates in this chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Returns `true` if this chain contains no certificates.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Validate the chain against `roots` at the moment `at`.
    ///
    /// Returns `Ok(())` iff every per-cert check passes AND the topmost
    /// cert anchors against at least one entry in `roots`.
    ///
    /// # Errors
    ///
    /// Returns the most-specific `Error` variant identifying which check
    /// failed; for per-cert failures the variant carries `cert_index`
    /// (0 = leaf). [`Error::UntrustedRoot`] is returned for empty chains,
    /// no matching anchor, or anchor signature failure.
    pub fn validate(&self, roots: &TrustedRoots, at: MatterTime) -> Result<()> {
        // Real implementation lands in Task 6. Placeholder so the file
        // compiles; the empty-chain return value happens to match the
        // final intended behaviour, so the test below stays valid.
        let _ = (roots, at);
        Err(Error::UntrustedRoot)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    #[test]
    fn trusted_roots_default_is_empty() {
        let roots = TrustedRoots::default();
        assert!(roots.is_empty());
        assert_eq!(roots.len(), 0);
        assert_eq!(roots.iter().count(), 0);
    }

    #[test]
    fn certificate_chain_empty_reports_zero_length() {
        let chain = CertificateChain::new(&[]);
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn placeholder_validate_returns_untrusted_root_for_empty_chain() {
        let roots = TrustedRoots::new();
        let chain = CertificateChain::new(&[]);
        let err = chain
            .validate(&roots, MatterTime::from_unix_secs(1_700_000_000))
            .unwrap_err();
        assert!(matches!(err, Error::UntrustedRoot));
    }
}
