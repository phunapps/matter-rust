//! [`PaaTrustStore`] — the set of PAA certificates the commissioner
//! considers trusted roots for device-attestation chain validation.
//!
//! Constructed via [`PaaTrustStore::empty`] (for callers building
//! their own trust policy) or [`PaaTrustStore::with_csa_test_roots`]
//! (for examples and integration tests; never use in production).
//! There is intentionally no `Default` impl — picking the wrong
//! default for a trust anchor list is a security footgun.

use crate::attestation::x509::Paa;

/// A collection of PAA certs that the commissioner trusts as roots of
/// attestation chains.
#[derive(Debug, Clone)]
pub struct PaaTrustStore {
    roots: Vec<Paa>,
}

impl PaaTrustStore {
    /// Construct a trust store with no PAAs. Add roots via
    /// [`PaaTrustStore::add`].
    pub fn empty() -> Self {
        Self { roots: Vec::new() }
    }

    /// Construct a trust store seeded with bundled CSA **test** PAA
    /// roots. **Do not use in production.** See the module-level
    /// docs.
    //
    // Real body lands in T10 via include_bytes! of
    // src/attestation/csa_test_roots/*.der. T9 ships an empty store
    // so the public API surface is callable without compile
    // breakage; the integration test that confirms the bundled
    // roots load also lands in T10.
    pub fn with_csa_test_roots() -> Self {
        Self::empty()
    }

    /// Push a trusted PAA into the store.
    pub fn add(&mut self, paa: Paa) {
        self.roots.push(paa);
    }

    /// Return the number of PAAs in the store.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Return whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Iterate over the PAAs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &Paa> {
        self.roots.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::x509::Paa;

    const PAA_FFF1_DER: &[u8] = include_bytes!(
        "csa_test_roots/Chip-Test-PAA-FFF1-Cert.der"
    );

    #[test]
    fn empty_store_is_empty_and_zero_length() {
        let s = PaaTrustStore::empty();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.iter().next().is_none());
    }

    #[test]
    #[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
    fn add_grows_the_store() {
        let mut s = PaaTrustStore::empty();
        s.add(Paa::from_der(PAA_FFF1_DER).unwrap());
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
    fn iter_returns_paas_in_insertion_order() {
        let mut s = PaaTrustStore::empty();
        let a = Paa::from_der(PAA_FFF1_DER).unwrap();
        let b = Paa::from_der(PAA_FFF1_DER).unwrap();
        s.add(a);
        s.add(b);
        let collected: Vec<&[u8]> = s.iter().map(Paa::der).collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0], PAA_FFF1_DER);
        assert_eq!(collected[1], PAA_FFF1_DER);
    }
}
