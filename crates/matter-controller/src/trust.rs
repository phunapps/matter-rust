//! Device-attestation trust material: the PAA roots that anchor DAC/PAI chain
//! validation and the CD signing roots that anchor Certification-Declaration
//! signatures. Configured once on the controller (attestation is a fabric-wide
//! security policy — chip holds it on the commissioner the same way).
//!
//! This is a concrete value type for v1.0. When ledger-backed sourcing (DCL)
//! lands post-1.0, a `trait AttestationVerifier` can emerge here without an
//! API break to the commissioning entry point.

use std::path::Path;

use matter_commissioning::{CdSigningRoots, PaaTrustStore};

use crate::error::Error;

/// The trust anchors used to verify a device during commissioning.
#[derive(Debug)]
pub struct AttestationTrust {
    pub(crate) paa: PaaTrustStore,
    pub(crate) cd: CdSigningRoots,
}

impl AttestationTrust {
    /// Construct from the bundled CSA **test** roots. Suitable for CSA-test
    /// devices and the hermetic loopback; real certified devices need
    /// [`Self::from_dirs`] pointed at production roots.
    #[must_use]
    pub fn csa_test_roots() -> Self {
        Self {
            paa: PaaTrustStore::with_csa_test_roots(),
            cd: CdSigningRoots::with_csa_test_roots(),
        }
    }

    /// Load PAA roots from a directory of `.der` certificates and CD signing
    /// roots from a directory (or single file) of `.der` certificates — the
    /// production path (e.g. connectedhomeip's `credentials/production/...`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Trust`] if a directory cannot be read or a certificate
    /// fails to parse.
    pub fn from_dirs(paa_dir: &Path, cd_dir: &Path) -> Result<Self, Error> {
        let mut paa = PaaTrustStore::empty();
        for entry in
            std::fs::read_dir(paa_dir).map_err(|e| Error::Trust(format!("paa dir: {e}")))?
        {
            let path = entry
                .map_err(|e| Error::Trust(format!("paa entry: {e}")))?
                .path();
            if path.extension().and_then(|x| x.to_str()) != Some("der") {
                continue;
            }
            let der = std::fs::read(&path).map_err(|e| Error::Trust(format!("paa read: {e}")))?;
            let cert = matter_commissioning::Paa::from_der(&der)
                .map_err(|e| Error::Trust(format!("paa parse {}: {e:?}", path.display())))?;
            paa.add(cert);
        }

        let mut cd_ders: Vec<Vec<u8>> = Vec::new();
        if cd_dir.is_dir() {
            for entry in
                std::fs::read_dir(cd_dir).map_err(|e| Error::Trust(format!("cd dir: {e}")))?
            {
                let path = entry
                    .map_err(|e| Error::Trust(format!("cd entry: {e}")))?
                    .path();
                if path.extension().and_then(|x| x.to_str()) != Some("der") {
                    continue;
                }
                cd_ders
                    .push(std::fs::read(&path).map_err(|e| Error::Trust(format!("cd read: {e}")))?);
            }
        } else {
            cd_ders.push(std::fs::read(cd_dir).map_err(|e| Error::Trust(format!("cd read: {e}")))?);
        }
        let refs: Vec<&[u8]> = cd_ders.iter().map(Vec::as_slice).collect();
        let cd = CdSigningRoots::from_cert_der(&refs)
            .map_err(|e| Error::Trust(format!("cd parse: {e:?}")))?;

        Ok(Self { paa, cd })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md allows unwrap/expect with justification.
mod tests {
    use super::*;

    #[test]
    fn csa_test_roots_constructs() {
        let _trust = AttestationTrust::csa_test_roots();
        // Construction succeeds and yields usable PAA + CD stores; deeper
        // verification is covered by matter-commissioning's attestation tests.
    }

    #[test]
    fn from_dirs_errors_on_missing_dir() {
        let err = AttestationTrust::from_dirs(
            Path::new("/nonexistent/paa"),
            Path::new("/nonexistent/cd"),
        )
        .expect_err("missing dir must error");
        assert!(matches!(err, Error::Trust(_)));
    }
}
