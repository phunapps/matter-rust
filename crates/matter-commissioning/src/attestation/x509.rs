//! X.509 DER cert wrappers for the Matter attestation chain
//! ([`Dac`], [`Pai`], [`Paa`]).
//!
//! Each wrapper owns its DER bytes plus the few fields the verifier
//! needs (subject VID/PID per role, SPKI). Parsing happens once at
//! construction so the accessors are infallible and cheap.

use x509_parser::prelude::{FromDer, X509Certificate};

use crate::attestation::error::AttestationError;
use crate::attestation::extensions::{self, ProductId, VendorId};

/// Device Attestation Certificate.
///
/// Matter Core Spec §6.2.3: a conventional X.509v3 leaf certificate
/// issued by a PAI. Subject DN MUST contain both a [`VendorId`] and a
/// [`ProductId`] attribute (Matter §6.5.6).
#[derive(Debug, Clone)]
pub struct Dac {
    der: Vec<u8>,
    subject_vid: VendorId,
    subject_pid: ProductId,
    public_key: Vec<u8>,
}

impl Dac {
    /// Parse and validate the structural shape of a DAC from its DER
    /// bytes. Does NOT validate the signature chain — that's the job
    /// of `verify_chain` in M6.2.2.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::Parse`] if the DER is malformed,
    /// or if the subject DN is missing the required Matter
    /// [`VendorId`] or [`ProductId`] attribute, or if either of those
    /// attributes' values is itself malformed (not 4 UPPERCASE hex
    /// chars per Matter §6.5.6.1).
    pub fn from_der(bytes: &[u8]) -> Result<Self, AttestationError> {
        let (_, cert) = X509Certificate::from_der(bytes)
            .map_err(|e| AttestationError::Parse(Box::new(e.clone())))?;
        let subject = cert.subject();

        let vid = extensions::extract_vid(subject)
            .map_err(|e| AttestationError::Parse(Box::new(e)))?
            .ok_or_else(|| {
                AttestationError::Parse(Box::new(MissingRequired(
                    "DAC subject VendorId",
                )))
            })?;

        let pid = extensions::extract_pid(subject)
            .map_err(|e| AttestationError::Parse(Box::new(e)))?
            .ok_or_else(|| {
                AttestationError::Parse(Box::new(MissingRequired(
                    "DAC subject ProductId",
                )))
            })?;

        let public_key = cert
            .public_key()
            .subject_public_key
            .data
            .as_ref()
            .to_vec();

        Ok(Self {
            der: bytes.to_vec(),
            subject_vid: vid,
            subject_pid: pid,
            public_key,
        })
    }

    /// Borrow the original DER bytes.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Subject [`VendorId`] (Matter spec: required on DAC).
    pub fn subject_vid(&self) -> VendorId {
        self.subject_vid
    }

    /// Subject [`ProductId`] (Matter spec: required on DAC).
    pub fn subject_pid(&self) -> ProductId {
        self.subject_pid
    }

    /// Subject Public Key Info — raw P-256 SEC1 uncompressed bytes
    /// (`0x04` || X || Y, 65 bytes total). This is what `ring` will
    /// consume in M6.2.3 for ECDSA signature verification.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Placeholder. Real implementation lands in T7.
pub struct Pai;
/// Placeholder. Real implementation lands in T8.
pub struct Paa;

/// Internal error: a required DN attribute was missing. Wrapped into
/// [`AttestationError::Parse`] by callers.
#[derive(Debug, thiserror::Error)]
#[error("required field absent: {0}")]
struct MissingRequired(&'static str);

#[cfg(test)]
mod tests {
    use super::*;

    const DAC_DER: &[u8] = include_bytes!(
        "../../../../test-vectors/certs/attestation/happy-path/Chip-Test-DAC-FFF1-8000-0004-Cert.der"
    );

    #[test]
    #[allow(clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
    fn dac_from_der_parses_happy_path() {
        let dac = Dac::from_der(DAC_DER).expect("happy-path DAC parses");
        assert_eq!(dac.subject_vid(), VendorId::new(0xFFF1));
        assert_eq!(dac.subject_pid(), ProductId::new(0x8000));
    }

    #[test]
    #[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
    fn dac_round_trips_der_bytes() {
        let dac = Dac::from_der(DAC_DER).unwrap();
        assert_eq!(dac.der(), DAC_DER);
    }

    #[test]
    #[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
    fn dac_public_key_is_sec1_uncompressed_p256() {
        let dac = Dac::from_der(DAC_DER).unwrap();
        let pk = dac.public_key();
        // P-256 SEC1 uncompressed is 65 bytes: 0x04 || X(32) || Y(32).
        assert_eq!(pk.len(), 65, "P-256 uncompressed SPKI must be 65 bytes");
        assert_eq!(pk[0], 0x04, "leading byte must be 0x04 (uncompressed)");
    }

    #[test]
    #[allow(clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
    fn dac_from_der_rejects_empty_input() {
        let err = Dac::from_der(&[]).expect_err("empty bytes must error");
        assert!(matches!(err, AttestationError::Parse(_)));
    }

    #[test]
    #[allow(clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
    fn dac_from_der_rejects_truncated_input() {
        let err = Dac::from_der(&DAC_DER[..10]).expect_err("truncated must error");
        assert!(matches!(err, AttestationError::Parse(_)));
    }

    #[test]
    #[allow(clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
    fn dac_from_der_rejects_random_bytes() {
        let garbage = vec![0xAA; 256];
        let err = Dac::from_der(&garbage).expect_err("garbage must error");
        assert!(matches!(err, AttestationError::Parse(_)));
    }
}
