//! Pluggable ECDSA-P256-SHA256 signer for CASE.
//!
//! M4.1 stub. Real implementation lands in Task 3.

use matter_cert::PublicKey;

/// Errors returned by a [`CaseSigner`] implementation.
///
/// This type is intentionally `#[non_exhaustive]` so that future backends
/// (HSMs, software key stores, OS keychain) can add variants without breaking
/// callers that only handle the existing arms.
#[allow(dead_code)] // variants are consumed in Task 3 when RingSigner lands
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// Signer hardware is not available (e.g., HSM disconnected).
    #[error("signer hardware unavailable")]
    Unavailable,
    /// Signer explicitly rejected the operation (e.g., policy violation).
    #[error("signer rejected the operation: {0}")]
    Rejected(&'static str),
    /// Internal signer error (e.g., ring returned an opaque failure).
    #[error("internal signer error")]
    Internal,
}

/// Pluggable ECDSA-P256-SHA256 signer for CASE.
///
/// Full body (with `RingSigner` wrapper) lands in Task 3 of M4.1.
/// This declaration exists so `CaseCredentials.signer` can be a
/// `Box<dyn CaseSigner>` from Task 2 onwards.
pub trait CaseSigner: Send + Sync + std::fmt::Debug {
    /// Sign `message` with the NOC's private ECDSA-P256 key.
    /// Returns raw 64-byte r||s signature (Matter wire format).
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] if the signing operation fails (hardware
    /// unavailable, policy rejection, or internal error).
    fn sign_p256_sha256(&self, message: &[u8]) -> std::result::Result<[u8; 64], SignerError>;

    /// The 65-byte SEC1-uncompressed P-256 public key matching the NOC.
    fn public_key(&self) -> &PublicKey;
}
