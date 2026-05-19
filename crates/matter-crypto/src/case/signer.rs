//! Pluggable ECDSA-P256-SHA256 signer for CASE.
//!
//! M4.1 stub. Real implementation lands in Task 3.

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
