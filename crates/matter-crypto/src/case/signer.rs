//! Pluggable ECDSA-P256-SHA256 signer for CASE.
//!
//! M4.1: `SignerError`, `CaseSigner` trait, and `RingSigner` (the in-tree
//! production-default implementation backed by `ring::signature::EcdsaKeyPair`).

use matter_cert::PublicKey;

use crate::error::{Error, Result};

/// Errors returned by a [`CaseSigner`] implementation.
///
/// This type is intentionally `#[non_exhaustive]` so that future backends
/// (HSMs, software key stores, OS keychain) can add variants without breaking
/// callers that only handle the existing arms.
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
/// The in-tree concrete implementation is [`RingSigner`], which wraps
/// `ring::signature::EcdsaKeyPair`. Alternative backends (HSM, OS keychain,
/// software key store) can implement this trait without touching core CASE code.
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

// ── RingSigner ────────────────────────────────────────────────────────────────

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

/// [`CaseSigner`] backed by `ring::signature::EcdsaKeyPair` — the in-tree
/// production-default implementation.
///
/// Use [`Self::from_pkcs8`] to load existing keys (e.g., from a fabric
/// store), or [`Self::generate`] in tests to mint a fresh keypair.
pub struct RingSigner {
    keypair: EcdsaKeyPair,
    rng: SystemRandom,
    public_key: PublicKey,
}

impl std::fmt::Debug for RingSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingSigner")
            .field("public_key", &self.public_key)
            .field("keypair", &"<ring::EcdsaKeyPair>")
            .finish_non_exhaustive()
    }
}

impl RingSigner {
    /// Construct from PKCS#8 v1 encoded private key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SigningFailed`] with [`SignerError::Internal`] if the
    /// bytes are not a valid PKCS#8-encoded P-256 key, or if the encoded
    /// public key does not carry the expected `0x04` uncompressed-point prefix.
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self> {
        let rng = SystemRandom::new();
        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes, &rng)
            .map_err(|_| Error::SigningFailed(SignerError::Internal))?;

        let mut pk_bytes = [0u8; 65];
        pk_bytes.copy_from_slice(keypair.public_key().as_ref());
        let public_key =
            PublicKey::new(pk_bytes).map_err(|_| Error::SigningFailed(SignerError::Internal))?;

        Ok(Self {
            keypair,
            rng,
            public_key,
        })
    }

    /// Generate a fresh ECDSA-P256 keypair. Returns the signer plus the
    /// PKCS#8 bytes so the caller can persist them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SigningFailed`] with [`SignerError::Internal`] if the
    /// OS RNG or key-generation step fails (extremely unlikely in practice).
    pub fn generate() -> Result<(Self, Vec<u8>)> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| Error::SigningFailed(SignerError::Internal))?;
        let pkcs8_vec = pkcs8.as_ref().to_vec();
        let signer = Self::from_pkcs8(&pkcs8_vec)?;
        Ok((signer, pkcs8_vec))
    }
}

impl CaseSigner for RingSigner {
    fn sign_p256_sha256(&self, message: &[u8]) -> std::result::Result<[u8; 64], SignerError> {
        let sig = self
            .keypair
            .sign(&self.rng, message)
            .map_err(|_| SignerError::Internal)?;
        let bytes = sig.as_ref();
        if bytes.len() != 64 {
            return Err(SignerError::Internal);
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_round_trip_through_pkcs8() {
        let (signer1, pkcs8) = RingSigner::generate().unwrap();
        let signer2 = RingSigner::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(
            signer1.public_key().as_bytes(),
            signer2.public_key().as_bytes()
        );
    }

    #[test]
    fn signing_produces_64_byte_signature() {
        let (signer, _) = RingSigner::generate().unwrap();
        let sig = signer.sign_p256_sha256(b"hello world").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn signing_same_message_twice_may_differ() {
        // ring's ECDSA mixes in a random nonce contribution even though it also
        // uses an RFC6979-derived component; two signs of the same message
        // produce different signatures with overwhelming probability.
        let (signer, _) = RingSigner::generate().unwrap();
        let a = signer.sign_p256_sha256(b"same").unwrap();
        let b = signer.sign_p256_sha256(b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn signing_produces_verifiable_signature() {
        use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
        let (signer, _) = RingSigner::generate().unwrap();
        let msg = b"verify me";
        let sig = signer.sign_p256_sha256(msg).unwrap();
        let pk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, signer.public_key().as_bytes());
        pk.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn pkcs8_from_invalid_bytes_returns_error() {
        let err = RingSigner::from_pkcs8(b"garbage").unwrap_err();
        assert!(matches!(err, Error::SigningFailed(SignerError::Internal)));
    }
}
