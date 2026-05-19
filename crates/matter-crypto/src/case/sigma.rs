//! SIGMA-I math primitives for Matter CASE.
//!
//! Pure functions implementing the SIGMA-I cryptographic equations used
//! in Matter Core Spec §4.13 (CASE / SIGMA). No state is held here.
//! The state-bearing [`super::initiator`] and [`super::responder`] modules
//! call these helpers to compose each handshake step.
//!
//! # Primitives
//!
//! | Primitive | Crate | Notes |
//! |-----------|-------|-------|
//! | P-256 ephemeral keypair | `p256` | rejection-sampled from `ring::rand` |
//! | ECDH | `p256::ecdh` | 32-byte X-coordinate output |
//! | SHA-256 / HKDF-SHA256 | `ring` | mirror of `pase::kdf::hkdf_expand` |
//! | AES-128-CCM | `ccm + aes` | 13-byte nonce, 16-byte tag |
//! | constant-time compare | `subtle` | never `==` on tag bytes |
//!
//! # matter.js cross-reference
//!
//! All constants below were pinned against
//! `@matter/protocol/src/session/case/CaseMessages.ts` and
//! `@matter/general/src/crypto/Crypto.ts`:
//!
//! - `CRYPTO_ENCRYPT_ALGORITHM = "aes-128-ccm"` — confirmed AES-128-CCM.
//! - `CRYPTO_AEAD_NONCE_LENGTH_BYTES = 13` — 13-byte nonce.
//! - `CRYPTO_AEAD_MIC_LENGTH_BYTES = 16` — 16-byte tag.
//! - `KDFSR2_INFO = Bytes.fromString("Sigma2")` — Sigma2 encryption key.
//! - `KDFSR3_INFO = Bytes.fromString("Sigma3")` — Sigma3 encryption key.
//! - `KDFSR1_KEY_INFO = Bytes.fromString("Sigma1_Resume")`.
//! - `KDFSR2_KEY_INFO = Bytes.fromString("Sigma2_Resume")`.
//! - `TBE_DATA2_NONCE = Bytes.fromString("NCASE_Sigma2N")`.
//! - `TBE_DATA3_NONCE = Bytes.fromString("NCASE_Sigma3N")`.
//! - `RESUME1_MIC_NONCE = Bytes.fromString("NCASE_SigmaS1")`.
//! - `RESUME2_MIC_NONCE = Bytes.fromString("NCASE_SigmaS2")`.
//!
//! The transcript hash is `SHA-256(concatenation of message bytes)` — no
//! protocol-version prefix; the IPK-derived `operationalIdentityProtectionKey`
//! acts as the domain-separating context in every HKDF salt (CaseClient.ts
//! lines 153–159, 199–203, 220–223).

// Constants and functions in this module are consumed by `initiator.rs` and
// `responder.rs` (Tasks 6/7). Until those files are populated the compiler
// sees them as dead code; this allow will be removed once Tasks 6/7 land.
#![allow(dead_code)]

use aes::Aes128;
use ccm::{
    aead::{Aead, KeyInit, Payload},
    consts::{U13, U16},
    Ccm, Nonce,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{NonZeroScalar, PublicKey as P256PublicKey, SecretKey};
use ring::digest::{digest, SHA256};
use ring::hkdf;
use ring::rand::SecureRandom;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

// =============================================================================
// AES-128-CCM type alias
// =============================================================================

/// AES-128-CCM with a 13-byte nonce and 16-byte (128-bit) authentication tag.
///
/// Matter Core Spec §3.6:
/// - `CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES = 16` (AES-128)
/// - `CRYPTO_AEAD_NONCE_LENGTH_BYTES = 13`
/// - `CRYPTO_AEAD_MIC_LENGTH_BYTES = 16`
type Aes128Ccm = Ccm<Aes128, U16, U13>;

// =============================================================================
// Constants pinned from matter.js
// =============================================================================

/// AES-128-CCM key length in bytes (16 = 128 bits).
pub(crate) const AEAD_KEY_LEN: usize = 16;

/// AES-128-CCM authentication tag length in bytes.
pub(crate) const AEAD_TAG_LEN: usize = 16;

/// AES-128-CCM nonce length in bytes.
pub(crate) const AEAD_NONCE_LEN: usize = 13;

// ---------------------------------------------------------------------------
// HKDF info labels — exact UTF-8 bytes as used by matter.js
// (from @matter/protocol/src/session/case/CaseMessages.ts)
// ---------------------------------------------------------------------------

/// HKDF info for deriving the Sigma2 `TBEData` encryption key.
///
/// `KDFSR2_INFO = Bytes.fromString("Sigma2")` in matter.js.
pub(crate) const HKDF_INFO_SIGMA2: &[u8] = b"Sigma2";

/// HKDF info for deriving the Sigma3 `TBEData` encryption key.
///
/// `KDFSR3_INFO = Bytes.fromString("Sigma3")` in matter.js.
pub(crate) const HKDF_INFO_SIGMA3: &[u8] = b"Sigma3";

/// HKDF info for deriving the `Sigma1_Resume` resumption key.
///
/// `KDFSR1_KEY_INFO = Bytes.fromString("Sigma1_Resume")` in matter.js.
pub(crate) const HKDF_INFO_SIGMA1_RESUME: &[u8] = b"Sigma1_Resume";

/// HKDF info for deriving the `Sigma2_Resume` resumption key.
///
/// `KDFSR2_KEY_INFO = Bytes.fromString("Sigma2_Resume")` in matter.js.
pub(crate) const HKDF_INFO_SIGMA2_RESUME: &[u8] = b"Sigma2_Resume";

// ---------------------------------------------------------------------------
// AEAD nonces — exact UTF-8 bytes as used by matter.js.
// All nonces are exactly 13 bytes (CRYPTO_AEAD_NONCE_LENGTH_BYTES).
// ---------------------------------------------------------------------------

/// AEAD nonce for encrypting `TBEData` in Sigma2.
///
/// `TBE_DATA2_NONCE = Bytes.fromString("NCASE_Sigma2N")` — 13 bytes.
pub(crate) const NONCE_TBE_DATA2: &[u8; AEAD_NONCE_LEN] = b"NCASE_Sigma2N";

/// AEAD nonce for encrypting `TBEData` in Sigma3.
///
/// `TBE_DATA3_NONCE = Bytes.fromString("NCASE_Sigma3N")` — 13 bytes.
pub(crate) const NONCE_TBE_DATA3: &[u8; AEAD_NONCE_LEN] = b"NCASE_Sigma3N";

/// AEAD nonce for the `Sigma1_Resume` MIC (resumption MAC).
///
/// `RESUME1_MIC_NONCE = Bytes.fromString("NCASE_SigmaS1")` — 13 bytes.
pub(crate) const NONCE_RESUME1_MIC: &[u8; AEAD_NONCE_LEN] = b"NCASE_SigmaS1";

/// AEAD nonce for the `Sigma2_Resume` MIC (resumption MAC).
///
/// `RESUME2_MIC_NONCE = Bytes.fromString("NCASE_SigmaS2")` — 13 bytes.
pub(crate) const NONCE_RESUME2_MIC: &[u8; AEAD_NONCE_LEN] = b"NCASE_SigmaS2";

// =============================================================================
// Ephemeral keypair generation
// =============================================================================

/// Generate a fresh ephemeral P-256 keypair.
///
/// Returns `(secret_key, public_key_bytes_sec1_uncompressed)`.
///
/// The public key is 65 bytes in SEC1 uncompressed form (`0x04 || X || Y`).
///
/// # Errors
///
/// Returns [`Error::EphemeralKeyGenerationFailed`] if the RNG fails or if
/// 16 consecutive scalar samples are all zero or out of range (astronomically
/// unlikely in practice).
pub(crate) fn generate_ephemeral_keypair(rng: &dyn SecureRandom) -> Result<(SecretKey, [u8; 65])> {
    // P-256 scalars must be in [1, n-1]. We rejection-sample up to 16 times;
    // the probability of hitting zero is ~2^-256 per attempt.
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .map_err(|_| Error::EphemeralKeyGenerationFailed)?;

        // `NonZeroScalar::from_repr` returns a `CtOption<NonZeroScalar>`,
        // which is `Some` iff the bytes represent a value in [1, n-1].
        let scalar_opt = NonZeroScalar::from_repr(bytes.into());
        if let Some(scalar) = Option::<NonZeroScalar>::from(scalar_opt) {
            let sk = SecretKey::new(scalar.into());
            let pk = sk.public_key();
            let encoded = pk.to_encoded_point(false); // false = uncompressed
            let mut pub_bytes = [0u8; 65];
            pub_bytes.copy_from_slice(encoded.as_bytes());
            return Ok((sk, pub_bytes));
        }
    }
    Err(Error::EphemeralKeyGenerationFailed)
}

// =============================================================================
// ECDH
// =============================================================================

/// Compute the P-256 ECDH shared secret, returning the 32-byte X-coordinate.
///
/// Matter uses the raw X-coordinate as the shared secret input to HKDF
/// (same as ANSI X9.63 without cofactor multiplication on P-256, which has
/// cofactor 1).
///
/// # Errors
///
/// Returns [`Error::InvalidParameter`] if `peer_pub_bytes` is not a valid
/// uncompressed P-256 public key.
pub(crate) fn ecdh_shared_secret(
    my_secret: &SecretKey,
    peer_pub_bytes: &[u8; 65],
) -> Result<[u8; 32]> {
    let peer_pub =
        P256PublicKey::from_sec1_bytes(peer_pub_bytes).map_err(|_| Error::InvalidParameter)?;
    // `diffie_hellman` performs scalar-multiplication and returns a
    // `SharedSecret` whose `raw_secret_bytes` is the big-endian X-coordinate.
    let shared = p256::ecdh::diffie_hellman(my_secret.to_nonzero_scalar(), peer_pub.as_affine());
    let bytes = shared.raw_secret_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    Ok(out)
}

// =============================================================================
// HKDF
// =============================================================================

/// HKDF-SHA256 expand.
///
/// Mirrors `pase::kdf::hkdf_expand`. The caller passes a pseudo-random key
/// (`prk`, 32 bytes in all CASE call sites) and an info label; the function
/// fills `out` with the requested number of bytes.
///
/// Uses an empty salt for `Extract` because `prk` is already a well-seeded
/// pseudo-random key in all CASE call sites (it is itself the output of an
/// HKDF-Extract or ECDH step).
///
/// # Errors
///
/// Returns an error only if `out.len()` exceeds ring's HKDF output limit
/// (255 × hash-length = 8160 bytes for SHA-256), which is impossible for
/// any Matter message length.
pub(crate) fn hkdf_expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk_obj = salt.extract(prk);
    let info_arr = [info];
    let okm = prk_obj
        .expand(&info_arr, OutLen(out.len()))
        .map_err(|_| Error::EphemeralKeyGenerationFailed)?;
    okm.fill(out)
        .map_err(|_| Error::EphemeralKeyGenerationFailed)?;
    Ok(())
}

/// `KeyType` adapter so we can pass a runtime-determined output length to
/// `ring::hkdf::Prk::expand`.
struct OutLen(usize);

impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

// =============================================================================
// Transcript hash
// =============================================================================

/// Compute a transcript hash: `SHA-256(msg[0] || msg[1] || ...)`.
///
/// Matter CASE uses this to bind each step's HKDF salt to all prior messages:
///
/// - Sigma2 salt includes `SHA-256(sigma1_bytes)`.
/// - Sigma3 salt includes `SHA-256(sigma1_bytes || sigma2_bytes)`.
/// - Session key salt includes `SHA-256(sigma1_bytes || sigma2_bytes || sigma3_bytes)`.
///
/// There is no protocol-version prefix; domain separation comes from the
/// IPK-derived `operationalIdentityProtectionKey` that also appears in every
/// salt (pinned from `CaseClient.ts`).
pub(crate) fn transcript_hash(messages: &[&[u8]]) -> [u8; 32] {
    // Allocate a single buffer to avoid multiple digest invocations.
    let total_len = messages.iter().map(|m| m.len()).sum();
    let mut buf: Vec<u8> = Vec::with_capacity(total_len);
    for msg in messages {
        buf.extend_from_slice(msg);
    }
    let d = digest(&SHA256, &buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

// =============================================================================
// AEAD — AES-128-CCM (13-byte nonce, 16-byte tag)
// =============================================================================

/// Encrypt `plaintext` with AES-128-CCM, returning `ciphertext || tag`.
///
/// The output is `plaintext.len() + 16` bytes: the ciphertext followed by the
/// 16-byte authentication tag. This layout matches matter.js's
/// `crypto.encrypt(key, plaintext, nonce, aad?)`.
///
/// # Errors
///
/// Returns [`Error::EphemeralKeyGenerationFailed`] on cipher initialisation
/// failure (key length mismatch — impossible at compile time with fixed array).
/// Returns the same error on encryption failure (also not expected in practice).
pub(crate) fn aead_encrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes128Ccm::new_from_slice(key).map_err(|_| Error::EphemeralKeyGenerationFailed)?;
    // `(*nonce).into()` converts `[u8; 13]` → `GenericArray<u8, U13>` via
    // the `From<[u8; N]>` impl present since generic-array 0.14.
    let nonce_arr: Nonce<U13> = (*nonce).into();
    cipher
        .encrypt(
            &nonce_arr,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::EphemeralKeyGenerationFailed)
}

/// Decrypt an AES-128-CCM ciphertext blob (`ciphertext || tag`).
///
/// The `ciphertext` slice must be at least 16 bytes (the tag). Returns the
/// original plaintext if the tag verifies; returns
/// [`Error::EncryptedBlobDecryptionFailed`] if decryption or tag verification
/// fails.
///
/// The `ccm` crate verifies the tag in constant time internally via `subtle`.
///
/// # Errors
///
/// Returns [`Error::EncryptedBlobDecryptionFailed`] on any authentication or
/// decryption failure.
pub(crate) fn aead_decrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        Aes128Ccm::new_from_slice(key).map_err(|_| Error::EncryptedBlobDecryptionFailed)?;
    let nonce_arr: Nonce<U13> = (*nonce).into();
    cipher
        .decrypt(
            &nonce_arr,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::EncryptedBlobDecryptionFailed)
}

// =============================================================================
// Constant-time MAC verify
// =============================================================================

/// Constant-time 16-byte MAC comparison.
///
/// Used for Sigma resumption MAC tags (`RESUME1_MIC` / `RESUME2_MIC`).
/// MUST NOT use `==` because a timing side-channel on tag comparison can
/// allow an attacker to forge MACs byte-by-byte.
///
/// # Errors
///
/// Returns [`Error::ResumptionMacMismatch`] if the tags differ.
pub(crate) fn verify_mac(expected: &[u8; 16], received: &[u8; 16]) -> Result<()> {
    if expected.ct_eq(received).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(Error::ResumptionMacMismatch)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    // ─── Nonce length assertions ─────────────────────────────────────────────

    /// Prove at test time that all nonce constants are exactly 13 bytes.
    /// A mismatch would also be a compile error because of the `[u8; 13]` type,
    /// but an explicit assertion makes the intent obvious in the test output.
    #[test]
    fn nonce_constants_are_13_bytes() {
        assert_eq!(NONCE_TBE_DATA2.len(), AEAD_NONCE_LEN);
        assert_eq!(NONCE_TBE_DATA3.len(), AEAD_NONCE_LEN);
        assert_eq!(NONCE_RESUME1_MIC.len(), AEAD_NONCE_LEN);
        assert_eq!(NONCE_RESUME2_MIC.len(), AEAD_NONCE_LEN);
    }

    // ─── generate_ephemeral_keypair ──────────────────────────────────────────

    #[test]
    fn ephemeral_keypair_generates_valid_p256_point() {
        let rng = SystemRandom::new();
        let (_sk, pub_bytes) = generate_ephemeral_keypair(&rng).unwrap();
        // SEC1 uncompressed public keys always start with 0x04.
        assert_eq!(pub_bytes[0], 0x04, "SEC1 uncompressed prefix must be 0x04");
        assert_eq!(
            pub_bytes.len(),
            65,
            "SEC1 uncompressed P-256 point is 65 bytes"
        );
    }

    // ─── ecdh_shared_secret ──────────────────────────────────────────────────

    #[test]
    fn ecdh_is_symmetric() {
        let rng = SystemRandom::new();
        let (sk_a, pub_a) = generate_ephemeral_keypair(&rng).unwrap();
        let (sk_b, pub_b) = generate_ephemeral_keypair(&rng).unwrap();
        let shared_a = ecdh_shared_secret(&sk_a, &pub_b).unwrap();
        let shared_b = ecdh_shared_secret(&sk_b, &pub_a).unwrap();
        assert_eq!(shared_a, shared_b, "ECDH shared secret must be symmetric");
    }

    // ─── hkdf_expand ────────────────────────────────────────────────────────

    #[test]
    fn hkdf_expand_deterministic_and_input_sensitive() {
        let prk = [0x42u8; 32];
        let mut out_a = [0u8; 16];
        let mut out_b = [0u8; 16];
        let mut out_c = [0u8; 16];
        hkdf_expand(&prk, HKDF_INFO_SIGMA2, &mut out_a).unwrap();
        hkdf_expand(&prk, HKDF_INFO_SIGMA2, &mut out_b).unwrap();
        hkdf_expand(&prk, HKDF_INFO_SIGMA3, &mut out_c).unwrap();
        // Same inputs → same output.
        assert_eq!(out_a, out_b, "HKDF must be deterministic");
        // Different info → different output.
        assert_ne!(
            out_a, out_c,
            "Different info labels must produce different keys"
        );
    }

    // ─── transcript_hash ────────────────────────────────────────────────────

    #[test]
    fn transcript_hash_deterministic_and_input_sensitive() {
        let h1 = transcript_hash(&[b"sigma1", b"sigma2"]);
        let h2 = transcript_hash(&[b"sigma1", b"sigma2"]);
        assert_eq!(h1, h2, "Transcript hash must be deterministic");
        let h3 = transcript_hash(&[b"sigma1", b"sigma3"]);
        assert_ne!(h1, h3, "Different messages must produce different hashes");
    }

    #[test]
    fn transcript_hash_single_message_matches_sha256() {
        // transcript_hash([msg]) must equal SHA-256(msg) with no prefix.
        let msg = b"test message for sigma";
        let ours = transcript_hash(&[msg.as_slice()]);
        let d = ring::digest::digest(&ring::digest::SHA256, msg);
        assert_eq!(
            ours,
            d.as_ref(),
            "transcript_hash of one message must equal SHA-256(message)"
        );
    }

    // ─── AEAD ───────────────────────────────────────────────────────────────

    #[test]
    fn aead_round_trip() {
        let key = [0x11u8; AEAD_KEY_LEN];
        let nonce = *NONCE_TBE_DATA2;
        let aad = b"associated data";
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();
        // Output must be plaintext length + 16-byte tag.
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_LEN);
        let decrypted = aead_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(
            decrypted, plaintext,
            "Decrypted output must match original plaintext"
        );
    }

    #[test]
    fn aead_tampered_ciphertext_rejected() {
        let key = [0x11u8; AEAD_KEY_LEN];
        let nonce = *NONCE_TBE_DATA3;
        let aad = b"";
        let mut ciphertext = aead_encrypt(&key, &nonce, aad, b"plaintext").unwrap();
        // Flip a bit in the ciphertext body (not just the tag).
        ciphertext[0] ^= 1;
        assert!(
            matches!(
                aead_decrypt(&key, &nonce, aad, &ciphertext),
                Err(Error::EncryptedBlobDecryptionFailed)
            ),
            "Tampered ciphertext must fail decryption"
        );
    }

    #[test]
    fn aead_tampered_tag_rejected() {
        let key = [0x11u8; AEAD_KEY_LEN];
        let nonce = *NONCE_TBE_DATA2;
        let aad = b"some aad";
        let mut ciphertext = aead_encrypt(&key, &nonce, aad, b"plaintext content").unwrap();
        // Flip a bit in the tag (last 16 bytes).
        let tag_start = ciphertext.len() - AEAD_TAG_LEN;
        ciphertext[tag_start] ^= 1;
        assert!(
            matches!(
                aead_decrypt(&key, &nonce, aad, &ciphertext),
                Err(Error::EncryptedBlobDecryptionFailed)
            ),
            "Tampered tag must fail decryption"
        );
    }

    // ─── verify_mac ─────────────────────────────────────────────────────────

    #[test]
    fn verify_mac_accepts_match() {
        let a = [0x11u8; 16];
        let b = [0x11u8; 16];
        verify_mac(&a, &b).unwrap();
    }

    #[test]
    fn verify_mac_rejects_mismatch() {
        let a = [0x11u8; 16];
        let mut b = a;
        b[0] ^= 1;
        assert!(
            matches!(verify_mac(&a, &b), Err(Error::ResumptionMacMismatch)),
            "Single-byte difference must fail MAC verify"
        );
    }
}
