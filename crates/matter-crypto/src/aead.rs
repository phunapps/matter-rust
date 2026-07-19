//! AES-128-CCM-128 (16-byte key, 13-byte nonce, 16-byte tag) AEAD helpers.
//!
//! Used internally by [`crate::case`] for SIGMA-I encrypted blobs and
//! externally by `matter-transport` for the Matter secured-message
//! framing layer (Matter Core Spec §4.5). The cipher itself comes from
//! the `aes` + `ccm` crates; this module is a thin, typed adapter that
//! matches matter.js's `crypto.encrypt`/`decrypt` byte layout (`ciphertext
//! || tag`).
//!
//! We never implement primitives here — only the type-safe wrapper.

use aes::Aes128;
use ccm::{
    aead::{Aead, KeyInit, Payload},
    consts::{U13, U16},
    Ccm, Nonce,
};

use crate::error::{Error, Result};

/// AES-128-CCM with a 16-byte tag and a 13-byte nonce — the Matter cipher.
type Aes128Ccm = Ccm<Aes128, U16, U13>;

/// AES-128 key length in bytes.
pub const AEAD_KEY_LEN: usize = 16;

/// AES-CCM nonce length in bytes (Matter uses 13-byte nonces).
pub const AEAD_NONCE_LEN: usize = 13;

/// AEAD authentication tag length in bytes.
pub const AEAD_TAG_LEN: usize = 16;

/// AES-128-CCM-128 encrypt: returns `ciphertext || tag` (so
/// `output.len() == plaintext.len() + AEAD_TAG_LEN`).
///
/// `aad` may be empty. Matches matter.js's `crypto.encrypt(key, plaintext,
/// nonce, aad?)` byte-for-byte.
///
/// # Errors
///
/// Returns [`Error::EncryptionFailed`] on key initialisation failure
/// (impossible with a fixed-length array key) or encryption failure (not
/// expected in practice for the spec-bounded message sizes).
pub fn encrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes128Ccm::new_from_slice(key).map_err(|_| Error::EncryptionFailed)?;
    let nonce_arr: Nonce<U13> = (*nonce).into();
    cipher
        .encrypt(
            &nonce_arr,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::EncryptionFailed)
}

/// AES-128-CCM-128 decrypt: input is `ciphertext || tag` (so
/// `ciphertext.len() >= AEAD_TAG_LEN`). Returns the plaintext if the tag
/// verifies.
///
/// `aad` may be empty. The `ccm` crate verifies the tag in constant time
/// internally via `subtle`.
///
/// # Errors
///
/// Returns [`Error::EncryptedBlobDecryptionFailed`] on any authentication
/// or decryption failure. The error is intentionally not specific —
/// distinguishing "wrong key" from "tampered ciphertext" is a spec-level
/// design choice that prevents oracle attacks.
pub fn decrypt(
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

/// AES-128-CTR keystream application (encrypt == decrypt), using the CCM
/// counter-block convention for a 13-byte nonce — the construction chip's
/// `AES_CTR_crypt` uses for group-message **privacy** obfuscation (Matter
/// Core Spec §4.8.3).
///
/// Implemented as AES-CCM **encryption with empty AAD, discarding the tag**:
/// CCM's payload keystream IS CTR mode with counter blocks
/// `flags(L=2) || nonce || counter` starting at 1, which is byte-identical to
/// chip's CTR construction for the same nonce (verified end-to-end by the
/// full-frame privacy KAT in `matter-transport`, from connectedhomeip
/// `TestSessionManagerDispatch.cpp`). This stays composition — the cipher
/// itself remains the `aes`+`ccm` crates.
///
/// Applying the function twice with the same key + nonce returns the input
/// (XOR keystream), so one function serves obfuscation and de-obfuscation.
///
/// # Errors
///
/// Returns [`Error::EncryptionFailed`] if the underlying cipher fails (not
/// expected in practice for spec-bounded sizes).
pub fn ctr_apply(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut out = encrypt(key, nonce, &[], data)?;
    out.truncate(data.len()); // drop the CCM tag — only the keystream XOR remains
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    #[test]
    fn ctr_apply_is_an_involution() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let nonce = [0x17u8; AEAD_NONCE_LEN];
        let data = b"obfuscate me please";
        let once = ctr_apply(&key, &nonce, data).unwrap();
        assert_ne!(&once[..], &data[..]);
        let twice = ctr_apply(&key, &nonce, &once).unwrap();
        assert_eq!(&twice[..], &data[..]);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let nonce = [0x17u8; AEAD_NONCE_LEN];
        let aad = b"matter aad";
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        let ciphertext = encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_LEN);

        let decrypted = decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let nonce = [0x17u8; AEAD_NONCE_LEN];
        let mut ciphertext = encrypt(&key, &nonce, b"", b"payload").unwrap();
        ciphertext[0] ^= 1;
        assert!(decrypt(&key, &nonce, b"", &ciphertext).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let bad_key = [0x43u8; AEAD_KEY_LEN];
        let nonce = [0x17u8; AEAD_NONCE_LEN];
        let ciphertext = encrypt(&key, &nonce, b"", b"payload").unwrap();
        assert!(decrypt(&bad_key, &nonce, b"", &ciphertext).is_err());
    }

    #[test]
    fn wrong_aad_rejected() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let nonce = [0x17u8; AEAD_NONCE_LEN];
        let ciphertext = encrypt(&key, &nonce, b"good aad", b"payload").unwrap();
        assert!(decrypt(&key, &nonce, b"bad aad", &ciphertext).is_err());
    }
}
