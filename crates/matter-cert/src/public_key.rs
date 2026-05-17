//! Matter EC public key (P-256, uncompressed point).
//!
//! M2.1 ships only the byte container; M2.2 adds signature verification
//! via `ring`.

use core::fmt;

use crate::error::{Error, Result};

/// A 65-byte uncompressed P-256 public key: `0x04 || X(32) || Y(32)`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 65]);

impl PublicKey {
    /// Construct from raw bytes. Validates the `0x04` uncompressed-point
    /// prefix; rejects compressed or hybrid encodings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadPublicKeyPrefix`] if `bytes[0] != 0x04`.
    pub fn new(bytes: [u8; 65]) -> Result<Self> {
        if bytes[0] != 0x04 {
            return Err(Error::BadPublicKeyPrefix);
        }
        Ok(Self(bytes))
    }

    /// Construct from a byte slice. Rejects wrong-length input.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WrongPublicKeyLength`] if `slice.len() != 65`,
    /// or [`Error::BadPublicKeyPrefix`] if the first byte is not `0x04`.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; 65] = slice
            .try_into()
            .map_err(|_| Error::WrongPublicKeyLength(slice.len()))?;
        Self::new(bytes)
    }

    /// The raw 65-byte uncompressed point.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({:02x}{:02x}{:02x}{:02x}…)",
            self.0[1], self.0[2], self.0[3], self.0[4]
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    #[test]
    fn new_rejects_non_0x04_prefix() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x02;
        assert!(matches!(PublicKey::new(bytes), Err(Error::BadPublicKeyPrefix)));
    }

    #[test]
    fn new_accepts_0x04_prefix() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        bytes[1] = 0xAB;
        let key = PublicKey::new(bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        let short = [0x04u8; 10];
        assert!(matches!(
            PublicKey::from_slice(&short),
            Err(Error::WrongPublicKeyLength(10))
        ));
    }

    #[test]
    fn debug_format_does_not_leak_full_key() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        bytes[1] = 0xAB;
        bytes[2] = 0xCD;
        bytes[3] = 0xEF;
        bytes[4] = 0x12;
        let key = PublicKey::new(bytes).unwrap();
        let s = format!("{key:?}");
        assert!(s.contains("abcdef12"));
        assert!(!s.contains("00000000"));
    }
}
