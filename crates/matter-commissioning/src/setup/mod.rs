//! Setup payload parsing and encoding for Matter QR codes and manual
//! pairing codes (Matter Core Spec §5.1).
//!
//! This is Milestone 6 phase 1 of the `matter-rust` roadmap. See
//! `docs/superpowers/specs/2026-05-22-matter-commissioning-setup-payload-design.md`
//! for design rationale and `docs/superpowers/specs/2026-05-22-matter-commissioning-design.md`
//! for the M6 umbrella.
//!
//! # Phase status
//!
//! - **M6.1 (this revision):** QR-code and manual-pairing-code codec, no
//!   vendor TLV (deferred to a later phase). `SetupPayload` is the
//!   canonical in-memory representation.

#![forbid(unsafe_code)]

mod base38;
mod manual_packer;
mod qr_packer;
mod verhoeff;

/// Twelve-bit long discriminator identifying a Matter device while it
/// is commissionable (Matter Core Spec §5.1.2.2).
///
/// Constructors enforce the 12-bit range. The short discriminator (the
/// upper 4 bits) is what manual pairing codes carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Discriminator(u16);

impl Discriminator {
    /// Construct from a 12-bit value.
    ///
    /// # Errors
    /// Returns [`Error::DiscriminatorOutOfRange`] if `value > 0x0FFF`.
    pub const fn new(value: u16) -> Result<Self> {
        if value > 0x0FFF {
            Err(Error::DiscriminatorOutOfRange(value))
        } else {
            Ok(Self(value))
        }
    }

    /// The discriminator as a raw `u16` in the range `0..=0x0FFF`.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Upper 4 bits — the *short* discriminator carried by manual
    /// pairing codes.
    pub const fn short(self) -> u8 {
        ((self.0 >> 8) & 0x0F) as u8
    }
}

/// Errors from setup-payload parsing and encoding.
///
/// All variants carry enough context (position, value, expected) for
/// callers to render useful diagnostics.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// QR strings must begin with the four-character `MT:` prefix.
    #[error("QR string is missing the `MT:` prefix")]
    MissingMtPrefix,

    /// A character outside Matter's 38-character alphabet appeared in
    /// the Base38 payload.
    #[error("invalid Base38 character `{0}` at position {1}")]
    InvalidBase38Char(char, usize),

    /// The Base38-decoded payload is the wrong size for a Matter QR.
    #[error("QR payload is the wrong length: {got} bytes, expected exactly {need}")]
    QrPayloadWrongLength {
        /// Number of bytes actually decoded.
        got: usize,
        /// Number of bytes the spec requires (currently always 11).
        need: usize,
    },

    /// The Base38-decoded payload is longer than the fixed 11-byte block;
    /// M6.1 does not support the optional vendor TLV blob.
    #[error("QR payload has {extra} byte(s) after the fixed 11-byte block; vendor TLV blobs are not supported in this release")]
    QrTrailingBytes {
        /// Number of bytes past the fixed block.
        extra: usize,
    },

    /// Manual code must be exactly 11 or 21 digits.
    #[error("manual code must be 11 or 21 digits; got {0}")]
    ManualCodeWrongLength(usize),

    /// Manual code contains a non-digit character.
    #[error("manual code contains non-digit `{0}` at position {1}")]
    ManualCodeNonDigit(char, usize),

    /// The Verhoeff check digit at the end of the manual code did not
    /// validate against the preceding digits.
    #[error("manual code Verhoeff check digit failed")]
    ManualCodeBadChecksum,

    /// The 12-bit Long Discriminator field is out of range.
    #[error("discriminator {0} exceeds the 12-bit field width")]
    DiscriminatorOutOfRange(u16),

    /// The 27-bit Passcode field is out of range.
    #[error("passcode {0} exceeds the 27-bit field width")]
    PasscodeOutOfRange(u32),

    /// The passcode value is on the Matter spec's disallowed-trivial list
    /// (Matter Core Spec §5.1.7.1).
    #[error("passcode {0} is in the disallowed-trivial list (spec §5.1.7.1)")]
    PasscodeDisallowedTrivial(u32),

    /// The 2-bit Commissioning Flow field decoded to a reserved value.
    #[error("commissioning flow value {0} is reserved")]
    CommissioningFlowReserved(u8),

    /// `encode_qr` was called on a `SetupPayload` whose VID or PID is
    /// `None` (the manual-code-only case).
    #[error("QR-form payload requires both vendor_id and product_id to be present")]
    QrRequiresVidPid,

    /// The Matter spec defines a `Custom` commissioning flow whose
    /// semantics are vendor-defined and not supported by matter-rust.
    #[error("commissioning flow `Custom` requires vendor-specific QR fields not supported by matter-rust")]
    CustomFlowUnsupported,
}

/// Convenience alias for `Result<T, Error>` inside the setup module.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod error_tests {
    use super::Error;

    #[test]
    fn display_missing_mt_prefix() {
        assert_eq!(
            Error::MissingMtPrefix.to_string(),
            "QR string is missing the `MT:` prefix"
        );
    }

    #[test]
    fn display_invalid_base38_char() {
        assert_eq!(
            Error::InvalidBase38Char('?', 7).to_string(),
            "invalid Base38 character `?` at position 7"
        );
    }

    #[test]
    fn display_qr_trailing_bytes() {
        assert_eq!(
            Error::QrTrailingBytes { extra: 3 }.to_string(),
            "QR payload has 3 byte(s) after the fixed 11-byte block; vendor TLV blobs are not supported in this release"
        );
    }

    #[test]
    fn display_manual_bad_checksum() {
        assert_eq!(
            Error::ManualCodeBadChecksum.to_string(),
            "manual code Verhoeff check digit failed"
        );
    }
}

#[cfg(test)]
mod discriminator_tests {
    use super::{Discriminator, Error};

    #[test]
    fn new_accepts_zero() {
        let d = Discriminator::new(0).unwrap();
        assert_eq!(d.as_u16(), 0);
        assert_eq!(d.short(), 0);
    }

    #[test]
    fn new_accepts_max_12_bit() {
        let d = Discriminator::new(0x0FFF).unwrap();
        assert_eq!(d.as_u16(), 0x0FFF);
        assert_eq!(d.short(), 0x0F);
    }

    #[test]
    fn new_rejects_13_bit() {
        let err = Discriminator::new(0x1000).unwrap_err();
        assert!(matches!(err, Error::DiscriminatorOutOfRange(0x1000)));
    }

    #[test]
    fn short_is_upper_4_bits() {
        // 0xABC = bits 10101011 1100; upper 4 bits = 0xA
        let d = Discriminator::new(0x0ABC).unwrap();
        assert_eq!(d.short(), 0xA);
    }
}
