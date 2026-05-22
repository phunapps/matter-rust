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

/// Disallowed-trivial passcode values from Matter Core Spec §5.1.7.1.
///
/// All-same-digit values plus the counting-up and counting-down sequences.
/// The Matter spec rejects these because they offer no protection against
/// guessing during the commissioning window.
///
/// Note: the standard test passcode `20_202_021` is NOT on this list —
/// the spec carves it out as a permitted test value.
pub(super) const DISALLOWED_PASSCODES: &[u32] = &[
    0,
    11_111_111,
    22_222_222,
    33_333_333,
    44_444_444,
    55_555_555,
    66_666_666,
    77_777_777,
    88_888_888,
    99_999_999,
    12_345_678,
    87_654_321,
];

/// 27-bit Matter setup passcode (Matter Core Spec §5.1.7).
///
/// Constructors enforce the 27-bit range and exclude the disallowed-trivial
/// values from spec §5.1.7.1. The standard test passcode `20_202_021` is
/// permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Passcode(u32);

impl Passcode {
    /// Construct from a 27-bit value.
    ///
    /// # Errors
    /// Returns [`Error::PasscodeOutOfRange`] if `value >= 1 << 27`.
    /// Returns [`Error::PasscodeDisallowedTrivial`] if `value` is one of
    /// the spec-disallowed values listed in [`DISALLOWED_PASSCODES`].
    pub fn new(value: u32) -> Result<Self> {
        if value >= 1 << 27 {
            return Err(Error::PasscodeOutOfRange(value));
        }
        if DISALLOWED_PASSCODES.contains(&value) {
            return Err(Error::PasscodeDisallowedTrivial(value));
        }
        Ok(Self(value))
    }

    /// The passcode as a raw `u32` in the range `0..1 << 27`.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Commissioning flow indicator from Matter Core Spec §5.1.3.1 Table 39.
///
/// Two bits on the wire. Value `3` is reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommissioningFlow {
    /// `0` — Device is fully configured; commissioning works as published.
    Standard,
    /// `1` — Device requires user-intent (a button press or similar) before
    /// it begins advertising commissioning.
    UserIntent,
    /// `2` — Custom commissioning flow; commissioner must consult the
    /// vendor's instructions. Not supported by matter-rust.
    Custom,
}

impl CommissioningFlow {
    /// Decode a wire-format value.
    ///
    /// # Errors
    /// Returns [`Error::CommissioningFlowReserved`] for any input outside
    /// `0..=2` (including the spec-reserved value `3`).
    pub const fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Standard),
            1 => Ok(Self::UserIntent),
            2 => Ok(Self::Custom),
            other => Err(Error::CommissioningFlowReserved(other)),
        }
    }

    /// Encode as the wire-format 2-bit value.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Standard => 0,
            Self::UserIntent => 1,
            Self::Custom => 2,
        }
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

#[cfg(test)]
mod passcode_tests {
    use super::{Error, Passcode};

    #[test]
    fn new_accepts_normal_value() {
        // 20202021 is the standard Matter test passcode. The spec excludes
        // a handful of trivial all-same-digit and counting-sequence
        // values, but 20202021 is allowed.
        let p = Passcode::new(20_202_021).unwrap();
        assert_eq!(p.as_u32(), 20_202_021);
    }

    #[test]
    fn new_rejects_28_bit_value() {
        let too_large = 1u32 << 27;
        let err = Passcode::new(too_large).unwrap_err();
        assert!(matches!(err, Error::PasscodeOutOfRange(v) if v == too_large));
    }

    #[test]
    fn new_accepts_max_27_bit() {
        // Largest 27-bit value not on the disallowed list. We use 99_000_001
        // (well under 2^27 = 134_217_728, and not on any trivial-pattern list).
        let p = Passcode::new(99_000_001).unwrap();
        assert_eq!(p.as_u32(), 99_000_001);
    }

    #[test]
    fn new_rejects_all_zeros() {
        let err = Passcode::new(0).unwrap_err();
        assert!(matches!(err, Error::PasscodeDisallowedTrivial(0)));
    }

    #[test]
    fn new_rejects_all_ones() {
        let err = Passcode::new(11_111_111).unwrap_err();
        assert!(matches!(err, Error::PasscodeDisallowedTrivial(11_111_111)));
    }

    #[test]
    fn new_rejects_counting_up() {
        let err = Passcode::new(12_345_678).unwrap_err();
        assert!(matches!(err, Error::PasscodeDisallowedTrivial(12_345_678)));
    }

    #[test]
    fn new_rejects_counting_down() {
        let err = Passcode::new(87_654_321).unwrap_err();
        assert!(matches!(err, Error::PasscodeDisallowedTrivial(87_654_321)));
    }

    #[test]
    fn new_rejects_all_disallowed() {
        for &v in super::DISALLOWED_PASSCODES {
            let err = Passcode::new(v).unwrap_err();
            assert!(
                matches!(err, Error::PasscodeDisallowedTrivial(x) if x == v),
                "expected DisallowedTrivial for {v}, got {err:?}"
            );
        }
    }
}

#[cfg(test)]
mod commissioning_flow_tests {
    use super::{CommissioningFlow, Error};

    #[test]
    fn from_u8_standard() {
        assert_eq!(CommissioningFlow::from_u8(0).unwrap(), CommissioningFlow::Standard);
    }

    #[test]
    fn from_u8_user_intent() {
        assert_eq!(CommissioningFlow::from_u8(1).unwrap(), CommissioningFlow::UserIntent);
    }

    #[test]
    fn from_u8_custom() {
        assert_eq!(CommissioningFlow::from_u8(2).unwrap(), CommissioningFlow::Custom);
    }

    #[test]
    fn from_u8_reserved() {
        let err = CommissioningFlow::from_u8(3).unwrap_err();
        assert!(matches!(err, Error::CommissioningFlowReserved(3)));
    }

    #[test]
    fn from_u8_out_of_range() {
        // 4..255 are all invalid; the 2-bit field can only ever yield 0..=3
        // when read from a real QR, but a programmatic caller could pass
        // anything.
        let err = CommissioningFlow::from_u8(99).unwrap_err();
        assert!(matches!(err, Error::CommissioningFlowReserved(99)));
    }

    #[test]
    fn as_u8_roundtrip() {
        assert_eq!(CommissioningFlow::Standard.as_u8(), 0);
        assert_eq!(CommissioningFlow::UserIntent.as_u8(), 1);
        assert_eq!(CommissioningFlow::Custom.as_u8(), 2);
    }
}
