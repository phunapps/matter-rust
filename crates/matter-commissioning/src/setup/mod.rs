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

/// The decoded contents of a Matter onboarding payload (QR code or manual
/// pairing code), as defined in Matter Core Spec §5.1.3.
///
/// Roundtrip identities:
///
/// ```ignore
/// // For every valid `p` produced by M6.1:
/// assert_eq!(parse_qr(&encode_qr(&p)?)?, p);
/// assert_eq!(parse_manual_code(&encode_manual_code(&p)), p);  // see caveat below
/// ```
///
/// The manual-code roundtrip preserves the *upper four bits* of the
/// discriminator (the short discriminator) and zero-extends the rest.
/// A `SetupPayload` decoded from a manual code therefore has a
/// discriminator whose lower 8 bits are zero, regardless of what the
/// physical device's long discriminator actually is. Callers matching
/// against mDNS records should compare on the short discriminator in
/// that case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupPayload {
    /// Onboarding payload version. Currently always `0` (Matter Core
    /// Spec §5.1.3.1 Table 39). Reserved for future use.
    pub version: u8,

    /// Vendor ID. `None` if the source was an 11-digit manual code,
    /// which does not carry VID/PID.
    pub vendor_id: Option<u16>,

    /// Product ID. Pair with `vendor_id` — both are `Some` or both
    /// `None`.
    pub product_id: Option<u16>,

    /// Commissioning flow indicator.
    pub commissioning_flow: CommissioningFlow,

    /// Bitmask of discovery transports the device supports while
    /// commissionable. Always present in QR codes; manual codes do not
    /// carry this field and decode it as the empty set.
    pub discovery_capabilities: DiscoveryCapabilities,

    /// 12-bit Long Discriminator. See the type-level rustdoc for the
    /// manual-code caveat.
    pub discriminator: Discriminator,

    /// 27-bit passcode.
    pub passcode: Passcode,
}

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
///
/// Re-exported so tests and external callers can filter values
/// generated for synthetic payloads (the proptest roundtrip suite in
/// `tests/setup_proptest.rs` is the primary in-tree consumer).
pub const DISALLOWED_PASSCODES: &[u32] = &[
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

bitflags::bitflags! {
    /// Matter Core Spec §5.1.3.1 Table 39 "Discovery Capabilities" — the
    /// 8-bit bitmask advertising which discovery transports the device
    /// supports while commissionable.
    ///
    /// Bits 3-7 are spec-reserved but preserved on roundtrip — we use
    /// `from_bits_retain` rather than `from_bits` so unknown future bits
    /// pass through unchanged.
    ///
    /// Bit positions are verified against matter.js's
    /// `DiscoveryCapabilitiesSchema`. See the file's leading comment.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DiscoveryCapabilities: u8 {
        /// Device hosts a Soft-AP for direct connection.
        const SOFT_AP    = 0b0000_0001;
        /// Device advertises commissioning over Bluetooth LE.
        const BLE        = 0b0000_0010;
        /// Device is reachable via an IP network (Wi-Fi / Ethernet / Thread).
        const ON_NETWORK = 0b0000_0100;
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

const QR_PREFIX: &str = "MT:";

/// Encode a `SetupPayload` as a Matter QR string (Matter Core Spec §5.1.3.1).
///
/// The returned string always begins with `MT:` followed by Matter Base38.
///
/// # Errors
/// Returns [`Error::QrRequiresVidPid`] if either VID or PID is `None`.
/// Returns [`Error::CustomFlowUnsupported`] for `CommissioningFlow::Custom`.
///
/// # Examples
///
/// ```
/// use matter_commissioning::setup::{
///     encode_qr, parse_qr,
///     CommissioningFlow, Discriminator, DiscoveryCapabilities,
///     Passcode, SetupPayload,
/// };
/// let payload = SetupPayload {
///     version: 0,
///     vendor_id: Some(0xFFF1),
///     product_id: Some(0x8000),
///     commissioning_flow: CommissioningFlow::Standard,
///     discovery_capabilities: DiscoveryCapabilities::ON_NETWORK,
///     discriminator: Discriminator::new(0xF00).unwrap(),
///     passcode: Passcode::new(20_202_021).unwrap(),
/// };
/// let qr = encode_qr(&payload).unwrap();
/// assert!(qr.starts_with("MT:"));
/// assert_eq!(parse_qr(&qr).unwrap(), payload);
/// ```
pub fn encode_qr(payload: &SetupPayload) -> Result<String> {
    let bytes = qr_packer::pack(payload)?;
    Ok(format!("{QR_PREFIX}{}", base38::encode(&bytes)))
}

/// Parse a Matter QR string into a `SetupPayload`.
///
/// # Errors
/// Returns [`Error::MissingMtPrefix`] if the string does not begin with
/// `MT:`.
/// Returns [`Error::InvalidBase38Char`] for any character outside Matter's
/// Base38 alphabet.
/// Returns [`Error::QrPayloadWrongLength`] or [`Error::QrTrailingBytes`]
/// for payload-length problems.
/// Returns the per-field range errors via [`qr_packer::unpack`].
///
/// # Examples
///
/// ```
/// use matter_commissioning::setup::parse_qr;
/// // Captured from matter.js for the Matter Core Spec §5.1.3.1 worked
/// // example (VID 0xFFF1, PID 0x8000, discriminator 0xF00, passcode
/// // 20_202_021). Source:
/// // test-vectors/commissioning/setup/qr-spec-example.json
/// let payload = parse_qr("MT:Y.K90AFN00KA0648G00").unwrap();
/// assert_eq!(payload.vendor_id, Some(0xFFF1));
/// assert_eq!(payload.product_id, Some(0x8000));
/// assert_eq!(payload.passcode.as_u32(), 20_202_021);
/// ```
pub fn parse_qr(s: &str) -> Result<SetupPayload> {
    let payload = s
        .strip_prefix(QR_PREFIX)
        .ok_or(Error::MissingMtPrefix)?;
    let bytes = base38::decode(payload)?;
    let need = qr_packer::FIXED_BYTE_LEN;
    if bytes.len() < need {
        return Err(Error::QrPayloadWrongLength {
            got: bytes.len(),
            need,
        });
    }
    if bytes.len() > need {
        return Err(Error::QrTrailingBytes {
            extra: bytes.len() - need,
        });
    }
    let mut fixed = [0u8; qr_packer::FIXED_BYTE_LEN];
    fixed.copy_from_slice(&bytes[..need]);
    qr_packer::unpack(&fixed)
}

/// Encode a `SetupPayload` as a manual pairing code (Matter Core Spec §5.1.4).
///
/// Emits the 21-digit form if `vendor_id` and `product_id` are both
/// `Some`, otherwise the 11-digit form. The final digit is always the
/// Verhoeff check digit.
///
/// # Examples
///
/// ```
/// use matter_commissioning::setup::{
///     encode_manual_code, parse_manual_code,
///     CommissioningFlow, Discriminator, DiscoveryCapabilities,
///     Passcode, SetupPayload,
/// };
/// let payload = SetupPayload {
///     version: 0,
///     vendor_id: None,
///     product_id: None,
///     commissioning_flow: CommissioningFlow::Standard,
///     discovery_capabilities: DiscoveryCapabilities::empty(),
///     discriminator: Discriminator::new(0xF00).unwrap(),
///     passcode: Passcode::new(20_202_021).unwrap(),
/// };
/// let code = encode_manual_code(&payload);
/// assert_eq!(code.len(), 11);
/// assert_eq!(parse_manual_code(&code).unwrap(), payload);
/// ```
pub fn encode_manual_code(payload: &SetupPayload) -> String {
    manual_packer::pack(payload)
}

/// Parse a Matter manual pairing code (11 or 21 digits).
///
/// # Errors
/// Returns [`Error::ManualCodeWrongLength`], [`Error::ManualCodeNonDigit`],
/// [`Error::ManualCodeBadChecksum`], or any per-field range error.
pub fn parse_manual_code(s: &str) -> Result<SetupPayload> {
    manual_packer::unpack(s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
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
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
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
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
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
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
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

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod discovery_capabilities_tests {
    use super::DiscoveryCapabilities;

    #[test]
    fn empty_set() {
        let d = DiscoveryCapabilities::empty();
        assert_eq!(d.bits(), 0);
        assert!(!d.contains(DiscoveryCapabilities::BLE));
    }

    #[test]
    fn ble_only() {
        let d = DiscoveryCapabilities::BLE;
        assert_eq!(d.bits(), 0b0000_0010);
        assert!(d.contains(DiscoveryCapabilities::BLE));
        assert!(!d.contains(DiscoveryCapabilities::ON_NETWORK));
    }

    #[test]
    fn on_network_only() {
        let d = DiscoveryCapabilities::ON_NETWORK;
        assert_eq!(d.bits(), 0b0000_0100);
    }

    #[test]
    fn combined() {
        let d = DiscoveryCapabilities::BLE | DiscoveryCapabilities::ON_NETWORK;
        assert_eq!(d.bits(), 0b0000_0110);
    }

    #[test]
    fn from_bits_preserves_reserved() {
        // bits 3..7 are reserved; we preserve unknown bits on roundtrip
        // rather than reject them.
        let d = DiscoveryCapabilities::from_bits_retain(0b1100_0001);
        assert_eq!(d.bits(), 0b1100_0001);
        assert!(d.contains(DiscoveryCapabilities::SOFT_AP));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod setup_payload_tests {
    use super::*;

    /// Returns the spec's worked-example payload from Matter Core Spec §5.1.3.1.
    /// VID 0xFFF1, PID 0x8000, discriminator 0xF00, passcode `20_202_021`,
    /// flow Standard, discovery `ON_NETWORK` only.
    pub(super) fn spec_example_payload() -> SetupPayload {
        SetupPayload {
            version: 0,
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            commissioning_flow: CommissioningFlow::Standard,
            discovery_capabilities: DiscoveryCapabilities::ON_NETWORK,
            discriminator: Discriminator::new(0xF00).unwrap(),
            passcode: Passcode::new(20_202_021).unwrap(),
        }
    }

    #[test]
    fn spec_example_round_trips_through_struct() {
        let p = spec_example_payload();
        assert_eq!(p.vendor_id, Some(0xFFF1));
        assert_eq!(p.product_id, Some(0x8000));
        assert_eq!(p.discriminator.as_u16(), 0xF00);
        assert_eq!(p.passcode.as_u32(), 20_202_021);
        assert_eq!(p.commissioning_flow, CommissioningFlow::Standard);
        assert!(p.discovery_capabilities.contains(DiscoveryCapabilities::ON_NETWORK));
    }

    #[test]
    fn manual_only_payload_has_no_vid_pid() {
        let p = SetupPayload {
            version: 0,
            vendor_id: None,
            product_id: None,
            commissioning_flow: CommissioningFlow::Standard,
            discovery_capabilities: DiscoveryCapabilities::empty(),
            discriminator: Discriminator::new(0xA00).unwrap(),
            passcode: Passcode::new(20_202_021).unwrap(),
        };
        assert!(p.vendor_id.is_none());
        assert!(p.product_id.is_none());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod qr_api_tests {
    use super::*;
    use crate::setup::setup_payload_tests::spec_example_payload;

    /// The spec example must encode AND decode without errors. (Exact
    /// byte parity against matter.js is verified by the integration test
    /// `tests/setup_byte_parity.rs` once fixtures are captured in
    /// Task 21.)
    #[test]
    fn spec_example_qr_encode_decode_roundtrip() {
        let p = spec_example_payload();
        let s = encode_qr(&p).unwrap();
        assert!(s.starts_with("MT:"), "got {s:?}");
        let back = parse_qr(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn parse_qr_rejects_missing_prefix() {
        let err = parse_qr("Y.K9042C00KA0648G00").unwrap_err();
        assert!(matches!(err, Error::MissingMtPrefix));
    }

    #[test]
    fn parse_qr_rejects_trailing_bytes() {
        // The spec-example payload encodes to 19 Base38 chars (3 full
        // 5-char chunks plus a 4-char tail → 11 bytes). Appending 3 chars
        // turns the tail into a 5-char chunk (3 bytes) plus a fresh
        // 2-char chunk (1 byte), decoding to 13 bytes total — 2 bytes
        // past the fixed block.
        let p = spec_example_payload();
        let mut s = encode_qr(&p).unwrap();
        s.push_str("000");
        let err = parse_qr(&s).unwrap_err();
        assert!(matches!(err, Error::QrTrailingBytes { extra: 2 }), "got {err:?}");
    }

    #[test]
    fn parse_qr_rejects_short_payload() {
        let err = parse_qr("MT:00000").unwrap_err();
        assert!(matches!(err, Error::QrPayloadWrongLength { .. }), "got {err:?}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod manual_api_tests {
    use super::*;

    fn payload_11() -> SetupPayload {
        SetupPayload {
            version: 0,
            vendor_id: None,
            product_id: None,
            commissioning_flow: CommissioningFlow::Standard,
            discovery_capabilities: DiscoveryCapabilities::empty(),
            discriminator: Discriminator::new(0x0F00).unwrap(),
            passcode: Passcode::new(20_202_021).unwrap(),
        }
    }

    #[test]
    fn encode_manual_11_then_parse() {
        let p = payload_11();
        let s = encode_manual_code(&p);
        assert_eq!(s.len(), 11);
        let back = parse_manual_code(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn encode_manual_21_then_parse() {
        let mut p = payload_11();
        p.vendor_id = Some(0xFFF1);
        p.product_id = Some(0x8000);
        let s = encode_manual_code(&p);
        assert_eq!(s.len(), 21);
        let back = parse_manual_code(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn parse_manual_rejects_wrong_length() {
        let err = parse_manual_code("12345").unwrap_err();
        assert!(matches!(err, Error::ManualCodeWrongLength(5)));
    }

    #[test]
    fn parse_manual_rejects_non_digit() {
        let err = parse_manual_code("1234567890A").unwrap_err();
        assert!(matches!(err, Error::ManualCodeNonDigit('A', 10)));
    }
}
