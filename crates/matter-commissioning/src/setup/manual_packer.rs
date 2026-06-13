//! Manual pairing code packer / unpacker (Matter Core Spec §5.1.4).
//!
//! Two forms: 11 digits (no VID/PID) or 21 digits (with VID/PID).
//! Both end in a Verhoeff check digit.

use core::fmt::Write as _;

use crate::setup::{
    verhoeff, CommissioningFlow, DiscoveryCapabilities, Discriminator, Error, Passcode, Result,
    SetupPayload,
};

/// Pack a `SetupPayload` as a manual pairing code.
///
/// Emits the 21-digit form when both VID and PID are `Some`, otherwise
/// the 11-digit form. Always appends the Verhoeff check digit.
///
/// Bit layout follows Matter Core Spec §5.1.4 / matter.js's
/// `ManualPairingCodeSchema`:
///
/// - chunk0 (1 digit, decimal): bits 0-1 = discriminator bits 10-11,
///   bit 2 = has-VID/PID flag.
/// - chunk1 (5 digits, decimal): bits 0-13 = passcode bits 0-13,
///   bits 14-15 = discriminator bits 8-9.
/// - chunk2 (4 digits, decimal): passcode bits 14-26.
/// - optional chunks 3 and 4 (5 digits each): vendor ID and product ID.
/// - final digit: Verhoeff check digit over all preceding digits.
pub(super) fn pack(payload: &SetupPayload) -> String {
    let has_vid_pid = payload.vendor_id.is_some() && payload.product_id.is_some();
    let discriminator = u32::from(payload.discriminator.as_u16());
    let passcode = payload.passcode.as_u32();

    // chunk0: discriminator bits 10-11 | has-VID/PID flag at bit 2.
    let chunk0 = (discriminator >> 10) | (u32::from(has_vid_pid) << 2);

    // chunk1: passcode bits 0-13 | discriminator bits 8-9 placed at chunk1 bits 14-15.
    // `(discriminator & 0x300) << 6` lifts bits 8-9 to bit positions 14-15.
    let chunk1 = ((discriminator & 0x300) << 6) | (passcode & 0x3FFF);

    // chunk2: passcode bits 14-26.
    let chunk2 = passcode >> 14;

    let mut s = format!("{chunk0:01}{chunk1:05}{chunk2:04}");

    if has_vid_pid {
        let vid = payload.vendor_id.unwrap_or(0);
        let pid = payload.product_id.unwrap_or(0);
        // `write!` into a String is infallible — formatter never returns Err
        // for String. Discarding the Result avoids `format!` + allocation.
        let _ = write!(s, "{vid:05}{pid:05}");
    }

    s.push((verhoeff::check_digit(&s) + b'0') as char);
    s
}

/// Unpack a manual pairing code string. Validates length, digit-only,
/// Verhoeff check, and per-field ranges.
pub(super) fn unpack(s: &str) -> Result<SetupPayload> {
    if s.len() != 11 && s.len() != 21 {
        return Err(Error::ManualCodeWrongLength(s.len()));
    }
    for (i, ch) in s.char_indices() {
        if !ch.is_ascii_digit() {
            return Err(Error::ManualCodeNonDigit(ch, i));
        }
    }
    if !verhoeff::verify(s) {
        return Err(Error::ManualCodeBadChecksum);
    }

    // Digit-only verified above; the `map_err` arms are defensive so we
    // never bypass library policy on `expect`. CLAUDE.md: no expect in lib.
    let chunk0: u32 = s[0..1]
        .parse()
        .map_err(|_| Error::ManualCodeNonDigit('?', 0))?;
    let chunk1: u32 = s[1..6]
        .parse()
        .map_err(|_| Error::ManualCodeNonDigit('?', 1))?;
    let chunk2: u32 = s[6..10]
        .parse()
        .map_err(|_| Error::ManualCodeNonDigit('?', 6))?;

    // Mirror of `pack`'s layout:
    // - chunk0 bit 2          = has-VID/PID flag
    // - chunk0 bits 0-1       = discriminator bits 10-11 (upper 2 bits of the 4-bit short)
    // - chunk1 bits 14-15     = discriminator bits 8-9   (lower 2 bits of the 4-bit short)
    // - chunk1 bits 0-13      = passcode bits 0-13
    // - chunk2                = passcode bits 14-26
    let has_vid_pid = ((chunk0 >> 2) & 0b1) == 1;
    let short_upper = chunk0 & 0b11;
    let short_lower = (chunk1 >> 14) & 0b11;
    #[allow(clippy::cast_possible_truncation)] // 4-bit value, fits u16 trivially.
    let short = ((short_upper << 2) | short_lower) as u16; // 4-bit short discriminator

    let passcode_lo = chunk1 & 0x3FFF; // bits 0..=13
    let passcode_hi = chunk2 & 0x1FFF; // bits 14..=26
    let passcode = passcode_lo | (passcode_hi << 14);

    let (vendor_id, product_id) = if has_vid_pid {
        if s.len() != 21 {
            // Header says VID/PID is present, but the body length disagrees.
            return Err(Error::ManualCodeWrongLength(s.len()));
        }
        let vid: u32 = s[10..15]
            .parse()
            .map_err(|_| Error::ManualCodeNonDigit('?', 10))?;
        let pid: u32 = s[15..20]
            .parse()
            .map_err(|_| Error::ManualCodeNonDigit('?', 15))?;
        // VID/PID are 5-digit decimals (max 99_999), which exceeds u16::MAX
        // (65_535). Range-check BEFORE narrowing so an out-of-range value is
        // rejected with a typed error rather than silently truncated/wrapped.
        let vid = u16::try_from(vid).map_err(|_| Error::FieldOutOfRange {
            field: "vendor_id",
            value: vid,
        })?;
        let pid = u16::try_from(pid).map_err(|_| Error::FieldOutOfRange {
            field: "product_id",
            value: pid,
        })?;
        (Some(vid), Some(pid))
    } else {
        if s.len() != 11 {
            return Err(Error::ManualCodeWrongLength(s.len()));
        }
        (None, None)
    };

    // Manual code zero-extends to a 12-bit Discriminator with the short
    // value placed in the upper 4 bits.
    let long_discriminator = short << 8;

    Ok(SetupPayload {
        version: 0,
        vendor_id,
        product_id,
        commissioning_flow: CommissioningFlow::Standard,
        discovery_capabilities: DiscoveryCapabilities::empty(),
        discriminator: Discriminator::new(long_discriminator)?,
        passcode: Passcode::new(passcode)?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::{pack, unpack};
    use crate::setup::*;

    fn payload_11(short_disc: u8, passcode: u32) -> SetupPayload {
        SetupPayload {
            version: 0,
            vendor_id: None,
            product_id: None,
            commissioning_flow: CommissioningFlow::Standard,
            discovery_capabilities: DiscoveryCapabilities::empty(),
            discriminator: Discriminator::new(u16::from(short_disc) << 8).unwrap(),
            passcode: Passcode::new(passcode).unwrap(),
        }
    }

    fn payload_21(short_disc: u8, passcode: u32, vid: u16, pid: u16) -> SetupPayload {
        SetupPayload {
            version: 0,
            vendor_id: Some(vid),
            product_id: Some(pid),
            commissioning_flow: CommissioningFlow::Standard,
            discovery_capabilities: DiscoveryCapabilities::empty(),
            discriminator: Discriminator::new(u16::from(short_disc) << 8).unwrap(),
            passcode: Passcode::new(passcode).unwrap(),
        }
    }

    #[test]
    fn pack_11_digits_length_is_11() {
        let s = pack(&payload_11(0xA, 20_202_021));
        assert_eq!(s.len(), 11);
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn pack_21_digits_length_is_21() {
        let s = pack(&payload_21(0xA, 20_202_021, 0xFFF1, 0x8000));
        assert_eq!(s.len(), 21);
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn pack_unpack_roundtrip_11() {
        let p = payload_11(0xA, 20_202_021);
        let s = pack(&p);
        let back = unpack(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn pack_unpack_roundtrip_21() {
        let p = payload_21(0xA, 20_202_021, 0xFFF1, 0x8000);
        let s = pack(&p);
        let back = unpack(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn unpack_rejects_wrong_length() {
        assert!(matches!(
            unpack("123").unwrap_err(),
            Error::ManualCodeWrongLength(3)
        ));
        assert!(matches!(
            unpack("123456789012345").unwrap_err(),
            Error::ManualCodeWrongLength(15)
        ));
    }

    #[test]
    fn unpack_rejects_non_digit() {
        assert!(matches!(
            unpack("3497011233A").unwrap_err(),
            Error::ManualCodeNonDigit('A', 10)
        ));
    }

    #[test]
    fn unpack_rejects_bad_checksum() {
        // 11-digit form with last digit deliberately wrong.
        let mut s = pack(&payload_11(0xA, 20_202_021));
        let last = s.pop().unwrap();
        // Pick any other digit:
        let bad = if last == '0' { '1' } else { '0' };
        s.push(bad);
        assert!(matches!(
            unpack(&s).unwrap_err(),
            Error::ManualCodeBadChecksum
        ));
    }

    #[test]
    fn unpack_rejects_out_of_range_vid() {
        // Build a valid 21-digit code, then overwrite the VID digits (positions
        // 10..15) with 99999 (> u16::MAX) and re-append the correct Verhoeff
        // check digit so the failure is the range check, not the checksum.
        let mut s = pack(&payload_21(0xA, 20_202_021, 0x1234, 0x5678));
        s.truncate(20); // drop existing check digit
        s.replace_range(10..15, "99999"); // VID = 99999, out of u16 range
        s.push((super::verhoeff::check_digit(&s) + b'0') as char);
        match unpack(&s).unwrap_err() {
            Error::FieldOutOfRange { field, value } => {
                assert_eq!(field, "vendor_id");
                assert_eq!(value, 99999);
            }
            other => panic!("expected FieldOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn unpack_rejects_out_of_range_pid() {
        let mut s = pack(&payload_21(0xA, 20_202_021, 0x1234, 0x5678));
        s.truncate(20);
        s.replace_range(15..20, "70000"); // PID = 70000, out of u16 range
        s.push((super::verhoeff::check_digit(&s) + b'0') as char);
        match unpack(&s).unwrap_err() {
            Error::FieldOutOfRange { field, value } => {
                assert_eq!(field, "product_id");
                assert_eq!(value, 70000);
            }
            other => panic!("expected FieldOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn unpack_accepts_in_range_vid_pid_boundary() {
        // 65535 is the largest u16; must parse cleanly.
        let p = payload_21(0xA, 20_202_021, 0xFFFF, 0xFFFF);
        let s = pack(&p);
        let back = unpack(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn roundtrip_edge_short_discriminators() {
        for short in 0u8..=0xF {
            let p = payload_11(short, 20_202_021);
            let s = pack(&p);
            let back = unpack(&s).unwrap();
            assert_eq!(back, p, "failed at short=0x{short:x}");
        }
    }

    #[test]
    fn roundtrip_edge_passcodes() {
        // Skip disallowed-trivial values; pick boundary-ish allowed ones.
        for passcode in [1u32, 99_999_998, (1 << 27) - 1] {
            if super::super::DISALLOWED_PASSCODES.contains(&passcode) {
                continue;
            }
            let p = payload_11(0x5, passcode);
            let s = pack(&p);
            let back = unpack(&s).unwrap();
            assert_eq!(back, p);
        }
    }
}
