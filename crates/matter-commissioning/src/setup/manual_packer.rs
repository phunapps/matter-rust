//! Manual pairing code packer / unpacker (Matter Core Spec §5.1.4).
//!
//! Two forms: 11 digits (no VID/PID) or 21 digits (with VID/PID).
//! Both end in a Verhoeff check digit.

// M6.1 build-staging: this submodule lands ahead of its consumer
// (`setup::encode_manual_code` / `setup::parse_manual_code`, Task 13).
// The allow comes off in Task 13's commit. Precedent: `matter-crypto/src/case/sigma.rs`.
#![allow(dead_code)]

use core::fmt::Write as _;

use crate::setup::{
    verhoeff, CommissioningFlow, Discriminator, DiscoveryCapabilities, Error, Passcode, Result,
    SetupPayload,
};

/// Pack a `SetupPayload` as a manual pairing code.
///
/// Emits the 21-digit form when both VID and PID are `Some`, otherwise
/// the 11-digit form. Always appends the Verhoeff check digit.
pub(super) fn pack(payload: &SetupPayload) -> String {
    let has_vid_pid = payload.vendor_id.is_some() && payload.product_id.is_some();
    let short = u16::from(payload.discriminator.short());
    let passcode = payload.passcode.as_u32();

    // First chunk: 1 bit (has-VID/PID flag) | 2 bits (upper 2 bits of short).
    let chunk0 =
        (u32::from(has_vid_pid) & 0b1) | ((u32::from(short) >> 2) & 0b11) << 1;

    // Second chunk: 2 bits (lower 2 bits of short) | 14 bits (passcode 0..=13).
    let chunk1 = (u32::from(short) & 0b11) | ((passcode & 0x3FFF) << 2);

    // Third chunk: 13 bits (passcode 14..=26).
    let chunk2 = (passcode >> 14) & 0x1FFF;

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

    let has_vid_pid = (chunk0 & 0b1) == 1;
    let short_upper = (chunk0 >> 1) & 0b11;
    let short_lower = chunk1 & 0b11;
    #[allow(clippy::cast_possible_truncation)] // 4-bit value, fits u16 trivially.
    let short = ((short_upper << 2) | short_lower) as u16; // 4-bit short discriminator

    let passcode_lo = (chunk1 >> 2) & 0x3FFF;          // bits 0..=13
    let passcode_hi = chunk2 & 0x1FFF;                  // bits 14..=26
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
        #[allow(clippy::cast_possible_truncation)] // VID/PID are 5-digit decimals; max 99_999 fits u16.
        (Some(vid as u16), Some(pid as u16))
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
        assert!(matches!(unpack(&s).unwrap_err(), Error::ManualCodeBadChecksum));
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
