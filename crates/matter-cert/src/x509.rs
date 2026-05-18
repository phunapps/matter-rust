//! Matter TLV → X.509 DER `TBSCertificate` conversion.
//!
//! Real Matter certificates carry signatures over the X.509 DER form
//! of the certificate, not over the Matter TLV form. This module maps
//! a parsed [`crate::MatterCertificate`] into a byte-identical
//! representation of matter.js's `Certificate.asUnsignedDer()` output,
//! which `MatterCertificate::verify_signed_by` then hands to `ring`.
//!
//! See `docs/superpowers/specs/2026-05-18-matter-x509-conversion-design.md`
//! for the full design and the byte-parity rationale.

// The OID constants are defined now for completeness and documentation value;
// they are wired into the encoder in Tasks 3–9. Suppress dead-code warnings
// for the skeleton phase only — remove this attribute when the encoder lands.
#![allow(dead_code)]

use der::asn1::ObjectIdentifier;

use crate::certificate::MatterCertificate;
use crate::error::{Error, Result};

// =============================================================================
// Matter-specific DN attribute OIDs (CSA arc 1.3.6.1.4.1.37244)
// =============================================================================
//
// Values pinned from matter.js's asn.js (dist/cjs/certificate/kinds/definitions/asn.js).
// The .d.ts comments are authoritative:
//   /** matter-node-id            = ASN.1 OID 1.3.6.1.4.1.37244.1.1 */
//   /** matter-firmware-signing-id = ASN.1 OID 1.3.6.1.4.1.37244.1.2 */
//   /** matter-icac-id            = ASN.1 OID 1.3.6.1.4.1.37244.1.3 */
//   /** matter-rcac-id            = ASN.1 OID 1.3.6.1.4.1.37244.1.4 */
//   /** matter-fabric-id          = ASN.1 OID 1.3.6.1.4.1.37244.1.5 */
//   /** matter-noc-cat            = ASN.1 OID 1.3.6.1.4.1.37244.1.6 */
//   /** matter-vvs-id             = ASN.1 OID 1.3.6.1.4.1.37244.1.7 */  ← present in matter.js; not in the plan template
//   /** matter-oid-vid            = ASN.1 OID 1.3.6.1.4.1.37244.2.1 */
//   /** matter-oid-pid            = ASN.1 OID 1.3.6.1.4.1.37244.2.2 */
/// Operational-certificate attribute: Matter node-id.
const OID_MATTER_NODE_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.1");

/// Operational-certificate attribute: Matter firmware-signing-id.
const OID_MATTER_FIRMWARE_SIGNING_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.2");

/// Operational-certificate attribute: Matter ICAC id.
const OID_MATTER_ICAC_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.3");

/// Operational-certificate attribute: Matter RCAC id.
const OID_MATTER_RCAC_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.4");

/// Operational-certificate attribute: Matter fabric-id.
const OID_MATTER_FABRIC_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.5");

/// Operational-certificate attribute: Matter NOC CASE Authenticated Tag.
const OID_MATTER_NOC_CAT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.6");

/// Operational-certificate attribute: Matter VVS id.
///
/// Present in matter.js (arc `.1.7`) but absent from the plan template.
/// Included here for completeness; used in Vendor Verification Service
/// certificates introduced in a later Matter specification revision.
const OID_MATTER_VVS_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.7");

/// Attestation-certificate attribute: Matter vendor-id.
const OID_MATTER_VENDOR_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.2.1");

/// Attestation-certificate attribute: Matter product-id.
const OID_MATTER_PRODUCT_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.2.2");

// =============================================================================
// Standard X.509 DN attribute OIDs (RFC 5280 / X.520)
// =============================================================================

const OID_X520_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_X520_SURNAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.4");
const OID_X520_SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");
const OID_X520_COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const OID_X520_LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
const OID_X520_STATE_OR_PROVINCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
const OID_X520_ORG: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_X520_ORG_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_X520_TITLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.12");
const OID_X520_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.41");
const OID_X520_GIVEN_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.42");
const OID_X520_INITIALS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.43");
const OID_X520_GENERATION_QUALIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.44");
const OID_X520_DN_QUALIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.46");
const OID_X520_PSEUDONYM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.65");
const OID_DOMAIN_COMPONENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.25");

// =============================================================================
// X.509 extension OIDs (RFC 5280)
// =============================================================================

const OID_EXT_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_EXT_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_EXT_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_EXT_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.35");

// =============================================================================
// Algorithm + curve OIDs
// =============================================================================

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_EC_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

// =============================================================================
// Top-level entry point
// =============================================================================

/// Build the X.509 DER `TBSCertificate` for `cert`.
///
/// Byte-identical to matter.js's `Certificate.asUnsignedDer()` for the
/// same input. Used internally by `MatterCertificate::verify_signed_by`
/// and exposed publicly via `MatterCertificate::to_x509_tbs_der`.
pub(crate) fn matter_cert_to_x509_tbs_der(cert: &MatterCertificate) -> Result<Vec<u8>> {
    // Filled in by Task 9.
    let _ = cert;
    Err(Error::SignatureVerificationFailed) // placeholder so the file compiles
}

// =============================================================================
// Validity encoder
// =============================================================================

/// The Unix-seconds threshold at which X.509 switches from `UTCTime` to
/// `GeneralizedTime` per RFC 5280 §4.1.2.5: 2050-01-01T00:00:00Z.
const X509_UTCTIME_CUTOFF_UNIX_SECS: u64 = 2_524_608_000;

/// Encode an X.509 `Validity` SEQUENCE.
///
/// `MatterTime(0)` is the Matter "no expiry" sentinel; it maps to the
/// RFC 5280 §4.1.2.5 `GeneralizedTime` sentinel `99991231235959Z`.
fn encode_validity(
    not_before: crate::time::MatterTime,
    not_after: crate::time::MatterTime,
) -> Vec<u8> {
    let nb = encode_one_time(not_before, /* is_not_after = */ false);
    let na = encode_one_time(not_after, /* is_not_after = */ true);

    let mut inner = Vec::with_capacity(nb.len() + na.len());
    inner.extend_from_slice(&nb);
    inner.extend_from_slice(&na);
    wrap_sequence(&inner)
}

fn encode_one_time(t: crate::time::MatterTime, is_not_after: bool) -> Vec<u8> {
    // Matter "no expiry" only applies to not_after.
    if t == crate::time::MatterTime::NO_EXPIRY && is_not_after {
        // `GeneralizedTime` sentinel per RFC 5280 §4.1.2.5
        return encode_generalized_time_literal(b"99991231235959Z");
    }
    let unix = t.to_unix_secs();
    let (year, month, day, hour, minute, second) = unix_to_ymdhms(unix);
    if unix < X509_UTCTIME_CUTOFF_UNIX_SECS {
        // year is in [1970, 2049] here, so year % 100 fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        let yy = (year % 100) as u8;
        let s = format!("{yy:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
        encode_utc_time_literal(s.as_bytes())
    } else {
        let s = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
        encode_generalized_time_literal(s.as_bytes())
    }
}

/// `UTCTime` DER: tag 0x17, length, value.
fn encode_utc_time_literal(s: &[u8]) -> Vec<u8> {
    debug_assert_eq!(s.len(), 13);
    // s.len() == 13, which fits in u8 without truncation.
    #[allow(clippy::cast_possible_truncation)]
    let len_byte = s.len() as u8;
    let mut out = Vec::with_capacity(15);
    out.push(0x17);
    out.push(len_byte);
    out.extend_from_slice(s);
    out
}

/// `GeneralizedTime` DER: tag 0x18, length, value.
fn encode_generalized_time_literal(s: &[u8]) -> Vec<u8> {
    debug_assert_eq!(s.len(), 15);
    // s.len() == 15, which fits in u8 without truncation.
    #[allow(clippy::cast_possible_truncation)]
    let len_byte = s.len() as u8;
    let mut out = Vec::with_capacity(17);
    out.push(0x18);
    out.push(len_byte);
    out.extend_from_slice(s);
    out
}

// =============================================================================
// Serial number encoder
// =============================================================================

/// Encode a Matter serial number (1–20 raw bytes) as an X.509 INTEGER.
///
/// DER INTEGER rules require prepending `0x00` if the high bit of the
/// first content byte is set, to keep the integer non-negative.
fn encode_serial_number(serial_bytes: &[u8]) -> Result<Vec<u8>> {
    if serial_bytes.is_empty() {
        return Err(Error::FieldValueOutOfRange {
            tag: crate::tlv_tags::CERT_SERIAL_NUMBER,
        });
    }

    let needs_leading_zero = (serial_bytes[0] & 0x80) != 0;
    let content_len = serial_bytes.len() + usize::from(needs_leading_zero);

    let mut out = Vec::with_capacity(content_len + 2);
    out.push(0x02); // INTEGER tag
    encode_definite_length(&mut out, content_len);
    if needs_leading_zero {
        out.push(0x00);
    }
    out.extend_from_slice(serial_bytes);
    Ok(out)
}

/// Wrap content bytes in a DER SEQUENCE.
fn wrap_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(0x30);
    encode_definite_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Encode a DER definite-length prefix (short form ≤ 127, long form otherwise).
fn encode_definite_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        // len < 128, fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
        let used = &bytes[leading_zeros..];
        // used.len() is at most 8 (usize width on 64-bit), so the 0x80 OR
        // and cast to u8 is safe — the high bit encodes the long-form marker.
        #[allow(clippy::cast_possible_truncation)]
        out.push(0x80 | (used.len() as u8));
        out.extend_from_slice(used);
    }
}

/// Convert Unix seconds to `(year, month, day, hour, minute, second)` UTC.
///
/// Uses the civil-from-days algorithm from Howard Hinnant's date library
/// (public domain). Valid for any Unix second since 1970.
fn unix_to_ymdhms(unix_secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    // unix_secs / 86_400 fits in i64 for all values we will see
    // (the max Matter cert date 9999-12-31 is well within i64 range).
    #[allow(clippy::cast_possible_wrap)]
    let day = (unix_secs / 86_400) as i64;
    // unix_secs % 86_400 < 86_400 < u32::MAX — truncation is intentional.
    #[allow(clippy::cast_possible_truncation)]
    let seconds_in_day = (unix_secs % 86_400) as u32;
    let hour = seconds_in_day / 3600;
    let minute = (seconds_in_day / 60) % 60;
    let second = seconds_in_day % 60;

    let z = day + 719_468;
    let era = z.div_euclid(146_097);
    // z - era * 146_097 is always in [0, 146_096], fits in u32.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    // year is a calendar year (e.g. 2024, 9999) — always fits in u32.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let year_u32 = year as u32;
    (year_u32, m, d, hour, minute, second)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use crate::time::MatterTime;

    // ---- encode_validity --------------------------------------------------

    #[test]
    fn validity_pre_2050_uses_utctime() {
        // 2024-01-01T00:00:00Z, Matter-time form
        let not_before = MatterTime::from_unix_secs(1_704_067_200);
        // 2049-12-31T23:59:59Z (last UTCTime moment)
        let not_after = MatterTime::from_unix_secs(2_524_607_999);
        let bytes = encode_validity(not_before, not_after);

        // SEQUENCE { UTCTime("240101000000Z"), UTCTime("491231235959Z") }
        // Inner UTCTime is tag 0x17, length 0x0D, 13 ASCII chars.
        assert_eq!(bytes[0], 0x30); // outer SEQUENCE tag
        assert_eq!(bytes[2], 0x17); // first UTCTime tag
        assert_eq!(bytes[3], 0x0D); // length = 13
        assert_eq!(&bytes[4..17], b"240101000000Z");
        assert_eq!(bytes[17], 0x17); // second UTCTime tag
        assert_eq!(bytes[18], 0x0D);
        assert_eq!(&bytes[19..32], b"491231235959Z");
    }

    #[test]
    fn validity_post_2050_uses_generalizedtime() {
        // 2050-01-01T00:00:00Z (first GeneralizedTime moment)
        let not_before = MatterTime::from_unix_secs(2_524_608_000);
        // 2100-01-01T00:00:00Z
        let not_after = MatterTime::from_unix_secs(4_102_444_800);
        let bytes = encode_validity(not_before, not_after);

        // SEQUENCE { GeneralizedTime("20500101000000Z"), GeneralizedTime("21000101000000Z") }
        assert_eq!(bytes[0], 0x30);
        assert_eq!(bytes[2], 0x18); // GeneralizedTime tag
        assert_eq!(bytes[3], 0x0F); // length = 15
        assert_eq!(&bytes[4..19], b"20500101000000Z");
        assert_eq!(bytes[19], 0x18);
        assert_eq!(bytes[20], 0x0F);
        assert_eq!(&bytes[21..36], b"21000101000000Z");
    }

    #[test]
    fn validity_no_expiry_maps_to_sentinel() {
        let not_before = MatterTime::from_unix_secs(1_704_067_200);
        let bytes = encode_validity(not_before, MatterTime::NO_EXPIRY);
        // not_after must be GeneralizedTime("99991231235959Z")
        // Find it after the UTCTime not_before: 2 SEQUENCE header bytes + 15 UTCTime bytes = offset 17
        assert_eq!(bytes[17], 0x18); // GeneralizedTime tag
        assert_eq!(bytes[18], 0x0F);
        assert_eq!(&bytes[19..34], b"99991231235959Z");
    }

    // ---- encode_serial_number --------------------------------------------

    #[test]
    fn serial_high_bit_clear_no_leading_zero() {
        let bytes = encode_serial_number(&[0x01, 0x02, 0x03]).unwrap();
        // INTEGER tag 0x02, length 3, value 01 02 03
        assert_eq!(bytes, vec![0x02, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn serial_high_bit_set_prepends_leading_zero() {
        let bytes = encode_serial_number(&[0x80, 0x12, 0x34]).unwrap();
        // INTEGER tag 0x02, length 4, value 00 80 12 34
        assert_eq!(bytes, vec![0x02, 0x04, 0x00, 0x80, 0x12, 0x34]);
    }

    #[test]
    fn serial_single_byte_high_bit_set() {
        let bytes = encode_serial_number(&[0xFF]).unwrap();
        assert_eq!(bytes, vec![0x02, 0x02, 0x00, 0xFF]);
    }

    #[test]
    fn serial_empty_is_rejected() {
        // Spec disallows zero-length serials; we mirror that.
        assert!(encode_serial_number(&[]).is_err());
    }
}
