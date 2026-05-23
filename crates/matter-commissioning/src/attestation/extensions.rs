//! Matter-specific X.509 DN attribute extraction.
//!
//! Matter Core Spec §6.5.6 reserves OIDs under the CSA arc
//! `1.3.6.1.4.1.37244` for vendor and product identifiers in
//! Distinguished Names. M6.2.1 implements OID matching and value
//! extraction for the two attestation-relevant cases:
//!
//! - [`VendorId`][] OID: `1.3.6.1.4.1.37244.2.1`
//! - [`ProductId`][] OID: `1.3.6.1.4.1.37244.2.2`
//!
//! Values are encoded as 4-character UPPERCASE hex strings of the u16
//! identifier (Matter §6.5.6.1). e.g. VID `0xFFF1` appears as the
//! UTF-8 string `"FFF1"`.

/// A Matter vendor identifier. 16-bit, allocated by the CSA.
///
/// Wraps a `u16` for type-distinct API surface. `Display` formatting
/// emits a 4-character zero-padded UPPERCASE hex string — matches
/// Matter §6.5.6.1's encoding of [`VendorId`] inside cert DNs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VendorId(u16);

impl VendorId {
    /// Wrap a raw `u16` as a `VendorId`.
    ///
    /// `VendorId` and [`ProductId`] are deliberately distinct types
    /// to prevent accidental interchange at API boundaries. The
    /// following must fail to compile:
    ///
    /// ```compile_fail
    /// use matter_commissioning::attestation::{ProductId, VendorId};
    /// fn takes_vid(_: VendorId) {}
    /// takes_vid(ProductId::new(0));
    /// ```
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the underlying `u16` value.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl core::fmt::Display for VendorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04X}", self.0)
    }
}

/// A Matter product identifier. 16-bit, allocated by the vendor.
///
/// Same shape as [`VendorId`] — see its docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductId(u16);

impl ProductId {
    /// Wrap a raw `u16` as a `ProductId`.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the underlying `u16` value.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl core::fmt::Display for ProductId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04X}", self.0)
    }
}

use x509_parser::der_parser::oid::Oid;
use x509_parser::x509::X509Name;

// We use the `oid!` macro from `asn1-rs` (re-exported through
// `x509-parser::der_parser`). It builds an `Oid<'static>` at compile
// time from a dotted-notation literal — no runtime allocation, no
// `unwrap`, no const-fn-availability concerns. Invoked via its
// fully-qualified path to avoid module-vs-macro name collisions with
// the sibling `der_parser::oid` module.

/// Matter [`VendorId`] DN attribute OID: `1.3.6.1.4.1.37244.2.1`.
///
/// Per Matter Core Spec §6.5.6.1, the attribute value is a UTF-8
/// string of 4 UPPERCASE hex characters encoding the u16 VID.
//
// Consumed by extract_vid (this file) and by x509.rs in T6/T7. The
// dead-code allow is removed in T6 when the first non-test caller
// lands; for now only the test module references it.
#[allow(dead_code)] // T6 consumer pending.
pub(crate) const MATTER_VID_OID: Oid<'static> =
    x509_parser::der_parser::oid!(1.3.6.1.4.1.37244.2.1);

/// Matter [`ProductId`] DN attribute OID: `1.3.6.1.4.1.37244.2.2`.
///
/// Same encoding rules as [`MATTER_VID_OID`].
#[allow(dead_code)] // T6 consumer pending.
pub(crate) const MATTER_PID_OID: Oid<'static> =
    x509_parser::der_parser::oid!(1.3.6.1.4.1.37244.2.2);

/// Extract the Matter [`VendorId`] from an X.509 subject DN, if present.
///
/// Returns:
/// - `Ok(Some(vid))` — VID DN attribute present and parsed.
/// - `Ok(None)` — VID DN attribute absent.
/// - `Err(_)` — VID DN attribute present but its value is malformed
///   (not 4 hex chars, not UTF-8, or hex doesn't fit a u16, or not
///   UPPERCASE per Matter §6.5.6.1).
#[allow(dead_code)] // T6 consumer pending.
pub(crate) fn extract_vid(
    name: &X509Name<'_>,
) -> Result<Option<VendorId>, MatterDnError> {
    extract_matter_u16(name, &MATTER_VID_OID).map(|opt| opt.map(VendorId::new))
}

/// Extract the Matter [`ProductId`] from an X.509 subject DN, if present.
///
/// Same semantics as [`extract_vid`].
#[allow(dead_code)] // T7 consumer pending.
pub(crate) fn extract_pid(
    name: &X509Name<'_>,
) -> Result<Option<ProductId>, MatterDnError> {
    extract_matter_u16(name, &MATTER_PID_OID).map(|opt| opt.map(ProductId::new))
}

#[allow(dead_code)] // Used by extract_vid / extract_pid; T6 consumer pending.
fn extract_matter_u16(
    name: &X509Name<'_>,
    oid: &Oid<'_>,
) -> Result<Option<u16>, MatterDnError> {
    let Some(attr) = name.iter_attributes().find(|a| a.attr_type() == oid) else {
        return Ok(None);
    };
    let raw = attr.as_str().map_err(|_| MatterDnError::NonUtf8Value)?;
    if raw.len() != 4 {
        return Err(MatterDnError::WrongLength { actual: raw.len() });
    }
    let value =
        u16::from_str_radix(raw, 16).map_err(|_| MatterDnError::NotHex)?;
    // Reject lowercase by re-formatting and comparing — Matter §6.5.6.1
    // is explicit about UPPERCASE.
    let canonical = format!("{value:04X}");
    if raw != canonical {
        return Err(MatterDnError::NotUppercase);
    }
    Ok(Some(value))
}

/// Internal error type for Matter DN extraction failures. Wrapped into
/// [`crate::attestation::error::AttestationError::Parse`] by callers.
#[allow(dead_code)] // T6 consumer pending.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MatterDnError {
    /// The Matter VID/PID attribute value is not valid UTF-8.
    #[error("Matter VID/PID DN attribute is not valid UTF-8")]
    NonUtf8Value,
    /// The attribute value is the wrong length (must be 4 chars).
    #[error("Matter VID/PID DN attribute is {actual} chars, expected 4")]
    WrongLength {
        /// The actual length we observed.
        actual: usize,
    },
    /// The attribute value contains non-hex characters.
    #[error("Matter VID/PID DN attribute is not hex")]
    NotHex,
    /// The attribute value contains lowercase hex digits (Matter §6.5.6.1 requires UPPERCASE).
    #[error("Matter VID/PID DN attribute must be UPPERCASE hex")]
    NotUppercase,
}

#[cfg(test)]
mod tests {
    use super::{ProductId, VendorId};

    #[test]
    fn vendor_id_round_trips_through_u16() {
        let v = VendorId::new(0xFFF1);
        assert_eq!(v.as_u16(), 0xFFF1);
    }

    #[test]
    fn vendor_id_display_is_4char_uppercase_hex() {
        assert_eq!(VendorId::new(0x0001).to_string(), "0001");
        assert_eq!(VendorId::new(0xFFF1).to_string(), "FFF1");
        assert_eq!(VendorId::new(0x00AB).to_string(), "00AB");
    }

    #[test]
    fn product_id_round_trips_through_u16() {
        let p = ProductId::new(0x8000);
        assert_eq!(p.as_u16(), 0x8000);
    }

    #[test]
    fn product_id_display_is_4char_uppercase_hex() {
        assert_eq!(ProductId::new(0x0001).to_string(), "0001");
        assert_eq!(ProductId::new(0x8000).to_string(), "8000");
    }

    use x509_parser::prelude::{FromDer, X509Certificate};

    const DAC_DER: &[u8] = include_bytes!(
        "../../../../test-vectors/certs/attestation/happy-path/Chip-Test-DAC-FFF1-8000-0004-Cert.der"
    );

    #[test]
    #[allow(clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
    fn extract_vid_finds_dac_vid() {
        let (_, cert) =
            X509Certificate::from_der(DAC_DER).expect("happy-path DAC parses");
        let vid = super::extract_vid(cert.subject())
            .expect("VID well-formed")
            .expect("VID present");
        assert_eq!(vid, super::VendorId::new(0xFFF1));
    }

    #[test]
    #[allow(clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
    fn extract_pid_finds_dac_pid() {
        let (_, cert) =
            X509Certificate::from_der(DAC_DER).expect("happy-path DAC parses");
        let pid = super::extract_pid(cert.subject())
            .expect("PID well-formed")
            .expect("PID present");
        assert_eq!(pid, super::ProductId::new(0x8000));
    }

    #[test]
    #[allow(clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
    fn matter_vid_oid_constant_matches_spec_arc() {
        // Round-trip the OID's components to confirm the const
        // assembles the arc we intended (Matter §6.5.6.1).
        let parts: Vec<u64> = super::MATTER_VID_OID
            .iter()
            .expect("iterable")
            .collect();
        assert_eq!(parts, vec![1, 3, 6, 1, 4, 1, 37244, 2, 1]);
    }
}
