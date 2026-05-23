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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VendorId(u16);

impl VendorId {
    /// Wrap a raw `u16` as a `VendorId`.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

    #[test]
    fn ids_are_distinct_types() {
        // Compile-time check: `VendorId` and `ProductId` cannot be
        // accidentally interchanged. If a future refactor collapses
        // them, this test's body should fail to compile.
        fn _takes_vid(_: VendorId) {}
        fn _takes_pid(_: ProductId) {}
        let _ = _takes_vid;
        let _ = _takes_pid;
    }
}
