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

// VendorId/ProductId newtype impls land in T4; OID extraction helpers in T5.

/// Placeholder. Real implementation lands in T4.
pub struct VendorId;

/// Placeholder. Real implementation lands in T4.
pub struct ProductId;
