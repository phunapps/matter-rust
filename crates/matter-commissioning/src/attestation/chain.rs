//! Device attestation chain validation.
//!
//! [`verify_chain`] runs the load-bearing X.509 path validation
//! through `rustls-webpki` 0.103 and layers Matter-specific overlay
//! checks (VID/PID equality per Matter §6.2.3) on top.
//!
//! Pure sans-I/O — no network, no clock reads, no internal state.
//! Callers supply [`matter_cert::time::MatterTime`] explicitly so
//! tests pin behaviour to fixture validity windows. The DAC public
//! key surfaced in [`ChainVerification`] is the same bytes
//! [`crate::attestation::Dac`]'s `public_key()` accessor returns;
//! M6.2.3 will feed it into `verify_attestation_response`.

#![forbid(unsafe_code)]

use matter_cert::time::MatterTime;

use crate::attestation::error::AttestationError;
use crate::attestation::extensions::{ProductId, VendorId};
use crate::attestation::trust_store::PaaTrustStore;
use crate::attestation::x509::{Dac, Pai};

/// Outcome of a successful [`verify_chain`] call.
///
/// Returned by value (cheap — a few small fields plus an owned DER
/// public-key blob). Callers persist the [`VendorId`]/[`ProductId`]
/// for fabric records and pass `dac_public_key` to M6.2.3's
/// `verify_attestation_response`.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    /// [`VendorId`] matched on both the DAC and PAI subject DNs.
    pub vendor_id: VendorId,
    /// [`ProductId`] matched on the DAC subject DN (and on the PAI if
    /// the PAI was product-scoped).
    pub product_id: ProductId,
    /// DAC subject public key — raw P-256 SEC1 uncompressed bytes
    /// (`0x04 || X || Y`, 65 bytes).
    pub dac_public_key: Vec<u8>,
    /// DER-encoded PAA subject Name. Opaque to most callers; kept for
    /// audit logging ("attested by PAA `<subject>`").
    pub paa_subject: Vec<u8>,
}

/// Verify a Matter attestation chain.
///
/// Placeholder body — real implementation lands in T6 (webpki call +
/// VID/PID overlay).
///
/// # Errors
///
/// Always returns an error in T4's skeleton form. T6 wires the
/// fully-typed success and failure outcomes per the spec.
#[allow(dead_code, unused_variables)] // T6 implementation pending.
pub fn verify_chain(
    dac: &Dac,
    pai: &Pai,
    trust_store: &PaaTrustStore,
    at: MatterTime,
) -> Result<ChainVerification, AttestationError> {
    unimplemented!("verify_chain lands in T6")
}
