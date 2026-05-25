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
use rustls_pki_types::{CertificateDer, TrustAnchor};

use crate::attestation::error::AttestationError;
use crate::attestation::extensions::{ProductId, VendorId};
use crate::attestation::trust_store::PaaTrustStore;
use crate::attestation::x509::{Dac, Paa, Pai};

/// Build a [`TrustAnchor`] from one of our [`Paa`]s.
///
/// webpki's anchor wants pre-parsed `Subject`, `SubjectPublicKeyInfo`,
/// and (optionally) `NameConstraints` byte slices. Rather than re-parse
/// the DER ourselves — and risk drifting from webpki's own notion of
/// each field's byte range — we hand the original DER to webpki's
/// dedicated anchor-extraction entry point and let it carve up the
/// slices.
///
/// # Why this returns `TrustAnchor<'static>` rather than `TrustAnchor<'_>`
///
/// webpki 0.103's [`webpki::anchor_from_trusted_cert`] is signed as
/// `fn(&'a CertificateDer<'a>) -> Result<TrustAnchor<'a>, _>` — the
/// returned anchor borrows from the `CertificateDer` wrapper, not the
/// underlying `&[u8]`. If we construct the `CertificateDer` locally
/// (which we must — `Paa` stores `Vec<u8>`, not `CertificateDer`),
/// the returned anchor would borrow from a stack local and the
/// function couldn't return it. So we [`TrustAnchor::to_owned`] the
/// result, copying the three small slices (subject DN, SPKI, optional
/// name constraints — together a few hundred bytes) onto the heap.
/// T6's `verify_chain` calls this once per `verify_chain` invocation,
/// so the cost is negligible (the path validator itself does far more
/// allocation per call).
///
/// # Errors
///
/// Returns [`AttestationError::Parse`] if webpki cannot parse the PAA
/// DER. Should be unreachable in practice — [`Paa::from_der`] already
/// validated the bytes as a self-signed Matter PAA in M6.2.1 — but
/// `x509-parser` (M6.2.1's parser) and webpki's internal parser are
/// distinct implementations, so we wrap rather than panic on any
/// divergence.
///
/// # Why webpki 0.103 doesn't expose `webpki::types::*`
///
/// Pre-0.103, webpki re-exported `rustls-pki-types` items under
/// `webpki::types::*`. 0.103 dropped the re-export — the types now
/// live at their canonical path (`rustls_pki_types::*`), and crates
/// like ours that name them in signatures pull `rustls-pki-types`
/// directly. The Cargo.toml comment on that dep records this.
//
// pub(crate) — the only legitimate caller is `verify_chain` (T6).
// External callers don't need `TrustAnchor` in their hands; they
// see only [`AttestationError`] / [`ChainVerification`].
#[allow(dead_code)] // T6 consumer pending.
pub(crate) fn paa_to_trust_anchor(paa: &Paa) -> Result<TrustAnchor<'static>, AttestationError> {
    // `CertificateDer::from(&[u8])` is a zero-cost newtype wrap — no
    // copy of the PAA DER.
    let cert_der = CertificateDer::from(paa.der());
    webpki::anchor_from_trusted_cert(&cert_der)
        .map(|anchor| anchor.to_owned())
        .map_err(|e| AttestationError::Parse(Box::new(e)))
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::PaaTrustStore;

    #[test]
    #[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
    fn paa_to_trust_anchor_works_on_bundled_csa_root() {
        let store = PaaTrustStore::with_csa_test_roots();
        let paa = store.iter().next().unwrap();
        // Must not error; webpki should accept any well-formed
        // X.509v3 self-signed cert that Paa::from_der accepted.
        let _anchor = paa_to_trust_anchor(paa).unwrap();
    }
}
