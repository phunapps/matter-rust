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

use core::time::Duration;

use matter_cert::time::MatterTime;
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage};

use crate::attestation::error::{map_webpki_error, AttestationError};
use crate::attestation::extensions::{ProductId, VendorId};
use crate::attestation::trust_store::PaaTrustStore;
use crate::attestation::x509::{Dac, Paa, Pai};

/// Signature algorithms accepted in Matter attestation chains.
///
/// Matter Core Spec §6.2 mandates ECDSA over the NIST P-256 curve
/// with SHA-256 for every signature in the DAC -> PAI -> PAA chain.
/// We list exactly that algorithm and no others: any cert signed
/// with a different scheme (e.g. RSA, `EdDSA`, P-384) is rejected by
/// webpki with `UnsupportedSignatureAlgorithm`, which our
/// [`map_webpki_error`] funnels into
/// [`AttestationError::InvalidChain`].
static MATTER_SIG_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[webpki::ring::ECDSA_P256_SHA256];

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
/// Runs `rustls-webpki`'s RFC 5280 path validation (signature, name
/// chaining, validity windows, `BasicConstraints`, `KeyUsage`, and the
/// `id-kp-clientAuth` EKU per Matter §6.5), then layers Matter
/// §6.2.3's VID/PID equality overlay on top. The DAC is treated as
/// the end-entity, the PAI as the sole intermediate, and the trust
/// store as the set of candidate PAAs.
///
/// Pure sans-I/O: no clock reads, no network, no internal state.
/// Time is supplied via [`MatterTime`] so tests can pin behaviour to
/// fixture validity windows.
///
/// # Errors
///
/// - [`AttestationError::TimeBoundsViolation`] — a cert in the chain
///   was outside its validity window at `at`.
/// - [`AttestationError::BasicConstraintsViolation`] — a non-CA cert
///   was flagged as a CA, or the path-length constraint was violated.
/// - [`AttestationError::UntrustedRoot`] — no PAA in `trust_store`
///   anchors the PAI.
/// - [`AttestationError::InvalidChain`] — any other webpki rejection
///   (signature mismatch, unsupported algorithm, missing EKU, …).
/// - [`AttestationError::VidMismatch`] — DAC subject VID does not
///   equal PAI subject VID.
/// - [`AttestationError::PaiVidNotAuthorized`] — PAI is product-scoped
///   (carries a subject PID) and that PID does not equal the DAC's.
/// - [`AttestationError::Parse`] — a PAA in the trust store could not
///   be re-parsed by webpki (should be unreachable, since
///   [`Paa::from_der`] already validated the bytes).
pub fn verify_chain(
    dac: &Dac,
    pai: &Pai,
    trust_store: &PaaTrustStore,
    at: MatterTime,
) -> Result<ChainVerification, AttestationError> {
    // 1. Lift every PAA in the trust store into a webpki TrustAnchor.
    //    Each anchor borrows its bytes from a heap copy we own
    //    (paa_to_trust_anchor's `to_owned()` call), so the resulting
    //    Vec is `'static`-borrowed and can outlive any stack-local
    //    CertificateDer wrappers below.
    let anchors: Vec<TrustAnchor<'static>> = trust_store
        .iter()
        .map(paa_to_trust_anchor)
        .collect::<Result<Vec<_>, _>>()?;

    // 2. Wrap DAC + PAI DER as the webpki types. `CertificateDer::from`
    //    on a `&[u8]` is a zero-cost newtype wrap.
    let dac_der = CertificateDer::from(dac.der());
    let pai_der = CertificateDer::from(pai.der());
    let intermediates = [pai_der];
    let end_entity = EndEntityCert::try_from(&dac_der).map_err(map_webpki_error)?;

    // 3. Project MatterTime onto webpki's UnixTime. MatterTime stores
    //    seconds-since-Matter-epoch (2000-01-01); its `to_unix_secs`
    //    converts to seconds-since-Unix-epoch, which is the unit
    //    UnixTime takes.
    let now = UnixTime::since_unix_epoch(Duration::from_secs(at.to_unix_secs()));

    // 4. Path validation. webpki checks: signature on each cert with
    //    `MATTER_SIG_ALGS`; validity window vs `now`; BasicConstraints
    //    on every CA; KeyUsage matches the requested usage; EKU
    //    contains `id-kp-clientAuth` (Matter §6.5). No revocation
    //    (Matter doesn't define CRLs/OCSP for attestation in M6.2);
    //    no extra `verify_path` predicate (the Matter overlay below
    //    runs after webpki returns so we can produce typed errors
    //    rather than `Error::Other`).
    end_entity
        .verify_for_usage(
            MATTER_SIG_ALGS,
            &anchors,
            &intermediates,
            now,
            KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(map_webpki_error)?;

    // 5. Matter §6.2.3 overlay — VID/PID equality. webpki has already
    //    accepted the signatures and name-chain, so a mismatch here
    //    is a Matter-policy rejection rather than an X.509 one.
    let dac_vid = dac.subject_vid();
    let pai_vid = pai.subject_vid();
    if dac_vid != pai_vid {
        return Err(AttestationError::VidMismatch {
            dac: dac_vid,
            pai: pai_vid,
        });
    }
    if let Some(pai_pid) = pai.subject_pid() {
        if pai_pid != dac.subject_pid() {
            return Err(AttestationError::PaiVidNotAuthorized);
        }
    }

    // 6. Identify which PAA in the store actually anchored the chain
    //    so callers can audit-log "attested by PAA <subject>". Walk
    //    the trust store and find the PAA whose subject Name matches
    //    the PAI's issuer Name. Self-signed PAAs have
    //    issuer == subject (RFC 5280 §4.1.2.4), so this is the PAA
    //    webpki must have selected. If webpki accepted the chain
    //    above, exactly one such PAA exists; the `ok_or` is a safety
    //    net against subject-name encoding drift between webpki and
    //    x509-parser and should be unreachable.
    // x509-parser's `X509Name::as_raw()` returns the full DER-encoded
    // `Name` SEQUENCE (tag + length + contents), but webpki's
    // `TrustAnchor::subject` field stores only the SEQUENCE contents
    // (it strips the outer tag/length when extracting from the cert
    // — see `extract_trust_anchor_from_v1_cert_der` in webpki's
    // `trust_anchor.rs`). So we strip the SEQUENCE wrapper from the
    // PAI's issuer to put both sides on the same footing before
    // byte-comparing.
    let pai_issuer_contents =
        strip_sequence_wrapper(pai.issuer_raw()).ok_or(AttestationError::UntrustedRoot)?;
    let paa_subject = trust_store
        .iter()
        .find_map(|paa| {
            let anchor = paa_to_trust_anchor(paa).ok()?;
            if anchor.subject.as_ref() == pai_issuer_contents {
                Some(anchor.subject.as_ref().to_vec())
            } else {
                None
            }
        })
        .ok_or(AttestationError::UntrustedRoot)?;

    Ok(ChainVerification {
        vendor_id: dac_vid,
        product_id: dac.subject_pid(),
        dac_public_key: dac.public_key().to_vec(),
        paa_subject,
    })
}

/// Strip a DER `SEQUENCE` tag-and-length wrapper from `bytes`,
/// returning the inner contents.
///
/// Used to align an x509-parser-produced `Name` DER (full SEQUENCE
/// with tag + length + contents) against webpki's `TrustAnchor::subject`
/// (only the contents, the tag/length having been stripped during
/// anchor extraction). Returns `None` if `bytes` is not a definite-length
/// `SEQUENCE` or if the declared length runs past the slice — both
/// indicate input that already failed earlier DER parsing, so the
/// caller treats them as `UntrustedRoot`.
///
/// Handles the two length encodings observed in practice for Matter
/// `Name`s: short-form (single length byte, content < 128 bytes) and
/// long-form `0x81`/`0x82` (one or two length bytes, content up to
/// 65 535 bytes). Longer forms are rejected — a Matter `Name` would
/// never exceed a few hundred bytes.
fn strip_sequence_wrapper(bytes: &[u8]) -> Option<&[u8]> {
    // SEQUENCE constructed: tag byte 0x30.
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x30 {
        return None;
    }
    let (&first_len_byte, after_first) = rest.split_first()?;
    let (content_len, header_bytes) = match first_len_byte {
        // Short form: top bit clear, value is the length itself.
        n if n < 0x80 => (n as usize, 0_usize),
        // Long form: 0x81 = 1 length byte, 0x82 = 2 length bytes.
        0x81 => {
            let (&len, _) = after_first.split_first()?;
            (len as usize, 1)
        }
        0x82 => {
            let len_bytes: &[u8; 2] = after_first.get(..2)?.try_into().ok()?;
            (u16::from_be_bytes(*len_bytes) as usize, 2)
        }
        // 0x80 (indefinite-length) and 0x83+ (>= 16 MiB) are out of
        // scope for Matter Names.
        _ => return None,
    };
    let content_start = 2 + header_bytes;
    let content_end = content_start.checked_add(content_len)?;
    bytes.get(content_start..content_end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::PaaTrustStore;

    const HAPPY_DAC: &[u8] = include_bytes!(
        "../../../../test-vectors/certs/attestation/happy-path/Chip-Test-DAC-FFF1-8000-0004-Cert.der"
    );
    const HAPPY_PAI: &[u8] = include_bytes!(
        "../../../../test-vectors/certs/attestation/happy-path/Chip-Test-PAI-FFF1-8000-Cert.der"
    );

    #[test]
    #[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
    fn paa_to_trust_anchor_works_on_bundled_csa_root() {
        let store = PaaTrustStore::with_csa_test_roots();
        let paa = store.iter().next().unwrap();
        // Must not error; webpki should accept any well-formed
        // X.509v3 self-signed cert that Paa::from_der accepted.
        let _anchor = paa_to_trust_anchor(paa).unwrap();
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
    fn verify_chain_happy_path_on_csa_test_vectors() {
        let dac = Dac::from_der(HAPPY_DAC).unwrap();
        let pai = Pai::from_der(HAPPY_PAI).unwrap();
        let store = PaaTrustStore::with_csa_test_roots();

        // CSA test DAC issued ~2022 with multi-year validity; 2024
        // sits safely inside the window. Pinning the clock keeps the
        // test deterministic regardless of when it runs.
        let at = MatterTime::from_unix_secs(1_704_067_200); // 2024-01-01

        let result = verify_chain(&dac, &pai, &store, at).expect("happy-path verify_chain");
        assert_eq!(result.vendor_id, VendorId::new(0xFFF1));
        assert_eq!(result.product_id, ProductId::new(0x8000));
        assert_eq!(result.dac_public_key.len(), 65);
        assert!(!result.paa_subject.is_empty());
    }
}
