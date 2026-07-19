//! Role-aware constructors for Matter operational-PKI certificates
//! (spec §6.5.5): NOC, ICAC, RCAC.
//!
//! Each role has a pinned extension/DN profile the spec mandates; these
//! constructors bake the profile in so callers cannot accidentally build
//! a non-conformant operational certificate. Every constructor returns an
//! [`UnsignedCertificate`] — signing stays external, same two-stage split
//! as [`crate::builder`].
//!
//! Currently implemented: [`rcac`] (Root CA Certificate, spec §6.5.5).

use ring::digest;

use crate::builder::UnsignedCertificate;
use crate::certificate::MatterCertificate;
use crate::error::Result;
use crate::extensions::{BasicConstraints, Extensions, KeyIdentifier, KeyUsage};
use crate::name::{DistinguishedName, DnAttribute};
use crate::public_key::PublicKey;
use crate::time::MatterTime;

/// Parameters for [`rcac`].
///
/// `#[non_exhaustive]`: future spec-driven RCAC fields (e.g. an optional
/// `CommonName`) should be addable without breaking existing callers.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RcacParams {
    /// The Matter Root CA Identifier (subject/issuer DN `RcacId` attribute).
    pub rcac_id: u64,
    /// The root's own EC P-256 public key.
    pub public_key: PublicKey,
    /// Certificate serial number (1..=20 raw bytes per spec §6.5.1).
    pub serial: Vec<u8>,
    /// Start of the validity window.
    pub not_before: MatterTime,
    /// End of the validity window (`MatterTime::NO_EXPIRY` for none).
    pub not_after: MatterTime,
    /// `BasicConstraints.pathLen` for this root. The RCAC profile
    /// (spec §6.5.5) recommends `Some(1)`; pass `None` for no constraint.
    pub path_len: Option<u8>,
}

/// Compute a Subject/Authority Key Identifier from a public key: SHA-1 over
/// the SEC1-uncompressed public-key bytes (`0x04 || X || Y`, 65 bytes).
///
/// SKID/AKID are identifiers, not a security hash, so SHA-1 (otherwise
/// disallowed for new designs) is correct and intended here — this mirrors
/// RFC 5280 §4.2.1.2 method (1), applied to the raw EC point octet string.
fn skid_from_spki(pk: &PublicKey) -> KeyIdentifier {
    let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &pk.as_bytes()[..]);
    // digest::SHA1_FOR_LEGACY_USE_ONLY always yields exactly 20 bytes, so
    // this slice-to-array conversion cannot fail.
    let mut out = [0u8; 20];
    out.copy_from_slice(hash.as_ref());
    KeyIdentifier(out)
}

/// Build an unsigned self-signed Root CA Certificate (RCAC, spec §6.5.5).
///
/// Pins the RCAC profile from spec §6.5.5 / §6.5.4:
/// - subject DN = issuer DN = `RcacId(params.rcac_id)` (self-signed)
/// - `BasicConstraints { cA: true, pathLen: params.path_len }`, critical
/// - `KeyUsage { keyCertSign, cRLSign }`, critical
/// - `SubjectKeyIdentifier` = SHA-1(SPKI); `AuthorityKeyIdentifier` == SKID
///   (self-signed: the root is its own authority)
///
/// # Errors
///
/// Returns [`crate::Error::FieldValueOutOfRange`] if `params.serial` is
/// empty or longer than the 20-byte maximum (spec §6.5.1). All other
/// [`RcacParams`] fields are structurally valid by construction, so no
/// other builder error is reachable here.
pub fn rcac(params: RcacParams) -> Result<UnsignedCertificate> {
    let subject = DistinguishedName::new(vec![DnAttribute::RcacId(params.rcac_id)]);
    let issuer = subject.clone();

    let skid = skid_from_spki(&params.public_key);

    let extensions = Extensions::builder()
        .basic_constraints(Some(BasicConstraints::new(true, params.path_len)))
        .key_usage(Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN))
        .subject_key_identifier(Some(skid))
        .authority_key_identifier(Some(skid))
        .build();

    MatterCertificate::builder()
        .serial(params.serial)
        .issuer(issuer)
        .subject(subject)
        .validity(params.not_before, params.not_after)
        .public_key(params.public_key)
        .extensions(extensions)
        .build_unsigned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use crate::{MatterTime, PublicKey};

    fn spki() -> PublicKey {
        PublicKey::new([0x04; 65]).unwrap()
    }

    #[test]
    fn rcac_has_the_expected_profile() {
        let unsigned = rcac(RcacParams {
            rcac_id: 1,
            public_key: spki(),
            serial: vec![0x01],
            not_before: MatterTime::from_unix_secs(1_700_000_000),
            not_after: MatterTime::NO_EXPIRY,
            path_len: Some(1),
        })
        .unwrap();
        let ext = unsigned.extensions();
        let bc = ext.basic_constraints.unwrap();
        assert!(bc.is_ca && bc.path_len_constraint == Some(1));
        assert_eq!(
            ext.key_usage,
            Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
        );
        assert!(ext.subject_key_identifier.is_some());
        // Self-signed: AKID == SKID; issuer DN == subject DN (RcacId=1).
        assert_eq!(ext.authority_key_identifier, ext.subject_key_identifier);
        assert_eq!(unsigned.subject().rcac_id(), Some(1));
        assert_eq!(unsigned.issuer().rcac_id(), Some(1));
    }
}
