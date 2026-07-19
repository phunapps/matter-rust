//! Role-aware constructors for Matter operational-PKI certificates
//! (spec §6.5.5): NOC, ICAC, RCAC.
//!
//! Each role has a pinned extension/DN profile the spec mandates; these
//! constructors bake the profile in so callers cannot accidentally build
//! a non-conformant operational certificate. Every constructor returns an
//! [`UnsignedCertificate`] — signing stays external, same two-stage split
//! as [`crate::builder`].
//!
//! Currently implemented: [`rcac`] (Root CA Certificate, spec §6.5.5);
//! [`icac`] (Intermediate CA Certificate, spec §6.5.5); [`noc`] (Node
//! Operational Certificate, spec §6.5.5).

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

/// Parameters for [`icac`].
///
/// `#[non_exhaustive]`: future spec-driven ICAC fields should be addable
/// without breaking existing callers.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct IcacParams {
    /// The Matter Intermediate CA Identifier (subject DN `IcacId` attribute).
    pub icac_id: u64,
    /// The issuing RCAC's Distinguished Name (this ICAC's issuer DN).
    pub issuer: DistinguishedName,
    /// The issuing RCAC's Subject Key Identifier (this ICAC's AKID).
    pub issuer_skid: KeyIdentifier,
    /// The intermediate CA's own EC P-256 public key.
    pub public_key: PublicKey,
    /// Certificate serial number (1..=20 raw bytes per spec §6.5.1).
    pub serial: Vec<u8>,
    /// Start of the validity window.
    pub not_before: MatterTime,
    /// End of the validity window (`MatterTime::NO_EXPIRY` for none).
    pub not_after: MatterTime,
}

/// Parameters for [`noc`].
///
/// `#[non_exhaustive]`: future spec-driven NOC fields should be addable
/// without breaking existing callers.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct NocParams {
    /// The Fabric ID this NOC belongs to (subject DN `FabricId` attribute).
    pub fabric_id: u64,
    /// The Node ID assigned to this NOC's holder (subject DN `NodeId`
    /// attribute).
    pub node_id: u64,
    /// CASE Authenticated Tags (CATs). Each entry becomes its own
    /// `DnAttribute::CaseAuthenticatedTag` in the subject DN, appended in
    /// order after `FabricId`/`NodeId` (spec §6.5.6 Table 71).
    pub case_authenticated_tags: Vec<u32>,
    /// The issuing CA's (RCAC's or ICAC's) Distinguished Name (this NOC's
    /// issuer DN).
    pub issuer: DistinguishedName,
    /// The issuing CA's Subject Key Identifier (this NOC's AKID).
    pub issuer_skid: KeyIdentifier,
    /// The NOC holder's own EC P-256 public key.
    pub public_key: PublicKey,
    /// Certificate serial number (1..=20 raw bytes per spec §6.5.1).
    pub serial: Vec<u8>,
    /// Start of the validity window.
    pub not_before: MatterTime,
    /// End of the validity window (`MatterTime::NO_EXPIRY` for none).
    pub not_after: MatterTime,
}

/// Extended-key-usage OID arc values for the NOC profile (spec §6.5.4):
/// id-kp-clientAuth (1.3.6.1.5.5.7.3.2) and id-kp-serverAuth
/// (1.3.6.1.5.5.7.3.1). Client listed first — matches
/// `matter-commissioning::noc::issuer::issue_noc`'s constants and the
/// order matter.js's `Certificate.asUnsignedDer()` emits.
const EKU_CLIENT_AUTH: u32 = 2;
const EKU_SERVER_AUTH: u32 = 1;

/// Compute a Subject/Authority Key Identifier from a public key: SHA-1 over
/// the 64-byte `X || Y` of the SEC1-uncompressed point, **excluding the
/// leading `0x04` prefix byte**.
///
/// This is the Matter §6.5.4 convention: matter.js hashes the bare `X || Y`,
/// and it is byte-parity-pinned by `matter-commissioning`'s operational-cert
/// issuers (`noc::fabric` RCAC + `noc::issuer` NOC, the M6.3.3 gate). It
/// deliberately differs from RFC 5280 §4.2.1.2 method (1), which hashes the
/// whole `subjectPublicKey` BIT STRING (i.e. including the `0x04`). SKID/AKID
/// are identifiers, not a security hash, so SHA-1 is correct and intended
/// here.
fn skid_from_spki(pk: &PublicKey) -> KeyIdentifier {
    let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &pk.as_bytes()[1..]);
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

/// Build an unsigned Intermediate CA Certificate (ICAC, spec §6.5.5).
///
/// Pins the ICAC profile from spec §6.5.5 / §6.5.4:
/// - subject DN = `IcacId(params.icac_id)`; issuer DN = `params.issuer`
///   (the RCAC's DN)
/// - `BasicConstraints { cA: true, pathLen: Some(0) }`, critical
/// - `KeyUsage { keyCertSign, cRLSign }`, critical
/// - `SubjectKeyIdentifier` = SHA-1(SPKI) of this ICAC's own public key;
///   `AuthorityKeyIdentifier` = `params.issuer_skid` (the RCAC's SKID)
///
/// # Errors
///
/// Returns [`crate::Error::FieldValueOutOfRange`] if `params.serial` is
/// empty or longer than the 20-byte maximum (spec §6.5.1). All other
/// [`IcacParams`] fields are structurally valid by construction, so no
/// other builder error is reachable here.
pub fn icac(params: IcacParams) -> Result<UnsignedCertificate> {
    let subject = DistinguishedName::new(vec![DnAttribute::IcacId(params.icac_id)]);

    let skid = skid_from_spki(&params.public_key);

    let extensions = Extensions::builder()
        .basic_constraints(Some(BasicConstraints::new(true, Some(0))))
        .key_usage(Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN))
        .subject_key_identifier(Some(skid))
        .authority_key_identifier(Some(params.issuer_skid))
        .build();

    MatterCertificate::builder()
        .serial(params.serial)
        .issuer(params.issuer)
        .subject(subject)
        .validity(params.not_before, params.not_after)
        .public_key(params.public_key)
        .extensions(extensions)
        .build_unsigned()
}

/// Build an unsigned Node Operational Certificate (NOC, spec §6.5.5).
///
/// Pins the NOC profile from spec §6.5.5 / §6.5.4:
/// - subject DN = `FabricId(params.fabric_id)`, then `NodeId(params.node_id)`,
///   then one `CaseAuthenticatedTag` per entry of
///   `params.case_authenticated_tags` (in order); issuer DN =
///   `params.issuer` (the RCAC's or ICAC's DN)
/// - `BasicConstraints { cA: false }`
/// - `KeyUsage { digitalSignature }`
/// - `ExtendedKeyUsage = [id-kp-clientAuth, id-kp-serverAuth]`
/// - `SubjectKeyIdentifier` = SHA-1 of this NOC's own public key (the Matter
///   §6.5.4 64-byte `X || Y` convention); `AuthorityKeyIdentifier` =
///   `params.issuer_skid` (the issuing CA's SKID)
///
/// Byte-parity: the SKID matches
/// `matter-commissioning::noc::issuer::issue_noc`'s existing, wire-tested
/// computation (both go through the same §6.5.4 convention), so a later task
/// can refactor `issue_noc` onto this constructor without changing the wire
/// output.
///
/// # Errors
///
/// Returns [`crate::Error::FieldValueOutOfRange`] if `params.serial` is
/// empty or longer than the 20-byte maximum (spec §6.5.1). All other
/// [`NocParams`] fields are structurally valid by construction, so no
/// other builder error is reachable here.
pub fn noc(params: NocParams) -> Result<UnsignedCertificate> {
    let mut subject_attrs: Vec<DnAttribute> =
        Vec::with_capacity(2 + params.case_authenticated_tags.len());
    subject_attrs.push(DnAttribute::FabricId(params.fabric_id));
    subject_attrs.push(DnAttribute::NodeId(params.node_id));
    for cat in &params.case_authenticated_tags {
        subject_attrs.push(DnAttribute::CaseAuthenticatedTag(*cat));
    }
    let subject = DistinguishedName::new(subject_attrs);

    let skid = skid_from_spki(&params.public_key);

    let extensions = Extensions::builder()
        .basic_constraints(Some(BasicConstraints::new(false, None)))
        .key_usage(Some(KeyUsage::DIGITAL_SIGNATURE))
        .extended_key_usage(Some(vec![EKU_CLIENT_AUTH, EKU_SERVER_AUTH]))
        .subject_key_identifier(Some(skid))
        .authority_key_identifier(Some(params.issuer_skid))
        .build();

    MatterCertificate::builder()
        .serial(params.serial)
        .issuer(params.issuer)
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

    #[test]
    fn icac_has_the_expected_profile() {
        let issuer_dn = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);
        let issuer_skid = skid_from_spki(&spki());

        let unsigned = icac(IcacParams {
            icac_id: 2,
            issuer: issuer_dn.clone(),
            issuer_skid,
            public_key: spki(),
            serial: vec![0x02],
            not_before: MatterTime::from_unix_secs(1_700_000_000),
            not_after: MatterTime::NO_EXPIRY,
        })
        .unwrap();

        let ext = unsigned.extensions();
        let bc = ext.basic_constraints.unwrap();
        assert!(bc.is_ca && bc.path_len_constraint == Some(0));
        assert_eq!(
            ext.key_usage,
            Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
        );
        assert!(ext.subject_key_identifier.is_some());
        assert_eq!(ext.authority_key_identifier, Some(issuer_skid));
        assert_eq!(unsigned.subject().icac_id(), Some(2));
        assert_eq!(unsigned.issuer().rcac_id(), Some(1));
    }

    #[test]
    fn noc_has_the_expected_profile() {
        let issuer_dn = DistinguishedName::new(vec![DnAttribute::IcacId(2)]);
        let issuer_skid = skid_from_spki(&spki());

        let unsigned = noc(NocParams {
            fabric_id: 7,
            node_id: 0xDEAD_BEEF_CAFE_BABE,
            case_authenticated_tags: vec![0x0001_0002, 0x0003_0004],
            issuer: issuer_dn.clone(),
            issuer_skid,
            public_key: spki(),
            serial: vec![0x03],
            not_before: MatterTime::from_unix_secs(1_700_000_000),
            not_after: MatterTime::NO_EXPIRY,
        })
        .unwrap();

        let ext = unsigned.extensions();
        let bc = ext.basic_constraints.unwrap();
        assert!(!bc.is_ca);
        assert_eq!(ext.key_usage, Some(KeyUsage::DIGITAL_SIGNATURE));
        assert_eq!(ext.extended_key_usage, Some(vec![2, 1]));
        assert!(ext.subject_key_identifier.is_some());
        assert_eq!(ext.authority_key_identifier, Some(issuer_skid));

        // Subject DN attribute order: FabricId, NodeId, then CATs in order.
        assert_eq!(
            unsigned.subject().iter().cloned().collect::<Vec<_>>(),
            vec![
                DnAttribute::FabricId(7),
                DnAttribute::NodeId(0xDEAD_BEEF_CAFE_BABE),
                DnAttribute::CaseAuthenticatedTag(0x0001_0002),
                DnAttribute::CaseAuthenticatedTag(0x0003_0004),
            ]
        );
        assert_eq!(unsigned.issuer(), &issuer_dn);
    }

    #[test]
    fn skid_uses_matter_64byte_convention() {
        // Byte-parity guardrail (Matter §6.5.4): a NOC's SKID must hash the
        // 64-byte X||Y point (EXCLUDING the 0x04 prefix), matching
        // `matter-commissioning::noc::issuer::issue_noc` /
        // `noc::fabric`'s wire-tested computation. `skid_from_spki` (shared by
        // rcac/icac/noc) must use the same convention — if it regresses to
        // hashing the full 65-byte point, every operational cert's SKID
        // silently diverges from matter.js/chip.
        let pk = spki();
        let unsigned = noc(NocParams {
            fabric_id: 1,
            node_id: 2,
            case_authenticated_tags: vec![],
            issuer: DistinguishedName::new(vec![DnAttribute::RcacId(1)]),
            issuer_skid: skid_from_spki(&pk),
            public_key: pk.clone(),
            serial: vec![0x04],
            not_before: MatterTime::from_unix_secs(1_700_000_000),
            not_after: MatterTime::NO_EXPIRY,
        })
        .unwrap();

        let expected = {
            let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &pk.as_bytes()[1..]);
            let mut arr = [0u8; 20];
            arr.copy_from_slice(hash.as_ref());
            KeyIdentifier(arr)
        };
        // The NOC's SKID is the 64-byte-convention hash...
        assert_eq!(unsigned.extensions().subject_key_identifier, Some(expected));
        // ...and `skid_from_spki` produces exactly that (all roles consistent).
        assert_eq!(expected, skid_from_spki(&pk));
        // Guard the actual regression: hashing the full 65-byte point (the
        // old bug) is a DIFFERENT value.
        let full = {
            let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, pk.as_bytes());
            let mut arr = [0u8; 20];
            arr.copy_from_slice(hash.as_ref());
            KeyIdentifier(arr)
        };
        assert_ne!(expected, full);
    }
}
