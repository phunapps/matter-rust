//! NOC certificate issuance.

#![forbid(unsafe_code)]

use matter_cert::{
    BasicConstraints, DistinguishedName, DnAttribute, Extensions, KeyIdentifier, KeyUsage,
    MatterCertificate, MatterTime,
};
use ring::digest;

use crate::noc::csr::VerifiedCsr;
use crate::noc::error::{NocError, NocRng};
use crate::noc::fabric::FabricRecord;

/// Spec §6.5.4 EKU OIDs: id-kp-clientAuth (1.3.6.1.5.5.7.3.2) and
/// id-kp-serverAuth (1.3.6.1.5.5.7.3.1). matter-cert stores EKU as
/// the last-OID-arc list; the arc values below match how matter.js
/// emits them in `Certificate.asUnsignedDer()`.
const EKU_CLIENT_AUTH: u32 = 2;
const EKU_SERVER_AUTH: u32 = 1;

/// Construct + sign a NOC for the device whose CSR was verified.
///
/// # Errors
///
/// See [`NocError`] variants `DnAttributeOverflow`, `CertBuild`,
/// `SigningFailed`, and `Rng`.
pub fn issue_noc(
    fabric: &FabricRecord,
    verified_csr: &VerifiedCsr,
    node_id: u64,
    case_authenticated_tags: &[u32],
    validity: (MatterTime, MatterTime),
    rng: &dyn NocRng,
) -> Result<MatterCertificate, NocError> {
    // Subject DN: FabricId + NodeId + CATs (spec §6.5.6 Table 71).
    let mut subject_attrs: Vec<DnAttribute> = Vec::with_capacity(2 + case_authenticated_tags.len());
    subject_attrs.push(DnAttribute::FabricId(fabric.fabric_id));
    subject_attrs.push(DnAttribute::NodeId(node_id));
    for cat in case_authenticated_tags {
        subject_attrs.push(DnAttribute::CaseAuthenticatedTag(*cat));
    }
    let subject = DistinguishedName::new(subject_attrs);

    // Extensions per spec §6.5.4:
    //   BasicConstraints { cA = false }
    //   KeyUsage = DIGITAL_SIGNATURE
    //   EKU = [client_auth, server_auth]
    //   SKI = SHA-1(verified_csr.public_key[1..])
    //   AKI = fabric.root_cert SKI
    let ski_bytes = digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        &verified_csr.public_key.as_bytes()[1..],
    );
    let mut ski_arr = [0u8; 20];
    ski_arr.copy_from_slice(ski_bytes.as_ref());

    let root_ski = fabric
        .root_cert
        .extensions()
        .subject_key_identifier
        .ok_or_else(|| {
            // Tag value chosen to point at "subject-key-identifier" in the
            // existing extensions error space; the precise constant lives
            // in matter-cert's tlv_tags::EXT_SUBJECT_KEY_IDENTIFIER if
            // refactoring later — using a literal here keeps this crate
            // independent of matter-cert's internal tag constants.
            NocError::CertBuild(matter_cert::Error::MissingField(4))
        })?;

    let extensions = Extensions::builder()
        .basic_constraints(Some(BasicConstraints::new(false, None)))
        .key_usage(Some(KeyUsage::DIGITAL_SIGNATURE))
        .extended_key_usage(Some(vec![EKU_CLIENT_AUTH, EKU_SERVER_AUTH]))
        .subject_key_identifier(Some(KeyIdentifier(ski_arr)))
        .authority_key_identifier(Some(root_ski))
        .build();

    // Serial: 19 random bytes (matter.js convention; pinned by M6.3.3
    // byte-parity).
    let mut serial = vec![0u8; 19];
    rng.fill(&mut serial)?;
    // Top bit cleared — see fabric.rs `new_root_only` for the chip-vs-
    // matter.js INTEGER-normalization divergence this avoids.
    serial[0] &= 0x7F;

    let unsigned = MatterCertificate::builder()
        .serial(serial)
        .issuer(fabric.root_cert.subject().clone())
        .subject(subject)
        .validity(validity.0, validity.1)
        .public_key(verified_csr.public_key.clone())
        .extensions(extensions)
        .build_unsigned()
        .map_err(NocError::CertBuild)?;
    let tbs = unsigned.tbs_der().map_err(NocError::CertBuild)?;
    let sig = fabric
        .root_signer
        .sign_p256_sha256(&tbs)
        .map_err(NocError::SigningFailed)?;
    Ok(unsigned.assemble(sig))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use crate::noc::error::SystemNocRng;
    use matter_cert::PublicKey;
    use matter_crypto::{RingSigner, Signer};
    use std::sync::Arc;

    fn sample_verified_csr() -> VerifiedCsr {
        let (signer, _) = RingSigner::generate().unwrap();
        VerifiedCsr {
            public_key: PublicKey::from_slice(signer.public_key().as_bytes()).unwrap(),
        }
    }

    fn sample_fabric() -> FabricRecord {
        let (signer, _) = RingSigner::generate().unwrap();
        let signer: Arc<dyn Signer> = Arc::new(signer);
        FabricRecord::new_root_only(
            0x0000_0000_0000_0001,
            signer,
            MatterTime::from_unix_secs(1_700_000_000),
            MatterTime::NO_EXPIRY,
            7,
            &SystemNocRng,
        )
        .unwrap()
    }

    /// RNG stub returning all-0xFF — forces the serial's would-be MSB high.
    #[derive(Debug)]
    struct AllOnesRng;
    impl crate::noc::NocRng for AllOnesRng {
        fn fill(&self, dest: &mut [u8]) -> Result<(), crate::noc::NocError> {
            dest.fill(0xFF);
            Ok(())
        }
    }

    #[test]
    fn noc_serial_top_bit_is_clear() {
        // Same rule as the RCAC (see fabric.rs::rcac_serial_top_bit_is_clear):
        // an MSB-set serial is reconstructed differently by chip (verbatim)
        // vs matter.js/us (0x00-prepended), breaking the signature on-device.
        let fabric = sample_fabric();
        let verified = sample_verified_csr();
        let noc = issue_noc(
            &fabric,
            &verified,
            0xDEAD_BEEF_CAFE_BABE,
            &[],
            (
                MatterTime::from_unix_secs(1_700_000_000),
                MatterTime::NO_EXPIRY,
            ),
            &AllOnesRng,
        )
        .unwrap();
        assert_eq!(
            noc.serial()[0] & 0x80,
            0,
            "generated NOC serial must have the top bit clear"
        );
    }

    #[test]
    fn issue_noc_produces_self_consistent_certificate() {
        let fabric = sample_fabric();
        let verified = sample_verified_csr();
        let noc = issue_noc(
            &fabric,
            &verified,
            0xDEAD_BEEF_CAFE_BABE,
            &[0x0001_0002],
            (
                MatterTime::from_unix_secs(1_700_000_000),
                MatterTime::NO_EXPIRY,
            ),
            &SystemNocRng,
        )
        .unwrap();

        // Subject must contain FabricId and NodeId.
        assert_eq!(noc.subject().fabric_id(), Some(0x0000_0000_0000_0001));
        assert_eq!(noc.subject().node_id(), Some(0xDEAD_BEEF_CAFE_BABE));

        // Issuer DN == fabric.root_cert subject.
        assert_eq!(noc.issuer(), fabric.root_cert.subject());

        // NOC verifies under the fabric's root public key.
        noc.verify_signed_by(&fabric.root_public_key).unwrap();
    }
}
