//! Fabric creation. Mints the fabric trust root (RCAC + IPK) and the
//! controller's **stable** commissioner operational identity in one shot.
//! The commissioner NOC is minted here exactly once and persisted; every
//! later CASE handshake reuses it (retiring M6.6.4's per-call minting).

use std::sync::Arc;

use matter_cert::MatterTime;
use matter_commissioning::{issue_icac, issue_noc, FabricRecord, NocRng, VerifiedCsr};
use matter_crypto::{RingSigner, Signer};

use crate::error::Error;
use crate::state::{CommissionerIdentity, FabricEntry, IcacIdentity};

/// Inputs for creating a new fabric.
///
/// `#[non_exhaustive]`: future fabric-creation knobs (e.g. an explicit IPK or
/// an ICAC tier) can be added without a semver break. Construct via
/// [`FabricConfig::new`] from outside this crate.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FabricConfig {
    /// Matter fabric identifier (spec §6.2.1).
    pub fabric_id: u64,
    /// RCAC subject DN's `rcac-id` value.
    pub rcac_id: u64,
    /// The stable node ID the controller takes on this fabric.
    pub commissioner_node_id: u64,
    /// `(not_before, not_after)` validity for the RCAC and commissioner NOC.
    pub validity: (MatterTime, MatterTime),
    /// When `true`, `create_fabric` mints an intermediate CA (ICAC) under
    /// the RCAC and signs the commissioner NOC (and, later, all NOCs
    /// issued on this fabric) under the ICAC instead of directly under the
    /// RCAC. Defaults to `false` (the flat RCAC->NOC path) via
    /// [`FabricConfig::new`].
    pub issue_icac: bool,
}

impl FabricConfig {
    /// Construct a fabric configuration.
    ///
    /// This is the supported construction path now that [`FabricConfig`] is
    /// `#[non_exhaustive]`; the public fields remain readable/writable in
    /// place.
    #[must_use]
    pub fn new(
        fabric_id: u64,
        rcac_id: u64,
        commissioner_node_id: u64,
        validity: (MatterTime, MatterTime),
    ) -> Self {
        Self {
            fabric_id,
            rcac_id,
            commissioner_node_id,
            validity,
            issue_icac: false,
        }
    }
}

/// Create a fabric: generate the RCAC root key + self-signed RCAC, a fresh
/// IPK, the commissioner operational keypair, and the commissioner NOC.
///
/// The returned [`FabricEntry`] is fully persistable (private keys captured
/// as PKCS#8 DER) and has no devices yet.
///
/// # Errors
///
/// Returns [`Error::Signer`] if key generation fails, or [`Error::Noc`] if
/// RCAC construction or NOC issuance fails.
pub fn create_fabric(cfg: &FabricConfig, rng: &dyn NocRng) -> Result<FabricEntry, Error> {
    // 1. RCAC root key + self-signed root certificate.
    let (root_signer, rcac_pkcs8) =
        RingSigner::generate().map_err(|e| Error::Signer(e.to_string()))?;
    let root_arc: Arc<dyn Signer> = Arc::new(root_signer);
    let mut fabric_record = FabricRecord::new_root_only(
        cfg.fabric_id,
        root_arc,
        cfg.validity.0,
        cfg.validity.1,
        cfg.rcac_id,
        rng,
    )?;

    // 1b. Optionally mint an ICAC tier under the RCAC. This must happen
    //     BEFORE the commissioner NOC is issued below, so the commissioner
    //     NOC itself is signed under the ICAC (matching what a real
    //     ICAC-tier fabric does for every NOC it issues).
    let icac_identity = if cfg.issue_icac {
        let (icac_signer_raw, icac_pkcs8) =
            RingSigner::generate().map_err(|e| Error::Signer(e.to_string()))?;
        let icac_public_key = icac_signer_raw.public_key().clone();
        // Single-ICAC fabric: reuse `cfg.rcac_id` as the ICAC's `IcacId`
        // DN value too. `RcacId` and `IcacId` are distinct DN attribute
        // types (spec §6.5.5), so the shared numeric id is unambiguous —
        // there is no collision between "RCAC id 7" and "ICAC id 7".
        let icac_cert = issue_icac(
            &fabric_record,
            cfg.rcac_id,
            &icac_public_key,
            cfg.validity,
            rng,
        )
        .map_err(Error::Noc)?;
        fabric_record.icac_signer = Some(Arc::new(icac_signer_raw));
        fabric_record.icac_cert = Some(icac_cert.clone());
        Some(IcacIdentity {
            cert: icac_cert,
            pkcs8: icac_pkcs8,
        })
    } else {
        None
    };

    // 2. Commissioner operational keypair.
    let (comm_signer, comm_pkcs8) =
        RingSigner::generate().map_err(|e| Error::Signer(e.to_string()))?;
    let comm_public_key = comm_signer.public_key().clone();

    // 3. Mint the commissioner NOC over our own key. We generated the key
    //    ourselves, so there is no device CSR to verify — `VerifiedCsr`
    //    here asserts "this public key is trusted for issuance", which is
    //    sound for our own identity. When `fabric_record.icac_signer`/
    //    `icac_cert` are `Some` (set just above), `issue_noc` signs this
    //    under the ICAC instead of the RCAC.
    let verified = VerifiedCsr {
        public_key: comm_public_key,
    };
    let noc = issue_noc(
        &fabric_record,
        &verified,
        cfg.commissioner_node_id,
        &[], // no CASE Authenticated Tags for the controller identity
        cfg.validity,
        rng,
    )?;

    Ok(FabricEntry {
        fabric_id: cfg.fabric_id,
        ipk: fabric_record.identity_protection_key,
        rcac_cert: fabric_record.root_cert.clone(),
        rcac_pkcs8,
        commissioner: CommissionerIdentity {
            node_id: cfg.commissioner_node_id,
            operational_pkcs8: comm_pkcs8,
            noc,
        },
        devices: Vec::new(),
        group_keys: Vec::new(),
        outbound_group_counter: 0,
        icd_clients: Vec::new(),
        icac: icac_identity,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md allows unwrap/expect with justification.
mod tests {
    use super::*;
    use matter_commissioning::SystemNocRng;

    fn sample_cfg() -> FabricConfig {
        FabricConfig::new(
            0xDEAD_BEEF_0000_0001,
            1,
            0x0000_0000_0000_0001,
            (
                MatterTime::from_unix_secs(1_700_000_000),
                MatterTime::NO_EXPIRY,
            ),
        )
    }

    #[test]
    fn new_constructor_sets_all_fields() {
        // `FabricConfig` is `#[non_exhaustive]`; `new` is the supported
        // construction path. Verify it populates every field.
        let cfg = FabricConfig::new(
            7,
            9,
            3,
            (MatterTime::from_unix_secs(1), MatterTime::NO_EXPIRY),
        );
        assert_eq!(cfg.fabric_id, 7);
        assert_eq!(cfg.rcac_id, 9);
        assert_eq!(cfg.commissioner_node_id, 3);
        assert_eq!(cfg.validity.0, MatterTime::from_unix_secs(1));
    }

    #[test]
    fn creates_fabric_with_no_devices() {
        let fabric = create_fabric(&sample_cfg(), &SystemNocRng).expect("create");
        assert_eq!(fabric.fabric_id, 0xDEAD_BEEF_0000_0001);
        assert_eq!(fabric.commissioner.node_id, 1);
        assert!(fabric.devices.is_empty());
        assert!(!fabric.rcac_pkcs8.is_empty());
        assert!(!fabric.commissioner.operational_pkcs8.is_empty());
    }

    #[test]
    fn commissioner_noc_is_signed_by_the_rcac() {
        let fabric = create_fabric(&sample_cfg(), &SystemNocRng).expect("create");
        let rcac_key = fabric.rcac_cert.public_key();
        fabric
            .commissioner
            .noc
            .verify_signed_by(rcac_key)
            .expect("commissioner NOC must verify under the RCAC");
    }

    #[test]
    fn default_path_has_no_icac_and_noc_issuer_is_rcac() {
        // `issue_icac = false` (the `FabricConfig::new` default) must not
        // mint an ICAC, and the commissioner NOC's issuer must be the RCAC
        // subject (the flat RCAC->NOC path, byte-unchanged from Task 7).
        let fabric = create_fabric(&sample_cfg(), &SystemNocRng).expect("create");
        assert!(fabric.icac.is_none());
        assert_eq!(fabric.commissioner.noc.issuer(), fabric.rcac_cert.subject());
    }

    #[test]
    fn issue_icac_true_mints_chain_and_signs_commissioner_noc_under_icac() {
        let mut cfg = sample_cfg();
        cfg.issue_icac = true;
        let entry = create_fabric(&cfg, &SystemNocRng).expect("create");

        // The fabric entry carries a minted ICAC.
        let icac = entry.icac.clone().expect("icac must be Some");

        // Reconstructing the runtime FabricRecord restores both the ICAC
        // signer and cert.
        let rec = entry.to_fabric_record().expect("to_fabric_record");
        assert!(rec.icac_signer.is_some());
        assert!(rec.icac_cert.is_some());

        // The commissioner NOC's issuer DN is the ICAC's subject, not the
        // RCAC's.
        assert_eq!(entry.commissioner.noc.issuer(), icac.cert.subject());
        assert_ne!(entry.commissioner.noc.issuer(), entry.rcac_cert.subject());

        // 3-tier chain linkage + signature verification:
        // RCAC issued/signed the ICAC...
        assert_eq!(icac.cert.issuer(), entry.rcac_cert.subject());
        icac.cert
            .verify_signed_by(entry.rcac_cert.public_key())
            .expect("icac must verify under the rcac's public key");
        // ...and the ICAC issued/signed the commissioner NOC.
        assert_eq!(entry.commissioner.noc.issuer(), icac.cert.subject());
        entry
            .commissioner
            .noc
            .verify_signed_by(icac.cert.public_key())
            .expect("commissioner noc must verify under the icac's public key");

        // Snapshot round-trip preserves `icac` as `Some` with a matching
        // cert.
        let state = crate::state::ControllerState::new(vec![entry.clone()]);
        let bytes = crate::snapshot::serialize(&state).expect("serialize");
        let restored = crate::snapshot::deserialize(&bytes).expect("deserialize");
        let restored_icac = restored.fabrics[0]
            .icac
            .clone()
            .expect("icac must round-trip as Some");
        assert_eq!(
            restored_icac.cert.to_tlv().expect("tlv"),
            icac.cert.to_tlv().expect("tlv"),
            "restored icac cert must byte-match the original"
        );
    }

    #[test]
    fn commissioner_signer_matches_persisted_noc_key() {
        // The persisted operational key must correspond to the NOC's
        // public key — i.e. we can actually use the identity we minted.
        let fabric = create_fabric(&sample_cfg(), &SystemNocRng).expect("create");
        let signer = fabric.commissioner_signer().expect("reload signer");
        assert_eq!(
            signer.public_key().as_bytes(),
            fabric.commissioner.noc.public_key().as_bytes(),
            "persisted op key must match the NOC subject public key"
        );
    }
}
