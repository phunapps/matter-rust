//! Assemble CASE operational credentials from a persisted [`FabricEntry`].
//!
//! The controller authenticates to devices as its stable commissioner
//! identity (minted once in M8.1). The IPK handed to CASE is the *derived*
//! operational IPK — `HKDF(epoch_key, compressed_fabric_id)` — NOT the raw
//! epoch key stored in the fabric (real devices reject the raw key).

use matter_cert::{TrustAnchor, TrustedRoots};
use matter_crypto::{derive_compressed_fabric_id, derive_operational_ipk, CaseCredentials};

use crate::error::Error;
use crate::state::FabricEntry;

/// Build the CASE credentials, trusted roots, and compressed fabric id the
/// actor needs to open an operational session to a device on this fabric.
///
/// # Errors
///
/// Returns [`Error::Signer`] if the commissioner key cannot be
/// reconstructed, or [`Error::Operational`] if IPK / compressed-fabric-id
/// derivation fails.
pub(crate) fn operational_credentials(
    fabric: &FabricEntry,
) -> Result<(CaseCredentials, TrustedRoots, [u8; 8]), Error> {
    let signer = fabric.commissioner_signer()?; // RingSigner: impl CaseSigner
    let rcac_public_key = *fabric.rcac_cert.public_key().as_bytes();

    let compressed = derive_compressed_fabric_id(&rcac_public_key, fabric.fabric_id)
        .map_err(|e| Error::Operational(e.to_string()))?;
    let operational_ipk = derive_operational_ipk(&fabric.ipk, &compressed)
        .map_err(|e| Error::Operational(e.to_string()))?;

    let mut roots = TrustedRoots::new();
    roots.add(TrustAnchor::from_root_cert(&fabric.rcac_cert));

    let credentials = CaseCredentials {
        noc: fabric.commissioner.noc.clone(),
        icac: None,
        signer: Box::new(signer),
        fabric_id: fabric.fabric_id,
        node_id: fabric.commissioner.node_id,
        ipk: operational_ipk,
        rcac_public_key,
    };

    Ok((credentials, roots, compressed))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md allows unwrap/expect with justification.
mod tests {
    use super::*;
    use crate::fabric::{create_fabric, FabricConfig};
    use matter_cert::MatterTime;
    use matter_commissioning::SystemNocRng;

    fn sample_fabric() -> FabricEntry {
        let cfg = FabricConfig {
            fabric_id: 0x1122_3344_5566_7788,
            rcac_id: 1,
            commissioner_node_id: 0x0000_0000_0000_0001,
            validity: (
                MatterTime::from_unix_secs(1_700_000_000),
                MatterTime::NO_EXPIRY,
            ),
            issue_icac: false,
        };
        create_fabric(&cfg, &SystemNocRng).expect("create_fabric")
    }

    #[test]
    fn builds_credentials_with_derived_ipk_not_raw() {
        let fabric = sample_fabric();
        let (creds, roots, compressed) = operational_credentials(&fabric).expect("creds");

        // IPK passed to CASE must be the DERIVED operational IPK, not the raw epoch key.
        let expected = derive_operational_ipk(&fabric.ipk, &compressed).unwrap();
        assert_eq!(creds.ipk, expected);
        assert_ne!(
            creds.ipk, fabric.ipk,
            "must not hand CASE the raw epoch key"
        );

        assert_eq!(creds.node_id, fabric.commissioner.node_id);
        assert_eq!(creds.fabric_id, fabric.fabric_id);
        assert_eq!(
            creds.rcac_public_key,
            *fabric.rcac_cert.public_key().as_bytes()
        );
        assert_eq!(roots.iter().count(), 1);
    }

    #[test]
    fn credential_signer_matches_commissioner_noc() {
        let fabric = sample_fabric();
        let (creds, _roots, _c) = operational_credentials(&fabric).expect("creds");
        // The signer's public key must equal the NOC subject key — i.e. CASE
        // will sign Sigma3 with the key the NOC actually certifies.
        assert_eq!(
            creds.signer.public_key().as_bytes(),
            creds.noc.public_key().as_bytes()
        );
    }
}
