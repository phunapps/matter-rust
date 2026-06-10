//! In-memory controller state. These types are the *persistable* record;
//! live signers are reconstructed from the stored PKCS#8 keys on demand.

use std::sync::Arc;

use matter_cert::MatterCertificate;
use matter_commissioning::FabricRecord;
use matter_crypto::{RingSigner, Signer};

use crate::error::Error;

/// A device commissioned onto a fabric.
#[derive(Debug, Clone)]
pub struct DeviceEntry {
    /// The device's operational node ID on this fabric.
    pub node_id: u64,
    /// The device's NOC public key (SEC1 uncompressed, `0x04 || X || Y`).
    pub peer_noc_public_key: [u8; 65],
    /// Cached CASE resumption record (opaque bytes; typed in M8.2).
    pub resumption_record: Option<Vec<u8>>,
    /// Last operational address we reached the device at (a discovery hint).
    pub last_known_addr: Option<String>,
}

/// The controller's own stable operational identity on a fabric.
///
/// Minted **once** when the fabric is created (see
/// [`crate::fabric::create_fabric`]) and reused for every CASE handshake,
/// replacing M6.6.4's per-call NOC minting.
#[derive(Clone)]
pub struct CommissionerIdentity {
    /// The commissioner's stable node ID on this fabric.
    pub node_id: u64,
    /// The commissioner's operational private key, PKCS#8 DER.
    pub operational_pkcs8: Vec<u8>,
    /// The commissioner's NOC, signed by the fabric RCAC.
    pub noc: MatterCertificate,
}

impl std::fmt::Debug for CommissionerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommissionerIdentity")
            .field("node_id", &self.node_id)
            .field("operational_pkcs8", &"<redacted PKCS#8>")
            .field("noc", &"<MatterCertificate>")
            .finish()
    }
}

/// One fabric the controller administers: trust root, IPK, the
/// commissioner identity, and the devices commissioned onto it.
#[derive(Clone)]
pub struct FabricEntry {
    /// Matter fabric identifier.
    pub fabric_id: u64,
    /// 16-byte Identity Protection Key for this fabric.
    pub ipk: [u8; 16],
    /// Self-signed root (RCAC) certificate.
    pub rcac_cert: MatterCertificate,
    /// The RCAC root signing key, PKCS#8 DER.
    pub rcac_pkcs8: Vec<u8>,
    /// The controller's stable identity on this fabric.
    pub commissioner: CommissionerIdentity,
    /// Devices commissioned onto this fabric.
    pub devices: Vec<DeviceEntry>,
}

impl std::fmt::Debug for FabricEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FabricEntry")
            .field("fabric_id", &self.fabric_id)
            .field("ipk", &"<redacted; 16 bytes>")
            .field("rcac_cert", &"<MatterCertificate>")
            .field("rcac_pkcs8", &"<redacted PKCS#8>")
            .field("commissioner", &self.commissioner)
            .field("devices", &self.devices)
            .finish()
    }
}

impl FabricEntry {
    /// Reconstruct the RCAC root signer from the stored PKCS#8 key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signer`] if the stored key is not valid PKCS#8.
    pub fn rcac_signer(&self) -> Result<RingSigner, Error> {
        RingSigner::from_pkcs8(&self.rcac_pkcs8).map_err(|e| Error::Signer(e.to_string()))
    }

    /// Reconstruct the commissioner operational signer from PKCS#8.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signer`] if the stored key is not valid PKCS#8.
    pub fn commissioner_signer(&self) -> Result<RingSigner, Error> {
        RingSigner::from_pkcs8(&self.commissioner.operational_pkcs8)
            .map_err(|e| Error::Signer(e.to_string()))
    }

    /// Build a [`FabricRecord`] view (used by later sub-phases for NOC
    /// issuance and CASE). Reconstructs the RCAC signer from PKCS#8.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signer`] if the RCAC key cannot be reconstructed.
    pub fn to_fabric_record(&self) -> Result<FabricRecord, Error> {
        let signer = self.rcac_signer()?;
        let root_public_key = signer.public_key().clone();
        Ok(FabricRecord {
            fabric_id: self.fabric_id,
            root_public_key,
            root_signer: Arc::new(signer) as Arc<dyn Signer>,
            root_cert: self.rcac_cert.clone(),
            icac_signer: None,
            icac_cert: None,
            identity_protection_key: self.ipk,
        })
    }
}

/// The full controller state: all administered fabrics.
#[derive(Debug, Clone, Default)]
pub struct ControllerState {
    /// Fabrics this controller administers.
    pub fabrics: Vec<FabricEntry>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn reconstructed_signer_signs_and_verifies() {
        // A standalone RingSigner round-trips through PKCS#8 and signs.
        let (signer, pkcs8) = RingSigner::generate().expect("generate");
        let entry_key = pkcs8.clone();
        let reloaded = RingSigner::from_pkcs8(&entry_key).expect("reload");
        // Both signers share the same public key.
        assert_eq!(
            signer.public_key().as_bytes(),
            reloaded.public_key().as_bytes()
        );
        // The reloaded signer produces a verifiable signature.
        let msg = b"controller identity";
        let sig_bytes = reloaded.sign_p256_sha256(msg).expect("sign");
        // `PublicKey::verify` takes a `&matter_cert::Signature`, not a raw `[u8; 64]`.
        let sig = matter_cert::Signature::new(sig_bytes);
        reloaded
            .public_key()
            .verify(msg, &sig)
            .expect("reloaded signature verifies");
    }
}
