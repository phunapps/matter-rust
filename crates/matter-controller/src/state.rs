//! In-memory controller state. These types are the *persistable* record;
//! live signers are reconstructed from the stored PKCS#8 keys on demand.

use std::sync::Arc;

use matter_cert::MatterCertificate;
use matter_commissioning::FabricRecord;
use matter_crypto::{RingSigner, Signer};

use crate::error::Error;

/// The persisted material for one group key set.
///
/// Stored inside [`FabricEntry::group_keys`] and round-tripped through the
/// TLV snapshot at context tags t6 (key-set array) and t7 (outbound counter).
/// This carries only what the controller needs to *send* group-encrypted
/// messages; a full `GroupKeySet` cluster record lives in the device, not
/// here.
///
/// This is a `pub` type because callers that program group keys (e.g.
/// higher-level fabric-management APIs) need to construct and inspect it.
///
/// `#[non_exhaustive]`: persisted record whose shape may grow (e.g. key policy
/// epoch, security level flags); marking it keeps such additions non-breaking.
/// Construct via [`GroupKeySetConfig::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupKeySetConfig {
    /// Group Key Set ID (`GrpKeySetID`, 16-bit, spec §4.15).
    pub key_set_id: u16,
    /// 16-byte epoch key (`EpochKey0` / `EpochKey1` / `EpochKey2` per policy).
    pub epoch_key: [u8; 16],
    /// Epoch key start time in Matter epoch seconds (0 = unset / pre-operational).
    pub epoch_start_time: u64,
}

impl GroupKeySetConfig {
    /// Construct a [`GroupKeySetConfig`].
    ///
    /// Required because the struct is `#[non_exhaustive]`; external callers
    /// cannot use struct-literal syntax.
    #[must_use]
    pub fn new(key_set_id: u16, epoch_key: [u8; 16], epoch_start_time: u64) -> Self {
        Self {
            key_set_id,
            epoch_key,
            epoch_start_time,
        }
    }
}

/// A per-fabric intermediate CA (ICAC): the issued ICAC certificate plus the
/// PKCS#8 private key that signs NOCs under it. `None` for a flat RCAC->NOC
/// fabric (the default).
#[derive(Clone)]
#[non_exhaustive]
pub struct IcacIdentity {
    /// The RCAC-signed ICAC certificate.
    pub cert: MatterCertificate,
    /// The ICAC signing key, PKCS#8 DER.
    pub pkcs8: Vec<u8>,
}

impl std::fmt::Debug for IcacIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcacIdentity")
            .field("cert", &"<MatterCertificate>")
            .field("pkcs8", &"<redacted PKCS#8>")
            .finish()
    }
}

/// A device commissioned onto a fabric.
///
/// `#[non_exhaustive]`: persisted record whose shape may grow (e.g. CAT tags,
/// typed resumption state); marking it keeps such additions non-breaking. Only
/// constructed inside `matter-controller`.
#[derive(Clone)]
#[non_exhaustive]
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

impl std::fmt::Debug for DeviceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `resumption_record` is a serialized CASE ResumptionRecord and carries
        // a session shared secret — redact it (matches the redaction discipline
        // in `FabricEntry`/`CommissionerIdentity`). `peer_noc_public_key` and
        // `last_known_addr` are not secret.
        f.debug_struct("DeviceEntry")
            .field("node_id", &self.node_id)
            .field("peer_noc_public_key", &self.peer_noc_public_key)
            .field(
                "resumption_record",
                &self
                    .resumption_record
                    .as_ref()
                    .map(|_| "<redacted; CASE secret>"),
            )
            .field("last_known_addr", &self.last_known_addr)
            .finish()
    }
}

/// The controller's own stable operational identity on a fabric.
///
/// Minted **once** when the fabric is created (see
/// [`crate::fabric::create_fabric`]) and reused for every CASE handshake,
/// replacing M6.6.4's per-call NOC minting.
///
/// `#[non_exhaustive]`: persisted identity record that may grow; marking it
/// keeps additions non-breaking. Only constructed inside `matter-controller`.
#[derive(Clone)]
#[non_exhaustive]
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
///
/// `#[non_exhaustive]`: persisted record that may gain fields (e.g. an ICAC
/// tier, fabric label); marking it keeps such additions non-breaking. Only
/// constructed inside `matter-controller`.
#[derive(Clone)]
#[non_exhaustive]
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
    /// Group key sets programmed on this fabric (persisted for outbound group
    /// message encryption). Empty until the controller programs group keys.
    pub group_keys: Vec<GroupKeySetConfig>,
    /// The outbound group message counter for this fabric.
    ///
    /// Monotonically incremented each time the controller sends a group
    /// message. Persisted so the counter survives restarts (spec §4.6.7
    /// prohibits counter reuse across sessions / resets).
    pub outbound_group_counter: u32,
    /// ICD (Intermittently Connected Device) client registrations on this
    /// fabric. Each holds the shared key + counter floor the check-in listener
    /// uses to verify a registered device's Check-In messages. Empty until the
    /// controller calls `register_icd_client`.
    pub icd_clients: Vec<crate::icd::IcdRegistration>,
    /// Optional per-fabric intermediate CA. `None` for a flat RCAC->NOC
    /// fabric (the default); `Some` once the fabric adopts an ICAC tier.
    pub icac: Option<IcacIdentity>,
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
            .field(
                "group_keys",
                &format!("<{} key sets>", self.group_keys.len()),
            )
            .field("outbound_group_counter", &self.outbound_group_counter)
            .field(
                "icd_clients",
                &format!("<{} registrations>", self.icd_clients.len()),
            )
            .field("icac", &self.icac)
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
///
/// `#[non_exhaustive]`: the persisted top-level record may gain fields (e.g.
/// schema version, controller-wide settings); marking it keeps such additions
/// non-breaking. Construct via [`ControllerState::new`] or
/// [`ControllerState::default`] from outside this crate.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ControllerState {
    /// Fabrics this controller administers.
    pub fabrics: Vec<FabricEntry>,
}

impl ControllerState {
    /// Construct controller state from a list of administered fabrics.
    ///
    /// Supported construction path now that [`ControllerState`] is
    /// `#[non_exhaustive]`; the `fabrics` field stays directly accessible.
    #[must_use]
    pub fn new(fabrics: Vec<FabricEntry>) -> Self {
        Self { fabrics }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn controller_state_new_builds_from_fabrics() {
        // `ControllerState` is `#[non_exhaustive]`; `new` is the supported
        // construction path. An empty list yields no fabrics.
        let state = ControllerState::new(Vec::new());
        assert!(state.fabrics.is_empty());
    }

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
