//! In-memory controller state. Implemented in M8.1 Task 4.

use matter_cert::MatterCertificate;

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

/// One fabric the controller administers.
#[derive(Clone, Debug)]
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

/// The full controller state: all administered fabrics.
#[derive(Debug, Clone, Default)]
pub struct ControllerState {
    /// Fabrics this controller administers.
    pub fabrics: Vec<FabricEntry>,
}
