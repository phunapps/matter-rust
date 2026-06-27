//! Error type for `matter-controller`.

use crate::store::StoreError;

/// Errors surfaced by the controller's persistence and identity layer.
///
/// `#[non_exhaustive]` so later sub-phases can add networked variants
/// (e.g. `SessionLost`, `DeviceUnreachable`) without a breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The backing [`ControllerStore`](crate::store::ControllerStore) failed.
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    /// TLV encode/decode of the snapshot blob failed.
    #[error("TLV codec error: {0}")]
    Codec(#[from] matter_codec::Error),

    /// A certificate failed to parse or serialize.
    #[error("certificate error: {0}")]
    Cert(#[from] matter_cert::Error),

    /// NOC/RCAC issuance failed.
    #[error("NOC issuance error: {0}")]
    Noc(#[from] matter_commissioning::NocError),

    /// A signing key could not be generated or reconstructed.
    #[error("signer error: {0}")]
    Signer(String),

    /// The persisted snapshot was structurally invalid or an unknown version.
    #[error("malformed snapshot: {0}")]
    Snapshot(String),

    /// CASE session establishment failed, or a driver operation errored.
    #[error("driver error: {0}")]
    Driver(#[from] matter_commissioning::driver::DriverError),

    /// A transport / session-manager (framing, MRP) operation failed.
    #[error("transport error: {0}")]
    Transport(#[from] matter_transport::Error),

    /// No fabric exists, or the requested node/fabric is not addressable.
    #[error("not commissioned: {0}")]
    NotCommissioned(String),

    /// The owning controller task has stopped (channel closed).
    #[error("controller task is no longer running")]
    ControllerStopped,

    /// An Interaction-Model request/response failed to build or parse.
    #[error("interaction model error: {0}")]
    InteractionModel(#[from] matter_interaction::ImError),

    /// An operational-path failure with a human-readable detail — a key
    /// derivation (operational IPK / compressed fabric id), a transport/session
    /// send or decode, a request timeout, or a subscription liveness timeout.
    #[error("operational error: {0}")]
    Operational(String),

    /// Attestation trust material could not be loaded.
    #[error("attestation trust error: {0}")]
    Trust(String),

    /// The setup code (QR / manual) could not be parsed.
    #[error("invalid setup code: {0}")]
    SetupCode(String),

    /// Commissioning requires attestation trust, but none was configured.
    #[error("no attestation trust configured (use MatterController::builder)")]
    NoTrust,

    /// An `AdministratorCommissioning` command returned a non-success IM status
    /// (e.g. 0x02 Busy, 0x03 `PAKEParameterError`, 0x04 `WindowNotOpen` reported as
    /// a cluster status). The raw IM status byte is preserved.
    #[error("commissioning window command rejected (IM status {0:#04x})")]
    CommissioningWindowRejected(u8),

    /// Refused to remove the controller's own fabric (would sever the CASE
    /// session and orphan persisted device state). No `force` override exists.
    #[error("refusing to remove our own fabric (would orphan the device)")]
    WouldRemoveSelf,

    /// An `OperationalCredentials` command returned a non-success
    /// `NodeOperationalCertStatusEnum` (e.g. 7 `InvalidFabricIndex`). Raw code preserved.
    #[error("operational-credentials command rejected (status {0})")]
    OperationalCredentialsRejected(u8),

    /// Refused an ACL write that would strip our own administrative access
    /// (no Administer/CASE entry covering our commissioner node id). Prevents
    /// orphaning the device. Checked before any bytes are sent.
    #[error("refusing ACL write: it would remove our own administrative access")]
    AclWouldLockOut,

    /// A `Groups` / `GroupKeyManagement` command returned a non-success status
    /// (e.g. `ResourceExhausted` from `MaxGroupsPerFabric`). Raw status preserved.
    #[error("group command rejected (status {0})")]
    GroupCommandRejected(u8),

    /// A group send (`invoke_group`) named a `key_set_id` that has not been
    /// provisioned on the controller's fabric (no matching
    /// [`GroupKeySetConfig`](crate::GroupKeySetConfig) in `group_keys`). Call
    /// [`MatterController::create_group`](crate::MatterController::create_group)
    /// first to mint and persist the key set.
    #[error("group key set {0} is not provisioned on this fabric")]
    GroupNotProvisioned(u16),
}
