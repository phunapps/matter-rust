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

    /// No fabric exists, or the requested node/fabric is not addressable.
    #[error("not commissioned: {0}")]
    NotCommissioned(String),

    /// The owning controller task has stopped (channel closed).
    #[error("controller task is no longer running")]
    ControllerStopped,

    /// A cryptographic derivation (operational IPK / compressed fabric id) failed.
    #[error("operational key derivation failed: {0}")]
    Operational(String),
}
