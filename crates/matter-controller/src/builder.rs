//! Builder for [`MatterController`]. Configures attestation trust and the
//! admin vendor id before spawning the owning actor.

use std::sync::Arc;

use crate::controller::MatterController;
use crate::error::Error;
use crate::store::ControllerStore;
use crate::trust::AttestationTrust;

/// Default admin vendor id used in `AddNOC` (CSA test VID). Override via
/// [`MatterControllerBuilder::admin_vendor_id`].
pub const DEFAULT_ADMIN_VENDOR_ID: u16 = 0xFFF1;

/// Configures and opens a [`MatterController`].
pub struct MatterControllerBuilder {
    store: Arc<dyn ControllerStore>,
    trust: Option<AttestationTrust>,
    admin_vendor_id: u16,
}

impl MatterControllerBuilder {
    pub(crate) fn new(store: Arc<dyn ControllerStore>) -> Self {
        Self {
            store,
            trust: None,
            admin_vendor_id: DEFAULT_ADMIN_VENDOR_ID,
        }
    }

    /// Set the device-attestation trust material. Required to `commission`.
    #[must_use]
    pub fn attestation_trust(mut self, trust: AttestationTrust) -> Self {
        self.trust = Some(trust);
        self
    }

    /// Override the admin vendor id used in `AddNOC` (default `0xFFF1`).
    #[must_use]
    pub fn admin_vendor_id(mut self, vid: u16) -> Self {
        self.admin_vendor_id = vid;
        self
    }

    /// Bind the socket + discovery, load persisted state, and spawn the actor.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] / [`Error::Snapshot`] on load failure, or
    /// [`Error::Operational`] if the socket / mDNS cannot start.
    pub async fn build(self) -> Result<MatterController, Error> {
        MatterController::spawn_default(self.store, self.trust, self.admin_vendor_id).await
    }
}
