//! `MatterController` — the public entry point. A cheap, cloneable handle
//! over the owning actor task (a crate-internal `tokio` task).

use std::sync::Arc;

use matter_commissioning::driver::AsyncDatagram;
use matter_commissioning::{NocRng, SystemNocRng};
use matter_transport::Discovery;
use tokio::sync::{mpsc, oneshot};

use crate::actor::{Actor, Command};
use crate::builder::MatterControllerBuilder;
use crate::error::Error;
use crate::fabric::FabricConfig;
use crate::node::Node;
use crate::snapshot;
use crate::state::ControllerState;
use crate::store::ControllerStore;
use crate::trust::AttestationTrust;

const COMMAND_CHANNEL_DEPTH: usize = 32;

/// The high-level Matter controller. Cloneable; all clones talk to one
/// owning task.
#[derive(Clone)]
pub struct MatterController {
    tx: mpsc::Sender<Command>,
}

impl MatterController {
    /// Begin configuring a controller (attestation trust, admin vendor id).
    #[must_use]
    pub fn builder(store: Arc<dyn ControllerStore>) -> MatterControllerBuilder {
        MatterControllerBuilder::new(store)
    }

    /// Open a controller with default settings and **no** attestation trust —
    /// sufficient for operating already-commissioned devices, but `commission`
    /// will return [`Error::NoTrust`]. Use [`Self::builder`] to commission.
    ///
    /// # Errors
    ///
    /// As [`MatterControllerBuilder::build`].
    pub async fn open(store: Arc<dyn ControllerStore>) -> Result<Self, Error> {
        Self::spawn_default(store, None, crate::builder::DEFAULT_ADMIN_VENDOR_ID).await
    }

    pub(crate) async fn spawn_default(
        store: Arc<dyn ControllerStore>,
        trust: Option<AttestationTrust>,
        admin_vendor_id: u16,
    ) -> Result<Self, Error> {
        let transport = matter_transport::TokioUdpTransport::bind(0)
            .await
            .map_err(|e| Error::Operational(format!("bind: {e}")))?;
        let discovery = matter_transport::MdnsSdDiscovery::new()
            .map_err(|e| Error::Operational(format!("mdns: {e}")))?;
        Self::with_components(
            store,
            transport,
            discovery,
            Arc::new(SystemNocRng),
            trust,
            admin_vendor_id,
        )
    }

    /// Construct over caller-supplied transport + discovery (used by tests to
    /// inject `InMemoryDatagram` + a mock `Discovery`).
    ///
    /// # Errors
    ///
    /// [`Error::Store`] / [`Error::Snapshot`] if the persisted snapshot is
    /// unreadable.
    pub(crate) fn with_components<T, D>(
        store: Arc<dyn ControllerStore>,
        transport: T,
        discovery: D,
        rng: Arc<dyn NocRng>,
        trust: Option<AttestationTrust>,
        admin_vendor_id: u16,
    ) -> Result<Self, Error>
    where
        // `Sync` because the spawned actor future holds `&self.transport`
        // across awaits (inside `run_case`/`secured_round_trip`); `Send` so the
        // future can be `tokio::spawn`ed onto the multi-thread runtime.
        T: AsyncDatagram + Send + Sync + 'static,
        D: Discovery + Send + 'static,
    {
        let state = match store.load()? {
            Some(bytes) => snapshot::deserialize(&bytes)?,
            None => ControllerState::default(),
        };
        let (tx, rx) = mpsc::channel(COMMAND_CHANNEL_DEPTH);
        let actor = Actor::new(
            transport,
            discovery,
            store,
            rng,
            state,
            trust,
            admin_vendor_id,
        );
        tokio::spawn(actor.run(rx));
        Ok(Self { tx })
    }

    /// Create and persist a new fabric (mints the stable commissioner
    /// identity). Returns the new fabric id.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`] if the task has stopped; otherwise any
    /// minting / persistence error.
    pub async fn create_fabric(&self, cfg: FabricConfig) -> Result<u64, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::CreateFabric { cfg, reply })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        rx.await.map_err(|_| Error::ControllerStopped)?
    }

    /// Handle addressing a device by node id (single-fabric in M8.2).
    #[must_use]
    pub fn node(&self, node_id: u64) -> Node {
        Node {
            tx: self.tx.clone(),
            node_id,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)] // Used in Task 5 loopback test; allow until then.
    pub(crate) async fn session_count(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::SessionCount { reply }).await.is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }
}
