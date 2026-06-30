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
    /// Retained so the OTA provider server ([`Self::serve_provider_once`]) can
    /// load the stable, committed operational identity without routing through
    /// the actor (the identity is minted once and never mutated after).
    store: Arc<dyn ControllerStore>,
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
            store.clone(),
            rng,
            state,
            trust,
            admin_vendor_id,
        );
        tokio::spawn(actor.run(rx));
        Ok(Self { tx, store })
    }

    /// Serve the OTA **provider** role once: advertise our operational service,
    /// accept one inbound CASE session, and dispatch up to `max_invokes`
    /// server-side `InvokeRequest`s through `handler`, then withdraw the
    /// advertisement. `handler` maps a parsed request to the encoded
    /// `InvokeResponse` bytes (e.g. via `matter_interaction::build_invoke_response_*`).
    ///
    /// The server runs on its **own** freshly-bound UDP socket and its own mDNS
    /// daemon — it does not touch the client actor (the long-running accept is
    /// kept off the proven request/MRP loop). It authenticates as our persisted
    /// operational identity (the M8 commissioner NOC/IPK/root).
    ///
    /// F3 ships the generic plumbing; F4 supplies the OTA `QueryImage` handler
    /// and the BDX transfer. Note: advertising a wildcard-bound address may not
    /// be routable to a foreign requestor — see the F3 runbook for the
    /// interface-selection caveat (the automated validation is the in-process
    /// loopback test).
    ///
    /// # Errors
    ///
    /// [`Error::NotCommissioned`] if no fabric exists; [`Error::Operational`] on
    /// bind / mDNS / clock failure; otherwise any CASE-accept or dispatch error
    /// from [`crate::provider_server::ProviderServer`].
    pub async fn serve_provider_once<H>(
        &self,
        port: u16,
        handler: H,
        max_invokes: usize,
    ) -> Result<usize, Error>
    where
        H: FnMut(&matter_interaction::ParsedInvokeRequest) -> Vec<u8>,
    {
        use crate::provider_server::{build_operational_service, ProviderServer};

        // 1. Load our persisted fabric + build the responder identity.
        let state = match self.store.load()? {
            Some(bytes) => snapshot::deserialize(&bytes)?,
            None => return Err(Error::NotCommissioned("no fabric to serve from".into())),
        };
        let fabric = state
            .fabrics
            .first()
            .ok_or_else(|| Error::NotCommissioned("no fabric to serve from".into()))?;
        let (credentials, roots, compressed) = crate::credentials::operational_credentials(fabric)?;
        let node_id = fabric.commissioner.node_id;
        let now = crate::actor::current_matter_time()?;

        // 2. Bind our own socket + advertise the operational service.
        let socket = matter_transport::TokioUdpTransport::bind(port)
            .await
            .map_err(|e| Error::Operational(format!("provider bind: {e}")))?;
        let local = socket
            .socket()
            .local_addr()
            .map_err(|e| Error::Operational(format!("provider local_addr: {e}")))?;
        let mut discovery = matter_transport::MdnsSdDiscovery::new()
            .map_err(|e| Error::Operational(format!("provider mdns: {e}")))?;
        let service =
            build_operational_service(compressed, node_id, vec![local.ip()], local.port());
        matter_transport::Discovery::publish(&mut discovery, &service)?;

        // 3. Accept one session + dispatch up to `max_invokes` invokes.
        let result = ProviderServer::new(socket, credentials, roots, /* sid */ 0x01, now)
            .accept_and_dispatch_once(handler, max_invokes)
            .await;

        // 4. Withdraw the advertisement regardless of outcome.
        let _ = matter_transport::Discovery::unpublish(
            &mut discovery,
            &service.instance_name,
            matter_transport::ServiceKind::Operational,
        );
        result
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

    /// Commission a device from a QR (`MT:...`) or manual pairing code, bring it
    /// onto the controller's fabric, and persist it. Returns the device's node id.
    ///
    /// # Errors
    ///
    /// [`Error::NoTrust`] if no attestation trust was configured,
    /// [`Error::SetupCode`] if the code is invalid, [`Error::ControllerStopped`]
    /// if the task stopped, or any driver/commissioning error.
    pub async fn commission(&self, setup_code: &str) -> Result<u64, Error> {
        let setup_payload = parse_setup_code(setup_code)?;
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Commission {
                setup_payload,
                reply,
            })
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

    /// Create a group key set on the controller's fabric: mints a fresh 16-byte
    /// epoch key from the CSPRNG, persists a `GroupKeySetConfig` under
    /// `key_set_id`, and returns the [`GroupKeySet`](crate::GroupKeySet) so the caller can program
    /// it onto each member device via
    /// [`Node::write_group_key_set`](crate::Node::write_group_key_set) and map a
    /// group to it. The key set is stored durably before this returns, so the
    /// controller can encrypt outbound group messages for it immediately
    /// (see [`Self::invoke_group`]).
    ///
    /// `epoch_start_time` is the Matter-epoch start time recorded in the
    /// returned `GroupKeySet` (the device-side `KeySetWrite` echoes it).
    ///
    /// # Errors
    ///
    /// [`Error::NotCommissioned`] if no single fabric exists,
    /// [`Error::ControllerStopped`] if the task has stopped, or any
    /// CSPRNG / persistence error.
    pub async fn create_group(
        &self,
        key_set_id: u16,
        epoch_start_time: u64,
    ) -> Result<crate::GroupKeySet, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::CreateGroup {
                key_set_id,
                epoch_start_time,
                reply,
            })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        rx.await.map_err(|_| Error::ControllerStopped)?
    }

    /// Fire-and-forget multicast group invoke: send `path`/`fields` to every
    /// device in `group_id`, encrypted with the operational group key derived
    /// from the persisted `key_set_id`. Returns as soon as the datagram is sent
    /// — group commands are unacknowledged, so there is no response.
    ///
    /// The caller supplies `key_set_id` (the key set the group was bound to when
    /// it was created): the controller's persisted `group_keys` are keyed by
    /// key set id, avoiding a separate group→key-set map. The outbound group
    /// message counter is bumped and persisted **before** the send so a counter
    /// is never reused across a crash.
    ///
    /// Real multicast delivery requires the host network to route the Matter
    /// site-local group address; on a host without it the send still succeeds at
    /// the socket layer (the bytes are correct — see the loopback test).
    ///
    /// # Errors
    ///
    /// [`Error::GroupNotProvisioned`] if `key_set_id` has no persisted key set,
    /// [`Error::NotCommissioned`] if no single fabric exists,
    /// [`Error::Operational`] on counter exhaustion or send failure,
    /// [`Error::ControllerStopped`] if the task has stopped, or any
    /// crypto / persistence error.
    pub async fn invoke_group(
        &self,
        group_id: u16,
        key_set_id: u16,
        path: crate::CommandPath,
        fields: crate::Value,
    ) -> Result<(), Error> {
        let fields_tlv = crate::node::value_to_tlv(&fields)?;
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::InvokeGroup {
                group_id,
                key_set_id,
                path,
                fields_tlv,
                reply,
            })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        rx.await.map_err(|_| Error::ControllerStopped)?
    }

    #[cfg(test)]
    pub(crate) async fn session_count(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::SessionCount { reply }).await.is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }
}

/// Parse a QR (`MT:...`) or manual pairing code into a [`matter_commissioning::SetupPayload`].
///
/// QR codes are identified by the `MT:` prefix (Matter Core Spec §5.1.3.1).
/// Anything else is treated as a manual pairing code.
///
/// # Errors
///
/// Returns [`Error::SetupCode`] if the string is not a valid QR or manual code.
fn parse_setup_code(code: &str) -> Result<matter_commissioning::SetupPayload, Error> {
    let trimmed = code.trim();
    let parsed = if trimmed.starts_with("MT:") {
        matter_commissioning::parse_qr(trimmed)
    } else {
        matter_commissioning::parse_manual_code(trimmed)
    };
    parsed.map_err(|e| Error::SetupCode(format!("{e:?}")))
}
