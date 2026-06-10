//! The owning controller task. Holds the transport, `SessionManager`,
//! discovery, and `ControllerState`; processes [`Command`]s sequentially.
//! Connect/round-trip logic is filled in Task 4.

use std::collections::HashMap;
use std::sync::Arc;

use matter_commissioning::driver::AsyncDatagram;
use matter_commissioning::NocRng;
use matter_transport::{Discovery, SessionId, SessionManager};
use tokio::sync::{mpsc, oneshot};

use crate::error::Error;
use crate::fabric::FabricConfig;
use crate::snapshot;
use crate::state::ControllerState;
use crate::store::ControllerStore;

/// Messages the handles send to the owning task. Each carries a `oneshot`
/// reply sender; a dropped reply sender means the caller gave up.
pub(crate) enum Command {
    CreateFabric {
        cfg: FabricConfig,
        reply: oneshot::Sender<Result<u64, Error>>,
    },
    /// Raw secured IM round-trip to `node_id` (typed verbs wrap this in M8.4).
    // Variant constructed in Node::round_trip (crate-internal). Task 4 wires the
    // handler; the #[allow] is removed when that code lands.
    #[allow(dead_code)]
    RoundTrip {
        node_id: u64,
        opcode: u8,
        protocol_id: matter_transport::ProtocolId,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Test/diagnostic: how many live cached sessions exist.
    #[cfg(test)]
    SessionCount { reply: oneshot::Sender<usize> },
}

/// A cached operational session to one device.
struct CachedSession {
    session_id: SessionId,
    peer: std::net::SocketAddr,
}

/// Owns all mutable state. Generic over transport + discovery so tests can
/// inject `InMemoryDatagram` + a mock `Discovery`.
pub(crate) struct Actor<T: AsyncDatagram, D: Discovery> {
    transport: T,
    discovery: D,
    sessions: SessionManager,
    store: Arc<dyn ControllerStore>,
    rng: Arc<dyn NocRng>,
    state: ControllerState,
    cache: HashMap<(u64, u64), CachedSession>, // (fabric_id, node_id) -> session
}

impl<T: AsyncDatagram, D: Discovery> Actor<T, D> {
    pub(crate) fn new(
        transport: T,
        discovery: D,
        store: Arc<dyn ControllerStore>,
        rng: Arc<dyn NocRng>,
        state: ControllerState,
    ) -> Self {
        Self {
            transport,
            discovery,
            sessions: SessionManager::new(),
            store,
            rng,
            state,
            cache: HashMap::new(),
        }
    }

    /// The task loop: process commands until all handles drop.
    pub(crate) async fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                Command::CreateFabric { cfg, reply } => {
                    let _ = reply.send(self.handle_create_fabric(&cfg));
                }
                Command::RoundTrip {
                    node_id,
                    opcode,
                    protocol_id,
                    payload,
                    reply,
                } => {
                    let _ = reply.send(
                        self.handle_round_trip(node_id, opcode, protocol_id, &payload)
                            .await,
                    );
                }
                #[cfg(test)]
                Command::SessionCount { reply } => {
                    let _ = reply.send(self.cache.len());
                }
            }
        }
    }

    fn handle_create_fabric(&mut self, cfg: &FabricConfig) -> Result<u64, Error> {
        let entry = crate::fabric::create_fabric(cfg, self.rng.as_ref())?;
        let fabric_id = entry.fabric_id;
        self.state.fabrics.push(entry);
        self.persist()?;
        Ok(fabric_id)
    }

    fn persist(&self) -> Result<(), Error> {
        let bytes = snapshot::serialize(&self.state)?;
        self.store.save(&bytes)?;
        Ok(())
    }

    /// The sole fabric, or an error if not exactly one (M8.2 is single-fabric;
    /// multi-fabric `fabric(id).node(id)` addressing is deferred).
    fn sole_fabric(&self) -> Result<&crate::state::FabricEntry, Error> {
        match self.state.fabrics.as_slice() {
            [one] => Ok(one),
            [] => Err(Error::NotCommissioned("no fabric created yet".into())),
            _ => Err(Error::NotCommissioned(
                "multiple fabrics; fabric(id).node(id) addressing is not in M8.2".into(),
            )),
        }
    }

    /// Establish a fresh CASE session to `node_id`, cache it, and record an
    /// address hint in persisted state. Resumption is dormant (M4.2): this
    /// always performs a full SIGMA handshake.
    async fn connect(&mut self, node_id: u64) -> Result<(SessionId, std::net::SocketAddr), Error> {
        let fabric_id = self.sole_fabric()?.fabric_id;
        let (credentials, roots, compressed) =
            crate::credentials::operational_credentials(self.sole_fabric()?)?;

        let peer = matter_commissioning::driver::resolve_operational(
            &mut self.discovery,
            compressed,
            node_id,
        )
        .await?;

        let sid = matter_commissioning::driver::run_case(
            &self.transport,
            &mut self.sessions,
            peer,
            credentials,
            roots,
            node_id,
            fabric_id,
        )
        .await?;

        self.upsert_device(fabric_id, node_id, peer);
        self.cache.insert(
            (fabric_id, node_id),
            CachedSession {
                session_id: sid,
                peer,
            },
        );
        Ok((sid, peer))
    }

    /// Record/refresh the device's last-known address in persisted state.
    /// The NOC public key stays unknown until M8.3 learns it during
    /// commissioning; this entry is an address/resumption cache only.
    fn upsert_device(&mut self, fabric_id: u64, node_id: u64, peer: std::net::SocketAddr) {
        let addr = peer.to_string();
        if let Some(fabric) = self
            .state
            .fabrics
            .iter_mut()
            .find(|f| f.fabric_id == fabric_id)
        {
            if let Some(dev) = fabric.devices.iter_mut().find(|d| d.node_id == node_id) {
                dev.last_known_addr = Some(addr);
            } else {
                fabric.devices.push(crate::state::DeviceEntry {
                    node_id,
                    peer_noc_public_key: [0u8; 65],
                    resumption_record: None,
                    last_known_addr: Some(addr),
                });
            }
        }
        // Address-hint persistence is best-effort; a write failure must not
        // abort an otherwise-successful connection.
        let _ = self.persist();
    }

    /// Send a secured IM payload, establishing/caching the session as needed.
    /// On a *cached*-session failure (e.g. the device evicted our session), the
    /// stale entry is dropped and the session re-established once before retry.
    async fn handle_round_trip(
        &mut self,
        node_id: u64,
        opcode: u8,
        protocol_id: matter_transport::ProtocolId,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let fabric_id = self.sole_fabric()?.fabric_id;

        if let Some((sid, peer)) = self
            .cache
            .get(&(fabric_id, node_id))
            .map(|c| (c.session_id, c.peer))
        {
            match self
                .round_trip_once(sid, peer, opcode, protocol_id, payload)
                .await
            {
                Ok(resp) => return Ok(resp),
                // Stale cached session — evict, re-establish once, retry.
                Err(Error::Driver(_)) => {
                    self.cache.remove(&(fabric_id, node_id));
                }
                Err(e) => return Err(e),
            }
        }

        let (sid, peer) = self.connect(node_id).await?;
        self.round_trip_once(sid, peer, opcode, protocol_id, payload)
            .await
    }

    async fn round_trip_once(
        &mut self,
        sid: SessionId,
        peer: std::net::SocketAddr,
        opcode: u8,
        protocol_id: matter_transport::ProtocolId,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let resp = matter_commissioning::driver::secured_round_trip(
            &self.transport,
            &mut self.sessions,
            sid,
            peer,
            opcode,
            protocol_id,
            payload,
        )
        .await?;
        Ok(resp.payload)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md allows unwrap/expect with justification.
mod tests {
    use super::*;
    use crate::fabric::FabricConfig;
    use crate::store::ControllerStore;
    use matter_cert::MatterTime;
    use matter_commissioning::driver::InMemoryDatagram;
    use matter_transport::{Discovery, MatterService, QueryHandle, ServiceKind};

    /// A discovery that finds nothing (sufficient for the `create_fabric` test).
    struct NullDiscovery;
    impl Discovery for NullDiscovery {
        fn publish(&mut self, _s: &MatterService) -> matter_transport::Result<()> {
            Ok(())
        }
        fn unpublish(&mut self, _n: &str, _k: ServiceKind) -> matter_transport::Result<()> {
            Ok(())
        }
        fn query(&mut self, _k: ServiceKind) -> matter_transport::Result<QueryHandle> {
            Ok(QueryHandle(0))
        }
        fn stop_query(&mut self, _h: QueryHandle) {}
        fn poll_results(&mut self, _h: QueryHandle) -> Vec<MatterService> {
            Vec::new()
        }
    }

    /// In-memory store for tests.
    #[derive(Default)]
    struct MemStore(std::sync::Mutex<Option<Vec<u8>>>);
    impl ControllerStore for MemStore {
        fn load(&self) -> Result<Option<Vec<u8>>, crate::store::StoreError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn save(&self, snapshot: &[u8]) -> Result<(), crate::store::StoreError> {
            *self.0.lock().unwrap() = Some(snapshot.to_vec());
            Ok(())
        }
    }

    fn cfg() -> FabricConfig {
        FabricConfig {
            fabric_id: 0xAABB_CCDD_0000_0001,
            rcac_id: 1,
            commissioner_node_id: 1,
            validity: (
                MatterTime::from_unix_secs(1_700_000_000),
                MatterTime::NO_EXPIRY,
            ),
        }
    }

    #[tokio::test]
    async fn create_fabric_persists_and_reopens() {
        let store = Arc::new(MemStore::default());
        let (io, _peer) = InMemoryDatagram::pair();
        let controller = crate::controller::MatterController::with_components(
            store.clone(),
            io,
            NullDiscovery,
            Arc::new(matter_commissioning::SystemNocRng),
        )
        .expect("open");

        let fid = controller
            .create_fabric(cfg())
            .await
            .expect("create_fabric");
        assert_eq!(fid, 0xAABB_CCDD_0000_0001);

        // The store now holds a snapshot that deserializes with one fabric.
        let bytes = store.load().expect("load").expect("snapshot present");
        let restored = crate::snapshot::deserialize(&bytes).expect("deserialize");
        assert_eq!(restored.fabrics.len(), 1);
        assert_eq!(restored.fabrics[0].commissioner.node_id, 1);
    }
}
