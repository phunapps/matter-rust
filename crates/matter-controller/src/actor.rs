//! The owning controller task. Holds the transport, `SessionManager`,
//! discovery, and `ControllerState`. Processes [`Command`]s; while any
//! subscription is active it also listens for unsolicited reports.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use matter_commissioning::driver::AsyncDatagram;
use matter_commissioning::NocRng;
use matter_transport::{
    DecodeInboundOutput, Discovery, MrpEvent, MrpFlags, ProtocolId, SessionId, SessionManager,
};
use tokio::sync::{mpsc, oneshot};

use crate::error::Error;
use crate::fabric::FabricConfig;
use crate::snapshot;
use crate::state::ControllerState;
use crate::store::ControllerStore;
use crate::subscription::AttributeReport;

/// IM opcodes used by the subscription flow.
const OP_SUBSCRIBE_REQUEST: u8 = 0x03;
const OP_SUBSCRIBE_RESPONSE: u8 = 0x04;
const OP_REPORT_DATA: u8 = 0x05;
const OP_STATUS_RESPONSE: u8 = 0x01;

/// How often the loop wakes to drive MRP / liveness when no MRP deadline is
/// pending and subscriptions are active.
const LIVENESS_TICK: std::time::Duration = std::time::Duration::from_millis(250);

/// Per-subscription routing state held by the actor.
struct SubEntry {
    /// Channel to the consumer's [`Subscription`].
    tx: mpsc::Sender<AttributeReport>,
    /// Operational peer address (for `StatusResponse` acks).
    peer: SocketAddr,
}

/// What `handle_subscribe` returns to `Node::subscribe`: the report receiver
/// and the `(session, exchange)` key (the `Node` adds the command sender to
/// build the public [`Subscription`]).
pub(crate) type SubEstablished = (mpsc::Receiver<AttributeReport>, (SessionId, u16));

/// Messages the handles send to the owning task. Each carries a `oneshot`
/// reply sender; a dropped reply sender means the caller gave up.
pub(crate) enum Command {
    CreateFabric {
        cfg: FabricConfig,
        reply: oneshot::Sender<Result<u64, Error>>,
    },
    /// Raw secured IM round-trip to `node_id`. Constructed by the crate-internal
    /// `Node::round_trip`, which the typed `read`/`write`/`invoke` verbs wrap.
    RoundTrip {
        node_id: u64,
        opcode: u8,
        protocol_id: matter_transport::ProtocolId,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Chunked secured read to `node_id` — returns every `ReportData` chunk
    /// payload in order (the `Node` reassembles them via `ReportAccumulator`).
    /// Used by `Node::read`; a non-chunked read yields a single-element `Vec`.
    Read {
        node_id: u64,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<Vec<u8>>, Error>>,
    },
    /// Commission a device from a parsed setup payload; returns its node id.
    Commission {
        setup_payload: matter_commissioning::SetupPayload,
        reply: oneshot::Sender<Result<u64, Error>>,
    },
    /// Establish a subscription to `paths` on `node_id`; returns the report
    /// receiver + `(session, exchange)` key for the `Node` to wrap.
    Subscribe {
        node_id: u64,
        paths: Vec<matter_interaction::ReadPath>,
        min_interval: u16,
        max_interval: u16,
        reply: oneshot::Sender<Result<SubEstablished, Error>>,
    },
    /// Cancel the subscription identified by its `(session, exchange)` key.
    CancelSubscription { key: (SessionId, u16) },
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
    trust: Option<crate::trust::AttestationTrust>,
    admin_vendor_id: u16,
    /// Active subscriptions, keyed by `(session, exchange)`. While non-empty,
    /// the run loop listens for unsolicited steady-state reports.
    subscriptions: HashMap<(SessionId, u16), SubEntry>,
}

impl<T: AsyncDatagram, D: Discovery> Actor<T, D> {
    pub(crate) fn new(
        transport: T,
        discovery: D,
        store: Arc<dyn ControllerStore>,
        rng: Arc<dyn NocRng>,
        state: ControllerState,
        trust: Option<crate::trust::AttestationTrust>,
        admin_vendor_id: u16,
    ) -> Self {
        Self {
            transport,
            discovery,
            sessions: SessionManager::new(),
            store,
            rng,
            state,
            cache: HashMap::new(),
            trust,
            admin_vendor_id,
            subscriptions: HashMap::new(),
        }
    }

    /// The task loop. With no active subscription it simply awaits commands
    /// (recv is owned only inside a command's `secured_round_trip`), so the
    /// round-trip / read / commission paths are byte-for-byte unchanged. While
    /// any subscription is active it also listens for unsolicited steady-state
    /// reports and drives MRP, between command handlers — recv is never owned
    /// concurrently (a command handler runs to completion first).
    ///
    /// KNOWN LIMITATION: a steady-state `ReportData` that arrives *while* a
    /// concurrent round-trip owns recv inside `secured_round_trip` is consumed
    /// there (counter recorded in the replay window) and discarded; on the
    /// device's retransmit it is recognised as a duplicate and re-acked, so the
    /// device stops resending — but that report's *value* is not delivered to
    /// the consumer. This bounded silent-loss window only exists when the caller
    /// issues round-trips on a node it is concurrently subscribed to (a pure
    /// subscription stream loses nothing). A full fix routes off-exchange
    /// subscription reports out of `secured_round_trip` (deferred with
    /// auto-resubscribe to the subscription-hardening follow-up).
    pub(crate) async fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        loop {
            if self.subscriptions.is_empty() {
                match rx.recv().await {
                    Some(cmd) => self.dispatch(cmd).await,
                    None => return,
                }
            } else {
                let now = Instant::now();
                let sleep_for = self
                    .sessions
                    .poll_timeout()
                    .map_or(LIVENESS_TICK, |d| d.saturating_duration_since(now));
                tokio::select! {
                    biased;
                    maybe = rx.recv() => match maybe {
                        Some(cmd) => self.dispatch(cmd).await,
                        None => return,
                    },
                    recv = self.transport.recv_from() => {
                        if let Ok((packet, from)) = recv {
                            self.demux_subscription_inbound(&packet, from).await;
                        }
                    }
                    () = tokio::time::sleep(sleep_for) => {
                        self.drive_subscription_mrp().await;
                    }
                }
            }
        }
    }

    /// Process one command.
    async fn dispatch(&mut self, cmd: Command) {
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
            Command::Read {
                node_id,
                payload,
                reply,
            } => {
                let _ = reply.send(self.handle_read(node_id, &payload).await);
            }
            Command::Commission {
                setup_payload,
                reply,
            } => {
                let _ = reply.send(self.handle_commission(setup_payload).await);
            }
            Command::Subscribe {
                node_id,
                paths,
                min_interval,
                max_interval,
                reply,
            } => {
                let _ = reply.send(
                    self.handle_subscribe(node_id, &paths, min_interval, max_interval)
                        .await,
                );
            }
            Command::CancelSubscription { key } => {
                self.subscriptions.remove(&key);
            }
            #[cfg(test)]
            Command::SessionCount { reply } => {
                let _ = reply.send(self.cache.len());
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

    /// Commission a device onto the sole fabric and persist a `DeviceEntry`.
    async fn handle_commission(
        &mut self,
        setup_payload: matter_commissioning::SetupPayload,
    ) -> Result<u64, Error> {
        use matter_commissioning::driver::{commission, DriverConfig};
        use matter_commissioning::CommissionerConfig;

        // Bind trust + admin_vendor_id from disjoint fields before the borrow
        // of self.sole_fabric() below. Binding them here keeps the lifetimes
        // clean: `trust` borrows only `self.trust`, which is disjoint from
        // `self.transport` and `self.discovery` used in commission().
        let trust = self.trust.as_ref().ok_or(Error::NoTrust)?;
        let admin_vendor_id = self.admin_vendor_id;

        // Snapshot what we need from the sole fabric into owned locals so we
        // don't hold a borrow of `self` across the commission() call (which
        // needs `&self.transport` + `&mut self.discovery`).
        let (
            fabric_record,
            fabric_id,
            commissioner_node_id,
            ipk_epoch_key,
            commissioner_noc,
            commissioner_pkcs8,
            assigned_node_id,
        ) = {
            let fabric = self.sole_fabric()?;
            (
                fabric.to_fabric_record()?,
                fabric.fabric_id,
                fabric.commissioner.node_id,
                fabric.ipk,
                fabric.commissioner.noc.clone(),
                fabric.commissioner.operational_pkcs8.clone(),
                crate::commission::next_device_node_id(fabric),
            )
        };

        let now = current_matter_time()?;
        let rng: std::sync::Arc<dyn matter_commissioning::NocRng> = self.rng.clone();

        let commissioner = CommissionerConfig {
            pase_attestation_challenge: [0u8; 16], // commission() overwrites from live PASE
            fabric: &fabric_record,
            setup_payload: &setup_payload,
            paa_trust_store: &trust.paa,
            cd_signing_roots: &trust.cd,
            commissioner_node_id,
            assigned_node_id,
            ipk_epoch_key,
            case_admin_subject: commissioner_node_id,
            admin_vendor_id,
            now,
            rng,
            wifi_credentials: None,
        };
        let config = DriverConfig {
            commissioner,
            commissionable_addr: None, // discover via mDNS using the discriminator
            passcode: setup_payload.passcode.as_u32(),
            commissioner_noc: &commissioner_noc,
            commissioner_signer_pkcs8: &commissioner_pkcs8,
        };

        let result = commission(&self.transport, &mut self.discovery, config).await?;

        // Persist the device.
        let device = crate::commission::device_entry_from_commissioned(&result);
        let node_id = device.node_id;
        if let Some(fabric) = self
            .state
            .fabrics
            .iter_mut()
            .find(|f| f.fabric_id == fabric_id)
        {
            fabric.devices.push(device);
        }
        self.persist()?;
        Ok(node_id)
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

    /// Chunked read with the same connect-on-demand + reconnect-once policy as
    /// [`handle_round_trip`](Self::handle_round_trip): try the cached session,
    /// drop it and reconnect once on a driver error, else connect fresh.
    async fn handle_read(&mut self, node_id: u64, payload: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let fabric_id = self.sole_fabric()?.fabric_id;

        if let Some((sid, peer)) = self
            .cache
            .get(&(fabric_id, node_id))
            .map(|c| (c.session_id, c.peer))
        {
            match self.read_once(sid, peer, payload).await {
                Ok(resp) => return Ok(resp),
                // Stale cached session — evict, re-establish once, retry.
                Err(Error::Driver(_)) => {
                    self.cache.remove(&(fabric_id, node_id));
                }
                Err(e) => return Err(e),
            }
        }

        let (sid, peer) = self.connect(node_id).await?;
        self.read_once(sid, peer, payload).await
    }

    /// One `secured_read` (chunked read transaction) over an established session.
    async fn read_once(
        &mut self,
        sid: SessionId,
        peer: std::net::SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, Error> {
        let chunks = matter_commissioning::driver::secured_read(
            &self.transport,
            &mut self.sessions,
            sid,
            peer,
            crate::node::OP_READ_REQUEST,
            matter_transport::ProtocolId::INTERACTION_MODEL,
            payload,
        )
        .await?;
        Ok(chunks)
    }

    /// Establish a subscription: send a `SubscribeRequest`, absorb the priming
    /// `ReportData`(s) (forwarding their attributes + acking), and register the
    /// subscription on the `SubscribeResponse`. Steady-state reports then arrive
    /// via the run loop's `demux_subscription_inbound`.
    async fn handle_subscribe(
        &mut self,
        node_id: u64,
        paths: &[matter_interaction::ReadPath],
        min_interval: u16,
        max_interval: u16,
    ) -> Result<SubEstablished, Error> {
        let fabric_id = self.sole_fabric()?.fabric_id;
        let (sid, peer) = match self.cache.get(&(fabric_id, node_id)) {
            Some(c) => (c.session_id, c.peer),
            None => self.connect(node_id).await?,
        };

        let req =
            matter_interaction::build_subscribe_request(&matter_interaction::SubscribeRequest {
                keep_subscriptions: false,
                min_interval_floor: min_interval,
                max_interval_ceiling: max_interval,
                paths: paths.to_vec(),
            });
        let out = self.sessions.encode_outbound(
            sid,
            None,
            OP_SUBSCRIBE_REQUEST,
            ProtocolId::INTERACTION_MODEL,
            &req,
            MrpFlags { reliable: true },
            Instant::now(),
        )?;
        let exchange = out.exchange_id;
        self.transport
            .send_to(&out.wire_bytes, peer)
            .await
            .map_err(|e| Error::Operational(format!("subscribe send: {e}")))?;

        let (tx, rx) = mpsc::channel::<AttributeReport>(64);

        // Bounded handshake: collect priming reports + ack them until the
        // SubscribeResponse arrives (or MRP gives up).
        loop {
            let now = Instant::now();
            let sleep_for = self
                .sessions
                .poll_timeout()
                .map_or(LIVENESS_TICK, |d| d.saturating_duration_since(now));
            tokio::select! {
                biased;
                recv = self.transport.recv_from() => {
                    let (packet, _from) = recv.map_err(|e| Error::Operational(format!("subscribe recv: {e}")))?;
                    if packet.len() >= 3 && packet[1] == 0 && packet[2] == 0 {
                        continue;
                    }
                    let decoded = match self.sessions.decode_inbound(&packet, Instant::now()) {
                        Ok(d) => d,
                        Err(matter_transport::Error::UnknownSession(_) | matter_transport::Error::DecryptionFailed) => continue,
                        Err(e) => return Err(Error::Operational(format!("subscribe decode: {e}"))),
                    };
                    match decoded {
                        DecodeInboundOutput::AppMessage { session_id, exchange_id, opcode, payload, .. }
                            if exchange_id == exchange =>
                        {
                            if opcode == OP_REPORT_DATA {
                                Self::forward_report(&payload, &tx);
                                self.send_status_ack(session_id, exchange_id, peer).await?;
                            } else if opcode == OP_SUBSCRIBE_RESPONSE {
                                self.subscriptions.insert((session_id, exchange_id), SubEntry { tx, peer });
                                return Ok((rx, (session_id, exchange_id)));
                            }
                        }
                        DecodeInboundOutput::AppMessage { .. } | DecodeInboundOutput::AckOnly { .. } => {}
                        DecodeInboundOutput::DuplicateReliableAckResent { ack_packet, .. } => {
                            let _ = self.transport.send_to(&ack_packet, peer).await;
                        }
                    }
                }
                () = tokio::time::sleep(sleep_for) => {
                    for event in self.sessions.handle_timeout(Instant::now()) {
                        match event {
                            MrpEvent::Retransmit { packet, .. } | MrpEvent::SendStandaloneAck { packet, .. } => {
                                let _ = self.transport.send_to(&packet, peer).await;
                            }
                            MrpEvent::Expired { .. } => {
                                return Err(Error::Operational("subscribe handshake timed out".into()));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Parse a `ReportData` payload and push each attribute to the subscription.
    ///
    // TODO(CR.3 subscription chunking): this forwards only `rd.attributes`
    // (Replace-only, single message). A chunked or list-append subscription
    // report (`more_chunked_messages` / `ReportOp::Append`) loses data here —
    // it must be reassembled through `matter_interaction::ReportAccumulator`
    // across the chunk sequence before forwarding. Tracked as the CR.3 / the
    // subscription-hardening follow-up.
    fn forward_report(payload: &[u8], tx: &mpsc::Sender<AttributeReport>) {
        if let Ok(rd) = matter_interaction::parse_report_data(payload) {
            for (path, value) in rd.attributes {
                let _ = tx.try_send(AttributeReport { path, value });
            }
        }
    }

    /// Send an application `StatusResponse(Success)` on a subscription exchange
    /// (also piggybacks the MRP ack for the received report).
    async fn send_status_ack(
        &mut self,
        sid: SessionId,
        exchange: u16,
        peer: SocketAddr,
    ) -> Result<(), Error> {
        let status = matter_interaction::build_status_response(0);
        let out = self.sessions.encode_outbound(
            sid,
            Some(exchange),
            OP_STATUS_RESPONSE,
            ProtocolId::INTERACTION_MODEL,
            &status,
            MrpFlags { reliable: false },
            Instant::now(),
        )?;
        self.transport
            .send_to(&out.wire_bytes, peer)
            .await
            .map_err(|e| Error::Operational(format!("status ack send: {e}")))?;
        Ok(())
    }

    /// Route an unsolicited inbound packet: a steady-state `ReportData` on a
    /// known subscription exchange is forwarded + acked; everything else is
    /// skipped.
    async fn demux_subscription_inbound(&mut self, packet: &[u8], from: SocketAddr) {
        if packet.len() >= 3 && packet[1] == 0 && packet[2] == 0 {
            return;
        }
        let Ok(decoded) = self.sessions.decode_inbound(packet, Instant::now()) else {
            return;
        };
        match decoded {
            DecodeInboundOutput::AppMessage {
                session_id,
                exchange_id,
                opcode,
                payload,
                ..
            } => {
                if opcode == OP_REPORT_DATA {
                    if let Some(entry) = self.subscriptions.get(&(session_id, exchange_id)) {
                        let tx = entry.tx.clone();
                        let peer = entry.peer;
                        Self::forward_report(&payload, &tx);
                        let _ = self.send_status_ack(session_id, exchange_id, peer).await;
                    }
                }
            }
            DecodeInboundOutput::AckOnly { .. } => {}
            DecodeInboundOutput::DuplicateReliableAckResent { ack_packet, .. } => {
                let _ = self.transport.send_to(&ack_packet, from).await;
            }
        }
    }

    /// Drive MRP retransmits/acks for active subscription sessions.
    async fn drive_subscription_mrp(&mut self) {
        for event in self.sessions.handle_timeout(Instant::now()) {
            match event {
                MrpEvent::Retransmit {
                    session_id, packet, ..
                }
                | MrpEvent::SendStandaloneAck {
                    session_id, packet, ..
                } => {
                    if let Some(peer) = self.peer_for_session(session_id) {
                        let _ = self.transport.send_to(&packet, peer).await;
                    }
                }
                MrpEvent::Expired { .. } => {}
            }
        }
    }

    /// The peer address of any active subscription on `sid`.
    fn peer_for_session(&self, sid: SessionId) -> Option<SocketAddr> {
        self.subscriptions
            .iter()
            .find(|((s, _), _)| *s == sid)
            .map(|(_, e)| e.peer)
    }
}

/// Convert the current wall-clock time to a [`matter_cert::MatterTime`] for use
/// in `CommissionerConfig.now`.
///
/// # Errors
///
/// Returns [`Error::Operational`] if the system clock is before the Unix epoch
/// (extremely unlikely in practice).
fn current_matter_time() -> Result<matter_cert::MatterTime, Error> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Operational(format!("clock: {e}")))?
        .as_secs();
    Ok(matter_cert::MatterTime::from_unix_secs(secs))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md allows unwrap/expect with justification.
mod tests {
    use super::*;
    use crate::fabric::FabricConfig;
    use crate::store::ControllerStore;
    use matter_cert::{MatterTime, TrustAnchor, TrustedRoots};
    use matter_commissioning::driver::{
        decode_unsecured, encode_unsecured, operational_instance_name, InMemoryDatagram,
    };
    use matter_commissioning::{issue_noc, SystemNocRng, VerifiedCsr};
    use matter_crypto::{
        derive_compressed_fabric_id, derive_operational_ipk, CaseCredentials, CaseResponder,
        RingSigner, Sigma1Outcome, Signer,
    };
    use matter_transport::{
        DecodeInboundOutput, Discovery, MatterService, MrpFlags, ProtocolId, QueryHandle,
        ServiceKind, SessionManager, SessionRole,
    };
    use std::time::Instant;

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
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
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

    // --- loopback acceptance test (CaseResponder over InMemoryDatagram) ---

    /// Discovery that always resolves the one operational node to `addr`.
    struct FixedDiscovery {
        addr: std::net::SocketAddr,
        instance_name: String,
    }
    impl Discovery for FixedDiscovery {
        fn publish(&mut self, _s: &MatterService) -> matter_transport::Result<()> {
            Ok(())
        }
        fn unpublish(&mut self, _n: &str, _k: ServiceKind) -> matter_transport::Result<()> {
            Ok(())
        }
        fn query(&mut self, _k: ServiceKind) -> matter_transport::Result<QueryHandle> {
            Ok(QueryHandle(1))
        }
        fn stop_query(&mut self, _h: QueryHandle) {}
        fn poll_results(&mut self, _h: QueryHandle) -> Vec<MatterService> {
            vec![MatterService {
                instance_name: self.instance_name.clone(),
                kind: ServiceKind::Operational,
                addresses: vec![self.addr.ip()],
                port: self.addr.port(),
                txt_records: std::collections::HashMap::new(),
            }]
        }
    }

    /// Device side: complete the CASE handshake (unsecured Sigma framing,
    /// mirroring `matter-commissioning`'s `run_case` loopback test), then
    /// answer `echoes` secured IM round-trips with a `b"pong"` `ReportData`.
    /// Build a minimal `ReportDataMessage` carrying one attribute
    /// `(ep, cl, at) = value`. Mirrors the exact TLV structure
    /// `matter-interaction`'s `parse_report_data` expects (see its
    /// `parses_single_attribute_value` test).
    fn build_report_data(ep: u16, cl: u32, at: u32, value: &matter_codec::Value) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap(); // ReportDataMessage
        w.start_array(Tag::Context(1)).unwrap(); // AttributeReports
        w.start_structure(Tag::Anonymous).unwrap(); // AttributeReportIB
        w.start_structure(Tag::Context(1)).unwrap(); // AttributeData
        w.start_list(Tag::Context(1)).unwrap(); // Path (AttributePathIB)
        w.put_uint(Tag::Context(2), u64::from(ep)).unwrap();
        w.put_uint(Tag::Context(3), u64::from(cl)).unwrap();
        w.put_uint(Tag::Context(4), u64::from(at)).unwrap();
        w.end_container().unwrap(); // /Path
        w.write_value(Tag::Context(2), value).unwrap(); // Data
        w.end_container().unwrap(); // /AttributeData
        w.end_container().unwrap(); // /AttributeReportIB
        w.end_container().unwrap(); // /AttributeReports
        w.put_uint(Tag::Context(0xFF), 11).unwrap(); // interactionModelRevision
        w.end_container().unwrap(); // /ReportDataMessage
        buf
    }

    /// Like [`build_report_data`] but sets `MoreChunkedMessages` (context tag 3)
    /// when `more` — i.e. a non-final chunk that must be acked + continued.
    fn build_report_data_chunk(
        ep: u16,
        cl: u32,
        at: u32,
        value: &matter_codec::Value,
        more: bool,
    ) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(1)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_structure(Tag::Context(1)).unwrap();
        w.start_list(Tag::Context(1)).unwrap();
        w.put_uint(Tag::Context(2), u64::from(ep)).unwrap();
        w.put_uint(Tag::Context(3), u64::from(cl)).unwrap();
        w.put_uint(Tag::Context(4), u64::from(at)).unwrap();
        w.end_container().unwrap();
        w.write_value(Tag::Context(2), value).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap(); // /AttributeReports
        if more {
            w.put_bool(Tag::Context(3), true).unwrap(); // MoreChunkedMessages
        }
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();
        buf
    }

    /// Loopback device that completes CASE, then answers ONE `Node::read` with a
    /// two-chunk `ReportData` sequence: chunk 0 (`MoreChunkedMessages=true`),
    /// then — after the controller's `StatusResponse` ack — the final chunk.
    async fn run_chunked_read_device(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        chunk0: Vec<u8>,
        chunk1: Vec<u8>,
    ) {
        let mut responder = CaseResponder::new(creds, roots, responder_session_id).unwrap();

        // --- CASE handshake (identical to run_loopback_device) ---
        let (p, _) = io.recv_from().await.unwrap();
        let m = decode_unsecured(&p).unwrap();
        assert!(matches!(
            responder.handle_sigma1(&m.payload).unwrap(),
            Sigma1Outcome::NewSession
        ));
        let sigma2 = responder.next_message().unwrap();
        let wire = encode_unsecured(
            200,
            m.exchange_id,
            0x31,
            ProtocolId::SECURE_CHANNEL,
            false,
            true,
            Some(m.message_counter),
            None,
            &sigma2,
        );
        io.send_to(&wire, ctrl_addr).await.unwrap();

        let (p, _) = io.recv_from().await.unwrap();
        let m = decode_unsecured(&p).unwrap();
        responder.handle_sigma3(&m.payload).unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        let report = encode_unsecured(
            201,
            m.exchange_id,
            0x40,
            ProtocolId::SECURE_CHANNEL,
            false,
            true,
            Some(m.message_counter),
            None,
            &body,
        );
        io.send_to(&report, ctrl_addr).await.unwrap();
        let _ack = io.recv_from().await.unwrap();
        let output = responder.finish().unwrap();

        // --- Chunked read transaction ---
        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);

        // 1. Receive the ReadRequest.
        let (wire, _) = io.recv_from().await.unwrap();
        let DecodeInboundOutput::AppMessage { exchange_id, .. } =
            sessions.decode_inbound(&wire, Instant::now()).unwrap()
        else {
            panic!("expected ReadRequest");
        };
        // 2. Send chunk 0 (MoreChunkedMessages=true), reliably.
        let out = sessions
            .encode_outbound(
                sid,
                Some(exchange_id),
                0x05,
                ProtocolId::INTERACTION_MODEL,
                &chunk0,
                MrpFlags { reliable: true },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        // 3. Receive the controller's StatusResponse ack (opcode 0x01).
        let (ack, _) = io.recv_from().await.unwrap();
        let DecodeInboundOutput::AppMessage { opcode, .. } =
            sessions.decode_inbound(&ack, Instant::now()).unwrap()
        else {
            panic!("expected StatusResponse ack");
        };
        assert_eq!(opcode, 0x01, "controller must ack the chunk");
        // 4. Send the final chunk.
        let out = sessions
            .encode_outbound(
                sid,
                Some(exchange_id),
                0x05,
                ProtocolId::INTERACTION_MODEL,
                &chunk1,
                MrpFlags { reliable: true },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
    }

    /// Loopback device: completes CASE, then replies to each secured IM request
    /// with `reply_payload` (opcode 0x05). Pass `b"pong"` for a raw-round-trip
    /// echo, or a `build_report_data` blob to answer a `Node::read`.
    async fn run_loopback_device(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        echoes: usize,
        reply_payload: Vec<u8>,
    ) {
        let mut responder = CaseResponder::new(creds, roots, responder_session_id).unwrap();

        // Sigma1 -> Sigma2
        let (p, _) = io.recv_from().await.unwrap();
        let m = decode_unsecured(&p).unwrap();
        assert!(matches!(
            responder.handle_sigma1(&m.payload).unwrap(),
            Sigma1Outcome::NewSession
        ));
        let sigma2 = responder.next_message().unwrap();
        let wire = encode_unsecured(
            200,
            m.exchange_id,
            0x31, // Sigma2
            ProtocolId::SECURE_CHANNEL,
            false,
            true,
            Some(m.message_counter),
            None,
            &sigma2,
        );
        io.send_to(&wire, ctrl_addr).await.unwrap();

        // Sigma3 -> success StatusReport, then absorb the controller's ack.
        let (p, _) = io.recv_from().await.unwrap();
        let m = decode_unsecured(&p).unwrap();
        responder.handle_sigma3(&m.payload).unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes()); // general code: success
        body.extend_from_slice(&0u32.to_le_bytes()); // protocol id
        body.extend_from_slice(&0u16.to_le_bytes()); // protocol code
        let report = encode_unsecured(
            201,
            m.exchange_id,
            0x40, // StatusReport
            ProtocolId::SECURE_CHANNEL,
            false,
            true,
            Some(m.message_counter),
            None,
            &body,
        );
        io.send_to(&report, ctrl_addr).await.unwrap();
        let _ack = io.recv_from().await.unwrap(); // controller's standalone ack

        let output = responder.finish().unwrap();

        // Secured IM echo: register the session, then reply to each request.
        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);
        for _ in 0..echoes {
            let (wire, _) = io.recv_from().await.unwrap();
            let decoded = sessions.decode_inbound(&wire, Instant::now()).unwrap();
            let DecodeInboundOutput::AppMessage { exchange_id, .. } = decoded else {
                panic!("expected an IM request app message");
            };
            // Reply on the same exchange; this piggybacks the ack for the
            // controller's reliable request. The reply itself is unreliable so
            // the device need not await an ack back.
            let out = sessions
                .encode_outbound(
                    sid,
                    Some(exchange_id),
                    0x05, // ReportData
                    ProtocolId::INTERACTION_MODEL,
                    &reply_payload,
                    MrpFlags { reliable: false },
                    Instant::now(),
                )
                .unwrap();
            io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        }
    }

    /// Build a `SubscribeResponse` TLV (device side): ctx0=subscriptionId,
    /// ctx2=maxInterval, ctx0xFF=revision — matching `parse_subscribe_response`.
    fn build_subscribe_response(subscription_id: u32, max_interval: u16) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), u64::from(subscription_id))
            .unwrap();
        w.put_uint(Tag::Context(2), u64::from(max_interval))
            .unwrap();
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();
        buf
    }

    /// Device acting as a subscription source: completes CASE, answers a
    /// `SubscribeRequest` with a `SubscribeResponse`, then sends `num_reports`
    /// steady-state `ReportData` frames (OnOff.OnOff(ep1)=true) on the
    /// subscription exchange.
    async fn run_subscription_device(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        num_reports: usize,
    ) {
        let mut responder = CaseResponder::new(creds, roots, responder_session_id).unwrap();
        // Sigma1 -> Sigma2
        let (p, _) = io.recv_from().await.unwrap();
        let m = decode_unsecured(&p).unwrap();
        assert!(matches!(
            responder.handle_sigma1(&m.payload).unwrap(),
            Sigma1Outcome::NewSession
        ));
        let sigma2 = responder.next_message().unwrap();
        let wire = encode_unsecured(
            200,
            m.exchange_id,
            0x31,
            ProtocolId::SECURE_CHANNEL,
            false,
            true,
            Some(m.message_counter),
            None,
            &sigma2,
        );
        io.send_to(&wire, ctrl_addr).await.unwrap();
        // Sigma3 -> success StatusReport, absorb the ack.
        let (p, _) = io.recv_from().await.unwrap();
        let m = decode_unsecured(&p).unwrap();
        responder.handle_sigma3(&m.payload).unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        let report = encode_unsecured(
            201,
            m.exchange_id,
            0x40,
            ProtocolId::SECURE_CHANNEL,
            false,
            true,
            Some(m.message_counter),
            None,
            &body,
        );
        io.send_to(&report, ctrl_addr).await.unwrap();
        let _ack = io.recv_from().await.unwrap();
        let output = responder.finish().unwrap();

        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);

        // Receive the SubscribeRequest; reply with SubscribeResponse (the
        // reply piggybacks the request's MRP ack).
        let (wire, _) = io.recv_from().await.unwrap();
        let decoded = sessions.decode_inbound(&wire, Instant::now()).unwrap();
        let DecodeInboundOutput::AppMessage {
            exchange_id,
            opcode,
            ..
        } = decoded
        else {
            panic!("expected SubscribeRequest");
        };
        assert_eq!(opcode, 0x03, "expected SubscribeRequest opcode");
        let sub_resp = build_subscribe_response(0x1234_5678, 30);
        let out = sessions
            .encode_outbound(
                sid,
                Some(exchange_id),
                0x04,
                ProtocolId::INTERACTION_MODEL,
                &sub_resp,
                MrpFlags { reliable: false },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();

        // Stream steady-state reports on the same exchange; drain the
        // controller's StatusResponse acks between sends.
        let report_blob = build_report_data(1, 0x06, 0x0000, &matter_codec::Value::Bool(true));
        for _ in 0..num_reports {
            let out = sessions
                .encode_outbound(
                    sid,
                    Some(exchange_id),
                    0x05,
                    ProtocolId::INTERACTION_MODEL,
                    &report_blob,
                    MrpFlags { reliable: false },
                    Instant::now(),
                )
                .unwrap();
            io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(100), io.recv_from()).await;
        }
    }

    /// Shared loopback setup: one fabric in the store, a device NOC under its
    /// RCAC, a paired datagram, and a discovery pinned to the device end.
    struct Harness {
        store: Arc<MemStore>,
        ctrl_io: InMemoryDatagram,
        dev_io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        discovery: FixedDiscovery,
        device_creds: CaseCredentials,
        device_roots: TrustedRoots,
        device_node_id: u64,
    }

    fn loopback_harness() -> Harness {
        let fabric = {
            let cfg = FabricConfig {
                fabric_id: 0x0102_0304_0506_0708,
                rcac_id: 1,
                commissioner_node_id: 1,
                validity: (
                    MatterTime::from_unix_secs(1_700_000_000),
                    MatterTime::NO_EXPIRY,
                ),
            };
            crate::fabric::create_fabric(&cfg, &SystemNocRng).unwrap()
        };
        let device_node_id: u64 = 0x0000_0000_0000_0042;

        let device_record = fabric.to_fabric_record().unwrap();
        let (device_signer, _pkcs8) = RingSigner::generate().unwrap();
        let device_noc = issue_noc(
            &device_record,
            &VerifiedCsr {
                public_key: device_signer.public_key().clone(),
            },
            device_node_id,
            &[],
            (
                MatterTime::from_unix_secs(1_700_000_000),
                MatterTime::NO_EXPIRY,
            ),
            &SystemNocRng,
        )
        .unwrap();
        let compressed =
            derive_compressed_fabric_id(fabric.rcac_cert.public_key().as_bytes(), fabric.fabric_id)
                .unwrap();
        let device_ipk = derive_operational_ipk(&fabric.ipk, &compressed).unwrap();
        let mut device_roots = TrustedRoots::new();
        device_roots.add(TrustAnchor::from_root_cert(&fabric.rcac_cert));
        let device_creds = CaseCredentials {
            noc: device_noc,
            icac: None,
            signer: Box::new(device_signer),
            fabric_id: fabric.fabric_id,
            node_id: device_node_id,
            ipk: device_ipk,
            rcac_public_key: *fabric.rcac_cert.public_key().as_bytes(),
        };

        let store = Arc::new(MemStore::default());
        store
            .save(
                &crate::snapshot::serialize(&ControllerState {
                    fabrics: vec![fabric],
                })
                .unwrap(),
            )
            .unwrap();
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let ctrl_addr = ctrl_io.local_addr();
        let dev_addr = dev_io.local_addr();
        let discovery = FixedDiscovery {
            addr: dev_addr,
            instance_name: operational_instance_name(compressed, device_node_id),
        };

        Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr,
            discovery,
            device_creds,
            device_roots,
            device_node_id,
        }
    }

    #[tokio::test]
    async fn connects_caches_and_round_trips_over_loopback() {
        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr,
            discovery,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D2,
            2,
            b"pong".to_vec(),
        ));

        let controller = crate::controller::MatterController::with_components(
            store,
            ctrl_io,
            discovery,
            Arc::new(SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        // First round-trip establishes + caches the session.
        let node = controller.node(device_node_id);
        let resp1 = node
            .round_trip(0x02, ProtocolId::INTERACTION_MODEL, b"ping".to_vec())
            .await
            .expect("first round-trip");
        assert_eq!(resp1, b"pong");
        assert_eq!(controller.session_count().await, 1, "session cached");

        // Second round-trip reuses the cached session (no new handshake).
        let resp2 = node
            .round_trip(0x02, ProtocolId::INTERACTION_MODEL, b"ping".to_vec())
            .await
            .expect("second round-trip");
        assert_eq!(resp2, b"pong");
        assert_eq!(
            controller.session_count().await,
            1,
            "still one session — reused, not re-established"
        );

        device.await.unwrap();
    }

    #[tokio::test]
    async fn read_verb_returns_report_data_over_loopback() {
        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr,
            discovery,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        // The device answers the one read with a ReportData carrying
        // OnOff.OnOff(ep 1) = true.
        let report_blob = build_report_data(1, 0x06, 0x0000, &matter_codec::Value::Bool(true));
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D2,
            1,
            report_blob,
        ));

        let controller = crate::controller::MatterController::with_components(
            store,
            ctrl_io,
            discovery,
            Arc::new(SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        let node = controller.node(device_node_id);
        let report = node
            .read(&[matter_interaction::ReadPath::concrete(1, 0x06, 0x0000)])
            .await
            .expect("read");

        assert_eq!(report.len(), 1);
        let (path, value) = &report[0];
        assert_eq!(path.endpoint, 1);
        assert_eq!(path.cluster, 0x06);
        assert_eq!(path.attribute, 0x0000);
        assert_eq!(*value, matter_codec::Value::Bool(true));

        device.await.unwrap();
    }

    #[tokio::test]
    async fn read_reassembles_chunked_report_over_loopback() {
        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr,
            discovery,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        // Wildcard read answered in two chunks: chunk 0 = ep0/BasicInfo.VendorID
        // (MoreChunkedMessages=true), final chunk = ep1/OnOff.OnOff. Reassembly
        // must surface BOTH — the real-device truncation this whole follow-up fixes.
        let chunk0 = build_report_data_chunk(0, 0x28, 0x0002, &matter_codec::Value::Uint(5010), true);
        let chunk1 = build_report_data_chunk(1, 0x06, 0x0000, &matter_codec::Value::Bool(true), false);
        let device = tokio::spawn(run_chunked_read_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D2,
            chunk0,
            chunk1,
        ));

        let controller = crate::controller::MatterController::with_components(
            store,
            ctrl_io,
            discovery,
            Arc::new(SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        let node = controller.node(device_node_id);
        let report = node
            .read(&[matter_interaction::ReadPath::all()])
            .await
            .expect("chunked read");

        assert_eq!(report.len(), 2, "both chunks reassembled");
        assert_eq!(report[0].0.endpoint, 0);
        assert_eq!(report[0].1, matter_codec::Value::Uint(5010));
        assert_eq!(report[1].0.endpoint, 1);
        assert_eq!(report[1].0.cluster, 0x06);
        assert_eq!(report[1].1, matter_codec::Value::Bool(true));

        device.await.unwrap();
    }

    #[tokio::test]
    async fn subscribe_streams_reports_over_loopback() {
        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr,
            discovery,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        let device = tokio::spawn(run_subscription_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D2,
            3,
        ));

        let controller = crate::controller::MatterController::with_components(
            store,
            ctrl_io,
            discovery,
            Arc::new(SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        let node = controller.node(device_node_id);
        let mut sub = node
            .subscribe(
                &[matter_interaction::ReadPath::concrete(1, 0x06, 0x0000)],
                1,
                30,
            )
            .await
            .expect("subscribe");

        // The device streams 3 steady-state reports; the consumer receives them.
        for _ in 0..3 {
            let report = sub.next().await.expect("subscription report");
            assert_eq!(report.path.endpoint, 1);
            assert_eq!(report.path.cluster, 0x06);
            assert_eq!(report.value, matter_codec::Value::Bool(true));
        }

        device.await.unwrap();
        sub.cancel().await.expect("cancel");
    }
}
