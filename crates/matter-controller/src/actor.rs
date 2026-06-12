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
use crate::subscription::{AttributeReport, SubscriptionEvent};

/// IM opcodes used by the subscription flow.
const OP_SUBSCRIBE_REQUEST: u8 = 0x03;
const OP_SUBSCRIBE_RESPONSE: u8 = 0x04;
const OP_REPORT_DATA: u8 = 0x05;
const OP_STATUS_RESPONSE: u8 = 0x01;

/// How often the loop wakes to drive MRP / liveness when no MRP deadline is
/// pending.
const LIVENESS_TICK: std::time::Duration = std::time::Duration::from_millis(250);

/// Max `ReportData` chunks a single read may span before aborting (mirrors
/// `matter_commissioning::driver::MAX_READ_CHUNKS`).
const MAX_READ_CHUNKS: usize = 64;
/// Max total decoded payload bytes a single read may accumulate (256 `KiB`).
const MAX_READ_BYTES: usize = 256 * 1024;

/// chip resubscribe backoff constants (`CHIPConfig.h`, verbatim).
const RESUB_MAX_FIBONACCI_STEP_INDEX: u32 = 14;
const RESUB_WAIT_TIME_MULTIPLIER_MS: u64 = 10_000;
const RESUB_MAX_RETRY_WAIT_INTERVAL_MS: u64 = 5_538_000;
const RESUB_MIN_WAIT_PERCENT: u64 = 30;

/// Approximation of chip's `roundTripTimeout`, added to the negotiated max
/// interval to form a subscription's liveness deadline. chip derives it from the
/// session MRP params + `kExpectedIMProcessingTime`; 5 s is a safe, tunable
/// stand-in (too small ⇒ spurious resubscribes).
const LIVENESS_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// chip `GetFibonacciForIndex` (F(0)=0, F(1)=1, F(2)=1, F(3)=2, …).
fn fibonacci(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        let next = a + b;
        a = b;
        b = next;
    }
    a
}

/// chip `ComputeTimeTillNextSubscription(retry_count)`: a Fibonacci-stepped max
/// wait (capped at [`RESUB_MAX_RETRY_WAIT_INTERVAL_MS`]), then a uniform jitter
/// in `[30%, 100%]` of it. `retry_count` 0 yields zero (immediate first retry).
fn resubscribe_backoff(rng: &dyn NocRng, retry_count: u32) -> std::time::Duration {
    let max_wait_ms = if retry_count <= RESUB_MAX_FIBONACCI_STEP_INDEX {
        fibonacci(retry_count).saturating_mul(RESUB_WAIT_TIME_MULTIPLIER_MS)
    } else {
        RESUB_MAX_RETRY_WAIT_INTERVAL_MS
    };
    let min_wait_ms = (RESUB_MIN_WAIT_PERCENT * max_wait_ms) / 100;
    let span = max_wait_ms - min_wait_ms;
    let jitter = if span == 0 {
        0
    } else {
        let mut buf = [0u8; 8];
        // RNG failure is effectively impossible for `SystemNocRng`; fall back to 0.
        let _ = rng.fill(&mut buf);
        u64::from_le_bytes(buf) % span
    };
    std::time::Duration::from_millis(min_wait_ms + jitter)
}

/// Controller-assigned stable subscription handle id. Survives auto-resubscribes
/// (the device's wire `subscription_id` changes on each re-establish, this does
/// not), so the consumer's [`Subscription`] stays valid across a resubscribe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SubId(pub(crate) u64);

/// Per-subscription routing + resubscribe state, keyed by [`SubId`].
struct SubEntry {
    /// Channel to the consumer's [`Subscription`].
    tx: mpsc::UnboundedSender<SubscriptionEvent>,
    /// Operational peer address (for `StatusResponse` acks).
    peer: SocketAddr,
    /// Reassembles a chunked steady-state notification before delivery.
    reassembler: ReportReassembler,
    /// Current device session + wire subscription id (both change on resubscribe).
    session_id: SessionId,
    wire_sub_id: u32,
    /// Subscribe params, retained to re-issue the `SubscribeRequest` on resubscribe.
    node_id: u64,
    paths: Vec<matter_interaction::ReadPath>,
    min_interval: u16,
    max_interval: u16,
    /// Re-subscribe if no report arrives by this instant.
    liveness_deadline: Instant,
}

/// A scheduled resubscribe attempt, fired by the timer arm when due.
struct PendingResubscribe {
    sub_id: SubId,
    attempt_at: Instant,
    node_id: u64,
    paths: Vec<matter_interaction::ReadPath>,
    min_interval: u16,
    max_interval: u16,
    retry_count: u32,
    tx: mpsc::UnboundedSender<SubscriptionEvent>,
}

/// An in-flight request awaiting its response, keyed in `pending` by
/// `(session, exchange)`. The actor owns recv centrally, so a round-trip/read
/// cannot block on its own response — it registers one of these and the central
/// [`Actor::handle_inbound`] resolves it.
struct Pending {
    /// Node this op targets, for the reconnect-once retry on timeout.
    node_id: u64,
    /// Peer the request was sent to.
    peer: SocketAddr,
    /// The request bytes, retained to re-send once after a transparent
    /// reconnect when the cached session was stale.
    request: PendingRequest,
    /// Has this op already been retried once after a reconnect?
    retried: bool,
    /// Where the resolved result is delivered.
    reply: PendingReply,
}

/// The original request, kept so a timed-out op on a stale cached session can be
/// re-sent once on a freshly re-established session.
struct PendingRequest {
    opcode: u8,
    protocol_id: ProtocolId,
    payload: Vec<u8>,
}

/// Where a resolved pending op delivers its result.
enum PendingReply {
    /// Single request/response (`Node::round_trip`).
    RoundTrip(oneshot::Sender<Result<Vec<u8>, Error>>),
    /// Chunked read: accumulate `ReportData` chunk payloads; resolve on the
    /// final chunk.
    Read {
        reply: oneshot::Sender<Result<Vec<Vec<u8>>, Error>>,
        chunks: Vec<Vec<u8>>,
        total_bytes: usize,
    },
    /// Subscribe handshake: buffer/ack priming reports until `SubscribeResponse`.
    /// `reply`/`report_rx` are `Some` for an initial subscribe and `None` for a
    /// resubscribe attempt (the consumer keeps its existing receiver).
    Subscribe {
        sub_id: SubId,
        reply: Option<oneshot::Sender<Result<SubEstablished, Error>>>,
        report_tx: mpsc::UnboundedSender<SubscriptionEvent>,
        report_rx: Option<mpsc::UnboundedReceiver<SubscriptionEvent>>,
        priming: ReportReassembler,
        node_id: u64,
        paths: Vec<matter_interaction::ReadPath>,
        min_interval: u16,
        max_interval: u16,
        retry_count: u32,
    },
}

/// What `handle_subscribe` returns to `Node::subscribe`: the report receiver
/// and the `(session, subscription_id)` key (the `Node` adds the command sender
/// to build the public [`Subscription`]).
pub(crate) type SubEstablished = (mpsc::UnboundedReceiver<SubscriptionEvent>, SubId);

/// Maximum non-final chunks a single subscription notification may span before
/// [`ReportReassembler`] drops the partial accumulation. Bounds memory against a
/// device that streams `MoreChunkedMessages=true` without ever finalising; far
/// above any conformant notification (a handful of chunks at most).
const MAX_SUB_CHUNKS: usize = 64;

/// Accumulates a chunked `ReportData` *sequence* (one logical notification) and
/// yields the merged attributes only when the final chunk arrives
/// (`MoreChunkedMessages` clear). A single-message report flushes immediately.
/// This is the streaming-subscription analogue of the read path's per-call
/// [`ReportAccumulator`](matter_interaction::ReportAccumulator) use: it merges
/// `Replace`/`Append` (`ListIndex`=null) items across a notification's chunks
/// before delivery, so list attributes and list-appends are not lost.
///
/// LIMITATION: there is no on-the-wire marker for a notification boundary, so a
/// chunked sequence whose final chunk never arrives (a device that dies
/// mid-notification) leaves a partial accumulation that would merge into the
/// *next* notification's flush. The [`MAX_SUB_CHUNKS`] cap bounds the memory of
/// such a runaway sequence; the stale-merge window itself is closed by the
/// liveness tracking + auto-resubscribe of SH.2 (an abandoned notification means
/// no complete report within `max_interval`, so liveness fires and we
/// re-subscribe to a fresh priming snapshot). Conformant devices do not start a
/// new notification before the prior chunked sequence completes, so this
/// requires non-conformant behaviour.
#[derive(Default)]
struct ReportReassembler {
    acc: matter_interaction::ReportAccumulator,
    /// Non-final chunks accumulated since the last flush.
    pending_chunks: usize,
}

impl ReportReassembler {
    /// Push one `ReportData` chunk payload. Returns `Some(merged attributes)`
    /// when this payload is the final chunk (`more_chunked_messages == false`),
    /// resetting for the next notification; returns `None` while more chunks are
    /// pending, the payload failed to parse, or the chunk cap was exceeded
    /// (partial dropped).
    fn push(
        &mut self,
        payload: &[u8],
    ) -> Option<Vec<(matter_interaction::AttributePath, matter_codec::Value)>> {
        // Drop a malformed chunk; keep prior accumulation.
        let Ok(rd) = matter_interaction::parse_report_data(payload) else {
            return None;
        };
        let more = rd.more_chunked_messages;
        self.acc.push(rd);
        if !more {
            self.pending_chunks = 0;
            return Some(std::mem::take(&mut self.acc).finish());
        }
        self.pending_chunks += 1;
        if self.pending_chunks > MAX_SUB_CHUNKS {
            // Runaway non-finalising sequence — drop the partial to bound memory.
            self.acc = matter_interaction::ReportAccumulator::default();
            self.pending_chunks = 0;
        }
        None
    }
}

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
    /// Cancel the subscription identified by its `(session, subscription_id)` key.
    CancelSubscription { key: SubId },
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
    /// Active subscriptions, keyed by the stable [`SubId`]. Each entry tracks its
    /// current device `(session, wire_sub_id)`; steady-state `ReportData` is
    /// routed by matching those (see [`Self::deliver_report`]).
    subscriptions: HashMap<SubId, SubEntry>,
    /// In-flight round-trips/reads/subscribe-handshakes, keyed by
    /// `(session, exchange)`. Resolved by [`Self::handle_inbound`].
    pending: HashMap<(SessionId, u16), Pending>,
    /// Monotonic source of stable [`SubId`]s.
    next_sub_id: u64,
    /// Scheduled resubscribe attempts (fired from the timer arm when due).
    resubscribes: Vec<PendingResubscribe>,
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
            pending: HashMap::new(),
            next_sub_id: 1,
            resubscribes: Vec::new(),
        }
    }

    /// The task loop. A single `select!` owns `recv_from()` continuously: it
    /// dispatches commands, routes every inbound datagram through
    /// [`Self::handle_inbound`] (resolving pending round-trips/reads by
    /// `(session, exchange)` and delivering subscription reports by
    /// `(session, subscriptionId)`), and drives MRP for all sessions in the
    /// timer arm. Because round-trips/reads register a pending op and return to
    /// the loop instead of owning recv, a steady-state report arriving during a
    /// concurrent round-trip is delivered, not dropped.
    ///
    /// `run_case` (CASE connect) and `handle_commission` remain blocking command
    /// handlers that briefly pause the loop; a report arriving during a connect
    /// is handled by `run_case`'s own recv. This residual window is far narrower
    /// than the pre-SH.1 per-round-trip window.
    pub(crate) async fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        loop {
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
                        self.handle_inbound(&packet, from).await;
                    }
                }
                () = tokio::time::sleep(sleep_for) => {
                    self.drive_mrp().await;
                    self.check_liveness();
                    self.drive_resubscribes().await;
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
                self.start_round_trip(node_id, opcode, protocol_id, payload, reply)
                    .await;
            }
            Command::Read {
                node_id,
                payload,
                reply,
            } => {
                self.start_read(node_id, payload, reply).await;
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
                self.start_subscribe(node_id, paths, min_interval, max_interval, reply)
                    .await;
            }
            Command::CancelSubscription { key } => {
                self.subscriptions.remove(&key);
                // Also drop any scheduled resubscribe for this handle. An
                // in-flight resubscribe attempt (a pending Subscribe) will
                // re-insert a SubEntry on its response — a benign tiny window
                // closed by the consumer's next cancel/Drop.
                self.resubscribes.retain(|pr| pr.sub_id != key);
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

        // Evict any prior session for this node from the SessionManager so its
        // dead MRP retransmits stop; we keep only the freshly-established one.
        if let Some(old) = self.cache.get(&(fabric_id, node_id)) {
            self.sessions.remove(old.session_id);
        }
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

    /// Return a live `(session, peer)` for `node_id`: the cached session if any,
    /// else connect fresh (this blocks the loop briefly — accepted residual).
    async fn session_for(&mut self, node_id: u64) -> Result<(SessionId, SocketAddr), Error> {
        let fabric_id = self.sole_fabric()?.fabric_id;
        if let Some((sid, peer)) = self
            .cache
            .get(&(fabric_id, node_id))
            .map(|c| (c.session_id, c.peer))
        {
            return Ok((sid, peer));
        }
        self.connect(node_id).await
    }

    /// Encode+send a reliable secured request; returns the allocated exchange id.
    async fn send_request(
        &mut self,
        sid: SessionId,
        peer: SocketAddr,
        opcode: u8,
        protocol_id: ProtocolId,
        payload: &[u8],
    ) -> Result<u16, Error> {
        let out = self.sessions.encode_outbound(
            sid,
            None,
            opcode,
            protocol_id,
            payload,
            MrpFlags { reliable: true },
            Instant::now(),
        )?;
        let exchange = out.exchange_id;
        self.transport
            .send_to(&out.wire_bytes, peer)
            .await
            .map_err(|e| Error::Operational(format!("request send: {e}")))?;
        Ok(exchange)
    }

    /// Send a secured IM round-trip and register a pending op; the central
    /// [`Self::handle_inbound`] resolves `reply` when the response (or timeout)
    /// arrives.
    async fn start_round_trip(
        &mut self,
        node_id: u64,
        opcode: u8,
        protocol_id: ProtocolId,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    ) {
        let (sid, peer) = match self.session_for(node_id).await {
            Ok(v) => v,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        match self
            .send_request(sid, peer, opcode, protocol_id, &payload)
            .await
        {
            Ok(exchange) => {
                self.pending.insert(
                    (sid, exchange),
                    Pending {
                        node_id,
                        peer,
                        request: PendingRequest {
                            opcode,
                            protocol_id,
                            payload,
                        },
                        retried: false,
                        reply: PendingReply::RoundTrip(reply),
                    },
                );
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    /// Send a `ReadRequest` and register a pending read; chunks accumulate in
    /// the pending entry and resolve on the final chunk.
    async fn start_read(
        &mut self,
        node_id: u64,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<Vec<u8>>, Error>>,
    ) {
        let (sid, peer) = match self.session_for(node_id).await {
            Ok(v) => v,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let opcode = crate::node::OP_READ_REQUEST;
        match self
            .send_request(sid, peer, opcode, ProtocolId::INTERACTION_MODEL, &payload)
            .await
        {
            Ok(exchange) => {
                self.pending.insert(
                    (sid, exchange),
                    Pending {
                        node_id,
                        peer,
                        request: PendingRequest {
                            opcode,
                            protocol_id: ProtocolId::INTERACTION_MODEL,
                            payload,
                        },
                        retried: false,
                        reply: PendingReply::Read {
                            reply,
                            chunks: Vec::new(),
                            total_bytes: 0,
                        },
                    },
                );
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    /// Route one inbound datagram: resolve a pending round-trip/read by
    /// `(session, exchange)`; deliver a steady-state `ReportData` to its
    /// subscription by `(session, subscriptionId)`; otherwise let MRP absorb it.
    async fn handle_inbound(&mut self, packet: &[u8], from: SocketAddr) {
        // Unsecured stragglers (session id 0) are not ours.
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
                if self.pending.contains_key(&(session_id, exchange_id)) {
                    self.resolve_pending(session_id, exchange_id, opcode, payload)
                        .await;
                } else if opcode == OP_REPORT_DATA {
                    self.deliver_report(session_id, exchange_id, &payload).await;
                }
                // else: foreign app message — nothing to do (MRP already acked).
            }
            DecodeInboundOutput::AckOnly { .. } => {}
            DecodeInboundOutput::DuplicateReliableAckResent { ack_packet, .. } => {
                let _ = self.transport.send_to(&ack_packet, from).await;
            }
        }
    }

    /// Resolve a pending op identified by `(session, exchange)`. For a
    /// round-trip, reply with the payload. For a read, accumulate the chunk and,
    /// if more chunks follow, ack to solicit the next; otherwise reply with all
    /// chunks. For a subscribe handshake, buffer/ack priming reports and finish
    /// on the `SubscribeResponse`.
    async fn resolve_pending(
        &mut self,
        session_id: SessionId,
        exchange_id: u16,
        opcode: u8,
        payload: Vec<u8>,
    ) {
        // Classify by variant, dropping the borrow before we remove/await.
        enum Kind {
            RoundTrip,
            Read,
            Subscribe,
        }
        let key = (session_id, exchange_id);
        let kind = match self.pending.get(&key) {
            Some(p) => match &p.reply {
                PendingReply::RoundTrip(_) => Kind::RoundTrip,
                PendingReply::Read { .. } => Kind::Read,
                PendingReply::Subscribe { .. } => Kind::Subscribe,
            },
            None => return,
        };
        match kind {
            Kind::RoundTrip => {
                if let Some(PendingReply::RoundTrip(reply)) =
                    self.pending.remove(&key).map(|p| p.reply)
                {
                    let _ = reply.send(Ok(payload));
                }
            }
            Kind::Read => {
                let peer = self.pending.get(&key).map(|p| p.peer);
                // `payload` is moved into `chunks` below, so compute `more` first.
                let more = matter_interaction::parse_report_data(&payload)
                    .is_ok_and(|rd| rd.more_chunked_messages);
                let over = match self.pending.get_mut(&key).map(|p| &mut p.reply) {
                    Some(PendingReply::Read {
                        chunks,
                        total_bytes,
                        ..
                    }) => {
                        *total_bytes = total_bytes.saturating_add(payload.len());
                        chunks.push(payload);
                        chunks.len() > MAX_READ_CHUNKS || *total_bytes > MAX_READ_BYTES
                    }
                    _ => return,
                };
                if over {
                    if let Some(PendingReply::Read { reply, .. }) =
                        self.pending.remove(&key).map(|p| p.reply)
                    {
                        let _ = reply.send(Err(Error::Operational("read too large".into())));
                    }
                } else if more {
                    // Ack this chunk on the same exchange to solicit the next.
                    if let Some(peer) = peer {
                        let _ = self.send_chunk_ack(session_id, exchange_id, peer).await;
                    }
                } else if let Some(PendingReply::Read { reply, chunks, .. }) =
                    self.pending.remove(&key).map(|p| p.reply)
                {
                    let _ = reply.send(Ok(chunks));
                }
            }
            Kind::Subscribe => {
                self.resolve_subscribe(session_id, exchange_id, opcode, payload)
                    .await;
            }
        }
    }

    /// Reliable `StatusResponse(SUCCESS)` on a read exchange to solicit the next
    /// chunk (mirrors `secured_read`'s per-chunk ack).
    async fn send_chunk_ack(
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
            MrpFlags { reliable: true },
            Instant::now(),
        )?;
        self.transport
            .send_to(&out.wire_bytes, peer)
            .await
            .map_err(|e| Error::Operational(format!("chunk ack send: {e}")))?;
        Ok(())
    }

    /// Deliver a steady-state `ReportData` to its subscription, matched by the
    /// current `(session, wire_sub_id)`, reassembling chunks and resetting the
    /// liveness deadline, then ack on the report's own exchange.
    async fn deliver_report(&mut self, session_id: SessionId, exchange_id: u16, payload: &[u8]) {
        let Ok(rd) = matter_interaction::parse_report_data(payload) else {
            return;
        };
        let Some(wire_sub_id) = rd.subscription_id else {
            return; // steady-state reports must carry a subscriptionId
        };
        let now = Instant::now();
        let forwarded = self
            .subscriptions
            .values_mut()
            .find(|e| e.session_id == session_id && e.wire_sub_id == wire_sub_id)
            .map(|e| {
                e.liveness_deadline = now
                    + std::time::Duration::from_secs(u64::from(e.max_interval))
                    + LIVENESS_GRACE;
                (e.tx.clone(), e.peer, e.reassembler.push(payload))
            });
        if let Some((tx, peer, merged)) = forwarded {
            if let Some(attrs) = merged {
                for (path, value) in attrs {
                    let _ = tx.send(SubscriptionEvent::Report(AttributeReport { path, value }));
                }
            }
            let _ = self.send_status_ack(session_id, exchange_id, peer).await;
        }
    }

    /// Send a `SubscribeRequest` and register a pending subscribe handshake. The
    /// report receiver is handed back via `reply` once the `SubscribeResponse`
    /// arrives (see [`Self::resolve_subscribe`]); priming reports that precede it
    /// flow through the same channel.
    async fn start_subscribe(
        &mut self,
        node_id: u64,
        paths: Vec<matter_interaction::ReadPath>,
        min_interval: u16,
        max_interval: u16,
        reply: oneshot::Sender<Result<SubEstablished, Error>>,
    ) {
        let (sid, peer) = match self.session_for(node_id).await {
            Ok(v) => v,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let req =
            matter_interaction::build_subscribe_request(&matter_interaction::SubscribeRequest {
                keep_subscriptions: false,
                min_interval_floor: min_interval,
                max_interval_ceiling: max_interval,
                paths: paths.clone(),
            });
        match self
            .send_request(
                sid,
                peer,
                OP_SUBSCRIBE_REQUEST,
                ProtocolId::INTERACTION_MODEL,
                &req,
            )
            .await
        {
            Ok(exchange) => {
                let sub_id = SubId(self.next_sub_id);
                self.next_sub_id += 1;
                let (report_tx, report_rx) = mpsc::unbounded_channel::<SubscriptionEvent>();
                self.pending.insert(
                    (sid, exchange),
                    Pending {
                        node_id,
                        peer,
                        request: PendingRequest {
                            opcode: OP_SUBSCRIBE_REQUEST,
                            protocol_id: ProtocolId::INTERACTION_MODEL,
                            payload: req,
                        },
                        retried: false,
                        reply: PendingReply::Subscribe {
                            sub_id,
                            reply: Some(reply),
                            report_tx,
                            report_rx: Some(report_rx),
                            priming: ReportReassembler::default(),
                            node_id,
                            paths,
                            min_interval,
                            max_interval,
                            retry_count: 0,
                        },
                    },
                );
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    /// Drive the subscribe handshake on its exchange: ack+buffer priming
    /// `ReportData`, and on `SubscribeResponse` register the subscription under
    /// `(session, subscriptionId)` and hand the report receiver back to the
    /// caller.
    async fn resolve_subscribe(
        &mut self,
        session_id: SessionId,
        exchange_id: u16,
        opcode: u8,
        payload: Vec<u8>,
    ) {
        let key = (session_id, exchange_id);
        if opcode == OP_REPORT_DATA {
            // Ack first (solicits the next chunk), then merge into priming.
            if let Some(peer) = self.pending.get(&key).map(|p| p.peer) {
                let _ = self.send_status_ack(session_id, exchange_id, peer).await;
            }
            if let Some(Pending {
                reply:
                    PendingReply::Subscribe {
                        report_tx, priming, ..
                    },
                ..
            }) = self.pending.get_mut(&key)
            {
                if let Some(attrs) = priming.push(&payload) {
                    for (path, value) in attrs {
                        let _ = report_tx
                            .send(SubscriptionEvent::Report(AttributeReport { path, value }));
                    }
                }
            }
        } else if opcode == OP_SUBSCRIBE_RESPONSE {
            let Some(p) = self.pending.remove(&key) else {
                return;
            };
            let PendingReply::Subscribe {
                sub_id,
                reply,
                report_tx,
                report_rx,
                node_id,
                paths,
                min_interval,
                ..
            } = p.reply
            else {
                return;
            };
            match matter_interaction::parse_subscribe_response(&payload) {
                Ok(resp) => {
                    // Liveness + the re-request ceiling both use the *negotiated*
                    // max interval (the device's agreed reporting cadence).
                    let deadline = Instant::now()
                        + std::time::Duration::from_secs(u64::from(resp.max_interval))
                        + LIVENESS_GRACE;
                    self.subscriptions.insert(
                        sub_id,
                        SubEntry {
                            tx: report_tx.clone(),
                            peer: p.peer,
                            reassembler: ReportReassembler::default(),
                            session_id,
                            wire_sub_id: resp.subscription_id,
                            node_id,
                            paths,
                            min_interval,
                            max_interval: resp.max_interval,
                            liveness_deadline: deadline,
                        },
                    );
                    // Signal (re-)establishment to the consumer (chip's
                    // OnSubscriptionEstablished). Any priming Reports already
                    // flowed — they precede the SubscribeResponse on the wire.
                    let _ = report_tx.send(SubscriptionEvent::Established {
                        subscription_id: resp.subscription_id,
                    });
                    // Initial subscribe hands the receiver back; a resubscribe
                    // (reply/report_rx None) reuses the consumer's existing rx.
                    if let (Some(reply), Some(rx)) = (reply, report_rx) {
                        let _ = reply.send(Ok((rx, sub_id)));
                    }
                }
                Err(e) => {
                    if let Some(reply) = reply {
                        let _ = reply.send(Err(Error::InteractionModel(e)));
                    }
                }
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

    /// Drive MRP for all sessions: send retransmits/standalone-acks, and on
    /// `Expired` resolve the matching pending op — retrying once on a fresh
    /// session if the cached one was stale (preserves the pre-SH.1
    /// reconnect-once policy).
    async fn drive_mrp(&mut self) {
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
                MrpEvent::Expired {
                    session_id,
                    exchange_id,
                    ..
                } => {
                    self.on_pending_timeout(session_id, exchange_id).await;
                }
            }
        }
    }

    /// A pending op timed out. If it ran on a stale cached session and has not
    /// yet been retried, evict the session, reconnect, and re-send once on the
    /// new session; otherwise resolve it with a timeout error.
    async fn on_pending_timeout(&mut self, session_id: SessionId, exchange_id: u16) {
        let Some(p) = self.pending.remove(&(session_id, exchange_id)) else {
            return;
        };
        // A resubscribe attempt (no oneshot reply) reschedules on the backoff
        // rather than failing — chip retries forever.
        if matches!(&p.reply, PendingReply::Subscribe { reply: None, .. }) {
            if let PendingReply::Subscribe {
                sub_id,
                report_tx,
                node_id,
                paths,
                min_interval,
                max_interval,
                retry_count,
                ..
            } = p.reply
            {
                self.reschedule_resubscribe(PendingResubscribe {
                    sub_id,
                    attempt_at: Instant::now(),
                    node_id,
                    paths,
                    min_interval,
                    max_interval,
                    retry_count,
                    tx: report_tx,
                });
            }
            return;
        }
        if !p.retried {
            if let Ok(fabric_id) = self.sole_fabric().map(|f| f.fabric_id) {
                self.cache.remove(&(fabric_id, p.node_id));
            }
            match self.connect(p.node_id).await {
                Ok((sid, peer)) => {
                    if let Ok(exchange) = self
                        .send_request(
                            sid,
                            peer,
                            p.request.opcode,
                            p.request.protocol_id,
                            &p.request.payload,
                        )
                        .await
                    {
                        let mut np = p;
                        np.peer = peer;
                        np.retried = true;
                        // The retry re-sends the original request, so any
                        // partial accumulation from the first attempt must be
                        // discarded (matches the old fresh-`secured_read` retry).
                        match &mut np.reply {
                            PendingReply::Read {
                                chunks,
                                total_bytes,
                                ..
                            } => {
                                chunks.clear();
                                *total_bytes = 0;
                            }
                            PendingReply::Subscribe { priming, .. } => {
                                *priming = ReportReassembler::default();
                            }
                            PendingReply::RoundTrip(_) => {}
                        }
                        self.pending.insert((sid, exchange), np);
                        return;
                    }
                }
                Err(e) => {
                    Self::fail_pending(p, e);
                    return;
                }
            }
        }
        Self::fail_pending(p, Error::Operational("round-trip timed out".into()));
    }

    /// Resolve a pending op's reply channel with an error.
    fn fail_pending(p: Pending, err: Error) {
        match p.reply {
            PendingReply::RoundTrip(reply) => {
                let _ = reply.send(Err(err));
            }
            PendingReply::Read { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            PendingReply::Subscribe { reply, .. } => {
                if let Some(reply) = reply {
                    let _ = reply.send(Err(err));
                }
            }
        }
    }

    /// Re-subscribe any subscription whose liveness deadline has passed.
    fn check_liveness(&mut self) {
        let now = Instant::now();
        let stale: Vec<SubId> = self
            .subscriptions
            .iter()
            .filter(|(_, e)| e.liveness_deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.begin_resubscribe(
                id,
                Error::Operational("subscription liveness timeout".into()),
            );
        }
    }

    /// Move a stale subscription into the resubscribe queue: emit `Resubscribing`,
    /// drop the dead `SubEntry`, and schedule the first attempt (retry 0 ≈ immediate).
    fn begin_resubscribe(&mut self, sub_id: SubId, cause: Error) {
        let Some(entry) = self.subscriptions.remove(&sub_id) else {
            return;
        };
        let _ = entry.tx.send(SubscriptionEvent::Resubscribing { cause });
        let wait = resubscribe_backoff(self.rng.as_ref(), 0);
        self.resubscribes.push(PendingResubscribe {
            sub_id,
            attempt_at: Instant::now() + wait,
            node_id: entry.node_id,
            paths: entry.paths,
            min_interval: entry.min_interval,
            max_interval: entry.max_interval,
            retry_count: 0,
            tx: entry.tx,
        });
    }

    /// Fire any due resubscribe attempts.
    async fn drive_resubscribes(&mut self) {
        let now = Instant::now();
        let mut due = Vec::new();
        let mut i = 0;
        while i < self.resubscribes.len() {
            if self.resubscribes[i].attempt_at <= now {
                due.push(self.resubscribes.swap_remove(i));
            } else {
                i += 1;
            }
        }
        for pr in due {
            self.attempt_resubscribe(pr).await;
        }
    }

    /// One resubscribe attempt: connect if needed, send a fresh `SubscribeRequest`,
    /// and register a pending Subscribe (no oneshot reply) so the central demux
    /// drives the handshake. On connect/send failure, reschedule with backoff.
    async fn attempt_resubscribe(&mut self, pr: PendingResubscribe) {
        let Ok((sid, peer)) = self.session_for(pr.node_id).await else {
            self.reschedule_resubscribe(pr);
            return;
        };
        let req =
            matter_interaction::build_subscribe_request(&matter_interaction::SubscribeRequest {
                keep_subscriptions: false,
                min_interval_floor: pr.min_interval,
                max_interval_ceiling: pr.max_interval,
                paths: pr.paths.clone(),
            });
        match self
            .send_request(
                sid,
                peer,
                OP_SUBSCRIBE_REQUEST,
                ProtocolId::INTERACTION_MODEL,
                &req,
            )
            .await
        {
            Ok(exchange) => {
                self.pending.insert(
                    (sid, exchange),
                    Pending {
                        node_id: pr.node_id,
                        peer,
                        request: PendingRequest {
                            opcode: OP_SUBSCRIBE_REQUEST,
                            protocol_id: ProtocolId::INTERACTION_MODEL,
                            payload: req,
                        },
                        // Skip SH.1's reconnect-once — a timeout reschedules on
                        // the backoff (see `on_pending_timeout`).
                        retried: true,
                        reply: PendingReply::Subscribe {
                            sub_id: pr.sub_id,
                            reply: None,
                            report_tx: pr.tx,
                            report_rx: None,
                            priming: ReportReassembler::default(),
                            node_id: pr.node_id,
                            paths: pr.paths,
                            min_interval: pr.min_interval,
                            max_interval: pr.max_interval,
                            retry_count: pr.retry_count,
                        },
                    },
                );
            }
            Err(_) => self.reschedule_resubscribe(pr),
        }
    }

    /// Reschedule a failed attempt with the next backoff step (retry forever).
    fn reschedule_resubscribe(&mut self, mut pr: PendingResubscribe) {
        pr.retry_count = pr.retry_count.saturating_add(1);
        let wait = resubscribe_backoff(self.rng.as_ref(), pr.retry_count);
        pr.attempt_at = Instant::now() + wait;
        self.resubscribes.push(pr);
    }

    /// The peer address for `sid`: from an active subscription, a pending op, or
    /// the session cache.
    fn peer_for_session(&self, sid: SessionId) -> Option<SocketAddr> {
        self.subscriptions
            .values()
            .find(|e| e.session_id == sid)
            .map(|e| e.peer)
            .or_else(|| {
                self.pending
                    .iter()
                    .find(|((s, _), _)| *s == sid)
                    .map(|(_, p)| p.peer)
            })
            .or_else(|| {
                self.cache
                    .values()
                    .find(|c| c.session_id == sid)
                    .map(|c| c.peer)
            })
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
        w.put_uint(Tag::Context(0), 0x1234_5678).unwrap(); // subscriptionId
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
        w.put_uint(Tag::Context(0), 0x1234_5678).unwrap(); // subscriptionId
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

    /// Build a `ReportData` whose single attribute is a list **append**
    /// (`AttributePathIB` carries `ListIndex` = null, context tag 5) — the
    /// list-chunking append form — with the given `MoreChunkedMessages` flag.
    fn build_report_data_append(
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
        w.put_uint(Tag::Context(0), 0x1234_5678).unwrap(); // subscriptionId
        w.start_array(Tag::Context(1)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_structure(Tag::Context(1)).unwrap();
        w.start_list(Tag::Context(1)).unwrap();
        w.put_uint(Tag::Context(2), u64::from(ep)).unwrap();
        w.put_uint(Tag::Context(3), u64::from(cl)).unwrap();
        w.put_uint(Tag::Context(4), u64::from(at)).unwrap();
        w.put_null(Tag::Context(5)).unwrap(); // ListIndex = null ⇒ append
        w.end_container().unwrap();
        w.write_value(Tag::Context(2), value).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        if more {
            w.put_bool(Tag::Context(3), true).unwrap();
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
        // 3. Receive the controller's StatusResponse ack (opcode 0x01). It must
        //    arrive on the SAME exchange as the read — that is what piggybacks
        //    chunk 0's MRP ack and solicits the next chunk; a fresh-exchange
        //    StatusResponse (no piggyback) would be caught here.
        let (ack, _) = io.recv_from().await.unwrap();
        let DecodeInboundOutput::AppMessage {
            opcode,
            exchange_id: ack_exchange,
            ..
        } = sessions.decode_inbound(&ack, Instant::now()).unwrap()
        else {
            panic!("expected StatusResponse ack");
        };
        assert_eq!(opcode, 0x01, "controller must ack the chunk");
        assert_eq!(
            ack_exchange, exchange_id,
            "StatusResponse must ride the read exchange (enables the chunk-ack piggyback)"
        );
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
        reports: Vec<Vec<u8>>,
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

        // Stream the given `ReportData` payloads on the same exchange (chunked
        // notifications just pass multiple payloads, the non-final ones with
        // MoreChunkedMessages set); drain the controller's StatusResponse acks
        // between sends.
        for report in &reports {
            let out = sessions
                .encode_outbound(
                    sid,
                    Some(exchange_id),
                    0x05,
                    ProtocolId::INTERACTION_MODEL,
                    report,
                    MrpFlags { reliable: false },
                    Instant::now(),
                )
                .unwrap();
            io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(100), io.recv_from()).await;
        }
    }

    /// Device that establishes a subscription, then — when a round-trip request
    /// arrives — sends a steady-state `ReportData` (on the subscription
    /// exchange, carrying the `subscriptionId`) *before* replying to the
    /// round-trip. This is the concurrent window the pre-SH.1 controller
    /// dropped the report in (consumed inside `secured_round_trip`'s recv loop).
    #[allow(clippy::too_many_lines)] // CASE-handshake boilerplate, as the sibling mocks.
    async fn run_concurrent_sub_roundtrip_device(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
    ) {
        let mut responder = CaseResponder::new(creds, roots, responder_session_id).unwrap();
        // --- CASE handshake (identical to run_subscription_device) ---
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

        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);

        // 1. SubscribeRequest -> SubscribeResponse (subscriptionId 0x1234_5678).
        let (wire, _) = io.recv_from().await.unwrap();
        let DecodeInboundOutput::AppMessage {
            exchange_id: sub_exchange,
            opcode,
            ..
        } = sessions.decode_inbound(&wire, Instant::now()).unwrap()
        else {
            panic!("expected SubscribeRequest");
        };
        assert_eq!(opcode, 0x03, "expected SubscribeRequest opcode");
        let sub_resp = build_subscribe_response(0x1234_5678, 30);
        let out = sessions
            .encode_outbound(
                sid,
                Some(sub_exchange),
                0x04,
                ProtocolId::INTERACTION_MODEL,
                &sub_resp,
                MrpFlags { reliable: false },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();

        // 2. Wait for the round-trip request (opcode 0x02 on a fresh exchange).
        let (wire, _) = io.recv_from().await.unwrap();
        let DecodeInboundOutput::AppMessage {
            exchange_id: rt_exchange,
            opcode: rt_opcode,
            ..
        } = sessions.decode_inbound(&wire, Instant::now()).unwrap()
        else {
            panic!("expected round-trip request");
        };
        assert_eq!(rt_opcode, 0x02, "expected the round-trip request opcode");

        // 3. CONCURRENT WINDOW: send a steady-state report on the subscription
        //    exchange (carrying subscriptionId 0x1234_5678) BEFORE replying to
        //    the round-trip.
        let steady = build_report_data(1, 0x06, 0x0000, &matter_codec::Value::Bool(true));
        let out = sessions
            .encode_outbound(
                sid,
                Some(sub_exchange),
                0x05,
                ProtocolId::INTERACTION_MODEL,
                &steady,
                MrpFlags { reliable: false },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();

        // 4. Now reply to the round-trip on its own exchange.
        let out = sessions
            .encode_outbound(
                sid,
                Some(rt_exchange),
                0x05,
                ProtocolId::INTERACTION_MODEL,
                b"pong",
                MrpFlags { reliable: false },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();

        // 5. Drain the controller's StatusResponse ack for the steady report.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), io.recv_from()).await;
    }

    /// Device that answers two subscribe cycles: it establishes (priming report
    /// then `SubscribeResponse`), goes silent so the controller's liveness fires,
    /// then answers the controller's auto-resubscribe with a fresh
    /// `SubscribeResponse` (new wire id) + a re-primed report, then returns.
    /// Only reacts to `SubscribeRequest`s (opcode 0x03); drains acks/other frames.
    #[allow(clippy::too_many_lines)] // CASE-handshake boilerplate, as the sibling mocks.
    async fn run_resubscribe_device(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
    ) {
        let mut responder = CaseResponder::new(creds, roots, responder_session_id).unwrap();
        // --- CASE handshake (identical to run_subscription_device) ---
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

        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);

        // Two subscribe cycles with distinct wire subscription ids.
        let wire_ids = [0x1111_1111_u32, 0x2222_2222_u32];
        let mut cycle = 0usize;
        // The recv loop tolerates a long silent gap (the controller's liveness +
        // backoff before it resubscribes).
        loop {
            let Ok(Ok((wire, _))) =
                tokio::time::timeout(std::time::Duration::from_secs(30), io.recv_from()).await
            else {
                return; // timeout or io error → device is done
            };
            if wire.len() >= 3 && wire[1] == 0 && wire[2] == 0 {
                continue; // unsecured straggler
            }
            let Ok(decoded) = sessions.decode_inbound(&wire, Instant::now()) else {
                continue;
            };
            let DecodeInboundOutput::AppMessage {
                exchange_id,
                opcode,
                ..
            } = decoded
            else {
                continue; // ack / duplicate — ignore
            };
            if opcode != 0x03 {
                continue; // only react to SubscribeRequest; drain StatusResponse acks
            }
            // Priming report FIRST (wire order: priming precedes SubscribeResponse),
            // then the SubscribeResponse — both on the request's exchange.
            let prime = build_report_data(1, 0x06, 0x0000, &matter_codec::Value::Bool(true));
            let out = sessions
                .encode_outbound(
                    sid,
                    Some(exchange_id),
                    0x05,
                    ProtocolId::INTERACTION_MODEL,
                    &prime,
                    MrpFlags { reliable: false },
                    Instant::now(),
                )
                .unwrap();
            io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
            let sub_resp = build_subscribe_response(wire_ids[cycle.min(1)], 0);
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
            cycle += 1;
            if cycle >= 2 {
                // Drain a little, then leave (the controller's later liveness
                // re-subscribe attempts go unanswered — fine, the test cancels).
                let _ = tokio::time::timeout(std::time::Duration::from_millis(200), io.recv_from())
                    .await;
                return;
            }
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
        let chunk0 =
            build_report_data_chunk(0, 0x28, 0x0002, &matter_codec::Value::Uint(5010), true);
        let chunk1 =
            build_report_data_chunk(1, 0x06, 0x0000, &matter_codec::Value::Bool(true), false);
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

    #[test]
    fn reassembler_flushes_only_on_final_chunk() {
        let mut r = ReportReassembler::default();
        // chunk 0: ep0/0x28/0x0002 = 5010, MoreChunkedMessages=true → no flush.
        let c0 = build_report_data_chunk(0, 0x28, 0x0002, &matter_codec::Value::Uint(5010), true);
        assert!(r.push(&c0).is_none(), "non-final chunk must not flush");
        // chunk 1: ep1/0x06/0x0000 = true, final → flush both.
        let c1 = build_report_data_chunk(1, 0x06, 0x0000, &matter_codec::Value::Bool(true), false);
        let merged = r.push(&c1).expect("final chunk flushes");
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].0.endpoint, 0);
        assert_eq!(merged[1].0.endpoint, 1);
    }

    #[test]
    fn reassembler_single_message_flushes_immediately() {
        let mut r = ReportReassembler::default();
        let only = build_report_data(1, 0x06, 0x0000, &matter_codec::Value::Bool(true));
        let merged = r
            .push(&only)
            .expect("single-message report flushes at once");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].0.cluster, 0x06);
    }

    #[test]
    fn reassembler_drops_runaway_sequence() {
        // A device that streams MoreChunkedMessages=true forever: past the cap
        // the partial is dropped, so a later final chunk flushes only itself —
        // the runaway accumulation does not bleed in.
        let mut r = ReportReassembler::default();
        let runaway = build_report_data_chunk(0, 0x28, 0x0002, &matter_codec::Value::Uint(1), true);
        for _ in 0..=MAX_SUB_CHUNKS {
            assert!(r.push(&runaway).is_none(), "non-final chunk never flushes");
        }
        let last =
            build_report_data_chunk(1, 0x06, 0x0000, &matter_codec::Value::Bool(true), false);
        let merged = r.push(&last).expect("final chunk flushes");
        assert_eq!(merged.len(), 1, "runaway partial was dropped, not merged");
        assert_eq!(merged[0].0.cluster, 0x06);
    }

    #[test]
    fn fibonacci_matches_chip_sequence() {
        // F(0)=0, F(1)=1, F(2)=1, F(3)=2, F(4)=3, F(5)=5, F(14)=377.
        assert_eq!(fibonacci(0), 0);
        assert_eq!(fibonacci(1), 1);
        assert_eq!(fibonacci(2), 1);
        assert_eq!(fibonacci(3), 2);
        assert_eq!(fibonacci(5), 5);
        assert_eq!(fibonacci(14), 377);
    }

    #[test]
    fn resubscribe_backoff_respects_chip_bounds() {
        let rng = SystemNocRng;
        // n=0 → Fib(0)=0 → maxWait 0 → wait 0 (immediate first retry).
        assert_eq!(resubscribe_backoff(&rng, 0), std::time::Duration::ZERO);
        // n=3 → Fib(3)=2 → maxWait 20_000ms; wait ∈ [6_000, 20_000].
        for _ in 0..32 {
            let d = u64::try_from(resubscribe_backoff(&rng, 3).as_millis()).unwrap();
            assert!(
                (6_000..=20_000).contains(&d),
                "n=3 wait {d} out of [6000,20000]"
            );
        }
        // Above the Fibonacci cap: maxWait = 5_538_000ms; wait ∈ [1_661_400, 5_538_000].
        for _ in 0..32 {
            let d = u64::try_from(resubscribe_backoff(&rng, 99).as_millis()).unwrap();
            assert!(
                (1_661_400..=5_538_000).contains(&d),
                "n=99 wait {d} out of cap band"
            );
        }
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
            vec![build_report_data(1, 0x06, 0x0000, &matter_codec::Value::Bool(true)); 3],
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

        // First event: Established (from the SubscribeResponse).
        match sub.next().await {
            Some(SubscriptionEvent::Established { subscription_id }) => {
                assert_eq!(subscription_id, 0x1234_5678);
            }
            other => panic!("expected Established, got {other:?}"),
        }
        // The device streams 3 steady-state reports; the consumer receives them.
        for _ in 0..3 {
            let Some(SubscriptionEvent::Report(report)) = sub.next().await else {
                panic!("expected a Report event");
            };
            assert_eq!(report.path.endpoint, 1);
            assert_eq!(report.path.cluster, 0x06);
            assert_eq!(report.value, matter_codec::Value::Bool(true));
        }

        device.await.unwrap();
        sub.cancel().await.expect("cancel");
    }

    // Note: a message-level chunked steady-state notification (whole attributes
    // spread across chunks) was already delivered correctly by the pre-CR.3
    // streaming code (each ReportData forwarded + acked), so it is not a
    // regression guard. The list-append test below is the discriminating guard:
    // the dropped `ListIndex=null` append is exactly what CR.3 fixes, and it
    // also exercises the `MoreChunkedMessages=true` accumulate-then-flush path.

    #[tokio::test]
    async fn subscribe_reassembles_list_append_over_loopback() {
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

        // List-chunked notification: chunk 0 replaces Descriptor.PartsList with
        // an empty list (MoreChunkedMessages=true); the final chunk appends one
        // element (ListIndex=null). The consumer must receive ONE merged report
        // whose value is the reassembled list.
        let chunk0 = build_report_data_chunk(
            1,
            0x1d,
            0x0003,
            &matter_codec::Value::Array(Vec::new()),
            true,
        );
        let chunk1 =
            build_report_data_append(1, 0x1d, 0x0003, &matter_codec::Value::Uint(7), false);
        let device = tokio::spawn(run_subscription_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D6,
            vec![chunk0, chunk1],
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
            .subscribe(&[matter_interaction::ReadPath::cluster(1, 0x1d)], 1, 30)
            .await
            .expect("subscribe");

        match sub.next().await {
            Some(SubscriptionEvent::Established { .. }) => {}
            other => panic!("expected Established, got {other:?}"),
        }
        let Some(SubscriptionEvent::Report(report)) = sub.next().await else {
            panic!("expected the merged list Report");
        };
        assert_eq!(report.path.endpoint, 1);
        assert_eq!(report.path.cluster, 0x1d);
        assert_eq!(report.path.attribute, 0x0003);
        assert_eq!(
            report.value,
            matter_codec::Value::Array(vec![matter_codec::Value::Uint(7)]),
            "list-append must reassemble into the full list"
        );

        device.await.unwrap();
        sub.cancel().await.expect("cancel");
    }

    /// SH.1 discriminating guard for the concurrent-round-trip report-loss
    /// (M8.5 known limitation #1): a steady-state report that arrives while a
    /// round-trip is in flight on the same node must be DELIVERED, not dropped.
    /// Under the pre-SH.1 code the report was consumed inside
    /// `secured_round_trip`'s owned recv loop and silently discarded (so
    /// `sub.next()` below would hang); the always-listening demux delivers it.
    #[tokio::test]
    async fn concurrent_round_trip_does_not_drop_subscription_report() {
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

        let device = tokio::spawn(run_concurrent_sub_roundtrip_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D2,
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

        // 1. Establish the subscription.
        let mut sub = node
            .subscribe(
                &[matter_interaction::ReadPath::concrete(1, 0x06, 0x0000)],
                1,
                30,
            )
            .await
            .expect("subscribe");

        // First event: Established (from the SubscribeResponse).
        match sub.next().await {
            Some(SubscriptionEvent::Established { .. }) => {}
            other => panic!("expected Established, got {other:?}"),
        }

        // 2. Issue a round-trip; the device sends a steady report DURING it
        //    (before replying). The round-trip itself must still complete.
        let resp = node
            .round_trip(0x02, ProtocolId::INTERACTION_MODEL, b"ping".to_vec())
            .await
            .expect("round-trip completes");
        assert_eq!(resp, b"pong");

        // 3. The steady report sent during the round-trip must have been
        //    delivered — bounded by a timeout so a regression fails fast.
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), sub.next())
            .await
            .expect("steady report must arrive (not dropped by the concurrent round-trip)")
            .expect("subscription still live");
        let SubscriptionEvent::Report(report) = event else {
            panic!("expected a Report event, got {event:?}");
        };
        assert_eq!(report.path.endpoint, 1);
        assert_eq!(report.path.cluster, 0x06);
        assert_eq!(report.value, matter_codec::Value::Bool(true));

        device.await.unwrap();
        sub.cancel().await.expect("cancel");
    }

    /// SH.2b discriminating guard: a subscription that goes silent past its
    /// liveness deadline (negotiated max interval 0 + `LIVENESS_GRACE`) must be
    /// transparently re-established — the consumer sees `Resubscribing`, a SECOND
    /// `Established`, and a re-primed `Report`, all behind the same handle. Takes
    /// ~`LIVENESS_GRACE` (≈5 s) to trip liveness.
    #[tokio::test]
    async fn liveness_timeout_triggers_resubscribe() {
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

        let device = tokio::spawn(run_resubscribe_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D2,
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
        // max_interval ceiling 0 → negotiated 0 → liveness ≈ LIVENESS_GRACE.
        let mut sub = node
            .subscribe(
                &[matter_interaction::ReadPath::concrete(1, 0x06, 0x0000)],
                1,
                0,
            )
            .await
            .expect("subscribe");

        // Read events until we observe the resubscribe lifecycle (or give up).
        let mut establishes = 0u32;
        let mut saw_resubscribing = false;
        let mut reprimed_after_resub = false;
        let overall = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
        // Keep reading until the full resubscribe lifecycle is observed: a second
        // Established arrives AFTER the re-primed Report (priming precedes the
        // SubscribeResponse on the wire), so do not stop on the Report alone.
        while tokio::time::Instant::now() < overall
            && !(saw_resubscribing && establishes >= 2 && reprimed_after_resub)
        {
            match tokio::time::timeout(std::time::Duration::from_secs(15), sub.next()).await {
                Ok(Some(SubscriptionEvent::Established { .. })) => establishes += 1,
                Ok(Some(SubscriptionEvent::Resubscribing { .. })) => saw_resubscribing = true,
                Ok(Some(SubscriptionEvent::Report(_))) => {
                    if saw_resubscribing {
                        reprimed_after_resub = true;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }

        assert!(saw_resubscribing, "expected a Resubscribing event");
        assert!(
            establishes >= 2,
            "expected a second Established after resubscribe, saw {establishes}"
        );
        assert!(
            reprimed_after_resub,
            "expected a re-primed Report after the resubscribe"
        );

        let _ = device.await;
        sub.cancel().await.ok();
    }
}
