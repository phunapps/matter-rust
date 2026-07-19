//! The owning controller task. Holds the transport, `SessionManager`,
//! discovery, and `ControllerState`. Processes [`Command`]s; while any
//! subscription is active it also listens for unsolicited reports.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use matter_commissioning::driver::AsyncDatagram;
use matter_commissioning::NocRng;
use matter_transport::{
    DecodeInboundOutput, Discovery, MrpEvent, MrpFlags, ProtocolHeader, ProtocolId, SessionId,
    SessionManager, SessionRole,
};
use tokio::sync::{mpsc, oneshot};

use crate::error::Error;
use crate::fabric::FabricConfig;
use crate::snapshot;
use crate::state::ControllerState;
use crate::store::ControllerStore;
use crate::subscription::{AttributeReport, SubscriptionEvent, SUBSCRIPTION_CHANNEL_CAP};

/// IM opcodes used by the subscription flow.
const OP_SUBSCRIBE_REQUEST: u8 = 0x03;
const OP_SUBSCRIBE_RESPONSE: u8 = 0x04;
const OP_REPORT_DATA: u8 = 0x05;
const OP_STATUS_RESPONSE: u8 = 0x01;
const OP_TIMED_REQUEST: u8 = 0x0a;
/// IM `WriteRequest` opcode — used by the chunked-write primitive.
const OP_WRITE_REQUEST: u8 = 0x06;
/// IM status `NEEDS_TIMED_INTERACTION` — a device returns this (as a message-level
/// `StatusResponse`) when a write/invoke that requires a timed interaction arrives
/// without a preceding `TimedRequest`. Triggers the transparent timed retry.
const NEEDS_TIMED_INTERACTION: u8 = 0xc6;

/// How often the loop wakes to drive MRP / liveness when no MRP deadline is
/// pending.
const LIVENESS_TICK: std::time::Duration = std::time::Duration::from_millis(250);

/// Max `ReportData` chunks a single read may span before aborting (mirrors
/// `matter_commissioning::driver::MAX_READ_CHUNKS`).
const MAX_READ_CHUNKS: usize = 64;
/// Max total decoded payload bytes a single read may accumulate (256 `KiB`).
const MAX_READ_BYTES: usize = 256 * 1024;

/// The Matter group multicast UDP port (Matter Core Spec §4.2.2 — operational
/// and group traffic share port 5540).
const MATTER_GROUP_PORT: u16 = 5540;

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

/// The actor's two senders into one consumer [`Subscription`], plus the
/// per-subscription dropped-report counter.
///
/// Steady-state reports go on a **bounded** channel (`report_tx`,
/// [`SUBSCRIPTION_CHANNEL_CAP`]) and are dropped — never blocked on — when full,
/// so a device that floods reports cannot grow controller memory or stall the
/// actor loop. Control events ([`SubscriptionEvent::Established`] /
/// [`SubscriptionEvent::Resubscribing`]) go on a separate, reliable, low-volume
/// channel (`ctrl_tx`) so they are never dropped by report backpressure.
struct ReportSink {
    /// Bounded report channel (capacity [`SUBSCRIPTION_CHANNEL_CAP`]).
    report_tx: mpsc::Sender<SubscriptionEvent>,
    /// Reliable control-event channel ([`SubscriptionEvent::Established`] /
    /// [`SubscriptionEvent::Resubscribing`]).
    ctrl_tx: mpsc::UnboundedSender<SubscriptionEvent>,
    /// Reports dropped (buffer full) since the last delivered `Lagged`.
    dropped: usize,
}

impl ReportSink {
    /// Try to forward a steady-state report without ever blocking the actor.
    ///
    /// On a full buffer the report is dropped and counted; the loss is later
    /// surfaced as a single coalesced [`SubscriptionEvent::Lagged`] once capacity
    /// frees. Returns `false` only if the consumer's report receiver is gone
    /// (closed), signalling the subscription should be reaped.
    fn try_send_report(&mut self, report: AttributeReport) -> bool {
        // Flush a pending Lagged first so the consumer learns of prior drops as
        // soon as there is room; if it still doesn't fit, fold this into dropped.
        if self.dropped > 0 {
            match self.report_tx.try_send(SubscriptionEvent::Lagged {
                dropped: self.dropped,
            }) {
                Ok(()) => self.dropped = 0,
                Err(mpsc::error::TrySendError::Closed(_)) => return false,
                Err(mpsc::error::TrySendError::Full(_)) => {}
            }
        }
        match self.report_tx.try_send(SubscriptionEvent::Report(report)) {
            Ok(()) => true,
            // Buffer full: drop this report and count it (coalesced Lagged later).
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped += 1;
                true
            }
            // Consumer gone: reap the subscription.
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Like [`try_send_report`](Self::try_send_report) but for an event report.
    /// Shares the bounded report channel + `Lagged` accounting (events are
    /// report-volume and the device controls their cadence, so they must be
    /// bounded the same way). Returns `false` only if the consumer's report
    /// receiver is gone (closed), signalling the subscription should be reaped.
    fn try_send_event(&mut self, event: matter_interaction::EventReport) -> bool {
        // Flush a pending Lagged first (mirrors try_send_report).
        if self.dropped > 0 {
            match self.report_tx.try_send(SubscriptionEvent::Lagged {
                dropped: self.dropped,
            }) {
                Ok(()) => self.dropped = 0,
                Err(mpsc::error::TrySendError::Closed(_)) => return false,
                Err(mpsc::error::TrySendError::Full(_)) => {}
            }
        }
        match self.report_tx.try_send(SubscriptionEvent::Event(event)) {
            Ok(()) => true,
            // Buffer full: drop this event and count it (coalesced Lagged later).
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped += 1;
                true
            }
            // Consumer gone: reap the subscription.
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Deliver a control event reliably. Returns `false` if the consumer's
    /// control receiver is gone (the subscription should be reaped).
    fn send_control(&self, event: SubscriptionEvent) -> bool {
        self.ctrl_tx.send(event).is_ok()
    }
}

/// Per-subscription routing + resubscribe state, keyed by [`SubId`].
struct SubEntry {
    /// Channels to the consumer's [`Subscription`].
    tx: ReportSink,
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
    event_paths: Vec<matter_interaction::EventPath>,
    event_filters: Vec<matter_interaction::EventFilter>,
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
    event_paths: Vec<matter_interaction::EventPath>,
    event_filters: Vec<matter_interaction::EventFilter>,
    min_interval: u16,
    max_interval: u16,
    retry_count: u32,
    tx: ReportSink,
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
    /// Timed handshake: a `TimedRequest` is in flight. On `StatusResponse(SUCCESS)`
    /// the actor sends `action_payload` (opcode `action_opcode`) on the SAME
    /// exchange and converts this pending into a [`RoundTrip`](Self::RoundTrip)
    /// awaiting the action's response, which resolves `reply`.
    TimedAction {
        action_opcode: u8,
        action_payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// A plain write/invoke awaiting its response. On a `NEEDS_TIMED_INTERACTION`
    /// rejection the actor records `keys` in the learned timed-cache and retries
    /// the action timed (`timed_payload`); otherwise it resolves `reply` with the
    /// response bytes. (See [`Actor::resolve_action`].)
    Action {
        opcode: u8,
        timed_payload: Vec<u8>,
        keys: Vec<(u32, u32)>,
        timeout_ms: u16,
        node_id: u64,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Chunked write: the final `WriteRequest` of a multi-chunk write is in
    /// flight (all preceding chunks were already sent reliably on the SAME
    /// exchange). On the device's single `WriteResponse` the actor resolves
    /// `reply` with the raw response bytes (the `Node` parses them into per-path
    /// statuses). There is exactly ONE such pending per exchange — the
    /// intermediate chunks are reliable sends awaiting MRP transport acks, NOT
    /// app-level pendings (SH.1 preserved).
    ChunkedWrite {
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Chunked read: accumulate parsed `ReportData` chunks; resolve on the
    /// final chunk. Each chunk is parsed exactly once here (in the actor's
    /// receive path) and handed to `Node::read` already decoded, so the read
    /// path does not walk the TLV a second time.
    Read {
        reply: oneshot::Sender<Result<Vec<matter_interaction::ReportData>, Error>>,
        chunks: Vec<matter_interaction::ReportData>,
        total_bytes: usize,
    },
    /// Subscribe handshake: buffer/ack priming reports until `SubscribeResponse`.
    /// `reply`/`report_rx` are `Some` for an initial subscribe and `None` for a
    /// resubscribe attempt (the consumer keeps its existing receiver).
    Subscribe {
        sub_id: SubId,
        reply: Option<oneshot::Sender<Result<SubEstablished, Error>>>,
        report_tx: ReportSink,
        /// The consumer's receivers, handed back on the initial `Established`.
        /// `None` for a resubscribe (the consumer keeps its existing receivers).
        report_rx: Option<SubReceivers>,
        // Boxed to keep the `Command` enum compact: the reassembler embeds a
        // `ReportAccumulator` (HashMaps + size-cap bookkeeping) that would
        // otherwise dominate every other variant's footprint.
        priming: Box<ReportReassembler>,
        node_id: u64,
        paths: Vec<matter_interaction::ReadPath>,
        event_paths: Vec<matter_interaction::EventPath>,
        event_filters: Vec<matter_interaction::EventFilter>,
        min_interval: u16,
        max_interval: u16,
        retry_count: u32,
    },
}

/// The consumer-side receivers for one subscription: the bounded report channel
/// and the reliable control-event channel.
pub(crate) struct SubReceivers {
    /// Bounded report receiver (capacity [`SUBSCRIPTION_CHANNEL_CAP`]).
    pub(crate) report_rx: mpsc::Receiver<SubscriptionEvent>,
    /// Reliable control-event receiver.
    pub(crate) ctrl_rx: mpsc::UnboundedReceiver<SubscriptionEvent>,
}

/// What `handle_subscribe` returns to `Node::subscribe`: the report receivers
/// and the `(session, subscription_id)` key (the `Node` adds the command sender
/// to build the public [`Subscription`]).
pub(crate) type SubEstablished = (SubReceivers, SubId);

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
    /// Push one already-parsed `ReportData` chunk. Returns `Some(merged
    /// attributes)` when this chunk is the final one
    /// (`more_chunked_messages == false`), resetting for the next notification;
    /// returns `None` while more chunks are pending, the chunk cap was
    /// exceeded, or the accumulator's in-crate total-size ceiling was exceeded
    /// (partial dropped in all three cases).
    ///
    /// This is the single-parse entry point: the caller (`deliver_report` /
    /// the priming path) parses the inbound datagram exactly once and hands the
    /// struct in by value, so the steady-state subscription hot path does not
    /// walk the TLV twice.
    fn push_parsed(
        &mut self,
        rd: matter_interaction::ReportData,
    ) -> Option<Vec<(matter_interaction::AttributePath, matter_codec::Value)>> {
        let more = rd.more_chunked_messages;
        if self.acc.push(rd).is_err() {
            // The accumulator's total-size ceiling was hit (a peer streaming an
            // unbounded report set). Drop the partial — same posture as the
            // chunk-count cap below — and wait for liveness/resubscribe to
            // recover a clean snapshot.
            self.acc = matter_interaction::ReportAccumulator::default();
            self.pending_chunks = 0;
            return None;
        }
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

    /// Parse one `ReportData` chunk payload and merge it via [`push_parsed`]. A
    /// malformed chunk is dropped (prior accumulation kept). Retained for tests
    /// that exercise the reassembler from raw bytes.
    ///
    /// [`push_parsed`]: ReportReassembler::push_parsed
    #[cfg(test)]
    fn push(
        &mut self,
        payload: &[u8],
    ) -> Option<Vec<(matter_interaction::AttributePath, matter_codec::Value)>> {
        // Drop a malformed chunk; keep prior accumulation.
        let rd = matter_interaction::parse_report_data(payload).ok()?;
        self.push_parsed(rd)
    }
}

/// Messages the handles send to the owning task. Each carries a `oneshot`
/// reply sender; a dropped reply sender means the caller gave up.
pub(crate) enum Command {
    CreateFabric {
        cfg: FabricConfig,
        reply: oneshot::Sender<Result<u64, Error>>,
    },
    /// Raw secured IM round-trip to `node_id`. A generic primitive retained for
    /// tests that exercise the actor's connect/cache/demux without IM payloads;
    /// the production verbs use `Read`/`Action`/`Subscribe`/`TimedRoundTrip`.
    #[cfg(test)]
    RoundTrip {
        node_id: u64,
        opcode: u8,
        protocol_id: matter_transport::ProtocolId,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Chunked secured read to `node_id` — returns every `ReportData` chunk
    /// already parsed, in order (the `Node` reassembles them via
    /// `ReportAccumulator`). Each chunk is TLV-parsed exactly once, inside the
    /// actor's receive path. Used by `Node::read`; a non-chunked read yields a
    /// single-element `Vec`.
    Read {
        node_id: u64,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<matter_interaction::ReportData>, Error>>,
    },
    /// Commission a device from a parsed setup payload; returns its node id.
    Commission {
        setup_payload: matter_commissioning::SetupPayload,
        reply: oneshot::Sender<Result<u64, Error>>,
    },
    /// Commission a device over BLE/BTP from a parsed setup payload and required
    /// network (Wi-Fi or Thread) credentials; returns its node id (feature
    /// `ble`). Runs on its own spawned task exactly like [`Command::Commission`],
    /// but the task first scans BLE, opens a BTP session, and drives
    /// `commission_ble`.
    #[cfg(feature = "ble")]
    CommissionBle {
        setup_payload: matter_commissioning::SetupPayload,
        network: matter_commissioning::NetworkCredentials,
        reply: oneshot::Sender<Result<u64, Error>>,
    },
    /// Establish a subscription to `paths` on `node_id`; returns the report
    /// receiver + `(session, exchange)` key for the `Node` to wrap.
    Subscribe {
        node_id: u64,
        paths: Vec<matter_interaction::ReadPath>,
        event_paths: Vec<matter_interaction::EventPath>,
        event_filters: Vec<matter_interaction::EventFilter>,
        min_interval: u16,
        max_interval: u16,
        reply: oneshot::Sender<Result<SubEstablished, Error>>,
    },
    /// A write/invoke that auto-handles timed interactions: if any `keys`
    /// `(cluster, id)` is in the learned timed-cache, go straight to a timed
    /// interaction; otherwise send `plain_payload`, and on a
    /// `NEEDS_TIMED_INTERACTION (0xc6)` rejection record the `keys` and transparently
    /// retry with `timed_payload`. Returns the final response bytes. (Explicit
    /// timed is [`Command::TimedRoundTrip`] via `write_timed`/`invoke_timed`.)
    Action {
        node_id: u64,
        opcode: u8, // OP_WRITE_REQUEST | OP_INVOKE_REQUEST
        plain_payload: Vec<u8>,
        timed_payload: Vec<u8>,
        keys: Vec<(u32, u32)>,
        timeout_ms: u16,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Timed round-trip: send a `TimedRequest`, await `StatusResponse(SUCCESS)`,
    /// then send `action_opcode`/`action_payload` on the SAME exchange and return
    /// its response bytes. Used by `Node::write_timed`/`invoke_timed` and the
    /// timed-escalation path of [`Command::Action`].
    TimedRoundTrip {
        node_id: u64,
        timeout_ms: u16,
        action_opcode: u8,
        action_payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Send a chunked write as N `WriteRequestMessage`s on ONE exchange. All but
    /// the last chunk carry `MoreChunkedMessages=true`; every chunk is sent
    /// reliably (MRP). The server processes the chunks and replies with a SINGLE
    /// `WriteResponseMessage` after the final chunk — there is no per-chunk
    /// app-level response (intermediate chunks are acknowledged at the MRP
    /// transport layer only). A single [`PendingReply::ChunkedWrite`] is
    /// registered on the final chunk's exchange (SH.1: one pending per
    /// `(session, exchange)`); it resolves with the `WriteResponse` bytes.
    ChunkedWrite {
        node_id: u64,
        chunks: Vec<Vec<u8>>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Return the actor's stored commissioner node id (the sole fabric's
    /// `commissioner.node_id`). Used by the ACL lockout guard, which must avoid
    /// writing an ACL that would lock the commissioner itself out.
    CommissionerNodeId {
        reply: oneshot::Sender<Result<u64, Error>>,
    },
    /// Return the sole fabric's stored CASE resumption record bytes for
    /// `node_id` (serialized [`matter_crypto::ResumptionRecord`], see
    /// [`crate::resumption`]), or `None` if the device has none. Read from the
    /// actor's live in-memory state — not the store — so a record written by a
    /// connect that JUST completed (e.g. the `serve_ota` announce) is visible
    /// without racing the offloaded persist.
    ResumptionRecordFor {
        node_id: u64,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, Error>>,
    },
    /// Store `record_bytes` as the sole fabric's CASE resumption record for
    /// `node_id` (best-effort persist). Invoked from `serve_ota` via the provider
    /// server's `record_sink`, once per completed CASE accept.
    StoreResumptionRecord {
        node_id: u64,
        record_bytes: Vec<u8>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// Persist an ICD client registration on the sole fabric (replacing any
    /// prior registration for the same node), then durably save. Used by
    /// `Node::register_icd_client` after a successful `RegisterClient`.
    PersistIcdRegistration {
        registration: crate::icd::IcdRegistration,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// Mint a fresh 16-byte group epoch key, append a
    /// [`GroupKeySetConfig`](crate::state::GroupKeySetConfig) to
    /// the sole fabric's `group_keys`, durably persist, and return the
    /// corresponding [`GroupKeySet`](crate::GroupKeySet) so the caller can
    /// program it onto devices via `Node::write_group_key_set`.
    CreateGroup {
        key_set_id: u16,
        epoch_start_time: u64,
        reply: oneshot::Sender<Result<crate::GroupKeySet, Error>>,
    },
    /// Fire-and-forget multicast group invoke. The actor derives the operational
    /// group key + session id from the persisted `key_set_id`, bumps and
    /// **persists** the fabric's outbound group counter BEFORE sending, encodes
    /// a group-secured `InvokeRequest`, and multicasts it. No pending is
    /// registered and no response is awaited (group sends are unacknowledged).
    InvokeGroup {
        group_id: u16,
        key_set_id: u16,
        path: matter_interaction::CommandPath,
        fields_tlv: Vec<u8>,
        reply: oneshot::Sender<Result<(), Error>>,
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

/// Await a blocking store save on the Tokio blocking pool.
///
/// Free function (owns its inputs) so the actor never holds a `&self` borrow
/// across the `.await`: that would make the actor future non-`Send` and so
/// unspawnable. A panic inside `save` surfaces as a `JoinError`, mapped to an
/// operational persistence error rather than unwinding the actor loop.
async fn save_offloaded(store: Arc<dyn ControllerStore>, bytes: Vec<u8>) -> Result<(), Error> {
    match tokio::task::spawn_blocking(move || store.save(&bytes)).await {
        Ok(saved) => Ok(saved?),
        Err(join_err) => Err(Error::Operational(format!(
            "persistence task failed: {join_err}"
        ))),
    }
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
    /// Attestation trust, `Arc`-wrapped so it can be cheaply shared into the
    /// spawned commission task (which runs off the actor loop — see
    /// [`Self::spawn_commission`]) without cloning the cert stores.
    trust: Option<Arc<crate::trust::AttestationTrust>>,
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
    /// Learned set of `(cluster_id, attr_or_command_id)` paths the device has
    /// rejected with `NEEDS_TIMED_INTERACTION` — a write/invoke to one of these
    /// skips the (wasted) plain attempt and goes straight to a timed interaction.
    /// Populated on a `0xc6` rejection; covers manufacturer/ungenerated clusters
    /// and survives for the controller's lifetime (the spec's B3 learned-cache).
    timed_paths: std::collections::HashSet<(u32, u32)>,
    /// Sender half of the spawned-commission completions channel (M9-G-d):
    /// cloned into each [`Self::spawn_commission`] task.
    commission_tx: mpsc::Sender<CommissionCompletion>,
    /// Receiver half, drained by an arm of the [`Self::run`] `select!`.
    commission_rx: mpsc::Receiver<CommissionCompletion>,
    /// M9-G-d event-driven connect: work waiting on an in-flight CASE connect,
    /// coalesced per device node id. A key's presence means a connect to that
    /// node is running on a spawned task; the queued [`ConnectWaiter`]s are
    /// resumed (on success) or resolved/rescheduled (on error) when it
    /// completes. See [`Self::enqueue_connect_waiter`] /
    /// [`Self::handle_connect_done`].
    pending_connects: HashMap<u64, Vec<ConnectWaiter>>,
    /// IPv6 multicast egress interface for group sends (destination scope
    /// id). Set via `MatterControllerBuilder::multicast_interface`; `None`
    /// falls back to the `MATTER_MULTICAST_IF` env var, then kernel default.
    multicast_if: Option<u32>,
    /// Per-in-flight-connect inbound queue (keyed by node id): the actor forwards
    /// the device's unsecured handshake replies here for the spawned task to
    /// consume via its [`HandshakeSocket`](crate::handshake_socket::HandshakeSocket).
    connect_inbound: HashMap<u64, mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    /// Peer-address → node-id route for in-flight handshakes. An inbound
    /// unsecured datagram from a mapped peer is a handshake reply and is
    /// forwarded to that connect. Installed when the actor sends the connect's
    /// first datagram, so it is always in place before any reply arrives.
    connect_routes: HashMap<SocketAddr, u64>,
    /// Shared outbound channel: spawned connect tasks push their handshake
    /// datagrams here; the actor sends each on its own socket (and installs the
    /// peer route). Kept on the actor so `recv` never closes.
    connect_outbound_tx: mpsc::Sender<crate::handshake_socket::HandshakeOutbound>,
    /// Receiver half, drained by an arm of the [`Self::run`] `select!`.
    connect_outbound_rx: mpsc::Receiver<crate::handshake_socket::HandshakeOutbound>,
    /// Connect-completion channel: a finished connect task hands its established
    /// session (or error) back here for registration + waiter resolution.
    connect_done_tx: mpsc::Sender<ConnectCompletion>,
    /// Receiver half, drained by an arm of the [`Self::run`] `select!`.
    connect_done_rx: mpsc::Receiver<ConnectCompletion>,
}

/// A completed spawned CASE connect (M9-G-d event-driven connect), delivered
/// back to the actor loop for session registration + waiter resolution. On
/// success it carries the established [`CaseSessionOutput`] (the actor registers
/// it — the task has no `SessionManager`) and the resolved device address.
///
/// [`CaseSessionOutput`]: matter_crypto::CaseSessionOutput
struct ConnectCompletion {
    node_id: u64,
    result: Result<(matter_crypto::CaseSessionOutput, SocketAddr), Error>,
}

/// A unit of work parked behind an in-flight CASE connect (M9-G-d). On connect
/// success each is resumed on the freshly-established `(session, peer)`; on
/// failure each is resolved/rescheduled per its kind ([`Actor::handle_connect_done`]
/// / [`Actor::fail_connect_waiters`]). This lets the two timer-arm recovery
/// reconnects share the same off-loop connect as the steady-state verb path, so
/// no CASE handshake runs inline on the actor loop.
enum ConnectWaiter {
    /// A device verb parked before dispatch (the steady-state path): re-dispatch
    /// on success (its `session_for` now cache-hits), fail its caller on error.
    Command(Command),
    /// A timed-out pending op to re-send on the fresh session (pending-retry
    /// recovery, from [`Actor::on_pending_timeout`]).
    ResendPending(Pending),
    /// A stranded subscription to re-establish on the fresh session (resubscribe
    /// recovery, from [`Actor::attempt_resubscribe`]); reschedule on failure.
    Resubscribe(PendingResubscribe),
}

/// Canonicalize a peer address for the in-flight-handshake route table (M9-G-d).
///
/// The address we *resolve* (from mDNS) and the address a datagram *arrives*
/// from can differ in representation for the same peer, so keying the route map
/// on the raw [`SocketAddr`] would miss:
/// - **IPv4-mapped IPv6:** on a dual-stack IPv6 socket, `TokioUdpTransport`
///   sends to an IPv4 peer as `::ffff:a.b.c.d` and `recv_from` reports the reply
///   `from` in that same mapped form, while the resolved `peer` is plain
///   `a.b.c.d`. Unmap so the two compare equal.
/// - **IPv6 scope id:** `recv_from` stamps a link-local `from` with the arrival
///   interface's scope id, which the resolved `peer` lacks. `IpAddr` carries no
///   scope id, so rebuilding through it drops the scope.
///
/// The port is preserved (a Matter device replies from the operational port it
/// received on), so distinct devices sharing an IP — e.g. two loopback DUTs —
/// still route independently.
fn route_key(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    };
    SocketAddr::new(ip, addr.port())
}

/// The device node id a command opens a session to, or `None` if it needs no
/// per-device session (fabric/group/ICD/diagnostic commands). Used by
/// [`Actor::dispatch`] to park a verb behind an off-loop connect (M9-G-d)
/// instead of running the handshake inline.
fn command_target_node(cmd: &Command) -> Option<u64> {
    match cmd {
        Command::Read { node_id, .. }
        | Command::Action { node_id, .. }
        | Command::TimedRoundTrip { node_id, .. }
        | Command::ChunkedWrite { node_id, .. }
        | Command::Subscribe { node_id, .. } => Some(*node_id),
        #[cfg(test)]
        Command::RoundTrip { node_id, .. } => Some(*node_id),
        _ => None,
    }
}

/// Resolve a parked verb's caller with `err` when its connect fails. Only the
/// verb variants [`command_target_node`] parks are handled; other commands are
/// never enqueued as connect waiters, so they fall through as a no-op.
fn fail_command(cmd: Command, err: Error) {
    // Arms are grouped by reply payload type (the `oneshot::Sender<Result<_,_>>`
    // differs per verb), so they cannot merge into one `|` pattern.
    match cmd {
        Command::Read { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        Command::Action { reply, .. }
        | Command::TimedRoundTrip { reply, .. }
        | Command::ChunkedWrite { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        Command::Subscribe { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        #[cfg(test)]
        Command::RoundTrip { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        _ => {}
    }
}

/// Run a CASE (SIGMA-I) handshake to an already-resolved `peer` **off the actor
/// loop** (M9-G-d), driving it over a
/// [`HandshakeSocket`](crate::handshake_socket::HandshakeSocket) whose datagrams
/// flow through the actor's own socket (this task never touches a socket).
/// Reports the established session (or error) back over `done_tx`. Takes only
/// owned inputs so the future is `'static + Send` and can be `tokio::spawn`ed.
///
/// The device is resolved on the actor via its injected discovery *before*
/// spawning ([`Actor::spawn_connect`]) — a brief bounded step that preserves the
/// discovery seam — so only the multi-round-trip handshake runs here.
#[allow(clippy::too_many_arguments)]
async fn run_connect_task(
    node_id: u64,
    fabric_id: u64,
    local_session_id: u16,
    credentials: matter_crypto::CaseCredentials,
    roots: matter_cert::TrustedRoots,
    now: matter_cert::MatterTime,
    peer: SocketAddr,
    inbound_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    outbound_tx: mpsc::Sender<crate::handshake_socket::HandshakeOutbound>,
    done_tx: mpsc::Sender<ConnectCompletion>,
) {
    let socket = crate::handshake_socket::HandshakeSocket::new(node_id, outbound_tx, inbound_rx);
    let result = matter_commissioning::driver::run_case_establish(
        &socket,
        peer,
        local_session_id,
        credentials,
        roots,
        node_id,
        fabric_id,
        now,
    )
    .await
    .map(|output| (output, peer))
    .map_err(Error::from);
    let _ = done_tx.send(ConnectCompletion { node_id, result }).await;
}

/// A completed spawned commission (M9-G-d), delivered back to the actor loop
/// over the completions channel for persistence + reply resolution.
struct CommissionCompletion {
    fabric_id: u64,
    result: Result<matter_commissioning::CommissionedFabric, Error>,
    reply: oneshot::Sender<Result<u64, Error>>,
}

/// Run a full commission on a **freshly-bound socket + discovery**, off the actor
/// loop (M9-G-d). Takes only owned inputs so the future is `'static` + `Send` and
/// can be `tokio::spawn`ed. `commission()` binds nothing itself here — the
/// transient PASE/CASE handshakes run on this task's own socket.
#[allow(clippy::too_many_arguments)]
async fn run_commission_task(
    setup_payload: matter_commissioning::SetupPayload,
    trust: Arc<crate::trust::AttestationTrust>,
    fabric_record: matter_commissioning::FabricRecord,
    commissioner_node_id: u64,
    ipk_epoch_key: [u8; 16],
    commissioner_noc: matter_cert::MatterCertificate,
    commissioner_pkcs8: Vec<u8>,
    assigned_node_id: u64,
    admin_vendor_id: u16,
    now: matter_cert::MatterTime,
    rng: Arc<dyn matter_commissioning::NocRng>,
) -> Result<matter_commissioning::CommissionedFabric, Error> {
    use matter_commissioning::driver::{commission, DriverConfig};
    use matter_commissioning::CommissionerConfig;

    let transport = matter_transport::TokioUdpTransport::bind(0)
        .await
        .map_err(|e| Error::Operational(format!("commission bind: {e}")))?;
    let mut discovery = matter_transport::MdnsSdDiscovery::new()
        .map_err(|e| Error::Operational(format!("commission mdns: {e}")))?;

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
        network: matter_commissioning::NetworkCredentials::AlreadyOnNetwork,
    };
    let config = DriverConfig {
        commissioner,
        commissionable_addr: None, // discover via mDNS using the discriminator
        passcode: setup_payload.passcode.as_u32(),
        commissioner_noc: &commissioner_noc,
        commissioner_signer_pkcs8: &commissioner_pkcs8,
    };
    commission(&transport, &mut discovery, config)
        .await
        .map_err(Error::from)
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
        Self::new_inner(
            transport,
            discovery,
            store,
            rng,
            state,
            trust,
            admin_vendor_id,
        )
    }

    /// Set the IPv6 multicast egress interface for group sends (the
    /// destination scope id). `None` falls back to `MATTER_MULTICAST_IF`,
    /// then the kernel default. See
    /// `MatterControllerBuilder::multicast_interface`.
    pub(crate) fn with_multicast_if(mut self, multicast_if: Option<u32>) -> Self {
        self.multicast_if = multicast_if;
        self
    }

    #[allow(clippy::too_many_arguments)] // mirrors `new`.
    fn new_inner(
        transport: T,
        discovery: D,
        store: Arc<dyn ControllerStore>,
        rng: Arc<dyn NocRng>,
        state: ControllerState,
        trust: Option<crate::trust::AttestationTrust>,
        admin_vendor_id: u16,
    ) -> Self {
        let (commission_tx, commission_rx) = mpsc::channel(8);
        let (connect_outbound_tx, connect_outbound_rx) = mpsc::channel(64);
        let (connect_done_tx, connect_done_rx) = mpsc::channel(8);
        Self {
            transport,
            discovery,
            sessions: SessionManager::new(),
            store,
            rng,
            state,
            cache: HashMap::new(),
            trust: trust.map(Arc::new),
            admin_vendor_id,
            subscriptions: HashMap::new(),
            pending: HashMap::new(),
            next_sub_id: 1,
            resubscribes: Vec::new(),
            timed_paths: std::collections::HashSet::new(),
            commission_tx,
            commission_rx,
            pending_connects: HashMap::new(),
            multicast_if: None,
            connect_inbound: HashMap::new(),
            connect_routes: HashMap::new(),
            connect_outbound_tx,
            connect_outbound_rx,
            connect_done_tx,
            connect_done_rx,
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
    /// ## Long handlers run off the loop (M9-G-d)
    ///
    /// The two multi-round-trip protocol flows — **commission** and **CASE
    /// connect** — no longer run inline on this task. Each is driven on a
    /// `tokio::spawn`ed task and reports back over a channel the `select!`
    /// drains, so the loop keeps servicing every other session's inbound, MRP
    /// retransmits, and subscription-liveness checks for the whole handshake
    /// window (audit item #1, resolved). Concretely:
    ///
    /// - **Commission** ([`Self::spawn_commission`]) runs on its own freshly
    ///   bound socket + discovery; on completion the device is persisted and the
    ///   caller's reply resolved ([`Self::handle_commission_completion`]).
    /// - **CASE connect** parks the triggering verb in `pending_connects` and
    ///   spawns [`run_connect_task`], whose handshake I/O flows through *this*
    ///   actor's socket via a [`HandshakeSocket`](crate::handshake_socket::HandshakeSocket):
    ///   its outbound datagrams are drained by the `connect_outbound_rx` arm
    ///   (which sends them and installs the peer route), and inbound handshake
    ///   replies are demuxed to the task by [`Self::handle_inbound`]. On
    ///   completion ([`Self::handle_connect_done`]) the session is registered and
    ///   the parked verbs re-dispatched. Because every datagram still leaves and
    ///   arrives on this socket, the session lives here from the first message —
    ///   no second socket, no session migration. The device is resolved via the
    ///   injected discovery *inline* first (a brief bounded mDNS poll — instant
    ///   when cached — kept on the actor to preserve the discovery seam).
    ///
    /// **Residual:** the two low-frequency *recovery* connects — a pending
    /// round-trip's post-timeout reconnect and a stranded subscription's
    /// resubscribe, both driven from the timer arm — still use the inline
    /// [`Self::connect`]. They briefly pause the loop; decoupling them the same
    /// way is a possible future refinement, not a steady-state concern.
    ///
    /// ## Timer fairness under sustained inbound load
    ///
    /// The `select!` is `biased`, so its arms are polled top-to-bottom and the
    /// future completes on the first ready arm. A device flooding `ReportData`
    /// keeps `recv_from()` perpetually ready. To stop that flood from starving
    /// the timer arm (which would delay MRP retransmits and subscription-liveness
    /// checks past their deadlines), the timer work is gated on an *explicit
    /// overdue check* evaluated at the top of every iteration BEFORE the
    /// `select!`: we compute the earliest moment timer work is due (the min of
    /// the next MRP deadline and the periodic liveness tick — subscription
    /// liveness is not part of `sessions.poll_timeout()`, so it is tracked
    /// separately), and whenever that moment has already passed we run
    /// [`Self::drive_mrp`]/[`Self::check_liveness`]/[`Self::drive_resubscribes`]
    /// immediately, then `continue`, regardless of how much inbound is pending.
    ///
    /// This guarantees deadlines are honoured under continuous inbound: each
    /// inbound packet costs one loop iteration, and at the start of the next
    /// iteration any deadline that came due is serviced before the next recv.
    /// It does not starve recv — the overdue path only fires when a timer is
    /// actually due (bounded by how many deadlines elapse, not by inbound rate),
    /// and otherwise we fall through to the `select!` where a ready recv is
    /// served. It does not busy-loop when idle — with no inbound and no due
    /// deadline the `select!` parks on the `sleep` until the next deadline (or
    /// `LIVENESS_TICK`). The trade-off versus simply dropping `biased` (letting
    /// tokio randomize) is determinism: the explicit check gives a hard "timers
    /// fire within one inbound-packet of their deadline" bound rather than a
    /// probabilistic one, which matters for MRP retransmit timing.
    pub(crate) async fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        // The next time the timer work is guaranteed to run even if no MRP
        // deadline is pending. Subscription-liveness deadlines and due
        // resubscribes are NOT reflected in `sessions.poll_timeout()` (that only
        // covers MRP/session timers), so the loop must wake at least every
        // `LIVENESS_TICK` to service them. We track this explicitly rather than
        // recomputing a sleep duration so the overdue guard below can also cover
        // the liveness tick under inbound pressure.
        let mut next_liveness_tick = Instant::now() + LIVENESS_TICK;
        loop {
            let now = Instant::now();
            // Earliest moment any timer work (MRP retransmit/expiry, or the
            // periodic liveness/resubscribe tick) must run.
            let next_deadline = match self.sessions.poll_timeout() {
                Some(mrp) => mrp.min(next_liveness_tick),
                None => next_liveness_tick,
            };

            // Fairness guard: if timer work is already due, service it before
            // draining any more inbound. This is what prevents a sustained
            // inbound flood (which keeps `recv_from()` perpetually ready) from
            // starving the timer arm and pushing MRP retransmits / subscription
            // liveness past their deadlines. It only fires when a deadline has
            // actually elapsed, so it cannot starve recv or busy-loop: each pass
            // either advances every MRP deadline forward (handle_timeout
            // reschedules or drops) or advances `next_liveness_tick`, so the
            // guard yields back to recv on the next iteration.
            if next_deadline <= now {
                self.drive_mrp().await;
                self.check_liveness();
                self.drive_resubscribes().await;
                next_liveness_tick = Instant::now() + LIVENESS_TICK;
                continue;
            }

            let sleep_for = next_deadline.saturating_duration_since(now);
            tokio::select! {
                biased;
                maybe = rx.recv() => match maybe {
                    Some(cmd) => self.dispatch(cmd).await,
                    None => return,
                },
                // M9-G-d: a spawned commission finished — persist + resolve its
                // reply. This arm keeps the loop responsive to other sessions
                // for the whole commission window.
                Some(completion) = self.commission_rx.recv() => {
                    self.handle_commission_completion(completion).await;
                }
                // M9-G-d event-driven connect: a spawned CASE handshake wants a
                // datagram put on the wire — the actor owns the socket, so it
                // sends it (and installs the peer route). Above the inbound arm
                // so an inbound flood cannot starve handshake progress.
                Some(out) = self.connect_outbound_rx.recv() => {
                    self.handle_connect_outbound(out).await;
                }
                // A spawned CASE connect completed — register the session (or
                // fail the parked verbs) and re-dispatch the waiters.
                Some(done) = self.connect_done_rx.recv() => {
                    self.handle_connect_done(done).await;
                }
                recv = self.transport.recv_from() => {
                    if let Ok((packet, from)) = recv {
                        self.handle_inbound(&packet, from).await;
                    }
                }
                () = tokio::time::sleep(sleep_for) => {
                    self.drive_mrp().await;
                    self.check_liveness();
                    self.drive_resubscribes().await;
                    next_liveness_tick = Instant::now() + LIVENESS_TICK;
                }
            }
        }
    }

    /// Process one command, parking device verbs behind an off-loop connect.
    ///
    /// M9-G-d: if `cmd` targets a device with no live cached session, the CASE
    /// handshake is run on a spawned task ([`Self::spawn_connect`]) and the
    /// command is queued in `pending_connects`; the actor loop returns
    /// immediately and stays responsive to every other session for the whole
    /// handshake. When the connect completes the queued verbs are re-dispatched
    /// through [`Self::dispatch_ready`] (their `session_for` now cache-hits).
    /// Commands that need no per-device session — and any verb whose session is
    /// already cached — run inline via [`Self::dispatch_ready`].
    async fn dispatch(&mut self, cmd: Command) {
        if let Some(node_id) = command_target_node(&cmd) {
            if let Ok(fabric_id) = self.sole_fabric().map(|f| f.fabric_id) {
                if !self.cache.contains_key(&(fabric_id, node_id)) {
                    self.enqueue_connect_waiter(fabric_id, node_id, ConnectWaiter::Command(cmd))
                        .await;
                    return;
                }
            }
        }
        self.dispatch_ready(cmd).await;
    }

    /// Process one command whose device session (if any) is already established.
    // A flat command dispatcher: one arm per `Command` variant, each a thin
    // delegation to a handler. Length tracks the verb count, not branching
    // complexity, so the line cap does not apply meaningfully here.
    #[allow(clippy::too_many_lines)]
    async fn dispatch_ready(&mut self, cmd: Command) {
        match cmd {
            Command::CreateFabric { cfg, reply } => {
                let _ = reply.send(self.handle_create_fabric(&cfg).await);
            }
            #[cfg(test)]
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
                // M9-G-d: spawn on its own socket + return to the loop
                // immediately; the result is resolved later via the completions
                // channel, so a multi-second commission no longer pauses other
                // sessions' MRP/liveness.
                self.spawn_commission(setup_payload, reply);
            }
            #[cfg(feature = "ble")]
            Command::CommissionBle {
                setup_payload,
                network,
                reply,
            } => {
                // Same off-loop pattern as `Command::Commission`, but the
                // spawned task scans BLE + opens a BTP session first.
                self.spawn_commission_ble(setup_payload, network, reply);
            }
            Command::Subscribe {
                node_id,
                paths,
                event_paths,
                event_filters,
                min_interval,
                max_interval,
                reply,
            } => {
                self.start_subscribe(
                    node_id,
                    paths,
                    event_paths,
                    event_filters,
                    min_interval,
                    max_interval,
                    reply,
                )
                .await;
            }
            Command::Action {
                node_id,
                opcode,
                plain_payload,
                timed_payload,
                keys,
                timeout_ms,
                reply,
            } => {
                self.handle_action(
                    node_id,
                    opcode,
                    plain_payload,
                    timed_payload,
                    keys,
                    timeout_ms,
                    reply,
                )
                .await;
            }
            Command::TimedRoundTrip {
                node_id,
                timeout_ms,
                action_opcode,
                action_payload,
                reply,
            } => {
                self.start_timed_round_trip(
                    node_id,
                    timeout_ms,
                    action_opcode,
                    action_payload,
                    reply,
                )
                .await;
            }
            Command::ChunkedWrite {
                node_id,
                chunks,
                reply,
            } => {
                self.handle_chunked_write(node_id, chunks, reply).await;
            }
            Command::CommissionerNodeId { reply } => {
                let _ = reply.send(self.sole_fabric().map(|f| f.commissioner.node_id));
            }
            Command::ResumptionRecordFor { node_id, reply } => {
                let result = self.sole_fabric().map(|f| {
                    f.devices
                        .iter()
                        .find(|d| d.node_id == node_id)
                        .and_then(|d| d.resumption_record.clone())
                });
                let _ = reply.send(result);
            }
            Command::StoreResumptionRecord {
                node_id,
                record_bytes,
                reply,
            } => {
                let _ = reply.send(self.handle_store_resumption_record(node_id, record_bytes));
            }
            Command::PersistIcdRegistration {
                registration,
                reply,
            } => {
                let _ = reply.send(self.handle_persist_icd_registration(registration).await);
            }
            Command::CreateGroup {
                key_set_id,
                epoch_start_time,
                reply,
            } => {
                let _ = reply.send(self.handle_create_group(key_set_id, epoch_start_time).await);
            }
            Command::InvokeGroup {
                group_id,
                key_set_id,
                path,
                fields_tlv,
                reply,
            } => {
                let _ = reply.send(
                    self.handle_invoke_group(group_id, key_set_id, path, &fields_tlv)
                        .await,
                );
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

    async fn handle_create_fabric(&mut self, cfg: &FabricConfig) -> Result<u64, Error> {
        let entry = crate::fabric::create_fabric(cfg, self.rng.as_ref())?;
        let fabric_id = entry.fabric_id;
        self.state.fabrics.push(entry);
        // Durability-critical: the caller must not consider the fabric created
        // (and its private keys safe) until the snapshot is on disk. Serialize
        // under `&self`, then drop the borrow before awaiting the offloaded save.
        let (store, bytes) = self.durable_save_inputs()?;
        save_offloaded(store, bytes).await?;
        Ok(fabric_id)
    }

    /// Persist an ICD client registration on the sole fabric, replacing any
    /// prior registration for the same device node, then durably save.
    async fn handle_persist_icd_registration(
        &mut self,
        registration: crate::icd::IcdRegistration,
    ) -> Result<(), Error> {
        let fabric = self.sole_fabric_mut()?;
        fabric
            .icd_clients
            .retain(|r| r.node_id != registration.node_id);
        fabric.icd_clients.push(registration);
        let (store, bytes) = self.durable_save_inputs()?;
        save_offloaded(store, bytes).await?;
        Ok(())
    }

    /// Kick off a commission on a **spawned task with its own socket** (M9-G-d).
    ///
    /// Commissioning is the longest protocol handler (PASE + attestation + CSR +
    /// NOC + operational CASE + config — multiple seconds). Running it inline on
    /// the actor loop would pause every other session's MRP retransmits and
    /// liveness for that whole window (2026-06-12 audit item #1). Instead we
    /// snapshot the owned inputs, spawn `run_commission_task` on a fresh socket,
    /// and return to the loop immediately; the result arrives later on the
    /// completions channel ([`Self::handle_commission_completion`]), which
    /// persists the device and resolves `reply`. `commission()` establishes only
    /// a transient session it does not hand back (the first post-commission
    /// invoke reconnects), so no session hand-off is needed here.
    fn spawn_commission(
        &mut self,
        setup_payload: matter_commissioning::SetupPayload,
        reply: oneshot::Sender<Result<u64, Error>>,
    ) {
        let Some(trust) = self.trust.clone() else {
            let _ = reply.send(Err(Error::NoTrust));
            return;
        };
        let admin_vendor_id = self.admin_vendor_id;
        let snapshot = match self.sole_fabric() {
            Ok(fabric) => match fabric.to_fabric_record() {
                Ok(fabric_record) => Ok((
                    fabric_record,
                    fabric.fabric_id,
                    fabric.commissioner.node_id,
                    fabric.ipk,
                    fabric.commissioner.noc.clone(),
                    fabric.commissioner.operational_pkcs8.clone(),
                    crate::commission::next_device_node_id(fabric),
                )),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        let (
            fabric_record,
            fabric_id,
            commissioner_node_id,
            ipk_epoch_key,
            commissioner_noc,
            commissioner_pkcs8,
            assigned_node_id,
        ) = match snapshot {
            Ok(s) => s,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let now = match current_matter_time() {
            Ok(n) => n,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let rng = self.rng.clone();
        let tx = self.commission_tx.clone();

        tokio::spawn(async move {
            let result = run_commission_task(
                setup_payload,
                trust,
                fabric_record,
                commissioner_node_id,
                ipk_epoch_key,
                commissioner_noc,
                commissioner_pkcs8,
                assigned_node_id,
                admin_vendor_id,
                now,
                rng,
            )
            .await;
            let _ = tx
                .send(CommissionCompletion {
                    fabric_id,
                    result,
                    reply,
                })
                .await;
        });
    }

    /// Spawn a BLE/BTP commission on its own task (feature `ble`), mirroring
    /// [`Self::spawn_commission`]: snapshot the same fabric inputs, then
    /// `tokio::spawn` [`crate::ble_commission::run_commission_ble_task`] (which
    /// constructs its own `BleCentral` — the macOS TCC point — plus BTP channel,
    /// UDP socket, and mDNS discovery). The completion is reported over the same
    /// [`CommissionCompletion`] channel as the IP path, so persistence + reply
    /// resolution reuse [`Self::handle_commission_completion`] unchanged. A
    /// btleplug-internal panic in the task drops the `reply`, surfacing to the
    /// caller as [`Error::ControllerStopped`] rather than hanging.
    #[cfg(feature = "ble")]
    fn spawn_commission_ble(
        &mut self,
        setup_payload: matter_commissioning::SetupPayload,
        network: matter_commissioning::NetworkCredentials,
        reply: oneshot::Sender<Result<u64, Error>>,
    ) {
        let Some(trust) = self.trust.clone() else {
            let _ = reply.send(Err(Error::NoTrust));
            return;
        };
        let admin_vendor_id = self.admin_vendor_id;
        let snapshot = match self.sole_fabric() {
            Ok(fabric) => match fabric.to_fabric_record() {
                Ok(fabric_record) => Ok((
                    fabric_record,
                    fabric.fabric_id,
                    fabric.commissioner.node_id,
                    fabric.ipk,
                    fabric.commissioner.noc.clone(),
                    fabric.commissioner.operational_pkcs8.clone(),
                    crate::commission::next_device_node_id(fabric),
                )),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        let (
            fabric_record,
            fabric_id,
            commissioner_node_id,
            ipk_epoch_key,
            commissioner_noc,
            commissioner_pkcs8,
            assigned_node_id,
        ) = match snapshot {
            Ok(s) => s,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let now = match current_matter_time() {
            Ok(n) => n,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let rng = self.rng.clone();
        let tx = self.commission_tx.clone();

        tokio::spawn(async move {
            let result = crate::ble_commission::run_commission_ble_task(
                setup_payload,
                trust,
                fabric_record,
                commissioner_node_id,
                ipk_epoch_key,
                commissioner_noc,
                commissioner_pkcs8,
                assigned_node_id,
                admin_vendor_id,
                now,
                rng,
                network,
            )
            .await;
            let _ = tx
                .send(CommissionCompletion {
                    fabric_id,
                    result,
                    reply,
                })
                .await;
        });
    }

    /// Handle a completed spawned commission (M9-G-d): on success persist the
    /// `DeviceEntry` + durably save, then resolve the original `reply`.
    async fn handle_commission_completion(&mut self, completion: CommissionCompletion) {
        let CommissionCompletion {
            fabric_id,
            result,
            reply,
        } = completion;
        let outcome = match result {
            Ok(commissioned) => {
                let device = crate::commission::device_entry_from_commissioned(&commissioned);
                let node_id = device.node_id;
                if let Some(fabric) = self
                    .state
                    .fabrics
                    .iter_mut()
                    .find(|f| f.fabric_id == fabric_id)
                {
                    fabric.devices.push(device);
                }
                // Durability-critical: report success only after the device
                // entry is durably persisted (same guarantee as the old inline
                // path).
                match self.durable_save_inputs() {
                    Ok((store, bytes)) => save_offloaded(store, bytes).await.map(|()| node_id),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        };
        let _ = reply.send(outcome);
    }

    /// Prepare the inputs for a durable, await-to-completion snapshot save.
    ///
    /// The actual blocking save (`File::create` + `write_all` + `fsync` +
    /// `rename` in the default [`FileStore`](crate::store::FileStore)) is run by
    /// [`save_offloaded`] on the Tokio blocking pool via
    /// [`spawn_blocking`](tokio::task::spawn_blocking), so a multi-millisecond
    /// fsync never runs on the actor task itself. The caller `await`s the
    /// returned save so it only sees success once the bytes are durable, and any
    /// [`StoreError`](crate::store::StoreError) propagates.
    ///
    /// Use this for state changes the caller relies on being durable before the
    /// operation is reported successful: fabric creation and commissioning. For
    /// best-effort updates (e.g. the per-connect address hint) use
    /// [`Self::persist_best_effort`].
    ///
    /// Returns the `(store, bytes)` to feed to [`save_offloaded`]. The split is
    /// deliberate: serializing under `&self` and awaiting the save are kept in
    /// separate statements so no borrow of the (non-`Sync`) actor is held across
    /// the `.await` — that would make the actor future non-`Send` and so
    /// unspawnable. Callers do `let (s, b) = self.durable_save_inputs()?;
    /// save_offloaded(s, b).await?;`.
    fn durable_save_inputs(&self) -> Result<(Arc<dyn ControllerStore>, Vec<u8>), Error> {
        let bytes = snapshot::serialize(&self.state)?;
        Ok((self.store.clone(), bytes))
    }

    /// Persist the snapshot best-effort, off the actor loop, without awaiting.
    ///
    /// The serialized bytes are handed to [`spawn_blocking`](tokio::task::spawn_blocking)
    /// and the join handle is dropped: the actor neither blocks on the fsync nor
    /// waits for its result. Use this only for updates a failed write may safely
    /// lose — currently just the per-connect last-known-address hint, which is a
    /// cache the controller can rebuild via mDNS. Durability-critical state must
    /// use [`Self::durable_save_inputs`] + [`save_offloaded`] (await-to-durable)
    /// instead.
    fn persist_best_effort(&self) {
        // Serialization failure here is purely best-effort state; dropping it
        // must not abort the connection that triggered it.
        let Ok(bytes) = snapshot::serialize(&self.state) else {
            return;
        };
        let store = self.store.clone();
        // Fire-and-forget: detach the blocking save. The actor loop returns
        // immediately and never observes the fsync latency or its outcome.
        // (No logging facility is wired into this crate yet; a write error is
        // silently dropped, which is acceptable for a rebuildable address cache.)
        drop(tokio::task::spawn_blocking(move || {
            let _ = store.save(&bytes);
        }));
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

    /// The sole fabric (mutable), or an error if not exactly one. Mirrors
    /// [`Self::sole_fabric`] for the group-key mutation paths.
    fn sole_fabric_mut(&mut self) -> Result<&mut crate::state::FabricEntry, Error> {
        match self.state.fabrics.as_mut_slice() {
            [one] => Ok(one),
            [] => Err(Error::NotCommissioned("no fabric created yet".into())),
            _ => Err(Error::NotCommissioned(
                "multiple fabrics; fabric(id).node(id) addressing is not in M8.2".into(),
            )),
        }
    }

    /// Mint a fresh group key set: generate a 16-byte epoch key from the CSPRNG,
    /// append a [`GroupKeySetConfig`](crate::state::GroupKeySetConfig) to the
    /// sole fabric's `group_keys`, durably persist the snapshot, and return the
    /// corresponding [`GroupKeySet`](crate::GroupKeySet) for the caller to
    /// program onto devices (`Node::write_group_key_set`).
    ///
    /// The epoch key never leaves the controller as plaintext on the wire — the
    /// returned `GroupKeySet` carries it so the caller can run the (CASE-secured)
    /// `KeySetWrite`; the key set is stored locally for outbound group encryption.
    async fn handle_create_group(
        &mut self,
        key_set_id: u16,
        epoch_start_time: u64,
    ) -> Result<crate::GroupKeySet, Error> {
        // Generate the 16-byte epoch key from the CSPRNG. The fixed-size array
        // type `[u8; 16]` guarantees the buffer is exactly 16 bytes.
        let mut epoch_key = [0u8; 16];
        matter_crypto::random_bytes(&mut epoch_key)
            .map_err(|e| Error::Operational(format!("group epoch-key generation failed: {e}")))?;

        // Append the persisted key-set config to the sole fabric.
        let fabric = self.sole_fabric_mut()?;
        fabric.group_keys.push(crate::state::GroupKeySetConfig::new(
            key_set_id,
            epoch_key,
            epoch_start_time,
        ));

        // Durability-critical: the caller relies on the key set being persisted
        // before it programs the key onto devices (so a crash mid-provision can
        // resume from a known key). Serialize under `&self`, then drop the
        // borrow before awaiting the offloaded save.
        let (store, bytes) = self.durable_save_inputs()?;
        save_offloaded(store, bytes).await?;

        Ok(crate::GroupKeySet::new(
            key_set_id,
            epoch_key.to_vec(),
            epoch_start_time,
        ))
    }

    /// Fire-and-forget multicast group invoke (see [`Command::InvokeGroup`]).
    ///
    /// Derives the operational group key + group session id from the persisted
    /// `key_set_id`, allocates the next outbound group counter and **persists it
    /// before sending** (a reused counter weakens replay protection), builds a
    /// group-secured `InvokeRequest`, and multicasts it to the group's
    /// site-local address. Returns `Ok(())` as soon as the datagram is handed to
    /// the socket — no response is awaited.
    async fn handle_invoke_group(
        &mut self,
        group_id: u16,
        key_set_id: u16,
        path: matter_interaction::CommandPath,
        fields_tlv: &[u8],
    ) -> Result<(), Error> {
        // --- Gather everything from the sole fabric into owned locals so no
        // borrow of `self` is held across the persist `.await` below. ---
        let (fabric_id, source_node_id, root_public_key, epoch_key, counter) = {
            let fabric = self.sole_fabric()?;
            // (a) Look up the epoch key for this key set.
            let epoch_key = fabric
                .group_keys
                .iter()
                .find(|k| k.key_set_id == key_set_id)
                .map(|k| k.epoch_key)
                .ok_or(Error::GroupNotProvisioned(key_set_id))?;
            // The RCAC root public key (SEC1 uncompressed) for the compressed
            // fabric id derivation (read straight off the stored root cert, as
            // the CASE credentials path does).
            let root_public_key = *fabric.rcac_cert.public_key().as_bytes();
            // (f) Allocate the counter; reject on overflow (re-key needed).
            if fabric.outbound_group_counter == u32::MAX {
                return Err(Error::Operational(
                    "group counter exhausted — re-key the group".to_string(),
                ));
            }
            (
                fabric.fabric_id,
                fabric.commissioner.node_id,
                root_public_key,
                epoch_key,
                fabric.outbound_group_counter,
            )
        };

        // (b-e) Crypto derivations (reuse E2; never hand-rolled).
        let compressed_fabric_id =
            matter_crypto::derive_compressed_fabric_id(&root_public_key, fabric_id)
                .map_err(|e| Error::Operational(format!("compressed fabric id: {e}")))?;
        let op_group_key = matter_crypto::derive_operational_ipk(&epoch_key, &compressed_fabric_id)
            .map_err(|e| Error::Operational(format!("operational group key: {e}")))?;
        let group_session_id = matter_crypto::derive_group_session_id(&op_group_key)
            .map_err(|e| Error::Operational(format!("group session id: {e}")))?;
        let mcast = matter_crypto::group_multicast_ipv6(fabric_id, group_id);

        // (f) Bump the counter and PERSIST BEFORE SENDING. A counter reused
        // after a crash would let an attacker replay an old group message, so
        // the new counter must be durable before any datagram carrying it
        // leaves the host.
        self.sole_fabric_mut()?.outbound_group_counter =
            counter.checked_add(1).ok_or_else(|| {
                Error::Operational("group counter exhausted — re-key the group".into())
            })?;
        let (store, bytes) = self.durable_save_inputs()?;
        save_offloaded(store, bytes).await?;

        // (g) Build the InvokeRequest IM payload (SuppressResponse=true — group
        // commands are unacknowledged) and a fresh-exchange protocol header.
        let payload = matter_interaction::build_invoke_request_group(path, fields_tlv);
        let mut eid = [0u8; 2];
        matter_crypto::random_bytes(&mut eid)
            .map_err(|e| Error::Operational(format!("exchange-id generation failed: {e}")))?;
        let protocol_header = ProtocolHeader {
            // The controller initiates the group exchange; no ack is piggybacked
            // (group sends are unreliable, so `ack_counter` is `None`).
            exchange_flags: matter_transport::ExchangeFlags::INITIATOR,
            opcode: crate::node::OP_INVOKE_REQUEST,
            exchange_id: u16::from_le_bytes(eid),
            protocol_id: ProtocolId::INTERACTION_MODEL,
            ack_counter: None,
        };

        // (h) Encode the group-secured wire message (reuses Task-3 framing).
        let wire = matter_transport::encode_group_secured(
            &op_group_key,
            group_session_id,
            source_node_id,
            group_id,
            counter,
            &protocol_header,
            &payload,
        )?;

        // (i) Multicast to the group address on the Matter group port (5540).
        // The transport's multicast hop limit was raised at bind time.
        // Egress interface for the admin-local `ff35:` group address: on a
        // multi-homed/macOS host the kernel resolves the outgoing interface from
        // the destination's scope id; without it the send fails with "No route
        // to host". The builder's `multicast_interface` supplies it; the
        // `MATTER_MULTICAST_IF` env var remains a compat fallback
        // (0 = kernel default).
        let scope_id = self.multicast_if.filter(|&i| i != 0).unwrap_or_else(|| {
            std::env::var("MATTER_MULTICAST_IF")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0)
        });
        let dest = SocketAddr::V6(std::net::SocketAddrV6::new(
            mcast,
            MATTER_GROUP_PORT,
            0,
            scope_id,
        ));
        self.transport
            .send_to(&wire, dest)
            .await
            .map_err(|e| Error::Operational(format!("group send: {e}")))?;

        // (j) Fire-and-forget: no pending, no MRP, no response awaited.
        Ok(())
    }

    /// Queue `waiter` behind an off-loop connect to `node_id`, starting the
    /// connect if this is the first waiter (M9-G-d). Concurrent work targeting
    /// the same not-yet-connected node coalesces onto a single handshake.
    async fn enqueue_connect_waiter(
        &mut self,
        fabric_id: u64,
        node_id: u64,
        waiter: ConnectWaiter,
    ) {
        let already_connecting = self.pending_connects.contains_key(&node_id);
        self.pending_connects
            .entry(node_id)
            .or_default()
            .push(waiter);
        if !already_connecting {
            self.spawn_connect(fabric_id, node_id).await;
        }
    }

    /// Resolve `node_id` via the actor's injected discovery, then spawn its CASE
    /// handshake on a task ([`run_connect_task`]) whose I/O flows through the
    /// actor's socket (M9-G-d). Resolution runs inline (a brief bounded mDNS
    /// poll — instant when cached — kept on the actor to preserve the discovery
    /// seam); only the multi-round-trip handshake is decoupled. On a setup or
    /// resolution failure the parked waiters are failed immediately.
    async fn spawn_connect(&mut self, fabric_id: u64, node_id: u64) {
        let creds = match self.sole_fabric() {
            Ok(fabric) => crate::credentials::operational_credentials(fabric),
            Err(e) => Err(e),
        };
        let (credentials, roots, compressed) = match creds {
            Ok(c) => c,
            Err(e) => {
                self.fail_connect_waiters(node_id, &e);
                return;
            }
        };
        let now = match current_matter_time() {
            Ok(n) => n,
            Err(e) => {
                self.fail_connect_waiters(node_id, &e);
                return;
            }
        };
        let peer = match matter_commissioning::driver::resolve_operational(
            &mut self.discovery,
            compressed,
            node_id,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                self.fail_connect_waiters(node_id, &Error::from(e));
                return;
            }
        };
        // Reserve the local session id the handshake advertises in Sigma1; the
        // actor registers the finished session under it on completion.
        let local_session_id = self.sessions.allocate_session_id().0;
        let (inbound_tx, inbound_rx) = mpsc::channel(16);
        self.connect_inbound.insert(node_id, inbound_tx);
        let outbound_tx = self.connect_outbound_tx.clone();
        let done_tx = self.connect_done_tx.clone();
        tokio::spawn(run_connect_task(
            node_id,
            fabric_id,
            local_session_id,
            credentials,
            roots,
            now,
            peer,
            inbound_rx,
            outbound_tx,
            done_tx,
        ));
    }

    /// Put a spawned connect's outbound datagram on the actor's own socket
    /// (M9-G-d). Installs the `peer` → node-id route first — before the send, so
    /// it is guaranteed present before the device's reply can arrive — then
    /// sends. The route is only installed while the connect is still live
    /// (`connect_inbound` holds its queue); a late outbound after completion is
    /// dropped without re-installing a stale route.
    async fn handle_connect_outbound(&mut self, out: crate::handshake_socket::HandshakeOutbound) {
        let crate::handshake_socket::HandshakeOutbound {
            node_id,
            bytes,
            peer,
        } = out;
        if self.connect_inbound.contains_key(&node_id) {
            self.connect_routes.insert(route_key(peer), node_id);
        }
        let _ = self.transport.send_to(&bytes, peer).await;
    }

    /// Handle a finished spawned connect (M9-G-d): tear down its routing, then
    /// on success register the established session + re-dispatch the parked
    /// verbs (their `session_for` now cache-hits), or on failure resolve each
    /// parked verb's caller with the error.
    async fn handle_connect_done(&mut self, done: ConnectCompletion) {
        let ConnectCompletion { node_id, result } = done;
        // The handshake is over: stop routing the peer's datagrams to the task.
        self.connect_inbound.remove(&node_id);
        self.connect_routes.retain(|_, n| *n != node_id);

        let (output, peer) = match result {
            Ok(ok) => ok,
            Err(e) => {
                self.fail_connect_waiters(node_id, &e);
                return;
            }
        };
        let fabric_id = match self.sole_fabric() {
            Ok(fabric) => fabric.fabric_id,
            Err(e) => {
                self.fail_connect_waiters(node_id, &e);
                return;
            }
        };

        // Mirror the inline `connect` bookkeeping: evict any prior session for
        // this node, register the fresh one, refresh the address hint + cache,
        // and rescue any subscription stranded on the replaced session.
        let old_session = self.cache.get(&(fabric_id, node_id)).map(|c| c.session_id);
        if let Some(old) = old_session {
            self.sessions.remove(old);
        }
        // Persist the fresh CASE resumption record alongside the address hint.
        // The device stores the same (id, secret) pair from this handshake, so
        // when it later initiates CASE to our provider server it will present
        // exactly this record's id. Serialization failure only costs the
        // fast-path (a later Sigma1-resume falls back to a full handshake).
        let record_bytes = output
            .resumption_record
            .as_ref()
            .and_then(|r| crate::resumption::serialize_record(r).ok());
        let sid = self.sessions.register_case(&output, SessionRole::Initiator);
        self.upsert_device(fabric_id, node_id, peer, record_bytes);
        self.cache.insert(
            (fabric_id, node_id),
            CachedSession {
                session_id: sid,
                peer,
            },
        );
        if let Some(old) = old_session {
            self.resubscribe_stranded(old);
        }

        // Resume every unit of work parked on this connect on the fresh
        // `(session, peer)`; each proceeds without blocking the loop.
        if let Some(waiters) = self.pending_connects.remove(&node_id) {
            for waiter in waiters {
                match waiter {
                    // A verb: re-dispatch — its `session_for` now cache-hits.
                    ConnectWaiter::Command(cmd) => self.dispatch_ready(cmd).await,
                    // A timed-out op: re-send on the fresh session.
                    ConnectWaiter::ResendPending(p) => {
                        self.resume_resend_pending(p, sid, peer).await;
                    }
                    // A stranded subscription: re-establish on the fresh session.
                    ConnectWaiter::Resubscribe(pr) => {
                        self.resume_resubscribe(pr, sid, peer).await;
                    }
                }
            }
        }
    }

    /// Resolve every unit of work parked on a failed connect to `node_id` and
    /// drop the connect's routing. A parked verb fails its caller, a timed-out op
    /// fails its caller, and a stranded subscription reschedules onto its backoff
    /// (chip retries a subscription forever). `Error` is not `Clone`, so each
    /// caller-facing failure gets a fresh `Error::Operational` with the text.
    fn fail_connect_waiters(&mut self, node_id: u64, err: &Error) {
        self.connect_inbound.remove(&node_id);
        self.connect_routes.retain(|_, n| *n != node_id);
        if let Some(waiters) = self.pending_connects.remove(&node_id) {
            let msg = err.to_string();
            let fail_err =
                || Error::Operational(format!("connect to node {node_id} failed: {msg}"));
            for waiter in waiters {
                match waiter {
                    ConnectWaiter::Command(cmd) => fail_command(cmd, fail_err()),
                    ConnectWaiter::ResendPending(p) => Self::fail_pending(p, fail_err()),
                    ConnectWaiter::Resubscribe(pr) => self.reschedule_resubscribe(pr),
                }
            }
        }
    }

    /// Re-send a timed-out pending op `p` on the freshly-established
    /// `(session, peer)` (M9-G-d pending-retry recovery, resumed by
    /// [`Self::handle_connect_done`]). Marks it `retried` and discards any
    /// partial read/subscribe accumulation from the first attempt; a send
    /// failure fails the op's caller.
    async fn resume_resend_pending(&mut self, p: Pending, sid: SessionId, peer: SocketAddr) {
        let sent = self
            .send_request(
                sid,
                peer,
                p.request.opcode,
                p.request.protocol_id,
                &p.request.payload,
            )
            .await;
        match sent {
            Ok(exchange) => {
                let mut np = p;
                np.peer = peer;
                np.retried = true;
                // The retry re-sends the original request, so any partial
                // accumulation from the first attempt must be discarded.
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
                        **priming = ReportReassembler::default();
                    }
                    PendingReply::RoundTrip(_)
                    | PendingReply::TimedAction { .. }
                    | PendingReply::Action { .. }
                    | PendingReply::ChunkedWrite { .. } => {}
                }
                self.pending.insert((sid, exchange), np);
            }
            Err(e) => Self::fail_pending(p, e),
        }
    }

    /// Re-establish a stranded subscription `pr` on the freshly-established
    /// `(session, peer)` (M9-G-d resubscribe recovery, resumed by
    /// [`Self::handle_connect_done`]). A send failure reschedules it on its
    /// backoff rather than dropping it.
    async fn resume_resubscribe(
        &mut self,
        pr: PendingResubscribe,
        sid: SessionId,
        peer: SocketAddr,
    ) {
        let req =
            matter_interaction::build_subscribe_request(&matter_interaction::SubscribeRequest {
                keep_subscriptions: false,
                min_interval_floor: pr.min_interval,
                max_interval_ceiling: pr.max_interval,
                paths: pr.paths.clone(),
                event_paths: pr.event_paths.clone(),
                event_filters: pr.event_filters.clone(),
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
                            priming: Box::new(ReportReassembler::default()),
                            node_id: pr.node_id,
                            paths: pr.paths,
                            event_paths: pr.event_paths,
                            event_filters: pr.event_filters,
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

    /// Establish a fresh CASE session to `node_id`, cache it, and record an
    /// address hint in persisted state. Resumption is dormant (M4.2): this
    /// always performs a full SIGMA handshake.
    ///
    /// M9-G-d: this INLINE handshake is now a defensive fallback only. Every
    /// real caller connects OFF the actor loop instead — verbs park behind
    /// [`Self::spawn_connect`] via [`Self::dispatch`], and the two timer-arm
    /// recovery reconnects (pending-retry in [`Self::on_pending_timeout`],
    /// resubscribe in [`Self::attempt_resubscribe`]) enqueue a
    /// [`ConnectWaiter`]. It survives only as the cache-miss branch of
    /// [`Self::session_for`], which those callers no longer reach with a missing
    /// session; if it ever runs it briefly blocks the loop, so it must stay
    /// unreached in normal operation.
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

        // Validate the device's operational cert chain against the real
        // wall-clock — the crypto layer never reads the system clock itself.
        let now = current_matter_time()?;
        let sid = matter_commissioning::driver::run_case(
            &self.transport,
            &mut self.sessions,
            peer,
            credentials,
            roots,
            node_id,
            fabric_id,
            now,
        )
        .await?;

        // Evict any prior session for this node from the SessionManager so its
        // dead MRP retransmits stop; we keep only the freshly-established one.
        let old_session = self.cache.get(&(fabric_id, node_id)).map(|c| c.session_id);
        if let Some(old) = old_session {
            self.sessions.remove(old);
        }
        // `run_case` registers the session internally and does not expose the
        // `CaseSessionOutput`, so this fallback path cannot persist a
        // resumption record (`None` leaves any stored record untouched).
        self.upsert_device(fabric_id, node_id, peer, None);
        self.cache.insert(
            (fabric_id, node_id),
            CachedSession {
                session_id: sid,
                peer,
            },
        );
        // Any subscription still on the now-replaced session is stranded (its
        // reports arrive on a session we just evicted). Proactively resubscribe
        // it onto the fresh session instead of waiting for its liveness deadline,
        // so a round-trip reconnect transparently re-establishes the subscription
        // too.
        if let Some(old) = old_session {
            self.resubscribe_stranded(old);
        }
        Ok((sid, peer))
    }

    /// Resubscribe every subscription still bound to `old_session` — its reports
    /// would otherwise be lost (that session was just evicted) until its own
    /// liveness deadline fires. A subscription mid-resubscribe is not in
    /// `subscriptions`, so it is not re-triggered here.
    fn resubscribe_stranded(&mut self, old_session: SessionId) {
        let stranded: Vec<SubId> = self
            .subscriptions
            .iter()
            .filter(|(_, e)| e.session_id == old_session)
            .map(|(id, _)| *id)
            .collect();
        for id in stranded {
            self.begin_resubscribe(id, Error::Operational("session replaced".into()));
        }
    }

    /// Record/refresh the device's last-known address and (when the fresh
    /// handshake produced one) its CASE resumption record in persisted state.
    /// The NOC public key stays unknown until M8.3 learns it during
    /// commissioning; this entry is an address/resumption cache only.
    ///
    /// `resumption_record` is the serialized [`matter_crypto::ResumptionRecord`]
    /// from the just-completed CASE connect (see [`crate::resumption`]). It is
    /// persisted so a peer that later initiates CASE *to us* — the OTA
    /// requestor querying our provider server — can be matched by resumption
    /// id and accepted via `CaseResponder::accept_resumption`. `None` leaves
    /// any stored record untouched (the inline fallback `connect` path, whose
    /// driver does not expose the handshake output).
    fn upsert_device(
        &mut self,
        fabric_id: u64,
        node_id: u64,
        peer: std::net::SocketAddr,
        resumption_record: Option<Vec<u8>>,
    ) {
        let addr = peer.to_string();
        // Track whether this connect actually changed persisted state. A
        // reconnect to the *same* address (the common hot-path case) leaves the
        // address hint unchanged; the resumption record, however, rotates on
        // every fresh handshake, so a connect that carries one always persists.
        let mut changed = false;
        if let Some(fabric) = self
            .state
            .fabrics
            .iter_mut()
            .find(|f| f.fabric_id == fabric_id)
        {
            if let Some(dev) = fabric.devices.iter_mut().find(|d| d.node_id == node_id) {
                if dev.last_known_addr.as_deref() != Some(addr.as_str()) {
                    dev.last_known_addr = Some(addr);
                    changed = true;
                }
                if let Some(rr) = resumption_record {
                    dev.resumption_record = Some(rr);
                    changed = true;
                }
            } else {
                fabric.devices.push(crate::state::DeviceEntry {
                    node_id,
                    peer_noc_public_key: [0u8; 65],
                    resumption_record,
                    last_known_addr: Some(addr),
                });
                changed = true;
            }
        }
        // Persistence here is best-effort and offloaded off the actor loop; a
        // write failure must not abort an otherwise-successful connection (the
        // address hint is rebuildable via mDNS, and a lost resumption record
        // only costs a full handshake later). Skip the fsync when nothing
        // changed (an unchanged reconnect on the inline fallback path).
        if changed {
            self.persist_best_effort();
        }
    }

    /// Replace the stored CASE resumption record for `node_id` on the sole
    /// fabric (best-effort persist). See [`Command::StoreResumptionRecord`].
    fn handle_store_resumption_record(
        &mut self,
        node_id: u64,
        record_bytes: Vec<u8>,
    ) -> Result<(), Error> {
        let fabric = self.sole_fabric()?;
        let fabric_id = fabric.fabric_id;
        let Some(dev) = self
            .state
            .fabrics
            .iter_mut()
            .find(|f| f.fabric_id == fabric_id)
            .and_then(|f| f.devices.iter_mut().find(|d| d.node_id == node_id))
        else {
            return Err(Error::Operational(format!(
                "no device entry for node {node_id:#x} to store a resumption record on"
            )));
        };
        dev.resumption_record = Some(record_bytes);
        self.persist_best_effort();
        Ok(())
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
    #[cfg(test)]
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

    /// Send a `TimedRequest` and register a [`PendingReply::TimedAction`] that, on
    /// the device's `StatusResponse(SUCCESS)`, sends `action_payload` on the same
    /// exchange (see [`Self::resolve_timed`]). Shared by
    /// [`Self::start_timed_round_trip`] and the timed-escalation path of a
    /// write/invoke `Action`.
    #[allow(clippy::too_many_arguments)] // the timed handshake inputs; bundling only renames them.
    async fn begin_timed(
        &mut self,
        sid: SessionId,
        peer: SocketAddr,
        node_id: u64,
        timeout_ms: u16,
        action_opcode: u8,
        action_payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    ) {
        let req = matter_interaction::build_timed_request(timeout_ms);
        match self
            .send_request(
                sid,
                peer,
                OP_TIMED_REQUEST,
                ProtocolId::INTERACTION_MODEL,
                &req,
            )
            .await
        {
            Ok(exchange) => {
                self.pending.insert(
                    (sid, exchange),
                    Pending {
                        node_id,
                        peer,
                        request: PendingRequest {
                            opcode: OP_TIMED_REQUEST,
                            protocol_id: ProtocolId::INTERACTION_MODEL,
                            payload: req,
                        },
                        retried: false,
                        reply: PendingReply::TimedAction {
                            action_opcode,
                            action_payload,
                            reply,
                        },
                    },
                );
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    /// Timed round-trip: resolve the session, then run the `TimedRequest` →
    /// action handshake (see [`Self::begin_timed`] / [`Self::resolve_timed`]).
    async fn start_timed_round_trip(
        &mut self,
        node_id: u64,
        timeout_ms: u16,
        action_opcode: u8,
        action_payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    ) {
        let (sid, peer) = match self.session_for(node_id).await {
            Ok(v) => v,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        self.begin_timed(
            sid,
            peer,
            node_id,
            timeout_ms,
            action_opcode,
            action_payload,
            reply,
        )
        .await;
    }

    /// Handle a write/invoke `Action`: consult the learned timed-cache and either
    /// go straight to a timed interaction (cache hit) or send the plain action and
    /// let [`Self::resolve_action`] retry-on-`0xc6`.
    #[allow(clippy::too_many_arguments)] // mirrors the Command::Action fields.
    async fn handle_action(
        &mut self,
        node_id: u64,
        opcode: u8,
        plain_payload: Vec<u8>,
        timed_payload: Vec<u8>,
        keys: Vec<(u32, u32)>,
        timeout_ms: u16,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    ) {
        let (sid, peer) = match self.session_for(node_id).await {
            Ok(v) => v,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        // Fast-path: a known-timed path skips the wasted plain attempt.
        if keys.iter().any(|k| self.timed_paths.contains(k)) {
            self.begin_timed(sid, peer, node_id, timeout_ms, opcode, timed_payload, reply)
                .await;
            return;
        }
        match self
            .send_request(
                sid,
                peer,
                opcode,
                ProtocolId::INTERACTION_MODEL,
                &plain_payload,
            )
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
                            payload: plain_payload,
                        },
                        retried: false,
                        reply: PendingReply::Action {
                            opcode,
                            timed_payload,
                            keys,
                            timeout_ms,
                            node_id,
                            reply,
                        },
                    },
                );
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    /// Resolve a plain write/invoke response. If the device rejected it with
    /// `NEEDS_TIMED_INTERACTION (0xc6)`, record the `keys` in the learned
    /// timed-cache and transparently retry the action as a timed interaction;
    /// otherwise resolve the caller with the response bytes.
    async fn resolve_action(&mut self, sid: SessionId, exchange: u16, payload: Vec<u8>) {
        let needs_timed = matches!(
            matter_interaction::parse_status_response(&payload),
            Ok(Some(NEEDS_TIMED_INTERACTION))
        );
        let Some(p) = self.pending.remove(&(sid, exchange)) else {
            return;
        };
        let PendingReply::Action {
            opcode,
            timed_payload,
            keys,
            timeout_ms,
            node_id,
            reply,
        } = p.reply
        else {
            return;
        };
        if !needs_timed {
            let _ = reply.send(Ok(payload));
            return;
        }
        // Learn these paths so future ops skip the wasted plain attempt, then
        // retry the action as a timed interaction feeding the same reply.
        for k in keys {
            self.timed_paths.insert(k);
        }
        self.begin_timed(
            sid,
            p.peer,
            node_id,
            timeout_ms,
            opcode,
            timed_payload,
            reply,
        )
        .await;
    }

    /// Send a `ReadRequest` and register a pending read; chunks accumulate in
    /// the pending entry and resolve on the final chunk.
    async fn start_read(
        &mut self,
        node_id: u64,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<matter_interaction::ReportData>, Error>>,
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

    /// Send a chunked write: all `chunks` go reliably on ONE exchange (mirrors
    /// [`Self::begin_timed`]'s two-messages-on-one-exchange pattern). The first
    /// chunk allocates the exchange (`encode_outbound(.., None, ..)`); every
    /// later chunk reuses it (`Some(exchange)`). All but the last carry
    /// `MoreChunkedMessages=true` (the caller built them via
    /// `build_list_write_chunks`). The server replies with ONE `WriteResponse`
    /// after the final chunk; intermediate chunks are acknowledged at the MRP
    /// transport layer only (no per-chunk app response — Matter §8.7.4 / §10.6,
    /// chip `WriteHandler` accumulates and only `SendWriteResponse` once
    /// `MoreChunkedMessages` is clear).
    ///
    /// SH.1: exactly ONE [`Pending`] is registered, keyed by the final chunk's
    /// `(session, exchange)`. The intermediate chunks are reliable sends whose
    /// MRP acks are driven by the central recv/`drive_mrp` loop — they are NOT
    /// app-level pendings, so no second pending ever shares the exchange.
    async fn handle_chunked_write(
        &mut self,
        node_id: u64,
        chunks: Vec<Vec<u8>>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    ) {
        if chunks.is_empty() {
            let _ = reply.send(Err(Error::Operational(
                "chunked_write requires at least one chunk".into(),
            )));
            return;
        }
        let (sid, peer) = match self.session_for(node_id).await {
            Ok(v) => v,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };

        // First chunk allocates the exchange; capture it so every later chunk
        // (and the final pending) rides the same one.
        let exchange = match self
            .send_request(
                sid,
                peer,
                OP_WRITE_REQUEST,
                ProtocolId::INTERACTION_MODEL,
                &chunks[0],
            )
            .await
        {
            Ok(ex) => ex,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        // Remaining chunks reuse the same exchange, reliably (MRP). The central
        // loop drives each chunk's MRP ack; we only register a pending on the
        // FINAL chunk so the single WriteResponse resolves it.
        for chunk in &chunks[1..] {
            if let Err(e) = self
                .send_on_exchange(sid, exchange, peer, OP_WRITE_REQUEST, chunk)
                .await
            {
                let _ = reply.send(Err(e));
                return;
            }
        }

        // SH.1: the single pending for this exchange — the final WriteResponse.
        // We retain the LAST chunk as the request bytes; the reconnect-once
        // retry on a stale session re-sends only the final message, which is the
        // expected behaviour for a fresh-session re-attempt (a partially-sent
        // chunked write on a dead session cannot be resumed mid-stream — the
        // device discards an incomplete chunked transaction, so re-sending the
        // whole thing would be required; we keep parity with the other verbs'
        // single-message retry and let the caller re-issue on a hard failure).
        let last = chunks.into_iter().next_back().unwrap_or_default();
        self.pending.insert(
            (sid, exchange),
            Pending {
                node_id,
                peer,
                request: PendingRequest {
                    opcode: OP_WRITE_REQUEST,
                    protocol_id: ProtocolId::INTERACTION_MODEL,
                    payload: last,
                },
                // The chunked write spans multiple reliable messages on one
                // exchange; a transparent reconnect-and-resend of only the final
                // chunk would corrupt the device's accumulation. Mark it already
                // retried so a timeout fails the op cleanly rather than re-sending
                // half a transaction onto a fresh session.
                retried: true,
                reply: PendingReply::ChunkedWrite { reply },
            },
        );
    }

    /// Route one inbound datagram: resolve a pending round-trip/read by
    /// `(session, exchange)`; deliver a steady-state `ReportData` to its
    /// subscription by `(session, subscriptionId)`; otherwise let MRP absorb it.
    async fn handle_inbound(&mut self, packet: &[u8], from: SocketAddr) {
        // Unsecured datagrams (session id 0). During an off-loop CASE connect
        // (M9-G-d) the device's handshake replies (Sigma2 / StatusReport /
        // standalone acks) arrive here from the connect's peer — forward them to
        // that spawned task via its inbound queue. Anything else is a straggler
        // we drop.
        if packet.len() >= 3 && packet[1] == 0 && packet[2] == 0 {
            if let Some(&node_id) = self.connect_routes.get(&route_key(from)) {
                if let Some(tx) = self.connect_inbound.get(&node_id) {
                    let _ = tx.send((packet.to_vec(), from)).await;
                }
            }
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
            DecodeInboundOutput::DuplicateReliableAckResent { ack_packet, .. } => {
                let _ = self.transport.send_to(&ack_packet, from).await;
            }
            // AckOnly (no app payload), and — `DecodeInboundOutput` being
            // `#[non_exhaustive]` — any future outcome: nothing to route here.
            _ => {}
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
            ChunkedWrite,
            Read,
            Subscribe,
            Timed,
            Action,
        }
        let key = (session_id, exchange_id);
        let kind = match self.pending.get(&key) {
            Some(p) => match &p.reply {
                PendingReply::RoundTrip(_) => Kind::RoundTrip,
                PendingReply::ChunkedWrite { .. } => Kind::ChunkedWrite,
                PendingReply::Read { .. } => Kind::Read,
                PendingReply::Subscribe { .. } => Kind::Subscribe,
                PendingReply::TimedAction { .. } => Kind::Timed,
                PendingReply::Action { .. } => Kind::Action,
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
            Kind::ChunkedWrite => {
                // The single WriteResponse for the whole chunked transaction.
                if let Some(PendingReply::ChunkedWrite { reply }) =
                    self.pending.remove(&key).map(|p| p.reply)
                {
                    let _ = reply.send(Ok(payload));
                }
            }
            Kind::Read => {
                let peer = self.pending.get(&key).map(|p| p.peer);
                // Parse the chunk exactly once here; `Node::read` consumes the
                // parsed structs directly (no second TLV walk). `total_bytes` is
                // accounted from the wire length before parsing.
                let chunk_len = payload.len();
                let rd = match matter_interaction::parse_report_data(&payload) {
                    Ok(rd) => rd,
                    Err(e) => {
                        // A malformed chunk fails the read, matching the old
                        // `Node::read` behaviour where re-parsing surfaced the
                        // error to the caller via `?`.
                        if let Some(PendingReply::Read { reply, .. }) =
                            self.pending.remove(&key).map(|p| p.reply)
                        {
                            let _ = reply.send(Err(Error::InteractionModel(e)));
                        }
                        return;
                    }
                };
                let more = rd.more_chunked_messages;
                let over = match self.pending.get_mut(&key).map(|p| &mut p.reply) {
                    Some(PendingReply::Read {
                        chunks,
                        total_bytes,
                        ..
                    }) => {
                        *total_bytes = total_bytes.saturating_add(chunk_len);
                        chunks.push(rd);
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
            Kind::Timed => {
                self.resolve_timed(session_id, exchange_id, payload).await;
            }
            Kind::Action => {
                self.resolve_action(session_id, exchange_id, payload).await;
            }
        }
    }

    /// Drive a timed handshake on the device's `StatusResponse` to our
    /// `TimedRequest`. On SUCCESS, send the action on the SAME exchange and
    /// convert the pending into a [`PendingReply::RoundTrip`] awaiting the action
    /// response. On a non-success/unparseable status, resolve the caller with the
    /// raw bytes so it can surface the status.
    async fn resolve_timed(&mut self, sid: SessionId, exchange: u16, payload: Vec<u8>) {
        let success = matches!(
            matter_interaction::parse_status_response(&payload),
            Ok(Some(0))
        );
        let Some(p) = self.pending.remove(&(sid, exchange)) else {
            return;
        };
        let PendingReply::TimedAction {
            action_opcode,
            action_payload,
            reply,
        } = p.reply
        else {
            return;
        };
        if !success {
            // The device rejected the TimedRequest (e.g. TIMED_REQUEST_MISMATCH)
            // or sent an unexpected message — hand the bytes back to the caller.
            let _ = reply.send(Ok(payload));
            return;
        }
        if let Err(e) = self
            .send_on_exchange(sid, exchange, p.peer, action_opcode, &action_payload)
            .await
        {
            let _ = reply.send(Err(e));
            return;
        }
        // Await the action's response on the same exchange as a normal round-trip.
        self.pending.insert(
            (sid, exchange),
            Pending {
                node_id: p.node_id,
                peer: p.peer,
                request: PendingRequest {
                    opcode: action_opcode,
                    protocol_id: ProtocolId::INTERACTION_MODEL,
                    payload: action_payload,
                },
                retried: true, // mid-handshake; do not trigger the reconnect-once dance
                reply: PendingReply::RoundTrip(reply),
            },
        );
    }

    /// Send `payload` (opcode `opcode`) on an EXISTING exchange — reuses the wire
    /// exchange id via `encode_outbound(.., Some(exchange), ..)`, exactly like
    /// [`Self::send_chunk_ack`]. Reliable. Sends the Write/Invoke half of a timed
    /// interaction on the same exchange as the preceding `TimedRequest`.
    async fn send_on_exchange(
        &mut self,
        sid: SessionId,
        exchange: u16,
        peer: SocketAddr,
        opcode: u8,
        payload: &[u8],
    ) -> Result<(), Error> {
        let out = self.sessions.encode_outbound(
            sid,
            Some(exchange),
            opcode,
            ProtocolId::INTERACTION_MODEL,
            payload,
            MrpFlags { reliable: true },
            Instant::now(),
        )?;
        self.transport
            .send_to(&out.wire_bytes, peer)
            .await
            .map_err(|e| Error::Operational(format!("timed action send: {e}")))?;
        Ok(())
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
        let Ok(mut rd) = matter_interaction::parse_report_data(payload) else {
            return;
        };
        let Some(wire_sub_id) = rd.subscription_id else {
            return; // steady-state reports must carry a subscriptionId
        };
        let now = Instant::now();
        let Some((sub_id, entry)) = self
            .subscriptions
            .iter_mut()
            .find(|(_, e)| e.session_id == session_id && e.wire_sub_id == wire_sub_id)
        else {
            return;
        };
        entry.liveness_deadline =
            now + std::time::Duration::from_secs(u64::from(entry.max_interval)) + LIVENESS_GRACE;
        let peer = entry.peer;
        // Events have no merge semantics — forward them immediately, bypassing the
        // attribute reassembler. Take them out before `push_parsed` consumes `rd`.
        // Both the event loop and `push_parsed` borrow `entry` mutably, so the
        // event forwarding completes before the reassembler call.
        let mut consumer_gone = false;
        for ev in std::mem::take(&mut rd.events) {
            // try_send_event: never blocks the actor loop; a full buffer drops +
            // counts (coalesced `Lagged`), a closed receiver reaps the sub.
            if !entry.tx.try_send_event(ev) {
                consumer_gone = true;
                break;
            }
        }
        // `rd` was parsed once above (to read its `subscription_id`); hand the
        // parsed struct straight to the reassembler rather than re-parsing the
        // same bytes inside `push`.
        if !consumer_gone {
            if let Some(attrs) = entry.reassembler.push_parsed(rd) {
                for (path, value) in attrs {
                    // try_send: never blocks the actor loop. A full buffer drops the
                    // report and counts it (surfaced later as a coalesced `Lagged`);
                    // a closed receiver means the consumer is gone — reap the sub.
                    if !entry.tx.try_send_report(AttributeReport { path, value }) {
                        consumer_gone = true;
                        break;
                    }
                }
            }
        }
        if consumer_gone {
            let sub_id = *sub_id;
            self.subscriptions.remove(&sub_id);
            return;
        }
        let _ = self.send_status_ack(session_id, exchange_id, peer).await;
    }

    /// Send a `SubscribeRequest` and register a pending subscribe handshake. The
    /// report receiver is handed back via `reply` once the `SubscribeResponse`
    /// arrives (see [`Self::resolve_subscribe`]); priming reports that precede it
    /// flow through the same channel.
    // Mirrors the `Command::Subscribe` variant's fields one-for-one; bundling them
    // into a params struct would only move the same set behind one name.
    #[allow(clippy::too_many_arguments)]
    async fn start_subscribe(
        &mut self,
        node_id: u64,
        paths: Vec<matter_interaction::ReadPath>,
        event_paths: Vec<matter_interaction::EventPath>,
        event_filters: Vec<matter_interaction::EventFilter>,
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
                event_paths: event_paths.clone(),
                event_filters: event_filters.clone(),
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
                // Bounded report channel + reliable control channel. The bounded
                // cap is the memory-DoS guard; control events bypass it.
                let (report_tx, report_rx) =
                    mpsc::channel::<SubscriptionEvent>(SUBSCRIPTION_CHANNEL_CAP);
                let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<SubscriptionEvent>();
                let report_tx = ReportSink {
                    report_tx,
                    ctrl_tx,
                    dropped: 0,
                };
                let report_rx = SubReceivers { report_rx, ctrl_rx };
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
                            priming: Box::new(ReportReassembler::default()),
                            node_id,
                            paths,
                            event_paths,
                            event_filters,
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
                // Parse the priming chunk once and merge the parsed struct.
                let Ok(mut rd) = matter_interaction::parse_report_data(&payload) else {
                    return;
                };
                // Priming events bypass the reassembler too — forward immediately.
                for ev in std::mem::take(&mut rd.events) {
                    if !report_tx.try_send_event(ev) {
                        break;
                    }
                }
                if let Some(attrs) = priming.push_parsed(rd) {
                    for (path, value) in attrs {
                        // Priming reports are bounded the same way as steady-state
                        // ones: try_send, drop+count on a full buffer.
                        if !report_tx.try_send_report(AttributeReport { path, value }) {
                            break;
                        }
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
                event_paths,
                event_filters,
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
                    // Signal (re-)establishment to the consumer on the reliable
                    // control channel BEFORE inserting, so we can reap on a dead
                    // receiver. Control events are never dropped by report
                    // backpressure (chip's OnSubscriptionEstablished). Any priming
                    // Reports already flowed — they precede the SubscribeResponse
                    // on the wire. If the consumer's receiver is already gone (a
                    // resubscribe raced a cancel/Drop), do not insert a zombie
                    // SubEntry that resubscribes forever.
                    if !report_tx.send_control(SubscriptionEvent::Established {
                        subscription_id: resp.subscription_id,
                    }) {
                        return;
                    }
                    self.subscriptions.insert(
                        sub_id,
                        SubEntry {
                            tx: report_tx,
                            peer: p.peer,
                            reassembler: ReportReassembler::default(),
                            session_id,
                            wire_sub_id: resp.subscription_id,
                            node_id,
                            paths,
                            event_paths,
                            event_filters,
                            min_interval,
                            max_interval: resp.max_interval,
                            liveness_deadline: deadline,
                        },
                    );
                    // Initial subscribe hands the receivers back; a resubscribe
                    // (reply/report_rx None) reuses the consumer's existing ones.
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
                // `MrpEvent` is `#[non_exhaustive]`; ignore future timer
                // events in the controller's MRP pump.
                _ => {}
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
                event_paths,
                event_filters,
                min_interval,
                max_interval,
                retry_count,
                ..
            } = p.reply
            {
                // The attempt timed out — the cached session is likely dead (most
                // commonly a device reboot, which invalidates CASE). Evict it so
                // the next attempt forces a fresh handshake; otherwise we would
                // retry forever on a session the device can no longer decrypt.
                // Only evict if the cache still holds the *expired* session; a
                // sibling timeout may already have replaced it with a fresh
                // healthy session, which we must not tear down (see the
                // round-trip branch below for the full rationale).
                if let Ok(fabric_id) = self.sole_fabric().map(|f| f.fabric_id) {
                    if self
                        .cache
                        .get(&(fabric_id, node_id))
                        .is_some_and(|c| c.session_id == session_id)
                    {
                        if let Some(old) = self.cache.remove(&(fabric_id, node_id)) {
                            self.sessions.remove(old.session_id);
                        }
                    }
                }
                self.reschedule_resubscribe(PendingResubscribe {
                    sub_id,
                    attempt_at: Instant::now(),
                    node_id,
                    paths,
                    event_paths,
                    event_filters,
                    min_interval,
                    max_interval,
                    retry_count,
                    tx: report_tx,
                });
            }
            return;
        }
        if !p.retried {
            let Ok(fabric_id) = self.sole_fabric().map(|f| f.fabric_id) else {
                Self::fail_pending(p, Error::Operational("round-trip timed out".into()));
                return;
            };
            // Only evict if the cache still holds the *expired* session. A
            // sibling op may have already timed out, evicted it, reconnected, and
            // cached a fresh healthy session under this node — dropping that here
            // would force a redundant CASE handshake and churn every subscription
            // just bound to the new session.
            if self
                .cache
                .get(&(fabric_id, p.node_id))
                .is_some_and(|c| c.session_id == session_id)
            {
                self.cache.remove(&(fabric_id, p.node_id));
            }
            // M9-G-d: re-send on a cached fresh session if a sibling already
            // reconnected, else reconnect OFF the actor loop (the handshake no
            // longer blocks other sessions) and re-send on completion.
            if let Some((sid, peer)) = self
                .cache
                .get(&(fabric_id, p.node_id))
                .map(|c| (c.session_id, c.peer))
            {
                self.resume_resend_pending(p, sid, peer).await;
            } else {
                self.enqueue_connect_waiter(fabric_id, p.node_id, ConnectWaiter::ResendPending(p))
                    .await;
            }
            return;
        }
        Self::fail_pending(p, Error::Operational("round-trip timed out".into()));
    }

    /// Resolve a pending op's reply channel with an error.
    fn fail_pending(p: Pending, err: Error) {
        match p.reply {
            PendingReply::RoundTrip(reply)
            | PendingReply::TimedAction { reply, .. }
            | PendingReply::Action { reply, .. }
            | PendingReply::ChunkedWrite { reply } => {
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
        // If the consumer dropped its receiver, reap the subscription instead of
        // resubscribing forever (closes the zombie-SubEntry window when a cancel
        // races an in-flight resubscribe, or the Drop cancel was lost). Sent on
        // the reliable control channel so it is never dropped by report backpressure.
        if !entry
            .tx
            .send_control(SubscriptionEvent::Resubscribing { cause })
        {
            return;
        }
        let wait = resubscribe_backoff(self.rng.as_ref(), 0);
        self.resubscribes.push(PendingResubscribe {
            sub_id,
            attempt_at: Instant::now() + wait,
            node_id: entry.node_id,
            paths: entry.paths,
            event_paths: entry.event_paths,
            event_filters: entry.event_filters,
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

    /// One resubscribe attempt: send a fresh `SubscribeRequest` on the node's
    /// cached session and register a pending Subscribe (no oneshot reply) so the
    /// central demux drives the handshake. If the node is not connected, reconnect
    /// OFF the actor loop (M9-G-d — the CASE handshake no longer blocks other
    /// sessions) and resume on completion; a missing fabric reschedules on backoff.
    async fn attempt_resubscribe(&mut self, pr: PendingResubscribe) {
        let Ok(fabric_id) = self.sole_fabric().map(|f| f.fabric_id) else {
            self.reschedule_resubscribe(pr);
            return;
        };
        if let Some((sid, peer)) = self
            .cache
            .get(&(fabric_id, pr.node_id))
            .map(|c| (c.session_id, c.peer))
        {
            self.resume_resubscribe(pr, sid, peer).await;
        } else {
            self.enqueue_connect_waiter(fabric_id, pr.node_id, ConnectWaiter::Resubscribe(pr))
                .await;
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
pub(crate) fn current_matter_time() -> Result<matter_cert::MatterTime, Error> {
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
            issue_icac: false,
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

    /// Loopback acceptance for the multicast group send.
    ///
    /// Drive `create_group` + `invoke_group`, capture the multicast frame the
    /// transport emits (the paired `InMemoryDatagram` endpoint receives every
    /// `send_to` regardless of destination), then DECODE it with
    /// `decode_group_secured` and the SAME operational group key (derived the
    /// same way from the persisted fabric + epoch key). Assert the recovered IM
    /// payload is the expected `InvokeRequest`, and the group header
    /// flags / group-id / source-node-id are correct.
    #[tokio::test]
    async fn invoke_group_emits_decodable_multicast_frame() {
        use matter_codec::{Tag, TlvReader, Value};
        use matter_transport::{decode_group_secured, DestNodeId, NodeId, SecuredMessageFlags};

        let store = Arc::new(MemStore::default());
        let (io, peer) = InMemoryDatagram::pair();
        let controller = crate::controller::MatterController::with_components(
            store.clone(),
            io,
            NullDiscovery,
            Arc::new(matter_commissioning::SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        let fabric_id = controller
            .create_fabric(cfg())
            .await
            .expect("create_fabric");

        // 1. Mint a group key set.
        let key_set_id = 0x0042u16;
        let group_key = controller
            .create_group(key_set_id, 0)
            .await
            .expect("create_group");
        assert_eq!(group_key.key_set_id, key_set_id);
        assert_eq!(group_key.epoch_key.len(), 16, "epoch key must be 16 bytes");

        // The create_group save must have persisted the key set.
        let snap = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(snap.fabrics[0].group_keys.len(), 1);
        assert_eq!(snap.fabrics[0].outbound_group_counter, 0);
        let commissioner_node_id = snap.fabrics[0].commissioner.node_id;
        let root_public_key = *snap.fabrics[0].rcac_cert.public_key().as_bytes();
        let epoch_key: [u8; 16] = group_key.epoch_key.clone().try_into().unwrap();

        // 2. Fire-and-forget group invoke: OnOff.On (cluster 0x0006, cmd 0x01).
        let group_id = 0xBEEFu16;
        let path = crate::CommandPath {
            endpoint: 0,
            cluster: 0x0006,
            command: 0x01,
        };
        let fields = Value::Structure(vec![]); // OnOff.On has no fields
        controller
            .invoke_group(group_id, key_set_id, path, fields.clone())
            .await
            .expect("invoke_group");

        // The counter must have been bumped AND persisted BEFORE the send.
        let snap2 = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(
            snap2.fabrics[0].outbound_group_counter, 1,
            "counter must be persisted (bumped) before send"
        );

        // 3. Capture the multicast frame on the paired endpoint.
        let (wire, _from) = peer.recv_from().await.expect("frame emitted");

        // 4. Derive the SAME operational group key the actor used.
        let compressed = derive_compressed_fabric_id(&root_public_key, fabric_id).unwrap();
        let op_group_key = derive_operational_ipk(&epoch_key, &compressed).unwrap();

        // 5. Decode the group-secured frame.
        let (header, plaintext) = decode_group_secured(&wire, &op_group_key).expect("decode group");

        // Group header: SOURCE_PRESENT | DEST_GROUP, the group id, and our node id.
        assert!(header.flags.contains(SecuredMessageFlags::SOURCE_PRESENT));
        assert!(header.flags.contains(SecuredMessageFlags::DEST_GROUP));
        assert_eq!(header.source_node_id, Some(NodeId(commissioner_node_id)));
        assert_eq!(
            header.destination_node_id,
            Some(DestNodeId::Group(group_id))
        );
        // Counter on the wire is the pre-bump value (0); the persisted counter is 1.
        assert_eq!(header.message_counter.0, 0);

        // 6. plaintext = protocol header || InvokeRequest. Strip + check opcode.
        let (ph, app) = matter_transport::decode_protocol_header(&plaintext).unwrap();
        assert_eq!(ph.opcode, crate::node::OP_INVOKE_REQUEST);
        assert_eq!(ph.protocol_id, ProtocolId::INTERACTION_MODEL);

        // The IM payload is exactly the group InvokeRequest builder output.
        let fields_tlv = crate::node::value_to_tlv(&fields).unwrap();
        let expected = matter_interaction::build_invoke_request_group(path, &fields_tlv);
        assert_eq!(app, &expected[..], "IM payload must be the InvokeRequest");

        // And it parses structurally to the expected command path.
        let (_t, msg) = TlvReader::new(app).read_value().unwrap();
        let Value::Structure(members) = msg else {
            panic!("InvokeRequest is a structure")
        };
        // SuppressResponse (t0) must be true for a group invoke.
        assert_eq!(
            members
                .iter()
                .find(|(t, _)| *t == Tag::Context(0))
                .map(|(_, v)| v),
            Some(&Value::Bool(true))
        );
        // InvokeRequests array (t2) → first CommandDataIB → CommandPath (t0 list).
        let invoke_requests = members
            .iter()
            .find(|(t, _)| *t == Tag::Context(2))
            .map(|(_, v)| v)
            .unwrap();
        let Value::Array(command_list) = invoke_requests else {
            panic!("InvokeRequests is an array")
        };
        let Value::Structure(first_command) = &command_list[0] else {
            panic!("CommandDataIB is a structure")
        };
        let cmd_path = first_command
            .iter()
            .find(|(t, _)| *t == Tag::Context(0))
            .map(|(_, v)| v)
            .unwrap();
        let Value::List(path_members) = cmd_path else {
            panic!("CommandPath is a list")
        };
        // endpoint t0 = 0, cluster t1 = 0x0006, command t2 = 0x01.
        assert_eq!(path_members[0], (Tag::Context(0), Value::Uint(0)));
        assert_eq!(path_members[1], (Tag::Context(1), Value::Uint(0x0006)));
        assert_eq!(path_members[2], (Tag::Context(2), Value::Uint(0x01)));
    }

    /// `invoke_group` with an unprovisioned key set is rejected up front.
    #[tokio::test]
    async fn invoke_group_unprovisioned_key_set_errors() {
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
        controller
            .create_fabric(cfg())
            .await
            .expect("create_fabric");

        let path = crate::CommandPath {
            endpoint: 0,
            cluster: 0x0006,
            command: 0x01,
        };
        let err = controller
            .invoke_group(0xBEEF, 0x0099, path, matter_codec::Value::Structure(vec![]))
            .await
            .expect_err("must reject unprovisioned key set");
        assert!(matches!(err, Error::GroupNotProvisioned(0x0099)));
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
            vec![MatterService::new(
                self.instance_name.clone(),
                ServiceKind::Operational,
                vec![self.addr.ip()],
                self.addr.port(),
                std::collections::HashMap::new(),
            )]
        }
    }

    /// Device side: complete the CASE handshake (unsecured Sigma framing,
    /// mirroring `matter-commissioning`'s `run_case` loopback test), then
    /// answer `echoes` secured IM round-trips with a `b"pong"` `ReportData`.
    /// Build a [`ReportSink`] wired to fresh consumer receivers, mirroring what
    /// `start_subscribe` constructs (bounded report channel + reliable control
    /// channel). Returns the sink and both receivers for assertions.
    fn test_report_sink() -> (
        ReportSink,
        mpsc::Receiver<SubscriptionEvent>,
        mpsc::UnboundedReceiver<SubscriptionEvent>,
    ) {
        let (report_tx, report_rx) = mpsc::channel::<SubscriptionEvent>(SUBSCRIPTION_CHANNEL_CAP);
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<SubscriptionEvent>();
        (
            ReportSink {
                report_tx,
                ctrl_tx,
                dropped: 0,
            },
            report_rx,
            ctrl_rx,
        )
    }

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

    /// Build a `ReportDataMessage` carrying one `eventReports[2]` entry: an
    /// `EventData` for `(ep, cl, ev)` with the given event number and payload.
    /// Mirrors the matter.js `report_data_event.json` fixture shape
    /// (`EventPathIB` is a list; `EventDataIB` tags path 0 / number 1 /
    /// priority 2 / epoch 3 / data 7).
    fn build_report_data_event(
        ep: u16,
        cl: u32,
        ev: u32,
        event_number: u64,
        value: &matter_codec::Value,
    ) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap(); // ReportDataMessage
        w.put_uint(Tag::Context(0), 0x1234_5678).unwrap(); // subscriptionId (steady-state)
        w.start_array(Tag::Context(2)).unwrap(); // eventReports
        w.start_structure(Tag::Anonymous).unwrap(); // EventReportIB
        w.start_structure(Tag::Context(1)).unwrap(); // EventData
        w.start_list(Tag::Context(0)).unwrap(); // Path (EventPathIB list)
        w.put_uint(Tag::Context(1), u64::from(ep)).unwrap();
        w.put_uint(Tag::Context(2), u64::from(cl)).unwrap();
        w.put_uint(Tag::Context(3), u64::from(ev)).unwrap();
        w.end_container().unwrap(); // /Path
        w.put_uint(Tag::Context(1), event_number).unwrap(); // EventNumber
        w.put_uint(Tag::Context(2), 2).unwrap(); // Priority = Critical
        w.put_uint(Tag::Context(3), 0).unwrap(); // EpochTimestamp
        w.write_value(Tag::Context(7), value).unwrap(); // Data
        w.end_container().unwrap(); // /EventData
        w.end_container().unwrap(); // /EventReportIB
        w.end_container().unwrap(); // /eventReports
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
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
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();

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
    #[allow(clippy::too_many_arguments)] // test harness; one more flag than the verbs it exercises.
    async fn run_loopback_device(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        echoes: usize,
        reply_payload: Vec<u8>,
        expect_timed: bool,
    ) {
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();

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
        // Timed interaction: the first inbound is a TimedRequest (opcode 0x0a);
        // ack it with StatusResponse(SUCCESS) on the same exchange. The following
        // action (Write/Invoke) then arrives on that exchange and is answered by
        // the echo loop below — exactly the chip TimedHandler flow.
        if expect_timed {
            let (wire, _) = io.recv_from().await.unwrap();
            let decoded = sessions.decode_inbound(&wire, Instant::now()).unwrap();
            let DecodeInboundOutput::AppMessage {
                exchange_id,
                opcode,
                ..
            } = decoded
            else {
                panic!("expected a TimedRequest app message");
            };
            assert_eq!(opcode, 0x0a, "expected TimedRequest opcode 0x0a");
            let status = matter_interaction::build_status_response(0);
            let out = sessions
                .encode_outbound(
                    sid,
                    Some(exchange_id),
                    0x01, // StatusResponse
                    ProtocolId::INTERACTION_MODEL,
                    &status,
                    MrpFlags { reliable: false },
                    Instant::now(),
                )
                .unwrap();
            io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        }
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

    /// Device side of one timed handshake: ack a `TimedRequest` (0x0a) with
    /// `StatusResponse(SUCCESS)`, then reply `write_response` (0x07) to the timed
    /// `WriteRequest` (0x06). Both replies reuse the inbound exchange.
    async fn ack_timed_then_reply(
        io: &InMemoryDatagram,
        sessions: &mut SessionManager,
        sid: SessionId,
        ctrl_addr: std::net::SocketAddr,
        write_response: &[u8],
    ) {
        let (w, _) = io.recv_from().await.unwrap();
        let DecodeInboundOutput::AppMessage {
            exchange_id,
            opcode,
            ..
        } = sessions.decode_inbound(&w, Instant::now()).unwrap()
        else {
            panic!("expected a TimedRequest app message");
        };
        assert_eq!(opcode, 0x0a, "expected TimedRequest opcode 0x0a");
        let status = matter_interaction::build_status_response(0);
        let out = sessions
            .encode_outbound(
                sid,
                Some(exchange_id),
                0x01,
                ProtocolId::INTERACTION_MODEL,
                &status,
                MrpFlags { reliable: false },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();

        let (w2, _) = io.recv_from().await.unwrap();
        let DecodeInboundOutput::AppMessage {
            exchange_id: e2,
            opcode: op2,
            ..
        } = sessions.decode_inbound(&w2, Instant::now()).unwrap()
        else {
            panic!("expected a timed WriteRequest app message");
        };
        assert_eq!(op2, 0x06, "expected timed WriteRequest opcode 0x06");
        let out2 = sessions
            .encode_outbound(
                sid,
                Some(e2),
                0x07,
                ProtocolId::INTERACTION_MODEL,
                write_response,
                MrpFlags { reliable: false },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out2.wire_bytes, ctrl_addr).await.unwrap();
    }

    /// Device exercising timed auto-upgrade: cycle 1 rejects the plain
    /// `WriteRequest` with `StatusResponse(0xc6)` then completes the timed
    /// handshake; cycle 2 expects a `TimedRequest` FIRST — proving the
    /// controller's learned cache skipped the plain attempt.
    async fn run_timed_retry_device(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        write_response: Vec<u8>,
    ) {
        // --- CASE handshake (identical to run_loopback_device) ---
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();
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

        // Cycle 1: reject the plain WriteRequest (0x06) with 0xc6.
        let (w, _) = io.recv_from().await.unwrap();
        let DecodeInboundOutput::AppMessage {
            exchange_id,
            opcode,
            ..
        } = sessions.decode_inbound(&w, Instant::now()).unwrap()
        else {
            panic!("expected a plain WriteRequest app message");
        };
        assert_eq!(opcode, 0x06, "cycle 1 must start with a plain WriteRequest");
        let reject = matter_interaction::build_status_response(0xc6);
        let out = sessions
            .encode_outbound(
                sid,
                Some(exchange_id),
                0x01,
                ProtocolId::INTERACTION_MODEL,
                &reject,
                MrpFlags { reliable: false },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        // ... then the controller escalates to a timed interaction.
        ack_timed_then_reply(&io, &mut sessions, sid, ctrl_addr, &write_response).await;

        // Cycle 2: the path is cached → the controller skips the plain attempt and
        // sends a TimedRequest first.
        ack_timed_then_reply(&io, &mut sessions, sid, ctrl_addr, &write_response).await;
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
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();
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
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();
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
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();
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
                issue_icac: false,
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
            false,
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

        // The completed connect must have stored the device's CASE resumption
        // record (id + 32-byte ECDH secret) in actor state — the provider
        // server later matches the device's Sigma1-resume against it.
        let record = controller
            .resumption_record_for(device_node_id)
            .await
            .expect("fetch resumption record")
            .expect("connect must persist a resumption record");
        assert_eq!(record.peer.node_id, device_node_id);

        device.await.unwrap();
    }

    /// M9-G-d route-key normalization (regression guard for the bug the live
    /// DUT surfaced): the address a handshake reply arrives *from* and the
    /// address we *resolved + sent to* must map to the same route key, or the
    /// device's Sigma2 is dropped and the handshake starves. Covers the two
    /// real-world forms: IPv4-mapped-IPv6 (dual-stack send) and an IPv6 scope id
    /// stamped onto the arrival address.
    #[test]
    fn route_key_unifies_mapped_ipv4_and_strips_scope() {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

        // A resolved IPv4 peer vs the same peer as recv_from reports it on a
        // dual-stack IPv6 socket (`::ffff:a.b.c.d`) must share a route key.
        let resolved: SocketAddr = (Ipv4Addr::new(192, 0, 2, 7), 5540).into();
        let arrived_mapped = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped()),
            5540,
        );
        assert_eq!(route_key(resolved), route_key(arrived_mapped));
        assert_eq!(
            route_key(resolved),
            resolved,
            "canonical form is the IPv4 one"
        );

        // A link-local IPv6 peer with no scope (resolved) vs the same address
        // stamped with an arrival-interface scope id (recv_from) must match.
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1d42);
        let resolved_v6 = SocketAddr::V6(SocketAddrV6::new(ll, 5540, 0, 0));
        let arrived_scoped = SocketAddr::V6(SocketAddrV6::new(ll, 5540, 0, 7));
        assert_eq!(route_key(resolved_v6), route_key(arrived_scoped));

        // Distinct devices sharing an IP but on different ports stay distinct.
        let a: SocketAddr = (Ipv4Addr::LOCALHOST, 5540).into();
        let b: SocketAddr = (Ipv4Addr::LOCALHOST, 5541).into();
        assert_ne!(route_key(a), route_key(b));
    }

    /// M9-G-d headline: a verb-triggered CASE connect runs its handshake **off
    /// the actor loop**, so a stalled handshake no longer starves other work.
    ///
    /// The device receives Sigma1 and never answers, so the connect's handshake
    /// stalls (retransmits Sigma1, eventually times out — seconds). We fire a
    /// round-trip at that device (which parks behind the connect) and then, while
    /// the handshake is stalled, issue an unrelated `session_count` command. It
    /// must be serviced promptly. On the pre-G-d inline design the connect ran on
    /// the actor task itself, so `session_count` would be blocked behind the
    /// whole stalled handshake and this 1s timeout would fire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_handshake_runs_off_loop_which_stays_responsive() {
        let Harness {
            store,
            ctrl_io,
            dev_io,
            discovery,
            device_node_id,
            ..
        } = loopback_harness();

        // Device that swallows Sigma1 and then goes quiet — the handshake stalls.
        let device = tokio::spawn(async move {
            let _ = dev_io.recv_from().await; // consume Sigma1, answer nothing
            tokio::time::sleep(std::time::Duration::from_secs(3)).await; // keep the endpoint alive
        });

        let controller = crate::controller::MatterController::with_components(
            store,
            ctrl_io,
            discovery,
            Arc::new(SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        // Fire a round-trip at the un-connected device; it parks behind the
        // stalled off-loop handshake and will not resolve until that fails.
        let node = controller.node(device_node_id);
        let parked = tokio::spawn(async move {
            let _ = node
                .round_trip(0x02, ProtocolId::INTERACTION_MODEL, b"ping".to_vec())
                .await;
        });

        // Despite the stalled handshake, an unrelated command is serviced fast.
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            controller.session_count(),
        )
        .await
        .expect("session_count must return while a connect handshake is stalled");
        assert_eq!(count, 0, "the stalled connect established no session");

        parked.abort();
        device.abort();
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
            false,
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
    async fn read_events_returns_event_report_over_loopback() {
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

        // The device answers the event read with a ReportData carrying one
        // EventData: BasicInformation.StartUp (0x28 / event 0x00) on ep 0.
        let report_blob = build_report_data_event(0, 0x28, 0x00, 1, &matter_codec::Value::Uint(7));
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D2,
            1,
            report_blob,
            false,
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
        let events = node
            .read_events(
                &[matter_interaction::EventPath::concrete(0, 0x28, 0x00)],
                &[],
            )
            .await
            .expect("read_events");

        assert_eq!(events.len(), 1);
        match &events[0] {
            matter_interaction::EventReport::Data(it) => {
                assert_eq!(it.path.endpoint, Some(0));
                assert_eq!(it.path.cluster, Some(0x28));
                assert_eq!(it.path.event, Some(0x00));
                assert_eq!(it.event_number, 1);
                assert_eq!(it.value, matter_codec::Value::Uint(7));
            }
            other => panic!("expected EventReport::Data, got {other:?}"),
        }

        device.await.unwrap();
    }

    #[tokio::test]
    async fn write_timed_does_handshake_over_loopback() {
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

        // Device flow: TimedRequest -> StatusResponse(SUCCESS) -> timed
        // WriteRequest -> WriteResponse(SUCCESS) for NodeLabel (0/0x28/0x05).
        let resp = {
            use matter_codec::{Tag, TlvWriter};
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_array(Tag::Context(0)).unwrap(); // WriteResponses
            w.start_structure(Tag::Anonymous).unwrap(); // AttributeStatusIB
            w.start_list(Tag::Context(0)).unwrap(); // Path
            w.put_uint(Tag::Context(2), 0).unwrap();
            w.put_uint(Tag::Context(3), 0x28).unwrap();
            w.put_uint(Tag::Context(4), 0x05).unwrap();
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
            w.put_uint(Tag::Context(0), 0).unwrap(); // SUCCESS
            w.end_container().unwrap();
            w.end_container().unwrap(); // AttributeStatusIB
            w.end_container().unwrap(); // array
            w.put_uint(Tag::Context(0xFF), 11).unwrap();
            w.end_container().unwrap();
            buf
        };
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D8,
            1,
            resp,
            true, // expect a TimedRequest first
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
        let statuses = node
            .write_timed(
                &[(
                    matter_interaction::AttributePath {
                        endpoint: 0,
                        cluster: 0x28,
                        attribute: 0x05,
                    },
                    matter_codec::Value::Utf8("x".to_string()),
                )],
                None,
            )
            .await
            .expect("write_timed");

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].1, matter_interaction::ImStatus::Success);

        device.await.unwrap();
    }

    #[tokio::test]
    async fn write_auto_upgrades_and_caches_timed() {
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

        // WriteResponse(SUCCESS) for NodeLabel (0/0x28/0x05), replied to each
        // (timed) WriteRequest by the retry device.
        let resp = {
            use matter_codec::{Tag, TlvWriter};
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_array(Tag::Context(0)).unwrap();
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_list(Tag::Context(0)).unwrap();
            w.put_uint(Tag::Context(2), 0).unwrap();
            w.put_uint(Tag::Context(3), 0x28).unwrap();
            w.put_uint(Tag::Context(4), 0x05).unwrap();
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap();
            w.put_uint(Tag::Context(0), 0).unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap();
            w.put_uint(Tag::Context(0xFF), 11).unwrap();
            w.end_container().unwrap();
            buf
        };
        let device = tokio::spawn(run_timed_retry_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D9,
            resp,
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
        let path = matter_interaction::AttributePath {
            endpoint: 0,
            cluster: 0x28,
            attribute: 0x05,
        };
        // First plain write is rejected with NEEDS_TIMED_INTERACTION → the
        // controller transparently retries timed and succeeds.
        let s1 = node
            .write(&[(path, matter_codec::Value::Utf8("a".to_string()))])
            .await
            .expect("write 1 (auto-upgrade)");
        assert_eq!(s1[0].1, matter_interaction::ImStatus::Success);
        // The path is now cached → the second write skips the plain attempt and
        // goes straight to the timed handshake (the device asserts a TimedRequest
        // arrives first, with no preceding plain WriteRequest).
        let s2 = node
            .write(&[(path, matter_codec::Value::Utf8("b".to_string()))])
            .await
            .expect("write 2 (cached timed)");
        assert_eq!(s2[0].1, matter_interaction::ImStatus::Success);

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
    fn push_parsed_matches_byte_path() {
        // The single-parse entry point (`push_parsed`, fed a pre-parsed
        // `ReportData`) must reassemble a multi-chunk notification identically
        // to the raw-bytes `push` path — proving the refactor that parses each
        // report once (rather than once to read the sub id and again inside the
        // reassembler) preserves decoded content and chunk reassembly.
        let c0 = build_report_data_chunk(0, 0x28, 0x0002, &matter_codec::Value::Uint(5010), true);
        let c1 = build_report_data_chunk(1, 0x06, 0x0000, &matter_codec::Value::Bool(true), false);

        // Reference: parse-then-bytes path.
        let mut bytes_path = ReportReassembler::default();
        assert!(bytes_path.push(&c0).is_none());
        let via_bytes = bytes_path.push(&c1).expect("final chunk flushes");

        // Under test: parse exactly once at the call site, hand in the struct.
        let mut parsed_path = ReportReassembler::default();
        let rd0 = matter_interaction::parse_report_data(&c0).expect("parse chunk 0");
        let rd1 = matter_interaction::parse_report_data(&c1).expect("parse chunk 1");
        assert!(parsed_path.push_parsed(rd0).is_none());
        let via_parsed = parsed_path.push_parsed(rd1).expect("final chunk flushes");

        assert_eq!(
            via_parsed, via_bytes,
            "single-parse path is content-identical"
        );
        assert_eq!(via_parsed.len(), 2);
        assert_eq!(via_parsed[0].0.endpoint, 0);
        assert_eq!(via_parsed[0].1, matter_codec::Value::Uint(5010));
        assert_eq!(via_parsed[1].0.endpoint, 1);
        assert_eq!(via_parsed[1].1, matter_codec::Value::Bool(true));
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
                &[],
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
            .subscribe(
                &[matter_interaction::ReadPath::cluster(1, 0x1d)],
                &[],
                1,
                30,
            )
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

    #[tokio::test]
    async fn subscribe_streams_event_over_loopback() {
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

        // The device streams one steady-state event report: BasicInformation.StartUp
        // (0x28 / event 0x00) on ep 0. The consumer must observe it as a
        // SubscriptionEvent::Event (events bypass the attribute reassembler).
        let event_blob = build_report_data_event(0, 0x28, 0x00, 1, &matter_codec::Value::Uint(7));
        let device = tokio::spawn(run_subscription_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D7,
            vec![event_blob],
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
                &[matter_interaction::ReadPath::cluster(1, 0x06)],
                &[matter_interaction::EventPath::cluster(0, 0x28)],
                1,
                30,
            )
            .await
            .expect("subscribe");

        match sub.next().await {
            Some(SubscriptionEvent::Established { .. }) => {}
            other => panic!("expected Established, got {other:?}"),
        }
        // Drain to the first event (Report/Lagged could in principle interleave).
        loop {
            match sub.next().await {
                Some(SubscriptionEvent::Event(matter_interaction::EventReport::Data(it))) => {
                    assert_eq!(it.path.endpoint, Some(0));
                    assert_eq!(it.path.cluster, Some(0x28));
                    assert_eq!(it.path.event, Some(0x00));
                    assert_eq!(it.event_number, 1);
                    assert_eq!(it.value, matter_codec::Value::Uint(7));
                    break;
                }
                Some(_) => {}
                None => panic!("subscription ended before an event arrived"),
            }
        }

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
                &[],
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
                &[],
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
                Ok(Some(_)) => {}
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

    /// A reconnect that replaces a node's session must proactively resubscribe
    /// any subscription stranded on the old session (and leave subscriptions on
    /// other sessions untouched), rather than waiting for their liveness deadline.
    #[test]
    fn resubscribe_stranded_moves_only_subs_on_the_replaced_session() {
        let (io, _peer) = InMemoryDatagram::pair();
        let mut actor = Actor::new(
            io,
            NullDiscovery,
            Arc::new(MemStore::default()),
            Arc::new(matter_commissioning::SystemNocRng),
            ControllerState { fabrics: vec![] },
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        );

        let peer: SocketAddr = "127.0.0.1:5540".parse().unwrap();
        let mk = |tx, session_id| SubEntry {
            tx,
            peer,
            reassembler: ReportReassembler::default(),
            session_id,
            wire_sub_id: 0x1234,
            node_id: 2,
            paths: vec![matter_interaction::ReadPath::all()],
            event_paths: vec![],
            event_filters: vec![],
            min_interval: 1,
            max_interval: 30,
            liveness_deadline: Instant::now() + std::time::Duration::from_secs(60),
        };
        // `Resubscribing` rides the reliable control channel, so the asserted
        // receivers below are the control (unbounded) ones.
        let (sink_a, _report_rx_a, mut rx_a) = test_report_sink();
        let (sink_b, _report_rx_b, mut rx_b) = test_report_sink();
        actor
            .subscriptions
            .insert(SubId(1), mk(sink_a, SessionId(7)));
        actor
            .subscriptions
            .insert(SubId(2), mk(sink_b, SessionId(9)));

        // Session 7 was replaced → only SubId(1) is resubscribed.
        actor.resubscribe_stranded(SessionId(7));

        assert!(
            !actor.subscriptions.contains_key(&SubId(1)),
            "stranded sub removed from the active map"
        );
        assert!(
            actor.resubscribes.iter().any(|pr| pr.sub_id == SubId(1)),
            "stranded sub scheduled for resubscribe"
        );
        assert!(
            matches!(rx_a.try_recv(), Ok(SubscriptionEvent::Resubscribing { .. })),
            "consumer notified with Resubscribing"
        );

        // SubId(2) on a different session is untouched.
        assert!(actor.subscriptions.contains_key(&SubId(2)));
        assert!(!actor.resubscribes.iter().any(|pr| pr.sub_id == SubId(2)));
        assert!(rx_b.try_recv().is_err(), "unaffected sub gets no event");
    }

    /// Build an actor with one real fabric in state so `sole_fabric()` (and thus
    /// the cache-eviction path in `on_pending_timeout`) is exercised. Discovery
    /// is null, so any `connect()` the timeout path attempts will fail without
    /// touching the cached session — exactly what we want to observe the guard.
    fn actor_with_one_fabric() -> Actor<InMemoryDatagram, NullDiscovery> {
        let (io, _peer) = InMemoryDatagram::pair();
        let fabric = {
            let cfg = FabricConfig {
                fabric_id: 0x0A0B_0C0D_0E0F_1011,
                rcac_id: 1,
                commissioner_node_id: 1,
                validity: (
                    MatterTime::from_unix_secs(1_700_000_000),
                    MatterTime::NO_EXPIRY,
                ),
                issue_icac: false,
            };
            crate::fabric::create_fabric(&cfg, &SystemNocRng).unwrap()
        };
        Actor::new(
            io,
            NullDiscovery,
            Arc::new(MemStore::default()),
            Arc::new(SystemNocRng),
            ControllerState {
                fabrics: vec![fabric],
            },
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
    }

    fn seed_pending_round_trip(
        actor: &mut Actor<InMemoryDatagram, NullDiscovery>,
        session: SessionId,
        exchange: u16,
        node_id: u64,
    ) {
        let (reply_tx, _reply_rx) = oneshot::channel();
        actor.pending.insert(
            (session, exchange),
            Pending {
                node_id,
                peer: "127.0.0.1:5540".parse().unwrap(),
                request: PendingRequest {
                    opcode: 0x02,
                    protocol_id: ProtocolId::INTERACTION_MODEL,
                    payload: vec![],
                },
                retried: false,
                reply: PendingReply::RoundTrip(reply_tx),
            },
        );
    }

    /// The bug: two ops are pending on session S (`Node` is `Clone`, so every
    /// concurrent op to one node shares a single cached session). Op A times out,
    /// evicts the cache, reconnects, and caches a fresh healthy session S'. Op B —
    /// still on the superseded S — later times out and `on_pending_timeout(S, …)`
    /// must NOT evict S' from the cache (which would force a redundant CASE
    /// handshake + churn every subscription just bound to S').
    #[tokio::test]
    async fn late_timeout_on_superseded_session_does_not_evict_current_session() {
        let mut actor = actor_with_one_fabric();
        let fabric_id = actor.sole_fabric().unwrap().fabric_id;
        let node_id = 0x42u64;
        let old_session = SessionId(7);
        let new_session = SessionId(9);

        // Op A already retried (evicted S, reconnected, cached the fresh S').
        actor.cache.insert(
            (fabric_id, node_id),
            CachedSession {
                session_id: new_session,
                peer: "127.0.0.1:5540".parse().unwrap(),
            },
        );

        // Op B is still pending on the superseded session S; fire its timeout.
        seed_pending_round_trip(&mut actor, old_session, 0xABCD, node_id);
        actor.on_pending_timeout(old_session, 0xABCD).await;

        // The healthy current session S' is still cached and untouched.
        let cached = actor
            .cache
            .get(&(fabric_id, node_id))
            .expect("current healthy session must remain cached");
        assert_eq!(
            cached.session_id, new_session,
            "late timeout on a superseded session must not evict the current session"
        );
        // No subscription churn was triggered.
        assert!(
            actor.resubscribes.is_empty(),
            "no resubscribe churn should be scheduled by a superseded-session timeout"
        );
    }

    /// The genuine-reconnect path: a timeout on the *current* cached session DOES
    /// evict it, so a real device reboot still forces a fresh handshake.
    #[tokio::test]
    async fn timeout_on_current_session_evicts_it() {
        let mut actor = actor_with_one_fabric();
        let fabric_id = actor.sole_fabric().unwrap().fabric_id;
        let node_id = 0x42u64;
        let session = SessionId(7);

        actor.cache.insert(
            (fabric_id, node_id),
            CachedSession {
                session_id: session,
                peer: "127.0.0.1:5540".parse().unwrap(),
            },
        );

        // The pending op is on the same session that is cached; its timeout must
        // evict the cache (connect then fails under NullDiscovery, leaving it empty).
        seed_pending_round_trip(&mut actor, session, 0xABCD, node_id);
        actor.on_pending_timeout(session, 0xABCD).await;

        assert!(
            !actor.cache.contains_key(&(fabric_id, node_id)),
            "timeout on the current session must evict it so genuine reconnect happens"
        );
    }

    fn mk_report(seq: usize) -> AttributeReport {
        AttributeReport {
            path: matter_interaction::AttributePath {
                endpoint: 1,
                cluster: 0x06,
                attribute: u32::try_from(seq).unwrap_or(u32::MAX),
            },
            value: matter_codec::Value::Bool(true),
        }
    }

    /// Memory-DoS guard: a device flooding reports past the bounded buffer must
    /// never block the actor (`try_send_report` always returns `true` for a live
    /// consumer) and must not grow the buffer past [`SUBSCRIPTION_CHANNEL_CAP`].
    /// The overflow is later surfaced as a single coalesced `Lagged { dropped }`.
    #[tokio::test]
    async fn report_overflow_drops_and_surfaces_lagged_without_blocking() {
        let (mut sink, mut report_rx, _ctrl_rx) = test_report_sink();

        // Stall the consumer: push far more than capacity without draining.
        let overflow = 100usize;
        let total = SUBSCRIPTION_CHANNEL_CAP + overflow;
        for i in 0..total {
            // Never blocks, never reports the consumer gone — reports past the
            // cap are dropped and counted, not awaited.
            assert!(
                sink.try_send_report(mk_report(i)),
                "actor must never block or fail on a full buffer (live consumer)"
            );
        }
        assert_eq!(
            sink.dropped, overflow,
            "exactly the over-capacity reports were dropped + counted"
        );
        // The buffer is bounded: it holds at most the cap, not the flood.
        assert_eq!(
            report_rx.len(),
            SUBSCRIPTION_CHANNEL_CAP,
            "buffered reports are bounded by the channel capacity"
        );

        // Drain enough slots to make room, then push again: the freed capacity
        // first carries a single coalesced Lagged announcing the dropped count.
        // (One drained slot is consumed by the Lagged itself, so the very next
        // report can still be dropped if the buffer immediately refills — drain a
        // couple to leave genuine headroom.)
        let first = report_rx.try_recv().expect("a buffered report");
        assert!(matches!(first, SubscriptionEvent::Report(_)));
        let _ = report_rx.try_recv().expect("a buffered report");
        assert!(
            sink.try_send_report(mk_report(9999)),
            "post-drain send still succeeds"
        );
        assert_eq!(
            sink.dropped, 0,
            "Lagged flush cleared the dropped counter and the new report fit"
        );

        // Drain the rest; somewhere in the stream is exactly one Lagged whose
        // count equals the overflow, and the report count stays bounded.
        let mut saw_lagged = None;
        let mut reports = 1usize; // the one drained above
        while let Ok(ev) = report_rx.try_recv() {
            match ev {
                SubscriptionEvent::Lagged { dropped } => {
                    assert!(saw_lagged.is_none(), "drops are coalesced into one Lagged");
                    saw_lagged = Some(dropped);
                }
                SubscriptionEvent::Report(_) => reports += 1,
                other => panic!("unexpected event on report channel: {other:?}"),
            }
        }
        assert_eq!(
            saw_lagged,
            Some(overflow),
            "a single Lagged surfaced the exact dropped count"
        );
        assert!(
            reports < total,
            "the flood was bounded: delivered fewer reports than were sent"
        );
    }

    /// A closed consumer (receiver dropped) is reported so the actor reaps the
    /// subscription rather than spinning forever.
    #[tokio::test]
    async fn report_send_reports_consumer_gone_when_receiver_dropped() {
        let (mut sink, report_rx, _ctrl_rx) = test_report_sink();
        drop(report_rx);
        assert!(
            !sink.try_send_report(mk_report(0)),
            "a closed report receiver signals the consumer is gone"
        );
    }

    /// Control events (`Established` / `Resubscribing`) must stay reliable even
    /// when the report buffer is saturated — they ride a separate channel and are
    /// never dropped by report backpressure, and `Subscription::next` prioritises
    /// them ahead of the report backlog.
    #[tokio::test]
    async fn control_events_delivered_even_when_report_channel_saturated() {
        let (mut sink, report_rx, ctrl_rx) = test_report_sink();

        // Saturate the report channel completely (and then some).
        for i in 0..(SUBSCRIPTION_CHANNEL_CAP + 50) {
            assert!(sink.try_send_report(mk_report(i)));
        }

        // Both control events still go through despite the full report buffer.
        assert!(
            sink.send_control(SubscriptionEvent::Established {
                subscription_id: 0xABCD,
            }),
            "Established must be delivered under report backpressure"
        );
        assert!(
            sink.send_control(SubscriptionEvent::Resubscribing {
                cause: Error::ControllerStopped,
            }),
            "Resubscribing must be delivered under report backpressure"
        );

        // Build the consumer handle and confirm next() yields the control events
        // FIRST, ahead of the buffered report backlog.
        let (cmd_tx, _cmd_rx) = mpsc::channel::<Command>(8);
        let mut sub = crate::subscription::Subscription {
            rx: report_rx,
            ctrl_rx,
            tx: cmd_tx,
            key: SubId(1),
            cancelled: true, // suppress the Drop cancel (no live actor here)
        };

        match sub.next().await {
            Some(SubscriptionEvent::Established { subscription_id }) => {
                assert_eq!(subscription_id, 0xABCD);
            }
            other => panic!("expected Established first, got {other:?}"),
        }
        match sub.next().await {
            Some(SubscriptionEvent::Resubscribing { .. }) => {}
            other => panic!("expected Resubscribing second, got {other:?}"),
        }
        // Only after the control events are drained do reports flow.
        match sub.next().await {
            Some(SubscriptionEvent::Report(_)) => {}
            other => panic!("expected a buffered Report next, got {other:?}"),
        }
    }

    // --- Task 14: offloaded persistence (store fsync off the actor loop) ---

    /// A store whose `save` always fails — proves durability-critical persists
    /// still surface their error to the caller after offloading.
    #[derive(Default)]
    struct FailingStore;
    impl ControllerStore for FailingStore {
        fn load(&self) -> Result<Option<Vec<u8>>, crate::store::StoreError> {
            Ok(None)
        }
        fn save(&self, _snapshot: &[u8]) -> Result<(), crate::store::StoreError> {
            Err(crate::store::StoreError::Io(std::io::Error::other(
                "disk full",
            )))
        }
    }

    /// A store that blocks inside `save` until released, and counts saves —
    /// used to prove a slow fsync runs off the actor loop (so the loop keeps
    /// serving other work) and that best-effort saves are debounced.
    #[derive(Default)]
    struct BlockingStore {
        inner: std::sync::Mutex<Option<Vec<u8>>>,
        saves: std::sync::atomic::AtomicUsize,
        /// While held by the test, every `save` blocks on acquiring it.
        gate: std::sync::Mutex<()>,
    }
    impl ControllerStore for BlockingStore {
        fn load(&self) -> Result<Option<Vec<u8>>, crate::store::StoreError> {
            Ok(self.inner.lock().unwrap().clone())
        }
        fn save(&self, snapshot: &[u8]) -> Result<(), crate::store::StoreError> {
            // Block here until the test drops its hold on `gate`. This models a
            // multi-millisecond fsync. If this ran on the actor task, the loop
            // would be wedged for the whole duration.
            let _held = self.gate.lock().unwrap();
            self.saves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.inner.lock().unwrap() = Some(snapshot.to_vec());
            Ok(())
        }
    }

    /// Durability-critical persists (fabric create) still surface store errors
    /// to the caller, even though the save is offloaded to the blocking pool.
    #[tokio::test]
    async fn durable_persist_surfaces_store_error() {
        let store: Arc<dyn ControllerStore> = Arc::new(FailingStore);
        let (io, _peer) = InMemoryDatagram::pair();
        let controller = crate::controller::MatterController::with_components(
            store,
            io,
            NullDiscovery,
            Arc::new(SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        let err = controller
            .create_fabric(cfg())
            .await
            .expect_err("a failing store must fail create_fabric");
        // The error must be the persistence failure, not a silent success.
        let msg = format!("{err}");
        assert!(
            msg.contains("disk full") || msg.to_lowercase().contains("i/o"),
            "expected the store I/O error to propagate, got: {msg}"
        );
    }

    /// Build a bare actor for unit-testing the persist paths in isolation.
    fn test_actor(store: Arc<dyn ControllerStore>) -> Actor<InMemoryDatagram, NullDiscovery> {
        let (io, _peer) = InMemoryDatagram::pair();
        Actor::new(
            io,
            NullDiscovery,
            store,
            Arc::new(SystemNocRng),
            ControllerState { fabrics: vec![] },
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
    }

    /// The best-effort per-connect persist (address hint) does NOT block the
    /// caller on the fsync: it is offloaded fire-and-forget. We hold the store's
    /// `gate` so any save would wedge, call `persist_best_effort`, and assert it
    /// returns immediately. Releasing the gate then lets the offloaded save run.
    ///
    /// This is the hot-path guarantee: a multi-ms fsync on a per-connect address
    /// hint never stalls the actor's `select!` loop (recv/MRP/liveness).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn best_effort_persist_does_not_block_on_fsync() {
        let store = Arc::new(BlockingStore::default());
        let actor = test_actor(store.clone());

        // Wedge any save until we release this guard.
        let held = store.gate.lock().unwrap();

        // Fire-and-forget; this must return immediately despite the wedged store.
        let start = std::time::Instant::now();
        actor.persist_best_effort();
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "best-effort persist must not block on the fsync"
        );
        // The blocked save hasn't run yet.
        assert_eq!(store.saves.load(std::sync::atomic::Ordering::SeqCst), 0);

        // Release the gate; the offloaded save eventually completes off-task.
        drop(held);
        let mut ran = false;
        for _ in 0..200 {
            if store.saves.load(std::sync::atomic::Ordering::SeqCst) >= 1 {
                ran = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(ran, "the offloaded best-effort save must eventually run");
    }

    /// Durability-critical persists block until the save completes AND surface
    /// store errors — the offload preserves these semantics. A successful
    /// durable save returns Ok and the bytes are present; a failing store
    /// returns Err. (The error-propagation path is also covered end-to-end by
    /// `durable_persist_surfaces_store_error`.)
    #[tokio::test]
    async fn durable_persist_inputs_offload_round_trip() {
        // Success path: a normal store records the save and returns Ok.
        let store = Arc::new(MemStore::default());
        let actor = test_actor(store.clone());
        let (s, bytes) = actor.durable_save_inputs().expect("serialize");
        save_offloaded(s, bytes).await.expect("durable save ok");
        assert!(
            store.load().expect("load").is_some(),
            "durable save must have written the snapshot"
        );

        // Failure path: a failing store surfaces the error to the awaiter.
        let actor = test_actor(Arc::new(FailingStore));
        let (s, bytes) = actor.durable_save_inputs().expect("serialize");
        let err = save_offloaded(s, bytes)
            .await
            .expect_err("a failing store must surface its error");
        assert!(
            format!("{err}").to_lowercase().contains("disk full")
                || format!("{err}").to_lowercase().contains("i/o"),
            "expected the store error to propagate, got: {err}"
        );
    }

    /// Timer-fairness regression: under a sustained inbound flood (which keeps
    /// `recv_from()` perpetually ready and, under the old `biased` select!,
    /// starved the timer arm), the subscription-liveness check must still fire
    /// within its deadline. We install a subscription whose `liveness_deadline`
    /// is already in the past, spawn the actor loop, and continuously feed the
    /// actor junk datagrams from the peer endpoint. The actor must reach
    /// `check_liveness` and emit `Resubscribing` despite recv always being
    /// ready. Pre-fix this test would hang (the timer arm never gets polled).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn liveness_timer_fires_under_inbound_flood() {
        let (io, peer) = InMemoryDatagram::pair();
        let mut actor = Actor::new(
            io,
            NullDiscovery,
            Arc::new(MemStore::default()),
            Arc::new(SystemNocRng),
            ControllerState { fabrics: vec![] },
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        );

        // A subscription that is ALREADY past its liveness deadline: the very
        // next `check_liveness` must mark it stale and emit `Resubscribing`.
        let (sink, _report_rx, mut ctrl_rx) = test_report_sink();
        actor.subscriptions.insert(
            SubId(1),
            SubEntry {
                tx: sink,
                peer: "127.0.0.1:5540".parse().unwrap(),
                reassembler: ReportReassembler::default(),
                session_id: SessionId(7),
                wire_sub_id: 0x1234,
                node_id: 2,
                paths: vec![matter_interaction::ReadPath::all()],
                event_paths: vec![],
                event_filters: vec![],
                min_interval: 1,
                max_interval: 30,
                // Already overdue at spawn time.
                liveness_deadline: Instant::now()
                    .checked_sub(std::time::Duration::from_secs(1))
                    .expect("instant minus 1s is representable"),
            },
        );

        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(8);
        let loop_handle = tokio::spawn(actor.run(cmd_rx));

        // Flood the actor's inbound queue with junk datagrams so `recv_from()`
        // is continuously ready. `handle_inbound` discards anything that does
        // not decode to a known secured session, so this is pure recv pressure.
        // Keep `peer` (and `cmd_tx`) alive for the whole test.
        let flood = tokio::spawn(async move {
            loop {
                if peer
                    .send_to(b"junk-datagram-pressure", peer.local_addr())
                    .await
                    .is_err()
                {
                    break;
                }
                // Yield so the flood does not monopolise the runtime; the actor
                // still sees a perpetually non-empty inbound queue.
                tokio::task::yield_now().await;
            }
        });

        // Despite the flood, the liveness timer must fire and notify the
        // consumer well within a generous bound.
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), ctrl_rx.recv()).await;

        flood.abort();
        drop(cmd_tx); // closes the command channel → actor loop returns
        let _ = loop_handle.await;

        assert!(
            matches!(got, Ok(Some(SubscriptionEvent::Resubscribing { .. }))),
            "liveness timer must fire under inbound flood (got {got:?})"
        );
    }

    /// M9-G-d decoupling, part 1 — the actor loop stays responsive while a
    /// commission is outstanding, and the completions-channel `select!` arm
    /// drains a finished commission and resolves its reply.
    ///
    /// The commission runs on its own spawned task ([`Actor::spawn_commission`])
    /// and reports back through `commission_tx`. We model "a commission is in
    /// flight" as "no completion has arrived on the channel yet": while that is
    /// the case, an unrelated `SessionCount` command must still be serviced
    /// promptly (pre-G-d, an inline `handle_commission().await` would have held
    /// the loop for the whole multi-second commission, starving this command).
    /// We then push a completion onto the channel and confirm the new arm drains
    /// it and resolves the caller's reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn commission_completion_drains_while_loop_stays_responsive() {
        let actor = actor_with_one_fabric();
        let fabric_id = actor.sole_fabric().unwrap().fabric_id;
        // Clone the completions sender before the loop consumes `actor`, so the
        // test can inject a completion the way a spawned commission task would.
        let completion_tx = actor.commission_tx.clone();

        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(8);
        let loop_handle = tokio::spawn(actor.run(cmd_rx));

        // A commission is outstanding (nothing on the completions channel yet):
        // an unrelated command must still be answered promptly.
        let (count_tx, count_rx) = oneshot::channel();
        cmd_tx
            .send(Command::SessionCount { reply: count_tx })
            .await
            .unwrap();
        let count = tokio::time::timeout(std::time::Duration::from_secs(1), count_rx)
            .await
            .expect("the loop must service SessionCount while a commission is outstanding")
            .expect("SessionCount reply");
        assert_eq!(count, 0, "no sessions cached yet");

        // The spawned commission finishes (here: with an error, which needs no
        // network). The completions arm must drain it and resolve the reply.
        let (reply_tx, reply_rx) = oneshot::channel();
        completion_tx
            .send(CommissionCompletion {
                fabric_id,
                result: Err(Error::Operational("simulated commission failure".into())),
                reply: reply_tx,
            })
            .await
            .unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), reply_rx)
            .await
            .expect("the completions arm must resolve the commission reply")
            .expect("reply channel");
        assert!(
            matches!(outcome, Err(Error::Operational(_))),
            "the commission error must propagate to the caller (got {outcome:?})"
        );

        drop(cmd_tx);
        let _ = loop_handle.await;
    }

    /// M9-G-d decoupling, part 2 — dispatching `Command::Commission` hands off
    /// without the loop `.await`ing the commission. With no attestation trust
    /// configured, `spawn_commission` short-circuits to `NoTrust` (no network),
    /// so this exercises the dispatch → spawn path in isolation and confirms a
    /// following command is serviced on the same responsive loop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn commission_dispatch_hands_off_without_blocking() {
        let actor = actor_with_one_fabric();
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(8);
        let loop_handle = tokio::spawn(actor.run(cmd_rx));

        let (c_tx, c_rx) = oneshot::channel();
        cmd_tx
            .send(Command::Commission {
                setup_payload: matter_commissioning::parse_manual_code("11693312331")
                    .expect("valid sample manual pairing code"),
                reply: c_tx,
            })
            .await
            .unwrap();
        let commission = tokio::time::timeout(std::time::Duration::from_secs(1), c_rx)
            .await
            .expect("Commission must be dispatched without blocking the loop")
            .expect("commission reply");
        assert!(
            matches!(commission, Err(Error::NoTrust)),
            "no trust configured → NoTrust (got {commission:?})"
        );

        // The loop is still live and services the next command.
        let (count_tx, count_rx) = oneshot::channel();
        cmd_tx
            .send(Command::SessionCount { reply: count_tx })
            .await
            .unwrap();
        let count = tokio::time::timeout(std::time::Duration::from_secs(1), count_rx)
            .await
            .expect("the loop must remain responsive after a Commission dispatch")
            .expect("SessionCount reply");
        assert_eq!(count, 0);

        drop(cmd_tx);
        let _ = loop_handle.await;
    }

    /// Build an `InvokeResponseMessage` whose single `InvokeResponseIB` carries
    /// a `CommandStatusIB` with `StatusIB.Status = 0x00` (SUCCESS). Used by
    /// [`open_commissioning_window_with_does_timed_invoke_over_loopback`] to
    /// simulate a device accepting `OpenCommissioningWindow`.
    fn build_invoke_status_success() -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap();
        w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
        w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
        w.start_structure(Tag::Context(1)).unwrap(); // Status = CommandStatusIB
        w.start_list(Tag::Context(0)).unwrap(); // CommandPath
        w.put_uint(Tag::Context(0), 0).unwrap(); // endpoint
        w.put_uint(
            Tag::Context(1),
            u64::from(crate::admin::ADMIN_COMMISSIONING_CLUSTER),
        )
        .unwrap(); // cluster
        w.put_uint(
            Tag::Context(2),
            u64::from(crate::admin::CMD_OPEN_COMMISSIONING_WINDOW),
        )
        .unwrap(); // command
        w.end_container().unwrap(); // /CommandPath
        w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
        w.put_uint(Tag::Context(0), 0x00).unwrap(); // SUCCESS
        w.end_container().unwrap(); // /StatusIB
        w.end_container().unwrap(); // /CommandStatusIB
        w.end_container().unwrap(); // /InvokeResponseIB
        w.end_container().unwrap(); // /InvokeResponses
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();
        buf
    }

    #[tokio::test]
    async fn open_commissioning_window_with_does_timed_invoke_over_loopback() {
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

        let reply = build_invoke_status_success();
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            reply,
            /* expect_timed */ true,
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
        let win = node
            .open_commissioning_window_with(180, 20_202_021, &[0x01; 32], 3840, 1000, None, None)
            .await
            .expect("open window");
        assert_eq!(win.passcode, 20_202_021);
        assert_eq!(win.discriminator, 3840);
        assert_eq!(win.manual_code.len(), 11);
        assert!(win.qr_code.is_none());
        device.await.unwrap();
    }

    #[tokio::test]
    async fn open_basic_commissioning_window_over_loopback() {
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
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            build_invoke_status_success(),
            /* expect_timed */ true,
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

        controller
            .node(device_node_id)
            .open_basic_commissioning_window(180)
            .await
            .expect("open basic");
        device.await.unwrap();
    }

    #[tokio::test]
    async fn announce_ota_provider_over_loopback() {
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

        // The device answers AnnounceOTAProvider (0, 0x002A, 0x00) with a bare
        // SUCCESS — built via the T3 server-side `build_invoke_response_status`,
        // exercising both halves end to end. AnnounceOTAProvider is a plain
        // (non-timed) invoke, so `expect_timed = false`.
        let reply = matter_interaction::build_invoke_response_status(
            matter_interaction::CommandPath {
                endpoint: 0,
                cluster: 0x002A,
                command: 0x00,
            },
            matter_interaction::ImStatus::Success,
        );
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            reply,
            /* expect_timed */ false,
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

        controller
            .node(device_node_id)
            .announce_ota_provider(
                /* provider_node_id */ 0x1122_3344_5566_7788,
                /* vendor_id */ 0xFFF1,
                /* endpoint */ 0,
            )
            .await
            .expect("announce ota provider");
        device.await.unwrap();
    }

    #[tokio::test]
    async fn register_icd_client_over_loopback_persists_registration() {
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
        // Device replies RegisterClientResponse{ ctx0 ICDCounter = 42 }.
        let resp_fields = {
            use matter_codec::{Tag, TlvWriter};
            let mut b = Vec::new();
            let mut w = TlvWriter::new(&mut b);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), 42).unwrap();
            w.end_container().unwrap();
            b
        };
        let reply = matter_interaction::build_invoke_response_command(
            matter_interaction::CommandPath {
                endpoint: 0,
                cluster: 0x0046,
                command: 0x01,
            },
            &resp_fields,
        );
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x55,
            1,
            reply,
            false,
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
        let reg = controller
            .node(device_node_id)
            .register_icd_client(1, crate::IcdClientType::Permanent)
            .await
            .expect("register_icd_client");
        assert_eq!(reg.node_id, device_node_id);
        assert_eq!(reg.start_counter, 42);
        assert_eq!(reg.check_in_node_id, 1); // loopback_harness commissioner node id
        assert_eq!(reg.monitored_subject, 1);
        device.await.unwrap();
    }

    #[tokio::test]
    async fn stay_active_request_over_loopback_returns_promised() {
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
        // Device replies StayActiveResponse{ ctx0 PromisedActiveDuration = 5000 }.
        let resp_fields = {
            use matter_codec::{Tag, TlvWriter};
            let mut b = Vec::new();
            let mut w = TlvWriter::new(&mut b);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), 5000).unwrap();
            w.end_container().unwrap();
            b
        };
        let reply = matter_interaction::build_invoke_response_command(
            matter_interaction::CommandPath {
                endpoint: 0,
                cluster: 0x0046,
                command: 0x04,
            },
            &resp_fields,
        );
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x55,
            1,
            reply,
            false,
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
        let promised = controller
            .node(device_node_id)
            .stay_active_request(3000)
            .await
            .expect("stay_active_request");
        assert_eq!(promised, 5000);
        device.await.unwrap();
    }

    #[tokio::test]
    async fn provider_server_accepts_case_and_dispatches_invoke_over_loopback() {
        use crate::provider_server::ProviderServer;
        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr: _,
            discovery,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        // The provider server plays the responder ("device") role with the
        // harness's operational identity; its handler replies SUCCESS for any
        // invoke. This swaps `run_loopback_device` for the production
        // `ProviderServer` — our own controller (initiator) CASE-connects and
        // gets the handler's response, in-process.
        let server = tokio::spawn(async move {
            ProviderServer::new(
                dev_io,
                vec![device_creds],
                device_roots,
                /* base_session_id */ 0x55,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .accept_and_dispatch_once(
                |req: &matter_interaction::ParsedInvokeRequest| {
                    let path = req.commands[0].path;
                    matter_interaction::build_invoke_response_status(
                        path,
                        matter_interaction::ImStatus::Success,
                    )
                },
                /* max_invokes */ 1,
            )
            .await
        });

        let controller = crate::controller::MatterController::with_components(
            store,
            ctrl_io,
            discovery,
            Arc::new(SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        // Drive a plain invoke from our client against our server.
        let path = matter_interaction::CommandPath {
            endpoint: 0,
            cluster: 0x0029,
            command: 0x00,
        };
        let result = controller
            .node(device_node_id)
            .invoke(path, matter_codec::Value::Structure(vec![]))
            .await
            .expect("invoke");
        assert!(matches!(
            result,
            crate::InvokeResult::Status(matter_interaction::ImStatus::Success)
        ));

        let dispatched = server.await.unwrap().expect("server ok");
        assert_eq!(dispatched, 1);
    }

    #[tokio::test]
    async fn serve_ota_once_full_flow_over_loopback() {
        use crate::provider_server::ProviderServer;
        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr: _,
            discovery: _,
            device_creds,
            device_roots,
            device_node_id: _,
        } = loopback_harness();

        // Provider = our commissioner identity (from the persisted fabric).
        let state = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let fabric = &state.fabrics[0];
        let (provider_creds, provider_roots, _compressed) =
            crate::credentials::operational_credentials(fabric).unwrap();
        let provider_node_id = fabric.commissioner.node_id;
        let fabric_id = fabric.fabric_id;

        let image: Vec<u8> = (0..2500u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let offer = matter_ota::ImageOffer {
            software_version: 2,
            software_version_string: "2.0".into(),
            image_uri: format!("bdx://{provider_node_id:016X}/fw.ota"),
            update_token: vec![0xAB; 16],
        };

        // Provider serves on dev_io; requestor drives from ctrl_io.
        let provider_addr = dev_io.local_addr();
        let image_for_assert = image.clone();
        let sunk: std::sync::Arc<std::sync::Mutex<Vec<matter_crypto::ResumptionRecord>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sunk_in = sunk.clone();
        let server = tokio::spawn(async move {
            ProviderServer::new(
                dev_io,
                vec![provider_creds],
                provider_roots,
                /* base_session_id */ 0x55,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .with_record_sink(Box::new(move |r| sunk_in.lock().unwrap().push(r)))
            .serve_ota_once(offer, image, /* max_block_size */ 256)
            .await
        });

        let reassembled = ota_test_requestor(
            ctrl_io,
            provider_addr,
            device_creds,
            device_roots,
            provider_node_id,
            fabric_id,
            /* current_version */ 1,
        )
        .await;

        assert_eq!(
            reassembled, image_for_assert,
            "requestor reassembled the served image"
        );
        server.await.unwrap().expect("provider served OTA");
        let records = sunk.lock().unwrap();
        assert_eq!(
            records.len(),
            1,
            "full-path accept must yield a resumption record to persist"
        );
    }

    /// The live chip-requestor shape: the requestor RESUMES the CASE session
    /// (its Sigma1 carries resumption fields matching the record both sides
    /// hold from a prior session) and the provider accepts via `Sigma2_Resume`,
    /// then serves the full OTA flow on the resumed session. Also pins the
    /// record rotation: the provider returns a rotated record (fresh id, same
    /// secret) for the caller to persist.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_ota_once_resumed_session_over_loopback() {
        use crate::provider_server::ProviderServer;
        use matter_crypto::{PeerInfo, ResumptionId, ResumptionRecord};

        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr: _,
            discovery: _,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        let state = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let fabric = &state.fabrics[0];
        let (provider_creds, provider_roots, _compressed) =
            crate::credentials::operational_credentials(fabric).unwrap();
        let provider_node_id = fabric.commissioner.node_id;
        let fabric_id = fabric.fabric_id;

        // Matched record pair from a (synthetic) prior session: both sides
        // hold the same id + 32-byte secret, each pinning the OTHER's identity.
        let prior_id = ResumptionId([0x42; 16]);
        let prior_secret = [0x24u8; 32];
        let provider_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: device_node_id,
                fabric_id,
                noc: device_creds.noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };
        let requestor_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: provider_node_id,
                fabric_id,
                noc: provider_creds.noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };

        let image: Vec<u8> = (0..2500u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let offer = matter_ota::ImageOffer {
            software_version: 2,
            software_version_string: "2.0".into(),
            image_uri: format!("bdx://{provider_node_id:016X}/fw.ota"),
            update_token: vec![0xAB; 16],
        };

        let provider_addr = dev_io.local_addr();
        let image_for_assert = image.clone();
        let sunk: std::sync::Arc<std::sync::Mutex<Vec<matter_crypto::ResumptionRecord>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sunk_in = sunk.clone();
        let server = tokio::spawn(async move {
            ProviderServer::new(
                dev_io,
                vec![provider_creds],
                provider_roots,
                /* base_session_id */ 0x55,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .with_resumption_records(vec![provider_record])
            .with_record_sink(Box::new(move |r| sunk_in.lock().unwrap().push(r)))
            .serve_ota_once(offer, image, /* max_block_size */ 256)
            .await
        });

        let reassembled = ota_test_requestor_resumed(
            ctrl_io,
            provider_addr,
            device_creds,
            device_roots,
            provider_node_id,
            fabric_id,
            /* current_version */ 1,
            requestor_record,
        )
        .await;

        assert_eq!(
            reassembled, image_for_assert,
            "requestor reassembled the served image over the RESUMED session"
        );
        server
            .await
            .unwrap()
            .expect("provider served OTA on resumed session");
        let records = sunk.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_ne!(records[0].id, prior_id, "Sigma2_Resume rotates the id");
        assert_eq!(
            records[0].shared_secret, prior_secret,
            "the shared secret carries over unchanged"
        );
    }

    /// In-process OTA **requestor**: CASE-connect to the provider, then drive
    /// `QueryImage` → BDX download → `ApplyUpdateRequest` → `NotifyUpdateApplied`,
    /// returning the reassembled image bytes. Uses `secured_round_trip` for each
    /// request/response (our server is BDX-exchange-agnostic, so per-message
    /// exchanges are fine in-process; the live requestor uses one BDX exchange).
    #[allow(clippy::too_many_lines)] // Linear OTA-requestor test driver; kept as one flow.
    async fn ota_test_requestor(
        io: matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        creds: matter_crypto::CaseCredentials,
        roots: matter_cert::TrustedRoots,
        provider_node_id: u64,
        fabric_id: u64,
        current_version: u32,
    ) -> Vec<u8> {
        use matter_commissioning::driver::run_case;
        use matter_transport::SessionManager;

        let now = MatterTime::from_unix_secs(2_000_000_000);
        let mut sessions = SessionManager::new();
        let sid = run_case(
            &io,
            &mut sessions,
            provider_addr,
            creds,
            roots,
            provider_node_id,
            fabric_id,
            now,
        )
        .await
        .unwrap();
        drive_ota_flow(&io, provider_addr, &mut sessions, sid, current_version).await
    }

    /// In-process OTA requestor that RESUMES a prior CASE session instead of
    /// running the full handshake: delegates to `resume_case_handshake` (which
    /// does Sigma1-with-resumption → `Sigma2_Resume` → `StatusReport` → ack) and
    /// then drives the same OTA flow. Mirrors chip's requestor behaviour after
    /// `AnnounceOTAProvider` (it always tries to resume the announce session).
    #[allow(clippy::too_many_arguments)] // Test driver mirroring ota_test_requestor + a record.
    async fn ota_test_requestor_resumed(
        io: matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        creds: matter_crypto::CaseCredentials,
        roots: matter_cert::TrustedRoots,
        provider_node_id: u64,
        fabric_id: u64,
        current_version: u32,
        record: matter_crypto::ResumptionRecord,
    ) -> Vec<u8> {
        let (mut sessions, sid) = resume_case_handshake(
            &io,
            provider_addr,
            creds,
            roots,
            provider_node_id,
            fabric_id,
            record,
            0x0021,
        )
        .await;
        drive_ota_flow(&io, provider_addr, &mut sessions, sid, current_version).await
    }

    /// Drive the full OTA flow on an already-established session, splitting the
    /// work across [`drive_ota_download_and_apply`] (steps 1-3) and
    /// [`send_notify_update_applied`] (step 4). Returns the reassembled image.
    async fn drive_ota_flow(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        sessions: &mut matter_transport::SessionManager,
        sid: matter_transport::SessionId,
        current_version: u32,
    ) -> Vec<u8> {
        let (reassembled, token) =
            drive_ota_download_and_apply(io, provider_addr, sessions, sid, current_version).await;
        send_notify_update_applied(
            io,
            provider_addr,
            sessions,
            sid,
            &token,
            current_version + 1,
        )
        .await;
        reassembled
    }

    /// Drive `QueryImage` → `QueryImageResponse` → BDX download →
    /// `ApplyUpdateRequest` → `ApplyUpdateResponse` (Proceed) on an
    /// already-established secured session, returning `(reassembled_image,
    /// update_token)`. The token is needed for `NotifyUpdateApplied` which may
    /// run on a DIFFERENT session (the post-reboot shape).
    async fn drive_ota_download_and_apply(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        sessions: &mut matter_transport::SessionManager,
        sid: matter_transport::SessionId,
        current_version: u32,
    ) -> (Vec<u8>, Vec<u8>) {
        let update_token = ota_query_image(io, provider_addr, sessions, sid, current_version).await;
        let length = bdx_receive_init(io, provider_addr, sessions, sid).await;
        let reassembled =
            bdx_pull_blocks_and_ack_eof(io, provider_addr, sessions, sid, length).await;
        ota_apply_update(
            io,
            provider_addr,
            sessions,
            sid,
            &update_token,
            current_version + 1,
        )
        .await;
        (reassembled, update_token)
    }

    /// `QueryImage` → `QueryImageResponse` (`UpdateAvailable`), returning the
    /// update token (needed later by Apply/Notify, possibly cross-session).
    async fn ota_query_image(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        sessions: &mut matter_transport::SessionManager,
        sid: matter_transport::SessionId,
        current_version: u32,
    ) -> Vec<u8> {
        use matter_clusters::gen::ota_software_update_provider as prov;
        use matter_commissioning::driver::secured_round_trip;
        use matter_interaction::{
            build_invoke_request, parse_invoke_response, CommandPath, InvokeResponse,
        };
        use matter_transport::ProtocolId;

        const IM: u8 = 0x08; // InvokeRequest

        let qi = prov::encode_query_image(
            0xFFF1,
            0x8000,
            current_version,
            &vec![prov::DownloadProtocolEnum::BdxSynchronous],
            None,
            None,
            None,
            None,
        );
        let qi_req = build_invoke_request(
            CommandPath {
                endpoint: 0,
                cluster: prov::CLUSTER_ID,
                command: prov::command_id::QUERY_IMAGE,
            },
            &qi,
        );
        let resp = secured_round_trip(
            io,
            sessions,
            sid,
            provider_addr,
            IM,
            ProtocolId::INTERACTION_MODEL,
            &qi_req,
        )
        .await
        .unwrap();
        match parse_invoke_response(&resp.payload).unwrap() {
            InvokeResponse::Command { fields_tlv, .. } => {
                let qir = prov::QueryImageResponse::decode(&fields_tlv).unwrap();
                assert_eq!(qir.status, prov::StatusEnum::UpdateAvailable);
                qir.update_token.unwrap()
            }
            other @ InvokeResponse::Status(_) => {
                panic!("expected QueryImageResponse command, got {other:?}")
            }
        }
    }

    /// BDX `ReceiveInit` → `ReceiveAccept`, returning the accepted transfer
    /// length. Callable mid-serve (no preceding `QueryImage` on THIS session)
    /// — the cross-session re-init regression needs exactly that shape.
    async fn bdx_receive_init(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        sessions: &mut matter_transport::SessionManager,
        sid: matter_transport::SessionId,
    ) -> usize {
        use matter_bdx::{ReceiveAccept, TransferControl, TransferInit};
        use matter_commissioning::driver::secured_round_trip;
        use matter_transport::ProtocolId;

        let init = TransferInit {
            control: TransferControl::RECEIVER_DRIVE,
            version: 0,
            max_block_size: 256,
            start_offset: 0,
            max_length: 0,
            file_designator: b"fw.ota".to_vec(),
            metadata: Vec::new(),
        };
        let acc = secured_round_trip(
            io,
            sessions,
            sid,
            provider_addr,
            matter_bdx::MessageType::ReceiveInit.to_u8(),
            ProtocolId::BDX,
            &init.encode(),
        )
        .await
        .unwrap();
        let accept = ReceiveAccept::decode(&acc.payload).unwrap();
        usize::try_from(accept.length).unwrap()
    }

    /// One `BlockQuery` → `Block` round, returning the block's data bytes.
    async fn bdx_query_one_block(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        sessions: &mut matter_transport::SessionManager,
        sid: matter_transport::SessionId,
        block_counter: u32,
    ) -> Vec<u8> {
        use matter_bdx::{CounterMessage, DataBlock};
        use matter_commissioning::driver::secured_round_trip;
        use matter_transport::ProtocolId;

        let q = CounterMessage { block_counter }.encode();
        let blk = secured_round_trip(
            io,
            sessions,
            sid,
            provider_addr,
            matter_bdx::MessageType::BlockQuery.to_u8(),
            ProtocolId::BDX,
            &q,
        )
        .await
        .unwrap();
        DataBlock::decode(&blk.payload).unwrap().data
    }

    /// Pull `BlockQuery`/`Block` rounds until `length` bytes are reassembled,
    /// then fire the closing `BlockAckEOF`. Returns the reassembled image.
    async fn bdx_pull_blocks_and_ack_eof(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        sessions: &mut matter_transport::SessionManager,
        sid: matter_transport::SessionId,
        length: usize,
    ) -> Vec<u8> {
        use matter_bdx::CounterMessage;
        use matter_transport::{MrpFlags, ProtocolId};
        use std::time::Instant;

        let mut reassembled = Vec::new();
        let mut counter = 0u32;
        while reassembled.len() < length {
            let data = bdx_query_one_block(io, provider_addr, sessions, sid, counter).await;
            reassembled.extend_from_slice(&data);
            counter += 1;
        }
        // BlockAckEOF (fire-and-forget; final block counter = counter - 1).
        let ack = CounterMessage {
            block_counter: counter - 1,
        }
        .encode();
        let out = sessions
            .encode_outbound(
                sid,
                None,
                matter_bdx::MessageType::BlockAckEof.to_u8(),
                ProtocolId::BDX,
                &ack,
                MrpFlags { reliable: false },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, provider_addr).await.unwrap();
        reassembled
    }

    /// `ApplyUpdateRequest` → `ApplyUpdateResponse` (Proceed). `target_version`
    /// is the version being applied (download's `current_version + 1`).
    async fn ota_apply_update(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        sessions: &mut matter_transport::SessionManager,
        sid: matter_transport::SessionId,
        update_token: &[u8],
        target_version: u32,
    ) {
        use matter_clusters::gen::ota_software_update_provider as prov;
        use matter_commissioning::driver::secured_round_trip;
        use matter_interaction::{
            build_invoke_request, parse_invoke_response, CommandPath, InvokeResponse,
        };
        use matter_transport::ProtocolId;

        const IM: u8 = 0x08; // InvokeRequest

        let aur = prov::encode_apply_update_request(&update_token.to_vec(), target_version);
        let aur_req = build_invoke_request(
            CommandPath {
                endpoint: 0,
                cluster: prov::CLUSTER_ID,
                command: prov::command_id::APPLY_UPDATE_REQUEST,
            },
            &aur,
        );
        let ar = secured_round_trip(
            io,
            sessions,
            sid,
            provider_addr,
            IM,
            ProtocolId::INTERACTION_MODEL,
            &aur_req,
        )
        .await
        .unwrap();
        match parse_invoke_response(&ar.payload).unwrap() {
            InvokeResponse::Command { fields_tlv, .. } => {
                let r = prov::ApplyUpdateResponse::decode(&fields_tlv).unwrap();
                assert_eq!(r.action, prov::ApplyUpdateActionEnum::Proceed);
            }
            other @ InvokeResponse::Status(_) => {
                panic!("expected ApplyUpdateResponse command, got {other:?}")
            }
        }
    }

    /// Send `NotifyUpdateApplied` on an already-established secured session and
    /// assert the provider returns a success status. `token` and
    /// `software_version` come from the download phase (possibly on a different
    /// session — the post-reboot shape).
    async fn send_notify_update_applied(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        sessions: &mut matter_transport::SessionManager,
        sid: matter_transport::SessionId,
        token: &[u8],
        software_version: u32,
    ) {
        use matter_clusters::gen::ota_software_update_provider as prov;
        use matter_commissioning::driver::secured_round_trip;
        use matter_interaction::{
            build_invoke_request, parse_invoke_response, CommandPath, InvokeResponse,
        };
        use matter_transport::ProtocolId;

        const IM: u8 = 0x08;

        let token_vec = token.to_vec();
        let nua = prov::encode_notify_update_applied(&token_vec, software_version);
        let nua_req = build_invoke_request(
            CommandPath {
                endpoint: 0,
                cluster: prov::CLUSTER_ID,
                command: prov::command_id::NOTIFY_UPDATE_APPLIED,
            },
            &nua,
        );
        let nr = secured_round_trip(
            io,
            sessions,
            sid,
            provider_addr,
            IM,
            ProtocolId::INTERACTION_MODEL,
            &nua_req,
        )
        .await
        .unwrap();
        assert!(matches!(
            parse_invoke_response(&nr.payload).unwrap(),
            InvokeResponse::Status(matter_interaction::ImStatus::Success)
        ));
    }

    /// CASE resumption handshake: sends a Sigma1 with resumption fields built
    /// from `record`, expects `Sigma2_Resume`, closes with a success
    /// `StatusReport` (absorbing the provider's standalone ack), and returns
    /// the registered `(SessionManager, SessionId)`. `session_id` is the
    /// initiator's advertised secured session id; the exchange id is derived
    /// from it (`0x7000 | session_id`) so two concurrent handshakes on the
    /// same socket never share an exchange. Mirrors chip's requestor behaviour
    /// after `AnnounceOTAProvider`.
    #[allow(clippy::too_many_arguments)] // Protocol-mirroring handshake driver; each arg maps to a distinct CASE parameter.
    async fn resume_case_handshake(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        creds: matter_crypto::CaseCredentials,
        roots: matter_cert::TrustedRoots,
        provider_node_id: u64,
        fabric_id: u64,
        record: matter_crypto::ResumptionRecord,
        session_id: u16,
    ) -> (
        matter_transport::SessionManager,
        matter_transport::SessionId,
    ) {
        use matter_commissioning::driver::{decode_unsecured, encode_unsecured};
        use matter_transport::{ProtocolId, SessionManager};

        const OP_SIGMA1: u8 = 0x30;
        const OP_SIGMA2_RESUME: u8 = 0x33;
        const OP_STATUS_REPORT: u8 = 0x40;
        let exchange: u16 = 0x7000 | session_id;

        let now = MatterTime::from_unix_secs(2_000_000_000);
        let mut initiator = matter_crypto::CaseInitiator::new_with_resumption(
            creds,
            roots,
            provider_node_id,
            fabric_id,
            record,
            session_id,
            now,
        )
        .unwrap();

        // Sigma1 (with resumption fields).
        let sigma1 = initiator.start().unwrap();
        let wire = encode_unsecured(
            1,
            exchange,
            OP_SIGMA1,
            ProtocolId::SECURE_CHANNEL,
            true,
            true,
            None,
            None,
            &sigma1,
        );
        io.send_to(&wire, provider_addr).await.unwrap();

        // Sigma2_Resume.
        let (bytes, _) = io.recv_from().await.unwrap();
        let m = decode_unsecured(&bytes).unwrap();
        assert_eq!(m.opcode, OP_SIGMA2_RESUME, "expected Sigma2_Resume");
        initiator.handle_sigma2_resume(&m.payload).unwrap();

        // SigmaFinished: success StatusReport (reliable, piggyback-acks
        // Sigma2_Resume), then absorb the provider's standalone ack.
        let mut body = Vec::with_capacity(8);
        body.extend_from_slice(&0u16.to_le_bytes()); // GeneralCode: success
        body.extend_from_slice(&0u32.to_le_bytes()); // ProtocolId: SecureChannel
        body.extend_from_slice(&0u16.to_le_bytes()); // ProtocolCode: 0
        let report = encode_unsecured(
            2,
            exchange,
            OP_STATUS_REPORT,
            ProtocolId::SECURE_CHANNEL,
            true,
            true,
            Some(m.message_counter),
            None,
            &body,
        );
        io.send_to(&report, provider_addr).await.unwrap();
        let _ack = io.recv_from().await.unwrap();

        let output = initiator.finish().unwrap();
        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, matter_transport::SessionRole::Initiator);
        (sessions, sid)
    }

    /// Build a fresh set of device CASE credentials under `fabric` (a new key
    /// pair + a newly issued NOC). The NOC is signed by `fabric`'s RCAC so the
    /// provider will accept it on a full handshake; on the resumed path the NOC
    /// is not re-verified (the resumption id suffices). Calling this function
    /// twice on the same fabric produces two independent credential sets, which
    /// the cross-session test needs (the first is consumed by session-1's
    /// handshake; the second is needed for session 2).
    fn make_device_creds_for_fabric(
        fabric: &crate::state::FabricEntry,
    ) -> (matter_crypto::CaseCredentials, matter_cert::TrustedRoots) {
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
        (device_creds, device_roots)
    }

    /// Hardening regression: stray datagrams arriving BEFORE the requestor's
    /// Sigma1 (undecodable noise + a stale unsecured ack) must not consume
    /// pooled credentials — the pool here is a SINGLE credential, so the old
    /// pop-before-validate behavior would exhaust it and fail the serve.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_ota_survives_stray_frames_before_sigma1() {
        use crate::provider_server::ProviderServer;
        use matter_crypto::{PeerInfo, ResumptionId, ResumptionRecord};

        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr: _,
            discovery: _,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        let state = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let fabric = &state.fabrics[0];
        let (provider_creds, provider_roots, _compressed) =
            crate::credentials::operational_credentials(fabric).unwrap();
        let provider_node_id = fabric.commissioner.node_id;
        let fabric_id = fabric.fabric_id;

        let prior_id = ResumptionId([0x43; 16]);
        let prior_secret = [0x25u8; 32];
        let provider_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: device_node_id,
                fabric_id,
                noc: device_creds.noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };
        let requestor_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: provider_node_id,
                fabric_id,
                noc: provider_creds.noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };

        let image: Vec<u8> = (0..500u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let offer = matter_ota::ImageOffer {
            software_version: 2,
            software_version_string: "2.0".into(),
            image_uri: format!("bdx://{provider_node_id:016X}/fw.ota"),
            update_token: vec![0xAB; 16],
        };

        let provider_addr = dev_io.local_addr();
        let image_for_assert = image.clone();
        let server = tokio::spawn(async move {
            ProviderServer::new(
                dev_io,
                vec![provider_creds], // ONE credential — strays must not burn it
                provider_roots,
                /* base_session_id */ 0x56,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .with_resumption_records(vec![provider_record])
            .serve_ota_once(offer, image, /* max_block_size */ 256)
            .await
        });

        // Stray traffic first: undecodable garbage + a stale unsecured
        // standalone ack. Neither is a Sigma1.
        ctrl_io
            .send_to(&[0xDE, 0xAD, 0xBE, 0xEF], provider_addr)
            .await
            .unwrap();
        let stray_ack = matter_commissioning::driver::encode_unsecured(
            1,
            0x7777,
            0x10, // MRP standalone ack
            matter_transport::ProtocolId::SECURE_CHANNEL,
            true,
            false,
            Some(1),
            None,
            &[],
        );
        ctrl_io.send_to(&stray_ack, provider_addr).await.unwrap();

        let reassembled = ota_test_requestor_resumed(
            ctrl_io,
            provider_addr,
            device_creds,
            device_roots,
            provider_node_id,
            fabric_id,
            /* current_version */ 1,
            requestor_record,
        )
        .await;

        assert_eq!(
            reassembled, image_for_assert,
            "the single-credential serve must survive pre-Sigma1 strays"
        );
        server
            .await
            .unwrap()
            .expect("serve completed despite stray frames");
    }

    /// Hardening regression: a serve pinned to a target node must reject an
    /// authenticated session from a DIFFERENT fabric member (here the pin is
    /// set to an id the requestor does not hold), consuming the credential
    /// but leaving no resumption state behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_ota_rejects_unpinned_peer() {
        use crate::provider_server::ProviderServer;
        use matter_crypto::{PeerInfo, ResumptionId, ResumptionRecord};

        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr: _,
            discovery: _,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        let state = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let fabric = &state.fabrics[0];
        let (provider_creds, provider_roots, _compressed) =
            crate::credentials::operational_credentials(fabric).unwrap();
        let provider_node_id = fabric.commissioner.node_id;
        let fabric_id = fabric.fabric_id;

        let prior_id = ResumptionId([0x44; 16]);
        let prior_secret = [0x26u8; 32];
        let provider_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: device_node_id,
                fabric_id,
                noc: device_creds.noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };
        let requestor_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: provider_node_id,
                fabric_id,
                noc: provider_creds.noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };

        let offer = matter_ota::ImageOffer {
            software_version: 2,
            software_version_string: "2.0".into(),
            image_uri: format!("bdx://{provider_node_id:016X}/fw.ota"),
            update_token: vec![0xAB; 16],
        };

        let provider_addr = dev_io.local_addr();
        let server = tokio::spawn(async move {
            ProviderServer::new(
                dev_io,
                vec![provider_creds], // one credential: the rejected accept ends the serve
                provider_roots,
                /* base_session_id */ 0x57,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .with_resumption_records(vec![provider_record])
            // Pin to an id the requestor does NOT authenticate as.
            .with_expected_peer(device_node_id + 1)
            .serve_ota_once(offer, vec![0u8; 64], /* max_block_size */ 256)
            .await
        });

        // The requestor's resumed handshake completes from ITS side (the peer
        // check runs after the responder finishes); it never gets served.
        let requestor = tokio::spawn(async move {
            let _ = resume_case_handshake(
                &ctrl_io,
                provider_addr,
                device_creds,
                device_roots,
                provider_node_id,
                fabric_id,
                requestor_record,
                /* session_id */ 0x0031,
            )
            .await;
        });

        let err = server
            .await
            .unwrap()
            .expect_err("pinned serve must reject the wrong peer");
        assert!(
            err.to_string().contains("not the expected"),
            "unexpected error: {err}"
        );
        requestor.abort();
    }

    /// The post-reboot shape: session 1 resumes CASE, downloads the image,
    /// and sends `ApplyUpdateRequest` (no same-session `NotifyUpdateApplied`);
    /// the requestor then "reboots" — a SECOND resumption handshake using the
    /// record rotated during accept 1 (captured via the sink) — and sends
    /// `NotifyUpdateApplied` on session 2. The `serve_ota_once` loop must
    /// complete `Ok` and the sink must show two rotations (one per accept).
    ///
    /// This mirrors the real chip OTA requestor shape: it reboots into the
    /// new image before sending `NotifyUpdateApplied`, so the notification
    /// arrives on a fresh session.
    #[allow(clippy::too_many_lines)] // Linear cross-session OTA protocol test; splitting hurts clarity.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_ota_spans_sessions_for_post_reboot_notify() {
        use crate::provider_server::ProviderServer;
        use matter_crypto::{PeerInfo, ResumptionId, ResumptionRecord};

        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr: _,
            discovery: _,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        let state = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let fabric = &state.fabrics[0];
        // TWO provider credential sets: session 1 (download + apply) and
        // session 2 (post-reboot Notify). accept_case consumes one per accept.
        let (provider_creds1, provider_roots, _compressed) =
            crate::credentials::operational_credentials(fabric).unwrap();
        let (provider_creds2, _, _) = crate::credentials::operational_credentials(fabric).unwrap();
        let provider_node_id = fabric.commissioner.node_id;
        let fabric_id = fabric.fabric_id;
        // Save the provider NOC before creds1 is moved into the server spawn.
        let provider_noc = provider_creds1.noc.clone();

        // Second requestor credential set for session 2 (session 1 consumes
        // device_creds). Same fabric/RCAC, fresh key pair — same identity is
        // fine on the resumed path (the provider validates the resumption id,
        // not the NOC chain again).
        let (device_creds2, device_roots2) = make_device_creds_for_fabric(fabric);

        // Matched record pair for a synthetic prior session.
        let prior_id = ResumptionId([0x42; 16]);
        let prior_secret = [0x24u8; 32];
        let provider_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: device_node_id,
                fabric_id,
                noc: device_creds.noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };
        let requestor_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: provider_node_id,
                fabric_id,
                noc: provider_noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };

        let image: Vec<u8> = (0..2500u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let offer = matter_ota::ImageOffer {
            software_version: 2,
            software_version_string: "2.0".into(),
            image_uri: format!("bdx://{provider_node_id:016X}/fw.ota"),
            update_token: vec![0xAB; 16],
        };

        let provider_addr = dev_io.local_addr();
        let image_for_assert = image.clone();
        let sunk: std::sync::Arc<std::sync::Mutex<Vec<matter_crypto::ResumptionRecord>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sunk_in = sunk.clone();
        let server = tokio::spawn(async move {
            ProviderServer::new(
                dev_io,
                vec![provider_creds1, provider_creds2],
                provider_roots,
                /* base_session_id */ 0x55,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .with_resumption_records(vec![provider_record])
            .with_record_sink(Box::new(move |r| sunk_in.lock().unwrap().push(r)))
            .serve_ota_once(offer, image, /* max_block_size */ 256)
            .await
        });

        // Session 1: resume CASE, download the image, apply — but no
        // same-session Notify (the requestor "reboots" first).
        let (mut s1, sid1) = resume_case_handshake(
            &ctrl_io,
            provider_addr,
            device_creds,
            device_roots,
            provider_node_id,
            fabric_id,
            requestor_record,
            0x0021,
        )
        .await;
        let (reassembled, token) =
            drive_ota_download_and_apply(&ctrl_io, provider_addr, &mut s1, sid1, 1).await;
        assert_eq!(
            reassembled, image_for_assert,
            "session-1 download must reassemble the full image"
        );

        // "Reboot": the requestor builds its session-2 record from the rotated
        // resumption id captured by the sink during accept 1. The sink is
        // called synchronously by accept_case before the IM dispatch loop, so
        // sunk[0] is guaranteed to be present by the time
        // drive_ota_download_and_apply returns (that flow requires many IM
        // round-trips that happen AFTER accept_case returns).
        let rotated = sunk.lock().unwrap()[0].clone();
        let requestor_record2 = ResumptionRecord {
            id: rotated.id,
            shared_secret: rotated.shared_secret,
            peer: PeerInfo {
                node_id: provider_node_id,
                fabric_id,
                noc: provider_noc, // same provider identity as session 1
                session_id: 0,
            },
            expires_at: None,
        };
        let (mut s2, sid2) = resume_case_handshake(
            &ctrl_io,
            provider_addr,
            device_creds2,
            device_roots2,
            provider_node_id,
            fabric_id,
            requestor_record2,
            0x0022,
        )
        .await;
        // Session 2: send NotifyUpdateApplied with the token from session 1.
        // software_version = 2 (the newly applied version = current_version + 1 = 1 + 1).
        send_notify_update_applied(&ctrl_io, provider_addr, &mut s2, sid2, &token, 2).await;

        server
            .await
            .unwrap()
            .expect("serve_ota_once must complete on cross-session Notify");
        let records = sunk.lock().unwrap();
        assert_eq!(
            records.len(),
            2,
            "one record per accept (one per CASE session)"
        );
        assert_ne!(
            records[0].id, records[1].id,
            "each accept rotates the resumption id"
        );
    }

    /// Full (non-resumed) CASE handshake driver: Sigma1 → Sigma2 → Sigma3 →
    /// success `StatusReport`. The `resume_case_handshake` counterpart for the
    /// full path. When `send_final_ack` is false the closing standalone ack of
    /// the provider's `StatusReport` is NOT sent — the caller controls what the
    /// provider's ack-absorb `recv` sees next (the fast-Sigma1 regression puts
    /// a new Sigma1 there).
    #[allow(clippy::too_many_arguments)] // Protocol-mirroring handshake driver; each arg maps to a distinct CASE parameter.
    async fn full_case_handshake(
        io: &matter_commissioning::driver::InMemoryDatagram,
        provider_addr: std::net::SocketAddr,
        creds: matter_crypto::CaseCredentials,
        roots: matter_cert::TrustedRoots,
        provider_node_id: u64,
        fabric_id: u64,
        session_id: u16,
        send_final_ack: bool,
    ) -> (
        matter_transport::SessionManager,
        matter_transport::SessionId,
    ) {
        use matter_commissioning::driver::{decode_unsecured, encode_unsecured};
        use matter_transport::{ProtocolId, SessionManager};

        const OP_SIGMA1: u8 = 0x30;
        const OP_SIGMA2: u8 = 0x31;
        const OP_SIGMA3: u8 = 0x32;
        const OP_STATUS_REPORT: u8 = 0x40;
        const OP_MRP_STANDALONE_ACK: u8 = 0x10;
        // Distinct exchange space from resume_case_handshake's 0x7000 |.
        let exchange: u16 = 0x6000 | session_id;

        let now = MatterTime::from_unix_secs(2_000_000_000);
        let mut initiator = matter_crypto::CaseInitiator::new(
            creds,
            roots,
            provider_node_id,
            fabric_id,
            session_id,
            now,
        )
        .unwrap();

        // Sigma1 (no resumption fields — plain full handshake).
        let sigma1 = initiator.start().unwrap();
        let wire = encode_unsecured(
            1,
            exchange,
            OP_SIGMA1,
            ProtocolId::SECURE_CHANNEL,
            true,
            true,
            None,
            None,
            &sigma1,
        );
        io.send_to(&wire, provider_addr).await.unwrap();

        // Sigma2 → Sigma3 (piggyback-acks Sigma2).
        let (bytes, _) = io.recv_from().await.unwrap();
        let m2 = decode_unsecured(&bytes).unwrap();
        assert_eq!(m2.opcode, OP_SIGMA2, "expected Sigma2");
        initiator.handle_sigma2(&m2.payload).unwrap();
        let sigma3 = initiator.next_message().unwrap();
        let wire = encode_unsecured(
            2,
            exchange,
            OP_SIGMA3,
            ProtocolId::SECURE_CHANNEL,
            true,
            true,
            Some(m2.message_counter),
            None,
            &sigma3,
        );
        io.send_to(&wire, provider_addr).await.unwrap();

        // Success StatusReport; ack it only when asked to.
        let (bytes, _) = io.recv_from().await.unwrap();
        let report = decode_unsecured(&bytes).unwrap();
        assert_eq!(report.opcode, OP_STATUS_REPORT, "expected StatusReport");
        assert_eq!(
            report.payload.get(0..2),
            Some(&[0u8, 0u8][..]),
            "handshake must close with a success StatusReport"
        );
        if send_final_ack {
            let ack = encode_unsecured(
                3,
                exchange,
                OP_MRP_STANDALONE_ACK,
                ProtocolId::SECURE_CHANNEL,
                true,
                false,
                Some(report.message_counter),
                None,
                &[],
            );
            io.send_to(&ack, provider_addr).await.unwrap();
        }

        let output = initiator.finish().unwrap();
        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, matter_transport::SessionRole::Initiator);
        (sessions, sid)
    }

    /// Residual-hardening regression (TODO-1.0 "OTA provider" residual 1): a
    /// fast NEW Sigma1 arriving where `complete_full` absorbs the initiator's
    /// closing standalone ack must be handed back and carried into the next
    /// accept — not eaten. Pre-fix, the Sigma1 was consumed as if it were the
    /// ack: the requestor here would hang awaiting a Sigma2 that never comes
    /// (bounded by the timeout below), and a live requestor's Sigma1
    /// retransmit would burn a retry credential this two-entry pool does not
    /// have.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_ota_carries_sigma1_arriving_in_place_of_close_ack() {
        use crate::provider_server::ProviderServer;

        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr: _,
            discovery: _,
            device_creds,
            device_roots,
            device_node_id: _,
        } = loopback_harness();

        let state = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let fabric = &state.fabrics[0];
        // EXACTLY two credentials: one per legitimate accept. An eaten Sigma1
        // would need a third for the retransmit.
        let (provider_creds1, provider_roots, _compressed) =
            crate::credentials::operational_credentials(fabric).unwrap();
        let (provider_creds2, _, _) = crate::credentials::operational_credentials(fabric).unwrap();
        let provider_node_id = fabric.commissioner.node_id;
        let fabric_id = fabric.fabric_id;
        // Session 2 needs its own credential set (session 1 consumes device_creds).
        let (device_creds2, device_roots2) = make_device_creds_for_fabric(fabric);

        let image: Vec<u8> = (0..2500u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let offer = matter_ota::ImageOffer {
            software_version: 2,
            software_version_string: "2.0".into(),
            image_uri: format!("bdx://{provider_node_id:016X}/fw.ota"),
            update_token: vec![0xAB; 16],
        };

        let provider_addr = dev_io.local_addr();
        let image_for_assert = image.clone();
        let sunk: std::sync::Arc<std::sync::Mutex<Vec<matter_crypto::ResumptionRecord>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sunk_in = sunk.clone();
        let server = tokio::spawn(async move {
            ProviderServer::new(
                dev_io,
                vec![provider_creds1, provider_creds2],
                provider_roots,
                /* base_session_id */ 0x55,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .with_record_sink(Box::new(move |r| sunk_in.lock().unwrap().push(r)))
            .serve_ota_once(offer, image, /* max_block_size */ 256)
            .await
        });

        // Session 1: full handshake whose closing standalone ack is never
        // sent — the requestor "reboots" and moves straight to a new
        // handshake instead (the fast post-reboot shape).
        let (_s1, _sid1) = full_case_handshake(
            &ctrl_io,
            provider_addr,
            device_creds,
            device_roots,
            provider_node_id,
            fabric_id,
            /* session_id */ 0x0021,
            /* send_final_ack */ false,
        )
        .await;

        // Session 2: its Sigma1 lands exactly where the provider absorbs
        // session 1's close ack. Bounded so the pre-fix swallow fails the
        // test instead of hanging it.
        let (mut s2, sid2) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            full_case_handshake(
                &ctrl_io,
                provider_addr,
                device_creds2,
                device_roots2,
                provider_node_id,
                fabric_id,
                /* session_id */ 0x0022,
                /* send_final_ack */ true,
            ),
        )
        .await
        .expect("provider must answer the fast Sigma1 (pre-fix it was absorbed as the close ack)");

        // The whole OTA flow (download, apply, notify) runs on session 2.
        let reassembled = drive_ota_flow(&ctrl_io, provider_addr, &mut s2, sid2, 1).await;
        assert_eq!(reassembled, image_for_assert);
        server
            .await
            .unwrap()
            .expect("serve must complete on session 2's Notify");
        assert_eq!(
            sunk.lock().unwrap().len(),
            2,
            "one resumption record per accept"
        );
    }

    /// Residual-hardening regression (TODO-1.0 "OTA provider" residual 2): a
    /// requestor that reconnects mid-download re-initiates BDX with a
    /// `ReceiveInit` on its new session WITHOUT re-querying (its cached
    /// `QueryImageResponse` URI is still valid). The `BlockSender` armed by
    /// session 1's `QueryImage` is mid-transfer; the serve must re-arm it and
    /// serve the transfer from the start — pre-fix it aborted the whole serve
    /// with "BDX transfer aborted".
    #[allow(clippy::too_many_lines)] // Linear cross-session OTA protocol test; splitting hurts clarity.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_ota_rearms_bdx_for_cross_session_receive_init() {
        use crate::provider_server::ProviderServer;
        use matter_crypto::{PeerInfo, ResumptionId, ResumptionRecord};

        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr: _,
            discovery: _,
            device_creds,
            device_roots,
            device_node_id,
        } = loopback_harness();

        let state = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let fabric = &state.fabrics[0];
        let (provider_creds1, provider_roots, _compressed) =
            crate::credentials::operational_credentials(fabric).unwrap();
        let (provider_creds2, _, _) = crate::credentials::operational_credentials(fabric).unwrap();
        let provider_node_id = fabric.commissioner.node_id;
        let fabric_id = fabric.fabric_id;
        let provider_noc = provider_creds1.noc.clone();
        let (device_creds2, device_roots2) = make_device_creds_for_fabric(fabric);

        let prior_id = ResumptionId([0x45; 16]);
        let prior_secret = [0x27u8; 32];
        let provider_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: device_node_id,
                fabric_id,
                noc: device_creds.noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };
        let requestor_record = ResumptionRecord {
            id: prior_id,
            shared_secret: prior_secret,
            peer: PeerInfo {
                node_id: provider_node_id,
                fabric_id,
                noc: provider_noc.clone(),
                session_id: 0,
            },
            expires_at: None,
        };

        let image: Vec<u8> = (0..2500u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let offer = matter_ota::ImageOffer {
            software_version: 2,
            software_version_string: "2.0".into(),
            image_uri: format!("bdx://{provider_node_id:016X}/fw.ota"),
            update_token: vec![0xAB; 16],
        };

        let provider_addr = dev_io.local_addr();
        let image_for_assert = image.clone();
        let sunk: std::sync::Arc<std::sync::Mutex<Vec<matter_crypto::ResumptionRecord>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sunk_in = sunk.clone();
        let server = tokio::spawn(async move {
            ProviderServer::new(
                dev_io,
                vec![provider_creds1, provider_creds2],
                provider_roots,
                /* base_session_id */ 0x58,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .with_resumption_records(vec![provider_record])
            .with_record_sink(Box::new(move |r| sunk_in.lock().unwrap().push(r)))
            .serve_ota_once(offer, image, /* max_block_size */ 256)
            .await
        });

        // Session 1: resume CASE, QueryImage, START the download (one block)
        // — then "reboot" mid-transfer, leaving the BlockSender in Sending.
        let (mut s1, sid1) = resume_case_handshake(
            &ctrl_io,
            provider_addr,
            device_creds,
            device_roots,
            provider_node_id,
            fabric_id,
            requestor_record,
            0x0023,
        )
        .await;
        let token = ota_query_image(&ctrl_io, provider_addr, &mut s1, sid1, 1).await;
        let length = bdx_receive_init(&ctrl_io, provider_addr, &mut s1, sid1).await;
        let first_block = bdx_query_one_block(&ctrl_io, provider_addr, &mut s1, sid1, 0).await;
        assert!(
            !first_block.is_empty() && first_block.len() < length,
            "session 1 must stop mid-transfer"
        );

        // "Reboot": session 2 resumes with the record rotated during accept 1
        // and re-initiates BDX directly — NO fresh QueryImage.
        let rotated = sunk.lock().unwrap()[0].clone();
        let requestor_record2 = ResumptionRecord {
            id: rotated.id,
            shared_secret: rotated.shared_secret,
            peer: PeerInfo {
                node_id: provider_node_id,
                fabric_id,
                noc: provider_noc,
                session_id: 0,
            },
            expires_at: None,
        };
        let (mut s2, sid2) = resume_case_handshake(
            &ctrl_io,
            provider_addr,
            device_creds2,
            device_roots2,
            provider_node_id,
            fabric_id,
            requestor_record2,
            0x0024,
        )
        .await;
        let length2 = bdx_receive_init(&ctrl_io, provider_addr, &mut s2, sid2).await;
        assert_eq!(
            length2,
            image_for_assert.len(),
            "re-armed transfer serves the full image"
        );
        let reassembled =
            bdx_pull_blocks_and_ack_eof(&ctrl_io, provider_addr, &mut s2, sid2, length2).await;
        assert_eq!(
            reassembled, image_for_assert,
            "the re-initiated transfer must serve the image from the start"
        );
        // Apply + Notify on session 2 with session 1's token.
        ota_apply_update(&ctrl_io, provider_addr, &mut s2, sid2, &token, 2).await;
        send_notify_update_applied(&ctrl_io, provider_addr, &mut s2, sid2, &token, 2).await;

        server
            .await
            .unwrap()
            .expect("serve must survive the cross-session ReceiveInit");
    }

    #[tokio::test]
    async fn set_utc_time_over_loopback() {
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
        let reply = matter_interaction::build_invoke_response_status(
            matter_interaction::CommandPath {
                endpoint: 0,
                cluster: 0x0038,
                command: 0x00,
            },
            matter_interaction::ImStatus::Success,
        );
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x55,
            1,
            reply,
            /* expect_timed */ false,
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
        controller
            .node(device_node_id)
            .set_utc_time(1_000_000, crate::TimeGranularity::Seconds)
            .await
            .expect("set utc time");
        device.await.unwrap();
    }

    #[tokio::test]
    async fn set_time_zone_over_loopback_returns_dst_required() {
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
        // Device replies SetTimeZoneResponse{ ctx0 DSTOffsetRequired = true }.
        let resp_fields = {
            use matter_codec::{Tag, TlvWriter};
            let mut b = Vec::new();
            let mut w = TlvWriter::new(&mut b);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_bool(Tag::Context(0), true).unwrap();
            w.end_container().unwrap();
            b
        };
        let reply = matter_interaction::build_invoke_response_command(
            matter_interaction::CommandPath {
                endpoint: 0,
                cluster: 0x0038,
                command: 0x03,
            },
            &resp_fields,
        );
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x55,
            1,
            reply,
            false,
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
        let dst_required = controller
            .node(device_node_id)
            .set_time_zone(&[crate::TimeZoneEntry {
                offset_seconds: 3600,
                valid_at_us: 0,
                name: Some("CET".into()),
            }])
            .await
            .expect("set time zone");
        assert!(dst_required);
        device.await.unwrap();
    }

    #[tokio::test]
    async fn set_dst_offset_over_loopback() {
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
        let reply = matter_interaction::build_invoke_response_status(
            matter_interaction::CommandPath {
                endpoint: 0,
                cluster: 0x0038,
                command: 0x04,
            },
            matter_interaction::ImStatus::Success,
        );
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x55,
            1,
            reply,
            false,
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
        controller
            .node(device_node_id)
            .set_dst_offset(&[crate::DstOffsetEntry {
                offset_seconds: 3600,
                valid_starting_us: 0,
                valid_until_us: None,
            }])
            .await
            .expect("set dst offset");
        device.await.unwrap();
    }

    #[tokio::test]
    async fn revoke_commissioning_over_loopback() {
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
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            build_invoke_status_success(),
            /* expect_timed */ true,
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

        controller
            .node(device_node_id)
            .revoke_commissioning()
            .await
            .expect("revoke");
        device.await.unwrap();
    }

    #[tokio::test]
    async fn commissioning_window_status_reads_window_status_over_loopback() {
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

        // Device answers the read with WindowStatus = 1 (EnhancedWindowOpen).
        let reply = build_report_data(0, 0x003C, 0x0000, &matter_codec::Value::Uint(1));
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            reply,
            /* expect_timed */ false,
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

        let ws = controller
            .node(device_node_id)
            .commissioning_window_status()
            .await
            .expect("status");
        assert_eq!(
            ws.status,
            crate::admin::CommissioningWindowStatus::EnhancedWindowOpen
        );
        device.await.unwrap();
    }

    #[tokio::test]
    async fn list_fabrics_reads_fabrics_over_loopback() {
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

        // Build a single-fabric reply: one Structure with the six context-tagged fields.
        let fabric = matter_codec::Value::Structure(vec![
            (
                matter_codec::Tag::Context(1),
                matter_codec::Value::Bytes(vec![4u8; 65]),
            ),
            (
                matter_codec::Tag::Context(2),
                matter_codec::Value::Uint(0xFFF1),
            ),
            (
                matter_codec::Tag::Context(3),
                matter_codec::Value::Uint(0xAABB),
            ),
            (
                matter_codec::Tag::Context(4),
                matter_codec::Value::Uint(0x1234),
            ),
            (
                matter_codec::Tag::Context(5),
                matter_codec::Value::Utf8("home".into()),
            ),
            (
                matter_codec::Tag::Context(254),
                matter_codec::Value::Uint(1),
            ),
        ]);
        let reply = build_report_data(0, 0x003E, 0x0001, &matter_codec::Value::Array(vec![fabric]));
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            reply,
            /* expect_timed */ false,
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

        let fabrics = controller
            .node(device_node_id)
            .list_fabrics()
            .await
            .expect("list");
        assert_eq!(fabrics.len(), 1);
        assert_eq!(fabrics[0].fabric_index, 1);
        assert_eq!(fabrics[0].fabric_id, 0xAABB);
        device.await.unwrap();
    }

    // --- Task 3: read_acl loopback test ---

    #[tokio::test]
    async fn read_acl_reads_acl_over_loopback() {
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

        // Build a single-entry ACL reply: Administer/CASE/node 0x1234/no targets/fabric 1.
        let entry = matter_codec::Value::Structure(vec![
            (
                matter_codec::Tag::Context(1),
                matter_codec::Value::Uint(5), // privilege = Administer
            ),
            (
                matter_codec::Tag::Context(2),
                matter_codec::Value::Uint(2), // auth_mode = CASE
            ),
            (
                matter_codec::Tag::Context(3),
                matter_codec::Value::Array(vec![matter_codec::Value::Uint(0x1234)]),
            ),
            (matter_codec::Tag::Context(4), matter_codec::Value::Null),
            (
                matter_codec::Tag::Context(254),
                matter_codec::Value::Uint(1), // fabric_index
            ),
        ]);
        let reply = build_report_data(0, 0x001F, 0x0000, &matter_codec::Value::Array(vec![entry]));
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            reply,
            /* expect_timed */ false,
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

        let acl = controller
            .node(device_node_id)
            .read_acl()
            .await
            .expect("read_acl");
        assert_eq!(acl.len(), 1);
        assert_eq!(acl[0].privilege, crate::acl::AclPrivilege::Administer);
        device.await.unwrap();
    }

    // --- Task 4: remove_fabric helpers + loopback tests ---

    /// Build an `InvokeResponseMessage` whose single `InvokeResponseIB` carries
    /// a `CommandDataIB` (not `CommandStatusIB`) with the `NOCResponse` response
    /// command (cluster 0x003E, command 0x08). The fields struct is
    /// `[ctx0 = status, ctx1 = fabric_index?]`. This is the RESPONSE COMMAND
    /// shape — `InvokeResponse::Command { path, fields_tlv }` — mirroring the
    /// `parses_command_response_payload` test in `matter-interaction/src/invoke.rs`.
    fn build_invoke_response_noc(status: u8, fabric_index: Option<u8>) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseMessage
        w.put_bool(Tag::Context(0), false).unwrap(); // SuppressResponse
        w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
        w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
        w.start_structure(Tag::Context(0)).unwrap(); // Command = CommandDataIB
        w.start_list(Tag::Context(0)).unwrap(); // CommandPath
        w.put_uint(Tag::Context(0), 0).unwrap(); // endpoint
        w.put_uint(
            Tag::Context(1),
            u64::from(crate::opcreds::OPERATIONAL_CREDENTIALS_CLUSTER),
        )
        .unwrap(); // cluster 0x003E
        w.put_uint(Tag::Context(2), 0x08).unwrap(); // NOCResponse command id
        w.end_container().unwrap(); // /CommandPath
        w.start_structure(Tag::Context(1)).unwrap(); // CommandFields = NOCResponse struct
        w.put_uint(Tag::Context(0), u64::from(status)).unwrap(); // StatusCode
        if let Some(fi) = fabric_index {
            w.put_uint(Tag::Context(1), u64::from(fi)).unwrap(); // FabricIndex (optional)
        }
        w.end_container().unwrap(); // /CommandFields
        w.end_container().unwrap(); // /CommandDataIB
        w.end_container().unwrap(); // /InvokeResponseIB
        w.end_container().unwrap(); // /InvokeResponses
        w.put_uint(Tag::Context(0xFF), 11).unwrap(); // InteractionModelRevision
        w.end_container().unwrap(); // /InvokeResponseMessage
        buf
    }

    /// Like [`run_loopback_device`] but with NO timed handshake and a distinct
    /// reply for each inbound IM request: `replies[i]` is sent in response to the
    /// i-th request received after the CASE handshake.
    ///
    /// Used for `remove_fabric` which issues two sequential requests (a read then
    /// an invoke) and needs different reply content for each.
    async fn run_loopback_device_seq(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        replies: Vec<Vec<u8>>,
    ) {
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();

        // Sigma1 → Sigma2
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

        // Sigma3 → success StatusReport, absorb the ack.
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

        // Secured IM: reply to the i-th inbound request with replies[i].
        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);
        for reply_payload in &replies {
            let (wire, _) = io.recv_from().await.unwrap();
            let decoded = sessions.decode_inbound(&wire, Instant::now()).unwrap();
            let DecodeInboundOutput::AppMessage { exchange_id, .. } = decoded else {
                panic!("expected an IM request app message");
            };
            let out = sessions
                .encode_outbound(
                    sid,
                    Some(exchange_id),
                    0x05,
                    ProtocolId::INTERACTION_MODEL,
                    reply_payload,
                    MrpFlags { reliable: false },
                    Instant::now(),
                )
                .unwrap();
            io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        }
    }

    /// Does this `WriteRequestMessage` carry `MoreChunkedMessages` (ctx tag 3) =
    /// true? Mirrors `matter_interaction::write`'s `has_more_chunked` test helper:
    /// walk the top-level struct, skipping nested containers, looking for the
    /// boolean at context tag 3.
    fn write_request_has_more_chunked(msg: &[u8]) -> bool {
        use matter_codec::{Element, Tag, TlvReader};
        let mut r = TlvReader::new(msg);
        let _ = r.next(); // enter anonymous message struct
        loop {
            match r.next() {
                Ok(Some(Element::Scalar {
                    tag: Tag::Context(3),
                    value: matter_codec::Value::Bool(b),
                })) => return b,
                Ok(Some(Element::ContainerStart { .. })) => {
                    // Skip nested WriteRequests array / IBs.
                    let mut depth = 1usize;
                    while depth > 0 {
                        match r.next() {
                            Ok(Some(Element::ContainerStart { .. })) => depth += 1,
                            Ok(Some(Element::ContainerEnd)) => depth -= 1,
                            Ok(Some(_)) => {}
                            Ok(None) | Err(_) => return false,
                        }
                    }
                }
                Ok(Some(Element::ContainerEnd) | None) | Err(_) => return false,
                Ok(Some(_)) => {}
            }
        }
    }

    /// Loopback device for the chunked-write primitive. Completes CASE, then
    /// receives `expected_chunks` `WriteRequest`s (opcode 0x06) on ONE exchange,
    /// asserting `MoreChunkedMessages=true` on all but the last. Each
    /// non-final chunk is acknowledged at the MRP transport layer with a
    /// standalone ack (faithful to Matter §8.7.4: no per-chunk app response);
    /// after the final chunk it replies ONE `write_response` (opcode 0x07).
    #[allow(clippy::too_many_lines)] // CASE-handshake boilerplate, as the sibling mocks.
    async fn run_chunked_write_device(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        expected_chunks: usize,
        write_response: Vec<u8>,
    ) {
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();

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

        // --- Chunked write transaction ---
        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);

        let mut exchange_seen: Option<u16> = None;
        for i in 0..expected_chunks {
            let (w, _) = io.recv_from().await.unwrap();
            let recv_at = Instant::now();
            let DecodeInboundOutput::AppMessage {
                exchange_id,
                opcode,
                ..
            } = sessions.decode_inbound(&w, recv_at).unwrap()
            else {
                panic!("expected a WriteRequest app message for chunk {i}");
            };
            assert_eq!(opcode, 0x06, "chunk {i} must be a WriteRequest (0x06)");
            // All chunks ride ONE exchange (SH.1: one exchange for the whole
            // chunked transaction).
            match exchange_seen {
                None => exchange_seen = Some(exchange_id),
                Some(ex) => assert_eq!(
                    ex, exchange_id,
                    "every chunk must reuse the same exchange (one-exchange invariant)"
                ),
            }

            if i + 1 == expected_chunks {
                // Final chunk: MoreChunkedMessages must be clear (the last one).
                // Reply ONE WriteResponse on the same exchange — this piggybacks
                // the final chunk's MRP ack.
                let out = sessions
                    .encode_outbound(
                        sid,
                        Some(exchange_id),
                        0x07, // WriteResponse
                        ProtocolId::INTERACTION_MODEL,
                        &write_response,
                        MrpFlags { reliable: false },
                        Instant::now(),
                    )
                    .unwrap();
                io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
            } else {
                // Intermediate chunk: MoreChunkedMessages must be set. Ack it at
                // the MRP transport layer with a STANDALONE ack (no app payload)
                // — there is no per-chunk WriteResponse. We flush the buffered
                // piggyback ack by advancing the device's MRP clock past the
                // standalone-ack deadline (200ms), producing the ack packet.
                // (decode_inbound at `recv_at` buffered the pending ack.)
                let events =
                    sessions.handle_timeout(recv_at + std::time::Duration::from_millis(250));
                let mut sent_ack = false;
                for ev in events {
                    if let matter_transport::MrpEvent::SendStandaloneAck { packet, .. } = ev {
                        io.send_to(&packet, ctrl_addr).await.unwrap();
                        sent_ack = true;
                    }
                }
                assert!(
                    sent_ack,
                    "intermediate chunk {i} must produce a standalone MRP ack"
                );
            }
        }
    }

    /// The chunked-write primitive sends N `WriteRequest`s on ONE exchange (all
    /// but the last carrying `MoreChunkedMessages`), the device acks the
    /// intermediates at the MRP layer and replies one `WriteResponse(Success)`
    /// after the last; `chunked_write` returns those bytes, which parse to a
    /// per-path Success.
    #[tokio::test]
    async fn chunked_write_sends_all_chunks_one_exchange() {
        use matter_codec::{Tag, TlvWriter};
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

        // Build a real chunked write with a tiny budget so it splits into
        // multiple WriteRequestMessages (ReplaceAll + AppendItem chunks).
        let path = matter_interaction::AttributePath {
            endpoint: 1,
            cluster: 0x001F, // AccessControl-ish list target (value irrelevant to framing)
            attribute: 0x0000,
        };
        let elems: Vec<Vec<u8>> = (0u64..4)
            .map(|n| {
                let mut buf = Vec::new();
                let mut w = TlvWriter::new(&mut buf);
                w.put_uint(Tag::Anonymous, n).unwrap();
                buf
            })
            .collect();
        // Tiny budget forces several chunks; assert we actually chunked.
        let chunks = matter_interaction::build_list_write_chunks(path, &elems, 40, false);
        assert!(
            chunks.len() >= 2,
            "test needs a multi-chunk write; got {} chunk(s)",
            chunks.len()
        );
        // All but the last carry MoreChunkedMessages; the last does not.
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(
                write_request_has_more_chunked(c),
                i + 1 != chunks.len(),
                "chunk {i} MoreChunkedMessages flag"
            );
        }
        let n_chunks = chunks.len();

        // Hand-built WriteResponse(SUCCESS) for the written path (like
        // write_timed's blob).
        let write_response = {
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_array(Tag::Context(0)).unwrap(); // WriteResponses
            w.start_structure(Tag::Anonymous).unwrap(); // AttributeStatusIB
            w.start_list(Tag::Context(0)).unwrap(); // Path
            w.put_uint(Tag::Context(2), u64::from(path.endpoint))
                .unwrap();
            w.put_uint(Tag::Context(3), u64::from(path.cluster))
                .unwrap();
            w.put_uint(Tag::Context(4), u64::from(path.attribute))
                .unwrap();
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
            w.put_uint(Tag::Context(0), 0).unwrap(); // SUCCESS
            w.end_container().unwrap();
            w.end_container().unwrap(); // AttributeStatusIB
            w.end_container().unwrap(); // array
            w.put_uint(Tag::Context(0xFF), 11).unwrap();
            w.end_container().unwrap();
            buf
        };

        let device = tokio::spawn(run_chunked_write_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00DC,
            n_chunks,
            write_response,
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

        let resp = controller
            .node(device_node_id)
            .chunked_write(chunks)
            .await
            .expect("chunked_write");

        let statuses =
            matter_interaction::parse_write_response(&resp).expect("parse WriteResponse");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].1, matter_interaction::ImStatus::Success);

        device.await.unwrap();
    }

    /// `commissioner_node_id` returns the sole fabric's commissioner node id.
    #[tokio::test]
    async fn commissioner_node_id_returns_stored_id() {
        let Harness {
            store,
            ctrl_io,
            discovery,
            device_node_id,
            ..
        } = loopback_harness();

        let controller = crate::controller::MatterController::with_components(
            store,
            ctrl_io,
            discovery,
            Arc::new(SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        // loopback_harness creates the fabric with commissioner_node_id = 1.
        let id = controller
            .node(device_node_id)
            .commissioner_node_id()
            .await
            .expect("commissioner_node_id");
        assert_eq!(id, 1);
    }

    /// Self-protection guard: `remove_fabric` with the device's own fabric index
    /// must return `WouldRemoveSelf` WITHOUT sending an invoke — only the read
    /// (`CurrentFabricIndex`) goes to the device.
    #[tokio::test]
    async fn remove_fabric_refuses_self_over_loopback() {
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

        // Device replies to ONE request (the read for CurrentFabricIndex = 1).
        let reply = build_report_data(
            0,
            crate::opcreds::OPERATIONAL_CREDENTIALS_CLUSTER,
            crate::opcreds::ATTR_CURRENT_FABRIC_INDEX,
            &matter_codec::Value::Uint(1),
        );
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            reply,
            /* expect_timed */ false,
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

        let err = controller
            .node(device_node_id)
            .remove_fabric(1)
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::error::Error::WouldRemoveSelf),
            "expected WouldRemoveSelf, got {err:?}"
        );
        device.await.unwrap();
    }

    /// Happy path: `remove_fabric` for a DIFFERENT fabric index succeeds when the
    /// device responds with a `NOCResponse(status=0, fabric_index=2)`.
    #[tokio::test]
    async fn remove_fabric_removes_other_over_loopback() {
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

        // reply[0] = CurrentFabricIndex=1 (the read); reply[1] = NOCResponse(OK)
        let replies = vec![
            build_report_data(
                0,
                crate::opcreds::OPERATIONAL_CREDENTIALS_CLUSTER,
                crate::opcreds::ATTR_CURRENT_FABRIC_INDEX,
                &matter_codec::Value::Uint(1),
            ),
            build_invoke_response_noc(0, Some(2)),
        ];
        let device = tokio::spawn(run_loopback_device_seq(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x55,
            replies,
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

        controller
            .node(device_node_id)
            .remove_fabric(2)
            .await
            .expect("remove fabric 2 must succeed");
        device.await.unwrap();
    }

    /// Fail-closed guard: when the device's reply does NOT contain
    /// `CurrentFabricIndex` (here we reply with a different attribute on the
    /// same cluster — attribute 0x0001 `NOCs` — so
    /// `parse_current_fabric_index` returns `None`), `remove_fabric` must
    /// return `Err(Error::Operational(_))` and must NOT send a `RemoveFabric`
    /// invoke to the device.
    ///
    /// The loopback device is set to handle exactly ONE round-trip (the read).
    /// If `remove_fabric` falls through and attempts a second round-trip (the
    /// invoke), the device will have exited and the send will fail — the test
    /// would panic rather than silently pass. The `echoes = 1` constraint
    /// therefore also acts as a canary for the invoke-not-sent guarantee.
    #[tokio::test]
    async fn remove_fabric_fails_closed_when_fabric_index_unreadable() {
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

        // Reply with a report for attribute 0x0001 (NOCs), NOT 0x0005
        // (CurrentFabricIndex) — parse_current_fabric_index will return None.
        let reply = build_report_data(
            0,
            crate::opcreds::OPERATIONAL_CREDENTIALS_CLUSTER,
            0x0001, // NOCs — different attribute, not CurrentFabricIndex
            &matter_codec::Value::Array(vec![]),
        );
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            reply,
            /* expect_timed */ false,
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

        let err = controller
            .node(device_node_id)
            .remove_fabric(2)
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::error::Error::Operational(_)),
            "expected Operational error when CurrentFabricIndex unreadable, got {err:?}"
        );
        device.await.unwrap();
    }

    /// Build a `WriteResponseMessage` carrying one `AttributeStatusIB(path, SUCCESS)`.
    /// This is the device-side reply to a `WriteRequest` for ACL path 0/0x001F/0x0000.
    fn build_write_response_acl_success() -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(0)).unwrap(); // WriteResponses
        w.start_structure(Tag::Anonymous).unwrap(); // AttributeStatusIB
        w.start_list(Tag::Context(0)).unwrap(); // Path (AttributePathIB)
        w.put_uint(Tag::Context(2), 0).unwrap(); // endpoint 0
        w.put_uint(Tag::Context(3), 0x001F).unwrap(); // cluster AccessControl
        w.put_uint(Tag::Context(4), 0x0000).unwrap(); // attribute ACL
        w.end_container().unwrap();
        w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
        w.put_uint(Tag::Context(0), 0).unwrap(); // SUCCESS
        w.end_container().unwrap();
        w.end_container().unwrap(); // /AttributeStatusIB
        w.end_container().unwrap(); // /WriteResponses
        w.put_uint(Tag::Context(0xFF), 11).unwrap(); // IM revision
        w.end_container().unwrap();
        buf
    }

    /// `write_acl` with a small ACL that retains admin: device replies
    /// `WriteResponse(Success)` for path 0/0x001F/0x0000 → expect `[(path, Success)]`.
    ///
    /// `commissioner_node_id` is an internal actor query with no network round-trip,
    /// so the device only sees one datagram (the `WriteRequest` itself). `expect_timed`
    /// is false: the ACL attribute does not require a timed interaction.
    #[tokio::test]
    async fn write_acl_single_chunk_round_trip() {
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

        let reply = build_write_response_acl_success();
        // The device replies with WriteResponse opcode 0x07.  run_loopback_device
        // uses 0x05 (ReportData) for the reply opcode — the actor resolves by
        // (session, exchange), not opcode, so the bytes land correctly.  We need
        // 0x07 here to satisfy parse_write_response; use run_chunked_write_device
        // with expected_chunks=1 so the device sends 0x07.
        let device = tokio::spawn(run_chunked_write_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x60,
            /* expected_chunks */ 1,
            reply,
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

        // loopback_harness sets commissioner_node_id = 1; this entry retains admin.
        let our_node_id: u64 = 1;
        let entries = vec![crate::acl::AclEntry {
            privilege: crate::acl::AclPrivilege::Administer,
            auth_mode: crate::acl::AclAuthMode::Case,
            subjects: Some(vec![our_node_id]),
            targets: None,
            fabric_index: None,
        }];

        let statuses = controller
            .node(device_node_id)
            .write_acl(&entries)
            .await
            .expect("write_acl must succeed");

        assert_eq!(statuses.len(), 1);
        assert_eq!(
            statuses[0].1,
            matter_interaction::ImStatus::Success,
            "device must reply Success"
        );
        assert_eq!(statuses[0].0.cluster, crate::acl::ACCESS_CONTROL_CLUSTER);
        assert_eq!(statuses[0].0.attribute, crate::acl::ATTR_ACL);

        device.await.unwrap();
    }

    /// `write_acl` refuses an ACL that would lock out the commissioner and sends
    /// ZERO bytes to the device (the lockout guard runs before any network I/O).
    ///
    /// The device is NOT started at all: if `write_acl` tried to send anything
    /// there would be no device to accept the CASE handshake, and the test would
    /// panic or time out rather than pass silently.
    #[tokio::test]
    async fn write_acl_refuses_lockout() {
        let Harness {
            store,
            ctrl_io,
            discovery,
            ..
        } = loopback_harness();
        // No device spawned — zero datagrams must reach the network.

        let controller = crate::controller::MatterController::with_components(
            store,
            ctrl_io,
            discovery,
            Arc::new(SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        // Entry with Operate privilege (not Administer) for our node id = 1;
        // the lockout guard must fire before anything is sent.
        let entries = vec![crate::acl::AclEntry {
            privilege: crate::acl::AclPrivilege::Operate,
            auth_mode: crate::acl::AclAuthMode::Case,
            subjects: Some(vec![1]),
            targets: None,
            fabric_index: None,
        }];

        let err = controller
            .node(42) // node_id; irrelevant — lockout fires first
            .write_acl(&entries)
            .await
            .unwrap_err();

        assert!(
            matches!(err, crate::error::Error::AclWouldLockOut),
            "expected AclWouldLockOut, got {err:?}"
        );
        // No device was spawned — if write_acl had sent any bytes the test would
        // have failed because there is nothing to accept the CASE handshake.
    }

    /// `write_acl` multi-chunk path: build chunks directly with a tiny budget so
    /// they split, then drive them through `chunked_write` (which is what
    /// `write_acl` delegates to). The loopback device collects all chunks, asserts
    /// `MoreChunkedMessages=true` on all but the last (courtesy of
    /// `run_chunked_write_device`), then replies `WriteResponse(Success)`.
    ///
    /// Note: `write_acl` hardcodes budget=800 which won't force multi-chunk in a
    /// unit test (that would need ~100 large ACL entries). We therefore test the
    /// multi-chunk path via `chunked_write` directly, using the same tiny budget
    /// as Task 4's `chunked_write_sends_all_chunks_one_exchange`. This is
    /// explicitly endorsed by the brief ("a second from this angle is fine") and
    /// covers the end-to-end multi-chunk write path that `write_acl` delegates to.
    #[tokio::test]
    async fn write_acl_multi_chunk_reassembles() {
        use matter_codec::{Tag, TlvWriter};

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

        // Use AccessControl path to make it semantically coherent.
        let path = matter_interaction::AttributePath {
            endpoint: 0,
            cluster: crate::acl::ACCESS_CONTROL_CLUSTER,
            attribute: crate::acl::ATTR_ACL,
        };

        // Encode several small uint elements; a tiny budget forces multi-chunk.
        let elems: Vec<Vec<u8>> = (0u64..4)
            .map(|n| {
                let mut buf = Vec::new();
                let mut w = TlvWriter::new(&mut buf);
                w.put_uint(Tag::Anonymous, n).unwrap();
                buf
            })
            .collect();
        let chunks = matter_interaction::build_list_write_chunks(path, &elems, 40, false);
        assert!(
            chunks.len() >= 2,
            "test requires multi-chunk write; got {} chunk(s)",
            chunks.len()
        );
        let n_chunks = chunks.len();

        let write_response = build_write_response_acl_success();

        let device = tokio::spawn(run_chunked_write_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x61,
            n_chunks,
            write_response,
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

        let resp = controller
            .node(device_node_id)
            .chunked_write(chunks)
            .await
            .expect("chunked_write must succeed");

        let statuses =
            matter_interaction::parse_write_response(&resp).expect("parse WriteResponse");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].1, matter_interaction::ImStatus::Success);

        device.await.unwrap();
    }

    fn build_write_response_binding_success() -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(0)).unwrap(); // WriteResponses
        w.start_structure(Tag::Anonymous).unwrap(); // AttributeStatusIB
        w.start_list(Tag::Context(0)).unwrap(); // Path
        w.put_uint(Tag::Context(2), 1).unwrap(); // endpoint 1
        w.put_uint(Tag::Context(3), 0x001E).unwrap(); // cluster Binding
        w.put_uint(Tag::Context(4), 0x0000).unwrap(); // attribute Binding
        w.end_container().unwrap();
        w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
        w.put_uint(Tag::Context(0), 0).unwrap(); // SUCCESS
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();
        buf
    }

    #[tokio::test]
    async fn write_binding_single_chunk_round_trip() {
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
        let device = tokio::spawn(run_chunked_write_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x61,
            /* expected_chunks */ 1,
            build_write_response_binding_success(),
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
        let statuses = controller
            .node(device_node_id)
            .write_binding(
                1,
                &[crate::BindingTarget::new(
                    Some(0x1122),
                    None,
                    Some(1),
                    Some(0x0006),
                )],
            )
            .await
            .expect("write_binding");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].1, matter_interaction::ImStatus::Success);
        assert_eq!(statuses[0].0.cluster, 0x001E);
        assert_eq!(statuses[0].0.attribute, 0x0000);
        device.await.unwrap();
    }

    /// `write_acl` multi-chunk path exercised THROUGH the real `write_acl` dispatch.
    ///
    /// Uses `write_acl_with_budget` (the test-only budget seam) with a tiny budget
    /// (40 bytes) so the entries split into ≥2 chunks. This ensures the
    /// `if chunks.len() == 1 { … } else { chunked_write(…) }` branch inside
    /// `write_acl` is exercised: a miswired dispatch would be caught here, unlike
    /// `write_acl_multi_chunk_reassembles` which calls `chunked_write` directly.
    ///
    /// The lockout guard still runs first; we include an Administer/CASE entry
    /// for our node id so the guard passes.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn write_acl_multi_chunk_via_dispatch() {
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

        // loopback_harness sets commissioner_node_id = 1.  Administer/CASE/subject=1
        // ensures the lockout guard passes.  Three entries with budget=40 force ≥2 chunks.
        let entries = vec![
            crate::acl::AclEntry {
                privilege: crate::acl::AclPrivilege::Administer,
                auth_mode: crate::acl::AclAuthMode::Case,
                subjects: Some(vec![1u64]),
                targets: None,
                fabric_index: None,
            },
            crate::acl::AclEntry {
                privilege: crate::acl::AclPrivilege::Operate,
                auth_mode: crate::acl::AclAuthMode::Case,
                subjects: Some(vec![2u64]),
                targets: None,
                fabric_index: None,
            },
            crate::acl::AclEntry {
                privilege: crate::acl::AclPrivilege::View,
                auth_mode: crate::acl::AclAuthMode::Case,
                subjects: Some(vec![3u64]),
                targets: None,
                fabric_index: None,
            },
        ];

        // Compute expected chunk count so the device mock knows how many to receive.
        let acl_path = matter_interaction::AttributePath {
            endpoint: 0,
            cluster: crate::acl::ACCESS_CONTROL_CLUSTER,
            attribute: crate::acl::ATTR_ACL,
        };
        let element_tlvs: Vec<Vec<u8>> = entries
            .iter()
            .map(|e| crate::node::value_to_tlv(&crate::acl::acl_entry_value(e)).expect("encode"))
            .collect();
        let expected_chunks =
            matter_interaction::build_list_write_chunks(acl_path, &element_tlvs, 40, false).len();
        assert!(
            expected_chunks >= 2,
            "test requires multi-chunk write; got {expected_chunks} chunk(s)"
        );

        let device = tokio::spawn(run_chunked_write_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x62,
            expected_chunks,
            build_write_response_acl_success(),
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

        // Drive the multi-chunk path THROUGH write_acl's own dispatch branch.
        // Public write_acl uses budget=800; this seam forces the else-branch.
        let statuses = controller
            .node(device_node_id)
            .write_acl_with_budget(&entries, 40)
            .await
            .expect("write_acl_with_budget must succeed");

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].1, matter_interaction::ImStatus::Success);
        assert_eq!(statuses[0].0.cluster, crate::acl::ACCESS_CONTROL_CLUSTER);
        assert_eq!(statuses[0].0.attribute, crate::acl::ATTR_ACL);

        device.await.unwrap();
    }

    /// Byte-parity test: `build_list_write_chunks` for a one-entry ACL (Administer/CASE/
    /// subjects=[1]/targets=null) with a large budget produces bytes matching the
    /// spec-derived fixture at `test-vectors/acl/write_acl_single_chunk.json`.
    ///
    /// This confirms:
    /// 1. `acl_entry_value` encodes the spec-correct TLV layout.
    /// 2. Single-chunk output from `build_list_write_chunks` is byte-identical to a plain
    ///    `WriteRequestMessage`, which is the invariant `write_acl` relies on for the
    ///    single-chunk path (0xc6 auto-upgrade safety + network byte parity).
    #[test]
    fn write_acl_single_chunk_byte_parity() {
        use crate::acl::{acl_entry_value, AclAuthMode, AclEntry, AclPrivilege};
        use matter_codec::{Tag, TlvWriter};
        use matter_interaction::AttributePath;
        use std::{fs, path::PathBuf};

        // Struct and helpers declared before any statements (items_after_statements lint).
        #[derive(serde::Deserialize)]
        struct Fixture {
            entry_tlv_hex: String,
            expected_message_hex: String,
        }

        // Decode hex string to bytes.
        fn hex_decode(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }

        let fixture_path: PathBuf = {
            let mut p: PathBuf = env!("CARGO_MANIFEST_DIR").into();
            p.push("..");
            p.push("..");
            p.push("test-vectors");
            p.push("acl");
            p.push("write_acl_single_chunk.json");
            p
        };
        let Ok(raw) = fs::read_to_string(&fixture_path) else {
            eprintln!("skipping write_acl_single_chunk_byte_parity: fixture not found");
            return;
        };
        let f: Fixture = serde_json::from_str(&raw).unwrap();

        let expected_entry_tlv = hex_decode(&f.entry_tlv_hex);
        let expected_message = hex_decode(&f.expected_message_hex);

        // Encode the entry TLV using our public encoder.
        let entry = AclEntry {
            privilege: AclPrivilege::Administer,
            auth_mode: AclAuthMode::Case,
            subjects: Some(vec![1u64]),
            targets: None,
            fabric_index: None,
        };
        let mut entry_tlv: Vec<u8> = Vec::new();
        TlvWriter::new(&mut entry_tlv)
            .write_value(Tag::Anonymous, &acl_entry_value(&entry))
            .unwrap();
        assert_eq!(
            entry_tlv, expected_entry_tlv,
            "acl_entry_value TLV does not match fixture entry_tlv_hex"
        );

        let path = AttributePath {
            endpoint: 0,
            cluster: crate::acl::ACCESS_CONTROL_CLUSTER,
            attribute: crate::acl::ATTR_ACL,
        };
        let chunks = matter_interaction::build_list_write_chunks(path, &[entry_tlv], 4096, false);
        assert_eq!(chunks.len(), 1, "must be single chunk with big budget");
        assert_eq!(
            chunks[0], expected_message,
            "build_list_write_chunks single-chunk does not match fixture expected_message_hex"
        );
    }

    /// Happy path: `update_fabric_label` succeeds when the device responds
    /// with a `NOCResponse(status=0, fabric_index=1)`.
    #[tokio::test]
    async fn update_fabric_label_over_loopback() {
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
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            build_invoke_response_noc(0, Some(1)),
            /* expect_timed */ false,
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

        controller
            .node(device_node_id)
            .update_fabric_label("living-room")
            .await
            .expect("relabel");
        device.await.unwrap();
    }

    /// Happy path: `write_group_key_set` succeeds when the device responds
    /// with a bare `Success` status (plain invoke, not timed).
    #[tokio::test]
    async fn write_group_key_set_over_loopback() {
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
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            build_invoke_status_success(),
            /* expect_timed */ false,
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

        let set = crate::group::GroupKeySet::new(42, vec![0xABu8; 16], 0);
        controller
            .node(device_node_id)
            .write_group_key_set(&set)
            .await
            .expect("write_group_key_set");
        device.await.unwrap();
    }

    /// Build a `WriteResponseMessage` carrying one `AttributeStatusIB(path, SUCCESS)`.
    /// This is the device-side reply to a `WriteRequest` for `GroupKeyMap` 0/0x003F/0x0000.
    fn build_write_response_group_key_map_success() -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        #[allow(clippy::unwrap_used)] // test: Vec writer is infallible
        {
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_array(Tag::Context(0)).unwrap(); // WriteResponses
            w.start_structure(Tag::Anonymous).unwrap(); // AttributeStatusIB
            w.start_list(Tag::Context(0)).unwrap(); // Path (AttributePathIB)
            w.put_uint(Tag::Context(2), 0).unwrap(); // endpoint 0
            w.put_uint(Tag::Context(3), 0x003F).unwrap(); // cluster GroupKeyManagement
            w.put_uint(Tag::Context(4), 0x0000).unwrap(); // attribute GroupKeyMap
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
            w.put_uint(Tag::Context(0), 0).unwrap(); // SUCCESS
            w.end_container().unwrap();
            w.end_container().unwrap(); // /AttributeStatusIB
            w.end_container().unwrap(); // /WriteResponses
            w.put_uint(Tag::Context(0xFF), 11).unwrap(); // IM revision
            w.end_container().unwrap();
        }
        buf
    }

    /// `write_group_key_map` with one entry: device replies `WriteResponse(Success)`
    /// for path 0/0x003F/0x0000 → expect `[(path, Success)]`.
    ///
    /// `expect_timed` is false: `GroupKeyMap` does not require a timed interaction.
    #[tokio::test]
    async fn write_group_key_map_single_chunk_round_trip() {
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

        let reply = build_write_response_group_key_map_success();
        let device = tokio::spawn(run_chunked_write_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x61,
            /* expected_chunks */ 1,
            reply,
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

        let entries = vec![crate::group::GroupKeyMapEntry::new(7, 42)];
        let statuses = controller
            .node(device_node_id)
            .write_group_key_map(&entries)
            .await
            .expect("write_group_key_map must succeed");

        assert_eq!(statuses.len(), 1);
        assert_eq!(
            statuses[0].1,
            matter_interaction::ImStatus::Success,
            "device must reply Success"
        );
        assert_eq!(
            statuses[0].0.cluster,
            crate::group::GROUP_KEY_MANAGEMENT_CLUSTER
        );
        assert_eq!(statuses[0].0.attribute, crate::group::ATTR_GROUP_KEY_MAP);

        device.await.unwrap();
    }

    // --- Task 4 (M9-E1): add_group / remove_group loopback tests ---

    /// Build an `InvokeResponseMessage` carrying an `AddGroupResponse` response
    /// command (cluster 0x0004 `Groups`, command 0x00). Fields: `status` at
    /// context tag 0, `group_id` at context tag 1. This is the `CommandDataIB`
    /// shape (not `CommandStatusIB`) — `InvokeResponse::Command { path, fields_tlv }`.
    ///
    /// Replicates the `build_invoke_response_noc` structure with different
    /// cluster/command/fields.
    fn build_add_group_response(status: u8, group_id: u16) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        #[allow(clippy::unwrap_used)] // test: Vec writer is infallible
        {
            w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseMessage
            w.put_bool(Tag::Context(0), false).unwrap(); // SuppressResponse
            w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
            w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
            w.start_structure(Tag::Context(0)).unwrap(); // Command = CommandDataIB
            w.start_list(Tag::Context(0)).unwrap(); // CommandPath
            w.put_uint(Tag::Context(0), 1).unwrap(); // endpoint 1 (application ep on Tapo)
            w.put_uint(Tag::Context(1), u64::from(crate::group::GROUPS_CLUSTER))
                .unwrap(); // cluster 0x0004
            w.put_uint(Tag::Context(2), 0x00).unwrap(); // AddGroupResponse command id
            w.end_container().unwrap(); // /CommandPath
            w.start_structure(Tag::Context(1)).unwrap(); // CommandFields = AddGroupResponse struct
            w.put_uint(Tag::Context(0), u64::from(status)).unwrap(); // status
            w.put_uint(Tag::Context(1), u64::from(group_id)).unwrap(); // group_id
            w.end_container().unwrap(); // /CommandFields
            w.end_container().unwrap(); // /CommandDataIB
            w.end_container().unwrap(); // /InvokeResponseIB
            w.end_container().unwrap(); // /InvokeResponses
            w.put_uint(Tag::Context(0xFF), 11).unwrap(); // InteractionModelRevision
            w.end_container().unwrap(); // /InvokeResponseMessage
        }
        buf
    }

    /// `add_group` succeeds when the device replies with `AddGroupResponse(status=0, group_id=7)`.
    ///
    /// `expect_timed` is false: `Groups.AddGroup` does not require a timed interaction.
    #[tokio::test]
    async fn add_group_over_loopback() {
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
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            build_add_group_response(0, 7),
            /* expect_timed */ false,
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

        controller
            .node(device_node_id)
            .add_group(1, 7, "test")
            .await
            .expect("add_group must succeed");
        device.await.unwrap();
    }

    /// `remove_group` succeeds when the device replies with `RemoveGroupResponse(status=0, group_id=7)`.
    ///
    /// `expect_timed` is false: `Groups.RemoveGroup` does not require a timed interaction.
    #[tokio::test]
    async fn remove_group_over_loopback() {
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

        // RemoveGroupResponse (command 0x03) has the same field layout as AddGroupResponse.
        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            /* responder_session_id */ 0x55,
            /* echoes */ 1,
            build_add_group_response(0, 7),
            /* expect_timed */ false,
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

        controller
            .node(device_node_id)
            .remove_group(1, 7)
            .await
            .expect("remove_group must succeed");
        device.await.unwrap();
    }
}
