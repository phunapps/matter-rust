//! The owning controller task. Holds the transport, `SessionManager`,
//! discovery, and `ControllerState`. Processes [`Command`]s; while any
//! subscription is active it also listens for unsolicited reports.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use matter_commissioning::driver::AsyncDatagram;
use matter_commissioning::NocRng;
use matter_transport::{
    DecodeInboundOutput, Discovery, MrpEvent, MrpFlags, ProtocolHeader, ProtocolId, QueryHandle,
    ServiceKind, SessionId, SessionManager, SessionRole,
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
/// IM `WriteResponse` opcode — the device's per-chunk reply to a
/// `WriteRequest` in the chunked-write primitive. A device that rejects a
/// chunk outright (e.g. Busy) replies with a message-level `StatusResponse`
/// (opcode [`OP_STATUS_RESPONSE`]) instead — `resolve_chunked_write` checks
/// the opcode explicitly rather than assuming every reply is a `WriteResponse`.
const OP_WRITE_RESPONSE: u8 = 0x07;
/// IM status `NEEDS_TIMED_INTERACTION` — a device returns this when a write/invoke
/// that requires a timed interaction arrives without a preceding `TimedRequest`.
/// Triggers the transparent timed retry (see [`response_needs_timed`]).
const NEEDS_TIMED_INTERACTION: u8 = 0xc6;

/// `true` if a plain (non-timed) write/invoke response signals the device
/// requires a *timed* interaction (`NEEDS_TIMED_INTERACTION`, 0xc6).
///
/// A device may signal this two ways, and real hardware uses both:
/// * as a **message-level** `StatusResponse` (0xc6), or
/// * as a **per-command** `CommandStatusIB` inside an `InvokeResponse`, or a
///   **per-attribute** `AttributeStatusIB` inside a `WriteResponse`.
///
/// Only the first form was handled originally, so timed-required commands failed
/// against shipping devices that use the second — notably door locks (e.g. the
/// eufy E31, which returns 0xc6 as an `InvokeResponse` command status). Chip and
/// the Apple/Google controllers accept both forms, so handling both is required
/// for real-world interop. `opcode` is the original request opcode
/// (`OP_INVOKE_REQUEST` / `OP_WRITE_REQUEST`), used to select the response parser.
fn response_needs_timed(opcode: u8, payload: &[u8]) -> bool {
    // Message-level StatusResponse.
    if matches!(
        matter_interaction::parse_status_response(payload),
        Ok(Some(NEEDS_TIMED_INTERACTION))
    ) {
        return true;
    }
    // Per-command / per-attribute status embedded in the response body.
    match opcode {
        crate::node::OP_INVOKE_REQUEST => matches!(
            matter_interaction::parse_invoke_response_batch(payload),
            Ok(entries) if entries.iter().any(|e| matches!(
                e.response,
                matter_interaction::InvokeResponse::Status(s)
                    if s.to_u8() == NEEDS_TIMED_INTERACTION
            ))
        ),
        OP_WRITE_REQUEST => matches!(
            matter_interaction::parse_write_response(payload),
            Ok(statuses)
                if statuses.iter().any(|(_, s)| s.to_u8() == NEEDS_TIMED_INTERACTION)
        ),
        _ => false,
    }
}

/// How often the loop wakes while at least one operational resolve is parked.
///
/// mDNS results arrive by *polling* ([`Actor::drive_pending_resolves`] drains
/// [`Discovery::poll_results`]), not on a stored deadline, so this is the only
/// remaining periodic component of the actor's park: it applies solely while
/// `pending_resolves` is non-empty. Every other timer source contributes a real
/// deadline through [`Actor::next_timer_deadline`].
///
/// [`Discovery::poll_results`]: matter_transport::Discovery::poll_results
const RESOLVE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// How many consecutive `recv_from` errors the loop absorbs at full speed
/// before it starts backing off.
///
/// A socket surfaces isolated, recoverable errors as a matter of course — a
/// signal interrupting the syscall (`EINTR`), a spurious wakeup (`EWOULDBLOCK`),
/// or a queued ICMP error (`ECONNREFUSED`; that one reaches only a *connected*
/// UDP socket, which our `TokioUdpTransport` is not, but an out-of-tree
/// `AsyncDatagram` may well be) — and a blip must NOT cost the loop anything.
/// Only a *run* of errors, with no successful receive in between, suggests a
/// wedged transport rather than a blip, so the first few are free.
///
/// The run must also be close together in *time*: see [`RECV_ERROR_DECAY`],
/// which clears the counter after a quiet gap so the free budget is genuinely
/// restored rather than being a once-per-process allowance.
const RECV_ERROR_FREE_RETRIES: u32 = 8;

/// First backoff step (milliseconds) applied once [`RECV_ERROR_FREE_RETRIES`]
/// consecutive `recv_from` errors have gone by; it doubles per further
/// consecutive error, capped at [`RECV_ERROR_BACKOFF_MAX_MS`].
const RECV_ERROR_BACKOFF_MIN_MS: u64 = 1;

/// Ceiling (milliseconds) on the recv backoff.
///
/// Chosen below the ~300 ms floor of an MRP retransmit interval, so even a
/// permanently-erroring transport cannot suppress the recv arm long enough to
/// swallow a whole retransmit window for the datagrams that *do* arrive. It
/// bounds a wedged transport to ~5 wakeups per second — versus the ~75 000 per
/// second (~447 000 in 6 s) measured when the loop discarded the error and
/// immediately re-polled.
const RECV_ERROR_BACKOFF_MAX_MS: u64 = 200;

/// Quiet gap after which a run of `recv_from` errors is considered over, so the
/// consecutive counter (and the escalation state in [`RecvWarnStage`]) decays
/// back to zero.
///
/// Without this, `consecutive_recv_errors` would only ever be cleared by a
/// *successful* receive, and a controller whose only peer is offline — one
/// error per MRP retransmit, no intervening `Ok` for minutes — would march to
/// [`RECV_ERROR_BACKOFF_MAX_MS`] and stay pinned there for the life of the
/// process, delaying the first datagram from a returning device by up to that
/// cap. With the decay, the "an isolated blip costs nothing" property of
/// [`RECV_ERROR_FREE_RETRIES`] holds for every blip, not just the first few of a
/// process's life.
///
/// Deliberately LARGER than [`RECV_ERROR_BACKOFF_MAX_MS`]: at saturation the
/// backoff itself spaces polls ~200 ms apart, so a decay window at (or below)
/// the cap would be tripped by the backoff's own pacing and hand a permanently
/// wedged transport its free retries back on every cycle — re-opening a slow
/// version of the spin. Twice the cap leaves a comfortable margin over that
/// pacing while still being far shorter than any interval at which a healthy
/// controller sees repeated errors.
const RECV_ERROR_DECAY: std::time::Duration =
    std::time::Duration::from_millis(2 * RECV_ERROR_BACKOFF_MAX_MS);

/// Whether a `recv_from` error means the transport itself is gone, so the actor
/// should shut down rather than keep polling a socket that will never deliver.
///
/// Deliberately a SHORT list: everything not named here is treated as transient,
/// because killing a live controller over an error we failed to anticipate is
/// far worse than backing off on it (which [`Actor::run`] does, bounding the
/// cost of a permanently-transient error to
/// [`RECV_ERROR_BACKOFF_MAX_MS`]).
///
/// - [`std::io::ErrorKind::BrokenPipe`] — the endpoint's peer half is gone for
///   good. This is what [`matter_commissioning::driver::InMemoryDatagram`]
///   returns once its paired endpoint drops, and it is the case that spun.
/// - [`std::io::ErrorKind::NotConnected`] — `ENOTCONN`: the descriptor is no
///   longer a usable socket. No amount of retrying recovers it.
///
/// Everything else — `ConnectionRefused`, `ConnectionReset`, `Interrupted`
/// (`EINTR`), `WouldBlock`, `TimedOut`, `HostUnreachable`/`NetworkUnreachable`,
/// and any kind added by a future std — is transient. Only the two kinds above
/// are named, and both have been stable since Rust 1.0, so nothing here depends
/// on a variant newer than the 1.88 MSRV.
///
/// This split is part of the [`AsyncDatagram`] contract, not a private
/// heuristic: an out-of-tree transport that reports a *recoverable* gap as
/// `BrokenPipe` stops the controller for good. It is documented as such on
/// `AsyncDatagram::recv_from`.
///
/// [`AsyncDatagram`]: matter_commissioning::driver::AsyncDatagram
fn recv_error_is_terminal(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::NotConnected
    )
}

/// How long the recv arm stays suppressed after `consecutive` back-to-back
/// `recv_from` errors, or `None` while still inside the free-retry budget.
///
/// This is the backstop that makes the loop *incapable* of busy-looping on a
/// transport whose errors are transient-classified but recur forever: the delay
/// doubles from [`RECV_ERROR_BACKOFF_MIN_MS`] and saturates at
/// [`RECV_ERROR_BACKOFF_MAX_MS`], so a permanently-erroring transport settles at
/// a handful of wakeups per second. The suppression is expressed as a deadline
/// the loop parks on (not a `sleep` inside the arm), so commands, timers and MRP
/// keep running at full speed while it is in effect.
fn recv_error_backoff(consecutive: u32) -> Option<std::time::Duration> {
    let step = consecutive.saturating_sub(RECV_ERROR_FREE_RETRIES);
    if step == 0 {
        return None;
    }
    // `min(63)` keeps the shift in range; `unwrap_or` covers the (unreachable)
    // overflow return of `checked_shl` without an `unwrap`.
    let shift = (step - 1).min(63);
    let ms = RECV_ERROR_BACKOFF_MIN_MS
        .checked_shl(shift)
        .unwrap_or(u64::MAX)
        .min(RECV_ERROR_BACKOFF_MAX_MS);
    Some(std::time::Duration::from_millis(ms))
}

/// How far the current run of transient `recv_from` errors has already been
/// escalated to `warn`.
///
/// A transient error is logged at `debug`, which is right for the blip it
/// usually is — but a transport that fails EVERY receive is also "transient" by
/// the classification above, and it leaves the controller permanently deaf:
/// every read, write, subscribe and connect fails with a timeout while the
/// actor is alive and polling a handful of times a second. At the default
/// `info`/`warn` filter, nothing would ever say why. So the loop escalates to
/// `warn` on the *edges* of that condition — never per error, or a wedged
/// transport would become a log flood in its own right.
///
/// The stage only ever rises within a run; it is reset by a successful receive
/// and by [`RECV_ERROR_DECAY`], so a *later* wedge warns again.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum RecvWarnStage {
    /// Nothing warned for this run: either there is no run, or it is still
    /// inside the [`RECV_ERROR_FREE_RETRIES`] budget.
    #[default]
    Quiet,
    /// The run crossed [`RECV_ERROR_FREE_RETRIES`], so the receive arm is now
    /// being backed off — the first point at which "this is not a blip" is
    /// knowable.
    BackingOff,
    /// The backoff has reached [`RECV_ERROR_BACKOFF_MAX_MS`]: the transport has
    /// failed every receive across the whole ramp and looks wedged for good.
    Saturated,
}

/// The escalation stage implied by the backoff `recv_error_backoff` just
/// returned: `None` (still free) is [`RecvWarnStage::Quiet`], a capped backoff
/// is [`RecvWarnStage::Saturated`], anything in between is
/// [`RecvWarnStage::BackingOff`].
fn recv_error_warn_stage(backoff: Option<std::time::Duration>) -> RecvWarnStage {
    match backoff {
        None => RecvWarnStage::Quiet,
        Some(d) if d >= std::time::Duration::from_millis(RECV_ERROR_BACKOFF_MAX_MS) => {
            RecvWarnStage::Saturated
        }
        Some(_) => RecvWarnStage::BackingOff,
    }
}

/// Whether an error arriving at `now`, with the previous one at `prev`, starts a
/// NEW run — i.e. whether the quiet gap between them exceeded
/// [`RECV_ERROR_DECAY`], so the consecutive counter must decay to zero first.
///
/// `None` (no previous error, the state after every successful receive) is not a
/// broken run: there is nothing to decay.
fn recv_error_run_broken(prev: Option<Instant>, now: Instant) -> bool {
    prev.is_some_and(|prev| now.saturating_duration_since(prev) > RECV_ERROR_DECAY)
}

/// Backstop park duration when no timer work is scheduled at all. Timer
/// deadlines are recomputed after every loop iteration, so this only bounds
/// how long an unforeseen, unenumerated deadline source could stall; the
/// five known sources (MRP, liveness, resubscribe, resolve polling, recv
/// backoff) all flow through [`Actor::next_timer_deadline`].
const IDLE_PARK_MAX: std::time::Duration = std::time::Duration::from_secs(3600);

/// How long a parked operational resolve ([`Actor::park_resolve`]) waits for its
/// device's mDNS record before its waiters are failed. Matches the budget the
/// old inline resolve spent (`RESOLVE_POLL_ATTEMPTS` × 100 ms in
/// `matter_commissioning::driver`), which is of the same order as chip's
/// session-establishment discovery budget. The wait now costs the actor nothing
/// — it is one entry polled on the [`RESOLVE_POLL_INTERVAL`] arm, not a blocked
/// loop.
#[cfg(not(test))]
const RESOLVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
/// Shortened under `cfg(test)` so `actor_stays_live_while_resolve_pends` can
/// observe the expiry without 30 s of wall clock. Only the in-crate unit tests
/// see this; integration tests link the lib without `cfg(test)` and get 30 s.
#[cfg(test)]
const RESOLVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a drained operational record stays usable in `seen_records`.
///
/// Records must be cached at all because [`Discovery::poll_results`] CONSUMES
/// what it returns while the shared browse stays open: mdns-sd re-flushes its
/// cache only to *newly* opened browses, and otherwise re-emits an instance only
/// on an actual record refresh (its re-query backoff doubles 1 s, 2 s, 4 s … up
/// to an hour). Without the cache, a record drained while nothing was parked for
/// it would be lost, and a resolve parked seconds later for that very much
/// *online* device would sit until [`RESOLVE_DEADLINE`].
///
/// The TTL bounds the other direction: a device that moves address must not be
/// dialled at its old one indefinitely. A minute is far shorter than a Matter
/// operational record's typical TTL and than mdns-sd's own cache retention, so
/// a moved device is re-learned well before this matters.
const SEEN_RECORD_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Cap on cached operational records, so a large fabric (or a hostile flood of
/// `_matter._tcp` advertisements) cannot grow `seen_records` without bound. Well
/// above any realistic fabric size; the oldest entry is evicted to make room.
const SEEN_RECORD_CAP: usize = 256;

/// Max `ReportData` chunks a single read may span before aborting (mirrors
/// `matter_commissioning::driver::MAX_READ_CHUNKS`).
const MAX_READ_CHUNKS: usize = 64;
/// Max total decoded payload bytes a single read may accumulate (256 `KiB`).
const MAX_READ_BYTES: usize = 256 * 1024;

/// The Matter group multicast UDP port (Matter Core Spec §4.2.2 — operational
/// and group traffic share port 5540).
const MATTER_GROUP_PORT: u16 = 5540;

/// How many outbound group message counters one durable persist reserves.
///
/// The persisted `outbound_group_counter` holds the reserved **ceiling**, not
/// the last-sent value: every counter below it may be handed out without a
/// further store write. A crash therefore resumes at the ceiling, skipping at
/// most `GROUP_COUNTER_BLOCK - 1` never-sent values but NEVER reusing a sent
/// one (reuse would let an attacker replay an old group message).
///
/// 64 trades a bounded counter-space skip (the space is 2^32) for one fsync per
/// 64 group sends instead of one per send.
///
/// This is chip's design: `src/transport/GroupPeerMessageCounter.cpp` in
/// connectedhomeip persists a ceiling and keeps the live counter in RAM the
/// same way. chip reserves in blocks of 1000; 64 is the more conservative
/// choice (a crash skips fewer counters) and still amortizes the fsync away.
const GROUP_COUNTER_BLOCK: u32 = 64;

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
    /// the action timed (invoking `timed_payload`, which encodes the timed
    /// variant only at that point); otherwise it resolves `reply` with the
    /// response bytes and the unused closure is dropped. (See
    /// [`Actor::resolve_action`].)
    Action {
        opcode: u8,
        timed_payload: TimedPayload,
        keys: Vec<(u32, u32)>,
        timeout_ms: u16,
        node_id: u64,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    /// Chunked write: ONE `WriteRequest` chunk is in flight at a time on this
    /// exchange (chip's `WriteClient`: exactly one outstanding reliable
    /// message per exchange — Matter §8.7.4 / §10.6). `remaining` holds the
    /// chunks not yet sent, in order; `statuses` accumulates every chunk's
    /// parsed per-path statuses as they arrive.
    ///
    /// chip's `WriteClient` does NOT abort on a non-Success element status —
    /// it forwards every status to its callback and unconditionally sends the
    /// next chunk (`WriteClient.cpp:583-593`). So each `WriteResponse` (opcode
    /// [`OP_WRITE_RESPONSE`]) is parsed, its statuses appended to `statuses`,
    /// and — if `remaining` is non-empty — the next chunk is sent on the SAME
    /// exchange regardless of what those statuses were; the final chunk's
    /// `WriteResponse` (`remaining` empty) resolves `reply` with the FULL
    /// accumulated `statuses`.
    ///
    /// This is terminal (drops `remaining`, resolves `reply` with an `Err`)
    /// on: a malformed `WriteResponse` (parse failure — chip only aborts on a
    /// malformed response, not a bad element status); a message that is not a
    /// `WriteResponse` at all (a device that rejects a chunk outright — e.g.
    /// Busy 0x9C — replies with a message-level `StatusResponse` instead,
    /// which chip's `WriteHandler` sends via `StatusResponse::Send` then
    /// `Close`; parsing that as a `WriteResponse` would misread it as
    /// `Ok(vec![])`, a vacuous "all Success"); a send failure for the next
    /// chunk; or a pending timeout.
    ChunkedWrite {
        reply: oneshot::Sender<
            Result<
                Vec<(
                    matter_interaction::AttributePath,
                    matter_interaction::ImStatus,
                )>,
                Error,
            >,
        >,
        /// Chunks not yet sent, in order; popped from the front as each
        /// preceding chunk's `WriteResponse` arrives.
        remaining: VecDeque<Vec<u8>>,
        /// Per-path statuses accumulated across every chunk's `WriteResponse`
        /// so far, in arrival order.
        statuses: Vec<(
            matter_interaction::AttributePath,
            matter_interaction::ImStatus,
        )>,
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
/// liveness tracking + auto-resubscribe (an abandoned notification means
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

/// Lazily-built timed-variant payload for a write/invoke `Action`. The plain
/// payload is pre-encoded (it is always sent, except on a known-timed path);
/// the timed variant is built only when the device actually demands a timed
/// interaction (`NEEDS_TIMED_INTERACTION` escalation or learned-timed cache
/// hit) — the rare path. The common case drops this closure unused, so the
/// timed encode never runs.
pub(crate) type TimedPayload = Box<dyn FnOnce() -> Vec<u8> + Send>;

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
    /// Commission a device from a parsed setup payload; returns the resulting
    /// [`NodeInfo`](crate::NodeInfo) (with `vendor_id`/`product_id` left `None`
    /// — the controller fills those best-effort via a `BasicInformation` read
    /// after this reply resolves).  `label` is an opaque caller-supplied string
    /// persisted on the resulting `DeviceEntry` (set atomically with the rest
    /// of the entry, so it can never observably land only on a later save).
    Commission {
        setup_payload: matter_commissioning::SetupPayload,
        label: Option<String>,
        reply: oneshot::Sender<Result<crate::NodeInfo, Error>>,
    },
    /// Commission a device over BLE/BTP from a parsed setup payload and required
    /// network (Wi-Fi or Thread) credentials; returns the resulting
    /// [`NodeInfo`](crate::NodeInfo) (feature `ble`). Runs on its own spawned
    /// task exactly like [`Command::Commission`], but the task first scans BLE,
    /// opens a BTP session, and drives `commission_ble`. `label` is the same
    /// opaque caller-supplied string as [`Command::Commission`]'s.
    #[cfg(feature = "ble")]
    CommissionBle {
        setup_payload: matter_commissioning::SetupPayload,
        network: matter_commissioning::NetworkCredentials,
        label: Option<String>,
        reply: oneshot::Sender<Result<crate::NodeInfo, Error>>,
    },
    /// Persist `vendor_id`/`product_id` (from a post-commission `BasicInformation`
    /// read) onto the commissioned device `node_id`'s entry. Best-effort: a
    /// missing device is a no-op success. Used only by the commission
    /// orchestration, which has already reported success — this just enriches
    /// the stored metadata.
    SetNodeVidPid {
        node_id: u64,
        vendor_id: Option<u16>,
        product_id: Option<u16>,
        reply: oneshot::Sender<Result<(), Error>>,
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
    /// retry with `timed_payload` (built lazily, only on those two paths).
    /// Returns the final response bytes. (Explicit timed is
    /// [`Command::TimedRoundTrip`] via `write_timed`/`invoke_timed`.)
    Action {
        node_id: u64,
        opcode: u8, // OP_WRITE_REQUEST | OP_INVOKE_REQUEST
        plain_payload: Vec<u8>,
        timed_payload: TimedPayload,
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
    /// Send a chunked write as N `WriteRequestMessage`s on ONE exchange, ONE
    /// chunk in flight at a time — chip's `WriteClient` allows exactly one
    /// outstanding reliable message per exchange, gating each chunk on the
    /// device's `WriteResponse` to the previous one (see
    /// `Actor::handle_chunked_write` / `Actor::resolve_chunked_write`). All
    /// but the last chunk carry `MoreChunkedMessages=true`; every chunk is
    /// sent reliably (MRP). The device replies with a `WriteResponse` to
    /// EVERY chunk; every chunk's statuses are accumulated and the next chunk
    /// is sent UNCONDITIONALLY (chip's `WriteClient` pumps every chunk
    /// regardless of individual element statuses — it does not abort on a
    /// non-Success status). Terminal failure (no further chunks, `reply`
    /// resolves `Err`) happens only on a malformed `WriteResponse`, a
    /// non-`WriteResponse` reply (e.g. the device rejecting a chunk with a
    /// `StatusResponse`), a send failure, or a timeout. A single
    /// [`PendingReply::ChunkedWrite`] occupies `(session, exchange)` at any
    /// time — inserted after the first chunk, re-inserted after each
    /// subsequent chunk — and resolves with the FULL accumulated per-path
    /// status list on success.
    ChunkedWrite {
        node_id: u64,
        chunks: Vec<Vec<u8>>,
        reply: oneshot::Sender<
            Result<
                Vec<(
                    matter_interaction::AttributePath,
                    matter_interaction::ImStatus,
                )>,
                Error,
            >,
        >,
    },
    /// Return the actor's stored commissioner node id (the sole fabric's
    /// `commissioner.node_id`). Used by the ACL lockout guard, which must avoid
    /// writing an ACL that would lock the commissioner itself out.
    CommissionerNodeId {
        reply: oneshot::Sender<Result<u64, Error>>,
    },
    /// Enumerate all commissioned nodes across every fabric as typed
    /// [`NodeInfo`](crate::NodeInfo) — the snapshot-decoupled accessor.
    ListNodes {
        reply: oneshot::Sender<Vec<crate::NodeInfo>>,
    },
    /// Enumerate every fabric this controller has created as typed
    /// [`FabricInfo`](crate::FabricInfo) — the snapshot-decoupled accessor.
    /// Lets a caller check which `fabric_id`s already exist before calling
    /// [`Command::CreateFabric`] (issue #110).
    ListFabrics {
        reply: oneshot::Sender<Vec<crate::FabricInfo>>,
    },
    /// Drop ALL of the controller's own local state for `node_id` — the
    /// persisted `DeviceEntry`, its cached CASE session, and any parked
    /// connect bookkeeping — WITHOUT contacting the device. A local-state
    /// verb like [`Command::ListNodes`]/[`Command::SetNodeVidPid`]: handled
    /// only in [`Actor::dispatch_ready`], never routed through
    /// `command_target_node` (routing it as a node-addressed verb would try
    /// to open a CASE session to a node we are trying to forget, which may
    /// be unreachable or already reset). `reply` carries whether a device
    /// was actually found and removed.
    ForgetNode {
        node_id: u64,
        reply: oneshot::Sender<Result<bool, Error>>,
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
    /// group key + session id from the persisted `key_set_id`, takes the next
    /// outbound group counter from a **durably reserved block** (extending and
    /// persisting the reservation BEFORE sending when the block runs out),
    /// encodes a group-secured `InvokeRequest`, and multicasts it. No pending is
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

/// A serialized snapshot plus its ordering sequence.
///
/// Fully owned (no borrow of the actor): the actor is non-`Sync`, so anything
/// held across an `.await` — or moved into `spawn_blocking` — must own its
/// inputs, else the actor future is non-`Send` and unspawnable.
///
/// Saves are applied in **sequence order**, not in whichever order the blocking
/// pool happens to schedule them. Without this, a *detached* best-effort save
/// (see [`Actor::persist_best_effort`]) that was serialized first but
/// descheduled could win the store's atomic `rename` over a later durable save
/// and silently roll persisted state backwards. A job whose `seq` is older than
/// the last-written snapshot is therefore skipped.
struct SaveJob {
    store: Arc<dyn ControllerStore>,
    bytes: Vec<u8>,
    /// Serialize-time sequence from [`Actor::snapshot_seq`] (monotonic).
    seq: u64,
    /// Last-written sequence, shared by every save path of one actor. A `std`
    /// mutex, not a Tokio one, because it is only ever locked inside
    /// `spawn_blocking` — never on an async task, so it cannot block a runtime
    /// worker holding it across an await point.
    gate: Arc<std::sync::Mutex<u64>>,
}

impl SaveJob {
    /// Write the snapshot, unless a newer one already landed.
    ///
    /// Runs on the blocking pool. The gate lock is held across the store's
    /// write+fsync+rename deliberately: serializing writers *is* the ordering
    /// guarantee — releasing it earlier would let two renames interleave and
    /// leave the older bytes on disk. A stale job returns `Ok(())`: skipping is
    /// the intended outcome, not a failure.
    ///
    /// ## Why `Ok(())` on skip is sound for DURABLE saves
    ///
    /// A durable caller (`durable_save_inputs` + [`save_offloaded`]) treats
    /// `Ok(())` as "my state is on disk", so a skip must never lose a
    /// durability-critical write. Two things make that hold:
    ///
    /// 1. Durable saves are **serialized on the actor loop** — every one of them
    ///    is awaited inside a `select!` *arm body*, which runs to completion and
    ///    is never a cancellable branch future. No other save of this actor can
    ///    be serialized between a durable job's serialize and its write, so a
    ///    durable job is never actually skipped in today's code.
    /// 2. Even if one were, the snapshot is **whole-state**: a newer snapshot
    ///    already contains everything the skipped one did (sequences advance
    ///    monotonically from the same actor state), so "a newer write landed
    ///    first" and "my write landed" are indistinguishable on disk.
    ///
    /// NEW CALLERS MUST NOT issue durable saves from spawned tasks without
    /// revisiting this: off-loop saves can interleave with the loop's own, and
    /// point 1 — the property that makes the skip trivially unobservable — would
    /// no longer hold.
    ///
    /// A poisoned gate (a previous job panicked mid-save) is recovered rather
    /// than propagated: the protected value is a plain `u64` that a panic
    /// cannot leave in a torn state, and refusing every subsequent save would
    /// be strictly worse than continuing to order them.
    fn run(self) -> Result<(), crate::store::StoreError> {
        let mut last = match self.gate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.seq < *last {
            return Ok(());
        }
        self.store.save(&self.bytes)?;
        *last = self.seq;
        Ok(())
    }
}

/// Await a [`SaveJob`] on the Tokio blocking pool.
///
/// Free function (owns its inputs) so the actor never holds a `&self` borrow
/// across the `.await`: that would make the actor future non-`Send` and so
/// unspawnable. A panic inside `save` surfaces as a `JoinError`, mapped to an
/// operational persistence error rather than unwinding the actor loop.
async fn save_offloaded(job: SaveJob) -> Result<(), Error> {
    match tokio::task::spawn_blocking(move || job.run()).await {
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
    /// Secondary index over `subscriptions`: the device-facing identity
    /// `(session, wire subscription id)` → our stable [`SubId`]. Maintained
    /// exclusively by [`Self::insert_subscription`]/[`Self::remove_subscription`]
    /// so `deliver_report` resolves a steady-state report in O(1) instead of
    /// scanning every subscription per report.
    sub_index: HashMap<(SessionId, u32), SubId>,
    /// In-flight round-trips/reads/subscribe-handshakes, keyed by
    /// `(session, exchange)`. Resolved by [`Self::handle_inbound`].
    pending: HashMap<(SessionId, u16), Pending>,
    /// Monotonic source of stable [`SubId`]s.
    next_sub_id: u64,
    /// Monotonic snapshot sequence, bumped on every serialize. Stamped onto the
    /// resulting [`SaveJob`] so saves are applied in serialize order.
    snapshot_seq: u64,
    /// Sequence of the last snapshot actually written, shared by every save
    /// path (durable and best-effort) so they order against each other. See
    /// [`SaveJob::run`].
    save_gate: Arc<std::sync::Mutex<u64>>,
    /// Scheduled resubscribe attempts (fired from the timer arm when due).
    resubscribes: Vec<PendingResubscribe>,
    /// Learned set of `(cluster_id, attr_or_command_id)` paths the device has
    /// rejected with `NEEDS_TIMED_INTERACTION` — a write/invoke to one of these
    /// skips the (wasted) plain attempt and goes straight to a timed interaction.
    /// Populated on a `0xc6` rejection; covers manufacturer/ungenerated clusters
    /// and survives for the controller's lifetime (the spec's B3 learned-cache).
    timed_paths: std::collections::HashSet<(u32, u32)>,
    /// Sender half of the spawned-commission completions channel: cloned into
    /// each [`Self::spawn_commission`] task.
    commission_tx: mpsc::Sender<CommissionCompletion>,
    /// Receiver half, drained by an arm of the [`Self::run`] `select!`.
    commission_rx: mpsc::Receiver<CommissionCompletion>,
    /// Event-driven connect: work waiting on an in-flight CASE connect,
    /// coalesced per device node id. A key's presence means a connect to that
    /// node is running on a spawned task; the queued [`ConnectWaiter`]s are
    /// resumed (on success) or resolved/rescheduled (on error) when it
    /// completes. See [`Self::enqueue_connect_waiter`] /
    /// [`Self::handle_connect_done`].
    pending_connects: HashMap<u64, Vec<ConnectWaiter>>,
    /// Peer MRP config (from the operational mDNS `SII`/`SAI`/`SAT`) captured
    /// when a connect is spawned, applied to the session at
    /// [`Self::handle_connect_done`] so retransmits are sized to the peer, not
    /// our defaults (MRP-2). Keyed by node id; removed when the connect
    /// completes or the node is forgotten.
    connect_mrp: HashMap<u64, matter_transport::MrpConfig>,
    /// Operational resolves waiting on mDNS, polled from the timer arm by
    /// [`Self::drive_pending_resolves`]. A connect whose record is not already
    /// known parks here instead of blocking the loop on a poll loop; at most one
    /// entry per node (`pending_connects` coalesces concurrent connects).
    pending_resolves: Vec<PendingResolve>,
    /// When the next mDNS poll of `pending_resolves` is due.
    ///
    /// mDNS results arrive by *polling*, so unlike every other timer source the
    /// resolve tick has no naturally-occurring deadline — but it must still be
    /// an ABSOLUTE instant rather than a `now + RESOLVE_POLL_INTERVAL` computed per
    /// iteration: any other `select!` arm that fires more often than
    /// [`RESOLVE_POLL_INTERVAL`] (a busy device, or a transport whose `recv_from`
    /// returns errors back-to-back) would otherwise push a relative tick
    /// forward forever and starve discovery. Advanced by
    /// [`Self::drive_pending_resolves`]; only consulted while
    /// `pending_resolves` is non-empty.
    next_resolve_poll: Instant,
    /// Consecutive `recv_from` errors in the current run.
    ///
    /// Reset to zero by every `Ok` from the transport, and by a quiet gap of
    /// more than [`RECV_ERROR_DECAY`] between two errors (see
    /// [`recv_error_run_broken`] — without that decay the counter would only
    /// ever rise across the life of a controller whose peer is simply offline).
    /// It exists to size [`recv_error_backoff`], which is what stops a transport
    /// that errors forever from spinning the loop.
    consecutive_recv_errors: u32,
    /// When the most recent `recv_from` error arrived, or `None` if the last
    /// receive succeeded. Only used to age out a run of errors
    /// ([`RECV_ERROR_DECAY`]).
    last_recv_error_at: Option<Instant>,
    /// Which edge-triggered `warn!` about the current run of transient errors has
    /// already fired, so a permanently wedged transport is visible at default log
    /// levels without emitting a line per failed receive. See [`RecvWarnStage`].
    recv_warn_stage: RecvWarnStage,
    /// While `Some`, the `select!`'s recv arm is disabled until this instant —
    /// the backoff imposed after [`RECV_ERROR_FREE_RETRIES`] consecutive
    /// `recv_from` errors.
    ///
    /// Held as a deadline rather than a `sleep` inside the arm so a wedged
    /// transport never delays commands, MRP or subscription liveness: it is one
    /// more component of [`Self::next_timer_deadline`], and it is cleared at the
    /// top of every [`Self::run`] iteration once it has elapsed (an
    /// already-passed value here would make the loop's overdue-timer guard fire
    /// on every pass — the very spin this whole mechanism exists to prevent).
    recv_backoff_until: Option<Instant>,
    /// The ONE `_matter._tcp` browse shared by every parked resolve, opened when
    /// the first entry parks and stopped when the last one leaves.
    ///
    /// It must be shared: [`Discovery::stop_query`] stops the daemon-side browse
    /// for the whole [`ServiceKind`], so per-resolve handles would cancel each
    /// other's browse as they completed. One handle also means one
    /// [`Discovery::poll_results`] drain per tick serving all entries.
    resolve_query: Option<QueryHandle>,
    /// Operational records drained from that browse, keyed by ASCII-lowercased
    /// instance name. A drain consumes what it returns, so every record is
    /// cached — not just the ones a resolve is parked for right now — or a
    /// record that arrived before its resolve did would be lost. Bounded by
    /// [`SEEN_RECORD_CAP`], aged out by [`SEEN_RECORD_TTL`].
    seen_records: HashMap<String, SeenRecord>,
    /// IPv6 multicast egress interface for group sends (destination scope
    /// id). Set via `MatterControllerBuilder::multicast_interface`; `None`
    /// falls back to the `MATTER_MULTICAST_IF` env var, then kernel default.
    multicast_if: Option<u32>,
    /// Live next outbound group message counter per fabric id.
    ///
    /// **Never serialized.** The persisted
    /// [`FabricEntry::outbound_group_counter`](crate::state::FabricEntry) holds
    /// the reserved *ceiling* instead; this map hands out the values below it
    /// without touching the store, and initializes from the ceiling on restart
    /// (see [`GROUP_COUNTER_BLOCK`] and [`Self::handle_invoke_group`]).
    ///
    /// Entries are never removed because fabrics are never removed from
    /// `state.fabrics` locally — `Node::remove_fabric` removes *us* from a
    /// device's fabric table, and `forget_node` drops a device, not a fabric.
    /// If a local fabric-removal path is ever added it MUST drop the matching
    /// entry, or a re-created fabric with the same id would restart mid-block
    /// against a fresh (zero) persisted ceiling.
    group_counters: HashMap<u64, u32>,
    /// Derived group key material per fabric id, so a burst of group sends
    /// costs one set of HKDFs instead of four per packet
    /// ([`Self::handle_invoke_group`]).
    ///
    /// Same lifecycle note as `group_counters`: entries are never removed
    /// because fabrics are never removed locally. A future local
    /// fabric-removal path SHOULD still drop the matching entry: correctness
    /// does not depend on it (a re-created fabric changes either its epoch key
    /// or its RCAC public key, and [`Self::group_keys_for`] compares both), but
    /// leaving it keeps derived key material alive for a fabric that is gone.
    group_key_cache: HashMap<u64, GroupKeyCacheEntry>,
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

/// Derived group-key material for a fabric, computed once per
/// `(epoch_key, root_public_key)` pair.
///
/// Every value below is a pure function of `(epoch_key, root_public_key,
/// fabric_id)`. `fabric_id` is the map key, and the other two are **both**
/// stamped on the entry and compared on every use
/// ([`Actor::group_keys_for`]), which makes that pair the complete
/// invalidation condition. A key rotation (`create_group` / `KeySetWrite`)
/// changes the epoch key; a fabric that is ever removed and re-created under
/// the same id would change the RCAC public key. Either one forces
/// re-derivation, so an entry can never outlive the inputs it was derived
/// from — including under a future local fabric-removal path, which does not
/// exist today.
///
/// Deliberately keyed by fabric id alone, not by `(fabric_id, key_set_id)`:
/// nothing derived here depends on the key set id — it only selects WHICH
/// epoch key the caller passes in. Alternating sends between two key sets on
/// one fabric therefore stay correct (each send sees a different `epoch_key`
/// and re-derives), and in the degenerate case where two key sets hold the
/// same epoch key the cached material is the material both need anyway. The
/// cost of alternating is a re-derivation per send, i.e. today's behaviour.
///
/// The compressed fabric id is deliberately NOT stored: nothing reads it after
/// `op_group_key` is derived, and it is itself a pure function of the two
/// stamps above, so keeping it would only add a field that can go stale.
///
/// **Secret hygiene:** this holds derived key material long-lived and
/// unzeroized. That is acceptable because it is derived from the epoch key,
/// which is already resident unzeroized in
/// [`ControllerState`](crate::state::ControllerState) for as long as the
/// controller is open — dropping an entry removes no guarantee the caller had.
/// This is NOT a secret-erasure boundary (same position as
/// [`matter_crypto::aead::SessionAead`]): a caller that needs group key
/// material scrubbed must scrub the stored epoch keys.
struct GroupKeyCacheEntry {
    /// The epoch key these values were derived from — half the invalidation
    /// stamp.
    epoch_key: [u8; 16],
    /// The fabric's RCAC public key (SEC1 uncompressed), the compressed fabric
    /// id — and hence `op_group_key` — was derived from: the other half of the
    /// stamp. Fixed for a given fabric today; compared anyway so that a fabric
    /// re-created under the same id with a NEW root can never be served this
    /// entry's keys (which would put undecryptable frames on the wire).
    root_public_key: [u8; 65],
    /// Operational group key: the AES-CCM key for group messages.
    op_group_key: [u8; 16],
    /// Group session id carried in the group message header.
    group_session_id: u16,
    /// Privacy key for the header obfuscation (§4.8.3), derived from
    /// `op_group_key`.
    privacy_key: [u8; 16],
}

/// A completed spawned CASE connect (event-driven connect), delivered
/// back to the actor loop for session registration + waiter resolution. On
/// success it carries the established [`CaseSessionOutput`] (the actor registers
/// it — the task has no `SessionManager`) and the resolved device address.
///
/// [`CaseSessionOutput`]: matter_crypto::CaseSessionOutput
struct ConnectCompletion {
    node_id: u64,
    result: Result<(matter_crypto::CaseSessionOutput, SocketAddr), Error>,
}

/// A connect whose device has not been seen on mDNS yet, parked on the actor's
/// timer arm ([`Actor::drive_pending_resolves`]) instead of blocking the loop.
///
/// The connect's waiters already sit in `pending_connects` under `node_id`, so
/// this carries only what turning an mDNS hit into a spawned handshake needs.
struct PendingResolve {
    fabric_id: u64,
    node_id: u64,
    /// The operational instance name to match, case-insensitively:
    /// `<compressed-fabric-id>-<node-id>`.
    target: String,
    /// When to give up and fail the node's waiters.
    deadline: Instant,
}

/// One operational record drained from the shared browse, already reduced to
/// what a connect needs. Kept in `seen_records` so a record that arrives before
/// anyone is waiting for it is not thrown away — see [`SEEN_RECORD_TTL`].
struct SeenRecord {
    peer: SocketAddr,
    peer_mrp: matter_transport::MrpConfig,
    /// When this record was last drained; ages the entry out.
    seen: Instant,
}

/// A unit of work parked behind an in-flight CASE connect. On connect
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

/// Canonicalize a peer address for the in-flight-handshake route table.
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
/// [`Actor::dispatch`] to park a verb behind an off-loop connect instead of
/// running the handshake inline.
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
        Command::Action { reply, .. } | Command::TimedRoundTrip { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        // Distinct arm: `ChunkedWrite`'s reply carries parsed per-path
        // statuses, not raw bytes, so it cannot merge into the arm above.
        Command::ChunkedWrite { reply, .. } => {
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
/// loop**, driving it over a
/// [`HandshakeSocket`](crate::handshake_socket::HandshakeSocket) whose datagrams
/// flow through the actor's own socket (this task never touches a socket).
/// Reports the established session (or error) back over `done_tx`. Takes only
/// owned inputs so the future is `'static + Send` and can be `tokio::spawn`ed.
///
/// The device's address is resolved on the actor, via its injected discovery,
/// before this task is spawned ([`Actor::spawn_connect`] on a cached mDNS hit,
/// [`Actor::drive_pending_resolves`] once a parked lookup lands) — so only the
/// multi-round-trip handshake runs here.
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

/// A completed spawned commission, delivered back to the actor loop
/// over the completions channel for persistence + reply resolution.
struct CommissionCompletion {
    fabric_id: u64,
    result: Result<matter_commissioning::CommissionedFabric, Error>,
    /// Caller-supplied label to persist on the device entry, carried through
    /// from `Command::Commission`/`CommissionBle` (see there).
    label: Option<String>,
    reply: oneshot::Sender<Result<crate::NodeInfo, Error>>,
}

/// Run a full commission on a **freshly-bound socket + discovery**, off the actor
/// loop. Takes only owned inputs so the future is `'static` + `Send` and
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
    multicast_if: Option<u32>,
) -> Result<matter_commissioning::CommissionedFabric, Error> {
    use matter_commissioning::driver::{commission, DriverConfig};
    use matter_commissioning::CommissionerConfig;

    // Honour the builder's `multicast_interface` on this task-local socket
    // too (the main actor socket already binds with it); `None` keeps the
    // `MATTER_MULTICAST_IF` env fallback inside the transport.
    let transport = matter_transport::TokioUdpTransport::bind_with_multicast_if(0, multicast_if)
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
            sub_index: HashMap::new(),
            pending: HashMap::new(),
            next_sub_id: 1,
            snapshot_seq: 0,
            save_gate: Arc::new(std::sync::Mutex::new(0)),
            resubscribes: Vec::new(),
            timed_paths: std::collections::HashSet::new(),
            commission_tx,
            commission_rx,
            pending_connects: HashMap::new(),
            connect_mrp: HashMap::new(),
            pending_resolves: Vec::new(),
            next_resolve_poll: Instant::now(),
            consecutive_recv_errors: 0,
            last_recv_error_at: None,
            recv_warn_stage: RecvWarnStage::Quiet,
            recv_backoff_until: None,
            resolve_query: None,
            seen_records: HashMap::new(),
            multicast_if: None,
            group_counters: HashMap::new(),
            group_key_cache: HashMap::new(),
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
    /// ## Long handlers run off the loop
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
    ///   no second socket, no session migration. The device's address comes from
    ///   the injected discovery, drained non-blockingly: a cached record spawns
    ///   the handshake at once, and an unknown one parks a [`PendingResolve`]
    ///   polled on the timer arm ([`Self::drive_pending_resolves`]), so an
    ///   unreachable device costs the loop nothing while it is looked up.
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
    /// `select!`: [`Self::next_timer_deadline`] computes the earliest moment any
    /// timer work is due, and whenever that moment has already passed we run
    /// [`Self::drive_mrp`]/[`Self::check_liveness`]/[`Self::drive_resubscribes`]/
    /// [`Self::drive_pending_resolves`] immediately, then `continue`, regardless
    /// of how much inbound is pending.
    ///
    /// This guarantees deadlines are honoured under continuous inbound: each
    /// inbound packet costs one loop iteration, and at the start of the next
    /// iteration any deadline that came due is serviced before the next recv.
    /// It does not starve recv — the overdue path only fires when a timer is
    /// actually due (bounded by how many deadlines elapse, not by inbound rate),
    /// and otherwise we fall through to the `select!` where a ready recv is
    /// served. The trade-off versus simply dropping `biased` (letting tokio
    /// randomize) is determinism: the explicit check gives a hard "timers fire
    /// within one inbound-packet of their deadline" bound rather than a
    /// probabilistic one, which matters for MRP retransmit timing.
    ///
    /// ## Parking on the computed deadline
    ///
    /// The park is not periodic. Every iteration recomputes the deadline from
    /// the *scheduled work that actually exists* — MRP retransmit/ack-flush
    /// deadlines, subscription liveness deadlines, and pending resubscribe
    /// attempt times — with one exception: mDNS results arrive by polling rather
    /// than on a deadline, so while `pending_resolves` is non-empty the deadline
    /// also includes the [`RESOLVE_POLL_INTERVAL`] polling anchor
    /// `next_resolve_poll` — and, while a receive backoff is in force, the
    /// instant it expires (`recv_backoff_until`, see below).
    /// With nothing at all scheduled the loop parks on [`IDLE_PARK_MAX`];
    /// because all five sources are re-derived from live state after every
    /// iteration, work scheduled by any other `select!` arm shortens the very
    /// next park, so the backstop only bounds an unenumerated source.
    ///
    /// The consequence is that a fully idle controller (no in-flight MRP, no
    /// subscriptions, no parked resolves) wakes essentially never, instead of
    /// four times a second as the earlier fixed liveness tick did.
    ///
    /// ## Transport receive errors
    ///
    /// `recv_from` failures are classified rather than discarded. Discarding
    /// them (the original code) meant a transport whose error is *permanent*
    /// made the recv arm instantly ready forever and pegged a core — measured at
    /// ~447 000 error returns in 6 s (~75 000 per second) against an
    /// [`InMemoryDatagram`](matter_commissioning::driver::InMemoryDatagram)
    /// whose peer half had dropped.
    ///
    /// - A **terminal** kind ([`recv_error_is_terminal`]) means the socket will
    ///   never deliver again, so the actor shuts down through the same
    ///   [`Self::shutdown_discovery`] path a dropped command channel takes.
    /// - Anything else is **transient** and merely logged, because a socket
    ///   surfaces isolated, recoverable errors (`EINTR`, spurious wakeups, ICMP
    ///   errors queued on a connected socket) that must not kill a controller,
    ///   and because `ErrorKind` is `#[non_exhaustive]`: a kind we failed to
    ///   anticipate must back off, not stop the actor. To keep "transient" from
    ///   re-introducing the spin, [`RECV_ERROR_FREE_RETRIES`] consecutive errors
    ///   with no successful receive between them start a doubling backoff
    ///   ([`recv_error_backoff`]) that disables the recv arm until
    ///   `recv_backoff_until`. Because that is a deadline the loop parks on
    ///   rather than a sleep inside the arm, commands, MRP and liveness continue
    ///   at full speed while a wedged transport is backed off.
    ///
    /// A run of transient errors also decays ([`RECV_ERROR_DECAY`]), so a
    /// controller that sees one error every few seconds never creeps up to the
    /// backoff ceiling and stays there; and it escalates to `warn` on the edges
    /// of the condition ([`RecvWarnStage`]), so a transport that is wedged
    /// *transiently* — which leaves the controller unable to receive anything,
    /// at `debug` — is diagnosable at default log levels.
    pub(crate) async fn run(mut self, mut rx: mpsc::Receiver<Command>) {
        loop {
            let now = Instant::now();

            // Retire an elapsed recv backoff BEFORE the deadline is computed.
            // `recv_backoff_until` feeds `next_timer_deadline`, so a value left
            // behind in the past would make the overdue guard below fire on
            // every iteration — a spin of exactly the kind the backoff exists to
            // prevent. Cleared here, the field is only ever a future instant.
            if self.recv_backoff_until.is_some_and(|until| until <= now) {
                self.recv_backoff_until = None;
            }
            let recv_enabled = self.recv_backoff_until.is_none();

            let next_deadline = self.next_timer_deadline();

            // Fairness guard: if timer work is already due, service it before
            // draining any more inbound. This is what prevents a sustained
            // inbound flood (which keeps `recv_from()` perpetually ready) from
            // starving the timer arm and pushing MRP retransmits / subscription
            // liveness past their deadlines. It only fires when a deadline has
            // actually elapsed, so it cannot starve recv or busy-loop: each pass
            // advances every deadline forward — MRP `handle_timeout` reschedules
            // or drops, liveness/resubscribe entries are consumed or re-armed,
            // and `drive_pending_resolves` re-arms `next_resolve_poll` — so the
            // guard yields back to recv on the next iteration. The recv-backoff
            // deadline is the fifth source and is retired above before it can
            // ever be seen here as due.
            if next_deadline.is_some_and(|d| d <= now) {
                self.drive_mrp().await;
                self.check_liveness();
                self.drive_resubscribes().await;
                self.drive_pending_resolves();
                continue;
            }

            let sleep_for =
                next_deadline.map_or(IDLE_PARK_MAX, |d| d.saturating_duration_since(now));
            tokio::select! {
                biased;
                maybe = rx.recv() => match maybe {
                    Some(cmd) => self.dispatch(cmd).await,
                    // Every controller handle is gone: shut down.
                    None => return self.shutdown_discovery(),
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
                recv = self.transport.recv_from(), if recv_enabled => match recv {
                    Ok((packet, from)) => {
                        // Close the edge as loudly as it was opened: whoever saw
                        // "this transport is wedged" at `warn` must be able to
                        // see it recover at the same filter level. Bounded to one
                        // line per wedge, because the stage only leaves `Quiet`
                        // via the edge-triggered warnings below.
                        if self.recv_warn_stage > RecvWarnStage::Quiet {
                            tracing::warn!(
                                target: "matter_controller::actor",
                                after_consecutive_errors = self.consecutive_recv_errors,
                                "transport recv_from recovered; the controller is receiving again",
                            );
                        }
                        self.consecutive_recv_errors = 0;
                        self.last_recv_error_at = None;
                        self.recv_warn_stage = RecvWarnStage::Quiet;
                        self.handle_inbound(&packet, from).await;
                    }
                    // The transport is gone for good — leave through exactly the
                    // path a dropped command channel uses, so the shared mDNS
                    // browse is released rather than left running.
                    Err(e) if recv_error_is_terminal(e.kind()) => {
                        tracing::warn!(
                            target: "matter_controller::actor",
                            error = %e,
                            "transport recv_from failed terminally; stopping the actor loop",
                        );
                        return self.shutdown_discovery();
                    }
                    // Transient: keep serving, but back the recv arm off once a
                    // run of errors says the transport is not merely blipping.
                    Err(e) => self.note_transient_recv_error(&e, Instant::now()),
                },
                () = tokio::time::sleep(sleep_for) => {
                    tracing::trace!(target: "matter_controller::actor", "timer wake");
                    self.drive_mrp().await;
                    self.check_liveness();
                    self.drive_resubscribes().await;
                    self.drive_pending_resolves();
                }
            }
        }
    }

    /// Record a transient `recv_from` failure that arrived at `at`: age out a
    /// stale run, extend the current one, arm the backoff, and log it.
    ///
    /// Split out of [`Self::run`]'s `select!` so the loop body stays readable;
    /// `at` is a parameter (rather than an inner `Instant::now()`) so the
    /// decay's timing is testable.
    fn note_transient_recv_error(&mut self, e: &std::io::Error, at: Instant) {
        // Errors far enough apart are unrelated blips, not a run: decay first,
        // so the free-retry budget is genuinely restored rather than being a
        // once-per-process allowance.
        if recv_error_run_broken(self.last_recv_error_at, at) {
            self.consecutive_recv_errors = 0;
            self.recv_warn_stage = RecvWarnStage::Quiet;
        }
        self.last_recv_error_at = Some(at);
        self.consecutive_recv_errors = self.consecutive_recv_errors.saturating_add(1);
        let backoff = recv_error_backoff(self.consecutive_recv_errors);
        if let Some(backoff) = backoff {
            self.recv_backoff_until = Some(at + backoff);
        }
        // Edge-triggered escalation: `warn` exactly once when the run stops
        // looking like a blip, and once more when the backoff saturates. A
        // transport wedged on a transient kind makes the controller deaf, which
        // must not be invisible at `info` — but it must not be a log flood
        // either, so every other error stays at `debug`.
        let stage = recv_error_warn_stage(backoff);
        if stage > self.recv_warn_stage {
            self.recv_warn_stage = stage;
            let outlook = if stage == RecvWarnStage::Saturated {
                "the transport looks wedged for good; requests will time out until it recovers"
            } else {
                "backing the receive arm off; the controller receives nothing while this persists"
            };
            tracing::warn!(
                target: "matter_controller::actor",
                error = %e,
                kind = ?e.kind(),
                consecutive = self.consecutive_recv_errors,
                backoff = ?backoff,
                "transport recv_from keeps failing: {outlook}",
            );
        } else {
            tracing::debug!(
                target: "matter_controller::actor",
                error = %e,
                consecutive = self.consecutive_recv_errors,
                "transport recv_from failed transiently; continuing",
            );
        }
    }

    /// Earliest instant any timer work is due: MRP retransmit/ack-flush,
    /// subscription liveness, scheduled resubscribes — plus a polling tick
    /// ([`RESOLVE_POLL_INTERVAL`]) only while mDNS resolves are parked, because
    /// discovery results arrive by polling, not by deadline, and plus the recv
    /// backoff deadline while the recv arm is suppressed (else a loop with no
    /// other scheduled work would park past it and leave the arm disabled).
    /// `None` means nothing is scheduled and the loop parks on inbound/commands
    /// alone (bounded by [`IDLE_PARK_MAX`]).
    ///
    /// Recomputed from live state on every loop iteration, so any work
    /// scheduled by another `select!` arm is reflected in the very next park —
    /// there is no cached deadline to invalidate. Every component is an
    /// ABSOLUTE instant (including the resolve anchor, see
    /// `next_resolve_poll`), never `now + interval`: a relative component would
    /// be pushed forward by every unrelated wakeup and could be starved
    /// indefinitely by a busy loop.
    fn next_timer_deadline(&self) -> Option<Instant> {
        let mrp = self.sessions.poll_timeout();
        let liveness = self
            .subscriptions
            .values()
            .map(|e| e.liveness_deadline)
            .min();
        let resub = self.resubscribes.iter().map(|pr| pr.attempt_at).min();
        let resolve = if self.pending_resolves.is_empty() {
            None
        } else {
            Some(self.next_resolve_poll)
        };
        [mrp, liveness, resub, resolve, self.recv_backoff_until]
            .into_iter()
            .flatten()
            .min()
    }

    /// Process one command, parking device verbs behind an off-loop connect.
    ///
    /// If `cmd` targets a device with no live cached session, the CASE
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
                    self.enqueue_connect_waiter(fabric_id, node_id, ConnectWaiter::Command(cmd));
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
                label,
                reply,
            } => {
                // M9-G-d: spawn on its own socket + return to the loop
                // immediately; the result is resolved later via the completions
                // channel, so a multi-second commission no longer pauses other
                // sessions' MRP/liveness.
                self.spawn_commission(setup_payload, label, reply);
            }
            #[cfg(feature = "ble")]
            Command::CommissionBle {
                setup_payload,
                network,
                label,
                reply,
            } => {
                // Same off-loop pattern as `Command::Commission`, but the
                // spawned task scans BLE + opens a BTP session first.
                self.spawn_commission_ble(setup_payload, network, label, reply);
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
            Command::ListNodes { reply } => {
                let nodes = self
                    .state
                    .fabrics
                    .iter()
                    .flat_map(|f| {
                        f.devices.iter().map(move |d| crate::NodeInfo {
                            node_id: d.node_id,
                            fabric_id: f.fabric_id,
                            vendor_id: d.vendor_id,
                            product_id: d.product_id,
                            label: d.label.clone(),
                        })
                    })
                    .collect();
                let _ = reply.send(nodes);
            }
            Command::ListFabrics { reply } => {
                let fabrics = self
                    .state
                    .fabrics
                    .iter()
                    .map(|f| crate::FabricInfo {
                        fabric_id: f.fabric_id,
                        commissioner_node_id: f.commissioner.node_id,
                        node_count: f.devices.len(),
                        icac_enabled: f.icac.is_some(),
                    })
                    .collect();
                let _ = reply.send(fabrics);
            }
            Command::ForgetNode { node_id, reply } => {
                // Drop all LOCAL state for this node — no device round-trip, so
                // it works even when the device is unreachable or already reset.
                let mut removed = false;
                for fabric in &mut self.state.fabrics {
                    let before = fabric.devices.len();
                    let fabric_id = fabric.fabric_id;
                    fabric.devices.retain(|d| d.node_id != node_id);
                    if fabric.devices.len() != before {
                        removed = true;
                        // Evict the cached session (+ its dead MRP retransmits).
                        if let Some(c) = self.cache.remove(&(fabric_id, node_id)) {
                            self.sessions.remove(c.session_id);
                        }
                    }
                }
                // Fail any parked waiters and drop the connect bookkeeping for
                // this node. Reuse the existing helper — it removes
                // `connect_inbound`, `connect_routes`, AND `pending_connects`
                // and fails/reschedules each waiter by kind (do NOT hand-roll
                // this; a hand-rolled loop misses `connect_routes`).
                self.fail_connect_waiters(node_id, &Error::Operational("node forgotten".into()));
                // Drop any live subscriptions, scheduled resubscribes, and
                // in-flight pending ops for the node. This is essential to the
                // "no device contact" guarantee: a surviving `SubEntry` would,
                // on its next liveness deadline, drive the resubscribe engine to
                // open a fresh CASE handshake to the very node we just forgot —
                // reintroducing the exact hazard the local-only routing avoids.
                self.remove_subscriptions_for_node(node_id);
                self.resubscribes.retain(|pr| pr.node_id != node_id);
                self.pending.retain(|_, p| p.node_id != node_id);
                let outcome = if removed {
                    match self.durable_save_inputs() {
                        Ok(job) => save_offloaded(job).await.map(|()| true),
                        Err(e) => Err(e),
                    }
                } else {
                    Ok(false)
                };
                let _ = reply.send(outcome);
            }
            Command::SetNodeVidPid {
                node_id,
                vendor_id,
                product_id,
                reply,
            } => {
                let _ = reply.send(
                    self.handle_set_node_vid_pid(node_id, vendor_id, product_id)
                        .await,
                );
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
                self.remove_subscription(key);
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
        // Refuse a duplicate `fabric_id` before any key generation (issue
        // #110): loading a store that already has this fabric and calling
        // `create_fabric` unconditionally used to push a second `FabricEntry`
        // with the same id, after which `sole_fabric()` sees "multiple
        // fabrics" and every subsequent commission attempt fails opaquely.
        if self
            .state
            .fabrics
            .iter()
            .any(|f| f.fabric_id == cfg.fabric_id)
        {
            return Err(Error::FabricAlreadyExists(cfg.fabric_id));
        }
        // Clock-relative half of the validity check (issue #111's worse cases:
        // a `not_before` far in the future — typically a millisecond timestamp
        // — or an already-expired `not_after`). It lives here rather than in
        // `crate::fabric` so that `create_fabric` stays a pure function of its
        // inputs; this is the layer that already owns a clock reading.
        validate_validity_against_clock(cfg.validity, current_matter_time())?;
        let entry = crate::fabric::create_fabric(cfg, self.rng.as_ref())?;
        let fabric_id = entry.fabric_id;
        self.state.fabrics.push(entry);
        // Durability-critical: the caller must not consider the fabric created
        // (and its private keys safe) until the snapshot is on disk. Serialize
        // under `&self`, then drop the borrow before awaiting the offloaded save.
        let job = self.durable_save_inputs()?;
        save_offloaded(job).await?;
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
        let job = self.durable_save_inputs()?;
        save_offloaded(job).await?;
        Ok(())
    }

    /// Kick off a commission on a **spawned task with its own socket**.
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
        label: Option<String>,
        reply: oneshot::Sender<Result<crate::NodeInfo, Error>>,
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
        let multicast_if = self.multicast_if;

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
                multicast_if,
            )
            .await;
            let _ = tx
                .send(CommissionCompletion {
                    fabric_id,
                    result,
                    label,
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
        label: Option<String>,
        reply: oneshot::Sender<Result<crate::NodeInfo, Error>>,
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
                    label,
                    reply,
                })
                .await;
        });
    }

    /// Handle a completed spawned commission: on success persist the
    /// `DeviceEntry` + durably save, then resolve the original `reply`.
    async fn handle_commission_completion(&mut self, completion: CommissionCompletion) {
        let CommissionCompletion {
            fabric_id,
            result,
            label,
            reply,
        } = completion;
        let outcome = match result {
            Ok(commissioned) => {
                let mut device = crate::commission::device_entry_from_commissioned(&commissioned);
                device.label = label;
                // Build the NodeInfo to return. `vendor_id`/`product_id` are
                // `None` here — the controller fills them best-effort via a
                // BasicInformation read after this reply resolves (a device
                // read cannot run from inside the actor's completion handler).
                let info = crate::NodeInfo {
                    node_id: device.node_id,
                    fabric_id,
                    vendor_id: None,
                    product_id: None,
                    label: device.label.clone(),
                };
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
                    Ok(job) => save_offloaded(job).await.map(|()| info),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        };
        let _ = reply.send(outcome);
    }

    /// Persist `vendor_id`/`product_id` onto the commissioned device `node_id`'s
    /// entry (from the controller's post-commission `BasicInformation` read). A
    /// device that is not found is a no-op success — the metadata is enrichment,
    /// not a correctness-critical write, and the commission itself has already
    /// been reported successful. Persists only if a field actually changed.
    async fn handle_set_node_vid_pid(
        &mut self,
        node_id: u64,
        vendor_id: Option<u16>,
        product_id: Option<u16>,
    ) -> Result<(), Error> {
        let mut changed = false;
        for fabric in &mut self.state.fabrics {
            if let Some(device) = fabric.devices.iter_mut().find(|d| d.node_id == node_id) {
                if vendor_id.is_some() && device.vendor_id != vendor_id {
                    device.vendor_id = vendor_id;
                    changed = true;
                }
                if product_id.is_some() && device.product_id != product_id {
                    device.product_id = product_id;
                    changed = true;
                }
                break;
            }
        }
        if !changed {
            return Ok(());
        }
        let job = self.durable_save_inputs()?;
        save_offloaded(job).await
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
    /// Returns a fully owned [`SaveJob`] to feed to [`save_offloaded`]. The
    /// split is deliberate: serializing under `&mut self` and awaiting the save
    /// are kept in separate statements, and the job borrows nothing from the
    /// actor, so no borrow of the (non-`Sync`) actor is held across the
    /// `.await` — that would make the actor future non-`Send` and so
    /// unspawnable. Callers do `let job = self.durable_save_inputs()?;
    /// save_offloaded(job).await?;`.
    ///
    /// The job also carries the serialize-order sequence, so a concurrently
    /// detached best-effort save cannot overwrite it with older bytes.
    fn durable_save_inputs(&mut self) -> Result<SaveJob, Error> {
        let bytes = snapshot::serialize(&self.state)?;
        Ok(self.save_job(bytes))
    }

    /// Stamp already-serialized snapshot `bytes` with the next sequence and the
    /// shared write gate. The single place [`Actor::snapshot_seq`] advances, so
    /// every save path — durable and best-effort — is ordered against the rest.
    fn save_job(&mut self, bytes: Vec<u8>) -> SaveJob {
        self.snapshot_seq += 1;
        SaveJob {
            store: self.store.clone(),
            bytes,
            seq: self.snapshot_seq,
            gate: self.save_gate.clone(),
        }
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
    ///
    /// Detached does not mean unordered: the job carries its serialize-time
    /// sequence, so if a durable save lands first this write is skipped rather
    /// than rolling persisted state back to these older bytes
    /// ([`SaveJob::run`]).
    fn persist_best_effort(&mut self) {
        // Serialization failure here is purely best-effort state; dropping it
        // must not abort the connection that triggered it.
        let Ok(bytes) = snapshot::serialize(&self.state) else {
            return;
        };
        let job = self.save_job(bytes);
        // Fire-and-forget: detach the blocking save. The actor loop returns
        // immediately and never observes the fsync latency or its outcome.
        // (No logging facility is wired into this crate yet; a write error is
        // silently dropped, which is acceptable for a rebuildable address cache.)
        drop(tokio::task::spawn_blocking(move || {
            let _ = job.run();
        }));
    }

    /// The sole fabric, or an error if not exactly one (single-fabric only;
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

        // Upsert the persisted key-set config on the sole fabric. Re-creating
        // an existing `key_set_id` REPLACES it: a plain append would leave the
        // old epoch key first in the list, and the outbound path would keep
        // encrypting under the stale key while devices hold the newly
        // provisioned one — every group send would then fail to decrypt on the
        // device (found on real hardware, 2026-07-20). The retain also heals
        // stores already poisoned with duplicates by older builds.
        let fabric = self.sole_fabric_mut()?;
        fabric.group_keys.retain(|k| k.key_set_id != key_set_id);
        fabric.group_keys.push(crate::state::GroupKeySetConfig::new(
            key_set_id,
            epoch_key,
            epoch_start_time,
        ));

        // Durability-critical: the caller relies on the key set being persisted
        // before it programs the key onto devices (so a crash mid-provision can
        // resume from a known key). Serialize under `&self`, then drop the
        // borrow before awaiting the offloaded save.
        let job = self.durable_save_inputs()?;
        save_offloaded(job).await?;

        Ok(crate::GroupKeySet::new(
            key_set_id,
            epoch_key.to_vec(),
            epoch_start_time,
        ))
    }

    /// The fabric's derived group-key material, computed on first use and
    /// re-derived whenever the inputs it was derived from change.
    ///
    /// Four HKDFs (compressed fabric id → operational group key → group session
    /// id, plus the privacy key the framing layer would otherwise derive per
    /// packet) are pure overhead on a burst of group commands, since all four
    /// are a pure function of `(epoch_key, root_public_key, fabric_id)`.
    /// `fabric_id` is the cache key and the other two are compared here on
    /// every send — see [`GroupKeyCacheEntry`] for why that pair is the
    /// complete invalidation rule. A rotated key set (`create_group` /
    /// `KeySetWrite`) therefore re-derives before anything is sent under it.
    ///
    /// # Errors
    ///
    /// [`Error::Operational`] if any derivation fails (not expected: the inputs
    /// are fixed-size key material).
    fn group_keys_for(
        &mut self,
        fabric_id: u64,
        root_public_key: &[u8; 65],
        epoch_key: [u8; 16],
    ) -> Result<&GroupKeyCacheEntry, Error> {
        use std::collections::hash_map::Entry;
        match self.group_key_cache.entry(fabric_id) {
            // Hit: same fabric, same epoch key, same root key — every derived
            // value below is still exactly what a fresh derivation would
            // produce.
            Entry::Occupied(e)
                if e.get().epoch_key == epoch_key
                    && &e.get().root_public_key == root_public_key =>
            {
                Ok(e.into_mut())
            }
            // Miss (cold), or stale because the key set was rotated or the
            // fabric's root changed: derive the whole set.
            slot => {
                let compressed_fabric_id =
                    matter_crypto::derive_compressed_fabric_id(root_public_key, fabric_id)
                        .map_err(|e| Error::Operational(format!("compressed fabric id: {e}")))?;
                let op_group_key =
                    matter_crypto::derive_operational_ipk(&epoch_key, &compressed_fabric_id)
                        .map_err(|e| Error::Operational(format!("operational group key: {e}")))?;
                let group_session_id = matter_crypto::derive_group_session_id(&op_group_key)
                    .map_err(|e| Error::Operational(format!("group session id: {e}")))?;
                let privacy_key = matter_crypto::derive_group_privacy_key(&op_group_key)
                    .map_err(|e| Error::Operational(format!("group privacy key: {e}")))?;
                let fresh = GroupKeyCacheEntry {
                    epoch_key,
                    root_public_key: *root_public_key,
                    op_group_key,
                    group_session_id,
                    privacy_key,
                };
                // Replace the stale entry (or fill the empty slot) — the map
                // holds at most one entry per fabric either way.
                Ok(match slot {
                    Entry::Occupied(mut e) => {
                        e.insert(fresh);
                        e.into_mut()
                    }
                    Entry::Vacant(e) => e.insert(fresh),
                })
            }
        }
    }

    /// Fire-and-forget multicast group invoke (see [`Command::InvokeGroup`]).
    ///
    /// Derives the operational group key + group session id from the persisted
    /// `key_set_id`, allocates the next outbound group counter from a durably
    /// reserved block — **extending and persisting the reservation before
    /// sending** whenever the block is exhausted, since a reused counter
    /// weakens replay protection — builds a group-secured `InvokeRequest`, and
    /// multicasts it to the group's site-local address. Returns `Ok(())` as soon
    /// as the datagram is handed to the socket — no response is awaited.
    async fn handle_invoke_group(
        &mut self,
        group_id: u16,
        key_set_id: u16,
        path: matter_interaction::CommandPath,
        fields_tlv: &[u8],
    ) -> Result<(), Error> {
        // --- Gather everything from the sole fabric into owned locals so no
        // borrow of `self` is held across the persist `.await` below. ---
        let (fabric_id, source_node_id, root_public_key, epoch_key, ceiling) = {
            let fabric = self.sole_fabric()?;
            // (a) Look up the epoch key for this key set. Take the LAST match:
            // `create_group` upserts so duplicates no longer occur, but stores
            // written by older builds may still carry several entries for one
            // `key_set_id` — the most recently appended one is the key that was
            // last programmed onto devices via `KeySetWrite`, so it is the only
            // one the devices can decrypt.
            let epoch_key = fabric
                .group_keys
                .iter()
                .rfind(|k| k.key_set_id == key_set_id)
                .map(|k| k.epoch_key)
                .ok_or(Error::GroupNotProvisioned(key_set_id))?;
            // The RCAC root public key (SEC1 uncompressed) for the compressed
            // fabric id derivation (read straight off the stored root cert, as
            // the CASE credentials path does).
            let root_public_key = *fabric.rcac_cert.public_key().as_bytes();
            // (f) The persisted field is the reserved CEILING (see
            // `GROUP_COUNTER_BLOCK`), read here under the same borrow as the
            // rest. Exhaustion is detected at the reservation below — the only
            // place the ceiling can fail to advance — so there is no separate
            // pre-check: a ceiling of `u32::MAX` still has its last block's
            // counters left to burn.
            (
                fabric.fabric_id,
                fabric.commissioner.node_id,
                root_public_key,
                epoch_key,
                fabric.outbound_group_counter,
            )
        };

        // (b-e) Crypto derivations (reuse E2; never hand-rolled), computed once
        // per epoch key and cached per fabric — see `group_keys_for`.
        let entry = self.group_keys_for(fabric_id, &root_public_key, epoch_key)?;
        let op_group_key = entry.op_group_key;
        let group_session_id = entry.group_session_id;
        let privacy_key = entry.privacy_key;
        let mcast = matter_crypto::group_multicast_ipv6(fabric_id, group_id);

        // (f) Take the next counter from the reserved block, and PERSIST A NEW
        // RESERVATION BEFORE SENDING only when the block is exhausted.
        //
        // A counter reused after a crash would let an attacker replay an old
        // group message, so no datagram may carry a counter the store does not
        // already cover. The serialized `outbound_group_counter` therefore holds
        // the reservation CEILING, never the live value: any snapshot taken by
        // any save path — including a detached best-effort one that fires
        // mid-block — is safe, because a restart resumes at the ceiling, above
        // every counter this run could have sent.
        //
        // The live counter (`self.group_counters`) is deliberately NOT
        // serialized: persisting it is exactly the per-send fsync this replaces.
        //
        // No reentrancy: `handle_invoke_group` runs in a `select!` arm body on
        // the actor loop, which runs to completion, so no second group send can
        // interleave with the `.await` below and slip past the reservation.
        let next = *self.group_counters.entry(fabric_id).or_insert(ceiling);
        if next >= ceiling {
            // Extend the reservation. `checked_add` guards the wrap; when the
            // block would overflow we still reserve the remaining tail up to
            // `u32::MAX`, and only a `next` already AT `u32::MAX` is exhausted.
            let new_ceiling = next
                .checked_add(GROUP_COUNTER_BLOCK)
                .or_else(|| (next < u32::MAX).then_some(u32::MAX))
                .ok_or_else(|| {
                    Error::Operational("group counter exhausted — re-key the group".into())
                })?;
            self.sole_fabric_mut()?.outbound_group_counter = new_ceiling;
            let saved = match self.durable_save_inputs() {
                Ok(job) => save_offloaded(job).await,
                Err(e) => Err(e),
            };
            if let Err(e) = saved {
                // The raised ceiling never reached the store. Roll it back so a
                // later send cannot treat it as reserved — leaving it raised
                // in memory would hand out counters a crash would hand out
                // again. Nothing above `ceiling` was sent, so resuming there
                // stays sound.
                //
                // The lookup cannot fail: the identical call succeeded a few
                // lines above and the fabric set cannot change across the
                // awaited save (arm-body execution — see the reentrancy note).
                // It stays fallible-but-total rather than `?` so the store's
                // error, not a lookup error, is what the caller sees.
                debug_assert!(
                    self.sole_fabric().is_ok(),
                    "the fabric that was just reserved against must still exist"
                );
                if let Ok(fabric) = self.sole_fabric_mut() {
                    fabric.outbound_group_counter = ceiling;
                }
                return Err(e);
            }
        }
        // `saturating_add` cannot actually saturate below `u32::MAX`: `next` is
        // strictly below the (freshly extended) ceiling here, and `next ==
        // u32::MAX` already returned the exhaustion error above.
        self.group_counters
            .insert(fabric_id, next.saturating_add(1));
        let counter = next;

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
        // The privacy-key variant: ours is cached above, so the framing layer
        // does not re-derive it for every packet.
        let wire = matter_transport::encode_group_secured_with_privacy_key(
            &op_group_key,
            &privacy_key,
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
    /// connect if this is the first waiter. Concurrent work targeting
    /// the same not-yet-connected node coalesces onto a single handshake.
    fn enqueue_connect_waiter(&mut self, fabric_id: u64, node_id: u64, waiter: ConnectWaiter) {
        let already_connecting = self.pending_connects.contains_key(&node_id);
        self.pending_connects
            .entry(node_id)
            .or_default()
            .push(waiter);
        if !already_connecting {
            self.spawn_connect(fabric_id, node_id);
        }
    }

    /// Start a connect to `node_id`: look its operational record up on the
    /// actor's injected discovery and, once found, spawn the CASE handshake on a
    /// task ([`run_connect_task`]) whose I/O flows through the actor's socket.
    ///
    /// The lookup NEVER blocks the loop: the connect parks as a
    /// [`PendingResolve`] and is settled by a single non-sleeping
    /// [`Self::drive_pending_resolves`] pass — which usually resolves it on the
    /// spot, since the record is typically already in the browse's buffer (and
    /// which is what keeps the injected-discovery tests synchronous). Otherwise
    /// it stays parked for the timer arm. Previously this polled inline for the
    /// whole [`RESOLVE_DEADLINE`], stalling every other session behind one
    /// unreachable device.
    ///
    /// Only a credential/clock/query-setup failure fails the parked waiters here;
    /// a device that simply never answers fails at its deadline instead.
    fn spawn_connect(&mut self, fabric_id: u64, node_id: u64) {
        // Naming the record needs ONLY the compressed fabric id, so derive just
        // that — the full credential build (signer reconstruction from PKCS#8,
        // IPK derivation, cert clones) happens once, in `finish_spawn_connect`,
        // which may run many seconds later and wants a fresh validation clock.
        let compressed = self.sole_fabric().and_then(|fabric| {
            matter_crypto::derive_compressed_fabric_id(
                fabric.rcac_cert.public_key().as_bytes(),
                fabric.fabric_id,
            )
            .map_err(|e| Error::Operational(e.to_string()))
        });
        let compressed = match compressed {
            Ok(c) => c,
            Err(e) => {
                self.fail_connect_waiters(node_id, &e);
                return;
            }
        };
        let target = matter_commissioning::driver::operational_instance_name(compressed, node_id);

        if self.resolve_query.is_none() {
            match self.discovery.query(ServiceKind::Operational) {
                Ok(h) => self.resolve_query = Some(h),
                Err(e) => {
                    let err = Error::from(matter_commissioning::driver::DriverError::Transport(e));
                    self.fail_connect_waiters(node_id, &err);
                    return;
                }
            }
        }
        self.park_resolve(fabric_id, node_id, target);
        // Settle immediately rather than draining the browse here: every
        // `poll_results` call CONSUMES the records it returns, so a drain that
        // only looked for `target` would silently discard records other parked
        // resolves are waiting on. One settle pass owns every drain — and it
        // also consults `seen_records`, so a record drained before this connect
        // existed still resolves it on the spot.
        self.drive_pending_resolves();
    }

    /// Park an unresolved connect for the timer arm, with the
    /// [`RESOLVE_DEADLINE`] budget. The node's waiters stay in
    /// `pending_connects` and are resolved when the record lands or the deadline
    /// passes.
    ///
    /// Re-arms the polling anchor when this is the FIRST entry to park.
    /// `next_resolve_poll` is only consulted while `pending_resolves` is
    /// non-empty, so between resolves it goes stale (an instant far in the
    /// past); becoming due the moment the list refills would make
    /// [`Self::run`]'s overdue-timer guard spend one pass on a poll that was
    /// just performed. Re-arming here makes the invariant "the anchor is fresh
    /// whenever `pending_resolves` becomes non-empty" hold locally, instead of
    /// resting on the caller happening to call
    /// [`Self::drive_pending_resolves`] (which re-arms as its first statement)
    /// afterwards. Entries that join a non-empty list leave the existing anchor
    /// alone, so parking a second resolve cannot postpone the first's poll.
    fn park_resolve(&mut self, fabric_id: u64, node_id: u64, target: String) {
        if self.pending_resolves.is_empty() {
            self.next_resolve_poll = Instant::now() + RESOLVE_POLL_INTERVAL;
        }
        self.pending_resolves.push(PendingResolve {
            fabric_id,
            node_id,
            target,
            deadline: Instant::now() + RESOLVE_DEADLINE,
        });
    }

    /// `seen_records` key for an operational instance name. Matter instance
    /// names are hex, and DNS-SD comparison is case-insensitive, so lowercasing
    /// gives the same match the inline resolver's `eq_ignore_ascii_case` did.
    fn record_key(instance_name: &str) -> String {
        instance_name.to_ascii_lowercase()
    }

    /// Fold one browse drain into `seen_records`: age out stale entries, then
    /// store each record reduced to `(peer, peer_mrp)`.
    ///
    /// Address selection mirrors
    /// `matter_commissioning::driver::resolve_operational_with_mrp`'s per-poll
    /// body exactly (same
    /// [`preferred_address`](matter_commissioning::driver::preferred_address)
    /// routability pick, same `peer_mrp_config`) so the timer-driven path dials
    /// what the inline resolve would have dialled. A record with no usable
    /// address is dropped rather than cached as an un-dialable hit.
    fn record_seen(&mut self, services: &[matter_transport::MatterService], now: Instant) {
        self.seen_records
            .retain(|_, r| now.saturating_duration_since(r.seen) < SEEN_RECORD_TTL);
        for svc in services {
            let Some(addr) = matter_commissioning::driver::preferred_address(&svc.addresses) else {
                continue;
            };
            let key = Self::record_key(&svc.instance_name);
            // Make room for a genuinely new instance by dropping the oldest.
            if self.seen_records.len() >= SEEN_RECORD_CAP && !self.seen_records.contains_key(&key) {
                let oldest = self
                    .seen_records
                    .iter()
                    .min_by_key(|(_, r)| r.seen)
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    self.seen_records.remove(&k);
                }
            }
            self.seen_records.insert(
                key,
                SeenRecord {
                    peer: SocketAddr::new(addr, svc.port),
                    peer_mrp: svc.peer_mrp_config(),
                    seen: now,
                },
            );
        }
    }

    /// Last act of [`Self::run`]: abandon any parked resolve and release the
    /// shared mDNS browse.
    ///
    /// Dropping the actor is NOT enough. With a caller-supplied daemon
    /// (`MdnsSdDiscovery::with_daemon`, `owns_daemon == false`) nothing ever
    /// stops the browse, so a controller dropped mid-resolve would leave a
    /// `_matter._tcp` browse running on that shared daemon forever.
    fn shutdown_discovery(&mut self) {
        self.pending_resolves.clear();
        self.release_resolve_query_if_idle();
    }

    /// Drop the shared operational browse once no resolve still needs it, so an
    /// idle controller holds no mDNS query open.
    fn release_resolve_query_if_idle(&mut self) {
        if self.pending_resolves.is_empty() {
            if let Some(handle) = self.resolve_query.take() {
                self.discovery.stop_query(handle);
            }
        }
    }

    /// Drop any parked resolve for `node_id` (it has been resolved, failed, or
    /// the node was forgotten) and release the shared browse if it was the last.
    fn cancel_pending_resolve(&mut self, node_id: u64) {
        self.pending_resolves.retain(|pr| pr.node_id != node_id);
        self.release_resolve_query_if_idle();
    }

    /// Settle the parked resolves: drain the shared browse ONCE into
    /// `seen_records`, then match every parked entry against that cache — hits
    /// spawn their handshake, entries past [`RESOLVE_DEADLINE`] fail their node's
    /// waiters, the rest stay parked.
    ///
    /// The single drain is required for correctness, not just economy:
    /// [`Discovery::poll_results`] consumes what it returns, so a second drain
    /// elsewhere would steal records from entries this pass has not examined —
    /// and matching against the *cache* rather than this pass's snapshot is what
    /// stops a record that arrived before its resolve did from being lost (see
    /// [`SEEN_RECORD_TTL`]).
    ///
    /// Called from the timer arm, so [`RESOLVE_POLL_INTERVAL`] is the resolve's
    /// polling interval (the inline resolve it replaces polled every 100 ms), and once
    /// from [`Self::spawn_connect`] so an already-known record connects at once.
    /// Returns immediately when nothing is parked — an idle controller pays
    /// nothing.
    fn drive_pending_resolves(&mut self) {
        // Re-arm the polling tick FIRST, before any early return: the loop only
        // consults it while entries are parked, and arming it unconditionally
        // means no path can leave a due-in-the-past anchor behind that would
        // spin the fairness guard.
        self.next_resolve_poll = Instant::now() + RESOLVE_POLL_INTERVAL;
        let Some(handle) = self.resolve_query else {
            return;
        };
        if self.pending_resolves.is_empty() {
            return;
        }
        let services = self.discovery.poll_results(handle);
        let now = Instant::now();
        self.record_seen(&services, now);

        // Classify first, act after: the effects below need `&mut self`, which
        // the parked list cannot be borrowed across.
        let mut resolved: Vec<(u64, u64, SocketAddr, matter_transport::MrpConfig)> = Vec::new();
        let mut expired: Vec<(u64, String)> = Vec::new();
        let mut still_parked = Vec::with_capacity(self.pending_resolves.len());
        for pr in std::mem::take(&mut self.pending_resolves) {
            if let Some(rec) = self.seen_records.get(&Self::record_key(&pr.target)) {
                resolved.push((pr.fabric_id, pr.node_id, rec.peer, rec.peer_mrp));
            } else if now >= pr.deadline {
                expired.push((pr.node_id, pr.target));
            } else {
                still_parked.push(pr);
            }
        }
        self.pending_resolves = still_parked;
        self.release_resolve_query_if_idle();

        for (node_id, target) in expired {
            // Same error the inline resolve produced on budget exhaustion, so
            // callers that match on the message text are unaffected.
            let err = Error::from(matter_commissioning::driver::DriverError::Discovery(
                format!("operational node {target} not found via mDNS"),
            ));
            self.fail_connect_waiters(node_id, &err);
        }
        for (fabric_id, node_id, peer, peer_mrp) in resolved {
            self.finish_spawn_connect(fabric_id, node_id, peer, peer_mrp);
        }
    }

    /// Spawn the CASE handshake to an already-resolved `peer` — the tail of a
    /// connect, shared by [`spawn_connect`](Self::spawn_connect)'s fast path and
    /// the timer arm.
    ///
    /// The credentials and the certificate-validation clock are (re)built here
    /// rather than carried from `spawn_connect`: a parked connect may start its
    /// handshake many seconds later, and the device's operational chain must be
    /// checked against the time the handshake actually runs at.
    fn finish_spawn_connect(
        &mut self,
        fabric_id: u64,
        node_id: u64,
        peer: SocketAddr,
        peer_mrp: matter_transport::MrpConfig,
    ) {
        let creds = match self.sole_fabric() {
            Ok(fabric) => crate::credentials::operational_credentials(fabric),
            Err(e) => Err(e),
        };
        let (credentials, roots, _compressed) = match creds {
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
        // Capture the peer's advertised MRP config; applied to the session when
        // the handshake completes (MRP-2, see `handle_connect_done`).
        self.connect_mrp.insert(node_id, peer_mrp);
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

    /// Put a spawned connect's outbound datagram on the actor's own socket.
    /// Installs the `peer` → node-id route first — before the send, so
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

    /// Handle a finished spawned connect: tear down its routing, then
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
        // Apply the peer's advertised MRP config captured at spawn time (MRP-2);
        // default if the connect predates the capture (e.g. a recovery path).
        let peer_mrp = self.connect_mrp.remove(&node_id).unwrap_or_default();
        let sid = self
            .sessions
            .register_case_with_mrp(&output, SessionRole::Initiator, peer_mrp);
        if let Some(s) = self.sessions.get_mut(sid) {
            s.peer_addr = Some(peer);
        }
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
        // Drop any captured peer MRP config for this aborted/forgotten connect.
        self.connect_mrp.remove(&node_id);
        // …and any resolve still parked for it, so a forgotten node stops being
        // looked up and the shared browse closes with the last entry.
        self.cancel_pending_resolve(node_id);
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
    /// `(session, peer)` (pending-retry recovery, resumed by
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
    /// `(session, peer)` (resubscribe recovery, resumed by
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
    /// address hint in persisted state. Resumption is dormant: this
    /// always performs a full SIGMA handshake.
    ///
    /// This INLINE handshake is now a defensive fallback only. Every
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
        if let Some(s) = self.sessions.get_mut(sid) {
            s.peer_addr = Some(peer);
        }

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
    /// The NOC public key stays unknown until it is captured separately during
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
            }
            // UPDATE-ONLY: a `DeviceEntry` is born at commission time
            // ([`Self::handle_commission_completion`]), never on a connect. If
            // the node is not a known device — because it was `forget_node`ed
            // while this handshake was in flight, or was never commissioned —
            // this connect must NOT fabricate an entry. Doing so previously
            // pushed a placeholder with a ZEROED `peer_noc_public_key`, which
            // (a) resurrected a device the caller asked to forget and (b)
            // persisted a corrupt NOC key. A late connect to a forgotten node
            // now leaves persisted state untouched; its transient session is
            // never used (its waiters were failed by `forget_node`).
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
        timed_payload: TimedPayload,
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
        // Fast-path: a known-timed path skips the wasted plain attempt. This is
        // one of the two places the timed payload is actually encoded.
        if keys.iter().any(|k| self.timed_paths.contains(k)) {
            self.begin_timed(
                sid,
                peer,
                node_id,
                timeout_ms,
                opcode,
                timed_payload(),
                reply,
            )
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
        if !response_needs_timed(opcode, &payload) {
            let _ = reply.send(Ok(payload));
            return;
        }
        // Learn these paths so future ops skip the wasted plain attempt, then
        // retry the action as a timed interaction feeding the same reply. This
        // is the second (and only other) place the timed payload is encoded —
        // the same `build_*_timed` bytes as before, just built now instead of
        // up-front.
        for k in keys {
            self.timed_paths.insert(k);
        }
        self.begin_timed(
            sid,
            p.peer,
            node_id,
            timeout_ms,
            opcode,
            timed_payload(),
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

    /// Send a chunked write: `chunks` go on ONE exchange, ONE chunk in flight
    /// at a time (mirrors chip's `WriteClient`: exactly one outstanding
    /// reliable `WriteRequest` per exchange — Matter §8.7.4 / §10.6). The
    /// first chunk allocates the exchange (`encode_outbound(.., None, ..)`)
    /// via `send_request`; every later chunk reuses it (`Some(exchange)`),
    /// sent one at a time by [`Self::resolve_chunked_write`] as each
    /// preceding chunk's `WriteResponse` arrives. All but the last chunk
    /// carry `MoreChunkedMessages=true` (the caller built them via
    /// `build_list_write_chunks`). The device replies with a `WriteResponse`
    /// to EVERY chunk (chip's `WriteHandler` sends one per received
    /// `WriteRequest`); every chunk's statuses are accumulated and pumping
    /// continues UNCONDITIONALLY regardless of individual element statuses
    /// (chip's `WriteClient` does not abort on a non-Success status — see
    /// [`PendingReply::ChunkedWrite`]'s doc for the full terminal-failure list).
    ///
    /// Only ONE [`Pending`] is registered for this exchange at any time,
    /// keyed by `(session, exchange)`: registered here after the first
    /// chunk, then re-registered by [`Self::resolve_chunked_write`] after
    /// each subsequent chunk until the final chunk's `WriteResponse`
    /// resolves `reply` with the accumulated per-path status list.
    async fn handle_chunked_write(
        &mut self,
        node_id: u64,
        chunks: Vec<Vec<u8>>,
        reply: oneshot::Sender<
            Result<
                Vec<(
                    matter_interaction::AttributePath,
                    matter_interaction::ImStatus,
                )>,
                Error,
            >,
        >,
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

        // First chunk allocates the exchange; capture it so later chunks
        // (sent one at a time, gated on each WriteResponse — see
        // resolve_chunked_write) reuse it.
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

        // The remaining chunks are NOT sent here — chip's WriteClient gates
        // each chunk on the previous chunk's WriteResponse, so they wait in
        // `remaining` until resolve_chunked_write drains them one at a time.
        let mut remaining: VecDeque<Vec<u8>> = chunks.into();
        // The first chunk (just sent above) is also the request bytes this
        // pending retains — `remaining.pop_front()` re-yields it since
        // nothing has been popped yet.
        let first = remaining.pop_front().unwrap_or_default();

        self.pending.insert(
            (sid, exchange),
            Pending {
                node_id,
                peer,
                request: PendingRequest {
                    opcode: OP_WRITE_REQUEST,
                    protocol_id: ProtocolId::INTERACTION_MODEL,
                    // The chunk actually in flight right now (chunks[0]), not
                    // the final chunk — this is what a reconnect-resend would
                    // conceptually retry. `retried: true` below means a
                    // timeout never actually replays it (see that field's
                    // comment).
                    payload: first,
                },
                // A chunked write spans multiple reliable messages on one
                // exchange; a transparent reconnect-and-resend mid-transaction
                // would corrupt the device's accumulation (a partially-sent
                // chunked write on a dead session cannot be resumed — the
                // device discards an incomplete chunked transaction, and only
                // the caller re-issuing the whole write is correct). Mark it
                // already retried so a timeout fails the op cleanly instead
                // of attempting a reconnect-resend.
                retried: true,
                reply: PendingReply::ChunkedWrite {
                    reply,
                    remaining,
                    statuses: Vec::new(),
                },
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
                self.resolve_chunked_write(session_id, exchange_id, opcode, payload)
                    .await;
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

    /// Drive a chunked write's next chunk on the response to the chunk that
    /// just came back — chip's `WriteClient` allows exactly one outstanding
    /// `WriteRequest` per exchange (Matter §8.7.4 / §10.6). Mirrors
    /// [`Self::resolve_timed`]'s re-register-on-the-same-exchange shape, but
    /// unlike `resolve_timed` this checks `opcode` explicitly: a device that
    /// rejects a chunk outright (e.g. Busy) replies with a message-level
    /// `StatusResponse` (chip's `WriteHandler`: `StatusResponse::Send` then
    /// `Close`), not a `WriteResponse` — parsing that as a `WriteResponse`
    /// would misread it as `Ok(vec![])` (a vacuous "all Success") and pump
    /// the next chunk into a transaction the device has already closed.
    ///
    /// - If `opcode` is not [`OP_WRITE_RESPONSE`]: TERMINAL. If it's
    ///   [`OP_STATUS_RESPONSE`], parse the status and resolve `reply` with an
    ///   `Err` naming it; for any other opcode, resolve `reply` with an `Err`
    ///   naming the unexpected opcode. Either way, `remaining` is dropped —
    ///   no further chunks are sent.
    /// - Otherwise parse `payload` as a `WriteResponse`
    ///   ([`matter_interaction::parse_write_response`]). A parse failure is
    ///   also TERMINAL (`Err` to `reply`, `remaining` dropped) — chip only
    ///   aborts on a malformed response, not a bad element status.
    /// - On a successful parse, append its statuses to the accumulated
    ///   `statuses`. If `remaining` is empty, this was the final chunk:
    ///   resolve `reply` with `Ok(statuses)` (the full accumulated list).
    ///   Otherwise send the next chunk on the SAME exchange UNCONDITIONALLY
    ///   (chip's `WriteClient` pumps every chunk regardless of individual
    ///   element statuses — `WriteClient.cpp:583-593`) and re-register the
    ///   pending with what remains. A send failure resolves `reply` with the
    ///   error.
    async fn resolve_chunked_write(
        &mut self,
        sid: SessionId,
        exchange: u16,
        opcode: u8,
        payload: Vec<u8>,
    ) {
        let Some(p) = self.pending.remove(&(sid, exchange)) else {
            return;
        };
        let PendingReply::ChunkedWrite {
            reply,
            mut remaining,
            mut statuses,
        } = p.reply
        else {
            return;
        };

        if opcode != OP_WRITE_RESPONSE {
            let err = if opcode == OP_STATUS_RESPONSE {
                match matter_interaction::parse_status_response(&payload) {
                    Ok(Some(status)) => Error::Operational(format!(
                        "chunked write rejected by device: IM status 0x{status:02x}"
                    )),
                    _ => Error::Operational(
                        "chunked write rejected by device: malformed StatusResponse".into(),
                    ),
                }
            } else {
                Error::Operational(format!(
                    "chunked write: unexpected response opcode 0x{opcode:02x} (expected WriteResponse)"
                ))
            };
            let _ = reply.send(Err(err));
            return;
        }

        let chunk_statuses = match matter_interaction::parse_write_response(&payload) {
            Ok(s) => s,
            Err(e) => {
                let _ = reply.send(Err(Error::InteractionModel(e)));
                return;
            }
        };
        statuses.extend(chunk_statuses);

        let Some(next) = remaining.pop_front() else {
            // Final chunk: resolve with every chunk's accumulated statuses.
            let _ = reply.send(Ok(statuses));
            return;
        };
        if let Err(e) = self
            .send_on_exchange(sid, exchange, p.peer, OP_WRITE_REQUEST, &next)
            .await
        {
            let _ = reply.send(Err(e));
            return;
        }
        self.pending.insert(
            (sid, exchange),
            Pending {
                node_id: p.node_id,
                peer: p.peer,
                request: PendingRequest {
                    opcode: OP_WRITE_REQUEST,
                    protocol_id: ProtocolId::INTERACTION_MODEL,
                    payload: next,
                },
                retried: true, // see the ChunkedWrite insert in handle_chunked_write
                reply: PendingReply::ChunkedWrite {
                    reply,
                    remaining,
                    statuses,
                },
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
        let Some(&sub_id) = self.sub_index.get(&(session_id, wire_sub_id)) else {
            return;
        };
        let Some(entry) = self.subscriptions.get_mut(&sub_id) else {
            debug_assert!(false, "sub_index points at a missing subscription");
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
            self.remove_subscription(sub_id);
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
                    self.insert_subscription(
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
    /// session if the cached one was stale (preserves the original
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
        // ChunkedWrite pendings are always inserted with `retried: true` —
        // both the initial insert in `handle_chunked_write` and every
        // re-insert in `resolve_chunked_write` set it — so a timeout on one
        // always skips the `!p.retried` branch below and falls straight
        // through to `fail_pending`, never attempting a reconnect-resend
        // mid-transaction (see the rationale at those insert sites).
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
                self.enqueue_connect_waiter(fabric_id, p.node_id, ConnectWaiter::ResendPending(p));
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
            | PendingReply::Action { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            // Distinct arm: `ChunkedWrite`'s reply carries parsed per-path
            // statuses, not raw bytes, so it cannot merge into the arm above.
            PendingReply::ChunkedWrite { reply, .. } => {
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

    /// Insert/replace a subscription, keeping `sub_index` in lock-step.
    /// A resubscribe re-inserts the same `SubId` with a NEW
    /// `(session_id, wire_sub_id)` — the old index key is removed first
    /// (guarded: only if it still points at this `SubId`, see below).
    ///
    /// `wire_sub_id` comes from the device's `SubscribeResponse` — it is
    /// remote-influenced input, not our own bookkeeping. A non-compliant or
    /// hostile device can reuse a subscription id it already owns on a
    /// session for a second, distinct subscription, so two live `SubEntry`s
    /// CAN legitimately contend for one `(session_id, wire_sub_id)` key.
    /// This is handled as **keep-first-owner**: the key is claimed only when
    /// vacant or already owned by this `sub_id`; if a different `SubId`
    /// already holds it, that owner's index entry is left untouched and the
    /// new entry is simply left unindexed. An unindexed entry is dark to
    /// `deliver_report` until its own liveness deadline drives a resubscribe
    /// (which asks the device for a fresh id) — no worse than the old linear
    /// scan's arbitrary pick between two colliding entries, and unlike a
    /// blind overwrite it can never orphan the surviving owner's routing.
    fn insert_subscription(&mut self, sub_id: SubId, entry: SubEntry) {
        let new_key = (entry.session_id, entry.wire_sub_id);
        if let Some(old) = self.subscriptions.insert(sub_id, entry) {
            let old_key = (old.session_id, old.wire_sub_id);
            // Only clear the old key if it still maps to us — a collision
            // on that key (this `sub_id` never won it, see below) means
            // there is nothing of ours to remove there.
            if self.sub_index.get(&old_key) == Some(&sub_id) {
                self.sub_index.remove(&old_key);
            }
        }
        match self.sub_index.get(&new_key) {
            None => {
                self.sub_index.insert(new_key, sub_id);
            }
            Some(&existing) if existing == sub_id => {
                // Already ours (re-insert under an unchanged key) — no-op.
            }
            Some(_) => {
                // Deliberate keep-first-owner: a different live subscription
                // already holds this device-issued key. Leave it alone.
            }
        }
    }

    /// Remove a subscription and its index entry (the only removal path —
    /// a bare `subscriptions.remove` would silently corrupt `sub_index`).
    /// The index key is cleared only if it still maps to this `sub_id`: a
    /// subscription that lost a `(session, wire_sub_id)` collision in
    /// [`Self::insert_subscription`] was never indexed, so there is nothing
    /// to clear for it (and clearing unconditionally would delete the
    /// colliding survivor's live entry).
    fn remove_subscription(&mut self, sub_id: SubId) -> Option<SubEntry> {
        let entry = self.subscriptions.remove(&sub_id)?;
        let key = (entry.session_id, entry.wire_sub_id);
        if self.sub_index.get(&key) == Some(&sub_id) {
            self.sub_index.remove(&key);
        }
        Some(entry)
    }

    /// Remove every subscription bound to `node_id` (`forget_node`). Replaces
    /// the former bulk `retain`, which bypassed index maintenance.
    fn remove_subscriptions_for_node(&mut self, node_id: u64) {
        let ids: Vec<SubId> = self
            .subscriptions
            .iter()
            .filter(|(_, s)| s.node_id == node_id)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.remove_subscription(id);
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
        let Some(entry) = self.remove_subscription(sub_id) else {
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
    /// OFF the actor loop (the CASE handshake no longer blocks other
    /// sessions) and resume on completion; a missing fabric reschedules on backoff.
    async fn attempt_resubscribe(&mut self, pr: PendingResubscribe) {
        // A consumer that dropped both receivers can never observe this
        // subscription again — reap instead of retrying forever (the drop-side
        // cancel is lossy `try_send`, so this is the reliable reap point).
        if pr.tx.report_tx.is_closed() && pr.tx.ctrl_tx.is_closed() {
            return;
        }
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
            self.enqueue_connect_waiter(fabric_id, pr.node_id, ConnectWaiter::Resubscribe(pr));
        }
    }

    /// Reschedule a failed attempt with the next backoff step (retry forever).
    fn reschedule_resubscribe(&mut self, mut pr: PendingResubscribe) {
        // Same reap guard as `attempt_resubscribe`: a consumer that dropped
        // both receivers can never observe this subscription again.
        if pr.tx.report_tx.is_closed() && pr.tx.ctrl_tx.is_closed() {
            return;
        }
        pr.retry_count = pr.retry_count.saturating_add(1);
        let wait = resubscribe_backoff(self.rng.as_ref(), pr.retry_count);
        pr.attempt_at = Instant::now() + wait;
        self.resubscribes.push(pr);
    }

    /// The peer address for `sid`: O(1) from the session's stamped
    /// `peer_addr`; falls back to scanning subscriptions/pending/cache for
    /// sessions that predate stamping (defensive — every prod registration
    /// path stamps).
    fn peer_for_session(&self, sid: SessionId) -> Option<SocketAddr> {
        if let Some(addr) = self.sessions.get(sid).and_then(|s| s.peer_addr) {
            return Some(addr);
        }
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
/// (extremely unlikely in practice), or [`Error::SystemClockUnset`] if it reads
/// before the Matter epoch (see [`matter_time_from_unix_secs`]).
pub(crate) fn current_matter_time() -> Result<matter_cert::MatterTime, Error> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Operational(format!("clock: {e}")))?
        .as_secs();
    matter_time_from_unix_secs(secs)
}

/// Apply the clock-relative validity checks to a fabric's window, given
/// whatever this host's clock had to say.
///
/// Fabric creation itself needs no clock: `crate::fabric::create_fabric` mints
/// the RCAC, the optional ICAC and the commissioner NOC entirely from
/// `cfg.validity`. The clock is used only to *sanity-check* that caller-supplied
/// window, so an unusable clock means "cannot perform the check", not "cannot
/// create a fabric". We skip it and carry on: a board with no RTC that creates
/// its fabric during init with a hardcoded sane window and reaches an NTP server
/// seconds later is a normal deployment, and refusing it would buy nothing —
/// the certificates are entirely caller-supplied and may be perfectly good.
///
/// What is *not* skipped:
///
/// - The clock-independent half of the check still runs inside `create_fabric`
///   ([`crate::fabric`]'s `validate_validity`): epoch-zero `not_before` and an
///   inverted/empty window are rejected regardless. That matters here, because
///   code following our own documentation derives `not_before` from
///   `SystemTime::now()` — which on an unset clock is pre-2000, i.e. exactly the
///   `MatterTime(0)` that gets rejected. Since we know both facts at this point,
///   we say so explicitly rather than leaving the caller to guess why the
///   wall-clock time they passed was called "the Matter epoch".
/// - Every site that genuinely needs a real time — minting a *device* NOC during
///   commissioning, operational CASE — still calls [`current_matter_time`]
///   directly and still hard-fails with [`Error::SystemClockUnset`].
fn validate_validity_against_clock(
    validity: (matter_cert::MatterTime, matter_cert::MatterTime),
    clock: Result<matter_cert::MatterTime, Error>,
) -> Result<(), Error> {
    match clock {
        Ok(now) => crate::fabric::validate_validity_against_now(validity, now),
        Err(Error::SystemClockUnset(secs)) => {
            if validity.0 == matter_cert::MatterTime(0) {
                return Err(Error::InvalidFabricValidity(format!(
                    "not_before is the Matter epoch (MatterTime(0), 2000-01-01T00:00:00Z), and \
                     this host's clock is unset — it reads unix {secs}, before the Matter epoch — \
                     which is the likely source: MatterTime::from_unix_secs clamps any pre-2000 \
                     time to MatterTime(0). Set the host clock (NTP/RTC) before creating the \
                     fabric, or pass a known-good not_before explicitly"
                )));
            }
            tracing::warn!(
                target: "matter_controller::actor",
                unix_secs = secs,
                "host clock reads before the Matter epoch (unset RTC / pre-NTP); creating the \
                 fabric anyway from the caller-supplied validity window, but its plausibility \
                 could not be checked against a clock. Commissioning and CASE will still fail \
                 until the clock is set."
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Convert Unix seconds to a [`matter_cert::MatterTime`], refusing a reading
/// that predates the Matter epoch.
///
/// `MatterTime::from_unix_secs` **saturates** any pre-2000 time to
/// `MatterTime(0)`. On a host whose clock has not been set — embedded Linux
/// with no RTC, before NTP converges, a very plausible deployment — that is
/// exactly what we would get, and `MatterTime(0)` is the one value certificates
/// must never carry as `notBefore`: chip maps it to `99991231235959Z` when it
/// rebuilds the X.509 TBS, so the signature check fails and the certificate is
/// unusable (`ChipEpochToASN1Time`,
/// `connectedhomeip/src/credentials/CHIPCert.cpp`; the same root cause as issue
/// #111, one stage later at `AddNOC` rather than at
/// `AddTrustedRootCertificate`).
///
/// Failing here names the cause — an unset host clock — instead of minting a
/// device NOC that cannot work and letting it fail opaquely on the device.
///
/// # Errors
///
/// Returns [`Error::SystemClockUnset`] if `secs` is before the Matter epoch
/// (2000-01-01T00:00:00Z, Unix `946_684_800`).
fn matter_time_from_unix_secs(secs: u64) -> Result<matter_cert::MatterTime, Error> {
    let now = matter_cert::MatterTime::from_unix_secs(secs);
    if now.0 == 0 {
        return Err(Error::SystemClockUnset(secs));
    }
    Ok(now)
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

    /// Build a `WriteResponseMessage` whose single `AttributeStatusIB` carries
    /// `status` for `(endpoint, cluster, attribute)` — the per-attribute form of
    /// a write rejection (there is no public builder, so mirror the wire shape
    /// `parse_write_response` expects).
    fn build_write_response_status(
        endpoint: u16,
        cluster: u32,
        attribute: u32,
        status: u8,
    ) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(0)).unwrap(); // WriteResponses
        w.start_structure(Tag::Anonymous).unwrap(); // AttributeStatusIB
        w.start_list(Tag::Context(0)).unwrap(); // AttributePathIB
        w.put_uint(Tag::Context(2), u64::from(endpoint)).unwrap();
        w.put_uint(Tag::Context(3), u64::from(cluster)).unwrap();
        w.put_uint(Tag::Context(4), u64::from(attribute)).unwrap();
        w.end_container().unwrap();
        w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
        w.put_uint(Tag::Context(0), u64::from(status)).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();
        buf
    }

    // --- response_needs_timed: transparent timed auto-upgrade detection ---
    // Regression for the WeaveHome door-lock report: 0xc6 delivered inside an
    // InvokeResponse/WriteResponse (not just as a message-level StatusResponse)
    // must still trigger the timed retry.

    #[test]
    fn needs_timed_detects_message_level_status_response() {
        let payload = matter_interaction::build_status_response(NEEDS_TIMED_INTERACTION);
        // Detected regardless of which request opcode it answered.
        assert!(response_needs_timed(
            crate::node::OP_INVOKE_REQUEST,
            &payload
        ));
        assert!(response_needs_timed(OP_WRITE_REQUEST, &payload));
    }

    #[test]
    fn needs_timed_detects_per_command_invoke_status() {
        // The door-lock case: 0xc6 as a CommandStatusIB inside an InvokeResponse.
        let path = matter_interaction::CommandPath {
            endpoint: 1,
            cluster: 0x0101, // DoorLock
            command: 0x00,   // LockDoor
        };
        let payload = matter_interaction::build_invoke_response_status(
            path,
            matter_interaction::ImStatus::Failure(NEEDS_TIMED_INTERACTION),
        );
        assert!(
            response_needs_timed(crate::node::OP_INVOKE_REQUEST, &payload),
            "0xc6 carried in an InvokeResponse must trigger the timed retry"
        );
    }

    #[test]
    fn needs_timed_detects_per_attribute_write_status() {
        // 0xc6 as an AttributeStatusIB inside a WriteResponse.
        let payload = build_write_response_status(0, 0x0028, 0x05, NEEDS_TIMED_INTERACTION);
        assert!(
            response_needs_timed(OP_WRITE_REQUEST, &payload),
            "0xc6 carried in a WriteResponse must trigger the timed retry"
        );
    }

    #[test]
    fn needs_timed_false_for_success_and_other_failures() {
        let path = matter_interaction::CommandPath {
            endpoint: 1,
            cluster: 0x0101,
            command: 0x00,
        };
        // A successful invoke status is not a timed requirement.
        let ok = matter_interaction::build_invoke_response_status(
            path,
            matter_interaction::ImStatus::Success,
        );
        assert!(!response_needs_timed(crate::node::OP_INVOKE_REQUEST, &ok));
        // A different failure (e.g. FAILURE 0x01) must not be mistaken for 0xc6.
        let other = matter_interaction::build_invoke_response_status(
            path,
            matter_interaction::ImStatus::Failure(0x01),
        );
        assert!(!response_needs_timed(
            crate::node::OP_INVOKE_REQUEST,
            &other
        ));
        // A write success likewise.
        let wok = build_write_response_status(0, 0x0028, 0x05, 0x00);
        assert!(!response_needs_timed(OP_WRITE_REQUEST, &wok));
    }

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

    /// Issue #110: a second `create_fabric` call with the SAME `fabric_id`
    /// (the shape of the bug — a fresh-store guard missing on a later run
    /// that loaded an existing fabric from the store) must be refused with
    /// `Error::FabricAlreadyExists`, not silently push a duplicate
    /// `FabricEntry` that later breaks `sole_fabric()` addressing.
    #[tokio::test]
    async fn create_fabric_twice_same_id_is_refused() {
        let store = Arc::new(MemStore::default());
        let (io, _peer) = InMemoryDatagram::pair();
        let controller = crate::controller::MatterController::with_components(
            store,
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
            .expect("first create_fabric");

        let err = controller
            .create_fabric(cfg())
            .await
            .expect_err("second create_fabric with the same fabric_id must fail");
        match err {
            Error::FabricAlreadyExists(id) => assert_eq!(id, cfg().fabric_id),
            other => panic!("expected FabricAlreadyExists, got {other:?}"),
        }

        // Confirm no duplicate was pushed: exactly one fabric on disk.
        let fabrics = controller.fabrics().await.expect("fabrics");
        assert_eq!(fabrics.len(), 1);
    }

    /// A second `create_fabric` call with a DIFFERENT `fabric_id` must still
    /// succeed — the duplicate guard is keyed on `fabric_id`, not "has any
    /// fabric already been created".
    #[tokio::test]
    async fn create_fabric_twice_different_id_still_works() {
        let store = Arc::new(MemStore::default());
        let (io, _peer) = InMemoryDatagram::pair();
        let controller = crate::controller::MatterController::with_components(
            store,
            io,
            NullDiscovery,
            Arc::new(matter_commissioning::SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        let first = controller
            .create_fabric(cfg())
            .await
            .expect("first create_fabric");

        let mut cfg2 = cfg();
        cfg2.fabric_id = 0xAABB_CCDD_0000_0002;
        cfg2.commissioner_node_id = 2;
        let second = controller
            .create_fabric(cfg2)
            .await
            .expect("second create_fabric with a different fabric_id must succeed");

        assert_ne!(first, second);
        let fabrics = controller.fabrics().await.expect("fabrics");
        assert_eq!(fabrics.len(), 2);
    }

    /// `fabrics()` is empty before any fabric is created, and reflects each
    /// fabric's typed metadata (fabric id, commissioner node id, node count,
    /// ICAC-in-use) after creation.
    #[tokio::test]
    async fn fabrics_empty_before_populated_after() {
        let store = Arc::new(MemStore::default());
        let (io, _peer) = InMemoryDatagram::pair();
        let controller = crate::controller::MatterController::with_components(
            store,
            io,
            NullDiscovery,
            Arc::new(matter_commissioning::SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        assert_eq!(
            controller.fabrics().await.expect("fabrics"),
            Vec::new(),
            "no fabric created yet"
        );

        controller
            .create_fabric(cfg())
            .await
            .expect("create_fabric");

        let fabrics = controller.fabrics().await.expect("fabrics");
        assert_eq!(
            fabrics,
            vec![crate::FabricInfo {
                fabric_id: 0xAABB_CCDD_0000_0001,
                commissioner_node_id: 1,
                node_count: 0,
                icac_enabled: false,
            }]
        );
    }

    /// `FabricInfo::icac_enabled` must reflect the fabric's ACTUAL chain
    /// depth, not a hardcoded `false`: a fabric created with
    /// `issue_icac = true` reports `true`.
    #[tokio::test]
    async fn fabrics_reports_icac_enabled_for_an_icac_fabric() {
        let store = Arc::new(MemStore::default());
        let (io, _peer) = InMemoryDatagram::pair();
        let controller = crate::controller::MatterController::with_components(
            store,
            io,
            NullDiscovery,
            Arc::new(matter_commissioning::SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        let mut icac_cfg = cfg();
        icac_cfg.issue_icac = true;
        controller
            .create_fabric(icac_cfg)
            .await
            .expect("create_fabric with icac");

        let fabrics = controller.fabrics().await.expect("fabrics");
        assert_eq!(
            fabrics,
            vec![crate::FabricInfo {
                fabric_id: 0xAABB_CCDD_0000_0001,
                commissioner_node_id: 1,
                node_count: 0,
                icac_enabled: true,
            }]
        );
    }

    /// `FabricInfo::node_count` must count the fabric's commissioned devices,
    /// not report a hardcoded `0`. Seeded the same way as
    /// `nodes_lists_commissioned_devices_with_metadata` (a hand-built
    /// `ControllerState` written straight to the store), because commissioning
    /// a device through the public API is impractical in a unit test.
    #[tokio::test]
    async fn fabrics_reports_the_commissioned_node_count() {
        let mut fabric =
            crate::fabric::create_fabric(&cfg(), &SystemNocRng).expect("create_fabric");
        fabric.devices.push(crate::state::DeviceEntry {
            node_id: 0x0000_0000_0000_0042,
            peer_noc_public_key: [0u8; 65],
            resumption_record: None,
            last_known_addr: None,
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            label: Some("plug".to_string()),
        });

        let store = Arc::new(MemStore::default());
        store
            .save(
                &crate::snapshot::serialize(&ControllerState {
                    fabrics: vec![fabric],
                })
                .unwrap(),
            )
            .unwrap();

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

        let fabrics = controller.fabrics().await.expect("fabrics");
        assert_eq!(
            fabrics,
            vec![crate::FabricInfo {
                fabric_id: 0xAABB_CCDD_0000_0001,
                commissioner_node_id: 1,
                node_count: 1,
                icac_enabled: false,
            }]
        );
    }

    /// A `create_fabric` rejected for an invalid validity window must leave no
    /// trace: `fabrics()` stays empty (the epoch-zero `not_before` is caught
    /// before any key generation or state mutation).
    #[tokio::test]
    async fn create_fabric_rejected_for_validity_leaves_no_fabric() {
        let store = Arc::new(MemStore::default());
        let (io, _peer) = InMemoryDatagram::pair();
        let controller = crate::controller::MatterController::with_components(
            store,
            io,
            NullDiscovery,
            Arc::new(matter_commissioning::SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        let mut bad = cfg();
        bad.validity = (MatterTime::from_unix_secs(0), MatterTime::NO_EXPIRY);
        let err = controller
            .create_fabric(bad)
            .await
            .expect_err("epoch-zero not_before must be refused");
        assert!(
            matches!(err, Error::InvalidFabricValidity(_)),
            "expected InvalidFabricValidity, got {err:?}"
        );

        assert_eq!(
            controller.fabrics().await.expect("fabrics"),
            Vec::new(),
            "a rejected create_fabric must not leave a fabric behind"
        );
    }

    /// The clock-relative half of the validity check is wired into the actor:
    /// a MILLISECOND timestamp as `not_before` (saturating to ≈ 2136) is
    /// refused, and leaves no fabric behind. Without this the root would
    /// install on the device (`ValidateChipRCAC` skips validity times) and
    /// then fail every CASE session with `kNotYetValid`.
    #[tokio::test]
    async fn create_fabric_refuses_a_millisecond_not_before() {
        let store = Arc::new(MemStore::default());
        let (io, _peer) = InMemoryDatagram::pair();
        let controller = crate::controller::MatterController::with_components(
            store,
            io,
            NullDiscovery,
            Arc::new(matter_commissioning::SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("open");

        let mut bad = cfg();
        bad.validity = (
            MatterTime::from_unix_secs(1_700_000_000_000),
            MatterTime::NO_EXPIRY,
        );
        let err = controller
            .create_fabric(bad)
            .await
            .expect_err("far-future not_before must be refused");
        assert!(
            matches!(err, Error::InvalidFabricValidity(_)),
            "expected InvalidFabricValidity, got {err:?}"
        );
        assert_eq!(
            controller.fabrics().await.expect("fabrics"),
            Vec::new(),
            "a rejected create_fabric must not leave a fabric behind"
        );
    }

    /// An unset host clock (pre-2000 reading) must fail loudly instead of
    /// saturating to `MatterTime(0)` and minting certificates whose rebuilt
    /// X.509 TBS no longer matches their signature.
    #[test]
    fn matter_time_refuses_a_pre_matter_epoch_clock() {
        // Unix 0 — a host that booted with no RTC and no time sync.
        let err = matter_time_from_unix_secs(0).expect_err("unset clock must be refused");
        match err {
            Error::SystemClockUnset(secs) => assert_eq!(secs, 0),
            other => panic!("expected SystemClockUnset, got {other:?}"),
        }

        // One second before the Matter epoch: still saturates to
        // `MatterTime(0)`, still refused.
        let err = matter_time_from_unix_secs(946_684_799).expect_err("pre-epoch must be refused");
        assert!(matches!(err, Error::SystemClockUnset(_)));
        assert!(
            err.to_string().contains("unset"),
            "error must name the likely cause: {err}"
        );
    }

    /// The boundary on the other side: the Matter epoch plus one second is a
    /// legitimate (if implausible) clock reading and converts normally.
    #[test]
    fn matter_time_accepts_a_set_clock() {
        assert_eq!(
            matter_time_from_unix_secs(946_684_801).expect("set clock"),
            MatterTime(1)
        );
        assert_eq!(
            matter_time_from_unix_secs(1_700_000_000).expect("set clock"),
            MatterTime::from_unix_secs(1_700_000_000)
        );
    }

    /// An unusable host clock must NOT block fabric creation. `create_fabric`
    /// needs no clock — the certificates come entirely from the caller's
    /// `validity` — so a failed clock reading means the *sanity check* cannot
    /// run, not that the fabric is bad. An RTC-less board that creates its
    /// fabric at boot with a hardcoded sane window and syncs NTP seconds later
    /// is a normal deployment.
    ///
    /// The clock reading is injected here because `current_matter_time()` reads
    /// the real system clock, which a unit test cannot move.
    #[test]
    fn unset_clock_does_not_block_fabric_creation() {
        let window = (
            MatterTime::from_unix_secs(1_700_000_000),
            MatterTime::NO_EXPIRY,
        );
        validate_validity_against_clock(window, Err(Error::SystemClockUnset(0)))
            .expect("an unusable clock must not refuse a good caller-supplied window");
    }

    /// The clock-independent half still bites: a `not_before` at the Matter
    /// epoch is refused on an unset-clock host too — which is exactly the host
    /// where documentation-following code produces one, since it derives
    /// `not_before` from `SystemTime::now()`. The message must name the unset
    /// clock as the likely source rather than just calling the caller's
    /// wall-clock time "the Matter epoch".
    #[test]
    fn unset_clock_with_epoch_zero_not_before_is_still_rejected() {
        let window = (MatterTime(0), MatterTime::NO_EXPIRY);
        let err = validate_validity_against_clock(window, Err(Error::SystemClockUnset(0)))
            .expect_err("epoch-zero not_before must be refused");
        assert!(
            matches!(err, Error::InvalidFabricValidity(_)),
            "expected InvalidFabricValidity, got {err:?}"
        );
        assert!(
            err.to_string().contains("clock is unset"),
            "error must name the unset clock as the likely source: {err}"
        );
    }

    /// A usable clock still runs the full clock-relative check — both the
    /// far-future `not_before` bound and the already-expired `not_after` one.
    #[test]
    fn usable_clock_still_applies_the_clock_relative_checks() {
        let now = MatterTime::from_unix_secs(1_795_000_000);
        let far_future = (
            MatterTime::from_unix_secs(1_700_000_000_000),
            MatterTime::NO_EXPIRY,
        );
        assert!(matches!(
            validate_validity_against_clock(far_future, Ok(now)),
            Err(Error::InvalidFabricValidity(_))
        ));
        let expired = (
            MatterTime::from_unix_secs(1_700_000_000),
            MatterTime::from_unix_secs(1_731_536_000),
        );
        assert!(matches!(
            validate_validity_against_clock(expired, Ok(now)),
            Err(Error::InvalidFabricValidity(_))
        ));
        let good = (
            MatterTime::from_unix_secs(1_794_996_400),
            MatterTime::NO_EXPIRY,
        );
        validate_validity_against_clock(good, Ok(now)).expect("a sane window must be accepted");
    }

    /// A clock error that is *not* `SystemClockUnset` (e.g. a reading before
    /// the Unix epoch) still propagates — we only forgive the one case we know
    /// is harmless here.
    #[test]
    fn non_clock_unset_errors_still_propagate() {
        let window = (
            MatterTime::from_unix_secs(1_700_000_000),
            MatterTime::NO_EXPIRY,
        );
        let err = validate_validity_against_clock(
            window,
            Err(Error::Operational("clock: before Unix epoch".into())),
        )
        .expect_err("a non-SystemClockUnset clock error must propagate");
        assert!(matches!(err, Error::Operational(_)), "got {err:?}");
    }

    /// `nodes()` must enumerate every commissioned device across every fabric
    /// as typed `NodeInfo`, without requiring the caller to deserialize the
    /// on-disk snapshot. Seeded by pre-writing a hand-built `ControllerState`
    /// snapshot directly to the store (constructing a `DeviceEntry` with
    /// metadata through the public commissioning API is impractical in a unit
    /// test), then opening the controller over it.
    #[tokio::test]
    async fn nodes_lists_commissioned_devices_with_metadata() {
        let mut fabric =
            crate::fabric::create_fabric(&cfg(), &SystemNocRng).expect("create_fabric");
        let fabric_id = fabric.fabric_id;
        let node_id: u64 = 0x0000_0000_0000_0042;
        fabric.devices.push(crate::state::DeviceEntry {
            node_id,
            peer_noc_public_key: [0u8; 65],
            resumption_record: None,
            last_known_addr: None,
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            label: Some("plug".to_string()),
        });

        let store = Arc::new(MemStore::default());
        store
            .save(
                &crate::snapshot::serialize(&ControllerState {
                    fabrics: vec![fabric],
                })
                .unwrap(),
            )
            .unwrap();

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

        let nodes = controller.nodes().await.expect("nodes");
        assert_eq!(
            nodes,
            vec![crate::NodeInfo {
                node_id,
                fabric_id,
                vendor_id: Some(0xFFF1),
                product_id: Some(0x8000),
                label: Some("plug".to_string()),
            }]
        );
    }

    /// `forget_node` drops ALL of the controller's own local state
    /// for a node WITHOUT contacting the device: the persisted `DeviceEntry`,
    /// the cached CASE session, and any parked connect bookkeeping. Seeds a
    /// fabric with one device (same seeding style as
    /// `nodes_lists_commissioned_devices_with_metadata` above) plus a live
    /// cached session (same `CachedSession` seeding as
    /// `timeout_on_current_session_evicts_it` above — standing in for an
    /// established loopback session without a full CASE handshake), then
    /// confirms: (a) `nodes()` no longer lists the node afterward, (b) the
    /// cached session is evicted, (c) the reloaded on-disk snapshot has no
    /// such `DeviceEntry`, (d) `forget_node` returns `Ok(true)` the first time
    /// and `Ok(false)` on a repeat call for the same (now-absent) node.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one linear scenario: seed device+session+sub, forget, assert full drop
    async fn forget_node_drops_all_local_state_without_device_contact() {
        let mut fabric =
            crate::fabric::create_fabric(&cfg(), &SystemNocRng).expect("create_fabric");
        let fabric_id = fabric.fabric_id;
        let node_id: u64 = 0x0000_0000_0000_0042;
        fabric.devices.push(crate::state::DeviceEntry {
            node_id,
            peer_noc_public_key: [0u8; 65],
            resumption_record: None,
            last_known_addr: None,
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            label: Some("plug".to_string()),
        });

        let store = Arc::new(MemStore::default());
        let (io, _peer) = InMemoryDatagram::pair();
        let mut actor = Actor::new(
            io,
            NullDiscovery,
            store.clone(),
            Arc::new(SystemNocRng),
            ControllerState {
                fabrics: vec![fabric],
            },
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        );

        // A live cached session for the node — `forget_node` must evict this
        // too, or dead MRP retransmits keep firing on a session the caller
        // now believes is gone.
        actor.cache.insert(
            (fabric_id, node_id),
            CachedSession {
                session_id: SessionId(7),
                peer: "127.0.0.1:5540".parse().unwrap(),
            },
        );

        // A live subscription to the node — `forget_node` must drop this, or
        // its liveness timer would later drive the resubscribe engine to open a
        // fresh CASE handshake to the very node we forgot (the "no device
        // contact" guarantee would be silently violated).
        let (sink, _report_rx, _ctrl_rx) = test_report_sink();
        actor.insert_subscription(
            SubId(1),
            SubEntry {
                tx: sink,
                peer: "127.0.0.1:5540".parse().unwrap(),
                reassembler: ReportReassembler::default(),
                session_id: SessionId(7),
                wire_sub_id: 0x1234,
                node_id,
                paths: vec![matter_interaction::ReadPath::all()],
                event_paths: vec![],
                event_filters: vec![],
                min_interval: 1,
                max_interval: 30,
                liveness_deadline: Instant::now(),
            },
        );

        // The fixture is visible before forgetting.
        let (nodes_tx, nodes_rx) = oneshot::channel();
        actor
            .dispatch_ready(Command::ListNodes { reply: nodes_tx })
            .await;
        assert_eq!(
            nodes_rx.await.unwrap().len(),
            1,
            "fixture device must be listed before forget"
        );

        let (reply, rx) = oneshot::channel();
        actor
            .dispatch_ready(Command::ForgetNode { node_id, reply })
            .await;
        assert!(
            rx.await.unwrap().expect("forget_node"),
            "a device was found and removed"
        );

        assert!(
            !actor.cache.contains_key(&(fabric_id, node_id)),
            "the cached session must be evicted"
        );
        assert!(
            actor.subscriptions.values().all(|s| s.node_id != node_id),
            "the live subscription to the node must be dropped (else the \
             resubscribe engine reconnects to the forgotten node)"
        );

        let (after_tx, after_rx) = oneshot::channel();
        actor
            .dispatch_ready(Command::ListNodes { reply: after_tx })
            .await;
        assert!(
            after_rx.await.unwrap().is_empty(),
            "nodes() must no longer list the forgotten node"
        );

        // The reloaded on-disk snapshot has no such `DeviceEntry`.
        let bytes = store.load().unwrap().expect("snapshot saved");
        let restored = crate::snapshot::deserialize(&bytes).unwrap();
        assert!(
            restored
                .fabrics
                .iter()
                .all(|f| f.devices.iter().all(|d| d.node_id != node_id)),
            "the persisted snapshot must no longer contain the forgotten device"
        );

        // A second forget of the same (now-absent) node is a no-op `Ok(false)`.
        let (repeat_reply, repeat_rx) = oneshot::channel();
        actor
            .dispatch_ready(Command::ForgetNode {
                node_id,
                reply: repeat_reply,
            })
            .await;
        assert!(
            !repeat_rx.await.unwrap().expect("forget_node second call"),
            "a second forget of the same node finds nothing"
        );
    }

    /// `sub_index` must track `subscriptions` through insert, resubscribe
    /// (re-insert under a new `(session, wire_sub_id)` key), single cancel,
    /// and the bulk `forget_node` removal path — the index is only ever
    /// touched by `insert_subscription`/`remove_subscription`, so a bug in
    /// either would leave stale or missing index entries.
    #[test]
    fn sub_index_tracks_subscribe_resubscribe_cancel_and_forget() {
        let mut actor = actor_with_one_fabric();
        let sid_a = SessionId(7);
        let sid_b = SessionId(9);
        let peer: std::net::SocketAddr = "127.0.0.1:5540".parse().unwrap();
        let entry_for = |session_id, wire_sub_id, node_id| {
            let (sink, _report_rx, _ctrl_rx) = test_report_sink();
            SubEntry {
                tx: sink,
                peer,
                reassembler: ReportReassembler::default(),
                session_id,
                wire_sub_id,
                node_id,
                paths: vec![matter_interaction::ReadPath::all()],
                event_paths: vec![],
                event_filters: vec![],
                min_interval: 1,
                max_interval: 30,
                liveness_deadline: Instant::now(),
            }
        };

        let id = SubId(1);
        actor.insert_subscription(id, entry_for(sid_a, 0x1111, 7));
        assert_eq!(actor.sub_index.get(&(sid_a, 0x1111)), Some(&id));

        // Resubscribe: same SubId, new session + wire id — old key must vanish.
        actor.insert_subscription(id, entry_for(sid_b, 0x2222, 7));
        assert!(!actor.sub_index.contains_key(&(sid_a, 0x1111)));
        assert_eq!(actor.sub_index.get(&(sid_b, 0x2222)), Some(&id));
        assert_eq!(actor.sub_index.len(), 1);

        // Cancel: entry and index entry both go.
        actor.remove_subscription(id);
        assert!(actor.sub_index.is_empty() && actor.subscriptions.is_empty());

        // forget_node bulk removal maintains the index.
        actor.insert_subscription(SubId(2), entry_for(sid_a, 0x3333, 9));
        actor.insert_subscription(SubId(3), entry_for(sid_b, 0x4444, 9));
        actor.remove_subscriptions_for_node(9);
        assert!(actor.sub_index.is_empty() && actor.subscriptions.is_empty());

        // Collision: `wire_sub_id` is device-issued, remote-influenced input,
        // so a non-compliant/hostile device can reuse one on the same
        // session for a second, distinct subscription. Keep-first-owner:
        // the index must not panic and must not budge from the first
        // claimant; both `SubEntry`s stay live in `subscriptions`.
        let key = (sid_a, 0x5555);
        let sub_a = SubId(10);
        let sub_b = SubId(11);
        actor.insert_subscription(sub_a, entry_for(sid_a, 0x5555, 20));
        actor.insert_subscription(sub_b, entry_for(sid_a, 0x5555, 21));
        assert_eq!(
            actor.sub_index.get(&key),
            Some(&sub_a),
            "the index keeps the first owner of a colliding key"
        );
        assert!(
            actor.subscriptions.contains_key(&sub_a) && actor.subscriptions.contains_key(&sub_b),
            "both colliding subscriptions stay live in the primary map"
        );

        // Removing the shadowed loser must not disturb the winner's entry.
        actor.remove_subscription(sub_b);
        assert_eq!(
            actor.sub_index.get(&key),
            Some(&sub_a),
            "removing the shadowed loser leaves the winner's index entry intact"
        );
        assert!(!actor.subscriptions.contains_key(&sub_b));

        // Removing the winner frees the key.
        actor.remove_subscription(sub_a);
        assert!(!actor.sub_index.contains_key(&key));
        assert!(actor.subscriptions.is_empty());
    }

    /// Final-review C1 regression: a connect that completes AFTER the node was
    /// forgotten (or was never commissioned) must NOT resurrect a `DeviceEntry`.
    /// `upsert_device` is update-only — the corrupt zeroed-NOC-key placeholder
    /// it used to push would otherwise re-add a device the caller forgot (and
    /// persist a bogus key). We drive `upsert_device` directly, which is the
    /// exact call `handle_connect_done` makes when a spawned handshake lands.
    #[tokio::test]
    async fn upsert_device_is_update_only_and_never_resurrects_a_forgotten_node() {
        let mut actor = actor_with_one_fabric();
        let fabric_id = actor.sole_fabric().unwrap().fabric_id;
        let peer: std::net::SocketAddr = "127.0.0.1:5540".parse().unwrap();

        // (a) UNKNOWN/forgotten node: a completed connect must add nothing.
        actor.upsert_device(fabric_id, 0x0000_0000_0000_0042, peer, Some(vec![1, 2, 3]));
        assert!(
            actor.sole_fabric().unwrap().devices.is_empty(),
            "upsert_device must not fabricate a DeviceEntry for an unknown/forgotten node"
        );

        // (b) KNOWN node: the happy path (address-hint / resumption update) still
        // works — the update-only change must not break legitimate reconnects.
        let node_id = 0x0000_0000_0000_0007;
        actor
            .state
            .fabrics
            .iter_mut()
            .find(|f| f.fabric_id == fabric_id)
            .unwrap()
            .devices
            .push(crate::state::DeviceEntry {
                node_id,
                peer_noc_public_key: [0x04; 65],
                resumption_record: None,
                last_known_addr: None,
                vendor_id: None,
                product_id: None,
                label: None,
            });
        actor.upsert_device(fabric_id, node_id, peer, Some(vec![9, 9]));
        let dev = actor.sole_fabric().unwrap().devices[0].clone();
        assert_eq!(dev.last_known_addr.as_deref(), Some("127.0.0.1:5540"));
        assert_eq!(dev.resumption_record, Some(vec![9, 9]));
        assert_eq!(
            dev.peer_noc_public_key, [0x04; 65],
            "the existing NOC key must be preserved, never zeroed"
        );
        assert_eq!(
            actor.sole_fabric().unwrap().devices.len(),
            1,
            "no duplicate entry was created for the known node"
        );
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

        // A counter block must have been RESERVED and persisted BEFORE the send:
        // the serialized field holds the ceiling, not the last-sent value.
        let snap2 = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(
            snap2.fabrics[0].outbound_group_counter, GROUP_COUNTER_BLOCK,
            "the reservation ceiling must be persisted before the send"
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

    /// Re-creating a key set REPLACES the stored entry, and the outbound path
    /// always encrypts under the newest key — even when the store was
    /// poisoned with duplicates by an older build.
    ///
    /// Regression test for the real-hardware group-decrypt failure
    /// (2026-07-20): `create_group` used to append duplicates and
    /// `invoke_group` picked the FIRST match, so after any re-provision the
    /// controller kept encrypting under a stale epoch key while devices held
    /// the newly written one.
    #[tokio::test]
    async fn create_group_upserts_and_invoke_uses_newest_key() {
        use matter_transport::decode_group_secured;

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
        let fabric_id = controller
            .create_fabric(cfg())
            .await
            .expect("create_fabric");

        // Re-create the same key set: the second call must REPLACE the first.
        let key_set_id = 0x0042u16;
        let first = controller
            .create_group(key_set_id, 0)
            .await
            .expect("create_group #1");
        let second = controller
            .create_group(key_set_id, 0)
            .await
            .expect("create_group #2");
        assert_ne!(first.epoch_key, second.epoch_key, "fresh key each create");

        let snap = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(
            snap.fabrics[0].group_keys.len(),
            1,
            "create_group must upsert, not append a duplicate"
        );
        assert_eq!(
            snap.fabrics[0].group_keys[0].epoch_key[..],
            second.epoch_key[..],
            "the stored key must be the newest one"
        );

        // Poison the store the way pre-fix builds did: a STALE entry for the
        // same key set id sitting in front of the current one.
        let mut poisoned = snap;
        poisoned.fabrics[0].group_keys.insert(
            0,
            crate::state::GroupKeySetConfig::new(key_set_id, [0xAA; 16], 0),
        );
        store
            .save(&crate::snapshot::serialize(&poisoned).unwrap())
            .unwrap();

        // A controller opened on the poisoned store must STILL send under the
        // newest (last) key — the one devices actually hold.
        let (io2, peer2) = InMemoryDatagram::pair();
        let controller2 = crate::controller::MatterController::with_components(
            store.clone(),
            io2,
            NullDiscovery,
            Arc::new(matter_commissioning::SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("reopen");
        let path = crate::CommandPath {
            endpoint: 0,
            cluster: 0x0006,
            command: 0x01,
        };
        controller2
            .invoke_group(
                0x0008,
                key_set_id,
                path,
                matter_codec::Value::Structure(vec![]),
            )
            .await
            .expect("invoke_group");
        let (wire, _from) = peer2.recv_from().await.expect("frame emitted");

        let root_public_key = *poisoned.fabrics[0].rcac_cert.public_key().as_bytes();
        let compressed = derive_compressed_fabric_id(&root_public_key, fabric_id).unwrap();
        let newest_epoch: [u8; 16] = second.epoch_key.clone().try_into().unwrap();
        let op_newest = derive_operational_ipk(&newest_epoch, &compressed).unwrap();
        decode_group_secured(&wire, &op_newest)
            .expect("frame must decrypt under the NEWEST key for this key set id");
        let op_stale = derive_operational_ipk(&[0xAA; 16], &compressed).unwrap();
        assert!(
            decode_group_secured(&wire, &op_stale).is_err(),
            "frame must NOT be encrypted under the stale first-match key"
        );
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

    // --- per-fabric group key derivation cache ---

    /// An actor whose sole fabric already holds `epoch_key` under `key_set_id`
    /// (as `create_group` would have left it), plus the paired endpoint that
    /// receives every multicast the actor sends.
    fn group_test_actor(
        key_set_id: u16,
        epoch_key: [u8; 16],
    ) -> (Actor<InMemoryDatagram, NullDiscovery>, InMemoryDatagram) {
        let (io, peer) = InMemoryDatagram::pair();
        let mut fabric =
            crate::fabric::create_fabric(&cfg(), &SystemNocRng).expect("create_fabric");
        fabric.group_keys.push(crate::state::GroupKeySetConfig::new(
            key_set_id, epoch_key, 0,
        ));
        let actor = Actor::new(
            io,
            NullDiscovery,
            Arc::new(MemStore::default()),
            Arc::new(SystemNocRng),
            ControllerState {
                fabrics: vec![fabric],
            },
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        );
        (actor, peer)
    }

    /// The TLV for an empty command field set (`OnOff.On` takes none).
    fn empty_fields_tlv() -> Vec<u8> {
        crate::node::value_to_tlv(&matter_codec::Value::Structure(vec![])).unwrap()
    }

    /// Repeated group sends on one fabric derive the group key material ONCE:
    /// the second `invoke_group` hits the cache (still a single entry), and both
    /// frames still decode under an independent from-scratch derivation.
    #[tokio::test]
    async fn group_key_cache_reused_across_sends() {
        let key_set_id = 0x0042u16;
        let epoch_key = [0x11u8; 16];
        let (mut actor, peer) = group_test_actor(key_set_id, epoch_key);
        let fabric_id = actor.sole_fabric().unwrap().fabric_id;
        // Derived here the long way, exactly as a peer device would.
        let op_group_key = op_group_key_of(&actor.state, &epoch_key);
        let fields_tlv = empty_fields_tlv();

        assert!(
            actor.group_key_cache.is_empty(),
            "cache starts cold — nothing is derived before the first send"
        );

        actor
            .handle_invoke_group(0xBEEF, key_set_id, on_command_path(), &fields_tlv)
            .await
            .expect("first group send");
        assert_eq!(
            actor.group_key_cache.len(),
            1,
            "the first send must populate exactly one cache entry"
        );

        actor
            .handle_invoke_group(0xBEEF, key_set_id, on_command_path(), &fields_tlv)
            .await
            .expect("second group send");
        assert_eq!(
            actor.group_key_cache.len(),
            1,
            "the second send must reuse the entry, not add another"
        );
        let entry = actor
            .group_key_cache
            .get(&fabric_id)
            .expect("entry keyed by fabric id");
        assert_eq!(
            entry.epoch_key, epoch_key,
            "the cached entry must record the epoch key it was derived from"
        );
        assert_eq!(
            entry.op_group_key, op_group_key,
            "the cached operational group key must equal the from-scratch derivation"
        );
        assert_eq!(
            entry.privacy_key,
            matter_crypto::derive_group_privacy_key(&op_group_key).unwrap(),
            "the cached privacy key must equal the from-scratch derivation"
        );

        // Both frames decode under the independent derivation, with the
        // counters the reservation handed out.
        let (wire1, _from) = peer.recv_from().await.expect("frame 1 emitted");
        let (wire2, _from) = peer.recv_from().await.expect("frame 2 emitted");
        assert_eq!(wire_group_counter(&wire1, &op_group_key), 0);
        assert_eq!(wire_group_counter(&wire2, &op_group_key), 1);
        let (_h, plaintext) =
            matter_transport::decode_group_secured(&wire2, &op_group_key).expect("decode");
        let (_ph, app) = matter_transport::decode_protocol_header(&plaintext).unwrap();
        assert_eq!(
            app,
            &matter_interaction::build_invoke_request_group(on_command_path(), &fields_tlv)[..],
            "the cached path must still carry the same IM payload"
        );
    }

    /// Rotating the fabric's epoch key (what `create_group` / `KeySetWrite`
    /// does) MUST invalidate the cache: the next frame has to be encrypted
    /// under the new key's derivations, never the cached old ones. Without the
    /// `epoch_key` check this is exactly the 2026-07-20 hardware failure —
    /// devices hold the new key while we keep sending under the stale one.
    #[tokio::test]
    async fn group_key_cache_invalidated_on_epoch_rotation() {
        let key_set_id = 0x0042u16;
        let old_epoch = [0x11u8; 16];
        let new_epoch = [0x22u8; 16];
        let (mut actor, peer) = group_test_actor(key_set_id, old_epoch);
        let fabric_id = actor.sole_fabric().unwrap().fabric_id;
        let op_old = op_group_key_of(&actor.state, &old_epoch);
        let op_new = op_group_key_of(&actor.state, &new_epoch);
        let fields_tlv = empty_fields_tlv();

        // Send once under the old key — this is what warms the cache.
        actor
            .handle_invoke_group(0xBEEF, key_set_id, on_command_path(), &fields_tlv)
            .await
            .expect("send under the old epoch key");
        let (wire_old, _from) = peer.recv_from().await.expect("frame 1 emitted");
        matter_transport::decode_group_secured(&wire_old, &op_old)
            .expect("first frame must decrypt under the old key");

        // Rotate the key set in place, as `create_group`'s upsert does.
        {
            let fabric = actor.sole_fabric_mut().unwrap();
            let slot = fabric
                .group_keys
                .iter_mut()
                .rfind(|k| k.key_set_id == key_set_id)
                .expect("provisioned key set");
            *slot = crate::state::GroupKeySetConfig::new(key_set_id, new_epoch, 0);
        }

        actor
            .handle_invoke_group(0xBEEF, key_set_id, on_command_path(), &fields_tlv)
            .await
            .expect("send after rotation");
        let (wire_new, _from) = peer.recv_from().await.expect("frame 2 emitted");
        matter_transport::decode_group_secured(&wire_new, &op_new)
            .expect("frame must decrypt under the NEW epoch key's derivation");
        assert!(
            matter_transport::decode_group_secured(&wire_new, &op_old).is_err(),
            "frame must NOT still be encrypted under the cached stale key"
        );

        let entry = actor
            .group_key_cache
            .get(&fabric_id)
            .expect("entry keyed by fabric id");
        assert_eq!(
            entry.epoch_key, new_epoch,
            "the refreshed entry must record the new epoch key"
        );
        assert_eq!(entry.op_group_key, op_new);
        assert_eq!(
            actor.group_key_cache.len(),
            1,
            "invalidation replaces the entry rather than accumulating"
        );
    }

    /// The epoch key is only HALF the invalidation stamp: the derivation also
    /// takes the fabric's RCAC public key. A fabric re-created under the same
    /// id with a NEW root (no such local path today — hence the simulation
    /// below) must NOT be served the old root's keys, or every group frame
    /// would go out undecryptable.
    ///
    /// Simulated by poisoning the cached entry: same epoch key, a different
    /// `root_public_key`, and an `op_group_key` that decrypts nothing. If the
    /// hit condition ignored the root key this would be a cache HIT and the
    /// frame would be encrypted under the poison key.
    #[tokio::test]
    async fn group_key_cache_invalidated_on_root_key_change() {
        let key_set_id = 0x0042u16;
        let epoch_key = [0x11u8; 16];
        let (mut actor, peer) = group_test_actor(key_set_id, epoch_key);
        let fabric_id = actor.sole_fabric().unwrap().fabric_id;
        let op_real = op_group_key_of(&actor.state, &epoch_key);
        let real_root = *actor
            .sole_fabric()
            .unwrap()
            .rcac_cert
            .public_key()
            .as_bytes();
        let fields_tlv = empty_fields_tlv();

        // Warm the cache.
        actor
            .handle_invoke_group(0xBEEF, key_set_id, on_command_path(), &fields_tlv)
            .await
            .expect("first send");
        let (_wire, _from) = peer.recv_from().await.expect("frame 1 emitted");

        // Poison: as if the entry had been derived under a different root.
        {
            let entry = actor
                .group_key_cache
                .get_mut(&fabric_id)
                .expect("warmed entry");
            entry.root_public_key = [0x04; 65];
            entry.op_group_key = [0xEE; 16];
            entry.privacy_key = [0xEE; 16];
        }

        actor
            .handle_invoke_group(0xBEEF, key_set_id, on_command_path(), &fields_tlv)
            .await
            .expect("second send");
        let (wire, _from) = peer.recv_from().await.expect("frame 2 emitted");
        matter_transport::decode_group_secured(&wire, &op_real)
            .expect("frame must be re-derived under the fabric's REAL root key");
        assert!(
            matter_transport::decode_group_secured(&wire, &[0xEE; 16]).is_err(),
            "frame must not be encrypted under the poisoned cache entry"
        );

        let entry = actor
            .group_key_cache
            .get(&fabric_id)
            .expect("entry keyed by fabric id");
        assert_eq!(
            entry.root_public_key, real_root,
            "the refreshed entry must record the root key it was derived under"
        );
        assert_eq!(entry.op_group_key, op_real);
    }

    // --- group counter block reservation (spec §1.4) ---

    /// In-memory store that counts successful `save()` calls, so a test can
    /// assert how many store writes a sequence of operations cost. `fail` makes
    /// every subsequent save return an I/O error without writing, which is how
    /// the counter-reservation rollback path is exercised.
    #[derive(Default)]
    struct CountingStore {
        inner: std::sync::Mutex<Option<Vec<u8>>>,
        saves: std::sync::atomic::AtomicUsize,
        fail: std::sync::atomic::AtomicBool,
    }
    impl CountingStore {
        fn saves(&self) -> usize {
            self.saves.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn set_failing(&self, fail: bool) {
            self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl ControllerStore for CountingStore {
        fn load(&self) -> Result<Option<Vec<u8>>, crate::store::StoreError> {
            Ok(self.inner.lock().unwrap().clone())
        }
        fn save(&self, snapshot: &[u8]) -> Result<(), crate::store::StoreError> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(crate::store::StoreError::Io(std::io::Error::other(
                    "disk full",
                )));
            }
            // Order is load-bearing: the bytes land BEFORE the count is bumped,
            // so a test that observes `saves()` advance may then read `load()`
            // and be sure it sees the snapshot that advance refers to. (The
            // gate's last-written sequence is set by `SaveJob::run` only after
            // this returns, so gate assertions must poll the gate itself.)
            *self.inner.lock().unwrap() = Some(snapshot.to_vec());
            self.saves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// The operational group key for `epoch_key` on the fabric in `snap`.
    fn op_group_key_of(snap: &ControllerState, epoch_key: &[u8; 16]) -> [u8; 16] {
        let root_public_key = *snap.fabrics[0].rcac_cert.public_key().as_bytes();
        let compressed =
            derive_compressed_fabric_id(&root_public_key, snap.fabrics[0].fabric_id).unwrap();
        derive_operational_ipk(epoch_key, &compressed).unwrap()
    }

    /// The message counter carried by a captured group-secured frame.
    fn wire_group_counter(wire: &[u8], op_group_key: &[u8; 16]) -> u32 {
        let (header, _plaintext) =
            matter_transport::decode_group_secured(wire, op_group_key).expect("decode group");
        header.message_counter.0
    }

    fn on_command_path() -> crate::CommandPath {
        crate::CommandPath {
            endpoint: 0,
            cluster: 0x0006,
            command: 0x01,
        }
    }

    /// Consecutive group sends inside one reserved block cost exactly ONE store
    /// write, and still burn strictly increasing counters.
    ///
    /// Pre-fix every `invoke_group` fsynced the whole snapshot before the
    /// datagram left the host, so a burst of group commands ran at disk speed.
    #[tokio::test]
    async fn group_sends_share_one_reservation() {
        let store = Arc::new(CountingStore::default());
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
        controller
            .create_fabric(cfg())
            .await
            .expect("create_fabric");
        let key_set_id = 0x0042u16;
        let group_key = controller
            .create_group(key_set_id, 0)
            .await
            .expect("create_group");
        let epoch_key: [u8; 16] = group_key.epoch_key.clone().try_into().unwrap();

        // Baseline: everything before the group sends is already persisted.
        let baseline = store.saves();

        let mut counters = Vec::new();
        for _ in 0..3 {
            controller
                .invoke_group(
                    0xBEEF,
                    key_set_id,
                    on_command_path(),
                    matter_codec::Value::Structure(vec![]),
                )
                .await
                .expect("invoke_group");
            let (wire, _from) = peer.recv_from().await.expect("frame emitted");
            let snap = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
            let op = op_group_key_of(&snap, &epoch_key);
            counters.push(wire_group_counter(&wire, &op));
        }

        assert_eq!(
            store.saves() - baseline,
            1,
            "3 group sends inside one reserved block must cost exactly 1 store write"
        );
        assert_eq!(
            counters,
            vec![0, 1, 2],
            "counters must still be strictly increasing across the block"
        );

        // The persisted field holds the RESERVED CEILING, not the last-sent value.
        let snap = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(
            snap.fabrics[0].outbound_group_counter, GROUP_COUNTER_BLOCK,
            "the serialized counter must be the reservation ceiling"
        );
    }

    /// Crash-safety invariant: after a restart the controller resumes at the
    /// persisted ceiling, so no counter it already sent can be handed out again.
    #[tokio::test]
    async fn group_counter_survives_restart_without_reuse() {
        let store: Arc<CountingStore> = Arc::new(CountingStore::default());
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
        controller
            .create_fabric(cfg())
            .await
            .expect("create_fabric");
        let key_set_id = 0x0042u16;
        let group_key = controller
            .create_group(key_set_id, 0)
            .await
            .expect("create_group");
        let epoch_key: [u8; 16] = group_key.epoch_key.clone().try_into().unwrap();

        let mut sent = Vec::new();
        for _ in 0..2 {
            controller
                .invoke_group(
                    0xBEEF,
                    key_set_id,
                    on_command_path(),
                    matter_codec::Value::Structure(vec![]),
                )
                .await
                .expect("invoke_group");
            let (wire, _from) = peer.recv_from().await.expect("frame emitted");
            let snap = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
            let op = op_group_key_of(&snap, &epoch_key);
            sent.push(wire_group_counter(&wire, &op));
        }
        drop(controller);

        let persisted_ceiling = crate::snapshot::deserialize(&store.load().unwrap().unwrap())
            .unwrap()
            .fabrics[0]
            .outbound_group_counter;

        // Restart: a fresh controller over the SAME store (the actor's live
        // counter is never serialized, so this is a true cold start).
        let (io2, peer2) = InMemoryDatagram::pair();
        let controller2 = crate::controller::MatterController::with_components(
            store.clone(),
            io2,
            NullDiscovery,
            Arc::new(matter_commissioning::SystemNocRng),
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        )
        .expect("reopen");
        controller2
            .invoke_group(
                0xBEEF,
                key_set_id,
                on_command_path(),
                matter_codec::Value::Structure(vec![]),
            )
            .await
            .expect("invoke_group after restart");
        let (wire, _from) = peer2.recv_from().await.expect("frame emitted");
        let snap = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let op = op_group_key_of(&snap, &epoch_key);
        let after_restart = wire_group_counter(&wire, &op);

        assert!(
            after_restart >= persisted_ceiling,
            "post-restart counter {after_restart} must resume at or above the persisted ceiling {persisted_ceiling}"
        );
        assert!(
            sent.iter().all(|&c| after_restart > c),
            "post-restart counter {after_restart} must exceed every counter already sent ({sent:?})"
        );
    }

    /// A reservation whose durable save FAILS must roll the in-memory ceiling
    /// back — and must burn no counter doing so.
    ///
    /// This pins the security core of block reservation, and the one deliberate
    /// departure from the reviewed design (which propagated the save error with
    /// `?`, leaving the raised ceiling in memory). Both halves are asserted:
    ///
    /// - **No counter burned.** The failed send emits no datagram, and the next
    ///   successful send reuses the very counter the failed one would have used.
    /// - **No uncovered counter.** That successful send is preceded by a
    ///   reservation that actually reaches the store — which only happens if the
    ///   ceiling was rolled back. Without the rollback the in-memory ceiling
    ///   would still read 64, the send would skip the reservation entirely, and
    ///   the persisted ceiling would stay 0 while counter 0 went out on the
    ///   wire: a crash would then hand counter 0 out a second time.
    #[tokio::test]
    async fn failed_reservation_rolls_back_and_burns_no_counter() {
        let store = Arc::new(CountingStore::default());
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
        controller
            .create_fabric(cfg())
            .await
            .expect("create_fabric");
        let key_set_id = 0x0042u16;
        let group_key = controller
            .create_group(key_set_id, 0)
            .await
            .expect("create_group");
        let epoch_key: [u8; 16] = group_key.epoch_key.clone().try_into().unwrap();
        let snap_before = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(
            snap_before.fabrics[0].outbound_group_counter, 0,
            "no reservation yet"
        );

        // The store goes down exactly when the first reservation tries to land.
        store.set_failing(true);
        let err = controller
            .invoke_group(
                0xBEEF,
                key_set_id,
                on_command_path(),
                matter_codec::Value::Structure(vec![]),
            )
            .await
            .expect_err("a failed reservation save must fail the send");
        assert!(
            format!("{err}").to_lowercase().contains("disk full"),
            "expected the store error to propagate, got: {err}"
        );

        // NOTHING went on the wire — the reservation is persist-before-send.
        let emitted = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            Box::pin(peer.recv_from()),
        )
        .await;
        assert!(
            emitted.is_err(),
            "a send whose reservation never reached the store must emit no datagram"
        );
        // And the store still holds the pre-failure ceiling.
        let snap_failed = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(
            snap_failed.fabrics[0].outbound_group_counter, 0,
            "a failed save must not have persisted the raised ceiling"
        );

        // Store recovers; the retry must re-attempt the reservation.
        store.set_failing(false);
        controller
            .invoke_group(
                0xBEEF,
                key_set_id,
                on_command_path(),
                matter_codec::Value::Structure(vec![]),
            )
            .await
            .expect("invoke_group after the store recovers");
        let (wire, _from) = peer.recv_from().await.expect("frame emitted");
        let snap_after = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let op = op_group_key_of(&snap_after, &epoch_key);

        assert_eq!(
            wire_group_counter(&wire, &op),
            0,
            "the failed send burned no counter: the retry reuses it"
        );
        assert_eq!(
            snap_after.fabrics[0].outbound_group_counter, GROUP_COUNTER_BLOCK,
            "the retry must have re-run the reservation — proving the ceiling was rolled back"
        );
    }

    /// A best-effort snapshot taken MID-BLOCK is safe: it serializes the
    /// ceiling, never the live counter, so a crash immediately after it still
    /// resumes above every value already sent.
    ///
    /// This is the invariant that makes the reservation sound in the presence
    /// of the detached address-hint save path, which can snapshot at any time.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn best_effort_snapshot_mid_block_is_safe() {
        let store = Arc::new(CountingStore::default());
        let key_set_id = 0x0042u16;
        let fields_tlv =
            crate::node::value_to_tlv(&matter_codec::Value::Structure(vec![])).unwrap();

        let (io, peer) = InMemoryDatagram::pair();
        let fabric = crate::fabric::create_fabric(&cfg(), &SystemNocRng).unwrap();
        let mut actor = Actor::new(
            io,
            NullDiscovery,
            store.clone(),
            Arc::new(SystemNocRng),
            ControllerState {
                fabrics: vec![fabric],
            },
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        );

        let (reply, rx) = oneshot::channel();
        actor
            .dispatch_ready(Command::CreateGroup {
                key_set_id,
                epoch_start_time: 0,
                reply,
            })
            .await;
        let group_key = rx.await.unwrap().expect("create_group");
        let epoch_key: [u8; 16] = group_key.epoch_key.clone().try_into().unwrap();

        let (reply, rx) = oneshot::channel();
        actor
            .dispatch_ready(Command::InvokeGroup {
                group_id: 0xBEEF,
                key_set_id,
                path: on_command_path(),
                fields_tlv: fields_tlv.clone(),
                reply,
            })
            .await;
        rx.await.unwrap().expect("invoke_group");
        let (wire, _from) = peer.recv_from().await.expect("frame emitted");
        let snap = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        let op = op_group_key_of(&snap, &epoch_key);
        let first = wire_group_counter(&wire, &op);

        // Mid-block best-effort snapshot (what the per-connect address hint does).
        let before = store.saves();
        actor.persist_best_effort();
        let mut landed = false;
        for _ in 0..200 {
            if store.saves() > before {
                landed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(landed, "the detached best-effort save must have run");

        let mid = crate::snapshot::deserialize(&store.load().unwrap().unwrap()).unwrap();
        assert_eq!(
            mid.fabrics[0].outbound_group_counter, GROUP_COUNTER_BLOCK,
            "a mid-block best-effort snapshot must serialize the ceiling, not the live counter"
        );

        // Crash right there: restart from exactly those bytes.
        let (io2, peer2) = InMemoryDatagram::pair();
        let mut actor2 = Actor::new(
            io2,
            NullDiscovery,
            store.clone(),
            Arc::new(SystemNocRng),
            mid,
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        );
        let (reply, rx) = oneshot::channel();
        actor2
            .dispatch_ready(Command::InvokeGroup {
                group_id: 0xBEEF,
                key_set_id,
                path: on_command_path(),
                fields_tlv,
                reply,
            })
            .await;
        rx.await.unwrap().expect("invoke_group after crash");
        let (wire2, _from) = peer2.recv_from().await.expect("frame emitted");
        let after = wire_group_counter(&wire2, &op);

        assert!(
            after >= GROUP_COUNTER_BLOCK,
            "post-crash counter {after} must resume at the ceiling {GROUP_COUNTER_BLOCK}"
        );
        assert!(
            after > first,
            "post-crash counter {after} must not reuse the already-sent {first}"
        );
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

    /// Like [`FixedDiscovery`] but with mdns-sd's **consuming** drain semantics:
    /// a browse hands each record over once and never repeats it, because
    /// `poll_results` drains the daemon's event receiver. mdns-sd re-flushes its
    /// cache only to *newly opened* browses (an already-open one sees an instance
    /// again only on a real record refresh, whose re-query backoff doubles
    /// 1 s, 2 s, 4 s … up to an hour), so reopening the query is modelled as
    /// making the record available again.
    ///
    /// `FixedDiscovery` re-emits forever and therefore cannot exercise the
    /// actor's `seen_records` cache at all — this double is what pins it.
    struct DrainingDiscovery {
        addr: std::net::SocketAddr,
        instance_name: String,
        /// `true` once the current browse has handed the record over.
        drained: bool,
    }
    impl Discovery for DrainingDiscovery {
        fn publish(&mut self, _s: &MatterService) -> matter_transport::Result<()> {
            Ok(())
        }
        fn unpublish(&mut self, _n: &str, _k: ServiceKind) -> matter_transport::Result<()> {
            Ok(())
        }
        fn query(&mut self, _k: ServiceKind) -> matter_transport::Result<QueryHandle> {
            self.drained = false; // a fresh browse gets the daemon's cache flush
            Ok(QueryHandle(1))
        }
        fn stop_query(&mut self, _h: QueryHandle) {}
        fn poll_results(&mut self, _h: QueryHandle) -> Vec<MatterService> {
            if self.drained {
                return Vec::new();
            }
            self.drained = true;
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

    /// Keep a simulated device's endpoint open for the rest of the process.
    ///
    /// [`InMemoryDatagram`] is a *paired* transport: dropping one endpoint closes
    /// the channel feeding the other, so the surviving endpoint's `recv_from`
    /// returns [`std::io::ErrorKind::BrokenPipe`] forever. A device task that
    /// simply returned would therefore kill the CONTROLLER's socket — which
    /// [`Actor::run`] correctly treats as terminal and shuts down on (see
    /// [`recv_error_is_terminal`]), breaking every assertion a test makes after
    /// its device task finishes.
    ///
    /// No real UDP socket dies because the device on the other end went quiet, so
    /// the harness must not simulate that. Leaking the endpoint models the true
    /// situation — "the device stopped answering; the socket is still there" —
    /// and the leak is one small struct per device task in a short-lived test
    /// process.
    ///
    /// (Before the recv-error classification, the resulting `BrokenPipe` was
    /// silently discarded instead. Nine tests fail without this helper; in the
    /// subset that actually drives [`Actor::run`] against a closed endpoint the
    /// loop also spun on the discarded error — measured on
    /// `actor_stays_live_while_resolve_pends`, which burned 2.21 s of user CPU
    /// over 2.22 s of wall clock before the fix and 0.31 s after it. Several of
    /// the other call sites drive `Actor` methods directly without ever running
    /// the loop, so the broken transport was never polled there.)
    fn keep_endpoint_open(io: InMemoryDatagram) {
        std::mem::forget(io);
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
        keep_endpoint_open(io);
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
        keep_endpoint_open(io);
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
        keep_endpoint_open(io);
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
        keep_endpoint_open(io);
    }

    /// Device that establishes a subscription, then — when a round-trip request
    /// arrives — sends a steady-state `ReportData` (on the subscription
    /// exchange, carrying the `subscriptionId`) *before* replying to the
    /// round-trip. This is the concurrent window the previous controller design
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
        keep_endpoint_open(io);
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
                keep_endpoint_open(io);
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
        let mut fabric = {
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
        // Seed the device into the fabric, as a real commission would: the
        // controller only ever connects to an already-commissioned device
        // (device entries are born at commission, and `upsert_device` is
        // update-only). Without this, a connect would find no entry to update.
        let device_pubkey = *device_signer.public_key().as_bytes();
        fabric.devices.push(crate::state::DeviceEntry {
            node_id: device_node_id,
            peer_noc_public_key: device_pubkey,
            resumption_record: None,
            last_known_addr: None,
            vendor_id: None,
            product_id: None,
            label: None,
        });
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

    /// Liveness regression: an operational resolve that never lands must not
    /// stall the actor loop. `FixedDiscovery` only ever advertises the loopback
    /// device, so a verb aimed at `UNRESOLVABLE_NODE` can never match — its
    /// resolve parks on the timer arm, and every *other* session must keep
    /// running while it does. Before the timer-driven resolve this test hung:
    /// `spawn_connect` polled mDNS inline for the whole ~30 s budget, so the
    /// loopback round-trip below never got dispatched.
    #[tokio::test]
    async fn actor_stays_live_while_resolve_pends() {
        /// A node id no discovery record will ever match (the harness's device
        /// is `0x42`), so its resolve runs to the deadline.
        const UNRESOLVABLE_NODE: u64 = 0x0000_0000_0000_0099;

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
            1,
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

        // (1) Aim a verb at the unresolvable node and keep its future alive. The
        // short timeout both delivers the command and gives the actor time to
        // park the resolve; the future must still be *pending* (a failed connect
        // would have resolved it with an error instead).
        let unresolvable = controller.node(UNRESOLVABLE_NODE);
        let mut pending_verb = Box::pin(unresolvable.round_trip(
            0x02,
            ProtocolId::INTERACTION_MODEL,
            b"ping".to_vec(),
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), &mut pending_verb)
                .await
                .is_err(),
            "the parked resolve must not have failed yet"
        );

        // (2) The whole point: with that resolve parked, the loopback device's
        // CASE handshake + round-trip must still complete promptly.
        let node = controller.node(device_node_id);
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            node.round_trip(0x02, ProtocolId::INTERACTION_MODEL, b"ping".to_vec()),
        )
        .await
        .expect("actor stayed live while the other node's resolve was parked")
        .expect("loopback round-trip");
        assert_eq!(resp, b"pong");

        // (3) And the parked resolve is still parked, not yet expired — its
        // deadline outlives a whole handshake + round-trip on another session.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending_verb)
                .await
                .is_err(),
            "the parked resolve must outlive the other session's traffic"
        );

        // (4) Once RESOLVE_DEADLINE passes, the timer arm expires the entry and
        // fails its waiters with the mDNS-not-found error.
        let err = tokio::time::timeout(RESOLVE_DEADLINE * 3, pending_verb)
            .await
            .expect("the parked resolve must expire at its deadline")
            .expect_err("an unresolvable node must fail its waiters");
        let msg = err.to_string();
        assert!(
            msg.contains("not found via mDNS"),
            "expiry must report the mDNS-not-found error, got: {msg}"
        );

        device.await.unwrap();
    }

    /// Anti-starvation regression for the ABSOLUTE resolve-poll anchor.
    ///
    /// `next_resolve_poll` is a fixed instant, advanced only by
    /// [`Actor::drive_pending_resolves`]. The obvious alternative — having
    /// [`Actor::next_timer_deadline`] return `now + RESOLVE_POLL_INTERVAL`
    /// recomputed per iteration — is starvable: ANY `select!` arm firing more
    /// often than the interval pushes that relative deadline forward before it
    /// can elapse, so the timer arm never runs, `drive_pending_resolves` is
    /// never called, and every parked mDNS resolve stalls for as long as the
    /// traffic lasts (a device streaming reports is enough).
    ///
    /// So: keep the inbound arm genuinely hot while a resolve is parked, and
    /// assert the parked resolve still reaches its deadline. Against a relative
    /// anchor this hangs until the timeout and fails.
    ///
    /// This replaces coverage that was previously accidental. Before `recv_from`
    /// errors were classified, the harness's dropped device endpoint made the
    /// recv arm return `BrokenPipe` tens of thousands of times a second, which
    /// starved a relative anchor as a side effect of a bug — so fixing that bug
    /// would otherwise have deleted the only test of this invariant.
    #[tokio::test]
    async fn parked_resolve_expires_while_the_inbound_arm_is_hot() {
        /// Same unmatchable node id as `actor_stays_live_while_resolve_pends`.
        const UNRESOLVABLE_NODE: u64 = 0x0000_0000_0000_0099;
        /// Pacing of the synthetic inbound flood. 1 ms is 250x more frequent
        /// than [`RESOLVE_POLL_INTERVAL`], so a relative anchor could never
        /// elapse — while being slow enough that the queued junk stays tiny.
        const FLOOD_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1);
        /// Floor on the flood the assertions accept as "genuinely hot". Even a
        /// heavily loaded machine managing only this many sends across the
        /// resolve's lifetime fires the arm far above the 4 Hz poll interval.
        const MIN_FLOOD: usize = 100;

        let Harness {
            store,
            ctrl_io,
            dev_io,
            ctrl_addr,
            discovery,
            ..
        } = loopback_harness();

        // The hot arm: junk datagrams the actor decodes, rejects and discards,
        // one per millisecond, for the whole test. The task owns `dev_io`, and
        // `JoinHandle::abort` DOES drop the task's future — and with it `dev_io`,
        // which closes the controller's own endpoint (see `keep_endpoint_open`
        // for why that is terminal). What keeps this test sound is ordering, not
        // ownership: the abort is the last statement, after every assertion, so
        // nothing observes the controller once its endpoint is gone.
        let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flood_counter = Arc::clone(&sent);
        let flooder = tokio::spawn(async move {
            loop {
                dev_io
                    .send_to(b"not-a-matter-frame", ctrl_addr)
                    .await
                    .unwrap();
                flood_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::time::sleep(FLOOD_INTERVAL).await;
            }
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

        // `FixedDiscovery` only ever advertises the harness's own device, so
        // this node's resolve parks and can only ever end at its deadline — a
        // deadline reachable only if the timer arm is not starved by the flood.
        let err = tokio::time::timeout(
            RESOLVE_DEADLINE * 3,
            controller.node(UNRESOLVABLE_NODE).round_trip(
                0x02,
                ProtocolId::INTERACTION_MODEL,
                b"ping".to_vec(),
            ),
        )
        .await
        .expect("a parked resolve must reach its deadline even under a hot select arm")
        .expect_err("an unresolvable node must fail its waiters");
        let msg = err.to_string();
        assert!(
            msg.contains("not found via mDNS"),
            "expiry must report the mDNS-not-found error, got: {msg}"
        );

        let flood = sent.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            flood >= MIN_FLOOD,
            "the inbound arm must have been genuinely hot for this to prove \
             anything; only {flood} datagrams were sent"
        );
        // Last statement on purpose: this drops `dev_io` and therefore ends the
        // controller's transport (see the comment above the spawn).
        flooder.abort();
    }

    /// A transport whose `recv_from` fails TERMINALLY must stop the actor loop,
    /// not have its error discarded and be re-polled forever.
    ///
    /// `InMemoryDatagram` returns [`std::io::ErrorKind::BrokenPipe`] for good
    /// once its paired endpoint is gone, which is exactly the permanent-error
    /// shape this guards: the old `if let Ok(..) = recv` arm dropped it on the
    /// floor and re-polled immediately, spinning at ~75 000 iterations/second
    /// (~447 000 measured over 6 s).
    ///
    /// The command channel is deliberately held open across the assertion, so
    /// the only thing that can end the loop here is the transport.
    #[tokio::test]
    async fn terminal_transport_error_stops_the_actor_loop() {
        let (io, peer) = InMemoryDatagram::pair();
        // Every `recv_from` on `io` now fails with BrokenPipe, immediately.
        drop(peer);

        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(8);
        let loop_handle = tokio::spawn(actor_with_one_fabric_on(io).run(cmd_rx));

        tokio::time::timeout(std::time::Duration::from_secs(5), loop_handle)
            .await
            .expect("a terminally-failing transport must stop the loop, not spin on it")
            .expect("the loop must return normally, not panic");

        // Held to here on purpose: the loop exited on the transport, not on a
        // dropped command channel.
        drop(cmd_tx);
    }

    /// A transport failing with a TRANSIENT error must not stop the loop, and
    /// must not spin on it either.
    ///
    /// `WouldBlock` stands in for the whole transient class — the recoverable
    /// errors a socket surfaces (spurious wakeup, `EINTR`, a queued ICMP error),
    /// plus every kind std may add to a `#[non_exhaustive]` `ErrorKind`, none of
    /// which may kill a controller. The transport here fails EVERY receive, i.e.
    /// it is a permanently-transient one — the case the backoff exists for: the
    /// loop must still be alive and serving commands afterwards, and must have
    /// polled the transport a bounded number of times rather than as fast as the
    /// CPU allows.
    #[tokio::test]
    async fn transient_transport_errors_neither_stop_nor_spin_the_loop() {
        /// Always-failing datagram transport that counts its receive attempts.
        struct AlwaysWouldBlock(Arc<std::sync::atomic::AtomicUsize>);
        impl AsyncDatagram for AlwaysWouldBlock {
            async fn send_to(&self, _buf: &[u8], _peer: SocketAddr) -> std::io::Result<()> {
                Ok(())
            }
            async fn recv_from(&self) -> std::io::Result<(Vec<u8>, SocketAddr)> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "synthetic transient failure",
                ))
            }
        }

        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let transport = AlwaysWouldBlock(Arc::clone(&attempts));
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
        let actor = Actor::new(
            transport,
            NullDiscovery,
            Arc::new(MemStore::default()),
            Arc::new(SystemNocRng),
            ControllerState {
                fabrics: vec![fabric],
            },
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        );

        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(8);
        let loop_handle = tokio::spawn(actor.run(cmd_rx));

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Still alive and serving commands despite a transport that has never
        // once succeeded.
        let (count_tx, count_rx) = oneshot::channel();
        cmd_tx
            .send(Command::SessionCount { reply: count_tx })
            .await
            .unwrap();
        let count = tokio::time::timeout(std::time::Duration::from_secs(1), count_rx)
            .await
            .expect("a transient transport error must leave the loop responsive")
            .expect("SessionCount reply");
        assert_eq!(count, 0);

        // And bounded: RECV_ERROR_FREE_RETRIES free polls, then a doubling ramp
        // saturating at RECV_ERROR_BACKOFF_MAX_MS, i.e. ~18 polls over this
        // window (measured). Errors this dense never decay — at saturation they
        // are ~200 ms apart, well inside RECV_ERROR_DECAY — so the ramp is
        // climbed once and stays climbed. The ceiling below leaves an order of
        // magnitude of slack for a loaded CI box while still failing by more
        // than two orders of magnitude against an un-backed-off loop (~75 000
        // polls per second, i.e. ~37 000 across this window).
        let polls = attempts.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            polls < 200,
            "the recv arm must be backed off, not spun: {polls} polls in ~500 ms"
        );

        drop(cmd_tx);
        let _ = loop_handle.await;
    }

    /// The classification itself, and the shape of the backoff ramp.
    #[test]
    fn recv_error_classification_and_backoff_ramp() {
        use std::io::ErrorKind;

        // Terminal: the socket is gone and retrying cannot recover it.
        assert!(recv_error_is_terminal(ErrorKind::BrokenPipe));
        assert!(recv_error_is_terminal(ErrorKind::NotConnected));
        // Transient: recoverable, and routine on a real socket. ErrorKind is
        // #[non_exhaustive], so `Other` here also stands for every kind std has
        // yet to add — none of which may be allowed to kill a controller.
        // (ConnectionRefused is Linux surfacing a peer's ICMP port-unreachable;
        // it reaches only a *connected* UDP socket, which our TokioUdpTransport
        // is not — it binds `[::]:port` and never calls connect. It is listed
        // because an out-of-tree AsyncDatagram may well be connected.)
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
            ErrorKind::Other,
        ] {
            assert!(!recv_error_is_terminal(kind), "{kind:?} must be transient");
        }

        // The first RECV_ERROR_FREE_RETRIES cost nothing, so an isolated blip
        // never delays inbound.
        assert_eq!(recv_error_backoff(0), None);
        assert_eq!(recv_error_backoff(RECV_ERROR_FREE_RETRIES), None);
        // Then it doubles from RECV_ERROR_BACKOFF_MIN_MS…
        assert_eq!(
            recv_error_backoff(RECV_ERROR_FREE_RETRIES + 1),
            Some(std::time::Duration::from_millis(RECV_ERROR_BACKOFF_MIN_MS))
        );
        assert_eq!(
            recv_error_backoff(RECV_ERROR_FREE_RETRIES + 3),
            Some(std::time::Duration::from_millis(
                4 * RECV_ERROR_BACKOFF_MIN_MS
            ))
        );
        // …and saturates, including at the arithmetic edge (no overflow, no
        // wrap back to a zero-length backoff — either would restore the spin).
        let capped = Some(std::time::Duration::from_millis(RECV_ERROR_BACKOFF_MAX_MS));
        assert_eq!(recv_error_backoff(RECV_ERROR_FREE_RETRIES + 64), capped);
        assert_eq!(recv_error_backoff(u32::MAX), capped);

        // Monotonic non-decreasing across the whole ramp.
        let mut prev = std::time::Duration::ZERO;
        for n in 0..64 {
            let d = recv_error_backoff(n).unwrap_or(std::time::Duration::ZERO);
            assert!(d >= prev, "backoff must never shrink (at n = {n})");
            prev = d;
        }
    }

    /// A run of receive errors must DECAY, or the counter only ever rises: a
    /// controller whose only peer is offline sees one error per MRP retransmit
    /// with no successful receive in between, and would otherwise creep to the
    /// backoff ceiling and stay pinned there for the life of the process,
    /// delaying the first datagram from a returning device by up to the cap.
    #[test]
    fn recv_error_run_decays_after_a_quiet_gap() {
        // Instants are built by ADDING to a base rather than subtracting from
        // `now`: `Instant` subtraction can underflow, and clippy rejects it.
        let prev = Instant::now();

        // Nothing to decay before the first error of a run.
        assert!(!recv_error_run_broken(None, prev));
        // Errors inside the window are one run…
        assert!(!recv_error_run_broken(
            Some(prev),
            prev + RECV_ERROR_DECAY / 2
        ));
        // …including exactly at the boundary (the break is a strict `>`)…
        assert!(!recv_error_run_broken(Some(prev), prev + RECV_ERROR_DECAY));
        // …and a longer gap breaks it, restoring the free-retry budget.
        assert!(recv_error_run_broken(
            Some(prev),
            prev + RECV_ERROR_DECAY + std::time::Duration::from_millis(1)
        ));

        // The decay window MUST exceed the backoff ceiling. At saturation the
        // backoff itself paces polls ~RECV_ERROR_BACKOFF_MAX_MS apart, so a
        // window at or below the cap would be tripped by the backoff's own
        // pacing and hand a wedged transport its free retries back every cycle.
        assert!(
            RECV_ERROR_DECAY > std::time::Duration::from_millis(RECV_ERROR_BACKOFF_MAX_MS),
            "the decay window must be longer than the saturated backoff interval"
        );
    }

    /// The `warn` escalation must be EDGE-triggered: a wedged transport has to
    /// be visible at default log levels without turning into a log flood.
    #[test]
    fn recv_error_warn_stage_marks_the_two_edges() {
        use std::time::Duration;

        // Inside the free budget: nothing to say yet.
        assert_eq!(
            recv_error_warn_stage(recv_error_backoff(RECV_ERROR_FREE_RETRIES)),
            RecvWarnStage::Quiet
        );
        // First backoff step — the run stopped looking like a blip.
        assert_eq!(
            recv_error_warn_stage(recv_error_backoff(RECV_ERROR_FREE_RETRIES + 1)),
            RecvWarnStage::BackingOff
        );
        // Ceiling reached — the transport looks wedged for good.
        assert_eq!(
            recv_error_warn_stage(recv_error_backoff(u32::MAX)),
            RecvWarnStage::Saturated
        );
        assert_eq!(
            recv_error_warn_stage(Some(Duration::from_millis(RECV_ERROR_BACKOFF_MAX_MS))),
            RecvWarnStage::Saturated
        );

        // Ordered, because `run` fires a warning only when the stage RISES; an
        // unordered (or re-orderable) enum would re-warn per error.
        assert!(RecvWarnStage::Quiet < RecvWarnStage::BackingOff);
        assert!(RecvWarnStage::BackingOff < RecvWarnStage::Saturated);
        assert_eq!(RecvWarnStage::default(), RecvWarnStage::Quiet);

        // Every step of the ramp lands on exactly one of the two escalations, so
        // the stage can never skip back down mid-run.
        let mut prev = RecvWarnStage::Quiet;
        for n in 0..64 {
            let stage = recv_error_warn_stage(recv_error_backoff(n));
            assert!(stage >= prev, "the warn stage must never fall (at n = {n})");
            prev = stage;
        }
    }

    /// The decay and the warn edge must be wired into the actor's STATE, not
    /// just available as helpers: a long run climbs to the ceiling and warns
    /// twice; a quiet gap then starts a fresh run, with the free-retry budget
    /// and the warn edge both restored (so a later wedge warns again).
    #[tokio::test]
    async fn actor_recv_error_run_decays_and_re_arms_the_warn_edge() {
        let mut actor = actor_with_one_fabric();
        let err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "synthetic");
        let start = Instant::now();

        // A dense run: one error per millisecond, far inside RECV_ERROR_DECAY.
        let run_len = RECV_ERROR_FREE_RETRIES + 40;
        for i in 0..run_len {
            actor.note_transient_recv_error(
                &err,
                start + std::time::Duration::from_millis(i.into()),
            );
        }
        assert_eq!(actor.consecutive_recv_errors, run_len);
        assert_eq!(actor.recv_warn_stage, RecvWarnStage::Saturated);

        // A quiet gap: the next error is a NEW run, so it is free again and the
        // stage is back to Quiet (i.e. a later wedge warns rather than being
        // swallowed by the previous wedge's edge).
        let after_gap = start
            + std::time::Duration::from_millis(run_len.into())
            + RECV_ERROR_DECAY
            + std::time::Duration::from_millis(1);
        actor.note_transient_recv_error(&err, after_gap);
        assert_eq!(
            actor.consecutive_recv_errors, 1,
            "a blip after a quiet gap must not inherit the previous run's count"
        );
        assert_eq!(actor.recv_warn_stage, RecvWarnStage::Quiet);
    }

    /// A record drained from the shared browse while NO resolve was parked for
    /// it must not be thrown away: `poll_results` consumes what it returns, and
    /// an already-open browse will not see that instance again for a long time
    /// (mdns-sd re-flushes its cache only to new browses; its re-query backoff
    /// doubles to an hour). So the online device must still connect from the
    /// cached record — otherwise a node that is up and advertising fails at
    /// `RESOLVE_DEADLINE` purely because an unrelated offline node opened the
    /// browse first.
    #[tokio::test]
    async fn record_drained_before_its_resolve_parks_is_not_lost() {
        /// Offline node: never advertised, so it holds the browse open.
        const OFFLINE_NODE: u64 = 0x0000_0000_0000_0099;

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

        // Same device, but advertised with realistic consuming-drain semantics.
        let discovery = DrainingDiscovery {
            addr: discovery.addr,
            instance_name: discovery.instance_name,
            drained: false,
        };

        let device = tokio::spawn(run_loopback_device(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00D2,
            1,
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

        // (1) The OFFLINE node connects first. That opens the browse, and its
        // one and only drain carries the *loopback device's* record — which
        // nothing is parked for yet. Keep the verb alive so the browse stays
        // open (a closed+reopened browse would re-flush and mask the bug).
        let offline = controller.node(OFFLINE_NODE);
        let mut parked_verb =
            Box::pin(offline.round_trip(0x02, ProtocolId::INTERACTION_MODEL, b"ping".to_vec()));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), &mut parked_verb)
                .await
                .is_err(),
            "the offline node's resolve must still be parked, holding the browse open"
        );

        // (2) Now connect to the online device. Its record will never be emitted
        // again on this browse, so this can only succeed from the cache.
        let node = controller.node(device_node_id);
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            node.round_trip(0x02, ProtocolId::INTERACTION_MODEL, b"ping".to_vec()),
        )
        .await
        .expect("an online device must not be starved by a record drained before it parked")
        .expect("loopback round-trip");
        assert_eq!(resp, b"pong");

        device.await.unwrap();
    }

    /// Route-key normalization (regression guard for the bug the live
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

    /// A verb-triggered CASE connect runs its handshake **off
    /// the actor loop**, so a stalled handshake no longer starves other work.
    ///
    /// The device receives Sigma1 and never answers, so the connect's handshake
    /// stalls (retransmits Sigma1, eventually times out — seconds). We fire a
    /// round-trip at that device (which parks behind the connect) and then, while
    /// the handshake is stalled, issue an unrelated `session_count` command. It
    /// must be serviced promptly. On the previous inline design the connect ran on
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

    /// Discriminating guard for the concurrent-round-trip report-loss
    /// (a known limitation of the earlier design): a steady-state report that
    /// arrives while a round-trip is in flight on the same node must be
    /// DELIVERED, not dropped. Under the earlier code the report was consumed inside
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

    /// Discriminating guard: a subscription that goes silent past its
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
        actor.insert_subscription(SubId(1), mk(sink_a, SessionId(7)));
        actor.insert_subscription(SubId(2), mk(sink_b, SessionId(9)));

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

    /// A consumer that dropped both its report and control receivers can never
    /// observe a subscription again (the drop-side cancel is a lossy
    /// `try_send`, so it may not have reached the actor). `drive_resubscribes`
    /// must reap such an entry instead of retrying it forever, and must not
    /// enqueue a connect for it — there is no one left to deliver `Established`
    /// to.
    #[tokio::test]
    async fn dropped_subscription_reaps_pending_resubscribe() {
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

        let (sink, report_rx, ctrl_rx) = test_report_sink();
        drop(report_rx);
        drop(ctrl_rx);

        actor.resubscribes.push(PendingResubscribe {
            sub_id: SubId(1),
            attempt_at: Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .expect("instant minus 1s is representable"),
            node_id: 2,
            paths: vec![matter_interaction::ReadPath::all()],
            event_paths: vec![],
            event_filters: vec![],
            min_interval: 1,
            max_interval: 30,
            retry_count: 0,
            tx: sink,
        });

        actor.drive_resubscribes().await;

        assert!(
            actor.resubscribes.is_empty(),
            "zombie resubscribe entry must be reaped, not rescheduled"
        );
        assert!(
            actor.pending_connects.is_empty(),
            "no connect should be enqueued for a consumer that is gone"
        );
    }

    /// Build an actor with one real fabric in state so `sole_fabric()` (and thus
    /// the cache-eviction path in `on_pending_timeout`) is exercised. Discovery
    /// is null, so any `connect()` the timeout path attempts will fail without
    /// touching the cached session — exactly what we want to observe the guard.
    fn actor_with_one_fabric() -> Actor<InMemoryDatagram, NullDiscovery> {
        let (io, peer) = InMemoryDatagram::pair();
        // Nothing ever answers this actor, but its socket must stay OPEN rather
        // than break: dropping `peer` here would `BrokenPipe` the actor's
        // `recv_from` immediately, which `Actor::run` shuts down on.
        keep_endpoint_open(peer);
        actor_with_one_fabric_on(io)
    }

    /// [`actor_with_one_fabric`] over a caller-supplied transport, so a test can
    /// control what that transport does (notably: hand in an endpoint whose peer
    /// has been dropped, i.e. one that fails every `recv_from`).
    fn actor_with_one_fabric_on(io: InMemoryDatagram) -> Actor<InMemoryDatagram, NullDiscovery> {
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

    /// The address stamped onto a session is what `peer_for_session` returns
    /// in O(1) — and it disappears the moment the session is removed, rather
    /// than lingering in a side index (the whole point of storing it ON the
    /// session: eviction can't strand it).
    #[test]
    fn peer_for_session_uses_stamped_addr_and_dies_with_the_session() {
        use matter_crypto::pase::PaseSessionKeys;

        let mut actor = actor_with_one_fabric();
        let keys = PaseSessionKeys {
            ke: [0u8; 16],
            i2r_key: [1u8; 16],
            r2i_key: [2u8; 16],
            attestation_key: [3u8; 16],
        };
        let sid = actor.sessions.register_pase(
            keys,
            SessionRole::Initiator,
            1,
            matter_transport::PeerHint::default(),
        );
        let peer: SocketAddr = "[::1]:5540".parse().unwrap();
        if let Some(s) = actor.sessions.get_mut(sid) {
            s.peer_addr = Some(peer);
        }
        assert_eq!(actor.peer_for_session(sid), Some(peer));
        actor.sessions.remove(sid);
        assert_eq!(actor.peer_for_session(sid), None);
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
        let mut actor = test_actor(store.clone());

        // Wedge any save until we release this guard.
        let held = store.gate.lock().unwrap();

        // Fire-and-forget; this must return immediately despite the wedged store.
        let seq_before = actor.snapshot_seq;
        let start = std::time::Instant::now();
        actor.persist_best_effort();
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "best-effort persist must not block on the fsync"
        );
        // Ordering regression guard: the detached job must be stamped from the
        // actor's OWN sequence + gate, not a fresh one. A best-effort save that
        // silently built its own gate would order against nothing and could roll
        // durable state backwards — and every timing assertion here would still
        // pass. Assert the sequence advanced...
        assert_eq!(
            actor.snapshot_seq,
            seq_before + 1,
            "persist_best_effort must advance the actor's snapshot sequence"
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
        // ...and that the write landed on the actor's SHARED gate. Poll the gate
        // itself rather than asserting off the `saves` counter: `save()` bumps
        // that counter before it returns, while `SaveJob::run` publishes the
        // sequence only afterwards, so `ran` can be observed an instant early.
        let mut gated = false;
        for _ in 0..200 {
            if *actor.save_gate.lock().unwrap() == actor.snapshot_seq {
                gated = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            gated,
            "the detached best-effort job must share the actor's save gate \
             (gate {}, expected {})",
            *actor.save_gate.lock().unwrap(),
            actor.snapshot_seq
        );
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
        let mut actor = test_actor(store.clone());
        let job = actor.durable_save_inputs().expect("serialize");
        save_offloaded(job).await.expect("durable save ok");
        assert!(
            store.load().expect("load").is_some(),
            "durable save must have written the snapshot"
        );

        // Failure path: a failing store surfaces the error to the awaiter.
        let mut actor = test_actor(Arc::new(FailingStore));
        let job = actor.durable_save_inputs().expect("serialize");
        let err = save_offloaded(job)
            .await
            .expect_err("a failing store must surface its error");
        assert!(
            format!("{err}").to_lowercase().contains("disk full")
                || format!("{err}").to_lowercase().contains("i/o"),
            "expected the store error to propagate, got: {err}"
        );
    }

    /// Ordering regression: a snapshot serialized EARLIER must never overwrite
    /// one serialized LATER, whichever reaches the store's `rename` first.
    ///
    /// The hazard is real because best-effort saves are detached: a fire-and-
    /// forget job can be descheduled behind a later durable save and then land
    /// its (now stale) bytes on top. `SaveJob` carries the serialize-time
    /// sequence and a shared gate; a job older than the last-written sequence
    /// is skipped instead of clobbering.
    #[test]
    fn stale_snapshot_does_not_clobber_newer() {
        let store = Arc::new(MemStore::default());
        let gate = Arc::new(std::sync::Mutex::new(0u64));

        let newer = SaveJob {
            store: store.clone(),
            bytes: b"B".to_vec(),
            seq: 2,
            gate: gate.clone(),
        };
        let stale = SaveJob {
            store: store.clone(),
            bytes: b"A".to_vec(),
            seq: 1,
            gate: gate.clone(),
        };

        newer.run().expect("newer save ok");
        // The stale job still reports success — it is a skip, not a failure —
        // but must leave the newer bytes in place.
        stale.run().expect("stale save is a no-op, not an error");

        assert_eq!(
            store.load().expect("load"),
            Some(b"B".to_vec()),
            "the older snapshot must not have clobbered the newer one"
        );
        assert_eq!(*gate.lock().unwrap(), 2, "the gate tracks the newest write");
    }

    /// The async counterpart of `stale_snapshot_does_not_clobber_newer`: a
    /// detached best-effort save built from a snapshot serialized BEFORE a
    /// durable save must not overwrite the durable bytes when it finally runs
    /// on the blocking pool.
    ///
    /// The stale job is constructed directly (seq below the actor's gate) —
    /// that is exactly the state a `persist_best_effort` descheduled behind a
    /// durable save would be in, without needing to win a real race.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn best_effort_after_durable_is_noop() {
        let store = Arc::new(MemStore::default());
        let mut actor = test_actor(store.clone());

        // Durable save first: this advances the shared gate to its sequence.
        let job = actor.durable_save_inputs().expect("serialize");
        save_offloaded(job).await.expect("durable save ok");
        let durable = store.load().expect("load");
        assert!(durable.is_some(), "durable save must have written");

        // A best-effort job serialized *before* the durable one (lower seq),
        // detached exactly as `persist_best_effort` does.
        let stale = SaveJob {
            store: store.clone(),
            bytes: b"stale-snapshot".to_vec(),
            seq: 0,
            gate: actor.save_gate.clone(),
        };
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        drop(tokio::task::spawn_blocking(move || {
            let _ = stale.run();
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        // Drain the blocking pool: wait until the detached job has finished.
        let mut done = false;
        for _ in 0..200 {
            if ran.load(std::sync::atomic::Ordering::SeqCst) {
                done = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(done, "the detached best-effort job must have run");

        assert_eq!(
            store.load().expect("load"),
            durable,
            "a stale best-effort save must not roll the store back"
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
        actor.insert_subscription(
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

    /// Decoupled connect/commission handling, part 1 — the actor loop stays
    /// responsive while a commission is outstanding, and the completions-channel
    /// `select!` arm drains a finished commission and resolves its reply.
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
                label: None,
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

    /// A caller-supplied `label` riding along on a successful
    /// [`CommissionCompletion`] must land on the pushed `DeviceEntry`, atomically
    /// with the rest of the commissioning state (same durable-save path as the
    /// node id / peer key). We feed a synthetic success completion (skipping the
    /// real PASE/CASE network dance, exactly like
    /// `commission_completion_drains_while_loop_stays_responsive` does for the
    /// error path) and confirm the label round-trips through `ListNodes`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)] // one linear success-path scenario: label + vid/pid persistence
    async fn commission_completion_persists_label_on_device_entry() {
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
        let fabric_id = fabric.fabric_id;
        let fabric_record = fabric.to_fabric_record().expect("fabric record");
        let actor = Actor::new(
            io,
            NullDiscovery,
            Arc::new(MemStore::default()),
            Arc::new(SystemNocRng),
            ControllerState {
                fabrics: vec![fabric],
            },
            None,
            crate::builder::DEFAULT_ADMIN_VENDOR_ID,
        );
        let completion_tx = actor.commission_tx.clone();

        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(8);
        let loop_handle = tokio::spawn(actor.run(cmd_rx));

        let commissioned = matter_commissioning::test_support::commissioned_fabric_for_test(
            fabric_record,
            2,
            [0x04; 65],
        );

        let (reply_tx, reply_rx) = oneshot::channel();
        completion_tx
            .send(CommissionCompletion {
                fabric_id,
                result: Ok(commissioned),
                label: Some("plug".to_string()),
                reply: reply_tx,
            })
            .await
            .unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), reply_rx)
            .await
            .expect("the completions arm must resolve the commission reply")
            .expect("reply channel");
        let info = outcome.expect("commission reply");
        assert_eq!(info.node_id, 2, "node id must be the assigned peer id");
        assert_eq!(info.fabric_id, fabric_id, "NodeInfo carries the fabric id");
        assert_eq!(
            info.label,
            Some("plug".to_string()),
            "NodeInfo carries the label"
        );
        assert_eq!(
            (info.vendor_id, info.product_id),
            (None, None),
            "vid/pid are filled by the controller's post-commission read, not the actor"
        );

        // Read back the persisted device via the public `ListNodes` path.
        let (nodes_tx, nodes_rx) = oneshot::channel();
        cmd_tx
            .send(Command::ListNodes { reply: nodes_tx })
            .await
            .unwrap();
        let nodes = nodes_rx.await.unwrap();
        assert_eq!(nodes.len(), 1, "the device entry must have been pushed");
        assert_eq!(
            nodes[0].label,
            Some("plug".to_string()),
            "the caller-supplied label must be persisted on the device entry"
        );

        // Task 5 — `SetNodeVidPid` (the controller's post-commission
        // BasicInformation-capture persist) updates the same entry's vid/pid,
        // durably, and `ListNodes` reflects it.
        let (set_tx, set_rx) = oneshot::channel();
        cmd_tx
            .send(Command::SetNodeVidPid {
                node_id: 2,
                vendor_id: Some(0xFFF1),
                product_id: Some(0x8000),
                reply: set_tx,
            })
            .await
            .unwrap();
        set_rx.await.unwrap().expect("SetNodeVidPid persist");
        let (nodes2_tx, nodes2_rx) = oneshot::channel();
        cmd_tx
            .send(Command::ListNodes { reply: nodes2_tx })
            .await
            .unwrap();
        let nodes2 = nodes2_rx.await.unwrap();
        assert_eq!(
            (nodes2[0].vendor_id, nodes2[0].product_id),
            (Some(0xFFF1), Some(0x8000)),
            "SetNodeVidPid must persist vid/pid onto the device entry"
        );
        assert_eq!(
            nodes2[0].label,
            Some("plug".to_string()),
            "SetNodeVidPid must not disturb the existing label"
        );
        // An unknown node id is a no-op success (not an error).
        let (miss_tx, miss_rx) = oneshot::channel();
        cmd_tx
            .send(Command::SetNodeVidPid {
                node_id: 0xDEAD,
                vendor_id: Some(1),
                product_id: Some(2),
                reply: miss_tx,
            })
            .await
            .unwrap();
        miss_rx
            .await
            .unwrap()
            .expect("SetNodeVidPid for an unknown node is a no-op success");

        drop(cmd_tx);
        let _ = loop_handle.await;
    }

    /// Decoupled connect/commission handling, part 2 — dispatching
    /// `Command::Commission` hands off without the loop `.await`ing the
    /// commission. With no attestation trust
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
                label: None,
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

    #[cfg(feature = "ota")]
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

    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
    #[cfg(feature = "ota")]
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
            .set_time_zone(&[crate::TimeZoneEntry::new(3600, 0, Some("CET".into()))])
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
            .set_dst_offset(&[crate::DstOffsetEntry::new(3600, 0, None)])
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
        keep_endpoint_open(io);
    }

    /// Does this `WriteRequestMessage` carry `MoreChunkedMessages` (ctx tag 3) =
    /// true? Mirrors `matter_interaction::write`'s `more_chunked_flag` test helper:
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
    /// receives `expected_chunks` `WriteRequest`s (opcode 0x06) on ONE
    /// exchange, asserting `MoreChunkedMessages=true` on all but the last
    /// (the last carries an explicit `false`; decoded from each request, not
    /// just counted). Chip-faithful AND
    /// strict: replies to EVERY chunk with `write_response` (opcode 0x07) on
    /// the same exchange — chip's `WriteHandler` sends one `WriteResponse`
    /// per received `WriteRequest`, and `WriteClient` gates the next chunk on
    /// it (Matter §8.7.4 / §10.6) — and PANICS if a second `WriteRequest`
    /// arrives before this device has sent the response to the previous one
    /// (the pipelining detector this mock exists to catch).
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
                payload,
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
            // Decode MoreChunkedMessages from the request itself (not just
            // the loop index) and cross-check it against `expected_chunks`.
            let more = write_request_has_more_chunked(&payload);
            assert_eq!(
                more,
                i + 1 != expected_chunks,
                "chunk {i} MoreChunkedMessages flag disagrees with expected_chunks"
            );

            // STRICT pipelining detector: a client that correctly gates each
            // chunk on the previous chunk's WriteResponse cannot have sent
            // chunk i+1 yet — doing so requires first receiving OUR response
            // to chunk i, which we have not sent. If another datagram is
            // already sitting in the queue, the client pipelined ahead of
            // the gate. `yield_now` gives already-enqueued work exactly one
            // chance to surface; it introduces no wall-clock race because a
            // correctly-gated next chunk cannot exist yet at all.
            tokio::select! {
                biased;
                extra = io.recv_from() => {
                    let len = extra.map_or(0, |(b, _)| b.len());
                    panic!(
                        "chunked-write pipelining detected: a WriteRequest for chunk {} \
                         ({len} bytes) arrived before the device replied to chunk {i} — \
                         the client must gate each chunk on its WriteResponse",
                        i + 1
                    );
                }
                () = tokio::task::yield_now() => {}
            }

            // Chip-faithful: reply to EVERY chunk with a WriteResponse on the
            // same exchange (chip's WriteHandler sends one per WriteRequest;
            // WriteClient sends the next chunk only after receiving this).
            // `reliable: true` (a real device's WriteResponse is a reliable
            // MRP message) so the client's NEXT chunk on this exchange must
            // piggyback an ack for it — exercises that piggyback-ack path,
            // not just unreliable sends.
            let out = sessions
                .encode_outbound(
                    sid,
                    Some(exchange_id),
                    0x07, // WriteResponse
                    ProtocolId::INTERACTION_MODEL,
                    &write_response,
                    MrpFlags { reliable: true },
                    Instant::now(),
                )
                .unwrap();
            io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        }
        keep_endpoint_open(io);
    }

    /// The chunked-write primitive sends N `WriteRequest`s on ONE exchange (all
    /// but the last carrying `MoreChunkedMessages`), gated one chunk at a time
    /// on the device's per-chunk `WriteResponse(Success)` (chip parity — see
    /// `run_chunked_write_device`'s strict pipelining detector); `chunked_write`
    /// parses EVERY chunk's `WriteResponse` and accumulates its statuses, so
    /// the result has one status entry per chunk (all Success here, since the
    /// mock replies with the same single-status `WriteResponse` to every
    /// chunk).
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

        let statuses = controller
            .node(device_node_id)
            .chunked_write(chunks)
            .await
            .expect("chunked_write");

        // One accumulated status per chunk (chip-faithful: every chunk's
        // WriteResponse is parsed and appended, not just the final one).
        assert_eq!(statuses.len(), n_chunks);
        for (path, status) in &statuses {
            assert_eq!(*status, matter_interaction::ImStatus::Success);
            assert_eq!(path.cluster, 0x001F);
        }

        device.await.unwrap();
    }

    /// Loopback device for the "pump despite a bad element status" case.
    /// Completes CASE, then receives ALL `expected_chunks` `WriteRequest`s
    /// (opcode 0x06) on ONE exchange — same shape as `run_chunked_write_device`
    /// (strict pipelining detector, decoded `MoreChunkedMessages` cross-check
    /// against the loop index) — but replies to chunk 0 with `first_response`
    /// (a `WriteResponse` carrying a non-Success element status) and to every
    /// later chunk with `rest_response` (`Success`). Chip's `WriteClient` does
    /// NOT abort on a bad element status (`WriteClient.cpp:583-593`: it only
    /// forwards statuses to its callback and unconditionally sends the next
    /// chunk), so a correctly-implemented client sends every chunk regardless
    /// — this mock's `for` loop actually receiving all `expected_chunks` IS
    /// the assertion that the client kept pumping.
    #[allow(clippy::too_many_lines)] // CASE-handshake boilerplate, as the sibling mocks.
    #[allow(clippy::too_many_arguments)] // Test-only mock; mirrors the sibling mocks' shape.
    async fn run_chunked_write_device_pumps_all_despite_failure(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        expected_chunks: usize,
        first_response: Vec<u8>,
        rest_response: Vec<u8>,
    ) {
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();

        // --- CASE handshake (identical to run_chunked_write_device) ---
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

        let mut exchange_seen: Option<u16> = None;
        for i in 0..expected_chunks {
            let (w, _) = io.recv_from().await.unwrap();
            let DecodeInboundOutput::AppMessage {
                exchange_id,
                opcode,
                payload,
                ..
            } = sessions.decode_inbound(&w, Instant::now()).unwrap()
            else {
                panic!("expected a WriteRequest app message for chunk {i}");
            };
            assert_eq!(opcode, 0x06, "chunk {i} must be a WriteRequest (0x06)");
            match exchange_seen {
                None => exchange_seen = Some(exchange_id),
                Some(ex) => assert_eq!(
                    ex, exchange_id,
                    "every chunk must reuse the same exchange (one-exchange invariant)"
                ),
            }
            let more = write_request_has_more_chunked(&payload);
            assert_eq!(
                more,
                i + 1 != expected_chunks,
                "chunk {i} MoreChunkedMessages flag disagrees with expected_chunks"
            );

            // Same strict pipelining detector as run_chunked_write_device:
            // pumping unconditionally still means ONE chunk in flight at a
            // time, gated on the previous chunk's WriteResponse — a bad
            // element status changes what the client does with THIS
            // response's statuses, not whether it waits for the response.
            tokio::select! {
                biased;
                extra = io.recv_from() => {
                    let len = extra.map_or(0, |(b, _)| b.len());
                    panic!(
                        "chunked-write pipelining detected: a WriteRequest for chunk {} \
                         ({len} bytes) arrived before the device replied to chunk {i}",
                        i + 1
                    );
                }
                () = tokio::task::yield_now() => {}
            }

            let response = if i == 0 {
                &first_response
            } else {
                &rest_response
            };
            let out = sessions
                .encode_outbound(
                    sid,
                    Some(exchange_id),
                    0x07, // WriteResponse
                    ProtocolId::INTERACTION_MODEL,
                    response,
                    MrpFlags { reliable: false },
                    Instant::now(),
                )
                .unwrap();
            io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        }
        keep_endpoint_open(io);
    }

    /// chip does NOT abort a chunked write on a non-Success element status:
    /// the device rejects chunk 0's write (a `FAILURE` element status) but
    /// `chunked_write` keeps pumping every remaining chunk regardless (mock
    /// receives ALL of them — see
    /// `run_chunked_write_device_pumps_all_despite_failure`'s doc), and the
    /// caller gets back the FULL accumulated status list, including the
    /// chunk-0 failure.
    #[tokio::test]
    async fn chunked_write_pumps_all_chunks_despite_non_success_element_status() {
        use matter_codec::{Tag, TlvWriter};

        // Helper: a WriteResponse with one AttributeStatusIB carrying `status`.
        fn write_response_with_status(
            path: matter_interaction::AttributePath,
            status: u8,
        ) -> Vec<u8> {
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
            w.put_uint(Tag::Context(0), u64::from(status)).unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap(); // /AttributeStatusIB
            w.end_container().unwrap(); // /WriteResponses
            w.put_uint(Tag::Context(0xFF), 11).unwrap();
            w.end_container().unwrap();
            buf
        }

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

        let path = matter_interaction::AttributePath {
            endpoint: 1,
            cluster: 0x001F,
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
        let chunks = matter_interaction::build_list_write_chunks(path, &elems, 40, false);
        assert!(
            chunks.len() >= 2,
            "test needs a multi-chunk write; got {} chunk(s)",
            chunks.len()
        );
        let n_chunks = chunks.len();

        let first_response = write_response_with_status(path, 0x01); // FAILURE
        let rest_response = write_response_with_status(path, 0x00); // SUCCESS

        let device = tokio::spawn(run_chunked_write_device_pumps_all_despite_failure(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00DD,
            n_chunks,
            first_response,
            rest_response,
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
            .chunked_write(chunks)
            .await
            .expect("chunked_write must still resolve Ok — a bad element status is not terminal");

        // One accumulated status per chunk; chunk 0's is the FAILURE, every
        // later one is SUCCESS (mock proved the client sent them all, or the
        // spawned device task above would still be blocked in recv_from and
        // this .await would time out instead of returning).
        assert_eq!(statuses.len(), n_chunks);
        assert_eq!(statuses[0].1, matter_interaction::ImStatus::Failure(0x01));
        for status in &statuses[1..] {
            assert_eq!(status.1, matter_interaction::ImStatus::Success);
        }

        device.await.unwrap();
    }

    /// Loopback device for the chunked-write TERMINAL-REJECTION path.
    /// Completes CASE, then receives the FIRST `WriteRequest` chunk (asserting
    /// `MoreChunkedMessages` is set — the test needs ≥2 chunks) and replies
    /// with a message-level `StatusResponse(status)` (opcode 0x01) INSTEAD OF
    /// a `WriteResponse` — chip's `WriteHandler` rejects a chunk outright this
    /// way (e.g. Busy 0x9C) via `StatusResponse::Send` then `Close`, not via a
    /// `WriteResponse` with a per-path status. It then reads with a short
    /// grace timeout and PANICS if anything further arrives — a
    /// correctly-implemented client must treat this as terminal (the
    /// transaction the device already closed) rather than pump the remaining
    /// chunks into it.
    async fn run_chunked_write_device_rejects_with_status(
        io: InMemoryDatagram,
        ctrl_addr: std::net::SocketAddr,
        creds: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        status: u8,
    ) {
        let mut responder = CaseResponder::new(
            creds,
            roots,
            responder_session_id,
            MatterTime::from_unix_secs(2_000_000_000),
        )
        .unwrap();

        // --- CASE handshake (identical to run_chunked_write_device) ---
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

        // --- Reject chunk 0 with a message-level StatusResponse ---
        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);

        let (w, _) = io.recv_from().await.unwrap();
        let DecodeInboundOutput::AppMessage {
            exchange_id,
            opcode,
            payload,
            ..
        } = sessions.decode_inbound(&w, Instant::now()).unwrap()
        else {
            panic!("expected a WriteRequest app message for chunk 0");
        };
        assert_eq!(opcode, 0x06, "chunk 0 must be a WriteRequest (0x06)");
        assert!(
            write_request_has_more_chunked(&payload),
            "chunk 0 must carry MoreChunkedMessages (test needs a multi-chunk write)"
        );
        let status_bytes = matter_interaction::build_status_response(status);
        let out = sessions
            .encode_outbound(
                sid,
                Some(exchange_id),
                0x01, // StatusResponse — NOT a WriteResponse
                ProtocolId::INTERACTION_MODEL,
                &status_bytes,
                MrpFlags { reliable: false },
                Instant::now(),
            )
            .unwrap();
        io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();

        // Grace read: a correctly-implemented client sends nothing further
        // after the device closes the transaction with a rejection.
        let grace =
            tokio::time::timeout(std::time::Duration::from_millis(200), io.recv_from()).await;
        assert!(
            grace.is_err(),
            "client sent a further chunk after the device rejected the chunked write"
        );
        keep_endpoint_open(io);
    }

    /// Terminal path: the device rejects chunk 0 outright with
    /// `StatusResponse(0x9C Busy)` instead of a `WriteResponse` (chip's
    /// `WriteHandler` closing the transaction). `chunked_write` resolves
    /// `Err` naming the status (0x9c), and sends NO further chunks (verified
    /// by `run_chunked_write_device_rejects_with_status`'s grace-read
    /// assertion) — pumping a chunk into a transaction the device already
    /// closed would just hang until the device's own response timeout.
    #[tokio::test]
    async fn chunked_write_terminal_on_status_response_rejection() {
        use matter_codec::{Tag, TlvWriter};

        const BUSY: u8 = 0x9C;

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

        let path = matter_interaction::AttributePath {
            endpoint: 1,
            cluster: 0x001F,
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
        let chunks = matter_interaction::build_list_write_chunks(path, &elems, 40, false);
        assert!(
            chunks.len() >= 2,
            "test needs a multi-chunk write; got {} chunk(s)",
            chunks.len()
        );

        let device = tokio::spawn(run_chunked_write_device_rejects_with_status(
            dev_io,
            ctrl_addr,
            device_creds,
            device_roots,
            0x00DE,
            BUSY,
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
            .chunked_write(chunks)
            .await
            .expect_err("a StatusResponse rejection must be an Err, not Ok(vec![])");

        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("0x9c"),
            "error must name the IM status (0x9c); got: {msg}"
        );

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
    /// `MoreChunkedMessages=true` on all but the last — explicit `false` on the
    /// last (courtesy of `run_chunked_write_device`), then replies
    /// `WriteResponse(Success)`.
    ///
    /// Note: `write_acl` hardcodes budget=800 which won't force multi-chunk in a
    /// unit test (that would need ~100 large ACL entries). We therefore test the
    /// multi-chunk path via `chunked_write` directly, using the same tiny budget
    /// as `chunked_write_sends_all_chunks_one_exchange`. This is
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

        let statuses = controller
            .node(device_node_id)
            .chunked_write(chunks)
            .await
            .expect("chunked_write must succeed");

        // One accumulated status per chunk (every chunk's WriteResponse is
        // parsed and appended); the mock replies with the same single-status
        // WriteResponse to every chunk, so all `n_chunks` entries are Success.
        assert_eq!(statuses.len(), n_chunks);
        for (_, status) in &statuses {
            assert_eq!(*status, matter_interaction::ImStatus::Success);
        }

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

        // One accumulated status per chunk (every chunk's WriteResponse is
        // parsed and appended); the mock replies with the same single-status
        // WriteResponse to every chunk.
        assert_eq!(statuses.len(), expected_chunks);
        for (path, status) in &statuses {
            assert_eq!(*status, matter_interaction::ImStatus::Success);
            assert_eq!(path.cluster, crate::acl::ACCESS_CONTROL_CLUSTER);
            assert_eq!(path.attribute, crate::acl::ATTR_ACL);
        }

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
