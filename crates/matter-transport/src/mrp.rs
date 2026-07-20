//! Matter Message Reliability Protocol (MRP) — Matter Core Spec §4.11.
//!
//! Per-session, sans-IO state machine that owns pending retransmits,
//! piggyback ack queues, exchange tracking, and a recent-reliable
//! dedup-resend cache. Never touches crypto. Never builds wire bytes for
//! standalone acks (`SessionManager` does that via
//! [`crate::protocol_header::build_standalone_ack_header`] +
//! [`crate::framing::encode_secured`]).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::framing::{MessageCounter, SessionId};
use crate::protocol_header::{encode_protocol_header, ExchangeFlags, ProtocolHeader, ProtocolId};

/// Upper bound on the number of live exchanges tracked per session.
///
/// `exchange_id` is a peer-controlled 16-bit field, so without a bound a
/// long-lived session could accumulate one `ExchangeState` per distinct id
/// (up to 65 536) and never reclaim them — a slow memory-exhaustion denial
/// of service. An
/// exchange is reclaimed automatically once it goes idle (no pending
/// retransmit and no buffered outbound ack), so this cap only ever bites a
/// peer that holds an abnormal number of exchanges open simultaneously.
///
/// 256 sits far above any realistic concurrent-exchange count for a
/// controller (a handful of in-flight reads/subscriptions per session) while
/// still tightly bounding worst-case memory. The C++ reference
/// (`connectedhomeip`) likewise services exchanges from a small fixed pool.
pub const MAX_EXCHANGES_PER_SESSION: usize = 256;

/// Configuration knobs for MRP retransmit + ack timing. Defaults match
/// Matter Core Spec §4.11.8 (jitter omitted; see the M5.2 design's
/// "Non-goals" section).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct MrpConfig {
    /// Base retransmit delay used when the session is "active" (recent
    /// outbound traffic).
    pub initial_active: Duration,
    /// Base retransmit delay used when the session has been idle longer
    /// than `idle_threshold`.
    pub initial_idle: Duration,
    /// Multiplicative growth factor applied per retransmit attempt.
    pub backoff_factor: f32,
    /// Maximum number of retransmit attempts before the message is
    /// declared expired.
    pub max_attempts: u8,
    /// Maximum time a piggyback opportunity is buffered before a
    /// standalone-ack must be emitted (Matter Core Spec §4.11.5).
    pub standalone_ack_deadline: Duration,
    /// Gap-since-`last_outbound` above which the next outbound uses the
    /// idle base instead of the active base.
    pub idle_threshold: Duration,
}

impl Default for MrpConfig {
    fn default() -> Self {
        Self {
            initial_active: Duration::from_millis(300),
            initial_idle: Duration::from_millis(4200),
            backoff_factor: 1.6,
            max_attempts: 5,
            standalone_ack_deadline: Duration::from_millis(200),
            idle_threshold: Duration::from_secs(5),
        }
    }
}

/// Matter spec-default MRP parameters used for a peer that advertises no value
/// for a given key (chip `ReliableMessageProtocolConfig` non-Linux defaults):
/// SII (idle) = 500 ms, SAI (active) = 300 ms, SAT (active threshold) = 4000 ms.
const SPEC_DEFAULT_IDLE: Duration = Duration::from_millis(500);
const SPEC_DEFAULT_ACTIVE: Duration = Duration::from_millis(300);
const SPEC_DEFAULT_ACTIVE_THRESHOLD: Duration = Duration::from_secs(4);
/// Spec upper bounds: SII/SAI are 3-byte-ish intervals (Matter caps them at
/// 3600000 ms = 1 h); SAT is a `uint16` ms (≤ 65535 ms). A peer advertising an
/// out-of-range value is clamped rather than trusted or rejected.
const MAX_RETRANS_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_ACTIVE_THRESHOLD: Duration = Duration::from_millis(65_535);

impl MrpConfig {
    /// Build a per-session config from a peer's advertised MRP parameters
    /// (mDNS TXT `SII`/`SAI`/`SAT`, Matter Core Spec §4.3.1.8). Any field the
    /// peer omits falls back to the spec default; each supplied value is clamped
    /// to its spec upper bound. Retransmit shape (`backoff_factor`,
    /// `max_attempts`) and the local `standalone_ack_deadline` are NOT
    /// peer-controlled and keep their [`Default`] values.
    ///
    /// - `sii` → `initial_idle` (Session Idle Interval)
    /// - `sai` → `initial_active` (Session Active Interval)
    /// - `sat` → `idle_threshold` (Session Active Threshold)
    #[must_use]
    pub fn for_peer(sii: Option<Duration>, sai: Option<Duration>, sat: Option<Duration>) -> Self {
        let base = Self::default();
        Self {
            initial_idle: sii.unwrap_or(SPEC_DEFAULT_IDLE).min(MAX_RETRANS_INTERVAL),
            initial_active: sai.unwrap_or(SPEC_DEFAULT_ACTIVE).min(MAX_RETRANS_INTERVAL),
            idle_threshold: sat
                .unwrap_or(SPEC_DEFAULT_ACTIVE_THRESHOLD)
                .min(MAX_ACTIVE_THRESHOLD),
            ..base
        }
    }
}

/// Caller-facing MRP control bits for an outbound message.
#[derive(Debug, Clone, Copy, Default)]
pub struct MrpFlags {
    /// If true, the message requires an MRP acknowledgement and will be
    /// retransmitted on timeout.
    pub reliable: bool,
}

/// Per-session timer event before `SessionManager` folds it into
/// [`MrpEvent`] with the `session_id` attached.
#[derive(Debug)]
#[non_exhaustive]
pub enum MrpTimerEvent {
    /// A pending reliable message hit its retransmit deadline. The cached
    /// encrypted wire bytes are returned so the manager can re-send them
    /// unchanged.
    Retransmit {
        /// Exchange the message belongs to.
        exchange_id: u16,
        /// Counter of the original message being re-sent.
        counter: MessageCounter,
        /// Encrypted wire bytes previously recorded via
        /// [`MrpState::mark_packet_sent`].
        packet: Vec<u8>,
    },
    /// A buffered piggyback ack overflowed its 200ms deadline; the
    /// manager must emit a standalone-ack.
    StandaloneAckDeadlineFired {
        /// Exchange the ack relates to.
        exchange_id: u16,
        /// Peer counter being acknowledged.
        ack_counter: MessageCounter,
        /// Whether the local side originated the exchange (drives the
        /// `I` flag on the standalone-ack).
        is_local_initiator: bool,
    },
    /// A reliable message exhausted its retransmit budget. The exchange
    /// should be torn down by the caller.
    Expired {
        /// Exchange the expired message belongs to.
        exchange_id: u16,
        /// Counter of the expired message.
        counter: MessageCounter,
    },
}

/// Logical work emitted by `SessionManager::handle_timeout`. The
/// `session_id` field disambiguates events across the manager's
/// per-session timer streams. `SessionManager` pre-builds standalone-ack
/// packets before pushing `SendStandaloneAck` here.
#[derive(Debug)]
#[non_exhaustive]
pub enum MrpEvent {
    /// A pending reliable message must be re-sent.
    Retransmit {
        /// Session the packet belongs to.
        session_id: SessionId,
        /// Exchange identifier.
        exchange_id: u16,
        /// Counter of the original message being re-sent.
        counter: MessageCounter,
        /// Encrypted wire bytes to re-transmit unchanged.
        packet: Vec<u8>,
    },
    /// A standalone-ack must be sent; `packet` is the fully-encrypted
    /// wire bytes built by the manager.
    SendStandaloneAck {
        /// Session the packet belongs to.
        session_id: SessionId,
        /// Exchange identifier.
        exchange_id: u16,
        /// Encrypted wire bytes ready to send.
        packet: Vec<u8>,
    },
    /// A reliable message exhausted its retransmit budget.
    Expired {
        /// Session the message belonged to.
        session_id: SessionId,
        /// Exchange identifier.
        exchange_id: u16,
        /// Counter of the expired message.
        counter: MessageCounter,
    },
    /// A standalone-ack was due (the peer's reliable message must be
    /// acknowledged) but could not be built because the session's outbound
    /// message counter is exhausted (`u32::MAX`). Per Matter Core Spec
    /// §4.4.3 a counter cannot wrap; the session must be re-keyed (a new
    /// CASE handshake) before any further traffic — including this ack —
    /// can be sent. Surfaced (rather than silently dropped) so the caller
    /// can tear the session down promptly instead of leaving the peer
    /// un-acked with no signal. The unacked peer counter is included so the
    /// caller can log/trace which message went un-acknowledged.
    SessionCounterExhausted {
        /// Session whose outbound counter is exhausted.
        session_id: SessionId,
        /// Exchange the un-acked peer message belongs to.
        exchange_id: u16,
        /// Peer counter that could not be acknowledged.
        ack_counter: MessageCounter,
    },
}

/// Outcome of processing an inbound decrypted payload through MRP.
#[derive(Debug)]
#[non_exhaustive]
pub enum InboundOutcome {
    /// A new application message was received. `payload` is the bytes
    /// AFTER the protocol header.
    AppMessage {
        /// Exchange the message belongs to.
        exchange_id: u16,
        /// Whether the peer is the initiator (i.e. we are the responder).
        is_initiator: bool,
        /// Protocol id from the decoded protocol header.
        protocol_id: ProtocolId,
        /// Protocol opcode from the decoded protocol header.
        opcode: u8,
        /// Decrypted application payload (post-header).
        payload: Vec<u8>,
    },
    /// The inbound message was an ack-only standalone (no app payload).
    AckOnly {
        /// Exchange identifier.
        exchange_id: u16,
        /// Counter that was acknowledged.
        acked_counter: MessageCounter,
    },
    /// The inbound message duplicates a recently-seen reliable message
    /// from the peer.
    DuplicateReliable {
        /// Exchange identifier.
        exchange_id: u16,
        /// Counter that the peer re-sent.
        peer_counter: MessageCounter,
        /// Whether the local side originated the exchange.
        is_local_initiator: bool,
    },
}

/// Output of [`MrpState::prepare_outbound`]: the encoded wire payload
/// (protocol header || application bytes) plus exchange bookkeeping.
pub struct PreparedOutbound {
    /// Encoded protocol header concatenated with the caller's
    /// application payload. The session-manager passes this verbatim to
    /// [`crate::framing::encode_secured`].
    pub wire_payload: Vec<u8>,
    /// Exchange identifier carried in the protocol header.
    pub exchange_id: u16,
    /// Whether the local side initiated the exchange (mirrors the `I`
    /// flag).
    pub is_local_initiator: bool,
    /// Whether a pending peer counter was piggybacked into this message
    /// (Task 5).
    pub piggyback_acked: bool,
}

/// Snapshot view returned by [`MrpState::check_duplicate_reliable`].
pub struct RecentInboundView {
    /// Exchange the recently-cached reliable message belonged to.
    pub exchange_id: u16,
    /// Whether the local side originated that exchange.
    pub is_local_initiator: bool,
}

/// Pending retransmit entry for one outbound reliable message.
#[derive(Debug)]
struct PendingAck {
    packet_bytes: Vec<u8>,
    exchange_id: u16,
    next_attempt: Instant,
    attempts_remaining: u8,
}

/// Buffered piggyback-ack for one exchange. Held in a per-exchange map
/// (keyed by `exchange_id`) so concurrent reliable inbounds on different
/// exchanges never clobber each other's buffered ack. Each entry is either
/// drained by the next outbound in the same exchange (cheap) or flushed as
/// a standalone-ack when the 200ms deadline expires (fallback).
#[derive(Debug)]
struct PendingOutboundAck {
    ack_counter: MessageCounter,
    is_local_initiator: bool,
    deadline: Instant,
}

/// Cache entry for a recently-seen reliable inbound, kept in a 32-slot
/// ring buffer for duplicate-reliable detection (Matter Core Spec §4.11.6
/// dedup-resend path; M5.2 design Q5).
#[derive(Debug)]
struct RecentInbound {
    exchange_id: u16,
    counter: MessageCounter,
    is_local_initiator: bool,
}

/// Per-exchange state tracked across `prepare_outbound` /
/// `process_inbound` calls. Currently only carries `is_local_initiator`,
/// which determines the `I` flag for subsequent messages we send in this
/// exchange.
#[derive(Debug)]
struct ExchangeState {
    is_local_initiator: bool,
}

/// Per-session MRP state.
#[derive(Debug)]
pub struct MrpState {
    pending_acks: HashMap<MessageCounter, PendingAck>,
    pending_outbound_acks: HashMap<u16, PendingOutboundAck>,
    recent_reliable: [Option<RecentInbound>; 32],
    recent_next_slot: usize,
    exchanges: HashMap<u16, ExchangeState>,
    next_exchange_id: u16,
    last_outbound: Option<Instant>,
    /// Wall-clock of the most recent message RECEIVED from the peer, used to
    /// classify the peer as "active" (within `config.idle_threshold` = the
    /// Session Active Threshold, SAT) vs idle. The retransmit base interval is
    /// selected off THIS, not our own outbound timing — chip
    /// `SecureSession::IsPeerActive` / `GetMRPBaseTimeout` (MRP-1). `None` until
    /// the first inbound: a peer we have never heard from is treated as idle,
    /// so we never hammer a sleepy device with active-interval spacing.
    last_peer_activity: Option<Instant>,
    config: MrpConfig,
}

impl MrpState {
    /// Create a fresh state with the given config.
    #[must_use]
    pub fn new(config: MrpConfig) -> Self {
        Self {
            pending_acks: HashMap::new(),
            pending_outbound_acks: HashMap::new(),
            recent_reliable: std::array::from_fn(|_| None),
            recent_next_slot: 0,
            exchanges: HashMap::new(),
            next_exchange_id: 1,
            last_outbound: None,
            last_peer_activity: None,
            config,
        }
    }

    /// Whether the peer is currently "active" — it has sent us a message within
    /// the Session Active Threshold (`config.idle_threshold`, SAT). Drives the
    /// retransmit base interval (active → `initial_active`/SAI, idle →
    /// `initial_idle`/SII), re-evaluated on every retransmit exactly as chip's
    /// `GetMRPBaseTimeout` does. A peer we have never heard from (`None`) is
    /// idle: sizing the FIRST retransmit on the slower idle interval is the safe
    /// direction (it never over-drives a sleepy device).
    fn is_peer_active(&self, now: Instant) -> bool {
        match self.last_peer_activity {
            Some(t) => now.saturating_duration_since(t) < self.config.idle_threshold,
            None => false,
        }
    }

    /// Build an outbound wire payload (encoded protocol header concatenated
    /// with `app_payload`). Allocates a new exchange ID if `exchange_id` is
    /// `None` (we initiate) and inserts a fresh `ExchangeState` with
    /// `is_local_initiator = true`. For `Some(id)`, looks up the exchange
    /// table to determine `is_local_initiator`; if the exchange is not yet
    /// recorded (caller is using an arbitrary peer-assigned ID without a
    /// prior inbound), inserts a default record with `is_local_initiator =
    /// false` (we assume responding).
    ///
    /// When this exchange's buffered piggyback ack is drained, the outgoing
    /// header carries `A=1` and `ack_counter = pending.ack_counter`. The drain path's
    /// `is_local_initiator` is guaranteed to agree with the exchange-table
    /// lookup because both were populated from the same
    /// `!peer_is_initiator` computation during `process_inbound`.
    ///
    /// # Errors
    ///
    /// Currently infallible in practice — returns `Result` for forward
    /// compatibility with future exchange-table validation.
    pub fn prepare_outbound(
        &mut self,
        opcode: u8,
        protocol_id: ProtocolId,
        exchange_id: Option<u16>,
        app_payload: &[u8],
        mrp_flags: MrpFlags,
        _now: Instant,
    ) -> Result<PreparedOutbound> {
        // Resolve exchange_id + is_local_initiator via the exchange table.
        let (exchange_id, is_local_initiator) = match exchange_id {
            None => {
                let id = self.allocate_exchange_id();
                self.exchanges.insert(
                    id,
                    ExchangeState {
                        is_local_initiator: true,
                    },
                );
                (id, true)
            }
            Some(id) => {
                if let Some(state) = self.exchanges.get(&id) {
                    (id, state.is_local_initiator)
                } else {
                    // No record yet for this caller-provided id. Assume we
                    // are responding (safe default: I=0).
                    self.exchanges.insert(
                        id,
                        ExchangeState {
                            is_local_initiator: false,
                        },
                    );
                    (id, false)
                }
            }
        };

        // Drain the buffered piggyback for THIS exchange, if any. Other
        // exchanges' buffered acks are untouched.
        let (ack_flag, ack_counter, piggyback_acked) =
            if let Some(p) = self.pending_outbound_acks.remove(&exchange_id) {
                (ExchangeFlags::ACK, Some(p.ack_counter), true)
            } else {
                (ExchangeFlags::empty(), None, false)
            };

        let mut flags = ack_flag;
        if is_local_initiator {
            flags |= ExchangeFlags::INITIATOR;
        }
        if mrp_flags.reliable {
            flags |= ExchangeFlags::RELIABLE;
        }
        let header = ProtocolHeader {
            exchange_flags: flags,
            opcode,
            exchange_id,
            protocol_id,
            ack_counter,
        };
        let mut wire_payload = Vec::with_capacity(app_payload.len() + 16);
        encode_protocol_header(&header, &mut wire_payload);
        wire_payload.extend_from_slice(app_payload);

        Ok(PreparedOutbound {
            wire_payload,
            exchange_id,
            is_local_initiator,
            piggyback_acked,
        })
    }

    fn allocate_exchange_id(&mut self) -> u16 {
        let id = self.next_exchange_id;
        self.next_exchange_id = self.next_exchange_id.wrapping_add(1);
        if self.next_exchange_id == 0 {
            self.next_exchange_id = 1;
        }
        id
    }

    /// Register the encrypted wire bytes of a just-sent message. Caller
    /// passes `reliable` to indicate whether MRP should track this message
    /// for retransmit. Unreliable messages still update `last_outbound` so
    /// idle-vs-active classification remains accurate.
    ///
    /// The first retransmit deadline uses the active base (`initial_active`,
    /// SAI) when the PEER is active — it has sent us something within SAT
    /// (`is_peer_active`) — and the idle base (`initial_idle`, SII) otherwise.
    /// Selection is off the peer's activity, NOT our own outbound timing
    /// (MRP-1); subsequent retransmits re-evaluate it in `handle_timeout`.
    pub fn mark_packet_sent(
        &mut self,
        counter: MessageCounter,
        exchange_id: u16,
        packet_bytes: Vec<u8>,
        reliable: bool,
        now: Instant,
    ) {
        // `last_outbound` is retained for callers/telemetry; it no longer drives
        // the active/idle classification (that is peer-activity based now).
        self.last_outbound = Some(now);

        if !reliable {
            return;
        }

        let initial = if self.is_peer_active(now) {
            self.config.initial_active
        } else {
            self.config.initial_idle
        };
        self.pending_acks.insert(
            counter,
            PendingAck {
                packet_bytes,
                exchange_id,
                next_attempt: now + initial,
                attempts_remaining: self.config.max_attempts,
            },
        );
    }

    /// Earliest pending deadline across retransmits and the
    /// piggyback-ack flush deadline, or `None` if nothing pending.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let retransmit = self.pending_acks.values().map(|p| p.next_attempt).min();
        let standalone = self
            .pending_outbound_acks
            .values()
            .map(|p| p.deadline)
            .min();
        match (retransmit, standalone) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    /// Advance retransmit timers. For each pending whose `next_attempt`
    /// has elapsed, emit a `Retransmit` event and schedule the next
    /// attempt (exponential backoff). If `attempts_remaining` reaches 0,
    /// emit `Expired` and drop the entry.
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<MrpTimerEvent> {
        let mut events = Vec::new();
        let mut to_remove = Vec::new();
        // Exchanges whose live work cleared this tick (an expired retransmit
        // or a drained buffered ack); each is reclaimed if it ends up idle.
        let mut reclaim_candidates: Vec<u16> = Vec::new();

        // Re-evaluate the peer's active/idle state ONCE for this tick, exactly
        // as chip re-evaluates `IsPeerActive` on every retransmit scheduling:
        // a peer that has gone silent past SAT since the message was queued
        // switches to the slower idle base for its remaining retransmits (MRP-1;
        // the CASE-Sigma3-to-a-sleepy-device failure mode). `last_peer_activity`
        // does not change during this loop, so one read is exact.
        let peer_active = self.is_peer_active(now);

        for (counter, pending) in &mut self.pending_acks {
            if pending.next_attempt > now {
                continue;
            }
            if pending.attempts_remaining == 0 {
                events.push(MrpTimerEvent::Expired {
                    exchange_id: pending.exchange_id,
                    counter: *counter,
                });
                to_remove.push(*counter);
                reclaim_candidates.push(pending.exchange_id);
                continue;
            }
            events.push(MrpTimerEvent::Retransmit {
                exchange_id: pending.exchange_id,
                counter: *counter,
                packet: pending.packet_bytes.clone(),
            });
            pending.attempts_remaining -= 1;
            let base = if peer_active {
                self.config.initial_active
            } else {
                self.config.initial_idle
            };
            let attempts_done = self.config.max_attempts - pending.attempts_remaining;
            // Backoff math: base_ms × factor^attempts_done. The truncation to
            // u64 is intentional — fractional milliseconds are not part of
            // the spec's deadline grid (Matter Core Spec §4.11.8). Inputs are
            // bounded (base ≤ 4200 ms, factor ≈ 1.6, attempts ≤ 5) so the
            // f32 product stays well below 2^31 and is non-negative.
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss
            )]
            let scaled_ms = (base.as_secs_f32()
                * 1000.0
                * self.config.backoff_factor.powi(i32::from(attempts_done)))
                as u64;
            pending.next_attempt = now + Duration::from_millis(scaled_ms);
        }
        for c in to_remove {
            self.pending_acks.remove(&c);
        }

        // Standalone-ack deadline: flush every buffered piggyback whose
        // deadline has passed before the next outbound in its exchange,
        // emitting one standalone-ack per due exchange.
        let mut due_exchanges: Vec<u16> = self
            .pending_outbound_acks
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        // Deterministic emission order — HashMap iteration order is
        // unspecified; sorting keeps event ordering stable for callers/tests.
        due_exchanges.sort_unstable();
        for exchange_id in due_exchanges {
            if let Some(p) = self.pending_outbound_acks.remove(&exchange_id) {
                events.push(MrpTimerEvent::StandaloneAckDeadlineFired {
                    exchange_id,
                    ack_counter: p.ack_counter,
                    is_local_initiator: p.is_local_initiator,
                });
                reclaim_candidates.push(exchange_id);
            }
        }

        // Reclaim any exchange whose last piece of live work cleared this
        // tick and is now idle (no pending retransmit, no buffered ack).
        for exchange_id in reclaim_candidates {
            self.reclaim_if_idle(exchange_id);
        }

        events
    }

    /// Parse an inbound decrypted payload's protocol header and update MRP
    /// bookkeeping.
    ///
    /// - On `A=1`: clears the matching pending retransmit (`ack_counter`).
    ///   If the payload is a bare `StandaloneAck` (opcode `0x10`, empty app
    ///   payload, `R=0`), returns [`InboundOutcome::AckOnly`].
    /// - On `R=1`: buffers a per-exchange piggyback ack with the
    ///   200ms deadline from [`MrpConfig::standalone_ack_deadline`]. The
    ///   ack will be drained by the next outbound in the same exchange, or
    ///   flushed as a standalone-ack via [`MrpTimerEvent::StandaloneAckDeadlineFired`].
    /// - Otherwise: returns [`InboundOutcome::AppMessage`] with the
    ///   post-header bytes.
    ///
    /// # Errors
    ///
    /// Returns the underlying protocol-header decode error if the payload
    /// is malformed.
    pub fn process_inbound(
        &mut self,
        decrypted_payload: Vec<u8>,
        peer_counter: MessageCounter,
        now: Instant,
    ) -> Result<InboundOutcome> {
        // Any inbound is fresh evidence the peer is awake — it feeds the
        // active/idle classification (MRP-1, `is_peer_active`). Record it before
        // any early return so even an ack-only or duplicate frame counts.
        self.last_peer_activity = Some(now);
        // Decode once and use the tail-slice length to split off app bytes.
        let (header, header_len) = {
            let (h, tail) = crate::protocol_header::decode_protocol_header(&decrypted_payload)?;
            let header_len = decrypted_payload.len() - tail.len();
            (h, header_len)
        };
        // Drop the (small) protocol header in place and reuse the existing
        // allocation as the app payload. `drain(..header_len)` shifts the
        // body down within the same buffer (a memmove of the body, no second
        // heap allocation) — cheaper than collecting the tail into a fresh
        // Vec and leaving the original allocation as garbage.
        let mut app_payload = decrypted_payload;
        app_payload.drain(..header_len);

        let exchange_id = header.exchange_id;
        let peer_is_initiator = header.exchange_flags.contains(ExchangeFlags::INITIATOR);
        let we_are_initiator = !peer_is_initiator;

        // Record the exchange on first sight, bounding the table so a peer
        // cannot grow it without limit via fresh, peer-controlled
        // exchange_ids. If this is a NEW exchange and the table is already
        // at the cap, reject the message rather than insert. Messages on
        // exchanges we already track are always accepted (they cost no new
        // slot), so the cap never interferes with established traffic.
        if !self.exchanges.contains_key(&exchange_id) {
            if self.exchanges.len() >= MAX_EXCHANGES_PER_SESSION {
                return Err(Error::ExchangeTableFull);
            }
            self.exchanges.insert(
                exchange_id,
                ExchangeState {
                    is_local_initiator: we_are_initiator,
                },
            );
        }

        if header.exchange_flags.contains(ExchangeFlags::ACK) {
            if let Some(MessageCounter(c)) = header.ack_counter {
                self.pending_acks.remove(&MessageCounter(c));
            }
            // StandaloneAck: opcode 0x10, empty app payload, A=1, R=0.
            // `unwrap_or` here is safe — A=1 guarantees ack_counter is Some,
            // but the lint-clean form keeps clippy::unwrap_used happy.
            if header.opcode == crate::protocol_header::opcode::secure_channel::STANDALONE_ACK
                && app_payload.is_empty()
                && !header.exchange_flags.contains(ExchangeFlags::RELIABLE)
            {
                // A pure ack completes the round-trip from our side — the
                // pending retransmit just cleared above. Reclaim the
                // exchange if nothing else keeps it live.
                self.reclaim_if_idle(exchange_id);
                return Ok(InboundOutcome::AckOnly {
                    exchange_id,
                    acked_counter: header.ack_counter.unwrap_or(MessageCounter(0)),
                });
            }
        }

        if header.exchange_flags.contains(ExchangeFlags::RELIABLE) {
            // Buffer (or refresh) this exchange's piggyback ack. Keyed by
            // exchange_id so a concurrent reliable inbound on a different
            // exchange never clobbers this one.
            self.pending_outbound_acks.insert(
                exchange_id,
                PendingOutboundAck {
                    ack_counter: peer_counter,
                    is_local_initiator: we_are_initiator,
                    deadline: now + self.config.standalone_ack_deadline,
                },
            );
            // Insertion-order eviction into the 32-entry ring buffer.
            self.recent_reliable[self.recent_next_slot] = Some(RecentInbound {
                exchange_id,
                counter: peer_counter,
                is_local_initiator: we_are_initiator,
            });
            self.recent_next_slot = (self.recent_next_slot + 1) % 32;
        }

        // If a piggybacked ack cleared this exchange's last pending
        // retransmit and the inbound was not itself reliable (so it buffered
        // no outbound ack), the exchange is now idle and can be reclaimed.
        self.reclaim_if_idle(exchange_id);

        Ok(InboundOutcome::AppMessage {
            exchange_id,
            is_initiator: peer_is_initiator,
            protocol_id: header.protocol_id,
            opcode: header.opcode,
            payload: app_payload,
        })
    }

    /// Cancel a pending piggyback/standalone-ack registration for
    /// `exchange_id`, if any.
    ///
    /// Used by [`crate::session::SessionManager::decode_inbound`] when the
    /// owning session's `transport_reliable` flag is set: the underlying
    /// transport (BTP) already guarantees ordered, reliable delivery, so no
    /// local ack bookkeeping should be armed — defensively, even if a
    /// (possibly buggy) peer sets the R flag on an inbound message.
    pub(crate) fn cancel_pending_outbound_ack(&mut self, exchange_id: u16) {
        self.pending_outbound_acks.remove(&exchange_id);
    }

    /// Look up `peer_counter` in the 32-entry recent-reliable cache.
    /// Returns `Some(view)` if the counter was seen on a recent reliable
    /// inbound (the wider system uses this to trigger an ack-resend
    /// without re-delivering the application payload), or `None` if the
    /// counter is not cached (either never seen or already evicted).
    ///
    /// Linear scan over 32 slots — trivial cost.
    #[must_use]
    pub fn check_duplicate_reliable(
        &self,
        peer_counter: MessageCounter,
    ) -> Option<RecentInboundView> {
        self.recent_reliable
            .iter()
            .flatten()
            .find(|r| r.counter == peer_counter)
            .map(|r| RecentInboundView {
                exchange_id: r.exchange_id,
                is_local_initiator: r.is_local_initiator,
            })
    }

    /// Close the exchange identified by `exchange_id`:
    /// - Removes it from the exchange table.
    /// - Drops any pending retransmits scoped to that exchange.
    /// - Clears the pending piggyback-ack slot if it targets this
    ///   exchange.
    ///
    /// `recent_reliable` entries for this exchange are intentionally
    /// preserved: a late peer retransmit of a request from the now-closed
    /// exchange should still trigger the ack-resend path rather than
    /// surfacing as a fresh application message.
    pub fn close_exchange(&mut self, exchange_id: u16) {
        self.exchanges.remove(&exchange_id);
        self.pending_acks
            .retain(|_, p| p.exchange_id != exchange_id);
        self.pending_outbound_acks.remove(&exchange_id);
    }

    /// Returns `true` if `exchange_id` has no live work attached: no pending
    /// retransmit and no buffered outbound (piggyback) ack. Such an exchange
    /// is genuinely complete and its [`ExchangeState`] can be reclaimed.
    ///
    /// `recent_reliable` entries are intentionally NOT consulted: they are a
    /// fixed-size ring buffer (bounded memory) whose dedup-resend semantics
    /// must outlive the exchange, exactly as [`Self::close_exchange`]
    /// preserves them.
    fn exchange_is_idle(&self, exchange_id: u16) -> bool {
        let has_pending_retransmit = self
            .pending_acks
            .values()
            .any(|p| p.exchange_id == exchange_id);
        let has_buffered_ack = self.pending_outbound_acks.contains_key(&exchange_id);
        !has_pending_retransmit && !has_buffered_ack
    }

    /// Reclaim `exchange_id`'s [`ExchangeState`] if it is now idle (see
    /// [`Self::exchange_is_idle`]). Called at each point where an exchange's
    /// last piece of live work clears (an ack is received, a retransmit
    /// expires, or a buffered outbound ack drains), so completed exchanges
    /// are evicted automatically rather than depending on a caller invoking
    /// [`Self::close_exchange`].
    fn reclaim_if_idle(&mut self, exchange_id: u16) {
        if self.exchange_is_idle(exchange_id) {
            self.exchanges.remove(&exchange_id);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::protocol_header::{decode_protocol_header, ExchangeFlags};
    use std::time::Duration;

    fn t0() -> Instant {
        // Use a fixed reference Instant for all simulated-clock tests.
        Instant::now()
    }

    #[test]
    fn unreliable_send_no_pending_entry() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        let prepared = mrp
            .prepare_outbound(
                0x20,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"hello",
                MrpFlags { reliable: false },
                now,
            )
            .unwrap();

        assert!(prepared.is_local_initiator);
        assert_eq!(prepared.exchange_id, 1, "first allocated exchange_id");
        assert!(!prepared.piggyback_acked);
        // No pending_acks even after mark_packet_sent because R=0.
        mrp.mark_packet_sent(
            MessageCounter(1),
            prepared.exchange_id,
            vec![0u8; 16],
            false,
            now,
        );
        assert_eq!(mrp.poll_timeout(), None);
    }

    #[test]
    fn reliable_send_schedules_retransmit() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        // Peer is active (it sent us something just now) → active base (300 ms).
        mrp.last_peer_activity = Some(now);

        let prepared = mrp
            .prepare_outbound(
                0x02,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"read attr",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        mrp.mark_packet_sent(
            MessageCounter(1),
            prepared.exchange_id,
            vec![0xAAu8; 24],
            true,
            now,
        );

        let deadline = mrp.poll_timeout().expect("retransmit deadline scheduled");
        assert_eq!(deadline, now + Duration::from_millis(300));
    }

    #[test]
    fn handle_timeout_emits_retransmit_at_deadline() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        // Peer active → active base (300 ms) for the first retransmit.
        mrp.last_peer_activity = Some(now);
        let prepared = mrp
            .prepare_outbound(
                0x02,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"read",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        let packet = vec![0xAAu8; 24];
        mrp.mark_packet_sent(
            MessageCounter(1),
            prepared.exchange_id,
            packet.clone(),
            true,
            now,
        );

        // Before the deadline — no events.
        assert!(mrp
            .handle_timeout(now + Duration::from_millis(200))
            .is_empty());

        // At the deadline — retransmit.
        let events = mrp.handle_timeout(now + Duration::from_millis(300));
        assert_eq!(events.len(), 1);
        match &events[0] {
            MrpTimerEvent::Retransmit {
                exchange_id,
                counter,
                packet: bytes,
            } => {
                assert_eq!(*exchange_id, prepared.exchange_id);
                assert_eq!(*counter, MessageCounter(1));
                assert_eq!(*bytes, packet);
            }
            other => panic!("expected Retransmit, got {other:?}"),
        }

        // Next deadline at 300ms × 1.6 = 480ms from the previous attempt.
        let next = mrp.poll_timeout().unwrap();
        assert_eq!(next, now + Duration::from_millis(300 + 480));
    }

    #[test]
    fn exhausted_retransmit_emits_expired() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        let prepared = mrp
            .prepare_outbound(
                0x02,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"x",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        mrp.mark_packet_sent(
            MessageCounter(1),
            prepared.exchange_id,
            vec![1u8; 8],
            true,
            now,
        );

        // 5 attempts: 300, 300+480=780, 780+768=1548, 1548+1228=2776, 2776+1965=4741 ms.
        // After the 5th retransmit, attempts_remaining = 0; the NEXT timer
        // fires Expired.
        let mut total_retransmits = 0;
        for _ in 0..5 {
            let sim = mrp.poll_timeout().expect("timer scheduled");
            let events = mrp.handle_timeout(sim);
            for e in &events {
                if matches!(e, MrpTimerEvent::Retransmit { .. }) {
                    total_retransmits += 1;
                }
            }
        }
        assert_eq!(total_retransmits, 5);

        // Sixth firing: Expired.
        let sim = mrp.poll_timeout().expect("expiry timer scheduled");
        let events = mrp.handle_timeout(sim);
        assert!(matches!(
            events[0],
            MrpTimerEvent::Expired { exchange_id, counter }
            if exchange_id == prepared.exchange_id && counter == MessageCounter(1)
        ));
        assert_eq!(mrp.poll_timeout(), None, "no more pending after Expired");
    }

    /// Helper: queue one reliable message and return its scheduled first
    /// retransmit deadline.
    fn schedule_reliable(mrp: &mut MrpState, counter: u32, now: Instant) -> Instant {
        let p = mrp
            .prepare_outbound(
                0x02,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"x",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        mrp.mark_packet_sent(
            MessageCounter(counter),
            p.exchange_id,
            vec![1u8; 4],
            true,
            now,
        );
        mrp.poll_timeout().expect("retransmit deadline scheduled")
    }

    /// MRP-1: a fresh session (we have never heard from the peer) is IDLE, so
    /// the first retransmit uses the slow idle base (SII) — we never open with
    /// active-interval spacing at a device that might be a sleepy ICD. Once the
    /// peer sends us something (within SAT), the session is active (SAI).
    #[test]
    fn classification_follows_peer_activity_not_our_tx() {
        let now = t0();

        // Fresh session, no peer inbound → idle base (4200 ms).
        let mut fresh = MrpState::new(MrpConfig::default());
        assert_eq!(
            schedule_reliable(&mut fresh, 1, now),
            now + Duration::from_millis(4200),
            "a peer we have never heard from is idle (SII), regardless of our tx timing",
        );

        // Peer sent us something within SAT → active base (300 ms).
        let mut active = MrpState::new(MrpConfig::default());
        active.last_peer_activity = Some(now);
        assert_eq!(
            schedule_reliable(&mut active, 1, now),
            now + Duration::from_millis(300),
            "a peer active within SAT uses the active base (SAI)",
        );

        // Peer last spoke longer ago than SAT (idle_threshold, 5 s) → idle base.
        let mut aged = MrpState::new(MrpConfig::default());
        aged.last_peer_activity = Some(now);
        let later = now + Duration::from_secs(6);
        assert_eq!(
            schedule_reliable(&mut aged, 1, later),
            later + Duration::from_millis(4200),
            "a peer silent past SAT is idle (SII) again",
        );
    }

    /// MRP-1 core: the active/idle base is re-evaluated on EVERY retransmit
    /// (chip `GetMRPBaseTimeout`), not fixed at send time. A message queued
    /// while the peer was active must switch to the idle base once the peer
    /// goes silent past SAT — the CASE-Sigma3-to-a-sleepy-device failure mode.
    #[test]
    fn retransmit_reevaluates_peer_active_state() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        // Peer active at send → first retransmit at the active base (300 ms).
        mrp.last_peer_activity = Some(now);
        let d0 = schedule_reliable(&mut mrp, 1, now);
        assert_eq!(d0, now + Duration::from_millis(300));

        // Fire the first retransmit while the peer is STILL active (t+300ms,
        // within SAT). Next attempt uses the active base × backoff.
        let ev = mrp.handle_timeout(d0);
        assert_eq!(ev.len(), 1);
        let d1 = mrp.poll_timeout().unwrap();
        assert_eq!(
            d1,
            d0 + Duration::from_millis(480), // 300 * 1.6^1
            "still-active peer: active base with backoff",
        );

        // Now the peer has gone silent well past SAT (5 s). The NEXT retransmit
        // must switch to the idle base (4200 ms) × its backoff, not stay on the
        // active grid — this is the anti-hammer guarantee.
        let much_later = d1.max(now + Duration::from_secs(7));
        mrp.handle_timeout(much_later);
        let d2 = mrp.poll_timeout().unwrap();
        // attempts_done is now 2 → idle base 4200 * 1.6^2 = 10752 ms.
        assert_eq!(
            d2,
            much_later + Duration::from_millis(10752),
            "peer silent past SAT: retransmit re-evaluates to the idle base (SII)",
        );
    }

    #[test]
    fn exchange_id_allocation_increments() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        let p1 = mrp
            .prepare_outbound(
                0x02,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"a",
                MrpFlags::default(),
                now,
            )
            .unwrap();
        let p2 = mrp
            .prepare_outbound(
                0x02,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"b",
                MrpFlags::default(),
                now,
            )
            .unwrap();
        assert_eq!(p1.exchange_id, 1);
        assert_eq!(p2.exchange_id, 2);
    }

    #[test]
    fn prepared_payload_contains_encoded_header() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        let prepared = mrp
            .prepare_outbound(
                0x02,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"data",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();

        // The wire_payload starts with the encoded ProtocolHeader.
        let (header, tail) = decode_protocol_header(&prepared.wire_payload).unwrap();
        assert!(header.exchange_flags.contains(ExchangeFlags::INITIATOR));
        assert!(header.exchange_flags.contains(ExchangeFlags::RELIABLE));
        assert_eq!(header.exchange_id, prepared.exchange_id);
        assert_eq!(tail, b"data");
    }

    use crate::protocol_header::opcode;

    fn build_inbound_payload(
        flags: ExchangeFlags,
        opcode_value: u8,
        exchange_id: u16,
        ack_counter: Option<MessageCounter>,
        app_tail: &[u8],
    ) -> Vec<u8> {
        let header = ProtocolHeader {
            exchange_flags: flags,
            opcode: opcode_value,
            exchange_id,
            protocol_id: ProtocolId::INTERACTION_MODEL,
            ack_counter,
        };
        let mut out = Vec::new();
        encode_protocol_header(&header, &mut out);
        out.extend_from_slice(app_tail);
        out
    }

    /// MRP-1: an inbound from the peer marks it active, so a reliable send that
    /// follows uses the active base — proving `process_inbound` feeds the
    /// classification (it is the real hook, not the test-only field poke).
    #[test]
    fn process_inbound_marks_peer_active() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        // Before any inbound: fresh session is idle.
        let mut probe = MrpState::new(MrpConfig::default());
        assert_eq!(
            schedule_reliable(&mut probe, 1, now),
            now + Duration::from_millis(4200),
        );
        // After a real inbound: peer is active.
        let payload = build_inbound_payload(ExchangeFlags::INITIATOR, 0x02, 0x0001, None, b"hi");
        let _ = mrp
            .process_inbound(payload, MessageCounter(50), now)
            .unwrap();
        assert_eq!(
            schedule_reliable(&mut mrp, 1, now),
            now + Duration::from_millis(300),
            "a send right after a peer inbound uses the active base",
        );
    }

    /// MRP-2: `MrpConfig::for_peer` maps advertised `SII`/`SAI`/`SAT`, falls
    /// back to the Matter spec defaults for omitted keys, and clamps
    /// out-of-range values to their spec upper bounds.
    #[test]
    fn for_peer_maps_txt_defaults_and_clamps() {
        // All three supplied, in range.
        let c = MrpConfig::for_peer(
            Some(Duration::from_secs(6)),  // SII
            Some(Duration::from_secs(1)),  // SAI
            Some(Duration::from_secs(30)), // SAT
        );
        assert_eq!(c.initial_idle, Duration::from_secs(6));
        assert_eq!(c.initial_active, Duration::from_secs(1));
        assert_eq!(c.idle_threshold, Duration::from_secs(30));
        // Retransmit shape stays at the local defaults (not peer-controlled).
        assert_eq!(c.max_attempts, MrpConfig::default().max_attempts);
        assert!(
            (c.backoff_factor - MrpConfig::default().backoff_factor).abs() < f32::EPSILON,
            "backoff factor stays at the local default",
        );

        // None → spec defaults (SII 500, SAI 300, SAT 4000).
        let d = MrpConfig::for_peer(None, None, None);
        assert_eq!(d.initial_idle, Duration::from_millis(500));
        assert_eq!(d.initial_active, Duration::from_millis(300));
        assert_eq!(d.idle_threshold, Duration::from_secs(4));

        // Over-range → clamped (SII/SAI ≤ 3_600_000 ms, SAT ≤ 65_535 ms).
        let e = MrpConfig::for_peer(
            Some(Duration::from_secs(9999)),
            Some(Duration::from_secs(9999)),
            Some(Duration::from_secs(9999)),
        );
        assert_eq!(e.initial_idle, Duration::from_secs(3600));
        assert_eq!(e.initial_active, Duration::from_secs(3600));
        assert_eq!(e.idle_threshold, Duration::from_millis(65_535));
    }

    #[test]
    fn process_inbound_app_message_delivers_payload() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        let payload = build_inbound_payload(
            ExchangeFlags::INITIATOR, // peer initiated this exchange
            0x02,
            0x4242,
            None,
            b"hello from peer",
        );
        let outcome = mrp
            .process_inbound(payload, MessageCounter(100), now)
            .unwrap();
        match outcome {
            InboundOutcome::AppMessage {
                exchange_id,
                is_initiator,
                protocol_id,
                opcode,
                payload,
            } => {
                assert_eq!(exchange_id, 0x4242);
                assert!(is_initiator, "peer set I=1 → peer is the initiator");
                assert_eq!(protocol_id, ProtocolId::INTERACTION_MODEL);
                assert_eq!(opcode, 0x02);
                assert_eq!(payload, b"hello from peer");
            }
            other => panic!("expected AppMessage, got {other:?}"),
        }
    }

    #[test]
    fn process_inbound_ack_clears_pending() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // Send a reliable outbound first.
        let prepared = mrp
            .prepare_outbound(
                0x02,
                ProtocolId::INTERACTION_MODEL,
                None,
                b"x",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        mrp.mark_packet_sent(
            MessageCounter(1),
            prepared.exchange_id,
            vec![0xAAu8; 8],
            true,
            now,
        );
        assert!(mrp.poll_timeout().is_some());

        // Peer sending standalone-ack to us — they did NOT initiate our exchange. I=0 for them.
        let ack_payload = build_inbound_payload(
            ExchangeFlags::ACK,
            opcode::secure_channel::STANDALONE_ACK,
            prepared.exchange_id,
            Some(MessageCounter(1)),
            &[],
        );
        let outcome = mrp
            .process_inbound(ack_payload, MessageCounter(50), now)
            .unwrap();
        match outcome {
            InboundOutcome::AckOnly {
                exchange_id,
                acked_counter,
            } => {
                assert_eq!(exchange_id, prepared.exchange_id);
                assert_eq!(acked_counter, MessageCounter(1));
            }
            other => panic!("expected AckOnly, got {other:?}"),
        }
        assert_eq!(mrp.poll_timeout(), None, "pending_acks cleared");
    }

    #[test]
    fn reliable_inbound_queues_piggyback_ack() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        let payload = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0x4242,
            None,
            b"reliable inbound",
        );
        let _ = mrp
            .process_inbound(payload, MessageCounter(100), now)
            .unwrap();

        // 200ms standalone-ack deadline should be the poll deadline now.
        assert_eq!(
            mrp.poll_timeout().unwrap(),
            now + Duration::from_millis(200),
        );
    }

    #[test]
    fn piggyback_drained_by_next_outbound() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // Inbound reliable to queue the piggyback.
        let payload = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0x4242,
            None,
            b"in",
        );
        mrp.process_inbound(payload, MessageCounter(100), now)
            .unwrap();
        assert!(mrp.poll_timeout().is_some());

        // Next outbound in the SAME exchange — should piggyback the ack.
        let prepared = mrp
            .prepare_outbound(
                0x10,
                ProtocolId::SECURE_CHANNEL,
                Some(0x4242),
                b"",
                MrpFlags::default(),
                now + Duration::from_millis(50),
            )
            .unwrap();

        assert!(prepared.piggyback_acked);
        // The encoded header should have A=1 with ack_counter = 100.
        let (header, _) =
            crate::protocol_header::decode_protocol_header(&prepared.wire_payload).unwrap();
        assert!(header.exchange_flags.contains(ExchangeFlags::ACK));
        assert_eq!(header.ack_counter, Some(MessageCounter(100)));

        // Piggyback consumed → no standalone deadline pending.
        assert_eq!(mrp.poll_timeout(), None);
    }

    #[test]
    fn standalone_ack_deadline_fires_after_200ms() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
        let payload = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0x4242,
            None,
            b"in",
        );
        mrp.process_inbound(payload, MessageCounter(100), now)
            .unwrap();

        // Before deadline.
        assert!(mrp
            .handle_timeout(now + Duration::from_millis(199))
            .is_empty());

        // At deadline.
        let events = mrp.handle_timeout(now + Duration::from_millis(200));
        assert_eq!(events.len(), 1);
        match &events[0] {
            MrpTimerEvent::StandaloneAckDeadlineFired {
                exchange_id,
                ack_counter,
                is_local_initiator,
            } => {
                assert_eq!(*exchange_id, 0x4242);
                assert_eq!(*ack_counter, MessageCounter(100));
                // Peer set I=1, so peer is initiator, we are responder.
                assert!(!*is_local_initiator);
            }
            other => panic!("expected StandaloneAckDeadlineFired, got {other:?}"),
        }
        // Deadline drains; no more pending.
        assert_eq!(mrp.poll_timeout(), None);
    }

    #[test]
    fn caller_provided_exchange_id_responder_side() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // Peer initiates exchange 0x99 by sending us a reliable message.
        let inbound = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0x99,
            None,
            b"req",
        );
        mrp.process_inbound(inbound, MessageCounter(100), now)
            .unwrap();

        // We respond in the same exchange. We are NOT the initiator.
        let prepared = mrp
            .prepare_outbound(
                0x03,
                ProtocolId::INTERACTION_MODEL,
                Some(0x99),
                b"response",
                MrpFlags { reliable: true },
                now + Duration::from_millis(10),
            )
            .unwrap();
        assert_eq!(prepared.exchange_id, 0x99);
        assert!(!prepared.is_local_initiator);

        let (header, _) =
            crate::protocol_header::decode_protocol_header(&prepared.wire_payload).unwrap();
        assert!(
            !header.exchange_flags.contains(ExchangeFlags::INITIATOR),
            "we are responder for this exchange"
        );
        assert!(header.exchange_flags.contains(ExchangeFlags::RELIABLE));
        assert!(
            header.exchange_flags.contains(ExchangeFlags::ACK),
            "piggyback drained"
        );
        assert_eq!(header.ack_counter, Some(MessageCounter(100)));
    }

    #[test]
    fn close_exchange_drops_pending() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        let prepared = mrp
            .prepare_outbound(
                0x02,
                ProtocolId::INTERACTION_MODEL,
                None,
                b"x",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        mrp.mark_packet_sent(
            MessageCounter(1),
            prepared.exchange_id,
            vec![1u8; 4],
            true,
            now,
        );
        assert!(mrp.poll_timeout().is_some());

        mrp.close_exchange(prepared.exchange_id);
        assert_eq!(
            mrp.poll_timeout(),
            None,
            "closing exchange dropped pending retransmit"
        );
    }

    #[test]
    fn duplicate_reliable_returns_view() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // Receive a reliable inbound.
        let inbound = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0x4242,
            None,
            b"first",
        );
        mrp.process_inbound(inbound, MessageCounter(100), now)
            .unwrap();

        // Same counter again — the replay window in the wider system
        // would normally reject; in this test we directly query MRP's
        // recent-reliable cache.
        let view = mrp.check_duplicate_reliable(MessageCounter(100)).unwrap();
        assert_eq!(view.exchange_id, 0x4242);
        assert!(!view.is_local_initiator, "peer was initiator");
    }

    #[test]
    fn concurrent_exchanges_each_retain_their_pending_ack() {
        // H3 regression: a reliable inbound on exchange B must NOT clobber
        // the buffered piggyback ack for exchange A. Both exchanges must
        // drain their own ack on the next outbound in that exchange.
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // Reliable inbound on exchange A (peer counter 100).
        let in_a = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0xAAAA,
            None,
            b"req-a",
        );
        mrp.process_inbound(in_a, MessageCounter(100), now).unwrap();

        // Reliable inbound on exchange B (peer counter 200) BEFORE any
        // outbound or timeout drains A's ack.
        let in_b = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0xBBBB,
            None,
            b"req-b",
        );
        mrp.process_inbound(in_b, MessageCounter(200), now).unwrap();

        // Respond on exchange A — must piggyback A's ack (counter 100).
        let resp_a = mrp
            .prepare_outbound(
                0x03,
                ProtocolId::INTERACTION_MODEL,
                Some(0xAAAA),
                b"resp-a",
                MrpFlags::default(),
                now + Duration::from_millis(10),
            )
            .unwrap();
        assert!(resp_a.piggyback_acked, "exchange A's ack must drain");
        let (hdr_a, _) =
            crate::protocol_header::decode_protocol_header(&resp_a.wire_payload).unwrap();
        assert!(hdr_a.exchange_flags.contains(ExchangeFlags::ACK));
        assert_eq!(hdr_a.ack_counter, Some(MessageCounter(100)));

        // Respond on exchange B — must piggyback B's ack (counter 200).
        let resp_b = mrp
            .prepare_outbound(
                0x03,
                ProtocolId::INTERACTION_MODEL,
                Some(0xBBBB),
                b"resp-b",
                MrpFlags::default(),
                now + Duration::from_millis(10),
            )
            .unwrap();
        assert!(resp_b.piggyback_acked, "exchange B's ack must drain");
        let (hdr_b, _) =
            crate::protocol_header::decode_protocol_header(&resp_b.wire_payload).unwrap();
        assert!(hdr_b.exchange_flags.contains(ExchangeFlags::ACK));
        assert_eq!(hdr_b.ack_counter, Some(MessageCounter(200)));

        // Both drained → no standalone deadline pending.
        assert_eq!(mrp.poll_timeout(), None);
    }

    #[test]
    fn handle_timeout_flushes_all_due_standalone_acks() {
        // H3 regression: two buffered piggyback acks on different exchanges
        // must BOTH flush as standalone acks once their deadline passes.
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        let in_a = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0xAAAA,
            None,
            b"a",
        );
        mrp.process_inbound(in_a, MessageCounter(100), now).unwrap();

        let in_b = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0xBBBB,
            None,
            b"b",
        );
        mrp.process_inbound(in_b, MessageCounter(200), now).unwrap();

        // Advance past the 200ms standalone-ack deadline.
        let events = mrp.handle_timeout(now + Duration::from_millis(200));

        // Collect the (exchange_id, ack_counter) pairs from every
        // standalone-ack-deadline-fired event.
        let mut flushed: Vec<(u16, MessageCounter)> = events
            .iter()
            .filter_map(|e| match e {
                MrpTimerEvent::StandaloneAckDeadlineFired {
                    exchange_id,
                    ack_counter,
                    ..
                } => Some((*exchange_id, *ack_counter)),
                _ => None,
            })
            .collect();
        flushed.sort_by_key(|(xid, _)| *xid);

        assert_eq!(
            flushed,
            vec![(0xAAAA, MessageCounter(100)), (0xBBBB, MessageCounter(200)),],
            "both exchanges must flush a standalone ack"
        );

        // All drained → nothing pending.
        assert_eq!(mrp.poll_timeout(), None);
    }

    #[test]
    fn inbound_exchange_table_is_capped() {
        // Memory-DoS regression: a peer driving many distinct inbound
        // exchange_ids must not grow the exchange table without bound.
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // Drive far more distinct exchange_ids than the cap. Use
        // non-reliable inbounds so no pending state lingers — each one is
        // a complete, idle exchange the moment it is processed.
        let n = u32::try_from(MAX_EXCHANGES_PER_SESSION).unwrap() + 500;
        for id in 0..n {
            let inbound = build_inbound_payload(
                ExchangeFlags::INITIATOR,
                0x02,
                u16::try_from(id % 0xFFFF).unwrap(),
                None,
                b"x",
            );
            // Keep counters distinct so the replay/dedup paths stay sane.
            let _ = mrp.process_inbound(inbound, MessageCounter(id), now);
        }

        assert!(
            mrp.exchanges.len() <= MAX_EXCHANGES_PER_SESSION,
            "exchange table grew past the cap: {} > {}",
            mrp.exchanges.len(),
            MAX_EXCHANGES_PER_SESSION
        );
    }

    #[test]
    fn capped_new_inbound_exchange_is_rejected() {
        // Once the table is full of LIVE exchanges (each holding a buffered
        // outbound ack so it is not idle), a brand-new exchange_id must be
        // rejected rather than inserted.
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // Fill the table with reliable inbounds: each leaves a buffered
        // piggyback ack, so the exchange counts as live and won't be
        // reclaimed.
        for id in 0..u32::try_from(MAX_EXCHANGES_PER_SESSION).unwrap() {
            let inbound = build_inbound_payload(
                ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
                0x02,
                u16::try_from(id).unwrap(),
                None,
                b"x",
            );
            mrp.process_inbound(inbound, MessageCounter(id), now)
                .unwrap();
        }
        assert_eq!(mrp.exchanges.len(), MAX_EXCHANGES_PER_SESSION);

        // A new exchange_id at the cap must be rejected.
        let new_id = u16::try_from(MAX_EXCHANGES_PER_SESSION).unwrap();
        let outcome = mrp.process_inbound(
            build_inbound_payload(
                ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
                0x02,
                new_id,
                None,
                b"x",
            ),
            MessageCounter(0xFFFF),
            now,
        );
        assert!(
            matches!(outcome, Err(Error::ExchangeTableFull)),
            "new exchange past the cap must be rejected, got {outcome:?}"
        );
        assert_eq!(
            mrp.exchanges.len(),
            MAX_EXCHANGES_PER_SESSION,
            "rejected exchange must not be inserted"
        );

        // An inbound on an ALREADY-KNOWN exchange must still be accepted
        // even when the table is full.
        let known = mrp.process_inbound(
            build_inbound_payload(ExchangeFlags::INITIATOR, 0x02, 0, None, b"y"),
            MessageCounter(0xF000),
            now,
        );
        assert!(
            known.is_ok(),
            "inbound on a known exchange must still be accepted at the cap"
        );
    }

    #[test]
    fn completed_exchange_is_reclaimed() {
        // Reclaim regression: an exchange whose round-trip finishes (its
        // last pending ack clears, no buffered outbound ack) must be
        // evicted from the exchange table automatically.
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // We initiate a reliable outbound.
        let prepared = mrp
            .prepare_outbound(
                0x02,
                ProtocolId::INTERACTION_MODEL,
                None,
                b"read",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        mrp.mark_packet_sent(
            MessageCounter(1),
            prepared.exchange_id,
            vec![0xAAu8; 8],
            true,
            now,
        );
        assert!(
            mrp.exchanges.contains_key(&prepared.exchange_id),
            "exchange recorded while round-trip is in flight"
        );

        // Peer acks our message (standalone ack). Round-trip complete.
        let ack = build_inbound_payload(
            ExchangeFlags::ACK,
            opcode::secure_channel::STANDALONE_ACK,
            prepared.exchange_id,
            Some(MessageCounter(1)),
            &[],
        );
        mrp.process_inbound(ack, MessageCounter(50), now).unwrap();

        assert!(
            !mrp.exchanges.contains_key(&prepared.exchange_id),
            "completed exchange must be reclaimed once idle"
        );
        assert!(mrp.exchanges.is_empty(), "exchange table shrank to empty");
    }

    #[test]
    fn active_exchange_is_not_reclaimed() {
        // An exchange with a pending retransmit (round-trip still in
        // flight) must NOT be evicted by the reclaim logic.
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        let prepared = mrp
            .prepare_outbound(
                0x02,
                ProtocolId::INTERACTION_MODEL,
                None,
                b"read",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        mrp.mark_packet_sent(
            MessageCounter(1),
            prepared.exchange_id,
            vec![0xAAu8; 8],
            true,
            now,
        );

        // A reliable inbound arrives on a DIFFERENT exchange — processing it
        // triggers a reclaim sweep, but our exchange has a pending
        // retransmit and must survive.
        let other = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0x7777,
            None,
            b"other",
        );
        mrp.process_inbound(other, MessageCounter(100), now)
            .unwrap();

        assert!(
            mrp.exchanges.contains_key(&prepared.exchange_id),
            "exchange with a pending retransmit must not be reclaimed"
        );
    }

    #[test]
    fn buffered_outbound_ack_keeps_exchange_live() {
        // An exchange with a buffered outbound (piggyback) ack is NOT idle
        // and must not be reclaimed until the ack drains.
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // Reliable inbound buffers a piggyback ack for exchange 0x4242.
        let inbound = build_inbound_payload(
            ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            0x02,
            0x4242,
            None,
            b"req",
        );
        mrp.process_inbound(inbound, MessageCounter(100), now)
            .unwrap();
        assert!(
            mrp.exchanges.contains_key(&0x4242),
            "exchange with a buffered outbound ack stays live"
        );

        // Drain the ack via a standalone-ack timeout flush. After the ack
        // drains and nothing else is pending, the exchange is reclaimed.
        mrp.handle_timeout(now + Duration::from_millis(200));
        assert!(
            !mrp.exchanges.contains_key(&0x4242),
            "exchange reclaimed once its buffered ack drains and it is idle"
        );
    }

    #[test]
    fn recent_reliable_cache_evicts_after_32_entries() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

        // Record 33 distinct reliable inbounds; the first should be evicted.
        for n in 0u32..33 {
            let inbound = build_inbound_payload(
                ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
                0x02,
                u16::try_from(n).unwrap(),
                None,
                b"",
            );
            mrp.process_inbound(inbound, MessageCounter(n), now)
                .unwrap();
        }

        // Oldest (counter=0) was evicted.
        assert!(mrp.check_duplicate_reliable(MessageCounter(0)).is_none());
        // Newest is still there.
        assert!(mrp.check_duplicate_reliable(MessageCounter(32)).is_some());
    }
}
