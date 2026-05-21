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

use crate::error::Result;
use crate::framing::{MessageCounter, SessionId};
use crate::protocol_header::{encode_protocol_header, ExchangeFlags, ProtocolHeader, ProtocolId};

/// Configuration knobs for MRP retransmit + ack timing. Defaults match
/// Matter Core Spec §4.11.8 (jitter omitted; see the M5.2 design's
/// "Non-goals" section).
#[derive(Debug, Clone, Copy)]
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
}

/// Outcome of processing an inbound decrypted payload through MRP.
pub enum InboundOutcome {
    /// A new application message was received. `payload` is the bytes
    /// AFTER the protocol header.
    AppMessage {
        /// Exchange the message belongs to.
        exchange_id: u16,
        /// Whether the peer is the initiator (i.e. we are the responder).
        is_initiator: bool,
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
struct PendingAck {
    packet_bytes: Vec<u8>,
    exchange_id: u16,
    next_attempt: Instant,
    attempts_remaining: u8,
    is_active: bool,
}

/// Per-session MRP state.
pub struct MrpState {
    pending_acks: HashMap<MessageCounter, PendingAck>,
    /// Per-exchange reliability flag, populated by `prepare_outbound`
    /// and consumed by the next `mark_packet_sent` call for that
    /// exchange. Lets `mark_packet_sent` no-op for unreliable sends
    /// without a signature change.
    pending_reliability: HashMap<u16, bool>,
    next_exchange_id: u16,
    last_outbound: Option<Instant>,
    config: MrpConfig,
}

impl MrpState {
    /// Create a fresh state with the given config.
    #[must_use]
    pub fn new(config: MrpConfig) -> Self {
        Self {
            pending_acks: HashMap::new(),
            pending_reliability: HashMap::new(),
            next_exchange_id: 1,
            last_outbound: None,
            config,
        }
    }

    /// Build an outbound wire payload (encoded protocol header concatenated
    /// with `app_payload`). Allocates a new exchange ID if `exchange_id` is
    /// `None`.
    ///
    /// Task 4 constraint: `exchange_id` MUST be `None`. Task 6 lifts this
    /// constraint with an exchange table that tracks `is_local_initiator`
    /// for `Some(id)` callers.
    ///
    /// # Errors
    ///
    /// Currently infallible in practice — returns `Result` for forward
    /// compatibility with the exchange-table validation Task 6 adds.
    ///
    /// # Panics
    ///
    /// Panics if `exchange_id` is `Some` — Task 4 only supports allocating
    /// fresh exchange IDs.
    pub fn prepare_outbound(
        &mut self,
        opcode: u8,
        protocol_id: ProtocolId,
        exchange_id: Option<u16>,
        app_payload: &[u8],
        mrp_flags: MrpFlags,
        _now: Instant,
    ) -> Result<PreparedOutbound> {
        // Task 4 constraint: only None supported. Task 6 implements Some.
        assert!(
            exchange_id.is_none(),
            "MRP Task 4: caller-provided exchange_id not yet supported (Task 6)"
        );
        let exchange_id = self.allocate_exchange_id();

        let mut flags = ExchangeFlags::INITIATOR;
        if mrp_flags.reliable {
            flags |= ExchangeFlags::RELIABLE;
        }
        let header = ProtocolHeader {
            exchange_flags: flags,
            opcode,
            exchange_id,
            protocol_id,
            ack_counter: None,
        };
        let mut wire_payload = Vec::with_capacity(app_payload.len() + 16);
        encode_protocol_header(&header, &mut wire_payload);
        wire_payload.extend_from_slice(app_payload);

        // Record reliability for the next mark_packet_sent on this
        // exchange. Tasks 5/6 may revisit how this is tracked alongside
        // the full exchange table.
        self.pending_reliability
            .insert(exchange_id, mrp_flags.reliable);

        Ok(PreparedOutbound {
            wire_payload,
            exchange_id,
            is_local_initiator: true,
            piggyback_acked: false,
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

    /// Register the encrypted wire bytes of a just-sent message so
    /// [`MrpState::handle_timeout`] can retransmit them. Caller invokes
    /// AFTER `framing::encode_secured`.
    ///
    /// Internally tracks `reliable` per exchange via the most recent
    /// [`MrpState::prepare_outbound`] call. The pending-ack entry is only
    /// inserted for reliable messages; unreliable calls update
    /// `last_outbound` (so idle/active classification reflects the true
    /// send cadence) but otherwise no-op. This satisfies the
    /// `unreliable_send_no_pending_entry` contract without requiring the
    /// caller to gate the call externally.
    ///
    /// Idle vs active base is selected based on the gap from the previous
    /// `last_outbound`: if `now - last_outbound > config.idle_threshold`,
    /// the idle base applies to this message's first retransmit.
    pub fn mark_packet_sent(
        &mut self,
        counter: MessageCounter,
        exchange_id: u16,
        packet_bytes: Vec<u8>,
        now: Instant,
    ) {
        let is_active = match self.last_outbound {
            None => true, // first send is treated as active
            Some(prev) => now.saturating_duration_since(prev) <= self.config.idle_threshold,
        };
        self.last_outbound = Some(now);

        // Look up whether the exchange's most recent prepare_outbound
        // requested reliability. Missing entry (e.g. exchange unknown to
        // MRP) is treated as not-reliable — the caller-discipline path.
        let reliable = self
            .pending_reliability
            .remove(&exchange_id)
            .unwrap_or(false);
        if !reliable {
            return;
        }

        let initial = if is_active {
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
                is_active,
            },
        );
    }

    /// Earliest retransmit deadline across all pending acks, or `None`
    /// if no retransmits pending.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.pending_acks.values().map(|p| p.next_attempt).min()
    }

    /// Advance retransmit timers. For each pending whose `next_attempt`
    /// has elapsed, emit a `Retransmit` event and schedule the next
    /// attempt (exponential backoff). If `attempts_remaining` reaches 0,
    /// emit `Expired` and drop the entry.
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<MrpTimerEvent> {
        let mut events = Vec::new();
        let mut to_remove = Vec::new();

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
                continue;
            }
            events.push(MrpTimerEvent::Retransmit {
                exchange_id: pending.exchange_id,
                counter: *counter,
                packet: pending.packet_bytes.clone(),
            });
            pending.attempts_remaining -= 1;
            let base = if pending.is_active {
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
        events
    }

    /// Stub for Task 5.
    ///
    /// # Errors
    ///
    /// Not yet implemented — currently panics.
    pub fn process_inbound(
        &mut self,
        _decrypted_payload: Vec<u8>,
        _peer_counter: MessageCounter,
        _now: Instant,
    ) -> Result<InboundOutcome> {
        unimplemented!("Task 5")
    }

    /// Stub for Task 6.
    #[must_use]
    pub fn check_duplicate_reliable(
        &self,
        _peer_counter: MessageCounter,
    ) -> Option<RecentInboundView> {
        unimplemented!("Task 6")
    }

    /// Stub for Task 6.
    pub fn close_exchange(&mut self, _exchange_id: u16) {
        unimplemented!("Task 6")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
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
        mrp.mark_packet_sent(MessageCounter(1), prepared.exchange_id, vec![0u8; 16], now);
        assert_eq!(mrp.poll_timeout(), None);
    }

    #[test]
    fn reliable_send_schedules_retransmit() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();

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
            now,
        );

        let deadline = mrp.poll_timeout().expect("retransmit deadline scheduled");
        assert_eq!(deadline, now + Duration::from_millis(300));
    }

    #[test]
    fn handle_timeout_emits_retransmit_at_deadline() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let now = t0();
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
        mrp.mark_packet_sent(MessageCounter(1), prepared.exchange_id, packet.clone(), now);

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
        mrp.mark_packet_sent(MessageCounter(1), prepared.exchange_id, vec![1u8; 8], now);

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

    #[test]
    fn idle_session_uses_idle_base() {
        let mut mrp = MrpState::new(MrpConfig::default());
        let t = t0();

        // First outbound at t=0 — sets last_outbound but is the FIRST send,
        // which is treated as active per spec (no prior idle interval to measure).
        let p1 = mrp
            .prepare_outbound(
                0x02,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"x",
                MrpFlags { reliable: true },
                t,
            )
            .unwrap();
        mrp.mark_packet_sent(MessageCounter(1), p1.exchange_id, vec![1u8; 4], t);
        assert_eq!(mrp.poll_timeout().unwrap(), t + Duration::from_millis(300));

        // Clear pending (simulate ack).
        // For Task 4, we don't have process_inbound yet — instead, advance
        // through all 5 retransmits + Expired to clear, then send another.
        for _ in 0..6 {
            let sim = mrp.poll_timeout().expect("timer");
            mrp.handle_timeout(sim);
        }
        assert_eq!(mrp.poll_timeout(), None);

        // Second outbound at t + 10 seconds — more than idle_threshold (5s)
        // since last_outbound. Schedules with idle base.
        let later = t + Duration::from_secs(10);
        let p2 = mrp
            .prepare_outbound(
                0x02,
                crate::protocol_header::ProtocolId::INTERACTION_MODEL,
                None,
                b"y",
                MrpFlags { reliable: true },
                later,
            )
            .unwrap();
        mrp.mark_packet_sent(MessageCounter(2), p2.exchange_id, vec![2u8; 4], later);
        assert_eq!(
            mrp.poll_timeout().unwrap(),
            later + Duration::from_millis(4200),
            "idle base applied to second outbound after >5s gap",
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
}
