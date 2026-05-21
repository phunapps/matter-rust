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
#[derive(Debug)]
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
#[derive(Debug)]
struct PendingAck {
    packet_bytes: Vec<u8>,
    exchange_id: u16,
    next_attempt: Instant,
    attempts_remaining: u8,
    is_active: bool,
}

/// Buffered piggyback-ack slot. At most one outstanding inbound reliable
/// message is held here at a time; either drained by the next outbound in
/// the same exchange (cheap) or flushed as a standalone-ack when the 200ms
/// deadline expires (fallback).
#[derive(Debug)]
struct PendingOutboundAck {
    exchange_id: u16,
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
    pending_outbound_ack: Option<PendingOutboundAck>,
    recent_reliable: [Option<RecentInbound>; 32],
    recent_next_slot: usize,
    exchanges: HashMap<u16, ExchangeState>,
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
            pending_outbound_ack: None,
            recent_reliable: std::array::from_fn(|_| None),
            recent_next_slot: 0,
            exchanges: HashMap::new(),
            next_exchange_id: 1,
            last_outbound: None,
            config,
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
    /// When `pending_outbound_ack` is drained, the outgoing header carries
    /// `A=1` and `ack_counter = pending.ack_counter`. The drain path's
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

        // Drain pending piggyback if it matches THIS exchange.
        let (ack_flag, ack_counter, piggyback_acked) = match self.pending_outbound_ack.take() {
            Some(p) if p.exchange_id == exchange_id => {
                (ExchangeFlags::ACK, Some(p.ack_counter), true)
            }
            Some(p) => {
                // Different exchange — put it back, do not consume.
                self.pending_outbound_ack = Some(p);
                (ExchangeFlags::empty(), None, false)
            }
            None => (ExchangeFlags::empty(), None, false),
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
    /// Idle vs active base is selected based on the gap from the previous
    /// `last_outbound`: if `now - last_outbound > config.idle_threshold`,
    /// the idle base applies to this message's first retransmit.
    pub fn mark_packet_sent(
        &mut self,
        counter: MessageCounter,
        exchange_id: u16,
        packet_bytes: Vec<u8>,
        reliable: bool,
        now: Instant,
    ) {
        let is_active = match self.last_outbound {
            None => true, // first send is treated as active
            Some(prev) => now.saturating_duration_since(prev) <= self.config.idle_threshold,
        };
        self.last_outbound = Some(now);

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

    /// Earliest pending deadline across retransmits and the
    /// piggyback-ack flush deadline, or `None` if nothing pending.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let retransmit = self.pending_acks.values().map(|p| p.next_attempt).min();
        let standalone = self.pending_outbound_ack.as_ref().map(|p| p.deadline);
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

        // Standalone-ack deadline: if the buffered piggyback expired before
        // the next outbound in its exchange, flush it as a standalone-ack.
        if let Some(p) = &self.pending_outbound_ack {
            if p.deadline <= now {
                events.push(MrpTimerEvent::StandaloneAckDeadlineFired {
                    exchange_id: p.exchange_id,
                    ack_counter: p.ack_counter,
                    is_local_initiator: p.is_local_initiator,
                });
                self.pending_outbound_ack = None;
            }
        }
        events
    }

    /// Parse an inbound decrypted payload's protocol header and update MRP
    /// bookkeeping.
    ///
    /// - On `A=1`: clears the matching pending retransmit (`ack_counter`).
    ///   If the payload is a bare `StandaloneAck` (opcode `0x10`, empty app
    ///   payload, `R=0`), returns [`InboundOutcome::AckOnly`].
    /// - On `R=1`: buffers a piggyback ack (`pending_outbound_ack`) with the
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
        // Decode once and use the tail-slice length to split off app bytes.
        let (header, header_len) = {
            let (h, tail) = crate::protocol_header::decode_protocol_header(&decrypted_payload)?;
            let header_len = decrypted_payload.len() - tail.len();
            (h, header_len)
        };
        let mut bytes = decrypted_payload;
        let app_payload: Vec<u8> = bytes.drain(header_len..).collect();

        let exchange_id = header.exchange_id;
        let peer_is_initiator = header.exchange_flags.contains(ExchangeFlags::INITIATOR);
        let we_are_initiator = !peer_is_initiator;

        // Record the exchange on first sight. `or_insert` ensures we don't
        // overwrite an existing record if we already initiated this
        // exchange and are now seeing the peer's first reply.
        self.exchanges.entry(exchange_id).or_insert(ExchangeState {
            is_local_initiator: we_are_initiator,
        });

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
                return Ok(InboundOutcome::AckOnly {
                    exchange_id,
                    acked_counter: header.ack_counter.unwrap_or(MessageCounter(0)),
                });
            }
        }

        if header.exchange_flags.contains(ExchangeFlags::RELIABLE) {
            // Peer set I=1 ⇒ we are the responder for this exchange.
            self.pending_outbound_ack = Some(PendingOutboundAck {
                exchange_id,
                ack_counter: peer_counter,
                is_local_initiator: we_are_initiator,
                deadline: now + self.config.standalone_ack_deadline,
            });
            // Insertion-order eviction into the 32-entry ring buffer.
            self.recent_reliable[self.recent_next_slot] = Some(RecentInbound {
                exchange_id,
                counter: peer_counter,
                is_local_initiator: we_are_initiator,
            });
            self.recent_next_slot = (self.recent_next_slot + 1) % 32;
        }

        Ok(InboundOutcome::AppMessage {
            exchange_id,
            is_initiator: peer_is_initiator,
            payload: app_payload,
        })
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
        if let Some(p) = &self.pending_outbound_ack {
            if p.exchange_id == exchange_id {
                self.pending_outbound_ack = None;
            }
        }
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
        mrp.mark_packet_sent(MessageCounter(1), p1.exchange_id, vec![1u8; 4], true, t);
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
        mrp.mark_packet_sent(MessageCounter(2), p2.exchange_id, vec![2u8; 4], true, later);
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
                payload,
            } => {
                assert_eq!(exchange_id, 0x4242);
                assert!(is_initiator, "peer set I=1 → peer is the initiator");
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
