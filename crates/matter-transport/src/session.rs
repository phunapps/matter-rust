//! Per-session state and the [`SessionManager`] that owns it.
//!
//! M5.1 shipped the registration / counter / replay-window layer. M5.2
//! threads the protocol header and the per-session [`MrpState`] machine
//! through the manager so the same `SessionManager` value drives both the
//! framing and the reliability layers.
//!
//! Public surface added in M5.2:
//! - [`Session::mrp`] — one [`MrpState`] per session.
//! - [`SessionManager::encode_outbound`] / [`SessionManager::decode_inbound`]
//!   — new richer signatures that take the protocol-header inputs (opcode,
//!   protocol id, exchange id, MRP flags, `now`) and return structured
//!   output values rather than raw byte buffers.
//! - [`SessionManager::poll_timeout`] / [`SessionManager::handle_timeout`]
//!   — fold per-session [`MrpTimerEvent`]s into manager-wide
//!   [`MrpEvent`]s and build standalone-ack packets for the
//!   `StandaloneAckDeadlineFired` and duplicate-reliable-resend paths.

use std::collections::HashMap;
use std::time::Instant;

use matter_crypto::case::CaseSessionOutput;
use matter_crypto::pase::PaseSessionKeys;

use crate::error::{Error, Result};
use crate::framing::{
    decode_secured, encode_secured, MessageCounter, NodeId, ReplayWindow, SecuredMessageFlags,
    SecuredMessageHeader, SecurityFlags, SessionId,
};
use crate::mrp::{InboundOutcome, MrpConfig, MrpEvent, MrpFlags, MrpState, MrpTimerEvent};
use crate::protocol_header::{build_standalone_ack_header, encode_protocol_header, ProtocolId};

/// Which side of a session this end occupies. Decides which key in
/// [`SessionKeys`] is used for encoding vs decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// We sent the first message of the handshake (PASE prover / CASE
    /// initiator).
    Initiator,
    /// We received the first message of the handshake (PASE verifier /
    /// CASE responder).
    Responder,
}

/// Symmetric key material for a single Matter session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Encrypts traffic flowing initiator → responder.
    pub i2r_key: [u8; 16],
    /// Encrypts traffic flowing responder → initiator.
    pub r2i_key: [u8; 16],
    /// Attestation challenge key (PASE) / attestation challenge (CASE).
    pub attestation_key: [u8; 16],
}

impl From<PaseSessionKeys> for SessionKeys {
    fn from(p: PaseSessionKeys) -> Self {
        Self {
            i2r_key: p.i2r_key,
            r2i_key: p.r2i_key,
            attestation_key: p.attestation_key,
        }
    }
}

impl SessionKeys {
    /// Build session keys from a completed CASE handshake output.
    #[must_use]
    pub fn from_case_output(out: &CaseSessionOutput) -> Self {
        Self {
            i2r_key: out.keys.i2r_key,
            r2i_key: out.keys.r2i_key,
            attestation_key: out.keys.attestation_challenge,
        }
    }
}

/// Light identity hint about the peer, captured at registration time.
///
/// PASE sessions usually leave both fields `None` (commissioning has no
/// operational identity yet). CASE sessions populate both from the peer's
/// validated NOC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerHint {
    /// Peer's operational Node ID (CASE only).
    pub node_id: Option<NodeId>,
    /// Peer's fabric ID (CASE only).
    pub fabric_id: Option<u64>,
}

/// Single session — keys, counters, replay tracking, role, peer hint, MRP
/// state.
#[derive(Debug)]
pub struct Session {
    /// Our local ID. Peers send packets addressed to this ID.
    pub local_id: SessionId,
    /// Peer's local ID. Outbound headers carry this in their `session_id`
    /// field so the peer can demux on receipt.
    pub peer_id: SessionId,
    /// Whether we're the initiator or the responder of this session.
    pub role: SessionRole,
    /// Symmetric session keys.
    pub keys: SessionKeys,
    /// Next outbound message counter. Initialised per Matter Core Spec
    /// §4.4.3 (random and > `1 << 31`); M5.1 starts at 1 for simplicity
    /// and lets M6 (or a future hardening pass) overwrite the field.
    pub outbound_counter: u32,
    /// Inbound replay window for this session.
    pub replay_window: ReplayWindow,
    /// Peer identity hint (CASE) or default (PASE).
    pub peer: PeerHint,
    /// OUR node id mixed into the AES-CCM nonce of outbound frames (spec
    /// §4.8.2): the local *operational* node id on CASE sessions, `0` on
    /// PASE sessions. Decoupled from the wire header, which omits the
    /// source node id on secured unicast messages.
    pub local_nonce_node_id: u64,
    /// The PEER's node id mixed into the nonce when decrypting inbound
    /// frames: the peer's operational node id on CASE sessions, `0` on PASE.
    pub peer_nonce_node_id: u64,
    /// Per-session MRP state. Holds the exchange table, pending retransmits,
    /// pending piggyback-ack slot, and recent-reliable cache.
    pub mrp: MrpState,
}

/// Structured output of [`SessionManager::encode_outbound`]. Carries the
/// wire bytes plus the bookkeeping the caller needs to track the message
/// (exchange id, counter, whether a piggyback ack was attached).
#[derive(Debug)]
pub struct EncodeOutboundOutput {
    /// Fully-encrypted secured-message bytes ready to hand to the UDP
    /// transport.
    pub wire_bytes: Vec<u8>,
    /// Exchange identifier this message belongs to. Allocated by MRP if the
    /// caller did not provide one.
    pub exchange_id: u16,
    /// Whether the local side originated the exchange. Mirrors the `I` flag
    /// in the protocol header.
    pub is_local_initiator: bool,
    /// Outbound message counter consumed by this send (the slot used in the
    /// secured-message header before [`Session::outbound_counter`] was
    /// advanced).
    pub message_counter: MessageCounter,
    /// Whether MRP drained a pending piggyback-ack into this outbound
    /// header. Useful for tests and instrumentation; the caller usually
    /// does not need to act on it.
    pub piggyback_acked: bool,
}

/// Structured output of [`SessionManager::decode_inbound`]. The three
/// variants cover the cases a caller cares about: a fresh application
/// message, a standalone-ack-only inbound, and a duplicate-reliable inbound
/// for which the manager has already pre-built a standalone-ack packet to
/// re-send.
#[derive(Debug)]
pub enum DecodeInboundOutput {
    /// A new application message arrived. `payload` is the bytes AFTER the
    /// protocol header.
    AppMessage {
        /// Local session ID this message was demuxed onto.
        session_id: SessionId,
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
    /// The inbound was a standalone-ack-only message; no application bytes
    /// follow. MRP has already cleared any matching pending retransmit.
    AckOnly {
        /// Local session ID this message was demuxed onto.
        session_id: SessionId,
        /// Exchange identifier.
        exchange_id: u16,
        /// Counter that was acknowledged.
        acked_counter: MessageCounter,
    },
    /// The inbound packet's counter sat inside the replay window AND
    /// matched a recently-cached reliable peer message. The manager
    /// re-built a standalone-ack packet (consuming one outbound counter
    /// slot) to re-send to the peer; the caller need not deliver any
    /// application payload.
    DuplicateReliableAckResent {
        /// Local session ID this message was demuxed onto.
        session_id: SessionId,
        /// Exchange identifier from the cached entry.
        exchange_id: u16,
        /// Fully-encrypted standalone-ack packet ready to send.
        ack_packet: Vec<u8>,
    },
}

/// Owns all per-session state for one Matter node.
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    next_local_id: u16,
}

impl SessionManager {
    /// Create an empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_local_id: 1,
        }
    }

    /// Register a session whose keys came from a completed PASE handshake.
    /// Returns the allocated local session ID.
    pub fn register_pase(
        &mut self,
        keys: PaseSessionKeys,
        role: SessionRole,
        peer_session_id: u16,
        peer: PeerHint,
    ) -> SessionId {
        self.register(SessionKeys::from(keys), role, peer_session_id, peer)
    }

    /// Register a session whose keys came from a completed CASE handshake.
    ///
    /// The session is inserted under `output.local.session_id` — the id this
    /// node advertised in Sigma1 — so inbound secured packets from the peer
    /// demux correctly. The peer's Node ID, Fabric ID, and session ID are
    /// pulled from `output` automatically.
    pub fn register_case(&mut self, output: &CaseSessionOutput, role: SessionRole) -> SessionId {
        let local_id = SessionId(output.local.session_id);
        let peer = PeerHint {
            node_id: Some(NodeId(output.peer.node_id)),
            fabric_id: Some(output.peer.fabric_id),
        };
        self.insert_session(
            local_id,
            SessionKeys::from_case_output(output),
            role,
            output.peer.session_id,
            peer,
        );
        // CASE sessions mix each side's OPERATIONAL node id into the AES-CCM
        // nonce (spec §4.8.2) — devices silently drop frames built with the
        // PASE-style zero nonce node id (observed: Tapo P110M, M6.6.5).
        if let Some(session) = self.sessions.get_mut(&local_id) {
            session.local_nonce_node_id = output.local.node_id;
            session.peer_nonce_node_id = output.peer.node_id;
        }
        local_id
    }

    /// Reserve and return the next free local session id WITHOUT creating a
    /// session. The commissioning driver allocates this first, advertises it
    /// in the handshake, then registers the finished session under the same
    /// id via [`Self::register_pase_with_local_id`] or
    /// [`Self::register_case`].
    pub fn allocate_session_id(&mut self) -> SessionId {
        self.allocate_id()
    }

    /// Register a completed PASE session under a caller-chosen local id (the
    /// id previously advertised to the peer via
    /// [`Self::allocate_session_id`]).
    ///
    /// Use this when the commissioning driver has already embedded the local
    /// session id in the handshake message (e.g. the `PBKDFParamRequest`
    /// `initiator_session_id` field) and must register the completed session
    /// under that same id so the peer's secured replies demux correctly.
    pub fn register_pase_with_local_id(
        &mut self,
        local_id: SessionId,
        keys: PaseSessionKeys,
        role: SessionRole,
        peer_session_id: u16,
        peer: PeerHint,
    ) {
        self.insert_session(
            local_id,
            SessionKeys::from(keys),
            role,
            peer_session_id,
            peer,
        );
    }

    fn register(
        &mut self,
        keys: SessionKeys,
        role: SessionRole,
        peer_session_id: u16,
        peer: PeerHint,
    ) -> SessionId {
        let local_id = self.allocate_id();
        self.insert_session(local_id, keys, role, peer_session_id, peer);
        local_id
    }

    /// Build and insert a [`Session`] under the given `local_id`.
    ///
    /// Any pre-existing session stored at `local_id` is silently replaced
    /// (the caller is responsible for ensuring uniqueness, e.g. by calling
    /// [`Self::allocate_session_id`] first).
    fn insert_session(
        &mut self,
        local_id: SessionId,
        keys: SessionKeys,
        role: SessionRole,
        peer_session_id: u16,
        peer: PeerHint,
    ) {
        // Session id 0 is reserved for the unsecured session (spec §4.4.4).
        // `allocate_id` never returns it, and a completed handshake must have
        // advertised a non-zero id; registering a secured session under 0 would
        // shadow the unsecured path. Guard the invariant (the CASE *resumption*
        // initiator still stubs its session id to 0 — that path must supply a
        // real id before it registers via `register_case`).
        debug_assert_ne!(
            local_id.0, 0,
            "secured session registered under reserved id 0"
        );
        let session = Session {
            local_id,
            peer_id: SessionId(peer_session_id),
            role,
            keys,
            outbound_counter: 1,
            replay_window: ReplayWindow::new(),
            peer,
            // PASE default: zero nonce node ids (spec §4.8.2). `register_case`
            // overwrites both with the operational node ids.
            local_nonce_node_id: 0,
            peer_nonce_node_id: 0,
            mrp: MrpState::new(MrpConfig::default()),
        };
        self.sessions.insert(local_id, session);
    }

    fn allocate_id(&mut self) -> SessionId {
        // Skip zero (reserved for unsecured sessions per spec §4.4.4).
        loop {
            if self.next_local_id == 0 {
                self.next_local_id = 1;
            }
            let candidate = SessionId(self.next_local_id);
            self.next_local_id = self.next_local_id.wrapping_add(1);
            if !self.sessions.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    /// Look up a session by its local ID.
    #[must_use]
    pub fn get(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
    }

    /// Mutable lookup.
    #[must_use]
    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(&id)
    }

    /// Drop a session (e.g. on close, on counter overflow, on attestation
    /// failure).
    pub fn remove(&mut self, id: SessionId) -> Option<Session> {
        self.sessions.remove(&id)
    }

    /// Encode an outbound Matter message via the named session.
    ///
    /// The pipeline is:
    /// 1. MRP builds the wire payload (protocol header || `app_payload`),
    ///    allocating a new exchange id if `exchange_id` is `None` and
    ///    draining any pending piggyback-ack that targets the same
    ///    exchange.
    /// 2. Framing encrypts the payload under the session keys, producing
    ///    the secured-message wire bytes.
    /// 3. MRP records the packet for retransmit if `mrp_flags.reliable` is
    ///    set, and updates the idle/active timing baseline regardless.
    ///
    /// # Errors
    ///
    /// - [`Error::UnknownSession`] if `session_id` does not exist.
    /// - [`Error::CounterOverflow`] if the session's outbound counter would
    ///   wrap past `u32::MAX`. The session must be re-keyed (a new PASE /
    ///   CASE handshake) to continue.
    /// - [`Error::PayloadTooLarge`] if the encoded wire payload (protocol
    ///   header + `app_payload`) exceeds the framing cap.
    #[allow(clippy::too_many_arguments)] // Threaded protocol-header inputs.
    pub fn encode_outbound(
        &mut self,
        session_id: SessionId,
        exchange_id: Option<u16>,
        opcode: u8,
        protocol_id: ProtocolId,
        app_payload: &[u8],
        mrp_flags: MrpFlags,
        now: Instant,
    ) -> Result<EncodeOutboundOutput> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(Error::UnknownSession(session_id.0))?;

        if session.outbound_counter == u32::MAX {
            return Err(Error::CounterOverflow);
        }

        // 1. MRP builds the wire payload (protocol header || app_payload).
        let prepared = session.mrp.prepare_outbound(
            opcode,
            protocol_id,
            exchange_id,
            app_payload,
            mrp_flags,
            now,
        )?;

        // 2. Framing encrypts.
        let secured_header = SecuredMessageHeader {
            flags: SecuredMessageFlags::empty(),
            session_id: session.peer_id,
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(session.outbound_counter),
            source_node_id: None,
            destination_node_id: None,
        };
        let wire_bytes = encode_secured(
            &secured_header,
            &prepared.wire_payload,
            &session.keys,
            session.role,
            session.local_nonce_node_id,
        )?;
        let counter = MessageCounter(session.outbound_counter);
        session.outbound_counter = session.outbound_counter.wrapping_add(1);

        // 3. Record the send. mark_packet_sent always updates the
        //    idle/active timing baseline; pending-ack registration is gated
        //    internally by the `reliable` flag.
        session.mrp.mark_packet_sent(
            counter,
            prepared.exchange_id,
            wire_bytes.clone(),
            mrp_flags.reliable,
            now,
        );

        Ok(EncodeOutboundOutput {
            wire_bytes,
            exchange_id: prepared.exchange_id,
            is_local_initiator: prepared.is_local_initiator,
            message_counter: counter,
            piggyback_acked: prepared.piggyback_acked,
        })
    }

    /// Decode + verify + replay-check an inbound packet, then dispatch into
    /// MRP for exchange / ack / duplicate-reliable handling.
    ///
    /// The replay window is consulted as part of [`decode_secured`]; if it
    /// rejects the counter the manager checks the per-session
    /// recent-reliable cache and, on a hit, builds a fresh standalone-ack
    /// packet to re-send (the
    /// [`DecodeInboundOutput::DuplicateReliableAckResent`] variant).
    ///
    /// # Errors
    ///
    /// - [`Error::MalformedHeader`] if the secured-message header is
    ///   malformed.
    /// - [`Error::UnknownSession`] if the header's `session_id` does not
    ///   match a registered session.
    /// - [`Error::ReplayedCounter`] / [`Error::CounterTooOld`] per the
    ///   session's replay window — but only when the counter is NOT a
    ///   recognised duplicate-reliable resend.
    /// - [`Error::DecryptionFailed`] on AES-CCM tag failure.
    /// - [`Error::MalformedProtocolHeader`] if the decrypted bytes do not
    ///   parse as a valid Matter protocol header.
    /// - [`Error::CounterOverflow`] if building a duplicate-reliable
    ///   standalone-ack packet would overflow the outbound counter.
    pub fn decode_inbound(&mut self, packet: &[u8], now: Instant) -> Result<DecodeInboundOutput> {
        // Peek the secured header to learn the session_id.
        let (peeked, _) = crate::framing::decode_header(packet)?;
        let local_id = peeked.session_id;
        let peer_counter = peeked.message_counter;

        let session = self
            .sessions
            .get_mut(&local_id)
            .ok_or(Error::UnknownSession(local_id.0))?;

        // Attempt full decode.
        match decode_secured(
            packet,
            &session.keys,
            session.role,
            &mut session.replay_window,
            session.peer_nonce_node_id,
        ) {
            Ok((_, decrypted)) => {
                let outcome = session.mrp.process_inbound(decrypted, peer_counter, now)?;
                Ok(match outcome {
                    InboundOutcome::AppMessage {
                        exchange_id,
                        is_initiator,
                        protocol_id,
                        opcode,
                        payload,
                    } => DecodeInboundOutput::AppMessage {
                        session_id: local_id,
                        exchange_id,
                        is_initiator,
                        protocol_id,
                        opcode,
                        payload,
                    },
                    InboundOutcome::AckOnly {
                        exchange_id,
                        acked_counter,
                    } => DecodeInboundOutput::AckOnly {
                        session_id: local_id,
                        exchange_id,
                        acked_counter,
                    },
                    InboundOutcome::DuplicateReliable { .. } => {
                        // process_inbound only emits DuplicateReliable on
                        // the replay-window rejection path, which is
                        // handled in the Err arm below. If we ever get
                        // here, MRP and the replay window are out of sync
                        // — surface as DecryptionFailed (the closest
                        // existing variant) rather than panicking.
                        return Err(Error::DecryptionFailed);
                    }
                })
            }
            Err(Error::ReplayedCounter { counter }) => {
                // Check whether MRP recognises this as a reliable duplicate.
                if let Some(view) = session
                    .mrp
                    .check_duplicate_reliable(MessageCounter(counter))
                {
                    let ack_packet = Self::build_standalone_ack_packet(
                        session,
                        view.exchange_id,
                        MessageCounter(counter),
                        view.is_local_initiator,
                    )?;
                    Ok(DecodeInboundOutput::DuplicateReliableAckResent {
                        session_id: local_id,
                        exchange_id: view.exchange_id,
                        ack_packet,
                    })
                } else {
                    Err(Error::ReplayedCounter { counter })
                }
            }
            Err(other) => Err(other),
        }
    }

    /// Earliest pending MRP deadline across every registered session, or
    /// `None` if no session has any pending retransmit or piggyback-ack
    /// flush deadline.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.sessions
            .values()
            .filter_map(|s| s.mrp.poll_timeout())
            .min()
    }

    /// Drain every session's MRP timer events at `now`, folding them into
    /// manager-wide [`MrpEvent`]s. Standalone-ack-deadline events are
    /// materialised into encrypted ack packets here (consuming a session
    /// outbound counter slot) so the caller only sees ready-to-send bytes.
    ///
    /// If building a standalone-ack packet for a session fails (e.g.
    /// counter overflow), the event is silently dropped — the caller will
    /// observe `Session::outbound_counter == u32::MAX` on the next
    /// `encode_outbound` and tear the session down.
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<MrpEvent> {
        let mut out = Vec::new();
        let session_ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for sid in session_ids {
            let timer_events = match self.sessions.get_mut(&sid) {
                Some(s) => s.mrp.handle_timeout(now),
                None => continue,
            };
            for event in timer_events {
                match event {
                    MrpTimerEvent::Retransmit {
                        exchange_id,
                        counter,
                        packet,
                    } => {
                        out.push(MrpEvent::Retransmit {
                            session_id: sid,
                            exchange_id,
                            counter,
                            packet,
                        });
                    }
                    MrpTimerEvent::Expired {
                        exchange_id,
                        counter,
                    } => {
                        out.push(MrpEvent::Expired {
                            session_id: sid,
                            exchange_id,
                            counter,
                        });
                    }
                    MrpTimerEvent::StandaloneAckDeadlineFired {
                        exchange_id,
                        ack_counter,
                        is_local_initiator,
                    } => {
                        // Build the standalone-ack packet (consumes one
                        // outbound counter slot). Lookup is fallible to
                        // keep the borrow checker happy and to tolerate
                        // mid-iteration session removal, even though we
                        // just listed the IDs from the same HashMap.
                        if let Some(session) = self.sessions.get_mut(&sid) {
                            if let Ok(packet) = Self::build_standalone_ack_packet(
                                session,
                                exchange_id,
                                ack_counter,
                                is_local_initiator,
                            ) {
                                out.push(MrpEvent::SendStandaloneAck {
                                    session_id: sid,
                                    exchange_id,
                                    packet,
                                });
                            }
                            // If build fails (CounterOverflow), drop the
                            // ack — caller will see outbound_counter at
                            // MAX and tear the session down.
                        }
                    }
                }
            }
        }
        out
    }

    /// Build a standalone-ack secured-message packet. Used by both
    /// [`Self::decode_inbound`]'s duplicate-reliable-resend path and
    /// [`Self::handle_timeout`]'s standalone-ack-deadline-fired path.
    ///
    /// Consumes one outbound counter slot on `session`.
    ///
    /// # Errors
    ///
    /// - [`Error::CounterOverflow`] if `session.outbound_counter` is
    ///   already `u32::MAX`.
    /// - [`Error::PayloadTooLarge`] surfacing from the underlying
    ///   [`encode_secured`] call (will not occur in practice for a
    ///   standalone-ack header — the encoded form is well under 16 bytes
    ///   — but is propagated for completeness).
    pub(crate) fn build_standalone_ack_packet(
        session: &mut Session,
        exchange_id: u16,
        ack_counter: MessageCounter,
        is_local_initiator: bool,
    ) -> Result<Vec<u8>> {
        if session.outbound_counter == u32::MAX {
            return Err(Error::CounterOverflow);
        }
        let header = build_standalone_ack_header(exchange_id, ack_counter, is_local_initiator);
        let mut payload = Vec::with_capacity(16);
        encode_protocol_header(&header, &mut payload);
        // No app payload.
        let secured_header = SecuredMessageHeader {
            flags: SecuredMessageFlags::empty(),
            session_id: session.peer_id,
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(session.outbound_counter),
            source_node_id: None,
            destination_node_id: None,
        };
        let packet = encode_secured(
            &secured_header,
            &payload,
            &session.keys,
            session.role,
            session.local_nonce_node_id,
        )?;
        session.outbound_counter = session.outbound_counter.wrapping_add(1);
        Ok(packet)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use std::time::Instant;

    use matter_crypto::pase::PaseSessionKeys;

    use super::*;
    use crate::mrp::MrpFlags;
    use crate::protocol_header::ProtocolId;

    /// Two `SessionManager`s sharing one symmetric key set, cross-registered as
    /// Initiator/Responder. Both allocate local id 1 (allocator starts at 1),
    /// so each side's `peer_session_id` is 1.
    fn paired_sessions() -> (SessionManager, SessionManager) {
        let keys = PaseSessionKeys {
            ke: [0u8; 16],
            i2r_key: [1u8; 16],
            r2i_key: [2u8; 16],
            attestation_key: [3u8; 16],
        };
        let mut a = SessionManager::new();
        let mut b = SessionManager::new();
        a.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
        b.register_pase(keys, SessionRole::Responder, 1, PeerHint::default());
        (a, b)
    }

    #[test]
    fn decode_inbound_surfaces_protocol_and_opcode() {
        let (mut a, mut b) = paired_sessions();
        let session = SessionId(1);
        let out = a
            .encode_outbound(
                session,
                None,
                0x08, // InvokeRequest
                ProtocolId::INTERACTION_MODEL,
                b"payload",
                MrpFlags { reliable: true },
                Instant::now(),
            )
            .unwrap();
        let DecodeInboundOutput::AppMessage {
            protocol_id,
            opcode,
            payload,
            ..
        } = b.decode_inbound(&out.wire_bytes, Instant::now()).unwrap()
        else {
            panic!("expected AppMessage");
        };
        assert_eq!(protocol_id, ProtocolId::INTERACTION_MODEL);
        assert_eq!(opcode, 0x08);
        assert_eq!(payload, b"payload");
    }
}
