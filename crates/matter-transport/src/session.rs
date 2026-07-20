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
#[non_exhaustive]
pub struct PeerHint {
    /// Peer's operational Node ID (CASE only).
    pub node_id: Option<NodeId>,
    /// Peer's fabric ID (CASE only).
    pub fabric_id: Option<u64>,
}

/// Single session — keys, counters, replay tracking, role, peer hint, MRP
/// state.
#[derive(Debug)]
#[non_exhaustive]
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
    /// True when the underlying transport is reliable and ordered (BTP).
    /// Forces MRP off for this session per Matter spec 4.12: outbound R-flag
    /// suppressed, no retransmit registration, no inbound ack scheduling.
    /// Mirrors chip's `SecureSession::AllowsMRP()`, which returns `false`
    /// whenever the session's transport type is not UDP.
    pub transport_reliable: bool,
    /// Monotonic creation sequence, assigned by [`SessionManager`] on insert.
    /// Used ONLY to pick the oldest session to evict when the table hits its
    /// cap; not part of the wire or session identity.
    pub(crate) created_seq: u64,
}

/// Structured output of [`SessionManager::encode_outbound`]. Carries the
/// wire bytes plus the bookkeeping the caller needs to track the message
/// (exchange id, counter, whether a piggyback ack was attached).
#[derive(Debug)]
#[non_exhaustive]
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
#[non_exhaustive]
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

/// Default cap on the number of concurrently-registered secured sessions.
///
/// Bounds the session table's memory as defense-in-depth: a peer (or a flood of
/// half-open handshakes that complete) cannot grow the table without limit.
/// Sized far above any realistic controller workload (a home has tens of
/// devices, each typically one operational session), so legitimate use never
/// approaches it; tune via [`SessionManager::set_max_sessions`].
pub const DEFAULT_MAX_SESSIONS: usize = 256;

/// Owns all per-session state for one Matter node.
#[derive(Debug)]
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    next_local_id: u16,
    /// Monotonic counter stamped onto each session as `created_seq`, so the
    /// oldest can be identified for eviction when the table is full.
    next_seq: u64,
    /// Cap on `sessions.len()`; inserting into a full table evicts the oldest.
    max_sessions: usize,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    /// Create an empty manager with the default session cap
    /// ([`DEFAULT_MAX_SESSIONS`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_local_id: 1,
            next_seq: 0,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }

    /// Override the maximum number of concurrently-registered sessions. Values
    /// below 1 are clamped to 1 (the table must hold at least the session being
    /// registered). Registering into a full table evicts the oldest session.
    pub fn set_max_sessions(&mut self, max_sessions: usize) {
        self.max_sessions = max_sessions.max(1);
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
        self.register_case_with_mrp(output, role, MrpConfig::default())
    }

    /// [`Self::register_case`] but with the peer's advertised MRP retransmit
    /// config (from its operational mDNS TXT `SII`/`SAI`/`SAT`, via
    /// [`MatterService::peer_mrp_config`](crate::MatterService::peer_mrp_config)).
    ///
    /// Sizing retransmits to the peer's own parameters is what keeps us from
    /// hammering a sleepy device that polls on a long idle interval (MRP-2).
    /// The freshly-registered session has no pending MRP state yet, so applying
    /// the config here (right at creation, before any traffic) is safe.
    pub fn register_case_with_mrp(
        &mut self,
        output: &CaseSessionOutput,
        role: SessionRole,
        mrp_config: MrpConfig,
    ) -> SessionId {
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
            session.mrp = MrpState::new(mrp_config);
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
        // DoS defense: bound the table. If it is at capacity and this is a NEW
        // local id (a replacement of an existing id does not grow the table),
        // evict a victim before inserting. IDLE-FIRST: prefer a session with no
        // in-flight reliable work (`mrp.has_pending() == false`) over one
        // mid-exchange, so a burst of new sessions never tears down an active
        // handshake while an idle session is reclaimable; break ties by oldest
        // (`created_seq`). `false < true`, so the tuple key sorts idle sessions
        // ahead of busy ones.
        if self.sessions.len() >= self.max_sessions && !self.sessions.contains_key(&local_id) {
            if let Some(victim) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| (s.mrp.has_pending(), s.created_seq))
                .map(|(id, _)| *id)
            {
                self.sessions.remove(&victim);
            }
        }
        let created_seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
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
            // Default false everywhere sessions are constructed: MRP stays
            // on unless the caller explicitly opts a session into a
            // reliable transport via `set_transport_reliable`.
            transport_reliable: false,
            created_seq,
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

    /// Number of currently-registered secured sessions. Never exceeds the cap
    /// set by [`Self::set_max_sessions`] (default [`DEFAULT_MAX_SESSIONS`]).
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
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

    /// Mark a session as running over a reliable, ordered transport (BTP).
    /// Forces MRP off for the session per Matter spec 4.12 (see
    /// [`Session::transport_reliable`]).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSession`] if `id` does not name a registered session.
    pub fn set_transport_reliable(&mut self, id: SessionId, reliable: bool) -> Result<()> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(Error::UnknownSession(id.0))?;
        session.transport_reliable = reliable;
        Ok(())
    }

    /// Read a session's [`Session::transport_reliable`] flag.
    ///
    /// Returns `None` if `id` does not name a registered session.
    #[must_use]
    pub fn is_transport_reliable(&self, id: SessionId) -> Option<bool> {
        self.sessions.get(&id).map(|s| s.transport_reliable)
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

        // A transport_reliable session (BTP) forces MRP off regardless of
        // what the caller asked for: the underlying transport already
        // guarantees ordered, reliable delivery, so we never set the R bit
        // and never register a retransmit for this send. Mirrors chip's
        // `SecureSession::AllowsMRP()`.
        let effective_mrp_flags = MrpFlags {
            reliable: mrp_flags.reliable && !session.transport_reliable,
        };

        // 1. MRP builds the wire payload (protocol header || app_payload).
        let prepared = session.mrp.prepare_outbound(
            opcode,
            protocol_id,
            exchange_id,
            app_payload,
            effective_mrp_flags,
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
        //    internally by the `reliable` flag (already folded down to
        //    `effective_mrp_flags` above, so a transport_reliable session
        //    never registers a retransmit). The retransmit buffer is only
        //    retained for reliable messages, so we clone the wire bytes ONLY
        //    when `reliable` is set — an unreliable send hands `mark_packet_sent`
        //    an empty Vec (which it drops without copying), avoiding a full
        //    packet copy on every fire-and-forget datagram.
        let retransmit_copy = if effective_mrp_flags.reliable {
            wire_bytes.clone()
        } else {
            Vec::new()
        };
        session.mrp.mark_packet_sent(
            counter,
            prepared.exchange_id,
            retransmit_copy,
            effective_mrp_flags.reliable,
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
                // A transport_reliable session (BTP) skips ack scheduling
                // entirely, even if the peer's message carried R=1:
                // `process_inbound` above unconditionally arms a
                // standalone-ack deadline for a reliable-flagged inbound, so
                // undo that here rather than threading the flag through MRP.
                // Defensive only — a well-behaved BTP peer never sets R.
                if session.transport_reliable {
                    if let InboundOutcome::AppMessage { exchange_id, .. } = &outcome {
                        session.mrp.cancel_pending_outbound_ack(*exchange_id);
                    }
                }
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
    /// If building a standalone-ack packet fails because the session's
    /// outbound counter is exhausted, a [`MrpEvent::SessionCounterExhausted`]
    /// is emitted instead of the ack: the counter cannot wrap (Matter Core
    /// Spec §4.4.3), so the session must be re-keyed. Surfacing the event
    /// (rather than silently dropping the ack) lets the caller tear the
    /// session down promptly instead of leaving the peer un-acked with no
    /// signal.
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
                            match Self::build_standalone_ack_packet(
                                session,
                                exchange_id,
                                ack_counter,
                                is_local_initiator,
                            ) {
                                Ok(packet) => out.push(MrpEvent::SendStandaloneAck {
                                    session_id: sid,
                                    exchange_id,
                                    packet,
                                }),
                                Err(Error::CounterOverflow) => {
                                    // The outbound counter is exhausted, so the
                                    // ack cannot be sent without an illegal
                                    // counter wrap (Matter Core Spec §4.4.3).
                                    // Surface it rather than silently dropping
                                    // the ack: the caller must re-key the
                                    // session, and emitting the event lets it
                                    // tear the session down promptly instead of
                                    // leaving the peer un-acked with no signal.
                                    out.push(MrpEvent::SessionCounterExhausted {
                                        session_id: sid,
                                        exchange_id,
                                        ack_counter,
                                    });
                                }
                                Err(_) => {
                                    // Any other build failure (e.g.
                                    // PayloadTooLarge) cannot occur for a
                                    // standalone-ack header in practice; drop
                                    // the event defensively.
                                }
                            }
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

    /// An UNRELIABLE outbound must NOT register a retransmit entry — there is
    /// no pending deadline afterwards. This pins the perf fix that skips the
    /// retransmit-buffer clone for fire-and-forget datagrams: a clone is only
    /// worthwhile if MRP will actually hold the bytes for re-send.
    #[test]
    fn unreliable_outbound_registers_no_retransmit() {
        let (mut a, _b) = paired_sessions();
        let now = Instant::now();
        a.encode_outbound(
            SessionId(1),
            None,
            0x08,
            ProtocolId::INTERACTION_MODEL,
            b"fire-and-forget",
            MrpFlags { reliable: false },
            now,
        )
        .unwrap();
        assert_eq!(
            a.poll_timeout(),
            None,
            "an unreliable send must not schedule a retransmit"
        );
    }

    /// An unreliable round-trip still decodes correctly. This exercises the
    /// AAD-slice path in `decode_secured` (the AAD is sliced from the input
    /// header bytes rather than re-encoded) and the in-place payload split in
    /// MRP `process_inbound` on a non-reliable packet.
    #[test]
    fn unreliable_roundtrip_decodes() {
        let (mut a, mut b) = paired_sessions();
        let out = a
            .encode_outbound(
                SessionId(1),
                None,
                0x08,
                ProtocolId::INTERACTION_MODEL,
                b"unreliable payload",
                MrpFlags { reliable: false },
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
        assert_eq!(payload, b"unreliable payload");
    }

    /// When a standalone-ack is due but the session's outbound counter is
    /// exhausted (`u32::MAX`), `handle_timeout` must SURFACE the condition
    /// (via `MrpEvent::SessionCounterExhausted`) rather than silently
    /// dropping the ack and leaving the peer un-acked with no signal.
    #[test]
    fn standalone_ack_counter_overflow_surfaces_event() {
        let (_a, mut b) = paired_sessions();
        let session_id = SessionId(1);
        let now = Instant::now();

        // Buffer a reliable inbound on `b` so a standalone-ack becomes due.
        // We hand-build a reliable inbound payload directly through MRP so we
        // don't need a real encrypted frame from `a`.
        {
            let session = b.sessions.get_mut(&session_id).unwrap();
            let header = crate::protocol_header::ProtocolHeader {
                exchange_flags: crate::protocol_header::ExchangeFlags::INITIATOR
                    | crate::protocol_header::ExchangeFlags::RELIABLE,
                opcode: 0x02,
                exchange_id: 0x4242,
                protocol_id: ProtocolId::INTERACTION_MODEL,
                ack_counter: None,
            };
            let mut payload = Vec::new();
            encode_protocol_header(&header, &mut payload);
            session
                .mrp
                .process_inbound(payload, MessageCounter(100), now)
                .unwrap();
            // Force the outbound counter to the exhaustion point.
            session.outbound_counter = u32::MAX;
        }

        // Fire the standalone-ack deadline. The ack cannot be built (counter
        // exhausted), so we must see a SessionCounterExhausted event.
        let events = b.handle_timeout(now + std::time::Duration::from_millis(200));
        assert!(
            events.iter().any(|e| matches!(
                e,
                MrpEvent::SessionCounterExhausted {
                    session_id: s,
                    exchange_id: 0x4242,
                    ack_counter,
                } if *s == session_id && *ack_counter == MessageCounter(100)
            )),
            "counter-overflow standalone-ack must surface SessionCounterExhausted, got {events:?}"
        );
    }

    /// A `transport_reliable` session must never set the protocol header's
    /// R (reliable) bit, even when the caller passes `mrp_flags.reliable =
    /// true` — the underlying transport (BTP) already guarantees ordered,
    /// reliable delivery, so MRP's own reliability layer must stay off.
    #[test]
    fn transport_reliable_suppresses_r_bit() {
        let (mut a, b) = paired_sessions();
        a.get_mut(SessionId(1)).unwrap().transport_reliable = true;
        let now = Instant::now();
        let out = a
            .encode_outbound(
                SessionId(1),
                None,
                0x08,
                ProtocolId::INTERACTION_MODEL,
                b"payload",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();

        let b_session = b.get(SessionId(1)).unwrap();
        let mut replay_window = ReplayWindow::new();
        let (_, plaintext) = crate::framing::decode_secured(
            &out.wire_bytes,
            &b_session.keys,
            SessionRole::Responder,
            &mut replay_window,
            0,
        )
        .unwrap();
        let (header, _) = crate::protocol_header::decode_protocol_header(&plaintext).unwrap();
        assert!(
            !header
                .exchange_flags
                .contains(crate::protocol_header::ExchangeFlags::RELIABLE),
            "transport_reliable session must suppress the R bit, got flags {:?}",
            header.exchange_flags
        );
    }

    /// A `transport_reliable` outbound must not register a retransmit entry
    /// even when `mrp_flags.reliable` is true — no pending deadline
    /// afterwards.
    #[test]
    fn transport_reliable_skips_retransmit_registration() {
        let (mut a, _b) = paired_sessions();
        a.get_mut(SessionId(1)).unwrap().transport_reliable = true;
        let now = Instant::now();
        a.encode_outbound(
            SessionId(1),
            None,
            0x08,
            ProtocolId::INTERACTION_MODEL,
            b"payload",
            MrpFlags { reliable: true },
            now,
        )
        .unwrap();
        assert_eq!(
            a.poll_timeout(),
            None,
            "a transport_reliable session must not register a retransmit even when mrp_flags.reliable is set"
        );
    }

    /// Defensive check: even if a (buggy) peer sets R=1 on an inbound
    /// message, a `transport_reliable` receiving session must not arm a
    /// standalone-ack timer for it.
    #[test]
    fn transport_reliable_skips_inbound_ack_scheduling() {
        let (mut a, mut b) = paired_sessions();
        b.get_mut(SessionId(1)).unwrap().transport_reliable = true;
        let now = Instant::now();
        let out = a
            .encode_outbound(
                SessionId(1),
                None,
                0x08,
                ProtocolId::INTERACTION_MODEL,
                b"payload",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        b.decode_inbound(&out.wire_bytes, now).unwrap();
        assert_eq!(
            b.poll_timeout(),
            None,
            "a transport_reliable session must not arm a standalone-ack timer even for a reliable-flagged inbound"
        );
    }

    #[test]
    fn set_transport_reliable_unknown_session_errors() {
        let mut a = SessionManager::new();
        let err = a.set_transport_reliable(SessionId(42), true).unwrap_err();
        assert!(matches!(err, Error::UnknownSession(42)));
    }

    #[test]
    fn is_transport_reliable_reflects_flag_and_unknown_session() {
        let (mut a, _b) = paired_sessions();
        assert_eq!(a.is_transport_reliable(SessionId(1)), Some(false));
        a.set_transport_reliable(SessionId(1), true).unwrap();
        assert_eq!(a.is_transport_reliable(SessionId(1)), Some(true));
        assert_eq!(a.is_transport_reliable(SessionId(99)), None);
    }

    // TRAN-1: the duplicate-reliable re-ack decision must be made only AFTER
    // the message authenticates. An attacker who has observed a reliable
    // frame's plaintext header (session id + counter are cleartext) must not
    // be able to replay that header with any ciphertext and make us emit an
    // encrypted standalone ack + burn an outbound counter.
    #[test]
    fn tran1_forged_replay_emits_no_ack_and_burns_no_counter() {
        let (mut a, mut b) = paired_sessions();
        let now = Instant::now();
        // a -> b, RELIABLE: b records the counter and owes a reliable ack.
        let out = a
            .encode_outbound(
                SessionId(1),
                None,
                0x08,
                ProtocolId::INTERACTION_MODEL,
                b"payload",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        let _ = b.decode_inbound(&out.wire_bytes, now).unwrap();

        let before = b.sessions[&SessionId(1)].outbound_counter;

        // Forged: same header (valid session id + already-used reliable
        // counter) but a corrupted AEAD tag — never authenticates.
        let mut forged = out.wire_bytes.clone();
        let n = forged.len();
        forged[n - 1] ^= 0xFF;
        forged[n - 2] ^= 0xFF;

        let result = b.decode_inbound(&forged, now);
        assert!(
            !matches!(
                result,
                Ok(DecodeInboundOutput::DuplicateReliableAckResent { .. })
            ),
            "an unauthenticated replay must not emit a standalone ack; got {result:?}"
        );
        assert!(
            matches!(result, Err(Error::DecryptionFailed)),
            "forged ciphertext must fail authentication; got {result:?}"
        );
        assert_eq!(
            before,
            b.sessions[&SessionId(1)].outbound_counter,
            "no outbound counter may be burned by an unauthenticated replay"
        );
    }

    // Regression guard for the TRAN-1 fix: a genuine, AUTHENTICATED reliable
    // duplicate (a lost-ack retransmit) must still be re-acked — the fix must
    // not break MRP's legitimate duplicate handling.
    #[test]
    fn tran1_authentic_reliable_duplicate_is_still_reacked() {
        let (mut a, mut b) = paired_sessions();
        let now = Instant::now();
        let out = a
            .encode_outbound(
                SessionId(1),
                None,
                0x08,
                ProtocolId::INTERACTION_MODEL,
                b"payload",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();
        let first = b.decode_inbound(&out.wire_bytes, now).unwrap();
        assert!(matches!(first, DecodeInboundOutput::AppMessage { .. }));
        // Authentic retransmit of the exact same (authenticated) bytes.
        let second = b.decode_inbound(&out.wire_bytes, now).unwrap();
        assert!(
            matches!(
                second,
                DecodeInboundOutput::DuplicateReliableAckResent { .. }
            ),
            "an authenticated reliable duplicate must be re-acked; got {second:?}"
        );
    }

    #[test]
    fn session_table_is_bounded_and_evicts_oldest() {
        // DoS defense: the table never exceeds its cap; a new registration into
        // a full table evicts the OLDEST session, keeping the newest.
        let keys = PaseSessionKeys {
            ke: [0u8; 16],
            i2r_key: [1u8; 16],
            r2i_key: [2u8; 16],
            attestation_key: [3u8; 16],
        };
        let mut m = SessionManager::new();
        m.set_max_sessions(3);
        let id1 = m.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
        let id2 = m.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
        let id3 = m.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
        assert_eq!(m.session_count(), 3);

        // A 4th registration evicts the oldest (id1) and stays capped.
        let id4 = m.register_pase(keys, SessionRole::Initiator, 1, PeerHint::default());
        assert_eq!(m.session_count(), 3, "table stays capped at 3");
        assert!(m.get(id1).is_none(), "oldest session (id1) was evicted");
        assert!(m.get(id2).is_some());
        assert!(m.get(id3).is_some());
        assert!(m.get(id4).is_some());
    }

    #[test]
    fn session_eviction_prefers_idle_over_busy() {
        use crate::mrp::MrpFlags;
        use crate::protocol_header::ProtocolId;

        // idle-first: a session mid-exchange (in-flight reliable work) is spared
        // in favor of a truly-idle one, even though the busy session is OLDER.
        let keys = PaseSessionKeys {
            ke: [0u8; 16],
            i2r_key: [1u8; 16],
            r2i_key: [2u8; 16],
            attestation_key: [3u8; 16],
        };
        let mut m = SessionManager::new();
        m.set_max_sessions(2);
        let busy = m.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
        let idle = m.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());

        // Give the OLDER session in-flight reliable work (a pending retransmit).
        let now = std::time::Instant::now();
        let _ = m
            .encode_outbound(
                busy,
                None,
                0x02,
                ProtocolId::INTERACTION_MODEL,
                b"x",
                MrpFlags { reliable: true },
                now,
            )
            .unwrap();

        // A 3rd registration into the full (cap 2) table must evict the IDLE
        // session, NOT the older busy one mid-exchange.
        let fresh = m.register_pase(keys, SessionRole::Initiator, 1, PeerHint::default());
        assert_eq!(m.session_count(), 2, "table stays capped at 2");
        assert!(
            m.get(busy).is_some(),
            "the busy (mid-exchange) session is spared despite being older",
        );
        assert!(m.get(idle).is_none(), "the idle session is evicted first");
        assert!(m.get(fresh).is_some());
    }
}
