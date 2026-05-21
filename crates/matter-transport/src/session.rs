//! Per-session state and the [`SessionManager`] that owns it.
//!
//! M5.1 ships:
//! - [`SessionRole`], [`SessionKeys`], [`PeerHint`], [`Session`].
//! - [`SessionManager`] with `register_pase` / `register_case` /
//!   `encode_outbound` / `decode_inbound` / `get` / `get_mut` / `remove`.
//!
//! MRP-related methods (`poll_timeout`, `handle_timeout`) are added in
//! M5.2; their signatures are reserved here.

use std::collections::HashMap;

use matter_crypto::case::CaseSessionOutput;
use matter_crypto::pase::PaseSessionKeys;

use crate::error::{Error, Result};
use crate::framing::{
    decode_secured, encode_secured, MessageCounter, NodeId, ReplayWindow, SecuredMessageFlags,
    SecuredMessageHeader, SecurityFlags, SessionId,
};

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

/// Single session — keys, counters, replay tracking, role, peer hint.
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
    /// Pulls the peer's Node ID, Fabric ID, and session ID out of the CASE
    /// output so the caller does not need to repeat them.
    pub fn register_case(&mut self, output: &CaseSessionOutput, role: SessionRole) -> SessionId {
        let peer = PeerHint {
            node_id: Some(NodeId(output.peer.node_id)),
            fabric_id: Some(output.peer.fabric_id),
        };
        self.register(
            SessionKeys::from_case_output(output),
            role,
            output.peer.session_id,
            peer,
        )
    }

    fn register(
        &mut self,
        keys: SessionKeys,
        role: SessionRole,
        peer_session_id: u16,
        peer: PeerHint,
    ) -> SessionId {
        let local_id = self.allocate_id();
        let session = Session {
            local_id,
            peer_id: SessionId(peer_session_id),
            role,
            keys,
            outbound_counter: 1,
            replay_window: ReplayWindow::new(),
            peer,
        };
        self.sessions.insert(local_id, session);
        local_id
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

    /// Encode an outbound Matter message via the named session. Bumps the
    /// session's outbound counter; returns the wire bytes.
    ///
    /// MRP fields are accepted for forward compatibility but ignored in
    /// M5.1 — M5.2 wires them into the protocol header.
    ///
    /// # Errors
    ///
    /// - [`Error::UnknownSession`] if `session_id` does not exist.
    /// - [`Error::CounterOverflow`] if the outbound counter would wrap
    ///   past `u32::MAX`. The session must be re-keyed.
    /// - [`Error::PayloadTooLarge`] if `payload` exceeds the framing
    ///   cap.
    pub fn encode_outbound(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
        _mrp: crate::mrp::MrpFlags,
    ) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(Error::UnknownSession(session_id.0))?;

        if session.outbound_counter == u32::MAX {
            return Err(Error::CounterOverflow);
        }

        let header = SecuredMessageHeader {
            flags: SecuredMessageFlags::empty(),
            session_id: session.peer_id,
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(session.outbound_counter),
            source_node_id: None,
            destination_node_id: None,
        };
        let wire = encode_secured(&header, payload, &session.keys, session.role)?;
        session.outbound_counter = session.outbound_counter.wrapping_add(1);
        Ok(wire)
    }

    /// Decode + verify + replay-check an inbound packet. Returns the
    /// plaintext payload and the local session ID it belongs to.
    ///
    /// # Errors
    ///
    /// - [`Error::MalformedHeader`] if the header bytes cannot be parsed.
    /// - [`Error::UnknownSession`] if the header's `session_id` does not
    ///   match a registered session.
    /// - [`Error::ReplayedCounter`] / [`Error::CounterTooOld`] per the
    ///   session's replay window.
    /// - [`Error::DecryptionFailed`] on AES-CCM tag failure.
    pub fn decode_inbound(&mut self, packet: &[u8]) -> Result<(SessionId, Vec<u8>)> {
        // Peek at the header to learn the session ID. We re-parse fully
        // inside decode_secured below, but this peek is the only way to
        // route by session_id without doubling the cost.
        let (peeked, _) = crate::framing::decode_header(packet)?;
        let local_id = peeked.session_id;
        let session = self
            .sessions
            .get_mut(&local_id)
            .ok_or(Error::UnknownSession(local_id.0))?;

        let (_header, plaintext) = decode_secured(
            packet,
            &session.keys,
            session.role,
            &mut session.replay_window,
        )?;
        Ok((local_id, plaintext))
    }
}
