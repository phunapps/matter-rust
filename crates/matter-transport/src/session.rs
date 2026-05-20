//! Per-session state and the `SessionManager` that owns it.
//!
//! Implemented in Task 6 of the M5.1 plan.

#![allow(missing_docs, dead_code)]

use crate::framing::{NodeId, ReplayWindow, SessionId};

/// Which side of the session this end is. Decides whether `encode_secured`
/// uses `i2r_key` or `r2i_key` (and `decode_secured` uses the opposite).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// We sent the first message (PASE prover / CASE initiator).
    Initiator,
    /// We received the first message (PASE verifier / CASE responder).
    Responder,
}

/// Symmetric key material for a single session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Encrypts traffic flowing initiator → responder.
    pub i2r_key: [u8; 16],
    /// Encrypts traffic flowing responder → initiator.
    pub r2i_key: [u8; 16],
    /// Attestation challenge key (PASE) / attestation challenge (CASE).
    pub attestation_key: [u8; 16],
}

/// Light identity hint about the peer, captured at registration time so
/// inbound packets can be routed and outbound headers populated. Task 6
/// fleshes this out.
#[derive(Debug, Clone, Default)]
pub struct PeerHint {
    pub node_id: Option<NodeId>,
    pub fabric_id: Option<u64>,
}

/// Single session — keys, counters, replay tracking, role.
#[derive(Debug)]
pub struct Session {
    pub local_id: SessionId,
    pub peer_id: SessionId,
    pub role: SessionRole,
    pub keys: SessionKeys,
    pub outbound_counter: u32,
    pub replay_window: ReplayWindow,
    pub peer: PeerHint,
}

/// Owns all per-session state for one Matter node. Filled in by Task 6.
#[derive(Debug, Default)]
pub struct SessionManager {
    _todo: (),
}
