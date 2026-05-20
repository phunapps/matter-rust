//! Matter secured-message framing (Core Spec §4.4) and reception state.
//!
//! Implemented in M5.1.
//!
//! This module is filled in incrementally across Tasks 2, 3, 4, and 5 of the
//! M5.1 plan. The current revision only declares names so the surrounding
//! crate compiles between intermediate commits.

#![allow(missing_docs, dead_code, unused_imports, clippy::missing_errors_doc)]

use bitflags::bitflags;

bitflags! {
    /// Top byte of the secured-message header. See Matter Core Spec §4.4.1.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecuredMessageFlags: u8 {
        // Filled in by Task 2.
        const _PLACEHOLDER = 0;
    }

    /// Security-flags byte. See Matter Core Spec §4.4.1.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecurityFlags: u8 {
        // Filled in by Task 2.
        const _PLACEHOLDER = 0;
    }
}

/// Peer-allocated session identifier carried in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u16);

/// 32-bit monotonic message counter, per Matter Core Spec §4.4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageCounter(pub u32);

/// 64-bit Node ID used in source/destination header fields and the AES-CCM
/// nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeId(pub u64);

/// Destination address: either a unicast 64-bit Node ID or a 16-bit Group ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestNodeId {
    /// Unicast — `DSIZ = 0b01`.
    Node(NodeId),
    /// Multicast group — `DSIZ = 0b10`.
    Group(u16),
}

/// Parsed view of the secured-message header (everything before the
/// encrypted payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuredMessageHeader {
    pub flags: SecuredMessageFlags,
    pub session_id: SessionId,
    pub security_flags: SecurityFlags,
    pub message_counter: MessageCounter,
    pub source_node_id: Option<NodeId>,
    pub destination_node_id: Option<DestNodeId>,
}

/// Sliding-window dedup for inbound message counters per Matter Core Spec
/// §4.4.3. Filled in by Task 3.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    // Task 3 replaces this body.
    _todo: (),
}

/// Encode a secured Matter message. Filled in by Task 5.
pub fn encode_secured(
    _header: &SecuredMessageHeader,
    _payload: &[u8],
    _keys: &crate::session::SessionKeys,
    _role: crate::session::SessionRole,
) -> crate::Result<Vec<u8>> {
    unimplemented!("filled in by Task 5")
}

/// Decode a secured Matter message. Filled in by Task 5.
pub fn decode_secured(
    _bytes: &[u8],
    _keys: &crate::session::SessionKeys,
    _role: crate::session::SessionRole,
    _replay_window: &mut ReplayWindow,
) -> crate::Result<(SecuredMessageHeader, Vec<u8>)> {
    unimplemented!("filled in by Task 5")
}
