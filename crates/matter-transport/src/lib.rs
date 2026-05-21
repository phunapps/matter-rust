//! Matter network transport: secured-message framing, session management,
//! UDP, mDNS, and MRP reliability.
//!
//! Milestone 5 of the `matter-rust` roadmap. This crate consumes session
//! keys produced by completed PASE handshakes (`matter_crypto::pase`) or
//! CASE handshakes (`matter_crypto::case`) and ships them over the wire
//! in Matter's secured-message format (Matter Core Specification §4.4).
//!
//! # Phase status
//!
//! - **M5.1 (this revision):** framing + session manager skeleton.
//! - **M5.2 (next):** MRP — Matter's transport-layer reliability over UDP.
//! - **M5.3 (after):** Tokio UDP transport + mdns-sd discovery. README +
//!   version bump to `0.1.0-pre`.
//!
//! # Scope
//!
//! - [`framing`]: Matter secured-message header encode/decode + AES-CCM-128
//!   payload encryption + sliding-window replay protection.
//! - [`session`]: per-session key + counter + replay state, owned by
//!   [`session::SessionManager`].
//! - [`error`]: the crate error type.
//! - [`mrp`]: (placeholder — M5.2 work).
//! - [`udp`]: (placeholder — M5.3 work).
//! - [`mdns`]: (placeholder — M5.3 work).

#![forbid(unsafe_code)]

pub mod error;
pub mod framing;
pub mod mdns;
pub mod mrp;
pub mod protocol_header;
pub mod session;
pub mod udp;

pub use error::{Error, Result};
pub use framing::{
    decode_secured, encode_secured, DestNodeId, MessageCounter, NodeId, ReplayWindow,
    SecuredMessageFlags, SecuredMessageHeader, SecurityFlags, SessionId,
};
pub use mrp::{
    InboundOutcome, MrpConfig, MrpEvent, MrpFlags, MrpState, MrpTimerEvent, PreparedOutbound,
    RecentInboundView,
};
pub use protocol_header::{
    build_standalone_ack_header, decode_protocol_header, encode_protocol_header, ExchangeFlags,
    ProtocolHeader, ProtocolId,
};
pub use session::{
    DecodeInboundOutput, EncodeOutboundOutput, PeerHint, Session, SessionKeys, SessionManager,
    SessionRole,
};
