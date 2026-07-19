//! Matter network transport: secured-message framing, session management,
//! UDP, mDNS, and MRP reliability.
//!
//! Milestone 5 of the `matter-rust` roadmap. Consumes session keys
//! produced by completed PASE handshakes (`matter_crypto::pase`) or
//! CASE handshakes (`matter_crypto::case`) and ships them over the wire
//! in Matter's secured-message format.
//!
//! # Phase status
//!
//! - **M5.1:** framing + session manager skeleton.
//! - **M5.2:** MRP + application protocol header codec.
//! - **M5.3 (this revision):** Transport + Discovery traits + default
//!   Tokio UDP + mdns-sd adapters. Crate reaches `0.1.0-pre`.
//!
//! # Cargo features
//!
#![cfg_attr(
    feature = "tokio",
    doc = "- `tokio` (default): enables [`tokio_udp::TokioUdpTransport`] and the `Error::Io` variant."
)]
#![cfg_attr(
    not(feature = "tokio"),
    doc = "- `tokio` (default): enables `tokio_udp::TokioUdpTransport` and the `Error::Io` variant."
)]
#![cfg_attr(
    feature = "mdns-sd",
    doc = "- `mdns-sd` (default): enables [`mdns_sd_discovery::MdnsSdDiscovery`] and the `Error::Mdns` variant."
)]
#![cfg_attr(
    not(feature = "mdns-sd"),
    doc = "- `mdns-sd` (default): enables `mdns_sd_discovery::MdnsSdDiscovery` and the `Error::Mdns` variant."
)]
//!
//! Embedded callers disable defaults: the sans-IO core (framing, MRP,
//! protocol header, session manager, `Transport`/`Discovery` traits)
//! is always available.

#![forbid(unsafe_code)]

pub mod discovery;
pub mod error;
pub mod framing;
pub mod local_addr;
pub mod mrp;
pub mod protocol_header;
pub mod session;
pub mod transport;

#[cfg(feature = "tokio")]
pub mod tokio_udp;

#[cfg(feature = "mdns-sd")]
pub mod mdns_sd_discovery;

pub use error::{Error, Result};
pub use framing::{
    build_group_privacy_nonce, decode_group_secured, decode_header, decode_secured,
    encode_group_secured, encode_header, encode_secured, DestNodeId, MessageCounter, NodeId,
    ReplayWindow, SecuredMessageFlags, SecuredMessageHeader, SecurityFlags, SessionId,
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

pub use discovery::{Discovery, MatterService, QueryHandle, ServiceKind};
pub use local_addr::local_advertise_addrs;
pub use transport::{PeerAddress, Transport};

#[cfg(feature = "tokio")]
pub use tokio_udp::TokioUdpTransport;

#[cfg(feature = "mdns-sd")]
pub use mdns_sd_discovery::MdnsSdDiscovery;
