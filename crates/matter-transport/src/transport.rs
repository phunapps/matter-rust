//! Sans-IO `Transport` trait + `PeerAddress` newtype.
//!
//! The trait is what embedded callers (Embassy, smoltcp, custom HAL)
//! implement to plug their own UDP stack into the rest of
//! `matter-transport`. The default Tokio adapter
//! ([`crate::tokio_udp::TokioUdpTransport`]) implements it over
//! `tokio::net::UdpSocket` when the `tokio` Cargo feature is enabled.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::error::Result;

/// Network endpoint for a Matter peer.
///
/// Newtype around [`std::net::SocketAddr`] so IPv6 link-local zone IDs
/// ride along inside [`SocketAddrV6::scope_id`]. Implementing
/// [`Transport`] adapters honour the `scope_id` field at send time so
/// link-local addresses route to the correct interface on multi-NIC
/// hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerAddress(pub SocketAddr);

impl PeerAddress {
    /// Construct from an IPv6 address + port. `scope_id` and `flowinfo`
    /// default to 0.
    #[must_use]
    pub const fn from_ipv6(ip: Ipv6Addr, port: u16) -> Self {
        Self(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
    }

    /// Construct from an IPv4 address + port.
    #[must_use]
    pub const fn from_ipv4(ip: Ipv4Addr, port: u16) -> Self {
        Self(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }

    /// Construct an IPv6 link-local endpoint: combines an `fe80::`
    /// address with an interface `scope_id`. Use this when mDNS
    /// resolution yields `(addr, scope_id)` pairs.
    #[must_use]
    pub fn link_local(ip: Ipv6Addr, port: u16, scope_id: u32) -> Self {
        Self(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id)))
    }
}

/// What a network adapter must do to ship Matter packets.
///
/// Implemented by [`crate::tokio_udp::TokioUdpTransport`] for the
/// default async runtime when the `tokio` feature is enabled.
/// Embedded callers implement against their own UDP stack.
pub trait Transport {
    /// Ship one packet to `peer`. Non-blocking — on a real socket may
    /// fail with [`Error::Io`] containing `WouldBlock` if the OS send
    /// queue is full; callers retry after the socket reports writable.
    ///
    /// [`Error::Io`]: crate::error::Error::Io
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] on any socket-level failure (feature-gated).
    fn send(&mut self, peer: PeerAddress, packet: Vec<u8>) -> Result<()>;

    /// Poll for an inbound packet. Returns `Ok(None)` if no packet is
    /// available — this is the steady state for an idle socket, NOT an
    /// error. Non-blocking; callers MUST pair with their runtime's
    /// readiness primitive (e.g. `socket.readable().await` in a
    /// `tokio::select!`) to avoid busy-waiting.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] on any socket-level failure (feature-gated).
    ///
    /// [`Error::Io`]: crate::error::Error::Io
    fn poll_recv(&mut self) -> Result<Option<(PeerAddress, Vec<u8>)>>;

    /// Local socket address (what the adapter bound to). Useful for
    /// tests and for filling source-address fields into higher-layer
    /// state.
    fn local_address(&self) -> SocketAddr;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn from_ipv4_constructs_v4_variant() {
        let pa = PeerAddress::from_ipv4(Ipv4Addr::new(192, 0, 2, 1), 5540);
        match pa.0 {
            SocketAddr::V4(v4) => {
                assert_eq!(*v4.ip(), Ipv4Addr::new(192, 0, 2, 1));
                assert_eq!(v4.port(), 5540);
            }
            SocketAddr::V6(_) => panic!("expected V4"),
        }
    }

    #[test]
    fn from_ipv6_constructs_with_zero_scope_id() {
        let pa = PeerAddress::from_ipv6(Ipv6Addr::LOCALHOST, 5540);
        match pa.0 {
            SocketAddr::V6(v6) => {
                assert_eq!(*v6.ip(), Ipv6Addr::LOCALHOST);
                assert_eq!(v6.port(), 5540);
                assert_eq!(v6.scope_id(), 0);
                assert_eq!(v6.flowinfo(), 0);
            }
            SocketAddr::V4(_) => panic!("expected V6"),
        }
    }

    #[test]
    fn link_local_preserves_scope_id() {
        let fe80 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0);
        let pa = PeerAddress::link_local(fe80, 5540, 42);
        match pa.0 {
            SocketAddr::V6(v6) => {
                assert_eq!(*v6.ip(), fe80);
                assert_eq!(v6.port(), 5540);
                assert_eq!(v6.scope_id(), 42);
            }
            SocketAddr::V4(_) => panic!("expected V6"),
        }
    }

    #[test]
    fn peer_address_eq_hash_consistency() {
        use std::collections::HashSet;
        let a = PeerAddress::from_ipv6(Ipv6Addr::LOCALHOST, 5540);
        let b = PeerAddress::from_ipv6(Ipv6Addr::LOCALHOST, 5540);
        let c = PeerAddress::from_ipv6(Ipv6Addr::LOCALHOST, 5541);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }
}
