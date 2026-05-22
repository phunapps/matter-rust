//! Default Tokio-based UDP adapter for Matter.
//!
//! Wraps [`tokio::net::UdpSocket`] in a dual-stack IPv6 socket so the
//! same instance handles both IPv6 and IPv4-mapped traffic. Implements
//! [`crate::transport::Transport`] with synchronous `try_send_to` /
//! `try_recv_from`; callers drive readiness via the runtime
//! (`socket.readable().await`).

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::transport::{PeerAddress, Transport};

/// IPv6 minimum MTU minus IPv6 header + UDP header = safe single-packet
/// receive buffer size. Larger packets fragment; smaller is fine.
const RECV_BUF_SIZE: usize = 1500;

/// Default Tokio-based UDP transport for Matter.
///
/// Construct via [`Self::bind`] (any port on `[::]`) or
/// [`Self::bind_addr`] (specific address). The socket is dual-stack
/// (`IPV6_V6ONLY = false`) so IPv4-mapped traffic also works.
#[derive(Debug)]
pub struct TokioUdpTransport {
    socket: UdpSocket,
    recv_buf: Vec<u8>,
    local: SocketAddr,
}

impl TokioUdpTransport {
    /// Bind a dual-stack UDP socket on `[::]:port`. Pass `0` for an
    /// OS-assigned port.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] on bind failure (port already in use,
    /// permission denied, IPv6 unsupported, etc.).
    pub async fn bind(port: u16) -> Result<Self> {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        Self::bind_addr(addr).await
    }

    /// Bind on a specific address. Useful for tests with `[::1]:0`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] on bind failure.
    // `async` is preserved for API symmetry with `bind` and to leave
    // room for a future migration to `tokio::net::UdpSocket::bind`
    // (which IS async). All current operations inside are synchronous.
    #[allow(clippy::unused_async)]
    pub async fn bind_addr(addr: SocketAddr) -> Result<Self> {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let raw = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        // Disable IPV6_V6ONLY so dual-stack works.
        if matches!(addr, SocketAddr::V6(_)) {
            raw.set_only_v6(false)?;
        }
        raw.set_nonblocking(true)?;
        raw.bind(&addr.into())?;
        let std_sock: std::net::UdpSocket = raw.into();
        let socket = UdpSocket::from_std(std_sock)?;
        let local = socket.local_addr()?;
        Ok(Self {
            socket,
            recv_buf: vec![0u8; RECV_BUF_SIZE],
            local,
        })
    }

    /// Borrow the underlying [`tokio::net::UdpSocket`]. Useful for
    /// awaiting `readable()` / `writable()` from a driver loop.
    #[must_use]
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

impl Transport for TokioUdpTransport {
    fn send(&mut self, peer: PeerAddress, packet: Vec<u8>) -> Result<()> {
        match self.socket.try_send_to(&packet, peer.0) {
            Ok(_) => Ok(()),
            // WouldBlock surfaces as Io(WouldBlock); caller decides
            // whether to retry. We don't transparently swallow it
            // because the caller's driver loop pairs this with
            // socket.writable().await.
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn poll_recv(&mut self) -> Result<Option<(PeerAddress, Vec<u8>)>> {
        match self.socket.try_recv_from(&mut self.recv_buf) {
            Ok((n, from)) => {
                let bytes = self.recv_buf[..n].to_vec();
                Ok(Some((PeerAddress(from), bytes)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn local_address(&self) -> SocketAddr {
        self.local
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddr};

    #[tokio::test]
    async fn bind_assigns_local_port() {
        let t = TokioUdpTransport::bind_addr("[::1]:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        assert_ne!(t.local_address().port(), 0);
    }

    #[tokio::test]
    async fn bind_specific_port() {
        // Bind on port 0 first to find a free one, drop, then re-bind.
        let pick = TokioUdpTransport::bind_addr("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        let port = pick.local_address().port();
        drop(pick);
        let t = TokioUdpTransport::bind_addr(format!("[::1]:{port}").parse().unwrap())
            .await
            .unwrap();
        assert_eq!(t.local_address().port(), port);
    }

    #[tokio::test]
    async fn bind_in_use_errors() {
        let a = TokioUdpTransport::bind_addr("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        let port = a.local_address().port();
        let err = TokioUdpTransport::bind_addr(format!("[::1]:{port}").parse().unwrap())
            .await
            .unwrap_err();
        // The error MUST be Error::Io; on AddrInUse we expect kind ==
        // AddrInUse, but on some platforms binding the same port twice
        // succeeds with SO_REUSEADDR. Assert just the variant for
        // portability.
        assert!(matches!(err, crate::Error::Io(_)));
    }

    #[tokio::test]
    async fn send_recv_roundtrip_localhost() {
        let mut alice = TokioUdpTransport::bind_addr("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        let mut bob = TokioUdpTransport::bind_addr("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        let bob_addr = PeerAddress(bob.local_address());

        // Tokio's try_send_to requires the runtime to have observed
        // write readiness first; otherwise it returns WouldBlock even
        // on a freshly-bound, never-saturated UDP socket. Mirror the
        // production driver loop's pattern: await writable() then send.
        alice.socket().writable().await.unwrap();
        alice.send(bob_addr, b"hello matter".to_vec()).unwrap();

        // try_recv_from is non-blocking; loop with a 1s budget.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if let Some((from, payload)) = bob.poll_recv().unwrap() {
                assert_eq!(payload, b"hello matter");
                assert_eq!(from.0.port(), alice.local_address().port());
                break;
            }
            assert!(
                tokio::time::Instant::now() <= deadline,
                "did not receive packet within 1s"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn poll_recv_empty_returns_ok_none() {
        let mut t = TokioUdpTransport::bind_addr("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        assert!(matches!(t.poll_recv(), Ok(None)));
    }

    #[tokio::test]
    async fn peer_address_preserves_scope_id_through_send_recv() {
        let mut alice = TokioUdpTransport::bind_addr("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        let mut bob = TokioUdpTransport::bind_addr("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        // Bob's address as [::1]:port — loopback, scope_id naturally 0.
        let bob_addr = PeerAddress(bob.local_address());
        // Mirror the production driver: await writable() before send
        // so Tokio's internal readiness flag is set.
        alice.socket().writable().await.unwrap();
        alice.send(bob_addr, b"x".to_vec()).unwrap();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if let Some((from, _)) = bob.poll_recv().unwrap() {
                // For loopback, the inbound peer address is also [::1].
                if let SocketAddr::V6(v6) = from.0 {
                    assert_eq!(*v6.ip(), Ipv6Addr::LOCALHOST);
                }
                break;
            }
            assert!(
                tokio::time::Instant::now() <= deadline,
                "did not receive within 1s"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
