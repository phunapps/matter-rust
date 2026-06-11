//! The `AsyncDatagram` transport seam (M6.6 §4) and its two implementations.
//!
//! The seam is deliberately datagram-only — no MRP, no framing. All
//! reliability and framing live one layer up (`exchange.rs` /
//! `unsecured.rs`), so the real socket path and the in-memory test path run
//! byte-for-byte identical protocol logic. This mirrors connectedhomeip's
//! `Transport::Base`: an abstraction with two genuine implementations on day
//! one, not a speculative one.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{mpsc, Mutex};

/// UDP receive buffer size. The Matter UDP payload is bounded by the IPv6
/// minimum MTU (1280 bytes) minus IP+UDP headers, comfortably under this; the
/// Ethernet-MTU value leaves headroom and matches `matter-transport`'s socket
/// buffer. UDP truncates anything larger to the buffer length.
const RECV_BUF_SIZE: usize = 1500;

/// An async, unreliable, message-oriented datagram transport.
///
/// The returned futures are `Send`-bound (`-> impl Future + Send`) so a
/// downstream owner can drive this transport from a `tokio::spawn`ed task —
/// `matter-controller`'s session actor does exactly that. Both in-tree impls
/// (`TokioUdpTransport`, `InMemoryDatagram`) already yield `Send` futures, so
/// the bound is free for them; it only constrains hypothetical future impls.
/// The driver itself still runs all IO inline on a single task via
/// `tokio::join!`.
pub trait AsyncDatagram {
    /// Send `buf` as a single datagram to `peer`.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on socket-level failures.
    fn send_to(
        &self,
        buf: &[u8],
        peer: SocketAddr,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;

    /// Await the next inbound datagram, returning its bytes and source address.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on socket-level failures or when the peer
    /// endpoint is closed ([`io::ErrorKind::BrokenPipe`]).
    fn recv_from(
        &self,
    ) -> impl std::future::Future<Output = io::Result<(Vec<u8>, SocketAddr)>> + Send;
}

/// Real-socket implementation over the M5 `TokioUdpTransport`. Uses the
/// underlying `tokio::net::UdpSocket` directly (both `send_to`/`recv_from`
/// take `&self`), so this impl needs only a shared reference.
impl AsyncDatagram for matter_transport::TokioUdpTransport {
    async fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<()> {
        // The transport binds a dual-stack IPv6 socket (`[::]:port`). Sending to
        // a plain IPv4 destination on an `AF_INET6` socket fails with `EINVAL`;
        // it must be expressed as the IPv4-mapped IPv6 form `::ffff:a.b.c.d`.
        // (Devices commonly advertise an IPv4 address alongside their IPv6 ones,
        // which `preferred_address` selects.)
        let peer = match (self.socket().local_addr(), peer) {
            (Ok(SocketAddr::V6(_)), SocketAddr::V4(v4)) => {
                SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            _ => peer,
        };
        self.socket().send_to(buf, peer).await.map(|_n| ())
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        let (n, from) = self.socket().recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((buf, from))
    }
}

/// In-memory `AsyncDatagram` for hardware-free tests: a fixed two-endpoint
/// `mpsc` duplex. Routing ignores the `peer` argument (the pair is wired at
/// construction). `set_drops` lets a test silently drop the next N outbound
/// datagrams to exercise retransmit logic deterministically.
pub struct InMemoryDatagram {
    addr: SocketAddr,
    /// Channel carrying datagrams *to the peer* (the peer's inbound queue).
    tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    /// This endpoint's inbound queue.
    rx: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    /// Number of upcoming outbound datagrams to silently drop.
    drops_remaining: AtomicUsize,
}

impl InMemoryDatagram {
    /// Build a connected pair of endpoints with synthetic loopback addresses.
    #[must_use]
    pub fn pair() -> (Self, Self) {
        let addr_a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        let addr_b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2));
        // to_a carries datagrams whose destination is A; to_b for B.
        let (tx_to_a, rx_a) = mpsc::unbounded_channel();
        let (tx_to_b, rx_b) = mpsc::unbounded_channel();
        let a = Self {
            addr: addr_a,
            tx: tx_to_b,
            rx: Mutex::new(rx_a),
            drops_remaining: AtomicUsize::new(0),
        };
        let b = Self {
            addr: addr_b,
            tx: tx_to_a,
            rx: Mutex::new(rx_b),
            drops_remaining: AtomicUsize::new(0),
        };
        (a, b)
    }

    /// This endpoint's synthetic local address (used as the `from` field the
    /// peer observes on `recv_from`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Silently drop the next `n` outbound datagrams (test fault injection).
    pub fn set_drops(&self, n: usize) {
        self.drops_remaining.store(n, Ordering::SeqCst);
    }
}

impl AsyncDatagram for InMemoryDatagram {
    /// Deliver `buf` to the peer endpoint, or silently drop it.
    ///
    /// Returns `Ok(())` even when the datagram is dropped (injected fault) or
    /// the peer endpoint has been closed — an unreliable transport reports no
    /// delivery failure. A test whose peer endpoint is dropped early will see
    /// `Ok(())` here and then block in `recv_from`; keep both endpoints alive
    /// for the test's duration.
    async fn send_to(&self, buf: &[u8], _peer: SocketAddr) -> io::Result<()> {
        // Atomic decrement-if-nonzero: consumes exactly one drop credit even
        // under concurrent sends.
        let consumed_drop = self
            .drops_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                if v > 0 {
                    Some(v - 1)
                } else {
                    None
                }
            })
            .is_ok();
        if consumed_drop {
            return Ok(());
        }
        // Stamp our own address as the source, so the peer's recv_from sees a
        // realistic `from` (mirrors how the OS fills in the UDP source).
        let _ = self.tx.send((buf.to_vec(), self.addr));
        Ok(())
    }

    /// Await the next inbound datagram for this endpoint.
    ///
    /// # Concurrency
    ///
    /// Must not be called concurrently on the same endpoint: the receiver is
    /// behind a `Mutex` held across the await, so a second concurrent
    /// `recv_from` on the same endpoint will deadlock. The driver drives each
    /// endpoint from a single task (and `tokio::select!` drops and recreates
    /// the future each iteration rather than polling two at once), so this is
    /// never violated in practice.
    async fn recv_from(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "peer endpoint closed"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_datagram_delivers_both_directions() {
        let (a, b) = InMemoryDatagram::pair();
        a.send_to(b"hello", b.local_addr()).await.unwrap();
        let (got, from) = b.recv_from().await.unwrap();
        assert_eq!(got, b"hello");
        assert_eq!(from, a.local_addr());

        b.send_to(b"world", a.local_addr()).await.unwrap();
        let (got2, from2) = a.recv_from().await.unwrap();
        assert_eq!(got2, b"world");
        assert_eq!(from2, b.local_addr());
    }

    #[tokio::test]
    async fn in_memory_datagram_drops_configured_sends() {
        let (a, b) = InMemoryDatagram::pair();
        a.set_drops(1);
        a.send_to(b"dropped", b.local_addr()).await.unwrap(); // silently dropped
        a.send_to(b"delivered", b.local_addr()).await.unwrap(); // delivered
        let (got, _) = b.recv_from().await.unwrap();
        assert_eq!(got, b"delivered");

        // Exactly one credit was consumed: the next send (no drops left) must
        // arrive, proving the drop counter returned to zero.
        a.send_to(b"after", b.local_addr()).await.unwrap();
        let (after, _) = b.recv_from().await.unwrap();
        assert_eq!(after, b"after");
    }

    #[tokio::test]
    async fn tokio_udp_transport_send_recv_loopback() {
        use matter_transport::TokioUdpTransport;
        use matter_transport::Transport;

        let a = TokioUdpTransport::bind_addr("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b = TokioUdpTransport::bind_addr("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b_addr = b.local_address();

        AsyncDatagram::send_to(&a, b"ping", b_addr).await.unwrap();
        let (got, _from) = AsyncDatagram::recv_from(&b).await.unwrap();
        assert_eq!(got, b"ping");
    }
}
