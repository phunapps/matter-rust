//! Default Tokio-based UDP adapter for Matter. Task 4 of the M5.3 plan
//! fills this in.

#![allow(missing_docs, dead_code, unused_imports, clippy::missing_errors_doc)]

use std::net::SocketAddr;

use crate::error::Result;
use crate::transport::{PeerAddress, Transport};

pub struct TokioUdpTransport {
    _todo: (),
}

impl TokioUdpTransport {
    /// Bind a dual-stack UDP socket on `[::]:port`. Task 4 fills in.
    #[allow(clippy::unused_async)]
    pub async fn bind(_port: u16) -> Result<Self> {
        unimplemented!("filled in by Task 4")
    }

    /// Bind on a specific address. Task 4 fills in.
    #[allow(clippy::unused_async)]
    pub async fn bind_addr(_addr: SocketAddr) -> Result<Self> {
        unimplemented!("filled in by Task 4")
    }
}

impl Transport for TokioUdpTransport {
    fn send(&mut self, _peer: PeerAddress, _packet: Vec<u8>) -> Result<()> {
        unimplemented!("filled in by Task 4")
    }
    fn poll_recv(&mut self) -> Result<Option<(PeerAddress, Vec<u8>)>> {
        unimplemented!("filled in by Task 4")
    }
    fn local_address(&self) -> SocketAddr {
        unimplemented!("filled in by Task 4")
    }
}
