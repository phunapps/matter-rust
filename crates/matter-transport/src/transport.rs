//! Sans-IO `Transport` trait + `PeerAddress` newtype. Task 2 of the M5.3
//! plan fills this in.

#![allow(missing_docs, dead_code, unused_imports, clippy::missing_errors_doc)]

use std::net::SocketAddr;

use crate::error::Result;

/// Network endpoint for a Matter peer. Newtype around `SocketAddr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerAddress(pub SocketAddr);

/// What a network adapter must do to ship Matter packets. Task 2 fills
/// in the real method signatures.
pub trait Transport {
    fn send(&mut self, peer: PeerAddress, packet: Vec<u8>) -> Result<()>;
    fn poll_recv(&mut self) -> Result<Option<(PeerAddress, Vec<u8>)>>;
    fn local_address(&self) -> SocketAddr;
}
