//! PASE bridge (M6.6.3b): drive the sans-IO [`PaseProver`] over the unsecured
//! datagram path and register the resulting secured session.
//!
//! PASE runs UNSECURED (session-id 0, `SecureChannel` protocol). The bridge
//! allocates a local session id, threads it into the prover (so the device is
//! told to address us by it), drives the 5-message handshake over
//! [`UnsecuredExchange`], then registers via
//! [`SessionManager::register_pase_with_local_id`].

use std::net::SocketAddr;

use matter_crypto::pase::PaseProver;
use matter_transport::{PeerHint, SessionId, SessionManager, SessionRole};

use crate::driver::datagram::AsyncDatagram;
use crate::driver::error::DriverError;
use crate::driver::unsecured::UnsecuredExchange;

// SecureChannel opcodes for the PASE handshake (Matter Core Spec §4.14.1).
const OP_PBKDF_PARAM_REQUEST: u8 = 0x20;
const OP_PASE_PAKE1: u8 = 0x22;
const OP_PASE_PAKE3: u8 = 0x24;

// FLAGGED (from M6.6.2): production should seed the unsecured counter randomly
// (Matter Core Spec §4.5.1.1); a fixed seed is deterministic for tests.
const PASE_INITIAL_COUNTER: u32 = 1;
const PASE_EXCHANGE_ID: u16 = 1;

/// Drive a full PASE handshake against `peer` and register the resulting
/// secured session in `sessions`, returning its local [`SessionId`].
///
/// # Errors
///
/// - [`DriverError::Crypto`] if a SPAKE2+ step fails (e.g. wrong passcode).
/// - [`DriverError::Io`] / [`DriverError::Transport`] / [`DriverError::Timeout`]
///   on datagram, framing, or reply-timeout failure.
/// - [`DriverError::Handshake`] if negotiation produced no responder session id.
pub async fn run_pase<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    peer: SocketAddr,
    passcode: u32,
) -> Result<SessionId, DriverError> {
    let local = sessions.allocate_session_id();
    let mut prover = PaseProver::new_with_negotiation(passcode, local.0)?;
    let mut exch = UnsecuredExchange::new(PASE_INITIAL_COUNTER, PASE_EXCHANGE_ID);

    let request = prover.start()?;
    let resp = exch
        .send_and_recv(transport, peer, OP_PBKDF_PARAM_REQUEST, &request, None)
        .await?;
    prover.handle_pbkdf_response(&resp.payload)?;

    let pake1 = prover.next_message()?;
    let pake2 = exch
        .send_and_recv(transport, peer, OP_PASE_PAKE1, &pake1, Some(resp.message_counter))
        .await?;
    prover.handle_pake2(&pake2.payload)?;

    let pake3 = prover.next_message()?;
    exch.send(transport, peer, OP_PASE_PAKE3, &pake3, Some(pake2.message_counter))
        .await?;

    // Capture the responder session id before `finish` consumes `prover`.
    let peer_session_id = prover
        .responder_session_id()
        .ok_or(DriverError::Handshake("PASE negotiation produced no responder session id"))?;
    let keys = prover.finish()?;
    sessions.register_pase_with_local_id(
        local,
        keys,
        SessionRole::Initiator,
        peer_session_id,
        PeerHint::default(),
    );
    Ok(local)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use matter_crypto::pase::{PasePbkdfParams, PaseVerifier};
    use matter_transport::{SessionKeys, SessionManager};

    use super::*;
    use crate::driver::datagram::{AsyncDatagram, InMemoryDatagram};
    use crate::driver::unsecured::{decode_unsecured, encode_unsecured};

    const OP_PBKDF_RESP: u8 = 0x21;
    const OP_PAKE2: u8 = 0x23;

    #[tokio::test]
    async fn run_pase_establishes_matching_session() {
        let pin = 20_202_021;
        let params = PasePbkdfParams { iterations: 1000, salt: vec![0x55; 16] };

        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut sessions = SessionManager::new();

        let device = async {
            let mut verifier = PaseVerifier::new_from_pin(pin, params, 0x00BB).unwrap();
            let mut ctr: u32 = 100;
            let (p, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&p).unwrap();
            verifier.handle_pbkdf_request(&m.payload).unwrap();
            let resp = verifier.next_message().unwrap();
            let wire = encode_unsecured(ctr, m.exchange_id, OP_PBKDF_RESP,
                matter_transport::ProtocolId::SECURE_CHANNEL, false, true,
                Some(m.message_counter), &resp);
            ctr += 1;
            dev_io.send_to(&wire, ctrl_addr).await.unwrap();

            let (p, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&p).unwrap();
            verifier.handle_pake1(&m.payload).unwrap();
            let pake2 = verifier.next_message().unwrap();
            let wire = encode_unsecured(ctr, m.exchange_id, OP_PAKE2,
                matter_transport::ProtocolId::SECURE_CHANNEL, false, true,
                Some(m.message_counter), &pake2);
            dev_io.send_to(&wire, ctrl_addr).await.unwrap();

            let (p, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&p).unwrap();
            verifier.handle_pake3(&m.payload).unwrap();
            verifier.finish().unwrap()
        };

        let controller = run_pase(&ctrl_io, &mut sessions, dev_addr, pin);
        let (ctrl_result, dev_keys) = tokio::join!(controller, device);
        let sid = ctrl_result.unwrap();

        let registered = sessions.get(sid).unwrap();
        assert_eq!(registered.keys, SessionKeys::from(dev_keys));
        assert_eq!(registered.peer_id, matter_transport::SessionId(0x00BB));
    }
}
