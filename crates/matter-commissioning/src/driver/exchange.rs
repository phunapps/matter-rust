//! Secured-exchange round-trip over `SessionManager` + MRP (M6.6 §5).
//!
//! This is the single place where async IO and MRP retransmit timers meet for
//! *encrypted* exchanges. The sans-IO `SessionManager` produces wire bytes and
//! consumes inbound packets; this helper sends, then drives a
//! recv-or-timer-fire loop until the matching application response arrives,
//! silently absorbing acks, duplicate-reliable resends, and retransmits so the
//! policy layer above never sees MRP mechanics.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use matter_transport::{
    DecodeInboundOutput, MrpEvent, MrpFlags, ProtocolId, SessionId, SessionManager,
};

use crate::driver::datagram::AsyncDatagram;
use crate::driver::error::DriverError;

/// The application response decoded from a completed secured round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuredResponse {
    /// The exchange id the request/response pair ran on.
    pub exchange_id: u16,
    /// The decoded application payload (post-protocol-header bytes).
    pub payload: Vec<u8>,
}

/// Sentinel sleep when no MRP deadline is pending: the recv arm of the
/// `select!` should win, so we park on a long timer rather than busy-loop.
const IDLE_SLEEP: Duration = Duration::from_secs(3600);

/// Send `app_payload` as a *reliable* secured message on `session_id` to
/// `peer`, then drive MRP until the matching application response arrives.
///
/// `AckOnly` and `DuplicateReliableAckResent` outcomes are absorbed; retransmit
/// timers are honoured. `peer` is used only as the send destination — inbound
/// datagrams are matched by session id and exchange id (the source address is
/// not filtered), consistent with the single-peer commissioning flow.
///
/// The buffered piggyback-ack for the *received* response is left pending when
/// this returns. M6.6.4 (the `commission()` orchestrator) MUST account for it:
/// the next exchange uses a fresh exchange id, so MRP will not piggyback the
/// ack onto it; instead the 200 ms standalone-ack deadline fires inside the
/// *next* `secured_round_trip`'s timer arm and emits a `SendStandaloneAck`.
/// That is spec-correct (the peer still gets its ack), but it means a stray
/// standalone-ack send can preempt the start of the next exchange. If that
/// ordering ever matters, M6.6.4 should flush the ack explicitly before
/// starting the next exchange.
///
/// # Errors
///
/// - [`DriverError::Transport`] if framing/session/MRP rejects a frame.
/// - [`DriverError::Io`] if the datagram send/recv fails.
/// - [`DriverError::Timeout`] if MRP exhausts its retransmit budget.
pub async fn secured_round_trip<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    session_id: SessionId,
    peer: SocketAddr,
    opcode: u8,
    protocol_id: ProtocolId,
    app_payload: &[u8],
) -> Result<SecuredResponse, DriverError> {
    // 1. Encode + send the request (reliable → MRP tracks it for retransmit).
    let out = sessions.encode_outbound(
        session_id,
        None, // new exchange; MRP allocates the id and marks us initiator
        opcode,
        protocol_id,
        app_payload,
        MrpFlags { reliable: true },
        Instant::now(),
    )?;
    let our_exchange = out.exchange_id;
    transport.send_to(&out.wire_bytes, peer).await?;

    // 2. recv-or-timer loop.
    loop {
        let now = Instant::now();
        let sleep_for = sessions
            .poll_timeout()
            .map_or(IDLE_SLEEP, |deadline| deadline.saturating_duration_since(now));

        tokio::select! {
            biased;
            recv = transport.recv_from() => {
                // Single-peer flow: the source address is not trust-checked here;
                // `decode_inbound` authenticates by session id + AES-CCM tag.
                let (packet, _from) = recv?;
                match sessions.decode_inbound(&packet, Instant::now())? {
                    DecodeInboundOutput::AppMessage { exchange_id, payload, .. }
                        if exchange_id == our_exchange =>
                    {
                        return Ok(SecuredResponse { exchange_id, payload });
                    }
                    // App message for some other exchange — not expected in the
                    // strictly sequential commissioning flow; ignore and wait.
                    DecodeInboundOutput::AppMessage { .. } => {}
                    // Our request was acked; keep waiting for the response.
                    DecodeInboundOutput::AckOnly { .. } => {}
                    // Peer re-sent a reliable frame; bounce its standalone ack.
                    DecodeInboundOutput::DuplicateReliableAckResent { ack_packet, .. } => {
                        transport.send_to(&ack_packet, peer).await?;
                    }
                }
            }
            () = tokio::time::sleep(sleep_for) => {
                for event in sessions.handle_timeout(Instant::now()) {
                    match event {
                        MrpEvent::Retransmit { packet, .. }
                        | MrpEvent::SendStandaloneAck { packet, .. } => {
                            transport.send_to(&packet, peer).await?;
                        }
                        MrpEvent::Expired { exchange_id, .. } => {
                            return Err(DriverError::Timeout { exchange_id });
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use std::time::Instant;

    use matter_crypto::pase::PaseSessionKeys;
    use matter_transport::{
        DecodeInboundOutput, MrpFlags, PeerHint, ProtocolId, SessionManager, SessionRole,
    };

    use super::*;
    use crate::driver::datagram::{AsyncDatagram, InMemoryDatagram};

    /// Two `SessionManager`s sharing one symmetric key set, cross-registered as
    /// Initiator/Responder. Both allocate local id 1 (allocator starts at 1),
    /// so each side's `peer_session_id` is 1.
    fn paired_pase_sessions() -> (SessionManager, SessionManager) {
        let keys = PaseSessionKeys {
            ke: [0u8; 16],
            i2r_key: [1u8; 16],
            r2i_key: [2u8; 16],
            attestation_key: [3u8; 16],
        };
        let mut ctrl = SessionManager::new();
        let mut dev = SessionManager::new();
        let _ctrl_sid = ctrl.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
        let _dev_sid = dev.register_pase(keys, SessionRole::Responder, 1, PeerHint::default());
        (ctrl, dev)
    }

    #[tokio::test]
    async fn secured_round_trip_returns_response_payload() {
        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = matter_transport::SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        let request = b"invoke-request-tlv".as_slice();
        let response = b"invoke-response-tlv".as_slice();

        let controller = secured_round_trip(
            &ctrl_io,
            &mut ctrl,
            session,
            dev_addr,
            0x08, // InvokeRequest opcode (opaque to the transport here)
            ProtocolId::INTERACTION_MODEL,
            request,
        );

        let device = async {
            loop {
                let (pkt, _) = dev_io.recv_from().await.unwrap();
                match dev.decode_inbound(&pkt, Instant::now()).unwrap() {
                    DecodeInboundOutput::AppMessage { exchange_id, payload, .. } => {
                        assert_eq!(payload, request);
                        let out = dev
                            .encode_outbound(
                                session,
                                Some(exchange_id),
                                0x09, // InvokeResponse opcode
                                ProtocolId::INTERACTION_MODEL,
                                response,
                                MrpFlags { reliable: true },
                                Instant::now(),
                            )
                            .unwrap();
                        dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
                        break;
                    }
                    _ => continue,
                }
            }
        };

        let (got, ()) = tokio::join!(controller, device);
        let got = got.unwrap();
        assert_eq!(got.payload, response);
    }
}
