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
/// not filtered), consistent with the single-peer commissioning flow. A frame
/// that fails to decode (bad tag, replayed counter, malformed header) is
/// propagated as an error and aborts the round-trip rather than being skipped;
/// that is acceptable under the single-peer assumption but is a place to harden
/// if this is ever used where unrelated traffic can reach the socket.
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
    // M6 wire-trace capture: feeds JsonlLayer / cargo xtask trace-diff.
    #[cfg(feature = "tracing")]
    tracing::debug!(
        target: "matter_wire",
        dir = "tx",
        session_id = u64::from(session_id.0),
        exchange_id = u64::from(our_exchange),
        protocol = u64::from(protocol_id.protocol),
        opcode = u64::from(opcode),
        payload = %crate::hexdump::hex(app_payload),
        "wire"
    );

    // 2. recv-or-timer loop.
    loop {
        let now = Instant::now();
        let sleep_for = sessions.poll_timeout().map_or(IDLE_SLEEP, |deadline| {
            deadline.saturating_duration_since(now)
        });

        tokio::select! {
            biased;
            recv = transport.recv_from() => {
                // Single-peer flow: the source address is not trust-checked here;
                // `decode_inbound` authenticates by session id + AES-CCM tag.
                let (packet, _from) = recv?;
                // Unsecured stragglers (session id 0 — e.g. a PASE/CASE
                // StatusReport retransmit whose standalone ack was lost) are
                // not addressed to any secured session; skip, don't abort.
                if packet.len() >= 3 && packet[1] == 0 && packet[2] == 0 {
                    continue;
                }
                let decoded = match sessions.decode_inbound(&packet, Instant::now()) {
                    Ok(d) => d,
                    // A secured packet we cannot attribute to one of THIS
                    // manager's sessions, or cannot decrypt, is not our
                    // response — skip it, don't abort the exchange. Seen right
                    // after `commission()` hands off to a fresh operational
                    // `SessionManager`: the device keeps MRP-retransmitting its
                    // final commissioning-session frame (addressed to the old,
                    // now-unknown session id) into the new session's recv loop.
                    Err(
                        matter_transport::Error::UnknownSession(_)
                        | matter_transport::Error::DecryptionFailed,
                    ) => continue,
                    Err(e) => return Err(e.into()),
                };
                match decoded {
                    DecodeInboundOutput::AppMessage {
                        exchange_id,
                        payload,
                        protocol_id: msg_protocol_id,
                        opcode: msg_opcode,
                        ..
                    } if exchange_id == our_exchange => {
                        // M6 wire-trace capture: feeds JsonlLayer / cargo xtask trace-diff.
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            target: "matter_wire",
                            dir = "rx",
                            session_id = u64::from(session_id.0),
                            exchange_id = u64::from(exchange_id),
                            protocol = u64::from(msg_protocol_id.protocol),
                            opcode = u64::from(msg_opcode),
                            payload = %crate::hexdump::hex(&payload),
                            "wire"
                        );
                        #[cfg(not(feature = "tracing"))]
                        let _ = (&msg_protocol_id, &msg_opcode);
                        return Ok(SecuredResponse { exchange_id, payload });
                    }
                    // Peer re-sent a reliable frame; bounce its standalone ack.
                    DecodeInboundOutput::DuplicateReliableAckResent { ack_packet, .. } => {
                        transport.send_to(&ack_packet, peer).await?;
                    }
                    // Wait through everything else: an app message for a
                    // *different* exchange (not expected in the strictly
                    // sequential commissioning flow), an `AckOnly` for our request
                    // (response still pending), and — `DecodeInboundOutput` being
                    // `#[non_exhaustive]` — any future outcome.
                    _ => {}
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
                        // `MrpEvent` is `#[non_exhaustive]`; ignore future
                        // timer events here.
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Maximum number of `ReportData` chunks a single read may span before
/// [`secured_read`] aborts. A conformant wildcard read of a typical device is a
/// handful of chunks; 64 is far above that and bounds a buggy/hostile peer.
pub const MAX_READ_CHUNKS: usize = 64;

/// Maximum total decoded payload bytes a single read may accumulate before
/// [`secured_read`] aborts (256 `KiB`).
pub const MAX_READ_BYTES: usize = 256 * 1024;

/// IM `StatusResponse` opcode (Matter §8.7) — the per-chunk ack the reader
/// sends to solicit the next chunk.
const OP_STATUS_RESPONSE: u8 = 0x01;

/// Send a `ReadRequest` (`app_payload`) as a reliable secured message, then
/// drive the Matter chunked-read transaction: for every inbound `ReportData`
/// chunk that sets `MoreChunkedMessages`, reply with `StatusResponse(SUCCESS)`
/// on the same exchange — which piggybacks the chunk's MRP ack and solicits the
/// next chunk — stopping at the final chunk. Returns every chunk payload in
/// order.
///
/// A non-chunked read returns a single-element `Vec` (the loop runs once). The
/// final chunk's MRP ack is left pending on return — identical to
/// [`secured_round_trip`]'s contract; the next exchange or the standalone-ack
/// timer flushes it. Inbound demultiplexing (exchange match, unsecured-straggler
/// skip, `UnknownSession`/`DecryptionFailed` skip, duplicate-ack bounce, MRP
/// timer) is identical to [`secured_round_trip`].
///
/// # Errors
///
/// - [`DriverError::ReadTooLarge`] if the read exceeds [`MAX_READ_CHUNKS`] or
///   [`MAX_READ_BYTES`].
/// - [`DriverError::Im`] if a chunk is not a parseable `ReportData`.
/// - [`DriverError::Transport`] / [`DriverError::Io`] / [`DriverError::Timeout`]
///   as for [`secured_round_trip`].
pub async fn secured_read<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    session_id: SessionId,
    peer: SocketAddr,
    opcode: u8,
    protocol_id: ProtocolId,
    app_payload: &[u8],
) -> Result<Vec<Vec<u8>>, DriverError> {
    // 1. Encode + send the ReadRequest (reliable → MRP tracks it).
    let out = sessions.encode_outbound(
        session_id,
        None,
        opcode,
        protocol_id,
        app_payload,
        MrpFlags { reliable: true },
        Instant::now(),
    )?;
    let our_exchange = out.exchange_id;
    transport.send_to(&out.wire_bytes, peer).await?;

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut total_bytes = 0usize;

    // 2. recv-or-timer loop, acking each non-final chunk to solicit the next.
    loop {
        let now = Instant::now();
        let sleep_for = sessions.poll_timeout().map_or(IDLE_SLEEP, |deadline| {
            deadline.saturating_duration_since(now)
        });

        tokio::select! {
            biased;
            recv = transport.recv_from() => {
                let (packet, _from) = recv?;
                // Unsecured stragglers (session id 0) are not ours — skip.
                if packet.len() >= 3 && packet[1] == 0 && packet[2] == 0 {
                    continue;
                }
                let decoded = match sessions.decode_inbound(&packet, Instant::now()) {
                    Ok(d) => d,
                    Err(
                        matter_transport::Error::UnknownSession(_)
                        | matter_transport::Error::DecryptionFailed,
                    ) => continue,
                    Err(e) => return Err(e.into()),
                };
                match decoded {
                    DecodeInboundOutput::AppMessage { exchange_id, payload, .. }
                        if exchange_id == our_exchange =>
                    {
                        total_bytes = total_bytes.saturating_add(payload.len());
                        if chunks.len() + 1 > MAX_READ_CHUNKS {
                            return Err(DriverError::ReadTooLarge { limit: "MAX_READ_CHUNKS" });
                        }
                        if total_bytes > MAX_READ_BYTES {
                            return Err(DriverError::ReadTooLarge { limit: "MAX_READ_BYTES" });
                        }
                        let more = crate::im::parse_report_data(&payload)?.more_chunked_messages;
                        chunks.push(payload);
                        if !more {
                            return Ok(chunks);
                        }
                        // Ack this chunk + solicit the next on the same exchange.
                        let status = crate::im::build_status_response(0);
                        let ack = sessions.encode_outbound(
                            session_id,
                            Some(our_exchange),
                            OP_STATUS_RESPONSE,
                            ProtocolId::INTERACTION_MODEL,
                            &status,
                            MrpFlags { reliable: true },
                            Instant::now(),
                        )?;
                        transport.send_to(&ack.wire_bytes, peer).await?;
                    }
                    // Peer re-sent a reliable frame; bounce its standalone ack.
                    DecodeInboundOutput::DuplicateReliableAckResent { ack_packet, .. } => {
                        transport.send_to(&ack_packet, peer).await?;
                    }
                    // Keep waiting through everything else: an app message on
                    // another exchange, an `AckOnly` for our request, and —
                    // `DecodeInboundOutput` being `#[non_exhaustive]` — any
                    // future outcome.
                    _ => {}
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
                        // `MrpEvent` is `#[non_exhaustive]`; ignore future
                        // timer events here.
                        _ => {}
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
        let _ctrl_sid =
            ctrl.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
        let _dev_sid = dev.register_pase(keys, SessionRole::Responder, 1, PeerHint::default());
        (ctrl, dev)
    }

    #[tokio::test]
    async fn secured_round_trip_retransmits_dropped_request() {
        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = matter_transport::SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        // Drop the controller's FIRST outbound datagram (the original request).
        // MRP's ~300 ms active retransmit then re-sends it; the resend lands.
        ctrl_io.set_drops(1);

        let request = b"req".as_slice();
        let response = b"resp".as_slice();

        let controller = secured_round_trip(
            &ctrl_io,
            &mut ctrl,
            session,
            dev_addr,
            0x08,
            ProtocolId::INTERACTION_MODEL,
            request,
        );

        let device = async {
            // The device's single recv sees the retransmit (original was dropped).
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let DecodeInboundOutput::AppMessage {
                exchange_id,
                payload,
                ..
            } = dev.decode_inbound(&pkt, Instant::now()).unwrap()
            else {
                panic!("expected an application message");
            };
            assert_eq!(payload, request);
            let out = dev
                .encode_outbound(
                    session,
                    Some(exchange_id),
                    0x09,
                    ProtocolId::INTERACTION_MODEL,
                    response,
                    MrpFlags { reliable: true },
                    Instant::now(),
                )
                .unwrap();
            dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        assert_eq!(got.unwrap().payload, response);
    }

    #[tokio::test]
    async fn secured_round_trip_skips_unsecured_frames() {
        // A PASE/CASE StatusReport retransmit (session id 0) can straggle into
        // the secured IM phase if the device missed our standalone ack
        // (observed: Tapo P110M, M6.6.5 validation). It is not addressed to
        // any secured session — skip it rather than abort the round-trip.
        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = matter_transport::SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        let request = b"req".as_slice();
        let response = b"resp".as_slice();

        let controller = secured_round_trip(
            &ctrl_io,
            &mut ctrl,
            session,
            dev_addr,
            0x08,
            ProtocolId::INTERACTION_MODEL,
            request,
        );

        let device = async {
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let DecodeInboundOutput::AppMessage { exchange_id, .. } =
                dev.decode_inbound(&pkt, Instant::now()).unwrap()
            else {
                panic!("expected an application message");
            };
            // Straggler: an unsecured (session-id 0) StatusReport retransmit.
            let stray = crate::driver::unsecured::encode_unsecured(
                7,
                1,
                0x40,
                ProtocolId::SECURE_CHANNEL,
                false,
                true,
                None,
                None,
                &[0u8; 8],
            );
            dev_io.send_to(&stray, ctrl_addr).await.unwrap();
            // Then the real secured response.
            let out = dev
                .encode_outbound(
                    session,
                    Some(exchange_id),
                    0x09,
                    ProtocolId::INTERACTION_MODEL,
                    response,
                    MrpFlags { reliable: true },
                    Instant::now(),
                )
                .unwrap();
            dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        assert_eq!(got.unwrap().payload, response);
    }

    #[tokio::test]
    async fn secured_round_trip_skips_unknown_session_frames() {
        // After commission() hands off to a fresh operational SessionManager,
        // the device can keep MRP-retransmitting its final commissioning-session
        // frame, addressed to a (now-unknown) session id the new manager never
        // registered (observed: Tapo P110M, M7.5 validation). Such a secured
        // frame must be skipped, not abort the round-trip.
        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = matter_transport::SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        // A "stale" peer whose frames are addressed to session id 99 — an id the
        // controller's manager does not have.
        let stale_keys = PaseSessionKeys {
            ke: [9u8; 16],
            i2r_key: [9u8; 16],
            r2i_key: [9u8; 16],
            attestation_key: [9u8; 16],
        };
        let mut stale = SessionManager::new();
        let stale_sid =
            stale.register_pase(stale_keys, SessionRole::Initiator, 99, PeerHint::default());

        let request = b"req".as_slice();
        let response = b"resp".as_slice();

        let controller = secured_round_trip(
            &ctrl_io,
            &mut ctrl,
            session,
            dev_addr,
            0x08,
            ProtocolId::INTERACTION_MODEL,
            request,
        );

        let device = async {
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let DecodeInboundOutput::AppMessage { exchange_id, .. } =
                dev.decode_inbound(&pkt, Instant::now()).unwrap()
            else {
                panic!("expected an application message");
            };
            // Straggler: a secured frame addressed to unknown session id 99.
            let stray = stale
                .encode_outbound(
                    stale_sid,
                    None,
                    0x09,
                    ProtocolId::INTERACTION_MODEL,
                    b"stale",
                    MrpFlags { reliable: false },
                    Instant::now(),
                )
                .unwrap();
            dev_io.send_to(&stray.wire_bytes, ctrl_addr).await.unwrap();
            // Then the real secured response on the live session.
            let out = dev
                .encode_outbound(
                    session,
                    Some(exchange_id),
                    0x09,
                    ProtocolId::INTERACTION_MODEL,
                    response,
                    MrpFlags { reliable: true },
                    Instant::now(),
                )
                .unwrap();
            dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        assert_eq!(got.unwrap().payload, response);
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
                // Wait for the request; ignore any ack-only / other frames.
                if let DecodeInboundOutput::AppMessage {
                    exchange_id,
                    payload,
                    ..
                } = dev.decode_inbound(&pkt, Instant::now()).unwrap()
                {
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
            }
        };

        let (got, ()) = tokio::join!(controller, device);
        let got = got.unwrap();
        assert_eq!(got.payload, response);
    }

    /// Build a `ReportData` carrying one attribute `(ep,cl,at)=val` with the
    /// given `MoreChunkedMessages` flag (CR.1 wire shape).
    fn report_data(ep: u16, cl: u32, at: u32, val: u64, more: bool) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(1)).unwrap(); // AttributeReports
        w.start_structure(Tag::Anonymous).unwrap(); // AttributeReportIB
        w.start_structure(Tag::Context(1)).unwrap(); // AttributeData
        w.start_list(Tag::Context(1)).unwrap(); // Path
        w.put_uint(Tag::Context(2), u64::from(ep)).unwrap();
        w.put_uint(Tag::Context(3), u64::from(cl)).unwrap();
        w.put_uint(Tag::Context(4), u64::from(at)).unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(2), val).unwrap(); // Data
        w.end_container().unwrap(); // AttributeData
        w.end_container().unwrap(); // AttributeReportIB
        w.end_container().unwrap(); // array
        if more {
            w.put_bool(Tag::Context(3), true).unwrap(); // MoreChunkedMessages
        }
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();
        buf
    }

    #[tokio::test]
    async fn secured_read_reassembles_two_chunks() {
        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = matter_transport::SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        let controller = secured_read(
            &ctrl_io,
            &mut ctrl,
            session,
            dev_addr,
            0x02, // ReadRequest
            ProtocolId::INTERACTION_MODEL,
            b"readreq",
        );

        let device = async {
            // 1. Receive the ReadRequest.
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let DecodeInboundOutput::AppMessage { exchange_id, .. } =
                dev.decode_inbound(&pkt, Instant::now()).unwrap()
            else {
                panic!("expected ReadRequest");
            };
            // 2. Send chunk 0 (MoreChunkedMessages=true): ep0/0x28/0x0002 = 5010.
            let c0 = report_data(0, 0x28, 0x0002, 5010, true);
            let out = dev
                .encode_outbound(
                    session,
                    Some(exchange_id),
                    0x05, // ReportData
                    ProtocolId::INTERACTION_MODEL,
                    &c0,
                    MrpFlags { reliable: true },
                    Instant::now(),
                )
                .unwrap();
            dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
            // 3. Receive the controller's StatusResponse ack (opcode 0x01). It
            //    must ride the SAME exchange as the read — that is what
            //    piggybacks chunk 0's MRP ack and solicits the next chunk.
            let (ack, _) = dev_io.recv_from().await.unwrap();
            let DecodeInboundOutput::AppMessage {
                opcode,
                exchange_id: ack_exchange,
                ..
            } = dev.decode_inbound(&ack, Instant::now()).unwrap()
            else {
                panic!("expected StatusResponse");
            };
            assert_eq!(
                opcode, 0x01,
                "controller must ack the chunk with StatusResponse"
            );
            assert_eq!(
                ack_exchange, exchange_id,
                "StatusResponse must ride the read exchange (enables the chunk-ack piggyback)"
            );
            // 4. Send the final chunk (no MoreChunkedMessages): ep1/0x06/0x0000 = 1.
            let c1 = report_data(1, 0x06, 0x0000, 1, false);
            let out = dev
                .encode_outbound(
                    session,
                    Some(exchange_id),
                    0x05,
                    ProtocolId::INTERACTION_MODEL,
                    &c1,
                    MrpFlags { reliable: true },
                    Instant::now(),
                )
                .unwrap();
            dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        let chunks = got.unwrap();
        assert_eq!(chunks.len(), 2, "both chunks returned");
        // Reassemble through the CR.1 accumulator.
        let mut acc = crate::im::ReportAccumulator::new();
        for c in &chunks {
            acc.push(crate::im::parse_report_data(c).unwrap()).unwrap();
        }
        let attrs = acc.finish();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0.endpoint, 0);
        assert_eq!(attrs[1].0.endpoint, 1);
    }
}
