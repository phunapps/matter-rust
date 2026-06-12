//! Unsecured (session-id 0) message framing for the PASE handshake (M6.6 §5).
//!
//! `matter-transport`'s `SessionManager` only handles *encrypted* sessions —
//! it always encrypts and explicitly skips session id 0. The PASE handshake
//! runs UNSECURED (session id 0, plaintext, `SecureChannel` protocol, opcodes
//! `PBKDFParamRequest 0x20` … `PASE_Pake3 0x24`). connectedhomeip models this
//! as a first-class unauthenticated session, so it is a necessary path, not a
//! hack. This module builds it directly on the transport's header primitives:
//! the wire layout is `secured-message-header (session id 0) || protocol-header
//! || plaintext app payload` — no AES-CCM.
//!
//! Header conventions (resolved during M6.6.5 real-device validation, Tapo
//! P110M): session-establishment messages SHALL set the `S` bit and carry a
//! random *ephemeral source node id* (Matter Core Spec §4.13.2.1) — devices
//! key their unsecured session context on it and **silently drop** frames
//! without it. The unsecured message counter SHALL be seeded as a random
//! 28-bit value + 1 (§4.5.1.1). Security flags stay empty and the destination
//! node id stays absent on the initiator side; the responder echoes our
//! ephemeral id back as the destination.

use std::net::SocketAddr;
use std::time::Duration;

use matter_transport::{
    decode_header, decode_protocol_header, encode_header, encode_protocol_header, ExchangeFlags,
    MessageCounter, NodeId, ProtocolHeader, ProtocolId, SecuredMessageFlags, SecuredMessageHeader,
    SecurityFlags, SessionId,
};

use crate::driver::datagram::AsyncDatagram;
use crate::driver::error::DriverError;

/// `SecureChannel` `MRP Standalone Acknowledgement` opcode (spec §4.12.8).
/// Devices send one when a reliable message's response is not immediately
/// ready; it acknowledges delivery but is NOT the exchange's response.
const OPCODE_MRP_STANDALONE_ACK: u8 = 0x10;

/// `SecureChannel` `StatusReport` opcode (spec §4.10.1.1). Devices close a
/// PASE/CASE handshake with one (`SessionEstablishmentSuccess` or a failure
/// code) after the terminal message (Pake3 / Sigma3).
const OPCODE_STATUS_REPORT: u8 = 0x40;

/// Parsed `SecureChannel` `StatusReport` body (spec §4.10.1.1): three fixed
/// little-endian fields, no TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureChannelStatus {
    /// General code: `0` SUCCESS, `1` FAILURE, … (spec Table 22).
    pub general_code: u16,
    /// Protocol id the protocol code belongs to (`0x0000` = `SecureChannel`).
    pub protocol_id: u32,
    /// Protocol-specific code (`0x0000` = `SessionEstablishmentSuccess`).
    pub protocol_code: u16,
}

impl SecureChannelStatus {
    /// `true` for the handshake-closing success report: general SUCCESS and
    /// `SecureChannel` `SessionEstablishmentSuccess`.
    #[must_use]
    pub fn is_session_establishment_success(self) -> bool {
        self.general_code == 0 && self.protocol_id == 0 && self.protocol_code == 0
    }
}

/// Parse `msg` as a `SecureChannel` `StatusReport`, the message that closes a
/// PASE/CASE handshake.
///
/// # Errors
///
/// - [`DriverError::Handshake`] if the opcode is not `StatusReport 0x40` or
///   the body is shorter than the fixed 8-byte layout.
pub fn parse_status_report(msg: &UnsecuredMessage) -> Result<SecureChannelStatus, DriverError> {
    if msg.opcode != OPCODE_STATUS_REPORT {
        return Err(DriverError::Handshake(
            "expected a SecureChannel StatusReport to close the handshake",
        ));
    }
    let b = &msg.payload;
    if b.len() < 8 {
        return Err(DriverError::Handshake("StatusReport body truncated"));
    }
    Ok(SecureChannelStatus {
        general_code: u16::from_le_bytes([b[0], b[1]]),
        protocol_id: u32::from_le_bytes([b[2], b[3], b[4], b[5]]),
        protocol_code: u16::from_le_bytes([b[6], b[7]]),
    })
}

/// Require `msg` to be the `SecureChannel` handshake message `opcode`.
///
/// A `StatusReport` in its place is a *rejection* (e.g. `NoSharedTrustRoots`
/// when Sigma1's destination id matches no fabric, or `InvalidParameter` on
/// a failed PASE proof) and is surfaced as
/// [`DriverError::SessionEstablishmentFailed`] carrying the device's codes —
/// never fed into the next handshake parser (observed misparse on a real
/// device: Tapo P110M, M6.6.5 validation).
///
/// # Errors
///
/// - [`DriverError::SessionEstablishmentFailed`] for a `StatusReport`.
/// - [`DriverError::Handshake`] for any other unexpected opcode or a
///   malformed `StatusReport` body.
pub fn require_handshake_opcode(msg: &UnsecuredMessage, opcode: u8) -> Result<(), DriverError> {
    if msg.protocol_id == ProtocolId::SECURE_CHANNEL && msg.opcode == opcode {
        return Ok(());
    }
    if msg.protocol_id == ProtocolId::SECURE_CHANNEL && msg.opcode == OPCODE_STATUS_REPORT {
        let status = parse_status_report(msg)?;
        return Err(DriverError::SessionEstablishmentFailed {
            general_code: status.general_code,
            protocol_code: status.protocol_code,
        });
    }
    Err(DriverError::Handshake(
        "unexpected opcode in session-establishment exchange",
    ))
}

/// A decoded unsecured message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsecuredMessage {
    /// The secured-message-header message counter (the peer's outbound counter).
    pub message_counter: u32,
    /// Exchange id from the protocol header.
    pub exchange_id: u16,
    /// Protocol opcode (e.g. `PBKDFParamResponse 0x21`).
    pub opcode: u8,
    /// Protocol id (always `SECURE_CHANNEL` for PASE).
    pub protocol_id: ProtocolId,
    /// Whether the sender set the initiator (`I`) flag.
    pub is_initiator: bool,
    /// Acknowledged counter, if the `A` flag was set.
    pub ack_counter: Option<u32>,
    /// Sender's source node id, if the `S` flag was set (for session
    /// establishment this is the peer's random ephemeral node id).
    pub source_node_id: Option<u64>,
    /// Plaintext application payload (post-protocol-header bytes).
    pub payload: Vec<u8>,
}

/// Encode an unsecured (session-id 0, plaintext) message: secured-message
/// header || protocol header || `app_payload`. The `ACK` and `VENDOR` exchange
/// flags are auto-derived by `encode_protocol_header` from `ack`/`protocol_id`.
/// `source_node_id` sets the header's `S` flag and 8-byte field — required on
/// every session-establishment message (spec §4.13.2.1); devices drop frames
/// without it.
#[allow(clippy::too_many_arguments)] // Threaded header inputs; matches encode_outbound's shape.
#[must_use]
pub fn encode_unsecured(
    message_counter: u32,
    exchange_id: u16,
    opcode: u8,
    protocol_id: ProtocolId,
    initiator: bool,
    reliable: bool,
    ack: Option<u32>,
    source_node_id: Option<u64>,
    app_payload: &[u8],
) -> Vec<u8> {
    let mut flags = SecuredMessageFlags::empty();
    if source_node_id.is_some() {
        flags |= SecuredMessageFlags::SOURCE_PRESENT;
    }
    let header = SecuredMessageHeader {
        flags,
        session_id: SessionId(0),
        security_flags: SecurityFlags::empty(),
        message_counter: MessageCounter(message_counter),
        source_node_id: source_node_id.map(NodeId),
        destination_node_id: None,
    };
    let mut buf = encode_header(&header);

    let mut exchange_flags = ExchangeFlags::empty();
    if initiator {
        exchange_flags |= ExchangeFlags::INITIATOR;
    }
    if reliable {
        exchange_flags |= ExchangeFlags::RELIABLE;
    }
    let protocol_header = ProtocolHeader {
        exchange_flags,
        opcode,
        exchange_id,
        protocol_id,
        ack_counter: ack.map(MessageCounter),
    };
    encode_protocol_header(&protocol_header, &mut buf);
    buf.extend_from_slice(app_payload);
    buf
}

/// Decode an unsecured message. Rejects any frame whose session id is non-zero
/// (those are encrypted and must go through `SessionManager`).
///
/// # Errors
///
/// - [`DriverError::UnexpectedSecuredMessage`] if the session id is non-zero.
/// - [`DriverError::Transport`] if the secured-message or protocol header is
///   malformed.
pub fn decode_unsecured(bytes: &[u8]) -> Result<UnsecuredMessage, DriverError> {
    let (msg_header, rest) = decode_header(bytes)?;
    if msg_header.session_id.0 != 0 {
        return Err(DriverError::UnexpectedSecuredMessage(
            msg_header.session_id.0,
        ));
    }
    let (protocol_header, app) = decode_protocol_header(rest)?;
    Ok(UnsecuredMessage {
        message_counter: msg_header.message_counter.0,
        exchange_id: protocol_header.exchange_id,
        opcode: protocol_header.opcode,
        protocol_id: protocol_header.protocol_id,
        is_initiator: protocol_header
            .exchange_flags
            .contains(ExchangeFlags::INITIATOR),
        ack_counter: protocol_header.ack_counter.map(|c| c.0),
        source_node_id: msg_header.source_node_id.map(|n| n.0),
        payload: app.to_vec(),
    })
}

/// Minimal stop-and-wait reliable sender for the unsecured PASE handshake.
///
/// Owns the unsecured message counter and the handshake's exchange id. Each
/// `send_and_recv` transmits one message (initiator, reliable) and awaits the
/// next inbound unsecured message, retransmitting on timeout up to
/// `max_attempts`. This is intentionally simpler than full MRP — the 5 PASE
/// messages are strictly ordered request→response, so stop-and-wait suffices;
/// hardening to MRP-over-unsecured can follow.
pub struct UnsecuredExchange {
    counter: u32,
    exchange_id: u16,
    source_node_id: u64,
    retransmit: Duration,
    response_timeout: Duration,
    max_attempts: u8,
    /// The peer's highest message counter we have already consumed as a real
    /// response on this exchange, if any. Used by `send_and_recv` to drop a
    /// retransmitted prior-step frame (stop-and-wait dedup): the unsecured path
    /// has no `ReplayWindow` (that lives only in the secured `SessionManager`),
    /// so we track it here. `None` until the first response is consumed.
    last_consumed_peer_counter: Option<u32>,
}

impl UnsecuredExchange {
    /// Create an exchange with the given initial message counter, exchange id,
    /// and ephemeral source node id. Deterministic — intended for tests and
    /// trace reproduction; production callers use [`Self::new_ephemeral`].
    ///
    /// Defaults: 300 ms retransmit, 5 attempts (matching MRP's
    /// `initial_active` / `max_attempts`), 30 s post-ack response timeout.
    #[must_use]
    pub fn new(initial_counter: u32, exchange_id: u16, source_node_id: u64) -> Self {
        Self {
            counter: initial_counter,
            exchange_id,
            source_node_id,
            retransmit: Duration::from_millis(300),
            response_timeout: Duration::from_secs(30),
            max_attempts: 5,
            last_consumed_peer_counter: None,
        }
    }

    /// Create an exchange with a CSPRNG-seeded message counter and ephemeral
    /// source node id — the production constructor.
    ///
    /// - Counter: random 28-bit value + 1 (Matter Core Spec §4.5.1.1, matching
    ///   matter.js's `MessageCounter` initialisation).
    /// - Source node id: random, masked to the low 60 bits (keeps it inside
    ///   the operational node-id range `1..=0xFFFF_FFEF_FFFF_FFFF` required
    ///   for ephemeral ids, §4.13.2.1) and clamped nonzero.
    ///
    /// # Errors
    ///
    /// - [`DriverError::Handshake`] if the system CSPRNG fails (ring reports
    ///   no detail; this is effectively unreachable on supported platforms).
    pub fn new_ephemeral(exchange_id: u16) -> Result<Self, DriverError> {
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = [0u8; 12];
        ring::rand::SecureRandom::fill(&rng, &mut bytes).map_err(|_| {
            DriverError::Handshake("system CSPRNG failure seeding unsecured session")
        })?;
        // First 4 bytes → counter, remaining 8 → ephemeral node id.
        let counter_seed: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let node_seed: [u8; 8] = [
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ];
        let counter = (u32::from_le_bytes(counter_seed) & 0x0FFF_FFFF) + 1;
        let source_node_id = (u64::from_le_bytes(node_seed) & 0x0FFF_FFFF_FFFF_FFFF).max(1);
        Ok(Self::new(counter, exchange_id, source_node_id))
    }

    /// Send an MRP standalone acknowledgement (`SecureChannel 0x10`) for the
    /// peer's reliable message `peer_counter` — used to ack the handshake's
    /// closing `StatusReport` so the device stops retransmitting it. Fire and
    /// forget (an ack is itself never acked); advances the message counter.
    ///
    /// # Errors
    ///
    /// - [`DriverError::Io`] if the datagram send fails.
    pub async fn send_standalone_ack<T: AsyncDatagram>(
        &mut self,
        transport: &T,
        peer: SocketAddr,
        peer_counter: u32,
    ) -> Result<(), DriverError> {
        let counter = self.counter;
        self.counter = self.counter.wrapping_add(1);
        let wire = encode_unsecured(
            counter,
            self.exchange_id,
            OPCODE_MRP_STANDALONE_ACK,
            ProtocolId::SECURE_CHANNEL,
            true,
            false,
            Some(peer_counter),
            Some(self.source_node_id),
            &[],
        );
        transport.send_to(&wire, peer).await?;
        // M6 wire-trace capture: feeds JsonlLayer / cargo xtask trace-diff.
        #[cfg(feature = "tracing")]
        tracing::debug!(
            target: "matter_wire",
            dir = "tx",
            session_id = 0_u64,
            exchange_id = u64::from(self.exchange_id),
            protocol = u64::from(ProtocolId::SECURE_CHANNEL.protocol),
            opcode = u64::from(OPCODE_MRP_STANDALONE_ACK),
            payload = "",
            "wire"
        );
        Ok(())
    }

    /// Send one unsecured message (initiator, reliable) and await the
    /// exchange's response, retransmitting on timeout. `ack` piggybacks the
    /// previous message's counter when the caller has one to acknowledge.
    ///
    /// `opcode` is the opcode being sent; `expected_opcode` is the
    /// `SecureChannel` opcode of the awaited next-step response (e.g.
    /// `PBKDFParamResponse 0x21` after sending `PBKDFParamRequest 0x20`, or
    /// `StatusReport 0x40` after the terminal `Pake3`/`Sigma3`).
    ///
    /// Frames that are NOT the awaited next step are skipped rather than
    /// returned, so the handshake waits for the real frame instead of aborting:
    ///
    /// - MRP standalone acks (`SecureChannel 0x10`) — a standalone ack stops
    ///   further retransmission and extends the wait to the response timeout.
    /// - Frames from other exchanges (mismatched exchange id).
    /// - **Stale prior-step responses**: an in-flight MRP retransmit of a
    ///   previous step's response (the peer resends reliable frames until it
    ///   sees our next message) matches the exchange id but is not the awaited
    ///   opcode. The unsecured path has no `ReplayWindow`, so these are dropped
    ///   here both by opcode (not `expected_opcode`) and, as a backstop, by
    ///   message-counter dedup (counter `<=` the last consumed response).
    ///
    /// A terminal `StatusReport 0x40` is always surfaced (it carries a possible
    /// rejection); a genuinely unexpected frame that never resolves still fails
    /// via the response deadline rather than hanging.
    ///
    /// # Errors
    ///
    /// - [`DriverError::Io`] if a datagram send/recv fails.
    /// - [`DriverError::Transport`] / [`DriverError::UnexpectedSecuredMessage`]
    ///   if the reply does not decode as an unsecured message.
    /// - [`DriverError::Timeout`] if no reply arrives within `max_attempts`.
    // Cohesive single retransmit/recv loop: the length comes from the
    // cfg-gated wire-tracing blocks and the documented per-frame skip cases
    // (secured straggler, foreign exchange, standalone-ack, counter dedup,
    // opcode gate). Splitting it would force threading the loop state
    // (acked/attempts/counter) through a helper for no readability gain.
    #[allow(clippy::too_many_lines)]
    pub async fn send_and_recv<T: AsyncDatagram>(
        &mut self,
        transport: &T,
        peer: SocketAddr,
        opcode: u8,
        expected_opcode: u8,
        app_payload: &[u8],
        ack: Option<u32>,
    ) -> Result<UnsecuredMessage, DriverError> {
        let counter = self.counter;
        self.counter = self.counter.wrapping_add(1);
        let wire = encode_unsecured(
            counter,
            self.exchange_id,
            opcode,
            ProtocolId::SECURE_CHANNEL,
            true,
            true,
            ack,
            Some(self.source_node_id),
            app_payload,
        );

        #[cfg(feature = "tracing")]
        tracing::debug!(
            opcode = format_args!("{opcode:#04x}"),
            exchange_id = self.exchange_id,
            wire = %crate::hexdump::hex(&wire),
            "unsecured send"
        );
        // M6 wire-trace capture: feeds JsonlLayer / cargo xtask trace-diff.
        #[cfg(feature = "tracing")]
        tracing::debug!(
            target: "matter_wire",
            dir = "tx",
            session_id = 0_u64,
            exchange_id = u64::from(self.exchange_id),
            protocol = u64::from(ProtocolId::SECURE_CHANNEL.protocol),
            opcode = u64::from(opcode),
            payload = %crate::hexdump::hex(app_payload),
            "wire"
        );
        let mut attempts: u8 = 0;
        // Once the peer acknowledges delivery (standalone ack), stop
        // retransmitting and switch to the longer response timeout — the
        // device has the message and is computing its reply (observed: real
        // devices standalone-ack a PASE message before the SPAKE2+ response).
        let mut acked = false;
        loop {
            if !acked {
                transport.send_to(&wire, peer).await?;
            }
            let wait = if acked {
                self.response_timeout
            } else {
                self.retransmit
            };
            match tokio::time::timeout(wait, transport.recv_from()).await {
                Ok(recv) => {
                    let (packet, _from) = recv?;
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        len = packet.len(),
                        head = %crate::hexdump::hex(&packet[..packet.len().min(24)]),
                        "unsecured recv"
                    );
                    // Secured-session stragglers (session id ≠ 0 at header
                    // offset 1, e.g. an MRP retransmit of the last PASE-
                    // session response whose standalone ack the device has
                    // not seen yet) are not part of this unsecured exchange —
                    // skip, don't abort (observed: Tapo P110M, M6.6.5).
                    if packet.len() >= 3 && (packet[1] != 0 || packet[2] != 0) {
                        continue;
                    }
                    let msg = decode_unsecured(&packet)?;
                    if msg.exchange_id != self.exchange_id {
                        // Stray frame from another exchange — not ours.
                        continue;
                    }
                    if msg.protocol_id == ProtocolId::SECURE_CHANNEL
                        && msg.opcode == OPCODE_MRP_STANDALONE_ACK
                    {
                        acked = true;
                        continue;
                    }
                    // Counter dedup backstop: a retransmit of a prior-step
                    // response carries a counter we have already consumed on
                    // this exchange. The unsecured path has no ReplayWindow, so
                    // drop it here (stop-and-wait: each step's response counter
                    // is strictly greater than the last).
                    if let Some(last) = self.last_consumed_peer_counter {
                        if msg.message_counter <= last {
                            continue;
                        }
                    }
                    // Opcode gate: skip any frame that is neither the awaited
                    // next-step opcode nor a terminal StatusReport (a rejection
                    // we must surface). A retransmitted previous-step response
                    // (e.g. PBKDFParamResponse 0x21 while awaiting Pake2 0x23)
                    // is dropped here rather than returned — returning it would
                    // trip the require_handshake_opcode gate and abort the
                    // handshake (observed cause of intermittent commissioning
                    // failures on lossy/duplicating networks).
                    if msg.protocol_id == ProtocolId::SECURE_CHANNEL
                        && msg.opcode != expected_opcode
                        && msg.opcode != OPCODE_STATUS_REPORT
                    {
                        continue;
                    }
                    // This is the awaited response (or a terminal StatusReport):
                    // record its counter so any later retransmit of it is
                    // deduped on the next step.
                    self.last_consumed_peer_counter = Some(msg.message_counter);
                    // M6 wire-trace capture: feeds JsonlLayer / cargo xtask trace-diff.
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        target: "matter_wire",
                        dir = "rx",
                        session_id = 0_u64,
                        exchange_id = u64::from(msg.exchange_id),
                        protocol = u64::from(msg.protocol_id.protocol),
                        opcode = u64::from(msg.opcode),
                        payload = %crate::hexdump::hex(&msg.payload),
                        "wire"
                    );
                    return Ok(msg);
                }
                Err(_elapsed) => {
                    if acked {
                        // Delivery was acknowledged but no response came: the
                        // peer abandoned the exchange. Retransmitting cannot
                        // help (it would be deduplicated); surface a timeout.
                        return Err(DriverError::Timeout {
                            exchange_id: self.exchange_id,
                        });
                    }
                    attempts += 1;
                    if attempts >= self.max_attempts {
                        return Err(DriverError::Timeout {
                            exchange_id: self.exchange_id,
                        });
                    }
                    // loop → retransmit the same bytes.
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use matter_transport::ProtocolId;

    use crate::driver::datagram::{AsyncDatagram, InMemoryDatagram};

    use super::*;

    #[test]
    fn unsecured_roundtrip_preserves_fields() {
        // PASE_Pake1 (0x22), initiator, reliable, acking counter 7.
        let wire = encode_unsecured(
            0x8000_0001,
            42,
            0x22,
            ProtocolId::SECURE_CHANNEL,
            true,
            true,
            Some(7),
            None,
            b"pake1-bytes",
        );
        let msg = decode_unsecured(&wire).unwrap();
        assert_eq!(msg.message_counter, 0x8000_0001);
        assert_eq!(msg.exchange_id, 42);
        assert_eq!(msg.opcode, 0x22);
        assert_eq!(msg.protocol_id, ProtocolId::SECURE_CHANNEL);
        assert!(msg.is_initiator);
        assert_eq!(msg.ack_counter, Some(7));
        assert_eq!(msg.payload, b"pake1-bytes");
    }

    #[test]
    fn unsecured_rejects_secured_session_id() {
        // Hand-build a frame with a non-zero session id via the transport
        // primitive, then assert decode rejects it.
        use matter_transport::{
            encode_header, MessageCounter, SecuredMessageFlags, SecuredMessageHeader,
            SecurityFlags, SessionId,
        };
        let hdr = SecuredMessageHeader {
            flags: SecuredMessageFlags::empty(),
            session_id: SessionId(5), // non-zero ⇒ secured
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(1),
            source_node_id: None,
            destination_node_id: None,
        };
        let mut wire = encode_header(&hdr);
        wire.extend_from_slice(&[0u8; 6]); // minimal protocol-header bytes
        let err = decode_unsecured(&wire).unwrap_err();
        assert!(matches!(err, DriverError::UnexpectedSecuredMessage(5)));
    }

    #[tokio::test]
    async fn unsecured_send_and_recv_roundtrips() {
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut exch = UnsecuredExchange::new(1, 7, 0xE0E0);

        let controller = exch.send_and_recv(
            &ctrl_io, dev_addr, 0x20, /* PBKDFParamRequest */
            0x21, /* awaiting PBKDFParamResponse */
            b"req", None,
        );

        let device = async {
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let msg = decode_unsecured(&pkt).unwrap();
            assert_eq!(msg.opcode, 0x20);
            assert_eq!(msg.payload, b"req");
            // Reply PBKDFParamResponse (0x21), acking the request's counter.
            let reply = encode_unsecured(
                100,
                msg.exchange_id,
                0x21,
                ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(msg.message_counter),
                None,
                b"resp",
            );
            dev_io.send_to(&reply, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        let got = got.unwrap();
        assert_eq!(got.opcode, 0x21);
        assert_eq!(got.payload, b"resp");
    }

    #[tokio::test]
    async fn unsecured_standalone_ack_has_expected_shape() {
        let (a, b) = InMemoryDatagram::pair();
        let b_addr = b.local_addr();
        let mut exch = UnsecuredExchange::new(5, 9, 0xE0E0);
        exch.send_standalone_ack(&a, b_addr, 7).await.unwrap();
        let (pkt, _) = b.recv_from().await.unwrap();
        let msg = decode_unsecured(&pkt).unwrap();
        assert_eq!(msg.opcode, 0x10);
        assert!(msg.payload.is_empty());
        assert_eq!(msg.message_counter, 5);
        assert_eq!(msg.ack_counter, Some(7));
        assert!(msg.is_initiator);
        assert_eq!(msg.source_node_id, Some(0xE0E0));
    }

    #[test]
    fn status_report_parses_success_and_failure() {
        let mk = |general: u16, code: u16| UnsecuredMessage {
            message_counter: 1,
            exchange_id: 1,
            opcode: 0x40,
            protocol_id: ProtocolId::SECURE_CHANNEL,
            is_initiator: false,
            ack_counter: None,
            source_node_id: None,
            payload: {
                let mut b = Vec::new();
                b.extend_from_slice(&general.to_le_bytes());
                b.extend_from_slice(&0u32.to_le_bytes());
                b.extend_from_slice(&code.to_le_bytes());
                b
            },
        };
        let ok = parse_status_report(&mk(0, 0)).unwrap();
        assert!(ok.is_session_establishment_success());
        let no = parse_status_report(&mk(1, 0x0002)).unwrap();
        assert!(!no.is_session_establishment_success());
        assert_eq!(no.general_code, 1);
        assert_eq!(no.protocol_code, 0x0002);
        // Wrong opcode is rejected.
        let mut wrong = mk(0, 0);
        wrong.opcode = 0x21;
        assert!(parse_status_report(&wrong).is_err());
    }

    #[test]
    fn unsecured_encode_carries_source_node_id() {
        // Matter Core Spec §4.13.2.1: session-establishment messages SHALL set
        // the S flag and carry a random ephemeral source node id. Real devices
        // (observed: Tapo P110M, M6.6.5 validation) silently drop unsecured
        // frames without it.
        let wire = encode_unsecured(
            1,
            7,
            0x20,
            ProtocolId::SECURE_CHANNEL,
            true,
            true,
            None,
            Some(0x1122_3344_5566_7788),
            b"req",
        );
        // Byte 0 message flags: S bit (0b100) set.
        assert_eq!(wire[0] & 0b0000_0100, 0b0000_0100, "S flag must be set");
        // Bytes 8..16: the source node id, little-endian.
        assert_eq!(wire[8..16], 0x1122_3344_5566_7788u64.to_le_bytes());
        let msg = decode_unsecured(&wire).unwrap();
        assert_eq!(msg.source_node_id, Some(0x1122_3344_5566_7788));
    }

    #[tokio::test]
    async fn unsecured_exchange_frames_carry_source_node_id() {
        let (a, b) = InMemoryDatagram::pair();
        let b_addr = b.local_addr();
        let mut exch = UnsecuredExchange::new(5, 9, 0xABCD);
        exch.send_standalone_ack(&a, b_addr, 3).await.unwrap();
        let (pkt, _) = b.recv_from().await.unwrap();
        let msg = decode_unsecured(&pkt).unwrap();
        assert_eq!(msg.source_node_id, Some(0xABCD));
    }

    #[tokio::test]
    async fn unsecured_new_ephemeral_seeds_counter_and_node_id() {
        // The production constructor must seed both the unsecured message
        // counter (spec §4.5.1.1: random 28-bit + 1) and the ephemeral source
        // node id from the CSPRNG.
        let (a, b) = InMemoryDatagram::pair();
        let b_addr = b.local_addr();
        let mut exch = UnsecuredExchange::new_ephemeral(9).unwrap();
        exch.send_standalone_ack(&a, b_addr, 3).await.unwrap();
        let (pkt, _) = b.recv_from().await.unwrap();
        let msg = decode_unsecured(&pkt).unwrap();
        let node_id = msg.source_node_id.expect("ephemeral node id present");
        assert_ne!(node_id, 0, "node id must be nonzero (operational range)");
        assert_ne!(msg.message_counter, 0, "counter must be nonzero");
        assert!(
            msg.message_counter <= 0x0FFF_FFFF + 1,
            "counter seeded as random 28-bit + 1"
        );
    }

    #[tokio::test]
    async fn unsecured_send_and_recv_skips_standalone_ack() {
        // Real devices (observed: Tapo P110M, M6.6.5 validation) ack a reliable
        // PASE message with an MRP *standalone ack* (SecureChannel 0x10) first,
        // then send the actual response as a separate message. send_and_recv
        // must not surface the ack as if it were the response.
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut exch = UnsecuredExchange::new(1, 7, 0xE0E0);

        let controller = exch.send_and_recv(&ctrl_io, dev_addr, 0x20, 0x21, b"req", None);

        let device = async {
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let msg = decode_unsecured(&pkt).unwrap();
            // Standalone ack: SecureChannel 0x10, no payload, acks the request.
            let ack = encode_unsecured(
                100,
                msg.exchange_id,
                0x10,
                ProtocolId::SECURE_CHANNEL,
                false,
                false,
                Some(msg.message_counter),
                None,
                b"",
            );
            dev_io.send_to(&ack, ctrl_addr).await.unwrap();
            // Then the real PBKDFParamResponse on the same exchange.
            let reply = encode_unsecured(
                101,
                msg.exchange_id,
                0x21,
                ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(msg.message_counter),
                None,
                b"resp",
            );
            dev_io.send_to(&reply, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        let got = got.unwrap();
        assert_eq!(got.opcode, 0x21, "standalone ack must be skipped");
        assert_eq!(got.payload, b"resp");
    }

    #[tokio::test]
    async fn unsecured_send_and_recv_skips_secured_frames() {
        // An MRP retransmit of the last PASE-session (secured, session id ≠ 0)
        // response can straggle into the CASE handshake if its standalone ack
        // was still pending when the unsecured exchange started (observed:
        // Tapo P110M, M6.6.5 validation). Skip it — it is not part of this
        // exchange.
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut exch = UnsecuredExchange::new(1, 7, 0xE0E0);

        let controller = exch.send_and_recv(&ctrl_io, dev_addr, 0x30, 0x31, b"sigma1", None);

        let device = async {
            use matter_transport::{
                encode_header, MessageCounter, SecuredMessageFlags, SecuredMessageHeader,
                SecurityFlags, SessionId,
            };
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&pkt).unwrap();
            // Straggler: a secured frame (session id 1) — header built via the
            // transport primitive, payload irrelevant (it would be encrypted).
            let hdr = SecuredMessageHeader {
                flags: SecuredMessageFlags::empty(),
                session_id: SessionId(1),
                security_flags: SecurityFlags::empty(),
                message_counter: MessageCounter(99),
                source_node_id: None,
                destination_node_id: None,
            };
            let mut stray = encode_header(&hdr);
            stray.extend_from_slice(&[0xAA; 24]); // opaque ciphertext
            dev_io.send_to(&stray, ctrl_addr).await.unwrap();
            // Then the real response.
            let reply = encode_unsecured(
                100,
                m.exchange_id,
                0x31,
                ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(m.message_counter),
                None,
                b"sigma2",
            );
            dev_io.send_to(&reply, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        let got = got.unwrap();
        assert_eq!(got.opcode, 0x31, "secured straggler must be skipped");
        assert_eq!(got.payload, b"sigma2");
    }

    #[tokio::test]
    async fn unsecured_send_and_recv_skips_stale_prior_step_response() {
        // After step N's response is consumed and we send step N+1's request,
        // an in-flight MRP retransmit of step N's response (the device resends
        // reliable frames until it sees our next message) still matches the
        // exchange id. send_and_recv must skip it and wait for the real
        // next-step frame, not return it (which would abort the handshake at
        // the require_handshake_opcode gate). Here: awaiting Pake2 (0x23), the
        // device first re-emits the previous PBKDFParamResponse (0x21), then
        // sends the real Pake2.
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut exch = UnsecuredExchange::new(1, 7, 0xE0E0);

        let controller = exch.send_and_recv(
            &ctrl_io, dev_addr, 0x22, /* Pake1 */
            0x23, /* awaiting Pake2 */
            b"pake1", None,
        );

        let device = async {
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&pkt).unwrap();
            // Stale retransmit of the PREVIOUS step's response (0x21).
            let stale = encode_unsecured(
                100,
                m.exchange_id,
                0x21, /* PBKDFParamResponse — stale */
                ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(m.message_counter),
                None,
                b"stale-pbkdf-response",
            );
            dev_io.send_to(&stale, ctrl_addr).await.unwrap();
            // Then the real next-step frame, Pake2 (0x23).
            let reply = encode_unsecured(
                101,
                m.exchange_id,
                0x23,
                ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(m.message_counter),
                None,
                b"pake2",
            );
            dev_io.send_to(&reply, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        let got = got.unwrap();
        assert_eq!(
            got.opcode, 0x23,
            "stale prior-step response must be skipped"
        );
        assert_eq!(got.payload, b"pake2");
    }

    #[tokio::test]
    async fn unsecured_send_and_recv_unexpected_frame_times_out() {
        // A frame that is neither the awaited next-step opcode, a standalone
        // ack, nor a terminal StatusReport (and that never resolves) must not
        // hang forever — the response deadline must still fire and surface a
        // Timeout, so a misbehaving peer fails cleanly.
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut exch = UnsecuredExchange::new(1, 7, 0xE0E0);
        // Shorten the deadlines so the test is fast.
        exch.retransmit = Duration::from_millis(30);
        exch.response_timeout = Duration::from_millis(60);
        exch.max_attempts = 2;

        let controller = exch.send_and_recv(
            &ctrl_io, dev_addr, 0x22, /* Pake1 */
            0x23, /* awaiting Pake2 */
            b"pake1", None,
        );

        let device = async {
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&pkt).unwrap();
            // Standalone ack to stop retransmission and switch to the response
            // deadline, then a wrong-opcode frame that is never followed by the
            // real next-step frame.
            let ack = encode_unsecured(
                100,
                m.exchange_id,
                OPCODE_MRP_STANDALONE_ACK,
                ProtocolId::SECURE_CHANNEL,
                false,
                false,
                Some(m.message_counter),
                None,
                b"",
            );
            dev_io.send_to(&ack, ctrl_addr).await.unwrap();
            let stale = encode_unsecured(
                101,
                m.exchange_id,
                0x21, /* wrong opcode, never resolves */
                ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(m.message_counter),
                None,
                b"stale",
            );
            dev_io.send_to(&stale, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        assert!(
            matches!(got, Err(DriverError::Timeout { exchange_id: 7 })),
            "unexpected unresolving frame must time out, got: {got:?}"
        );
    }

    #[tokio::test]
    async fn unsecured_send_and_recv_retransmits_dropped_send() {
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut exch = UnsecuredExchange::new(1, 7, 0xE0E0);

        ctrl_io.set_drops(1); // drop the first send; the retransmit must land

        let controller = exch.send_and_recv(&ctrl_io, dev_addr, 0x20, 0x21, b"req", None);

        let device = async {
            let (pkt, _) = dev_io.recv_from().await.unwrap(); // sees the retransmit
            let msg = decode_unsecured(&pkt).unwrap();
            let reply = encode_unsecured(
                100,
                msg.exchange_id,
                0x21,
                ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(msg.message_counter),
                None,
                b"resp",
            );
            dev_io.send_to(&reply, ctrl_addr).await.unwrap();
        };

        let (got, ()) = tokio::join!(controller, device);
        assert_eq!(got.unwrap().opcode, 0x21);
    }
}
