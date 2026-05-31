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
//! FLAGGED TO MAINTAINER: the exact unsecured-PASE *header conventions*
//! (whether the source node id / `S` bit must be present, and which security
//! flags real devices expect) are NOT asserted here. This slice emits session
//! id 0, no source/dest node id, and empty security flags, and parameterises
//! initiator/reliable/ack explicitly. The spec-correct convention is confirmed
//! by byte-parity against matter.js when PASE actually flows (M6.6.3 wiring /
//! M6.6.5 real device). M6.6.2 proves only encode/decode inverse-ness.

use matter_transport::{
    decode_header, decode_protocol_header, encode_header, encode_protocol_header, ExchangeFlags,
    MessageCounter, ProtocolHeader, ProtocolId, SecuredMessageFlags, SecuredMessageHeader,
    SecurityFlags, SessionId,
};

use crate::driver::error::DriverError;

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
    /// Plaintext application payload (post-protocol-header bytes).
    pub payload: Vec<u8>,
}

/// Encode an unsecured (session-id 0, plaintext) message: secured-message
/// header || protocol header || `app_payload`. The `ACK` and `VENDOR` exchange
/// flags are auto-derived by `encode_protocol_header` from `ack`/`protocol_id`.
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
    app_payload: &[u8],
) -> Vec<u8> {
    let header = SecuredMessageHeader {
        flags: SecuredMessageFlags::empty(),
        session_id: SessionId(0),
        security_flags: SecurityFlags::empty(),
        message_counter: MessageCounter(message_counter),
        source_node_id: None,
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
        return Err(DriverError::UnexpectedSecuredMessage(msg_header.session_id.0));
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
        payload: app.to_vec(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use matter_transport::ProtocolId;

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
}
