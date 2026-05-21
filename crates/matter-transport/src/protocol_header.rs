//! Matter application protocol header codec (Matter Core Specification
//! §4.4.5).
//!
//! The bytes inside every encrypted payload that carry Exchange Flags,
//! Opcode, Exchange ID, Protocol ID, and optional Acknowledged Message
//! Counter / Secure Extensions / Vendor data. Pure codec — no state, no
//! clock.

use bitflags::bitflags;

use crate::error::{Error, Result};
use crate::framing::MessageCounter;

bitflags! {
    /// First byte of the Matter application protocol header. Bit
    /// positions match matter.js's `ExchangeFlag` enum (verified
    /// byte-parity in `tests/protocol_header_byte_parity.rs`).
    ///
    /// - Bit 0: `I` — initiator-of-exchange.
    /// - Bit 1: `A` — acknowledged message counter present.
    /// - Bit 2: `R` — reliable (requires ack).
    /// - Bit 3: `SX` — secure extensions present (data length-prefix-skipped).
    /// - Bit 4: `V` — vendor data present (data length-prefix-skipped).
    /// - Bits 5..7: reserved (rejected on decode).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExchangeFlags: u8 {
        /// We initiated this exchange.
        const INITIATOR        = 0b0000_0001;
        /// Header carries an acknowledged message counter.
        const ACK              = 0b0000_0010;
        /// Message requires an MRP ack from the peer.
        const RELIABLE         = 0b0000_0100;
        /// Secure-extension data present; decoder skips past it.
        const SECURE_EXTENSION = 0b0000_1000;
        /// Vendor data present; decoder skips past it.
        const VENDOR           = 0b0001_0000;
    }
}

const RESERVED_FLAG_BITS: u8 = 0b1110_0000;

/// Matter protocol identifier: 32-bit `(vendor_id, protocol_id)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolId {
    /// Vendor ID (CSA-assigned). Zero for spec-standard protocols.
    pub vendor: u16,
    /// Protocol short ID within the vendor namespace.
    pub protocol: u16,
}

impl ProtocolId {
    /// Secure Channel protocol — opcode 0x10 is `STANDALONE_ACK`.
    pub const SECURE_CHANNEL: Self = Self {
        vendor: 0,
        protocol: 0x0000,
    };
    /// Interaction Model (Read/Write/Invoke/Subscribe).
    pub const INTERACTION_MODEL: Self = Self {
        vendor: 0,
        protocol: 0x0001,
    };
    /// Bulk Data Exchange (OTA, etc.).
    pub const BDX: Self = Self {
        vendor: 0,
        protocol: 0x0002,
    };
}

/// Spec-defined opcodes by protocol.
pub mod opcode {
    /// Opcodes within `ProtocolId::SECURE_CHANNEL`.
    pub mod secure_channel {
        /// MRP standalone acknowledgement (Matter Core Spec §4.11.5).
        /// Empty payload, A=1, R=0.
        pub const STANDALONE_ACK: u8 = 0x10;
    }
}

/// Parsed view of the Matter application protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolHeader {
    /// Exchange-control flag bits.
    pub exchange_flags: ExchangeFlags,
    /// Protocol opcode (interpreted within `protocol_id`'s namespace).
    pub opcode: u8,
    /// Exchange identifier — uniquely identifies a request/response pair.
    pub exchange_id: u16,
    /// Protocol identifier.
    pub protocol_id: ProtocolId,
    /// Present iff `exchange_flags.contains(ACK)`.
    pub ack_counter: Option<MessageCounter>,
}

/// Encode a [`ProtocolHeader`] into the output buffer.
///
/// SX and V data are never emitted by this function — even if the caller
/// sets `SECURE_EXTENSION` or `VENDOR` in `exchange_flags`, no extension
/// bytes follow. (Encoder is asymmetric to the decoder for forward-compat;
/// it's a future expansion point.)
pub fn encode_protocol_header(h: &ProtocolHeader, out: &mut Vec<u8>) {
    out.push(h.exchange_flags.bits());
    out.push(h.opcode);
    out.extend_from_slice(&h.exchange_id.to_le_bytes());
    out.extend_from_slice(&h.protocol_id.vendor.to_le_bytes());
    out.extend_from_slice(&h.protocol_id.protocol.to_le_bytes());
    if let Some(MessageCounter(c)) = h.ack_counter {
        out.extend_from_slice(&c.to_le_bytes());
    }
}

/// Decode a [`ProtocolHeader`] from the start of `bytes`. Returns the
/// parsed header and the remaining bytes (the application payload tail).
///
/// SX and V data, when their bits are set, are length-prefix-skipped and
/// discarded. The bits stay set in `ExchangeFlags` so future callers can
/// detect that extensions were present.
///
/// # Errors
///
/// Returns [`Error::MalformedProtocolHeader`] if:
/// - the fixed 8-byte portion is truncated;
/// - `A=1` but the 4-byte ack counter is truncated;
/// - `SX=1` but the 2-byte length prefix or the announced data length is
///   truncated;
/// - `V=1` but the 2-byte length prefix or the announced data length is
///   truncated;
/// - any reserved flag bit (5..=7) is set.
pub fn decode_protocol_header(bytes: &[u8]) -> Result<(ProtocolHeader, &[u8])> {
    if bytes.len() < 8 {
        return Err(Error::MalformedProtocolHeader(bytes.len()));
    }
    let flag_byte = bytes[0];
    if flag_byte & RESERVED_FLAG_BITS != 0 {
        return Err(Error::MalformedProtocolHeader(0));
    }
    let flags = ExchangeFlags::from_bits_retain(flag_byte);
    let opcode = bytes[1];
    let exchange_id = u16::from_le_bytes([bytes[2], bytes[3]]);
    let vendor = u16::from_le_bytes([bytes[4], bytes[5]]);
    let protocol = u16::from_le_bytes([bytes[6], bytes[7]]);
    let protocol_id = ProtocolId { vendor, protocol };

    let mut offset = 8;

    let ack_counter = if flags.contains(ExchangeFlags::ACK) {
        if bytes.len() < offset + 4 {
            return Err(Error::MalformedProtocolHeader(offset));
        }
        let value = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;
        Some(MessageCounter(value))
    } else {
        None
    };

    if flags.contains(ExchangeFlags::SECURE_EXTENSION) {
        offset = skip_length_prefixed(bytes, offset)?;
    }
    if flags.contains(ExchangeFlags::VENDOR) {
        offset = skip_length_prefixed(bytes, offset)?;
    }

    let parsed = ProtocolHeader {
        exchange_flags: flags,
        opcode,
        exchange_id,
        protocol_id,
        ack_counter,
    };
    Ok((parsed, &bytes[offset..]))
}

/// Skip a 2-byte-LE-length-prefixed blob. Returns the new offset.
fn skip_length_prefixed(bytes: &[u8], offset: usize) -> Result<usize> {
    if bytes.len() < offset + 2 {
        return Err(Error::MalformedProtocolHeader(offset));
    }
    let len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    let data_offset = offset + 2;
    if bytes.len() < data_offset + len {
        return Err(Error::MalformedProtocolHeader(data_offset));
    }
    Ok(data_offset + len)
}

/// Build a [`ProtocolHeader`] for a standalone-ack message. Used by
/// `SessionManager` when piggyback drain misses the 200ms deadline OR a
/// duplicate reliable inbound is detected.
///
/// Flags = `A | (I if is_local_initiator)`. Opcode =
/// [`opcode::secure_channel::STANDALONE_ACK`]. Protocol = `SecureChannel`.
/// Exchange ID and `ack_counter` come from the caller.
#[must_use]
pub fn build_standalone_ack_header(
    exchange_id: u16,
    ack_counter: MessageCounter,
    is_local_initiator: bool,
) -> ProtocolHeader {
    let mut flags = ExchangeFlags::ACK;
    if is_local_initiator {
        flags |= ExchangeFlags::INITIATOR;
    }
    ProtocolHeader {
        exchange_flags: flags,
        opcode: opcode::secure_channel::STANDALONE_ACK,
        exchange_id,
        protocol_id: ProtocolId::SECURE_CHANNEL,
        ack_counter: Some(ack_counter),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    #[test]
    fn minimal_header_roundtrip() {
        let header = ProtocolHeader {
            exchange_flags: ExchangeFlags::INITIATOR,
            opcode: 0x20,
            exchange_id: 0x4242,
            protocol_id: ProtocolId::INTERACTION_MODEL,
            ack_counter: None,
        };
        let mut out = Vec::new();
        encode_protocol_header(&header, &mut out);
        assert_eq!(out.len(), 8, "8-byte fixed header without optional fields");
        // Flags(1) | opcode(1) | exchange_id LE(2) | protocol_id LE(4)
        assert_eq!(out, vec![0x01, 0x20, 0x42, 0x42, 0x00, 0x00, 0x01, 0x00],);
        let (parsed, rest) = decode_protocol_header(&out).unwrap();
        assert_eq!(parsed, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_with_ack_counter() {
        let header = ProtocolHeader {
            exchange_flags: ExchangeFlags::INITIATOR | ExchangeFlags::ACK,
            opcode: 0x10,
            exchange_id: 0x0001,
            protocol_id: ProtocolId::SECURE_CHANNEL,
            ack_counter: Some(MessageCounter(0xAABB_CCDD)),
        };
        let mut out = Vec::new();
        encode_protocol_header(&header, &mut out);
        assert_eq!(out.len(), 12, "8 fixed + 4 ack_counter");
        let (parsed, rest) = decode_protocol_header(&out).unwrap();
        assert_eq!(parsed, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_reliable_initiator() {
        let header = ProtocolHeader {
            exchange_flags: ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            opcode: 0x30,
            exchange_id: 0x1234,
            protocol_id: ProtocolId::INTERACTION_MODEL,
            ack_counter: None,
        };
        let mut out = Vec::new();
        encode_protocol_header(&header, &mut out);
        assert_eq!(out[0], 0b0000_0101, "I=1 R=1");
        let (parsed, rest) = decode_protocol_header(&out).unwrap();
        assert_eq!(parsed, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_preserves_payload_tail() {
        let header = ProtocolHeader {
            exchange_flags: ExchangeFlags::INITIATOR,
            opcode: 0x20,
            exchange_id: 7,
            protocol_id: ProtocolId::INTERACTION_MODEL,
            ack_counter: None,
        };
        let mut out = Vec::new();
        encode_protocol_header(&header, &mut out);
        out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let (_, rest) = decode_protocol_header(&out).unwrap();
        assert_eq!(rest, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn decode_truncated_fixed_portion() {
        let bytes = [0x01, 0x20, 0x42, 0x42, 0x00];
        let err = decode_protocol_header(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::MalformedProtocolHeader(_)
        ));
    }

    #[test]
    fn decode_truncated_ack_counter() {
        // Flags = I | A, but only 2 bytes of ack_counter present.
        let mut bytes = vec![0b0000_0011, 0x20, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00];
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let err = decode_protocol_header(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::MalformedProtocolHeader(_)
        ));
    }

    #[test]
    fn decode_skips_sx_data() {
        // Flags = I | SX. SX data is 2-byte LE length prefix (3) followed
        // by 3 bytes. Then 4 bytes of application payload.
        let bytes = vec![
            0b0000_1001, // I=1 SX=1
            0x20,        // opcode
            0x01,
            0x00, // exchange_id = 1
            0x00,
            0x00, // vendor = 0
            0x01,
            0x00, // protocol = 1
            0x03,
            0x00, // SX length = 3
            0x11,
            0x22,
            0x33, // SX data (discarded)
            0xDE,
            0xAD,
            0xBE,
            0xEF, // app payload
        ];
        let (parsed, rest) = decode_protocol_header(&bytes).unwrap();
        assert!(parsed
            .exchange_flags
            .contains(ExchangeFlags::SECURE_EXTENSION));
        assert_eq!(rest, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn decode_skips_vendor_data() {
        // Flags = I | V. Vendor data is 2-byte LE length prefix (2)
        // followed by 2 bytes. Then 3 bytes of application payload.
        let bytes = vec![
            0b0001_0001, // I=1 V=1
            0x20,
            0x01,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0x02,
            0x00, // V length = 2
            0x99,
            0x88, // V data (discarded)
            0xCA,
            0xFE,
            0x42, // app payload
        ];
        let (parsed, rest) = decode_protocol_header(&bytes).unwrap();
        assert!(parsed.exchange_flags.contains(ExchangeFlags::VENDOR));
        assert_eq!(rest, &[0xCA, 0xFE, 0x42]);
    }

    #[test]
    fn decode_truncated_sx_length_prefix() {
        // Flags = SX, but only 1 byte where SX length needs 2.
        let bytes = vec![
            0b0000_1001,
            0x20,
            0x01,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0x03, // truncated length prefix
        ];
        let err = decode_protocol_header(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::MalformedProtocolHeader(_)
        ));
    }

    #[test]
    fn decode_truncated_sx_data() {
        // Flags = SX, length prefix says 10 bytes, but only 3 follow.
        let bytes = vec![
            0b0000_1001,
            0x20,
            0x01,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
            0x0A,
            0x00, // length = 10
            0xAA,
            0xBB,
            0xCC, // only 3 of 10 bytes
        ];
        let err = decode_protocol_header(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::MalformedProtocolHeader(_)
        ));
    }

    #[test]
    fn decode_reserved_flag_bits_rejected() {
        // Bit 5 set is reserved per Matter spec §4.4.5.1.
        let bytes = [0b0010_0001, 0x20, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00];
        let err = decode_protocol_header(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::MalformedProtocolHeader(_)
        ));
    }

    #[test]
    fn build_standalone_ack_header_initiator() {
        let h = build_standalone_ack_header(
            0x4242,
            MessageCounter(100),
            /* is_local_initiator */ true,
        );
        assert_eq!(h.opcode, opcode::secure_channel::STANDALONE_ACK);
        assert_eq!(h.exchange_id, 0x4242);
        assert_eq!(h.protocol_id, ProtocolId::SECURE_CHANNEL);
        assert_eq!(h.ack_counter, Some(MessageCounter(100)));
        assert!(h.exchange_flags.contains(ExchangeFlags::INITIATOR));
        assert!(h.exchange_flags.contains(ExchangeFlags::ACK));
        assert!(!h.exchange_flags.contains(ExchangeFlags::RELIABLE));
    }

    #[test]
    fn build_standalone_ack_header_responder() {
        let h = build_standalone_ack_header(
            0x4242,
            MessageCounter(100),
            /* is_local_initiator */ false,
        );
        assert!(!h.exchange_flags.contains(ExchangeFlags::INITIATOR));
        assert!(h.exchange_flags.contains(ExchangeFlags::ACK));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod proptest_module {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_any_header(
            initiator in any::<bool>(),
            ack in any::<bool>(),
            reliable in any::<bool>(),
            opcode in any::<u8>(),
            exchange_id in any::<u16>(),
            vendor in any::<u16>(),
            protocol in any::<u16>(),
            ack_value in any::<u32>(),
        ) {
            let mut flags = ExchangeFlags::empty();
            if initiator { flags |= ExchangeFlags::INITIATOR; }
            if ack { flags |= ExchangeFlags::ACK; }
            if reliable { flags |= ExchangeFlags::RELIABLE; }

            let header = ProtocolHeader {
                exchange_flags: flags,
                opcode,
                exchange_id,
                protocol_id: ProtocolId { vendor, protocol },
                ack_counter: if ack { Some(MessageCounter(ack_value)) } else { None },
            };

            let mut out = Vec::new();
            encode_protocol_header(&header, &mut out);
            let (parsed, rest) = decode_protocol_header(&out).unwrap();
            prop_assert_eq!(parsed, header);
            prop_assert!(rest.is_empty());
        }
    }
}
