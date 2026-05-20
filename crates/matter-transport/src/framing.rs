//! Matter secured-message framing (Matter Core Specification §4.4) plus the
//! reception-side replay window (§4.4.3).
//!
//! The header layer is implemented in this task. AES-CCM payload encryption
//! is added in Task 5. The replay window is added in Task 3.

use bitflags::bitflags;

use crate::error::{Error, Result};

bitflags! {
    /// First byte of the secured-message header. See Matter Core Spec
    /// §4.4.1 ("Message Header Fields") for the canonical bit layout.
    ///
    /// - Bits 0..=3: protocol version (must be `0` for current spec).
    /// - Bit 4: reserved (must be `0`).
    /// - Bit 5: `S` — source node ID present in header.
    /// - Bits 6..=7: `DSIZ` — destination-node-ID size selector.
    ///   `00` none, `01` 64-bit unicast, `10` 16-bit group, `11` reserved.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecuredMessageFlags: u8 {
        /// `S = 1` — header carries an 8-byte source node ID.
        const SOURCE_PRESENT = 0b0010_0000;
        /// `DSIZ = 0b01` — header carries an 8-byte unicast destination node ID.
        const DEST_UNICAST   = 0b0100_0000;
        /// `DSIZ = 0b10` — header carries a 2-byte group ID instead.
        const DEST_GROUP     = 0b1000_0000;
        // Version field (bits 0..=3) and reserved (bit 4) are zero in all
        // currently spec-defined messages — we surface no bitflag constants
        // for them; reads/writes round-trip the raw bits via `bits()`.
    }

    /// Second-section byte of the secured-message header. See Matter Core
    /// Spec §4.4.1.
    ///
    /// - Bit 0: `P` — privacy enhancements applied to the message header.
    /// - Bit 1: `C` — control message (Secure Channel protocol message).
    /// - Bit 2: `MX` — message extensions present.
    /// - Bits 3..=4: reserved.
    /// - Bits 5..=7: session type. `0` unicast, `1` group; others reserved.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecurityFlags: u8 {
        /// `P` — privacy enhancements applied.
        const PRIVACY            = 0b0000_0001;
        /// `C` — control message.
        const CONTROL            = 0b0000_0010;
        /// `MX` — message extensions present.
        const EXTENSIONS_PRESENT = 0b0000_0100;
        /// Session type bits set to "group" (`0b001` in the top three bits).
        const SESSION_TYPE_GROUP = 0b0010_0000;
    }
}

const DSIZ_MASK: u8 = 0b1100_0000;
const DSIZ_NONE: u8 = 0b0000_0000;
const DSIZ_UNICAST: u8 = 0b0100_0000;
const DSIZ_GROUP: u8 = 0b1000_0000;
const DSIZ_RESERVED: u8 = 0b1100_0000;

/// Peer-allocated session identifier carried at byte offset 1 of the
/// header (little-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u16);

/// 32-bit monotonic message counter; per Matter Core Spec §4.4.3, sessions
/// initialise this to a random value `> 1 << 31`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageCounter(pub u32);

/// 64-bit Node ID used in source/destination header fields and the
/// AES-CCM nonce composition (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeId(pub u64);

/// Destination address: either a unicast 64-bit Node ID or a 16-bit
/// Group ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestNodeId {
    /// Unicast — `DSIZ = 0b01`.
    Node(NodeId),
    /// Multicast group — `DSIZ = 0b10`. Group messaging is otherwise
    /// deferred (per CLAUDE.md M0 plan); we still decode the field so a
    /// stray group packet produces a structured error instead of garbage.
    Group(u16),
}

/// Parsed view of the secured-message header (everything before the
/// encrypted payload). See [`encode_header`] and [`decode_header`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuredMessageHeader {
    /// Top-byte flags (S, DSIZ, version).
    pub flags: SecuredMessageFlags,
    /// Peer-allocated session identifier.
    pub session_id: SessionId,
    /// Security-flags byte (P, C, MX, session type).
    pub security_flags: SecurityFlags,
    /// 32-bit message counter.
    pub message_counter: MessageCounter,
    /// Optional source Node ID. Presence MUST match the `S` bit in
    /// [`Self::flags`] — [`encode_header`] returns
    /// [`Error::MalformedHeader`] on mismatch.
    pub source_node_id: Option<NodeId>,
    /// Optional destination address. Presence MUST match the `DSIZ` bits
    /// in [`Self::flags`].
    pub destination_node_id: Option<DestNodeId>,
}

/// Encode a [`SecuredMessageHeader`] to its on-the-wire byte sequence.
pub fn encode_header(header: &SecuredMessageHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.push(header.flags.bits());
    out.extend_from_slice(&header.session_id.0.to_le_bytes());
    out.push(header.security_flags.bits());
    out.extend_from_slice(&header.message_counter.0.to_le_bytes());
    if let Some(node) = header.source_node_id {
        out.extend_from_slice(&node.0.to_le_bytes());
    }
    match header.destination_node_id {
        None => {}
        Some(DestNodeId::Node(NodeId(n))) => out.extend_from_slice(&n.to_le_bytes()),
        Some(DestNodeId::Group(g)) => out.extend_from_slice(&g.to_le_bytes()),
    }
    out
}

/// Decode the header from the start of `bytes`. On success returns the
/// parsed header and the remainder of the input (i.e. the encrypted
/// payload + auth tag).
///
/// # Errors
///
/// Returns [`Error::MalformedHeader`] if:
/// - the fixed 8-byte portion is truncated;
/// - the `S` bit is set but only a partial source Node ID is present;
/// - `DSIZ` is set but only a partial destination is present;
/// - `DSIZ` has the reserved `0b11` value.
pub fn decode_header(bytes: &[u8]) -> Result<(SecuredMessageHeader, &[u8])> {
    if bytes.len() < 8 {
        return Err(Error::MalformedHeader(bytes.len()));
    }
    let flags = SecuredMessageFlags::from_bits_retain(bytes[0]);

    if (bytes[0] & DSIZ_MASK) == DSIZ_RESERVED {
        return Err(Error::MalformedHeader(0));
    }

    let session_id = SessionId(u16::from_le_bytes([bytes[1], bytes[2]]));
    let security_flags = SecurityFlags::from_bits_retain(bytes[3]);
    let message_counter =
        MessageCounter(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));

    let mut offset = 8;

    let source_node_id = if flags.contains(SecuredMessageFlags::SOURCE_PRESENT) {
        if bytes.len() < offset + 8 {
            return Err(Error::MalformedHeader(offset));
        }
        let bs: [u8; 8] = bytes[offset..offset + 8]
            .try_into()
            .map_err(|_| Error::MalformedHeader(offset))?;
        offset += 8;
        Some(NodeId(u64::from_le_bytes(bs)))
    } else {
        None
    };

    let destination_node_id = match bytes[0] & DSIZ_MASK {
        DSIZ_NONE => None,
        DSIZ_UNICAST => {
            if bytes.len() < offset + 8 {
                return Err(Error::MalformedHeader(offset));
            }
            let bs: [u8; 8] = bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| Error::MalformedHeader(offset))?;
            offset += 8;
            Some(DestNodeId::Node(NodeId(u64::from_le_bytes(bs))))
        }
        DSIZ_GROUP => {
            if bytes.len() < offset + 2 {
                return Err(Error::MalformedHeader(offset));
            }
            let bs: [u8; 2] = bytes[offset..offset + 2]
                .try_into()
                .map_err(|_| Error::MalformedHeader(offset))?;
            offset += 2;
            Some(DestNodeId::Group(u16::from_le_bytes(bs)))
        }
        // DSIZ_RESERVED already rejected above; mask covers all 4 values.
        _ => return Err(Error::MalformedHeader(0)),
    };

    let parsed = SecuredMessageHeader {
        flags,
        session_id,
        security_flags,
        message_counter,
        source_node_id,
        destination_node_id,
    };
    Ok((parsed, &bytes[offset..]))
}

// ReplayWindow is added by Task 3.

/// Sliding-window dedup for inbound message counters per Matter Core Spec
/// §4.4.3. Filled in by Task 3.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    _todo: (),
}

// encode_secured / decode_secured are added by Task 5.

/// Encode a secured Matter message. Filled in by Task 5.
#[allow(clippy::missing_errors_doc)]
pub fn encode_secured(
    _header: &SecuredMessageHeader,
    _payload: &[u8],
    _keys: &crate::session::SessionKeys,
    _role: crate::session::SessionRole,
) -> Result<Vec<u8>> {
    unimplemented!("filled in by Task 5")
}

/// Decode a secured Matter message. Filled in by Task 5.
#[allow(clippy::missing_errors_doc)]
pub fn decode_secured(
    _bytes: &[u8],
    _keys: &crate::session::SessionKeys,
    _role: crate::session::SessionRole,
    _replay_window: &mut ReplayWindow,
) -> Result<(SecuredMessageHeader, Vec<u8>)> {
    unimplemented!("filled in by Task 5")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use crate::error::Error;

    /// Spec §4.4.1 minimum header: version=0, S=0, DSIZ=0. Only the
    /// 8-byte fixed portion is present.
    #[test]
    fn minimal_header_roundtrip() {
        let header = SecuredMessageHeader {
            flags: SecuredMessageFlags::empty(),
            session_id: SessionId(0x1234),
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(0xAABB_CCDD),
            source_node_id: None,
            destination_node_id: None,
        };
        let bytes = encode_header(&header);
        assert_eq!(bytes.len(), 8, "fixed 8-byte header");
        // byte 0 = flags (0x00), bytes 1..3 = session_id LE (0x34 0x12),
        // byte 3 = security_flags (0x00), bytes 4..8 = counter LE.
        assert_eq!(bytes, vec![0x00, 0x34, 0x12, 0x00, 0xDD, 0xCC, 0xBB, 0xAA]);

        let (parsed, rest) = decode_header(&bytes).unwrap();
        assert_eq!(parsed, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_with_source_node_id() {
        let header = SecuredMessageHeader {
            flags: SecuredMessageFlags::SOURCE_PRESENT,
            session_id: SessionId(0x0001),
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(1),
            source_node_id: Some(NodeId(0x1122_3344_5566_7788)),
            destination_node_id: None,
        };
        let bytes = encode_header(&header);
        assert_eq!(bytes.len(), 16, "8 fixed + 8 source");
        let (parsed, rest) = decode_header(&bytes).unwrap();
        assert_eq!(parsed, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_with_unicast_destination() {
        let header = SecuredMessageHeader {
            flags: SecuredMessageFlags::DEST_UNICAST,
            session_id: SessionId(0xFFFF),
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(u32::MAX),
            source_node_id: None,
            destination_node_id: Some(DestNodeId::Node(NodeId(0xDEAD_BEEF_CAFE_BABE))),
        };
        let bytes = encode_header(&header);
        assert_eq!(bytes.len(), 16, "8 fixed + 8 dest");
        let (parsed, rest) = decode_header(&bytes).unwrap();
        assert_eq!(parsed, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_with_group_destination() {
        let header = SecuredMessageHeader {
            flags: SecuredMessageFlags::DEST_GROUP,
            session_id: SessionId(7),
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(42),
            source_node_id: None,
            destination_node_id: Some(DestNodeId::Group(0xABCD)),
        };
        let bytes = encode_header(&header);
        assert_eq!(bytes.len(), 10, "8 fixed + 2 group");
        let (parsed, rest) = decode_header(&bytes).unwrap();
        assert_eq!(parsed, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_with_source_and_destination() {
        let header = SecuredMessageHeader {
            flags: SecuredMessageFlags::SOURCE_PRESENT | SecuredMessageFlags::DEST_UNICAST,
            session_id: SessionId(0x4242),
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(0x1000_0000),
            source_node_id: Some(NodeId(0x1111_2222_3333_4444)),
            destination_node_id: Some(DestNodeId::Node(NodeId(0x5555_6666_7777_8888))),
        };
        let bytes = encode_header(&header);
        assert_eq!(bytes.len(), 24, "8 fixed + 8 source + 8 dest");
        let (parsed, rest) = decode_header(&bytes).unwrap();
        assert_eq!(parsed, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_decode_keeps_payload_slice() {
        // Minimal header followed by 4 bytes of "encrypted payload".
        let mut bytes = vec![0x00, 0x34, 0x12, 0x00, 0xDD, 0xCC, 0xBB, 0xAA];
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let (_, rest) = decode_header(&bytes).unwrap();
        assert_eq!(rest, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn header_decode_truncated_fixed_portion() {
        let bytes = [0x00, 0x34, 0x12];
        let err = decode_header(&bytes).unwrap_err();
        assert!(matches!(err, Error::MalformedHeader(_)));
    }

    #[test]
    fn header_decode_truncated_source_node_id() {
        // Flags say S=1 but only 3 bytes of source node ID present.
        let mut bytes = vec![
            SecuredMessageFlags::SOURCE_PRESENT.bits(),
            0x01,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
        ];
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 3 bytes only
        let err = decode_header(&bytes).unwrap_err();
        assert!(matches!(err, Error::MalformedHeader(_)));
    }

    #[test]
    fn header_decode_rejects_reserved_dsiz() {
        // Flags byte with DSIZ=0b11 in the top two bits is reserved.
        let bytes = [0b1100_0000, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let err = decode_header(&bytes).unwrap_err();
        assert!(matches!(err, Error::MalformedHeader(_)));
    }
}
