//! Matter secured-message framing (Matter Core Specification §4.4) plus the
//! reception-side replay window (§4.4.3).
//!
//! The header layer is implemented in this task. AES-CCM payload encryption
//! is added in Task 5. The replay window is added in Task 3.

use bitflags::bitflags;

use crate::error::{Error, Result};

bitflags! {
    /// First byte of the secured-message header. The bit layout follows
    /// matter.js's `PacketHeaderFlag` enum (`@matter/protocol`
    /// `codec/MessageCodec.ts`), cross-verified byte-for-byte against
    /// captured fixtures in `test-vectors/transport/`.
    ///
    /// - Bit 0: `DSIZ` low bit — set if destination is a unicast Node ID.
    /// - Bit 1: `DSIZ` high bit — set if destination is a 16-bit Group ID.
    ///   (`DSIZ = 0b11` is reserved.)
    /// - Bit 2: `S` — source node ID present in header.
    /// - Bit 3: reserved (must be `0`).
    /// - Bits 4..=7: protocol version (must be `0` for current spec).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecuredMessageFlags: u8 {
        /// `S = 1` — header carries an 8-byte source node ID.
        const SOURCE_PRESENT = 0b0000_0100;
        /// `DSIZ = 0b01` — header carries an 8-byte unicast destination node ID.
        const DEST_UNICAST   = 0b0000_0001;
        /// `DSIZ = 0b10` — header carries a 2-byte group ID instead.
        const DEST_GROUP     = 0b0000_0010;
        // Version field (bits 4..=7) and reserved (bit 3) are zero in all
        // currently spec-defined messages — we surface no bitflag constants
        // for them; reads/writes round-trip the raw bits via `bits()`.
    }

    /// Second-section byte of the secured-message header. Bit layout
    /// follows matter.js's `SecurityFlag` enum.
    ///
    /// - Bits 0..=1: session type (`SessionTypeMask`). `0` unicast,
    ///   `1` group; others reserved.
    /// - Bits 2..=4: reserved.
    /// - Bit 5: `MX` — message extensions present.
    /// - Bit 6: `C` — control message (Secure Channel protocol message).
    /// - Bit 7: `P` — privacy enhancements applied to the message header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecurityFlags: u8 {
        /// `P` — privacy enhancements applied.
        const PRIVACY            = 0b1000_0000;
        /// `C` — control message.
        const CONTROL            = 0b0100_0000;
        /// `MX` — message extensions present.
        const EXTENSIONS_PRESENT = 0b0010_0000;
        /// Session type bits set to "group" (`0b01` in the low two bits).
        const SESSION_TYPE_GROUP = 0b0000_0001;
    }
}

const DSIZ_MASK: u8 = 0b0000_0011;
const DSIZ_NONE: u8 = 0b0000_0000;
const DSIZ_UNICAST: u8 = 0b0000_0001;
const DSIZ_GROUP: u8 = 0b0000_0010;
const DSIZ_RESERVED: u8 = 0b0000_0011;

/// Peer-allocated session identifier carried at byte offset 1 of the
/// header (little-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u16);

/// 32-bit monotonic message counter; per Matter Core Spec §4.4.3, sessions
/// initialise this to a random value `> 1 << 31`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Sliding-window dedup for inbound message counters per Matter Core
/// Specification §4.4.3.
///
/// Tracks the highest counter seen plus a 32-bit bitmap covering the 32
/// counters immediately preceding it. Counters older than the window
/// (below `highest_seen - 31`) are rejected as too old; counters in the
/// window that have already been seen are rejected as duplicates;
/// everything else is accepted and recorded.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest_seen: Option<u32>,
    /// Bit `n` set ⇔ `highest_seen - n` has been observed.
    /// Bit 0 always corresponds to `highest_seen` itself.
    bitmap: u32,
}

impl ReplayWindow {
    /// Width of the sliding window in counter slots (bits in `bitmap`).
    pub const WIDTH: u32 = 32;

    /// Create an empty window — every counter is novel until the first
    /// `check_and_record` call.
    #[must_use]
    pub fn new() -> Self {
        Self {
            highest_seen: None,
            bitmap: 0,
        }
    }

    /// Validate `counter` against the window and, on success, record it.
    ///
    /// # Errors
    ///
    /// - [`Error::ReplayedCounter`] if `counter` is inside the window and
    ///   has already been observed.
    /// - [`Error::CounterTooOld`] if `counter` is older than
    ///   `highest_seen - 31`.
    pub fn check_and_record(&mut self, counter: u32) -> Result<()> {
        let Some(highest) = self.highest_seen else {
            // Empty window: any counter is fresh.
            self.highest_seen = Some(counter);
            self.bitmap = 1;
            return Ok(());
        };

        if counter > highest {
            // Forward jump. Shift the bitmap so the new highest is bit 0
            // and the previous highest moves to bit (counter - highest).
            let shift = counter - highest;
            self.bitmap = if shift >= Self::WIDTH {
                0
            } else {
                self.bitmap << shift
            };
            self.bitmap |= 1;
            self.highest_seen = Some(counter);
            Ok(())
        } else {
            let offset = highest - counter;
            if offset >= Self::WIDTH {
                return Err(Error::CounterTooOld {
                    counter,
                    window_low: highest.saturating_sub(Self::WIDTH - 1),
                    window_high: highest,
                });
            }
            let bit = 1u32 << offset;
            if self.bitmap & bit != 0 {
                return Err(Error::ReplayedCounter { counter });
            }
            self.bitmap |= bit;
            Ok(())
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Hard cap on encrypted payload size (in bytes). Matter Core Spec §4.4.4
/// recommends staying well under MTU; we additionally cap at 1280 (the
/// IPv6 minimum MTU) minus header (24 bytes max) minus AES-CCM tag
/// (16 bytes) ≈ 1240. We round to 1024 for headroom — large messages use
/// TCP transport (deferred post-1.0) or BDX.
const MAX_PAYLOAD_LEN: usize = 1024;

/// Encode + encrypt a Matter secured message.
///
/// The output layout is `header bytes || AES-CCM(payload) || 16-byte tag`,
/// matching matter.js's `MessageCodec.encodePayload(...)` byte-for-byte.
///
/// # Errors
///
/// - [`Error::PayloadTooLarge`] if `payload.len() > MAX_PAYLOAD_LEN`.
/// - [`Error::Crypto`] if the underlying AES-CCM cipher fails (not
///   expected in practice for spec-bounded message sizes).
pub fn encode_secured(
    header: &SecuredMessageHeader,
    payload: &[u8],
    keys: &crate::session::SessionKeys,
    role: crate::session::SessionRole,
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_LEN,
        });
    }

    let aad = encode_header(header);
    let nonce = build_nonce(header);
    let key = match role {
        crate::session::SessionRole::Initiator => &keys.i2r_key,
        crate::session::SessionRole::Responder => &keys.r2i_key,
    };

    let ciphertext = matter_crypto::aead::encrypt(key, &nonce, &aad, payload)?;
    let mut out = aad;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt + decode a Matter secured message.
///
/// On success returns the parsed header and the decrypted payload. The
/// caller's `replay_window` is consulted before decryption is even
/// attempted: a replayed or too-old counter is rejected without burning
/// AES-CCM cycles.
///
/// # Errors
///
/// - [`Error::MalformedHeader`] if the header bytes are truncated or
///   reserved-value bits are set.
/// - [`Error::ReplayedCounter`] / [`Error::CounterTooOld`] per
///   [`ReplayWindow::check_and_record`].
/// - [`Error::DecryptionFailed`] if the AES-CCM tag does not verify.
pub fn decode_secured(
    bytes: &[u8],
    keys: &crate::session::SessionKeys,
    role: crate::session::SessionRole,
    replay_window: &mut ReplayWindow,
) -> Result<(SecuredMessageHeader, Vec<u8>)> {
    let (header, rest) = decode_header(bytes)?;
    replay_window.check_and_record(header.message_counter.0)?;

    let aad = encode_header(&header);
    let nonce = build_nonce(&header);
    // We're decoding inbound from the peer; the peer's outbound key is
    // the opposite of ours.
    let key = match role {
        crate::session::SessionRole::Initiator => &keys.r2i_key,
        crate::session::SessionRole::Responder => &keys.i2r_key,
    };

    let plaintext = matter_crypto::aead::decrypt(key, &nonce, &aad, rest)
        .map_err(|_| Error::DecryptionFailed)?;
    Ok((header, plaintext))
}

/// Compose the AES-CCM nonce per Matter Core Spec §4.5:
/// `nonce = SecurityFlags(1) || MessageCounter(4 LE) || SourceNodeId(8 LE)`.
///
/// When the header has no source node ID (S=0), the `SourceNodeId` portion
/// is zero. Higher-level callers that know the operational Node ID (e.g.
/// matter-controller in M8) may pre-fill `header.source_node_id` even
/// though `S` is not set in the on-the-wire flags — but in M5.1 we always
/// derive nonce `SourceNodeId` from `header.source_node_id` directly, so
/// the two are coupled. Revisit if M6 needs the split.
fn build_nonce(header: &SecuredMessageHeader) -> [u8; matter_crypto::aead::AEAD_NONCE_LEN] {
    let mut nonce = [0u8; matter_crypto::aead::AEAD_NONCE_LEN];
    nonce[0] = header.security_flags.bits();
    nonce[1..5].copy_from_slice(&header.message_counter.0.to_le_bytes());
    if let Some(NodeId(n)) = header.source_node_id {
        nonce[5..13].copy_from_slice(&n.to_le_bytes());
    }
    nonce
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
        // Flags byte with DSIZ=0b11 in the low two bits is reserved.
        let bytes = [0b0000_0011, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let err = decode_header(&bytes).unwrap_err();
        assert!(matches!(err, Error::MalformedHeader(_)));
    }

    mod replay_window {
        use super::super::*;

        #[test]
        fn first_counter_accepted() {
            let mut w = ReplayWindow::new();
            assert!(w.check_and_record(100).is_ok());
        }

        #[test]
        fn duplicate_rejected() {
            let mut w = ReplayWindow::new();
            w.check_and_record(100).unwrap();
            let err = w.check_and_record(100).unwrap_err();
            assert!(matches!(err, Error::ReplayedCounter { counter: 100 }));
        }

        #[test]
        fn strictly_increasing_accepted() {
            let mut w = ReplayWindow::new();
            for n in [10u32, 11, 12, 13, 100, 101] {
                w.check_and_record(n).unwrap();
            }
        }

        #[test]
        fn within_window_unseen_accepted() {
            // After seeing 100, counters 100-31..=99 (within the 32-bit window)
            // that we have NOT yet seen must be accepted exactly once each.
            let mut w = ReplayWindow::new();
            w.check_and_record(100).unwrap();
            w.check_and_record(99).unwrap();
            w.check_and_record(98).unwrap();
            // Duplicates now rejected.
            assert!(w.check_and_record(99).is_err());
            assert!(w.check_and_record(98).is_err());
        }

        #[test]
        fn outside_window_rejected_as_too_old() {
            // After seeing 100, the window covers 69..=100 (32 entries).
            // 68 and below are too old.
            let mut w = ReplayWindow::new();
            w.check_and_record(100).unwrap();
            let err = w.check_and_record(68).unwrap_err();
            assert!(
                matches!(err, Error::CounterTooOld { counter: 68, .. }),
                "expected CounterTooOld for 68; got {err:?}",
            );
        }

        #[test]
        fn forward_jump_slides_window() {
            // Going from 100 to 200 must accept 200 and forget everything
            // older than (200 - 31) = 169.
            let mut w = ReplayWindow::new();
            w.check_and_record(100).unwrap();
            w.check_and_record(200).unwrap();
            // 100 is now too old to deduplicate against.
            let err = w.check_and_record(100).unwrap_err();
            assert!(matches!(err, Error::CounterTooOld { .. }));
            // 200 is now a duplicate.
            let err = w.check_and_record(200).unwrap_err();
            assert!(matches!(err, Error::ReplayedCounter { counter: 200 }));
        }

        #[test]
        fn counter_zero_accepted() {
            // Spec §4.4.3 says outbound counters start above 1<<31, but
            // inbound counters from a peer can technically be anything; we
            // do not special-case zero.
            let mut w = ReplayWindow::new();
            w.check_and_record(0).unwrap();
            assert!(w.check_and_record(0).is_err());
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod replay_proptest {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Strictly-increasing counters are always accepted.
        #[test]
        fn monotonic_sequence_always_accepted(
            seed in any::<u32>(),
            len in 1usize..=100,
        ) {
            let mut window = ReplayWindow::new();
            let mut counter = seed;
            for _ in 0..len {
                prop_assert!(window.check_and_record(counter).is_ok());
                counter = counter.wrapping_add(1);
                if counter == 0 {
                    // Wrap-around isn't supported; we'd need re-keying.
                    break;
                }
            }
        }

        /// Whatever counter we record, recording it twice always errors.
        #[test]
        fn idempotent_replay_rejection(c in any::<u32>()) {
            let mut window = ReplayWindow::new();
            window.check_and_record(c).unwrap();
            prop_assert!(window.check_and_record(c).is_err());
        }
    }
}
