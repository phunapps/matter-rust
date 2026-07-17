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

/// Bits of the first header byte that MUST be zero on the wire: bit 3
/// (reserved) and bits 4..=7 (the message-format version, which is `0` for
/// the current Matter Core Spec §4.4.1). Only bits 0..=2 (DSIZ + `S`) carry
/// meaning; any set bit in this mask marks an unsupported/malformed header.
const FLAGS_MUST_BE_ZERO_MASK: u8 = 0b1111_1000;

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
///
/// `#[non_exhaustive]`: the `DSIZ` field reserves a `0b11` encoding the spec
/// may later define; marking this lets a future variant land without a semver
/// break. Downstream `match`es must include a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
/// - the version field (bits 4..=7 of byte 0) is non-zero, or the reserved
///   bit 3 is set (both must be `0` per Matter Core Spec §4.4.1);
/// - the `S` bit is set but only a partial source Node ID is present;
/// - `DSIZ` is set but only a partial destination is present;
/// - `DSIZ` has the reserved `0b11` value.
pub fn decode_header(bytes: &[u8]) -> Result<(SecuredMessageHeader, &[u8])> {
    if bytes.len() < 8 {
        return Err(Error::MalformedHeader(bytes.len()));
    }
    let flags = SecuredMessageFlags::from_bits_retain(bytes[0]);

    // The message-format version (bits 4..=7) must be the supported value
    // (`0`) and the reserved bit 3 must be clear — Matter Core Spec §4.4.1.
    // Rejecting here keeps a future-version or corrupt datagram from being
    // silently mis-parsed as a current-spec message.
    if (bytes[0] & FLAGS_MUST_BE_ZERO_MASK) != 0 {
        return Err(Error::MalformedHeader(0));
    }

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

    /// Classify `counter` against the current window WITHOUT mutating any
    /// state. Both [`Self::check_and_record`] and [`Self::would_reject`]
    /// delegate here so the accept/reject decision can never drift between
    /// the mutating and non-mutating paths.
    ///
    /// Returns `Err` for the same conditions [`Self::check_and_record`]
    /// documents; otherwise `Ok`.
    fn classify(&self, counter: u32) -> Result<()> {
        let Some(highest) = self.highest_seen else {
            // Empty window: any counter is fresh.
            return Ok(());
        };

        if counter > highest {
            // Forward jump — always novel.
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
            if self.bitmap & (1u32 << offset) != 0 {
                return Err(Error::ReplayedCounter { counter });
            }
            Ok(())
        }
    }

    /// Check whether `counter` WOULD be rejected, without recording it or
    /// otherwise mutating the window. Takes `&self` and never writes.
    ///
    /// **Not used to gate the inbound path** (see TRAN-1 / [`decode_secured`]):
    /// classifying a replay from the *unauthenticated* header — before the
    /// AES-CCM tag is verified — let a forged datagram drive the caller's MRP
    /// duplicate-ack logic. Replay classification on inbound traffic is done
    /// only by [`Self::check_and_record`], after authentication. This
    /// non-mutating classifier remains for callers that genuinely want a
    /// read-only window query (and for tests); it must never be the basis for
    /// an ack, a counter increment, or any other side effect on an
    /// unauthenticated message.
    ///
    /// # Errors
    ///
    /// - [`Error::ReplayedCounter`] if `counter` is inside the window and
    ///   has already been observed.
    /// - [`Error::CounterTooOld`] if `counter` is older than
    ///   `highest_seen - 31`.
    pub fn would_reject(&self, counter: u32) -> Result<()> {
        self.classify(counter)
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
        // Decide first (no mutation); only commit once the counter is
        // accepted. Keeps the reject logic identical to `would_reject`.
        self.classify(counter)?;

        match self.highest_seen {
            None => {
                // Empty window: any counter is fresh.
                self.highest_seen = Some(counter);
                self.bitmap = 1;
            }
            Some(highest) if counter > highest => {
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
            }
            Some(highest) => {
                // In-window, novel (classify already ruled out replay/old).
                let offset = highest - counter;
                self.bitmap |= 1u32 << offset;
            }
        }
        Ok(())
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
/// `nonce_source_node_id` is the SENDER's node id mixed into the AES-CCM
/// nonce (spec §4.8.2): the sender's *operational* node id on CASE sessions
/// — even though the wire header omits it — and `0` on PASE sessions.
/// Real devices silently drop CASE frames encrypted with the wrong nonce
/// node id (observed: Tapo P110M, M6.6.5 validation).
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
    nonce_source_node_id: u64,
) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_LEN,
        });
    }

    let aad = encode_header(header);
    let nonce = build_nonce(header, nonce_source_node_id);
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
/// On success returns the parsed header and the decrypted payload.
///
/// Replay is classified ONLY after the message authenticates: the header
/// (session id, counter) is unauthenticated plaintext, so both advancing the
/// window *and reporting a replay* before verifying the AES-CCM tag are
/// unsafe. Advancing early would let a forged far-future counter poison the
/// window (stranding later genuine traffic — a remote single-packet `DoS`);
/// reporting a replay early (TRAN-1) would let a forged datagram carrying a
/// previously-seen reliable counter drive the caller's MRP duplicate-ack path
/// into emitting an encrypted ack and burning a counter. We therefore
/// authenticate first, then call [`ReplayWindow::check_and_record`] — the sole
/// replay gate on this path. A forged datagram fails the AEAD tag and returns
/// [`Error::DecryptionFailed`] before any replay/ack decision is reached.
///
/// # Errors
///
/// - [`Error::MalformedHeader`] if the header bytes are truncated or
///   reserved-value bits are set.
/// - [`Error::ReplayedCounter`] / [`Error::CounterTooOld`] per
///   [`ReplayWindow::check_and_record`].
/// - [`Error::DecryptionFailed`] if the AES-CCM tag does not verify.
///
/// `nonce_source_node_id` mirrors [`encode_secured`]: the SENDER'S (here:
/// the peer's) operational node id on CASE sessions, `0` on PASE sessions.
pub fn decode_secured(
    bytes: &[u8],
    keys: &crate::session::SessionKeys,
    role: crate::session::SessionRole,
    replay_window: &mut ReplayWindow,
    nonce_source_node_id: u64,
) -> Result<(SecuredMessageHeader, Vec<u8>)> {
    let (header, rest) = decode_header(bytes)?;

    // TRAN-1: replay classification happens AFTER authentication, never
    // before. The header (session id, counter) is unauthenticated cleartext,
    // so we do NOT run a pre-decrypt reject here — an attacker who replays a
    // previously-seen reliable counter with any ciphertext would otherwise be
    // reported to the caller as `ReplayedCounter`, which drives the MRP
    // duplicate-ack path (`SessionManager::decode_inbound`) into emitting an
    // encrypted standalone ack and burning an outbound counter for a datagram
    // that never authenticated. We decrypt first; only an authenticated
    // duplicate reaches `check_and_record` below and yields `ReplayedCounter`.
    // (chip does the same: decrypt+verify before message-counter verification,
    // `SessionManager.cpp:963`.)

    // The AAD is the on-the-wire header — the leading bytes of `bytes` up to
    // where the encrypted payload (`rest`) begins. `decode_header` returns
    // `rest = &bytes[header_len..]`, so `&bytes[..header_len]` is byte-for-byte
    // the header the sender authenticated. We slice it directly rather than
    // re-encoding via `encode_header(&header)` — the slice and the re-encode
    // are identical bytes (the framing roundtrip tests pin this), and the
    // slice avoids an allocation + re-serialisation on every inbound packet.
    let header_len = bytes.len() - rest.len();
    let aad = &bytes[..header_len];
    let nonce = build_nonce(&header, nonce_source_node_id);
    // We're decoding inbound from the peer; the peer's outbound key is
    // the opposite of ours.
    let key = match role {
        crate::session::SessionRole::Initiator => &keys.r2i_key,
        crate::session::SessionRole::Responder => &keys.i2r_key,
    };

    let plaintext = matter_crypto::aead::decrypt(key, &nonce, aad, rest)
        .map_err(|_| Error::DecryptionFailed)?;

    // Authenticated: now it is safe to COMMIT the counter to the replay
    // window. A forged datagram never reaches this point.
    replay_window.check_and_record(header.message_counter.0)?;
    Ok((header, plaintext))
}

/// Encode + encrypt a Matter **group** secured message (Matter Core Spec
/// §4.15 group messaging, framing per §4.4 / §4.8.2).
///
/// A group message differs from the unicast secured path in five ways, all
/// of which we mirror here against the independent matter.js vector
/// (`test-vectors/transport/group-message.json`):
///
/// 1. **Key.** AES-128-CCM uses the *operational group key* directly — there
///    is no per-session `i2r`/`r2i` split and no [`crate::session::Session`],
///    so the caller supplies the 16-byte key.
/// 2. **Security flags.** [`SecurityFlags::SESSION_TYPE_GROUP`] is set
///    (`0x01`); the wire `securityFlags` byte is `0x01`.
/// 3. **Message flags / destination.** [`SecuredMessageFlags::DEST_GROUP`]
///    (`DSIZ = 0b10`) plus [`SecuredMessageFlags::SOURCE_PRESENT`] — a group
///    header carries BOTH the 8-byte source node id and the 2-byte
///    destination group id (`msgFlags = 0x06`).
/// 4. **Nonce.** `SecurityFlags(1) || MessageCounter(4 LE) || SourceNodeId(8
///    LE)`, where the node id is OUR (the sender's) operational node id. The
///    header already carries this same source node id, so the nonce builder
///    picks it up from the header — but we pass it explicitly too for parity
///    with the unicast contract.
/// 5. **No MRP.** Group sends are unacknowledged; the caller owns the group
///    message counter (there is no session counter to advance).
///
/// `counter` is the group message counter the caller has allocated.
/// `protocol_header` and `app_payload` form the plaintext exactly as on the
/// unicast path: `encode_protocol_header(protocol_header) || app_payload`.
///
/// The output layout is `header bytes || AES-CCM(plaintext) || 16-byte tag`,
/// byte-for-byte the full group wire message.
///
/// # Errors
///
/// - [`Error::PayloadTooLarge`] if the encoded plaintext (protocol header +
///   `app_payload`) exceeds the framing payload cap.
/// - [`Error::Crypto`] if the underlying AES-CCM cipher fails (not expected
///   in practice for spec-bounded message sizes).
pub fn encode_group_secured(
    operational_group_key: &[u8; matter_crypto::aead::AEAD_KEY_LEN],
    group_session_id: u16,
    source_node_id: u64,
    group_id: u16,
    counter: u32,
    protocol_header: &crate::protocol_header::ProtocolHeader,
    app_payload: &[u8],
) -> Result<Vec<u8>> {
    // Plaintext = protocol header || app payload, identical to the unicast
    // path's `prepared.wire_payload`.
    let mut plaintext = Vec::with_capacity(16 + app_payload.len());
    crate::protocol_header::encode_protocol_header(protocol_header, &mut plaintext);
    plaintext.extend_from_slice(app_payload);

    if plaintext.len() > MAX_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge {
            len: plaintext.len(),
            max: MAX_PAYLOAD_LEN,
        });
    }

    let header = SecuredMessageHeader {
        // Group header carries BOTH the source node id (S=1) and the 2-byte
        // group id (DSIZ=0b10) → msgFlags = 0x06.
        flags: SecuredMessageFlags::SOURCE_PRESENT | SecuredMessageFlags::DEST_GROUP,
        session_id: SessionId(group_session_id),
        security_flags: SecurityFlags::SESSION_TYPE_GROUP,
        message_counter: MessageCounter(counter),
        source_node_id: Some(NodeId(source_node_id)),
        destination_node_id: Some(DestNodeId::Group(group_id)),
    };

    // AAD = the exact encoded packet-header bytes (spec §4.8.2; matter.js
    // `GroupSession.encode`). Nonce mixes the source node id; `build_nonce`
    // reads it from the header (which carries it for group messages).
    let aad = encode_header(&header);
    let nonce = build_nonce(&header, source_node_id);

    // Reuse the shared AES-CCM routine — never hand-roll the cipher.
    let ciphertext = matter_crypto::aead::encrypt(operational_group_key, &nonce, &aad, &plaintext)?;
    let mut out = aad;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt + decode a Matter **group** secured message produced by
/// [`encode_group_secured`] (or a matter.js group sender).
///
/// On success returns the parsed header and the decrypted plaintext (protocol
/// header || app payload). The caller recovers the source node id and group
/// id from the returned [`SecuredMessageHeader`].
///
/// Unlike [`decode_secured`], there is no replay window: group messaging is
/// stateless on the receive side here, and the caller owns any per-group
/// replay tracking. The nonce node id is taken from the header's source node
/// id (always present on group messages).
///
/// # Errors
///
/// - [`Error::MalformedHeader`] if the header bytes are truncated or
///   reserved-value bits are set.
/// - [`Error::DecryptionFailed`] if the AES-CCM tag does not verify (wrong
///   group key, tampered ciphertext, or mismatched AAD/nonce).
pub fn decode_group_secured(
    bytes: &[u8],
    operational_group_key: &[u8; matter_crypto::aead::AEAD_KEY_LEN],
) -> Result<(SecuredMessageHeader, Vec<u8>)> {
    let (header, rest) = decode_header(bytes)?;
    // AAD is the on-the-wire header — the leading bytes up to `rest` (same
    // optimisation as `decode_secured`).
    let header_len = bytes.len() - rest.len();
    let aad = &bytes[..header_len];
    // Group messages carry the source node id in the header; `build_nonce`
    // uses it. The fallback (0) is never reached for a well-formed group
    // header (S=1).
    let nonce = build_nonce(&header, 0);
    let plaintext = matter_crypto::aead::decrypt(operational_group_key, &nonce, aad, rest)
        .map_err(|_| Error::DecryptionFailed)?;
    Ok((header, plaintext))
}

/// Compose the AES-CCM nonce per Matter Core Spec §4.8.2:
/// `nonce = SecurityFlags(1) || MessageCounter(4 LE) || SourceNodeId(8 LE)`.
///
/// `nonce_source_node_id` is supplied by the caller because the nonce node
/// id is decoupled from the wire header: secured-session headers omit the
/// source node id (S=0), yet CASE sessions still mix the sender's
/// *operational* node id into the nonce (chip `CryptoContext::BuildNonce`).
/// PASE sessions and the historical header-coupled paths pass `0` or the
/// header's value respectively. When the header DOES carry a source node id
/// (group messages), the header value takes precedence — they must agree on
/// the wire anyway.
fn build_nonce(
    header: &SecuredMessageHeader,
    nonce_source_node_id: u64,
) -> [u8; matter_crypto::aead::AEAD_NONCE_LEN] {
    let mut nonce = [0u8; matter_crypto::aead::AEAD_NONCE_LEN];
    nonce[0] = header.security_flags.bits();
    nonce[1..5].copy_from_slice(&header.message_counter.0.to_le_bytes());
    let node_id = match header.source_node_id {
        Some(NodeId(n)) => n,
        None => nonce_source_node_id,
    };
    nonce[5..13].copy_from_slice(&node_id.to_le_bytes());
    nonce
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use crate::error::Error;

    /// Decode a hex string to bytes (test helper for the group KAT).
    fn hex(s: &str) -> Vec<u8> {
        assert!(
            s.len().is_multiple_of(2),
            "hex string must have even length"
        );
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Decode a 32-char hex string into a fixed 16-byte array.
    fn hex16(s: &str) -> [u8; 16] {
        let v = hex(s);
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        a
    }

    /// Lowercase hex-encode bytes (for readable KAT assertion messages).
    fn hex_encode(b: &[u8]) -> String {
        use std::fmt::Write as _;
        b.iter()
            .fold(String::with_capacity(b.len() * 2), |mut s, x| {
                let _ = write!(s, "{x:02x}");
                s
            })
    }

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

    #[test]
    fn header_decode_rejects_nonzero_version() {
        // Version field (bits 4..=7 of byte 0) must be 0 for the current
        // spec. A header advertising version=1 (bit 4 set) must be rejected.
        let bytes = [0b0001_0000, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let err = decode_header(&bytes).unwrap_err();
        assert!(matches!(err, Error::MalformedHeader(_)));
    }

    #[test]
    fn header_decode_rejects_set_reserved_bit() {
        // Bit 3 of byte 0 is reserved and must be 0.
        let bytes = [0b0000_1000, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let err = decode_header(&bytes).unwrap_err();
        assert!(matches!(err, Error::MalformedHeader(_)));
    }

    #[test]
    fn header_decode_accepts_all_legitimate_flag_bits() {
        // S + DSIZ=unicast set, version/reserved clear — must still decode.
        let bytes = [
            SecuredMessageFlags::SOURCE_PRESENT.bits() | SecuredMessageFlags::DEST_UNICAST.bits(),
            0x01,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            // 8-byte source node id + 8-byte dest node id.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert!(decode_header(&bytes).is_ok());
    }

    /// Load-bearing invariant for the `decode_secured` AAD optimisation:
    /// the leading header bytes of the input (`&bytes[..header_len]`, where
    /// `header_len = bytes.len() - rest.len()`) are byte-for-byte identical to
    /// `encode_header(&decoded_header)`. If this ever drifts — e.g. a header
    /// field that doesn't round-trip exactly — `decode_secured` would feed the
    /// AES-CCM verifier the wrong AAD and silently fail ALL decryption. We pin
    /// it here across the maximal header shape (S=1, DSIZ=unicast) plus a
    /// trailing payload so `rest` is non-empty.
    #[test]
    fn aad_slice_equals_reencoded_header() {
        let header = SecuredMessageHeader {
            flags: SecuredMessageFlags::SOURCE_PRESENT | SecuredMessageFlags::DEST_UNICAST,
            session_id: SessionId(0x4242),
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(0x1234_5678),
            source_node_id: Some(NodeId(0x1111_2222_3333_4444)),
            destination_node_id: Some(DestNodeId::Node(NodeId(0x5555_6666_7777_8888))),
        };
        let mut bytes = encode_header(&header);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // pretend payload+tag
        let (decoded, rest) = decode_header(&bytes).unwrap();
        let header_len = bytes.len() - rest.len();
        assert_eq!(
            &bytes[..header_len],
            encode_header(&decoded).as_slice(),
            "AAD slice must equal the re-encoded header byte-for-byte"
        );
    }

    /// Build a minimal secured header at `counter` for the secured-message
    /// tests below. S=0/DSIZ=0 (the common CASE/PASE unicast shape).
    fn secured_header(counter: u32) -> SecuredMessageHeader {
        SecuredMessageHeader {
            flags: SecuredMessageFlags::empty(),
            session_id: SessionId(0x0042),
            security_flags: SecurityFlags::empty(),
            message_counter: MessageCounter(counter),
            source_node_id: None,
            destination_node_id: None,
        }
    }

    /// Fixed, distinct key material for the secured-message tests. The exact
    /// bytes don't matter — only that encrypt/decrypt agree on them.
    fn test_session_keys() -> crate::session::SessionKeys {
        crate::session::SessionKeys {
            i2r_key: [0x11; 16],
            r2i_key: [0x22; 16],
            attestation_key: [0x33; 16],
        }
    }

    /// A forged datagram must not advance the replay window when its tag
    /// fails to verify. Pre-fix, `decode_secured` recorded the counter
    /// BEFORE authenticating, so a forged large counter poisoned the window
    /// and rejected subsequent genuine (smaller-counter) traffic.
    #[test]
    fn forged_packet_does_not_poison_replay_window() {
        let keys = test_session_keys();
        let mut window = ReplayWindow::new();

        // Genuine message at counter=5 — encoded by the Initiator (sender),
        // decoded by us as the Responder (receiver). Seeds the window at 5.
        let genuine5 = encode_secured(
            &secured_header(5),
            b"hello",
            &keys,
            crate::session::SessionRole::Initiator,
            0,
        )
        .unwrap();
        let (h5, _) = decode_secured(
            &genuine5,
            &keys,
            crate::session::SessionRole::Responder,
            &mut window,
            0,
        )
        .unwrap();
        assert_eq!(h5.message_counter.0, 5);

        // Forged datagram: well-formed header with a far-future counter
        // (1000) but garbage ciphertext, so the AES-CCM tag cannot verify.
        let mut forged = encode_header(&secured_header(1000));
        forged.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]);
        let err = decode_secured(
            &forged,
            &keys,
            crate::session::SessionRole::Responder,
            &mut window,
            0,
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::DecryptionFailed),
            "forged packet must fail authentication; got {err:?}",
        );

        // The window must still be seeded at 5, not 1000 — so a genuine
        // follow-up at counter=6 is accepted. Pre-fix this failed as
        // CounterTooOld (6 < 1000 - 31).
        let genuine6 = encode_secured(
            &secured_header(6),
            b"world",
            &keys,
            crate::session::SessionRole::Initiator,
            0,
        )
        .unwrap();
        let (h6, payload) = decode_secured(
            &genuine6,
            &keys,
            crate::session::SessionRole::Responder,
            &mut window,
            0,
        )
        .unwrap_or_else(|e| {
            panic!("genuine counter=6 must decode after a forged packet; got {e:?}")
        });
        assert_eq!(h6.message_counter.0, 6);
        assert_eq!(payload, b"world");
    }

    /// **Security-critical known-answer test.** The group-secured encode
    /// MUST byte-match the independent matter.js vector
    /// (`test-vectors/transport/group-message.json`, captured from
    /// `@matter/protocol` `GroupSession.encode` + Node `aes-128-ccm`). If the
    /// nonce, AAD, key, or header layout drifts by a single byte the tag
    /// changes and this fails. This is the proof that our group nonce/AAD/key
    /// construction matches the oracle.
    ///
    /// Inputs are read straight from the fixture:
    /// - `operational_group_key` = `4e6f436f6e74726f6c4d61747465724b`
    /// - `group_session_id` = 1, `group_id` = 0x1234, `message_counter` = 5
    /// - `source_node_id` = 0xDEADBEEFCAFEBABE
    /// - plaintext = `052102d10a0001003501290218` (a protocol header
    ///   `INITIATOR|RELIABLE`, opcode 0x21, exchange 0xd102, protocol 0x000a,
    ///   followed by the app payload tail `01003501290218`).
    /// - expected wire = header `0601000105000000bebafecaefbeadde3412` ||
    ///   ciphertext+tag.
    #[test]
    fn group_encode_matches_matterjs_vector() {
        use crate::protocol_header::{ExchangeFlags, ProtocolHeader, ProtocolId};

        // ---- Inputs (verbatim from group-message.json) ----
        let key: [u8; 16] = hex16("4e6f436f6e74726f6c4d61747465724b");
        let group_session_id: u16 = 1;
        let group_id: u16 = 0x1234; // 4660
        let counter: u32 = 5;
        let source_node_id: u64 = 0xDEAD_BEEF_CAFE_BABE;

        // The fixture's plaintext decodes as protocol-header || app-payload.
        // We reconstruct the header fields and the tail so the encoded
        // plaintext is byte-identical to `payload_hex`.
        let protocol_header = ProtocolHeader {
            exchange_flags: ExchangeFlags::INITIATOR | ExchangeFlags::RELIABLE,
            opcode: 0x21,
            exchange_id: 0xd102,
            protocol_id: ProtocolId {
                vendor: 0,
                protocol: 0x000a,
            },
            ack_counter: None,
        };
        let app_payload = hex("01003501290218");

        // Sanity: the reconstructed plaintext equals the fixture's payload_hex.
        let mut plaintext = Vec::new();
        crate::protocol_header::encode_protocol_header(&protocol_header, &mut plaintext);
        plaintext.extend_from_slice(&app_payload);
        assert_eq!(
            plaintext,
            hex("052102d10a0001003501290218"),
            "reconstructed plaintext must equal the fixture payload_hex"
        );

        // ---- Encode ----
        let wire = encode_group_secured(
            &key,
            group_session_id,
            source_node_id,
            group_id,
            counter,
            &protocol_header,
            &app_payload,
        )
        .unwrap();

        // ---- Assert byte-for-byte against the full fixture wire message ----
        let expected_wire =
            hex("0601000105000000bebafecaefbeadde34129506e3d4b7267e33e078a21650d79c70db886e5ddfc1398a6ee2212fb5");
        assert_eq!(
            hex_encode(&wire),
            hex_encode(&expected_wire),
            "group wire message must byte-match the matter.js vector"
        );

        // Cross-check the discrete fixture fields too: header + ciphertext+tag.
        let header_bytes = hex("0601000105000000bebafecaefbeadde3412");
        assert_eq!(
            &wire[..header_bytes.len()],
            &header_bytes[..],
            "header (AAD)"
        );
        assert_eq!(
            &wire[header_bytes.len()..],
            &hex("9506e3d4b7267e33e078a21650d79c70db886e5ddfc1398a6ee2212fb5")[..],
            "ciphertext || tag"
        );
    }

    /// Loopback: encode a group message then decode it with the SAME
    /// operational group key. Recover the payload, the group id, and the
    /// source node id from the decoded header.
    #[test]
    fn group_encode_decode_roundtrip() {
        use crate::protocol_header::{ExchangeFlags, ProtocolHeader, ProtocolId};

        let key: [u8; 16] = [0xA5; 16];
        let group_session_id: u16 = 0x0007;
        let group_id: u16 = 0xBEEF;
        let counter: u32 = 0x1234_5678;
        let source_node_id: u64 = 0x0011_2233_4455_6677;

        let protocol_header = ProtocolHeader {
            exchange_flags: ExchangeFlags::INITIATOR,
            opcode: 0x06, // ReportData
            exchange_id: 0x4242,
            protocol_id: ProtocolId::INTERACTION_MODEL,
            ack_counter: None,
        };
        let app_payload = b"group payload bytes";

        let wire = encode_group_secured(
            &key,
            group_session_id,
            source_node_id,
            group_id,
            counter,
            &protocol_header,
            app_payload,
        )
        .unwrap();

        let (header, plaintext) = decode_group_secured(&wire, &key).unwrap();

        // Header fields recovered.
        assert_eq!(header.session_id, SessionId(group_session_id));
        assert_eq!(header.message_counter, MessageCounter(counter));
        assert_eq!(header.source_node_id, Some(NodeId(source_node_id)));
        assert_eq!(
            header.destination_node_id,
            Some(DestNodeId::Group(group_id))
        );
        assert!(header
            .security_flags
            .contains(SecurityFlags::SESSION_TYPE_GROUP));
        assert!(header.flags.contains(SecuredMessageFlags::DEST_GROUP));
        assert!(header.flags.contains(SecuredMessageFlags::SOURCE_PRESENT));

        // Plaintext = protocol header || app payload. Strip the header back
        // off and confirm the app payload survived the round-trip.
        let (decoded_ph, tail) =
            crate::protocol_header::decode_protocol_header(&plaintext).unwrap();
        assert_eq!(decoded_ph.opcode, 0x06);
        assert_eq!(decoded_ph.exchange_id, 0x4242);
        assert_eq!(decoded_ph.protocol_id, ProtocolId::INTERACTION_MODEL);
        assert_eq!(tail, app_payload);
    }

    /// A group message decoded with the WRONG group key must fail
    /// authentication (the tag will not verify).
    #[test]
    fn group_decode_wrong_key_fails() {
        use crate::protocol_header::{ExchangeFlags, ProtocolHeader, ProtocolId};

        let key: [u8; 16] = [0x11; 16];
        let wrong: [u8; 16] = [0x22; 16];
        let ph = ProtocolHeader {
            exchange_flags: ExchangeFlags::INITIATOR,
            opcode: 0x06,
            exchange_id: 1,
            protocol_id: ProtocolId::INTERACTION_MODEL,
            ack_counter: None,
        };
        let wire = encode_group_secured(&key, 1, 0xCAFE, 0x1234, 9, &ph, b"x").unwrap();
        let err = decode_group_secured(&wire, &wrong).unwrap_err();
        assert!(matches!(err, Error::DecryptionFailed));
    }

    mod replay_window {
        use super::super::*;

        #[test]
        fn would_reject_does_not_mutate() {
            // Seed the window at 100.
            let mut w = ReplayWindow::new();
            w.check_and_record(100).unwrap();

            // An in-window, not-yet-seen counter: would_reject says Ok and
            // must NOT record it — check_and_record afterwards still succeeds.
            assert!(w.would_reject(95).is_ok());
            assert!(
                w.check_and_record(95).is_ok(),
                "would_reject must not have recorded counter 95",
            );

            // Agreement on a replayed counter (100 was recorded as the seed).
            assert!(matches!(
                w.would_reject(100),
                Err(Error::ReplayedCounter { counter: 100 })
            ));
            assert!(matches!(
                w.check_and_record(100),
                Err(Error::ReplayedCounter { counter: 100 })
            ));

            // Agreement on a too-old counter (window covers 69..=100).
            assert!(matches!(
                w.would_reject(68),
                Err(Error::CounterTooOld { counter: 68, .. })
            ));
            assert!(matches!(
                w.check_and_record(68),
                Err(Error::CounterTooOld { counter: 68, .. })
            ));

            // Empty-window case: would_reject accepts anything.
            let empty = ReplayWindow::new();
            assert!(empty.would_reject(7).is_ok());
        }

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
