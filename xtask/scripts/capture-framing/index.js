// xtask/scripts/capture-framing/index.js
//
// Drive matter.js's Matter secured-message encoder with FIXED keys +
// counters + payloads, capture the wire bytes, and emit JSON fixtures
// consumed by crates/matter-transport/tests/framing_byte_parity.rs.
//
// =====================================================================
// MATTER.JS ENTRY POINT
// =====================================================================
//
// matter.js owns secured-message framing across two pieces:
//
//   1. `@matter/protocol/src/codec/MessageCodec.ts`
//        MessageCodec.encodePacketHeader({ sessionId, sourceNodeId,
//            destNodeId, destGroupId, sessionType, messageId, ... })
//          → header bytes (the AES-CCM AAD).
//        MessageCodec.encodePacket({ header, applicationPayload })
//          → final wire bytes = header || ciphertext.
//
//   2. `@matter/protocol/src/session/Session.ts`
//        Session.generateNonce(securityFlags, messageId, nodeId)
//          → 13-byte AES-CCM nonce (LE securityFlags||messageId||nodeId).
//
//   3. `@matter/protocol/src/session/NodeSession.ts` ties them together:
//        NodeSession.encode(message) (lines 201-214):
//          1. encodePacketHeader → headerBytes (= AAD)
//          2. nonce = generateNonce(securityFlags, messageId, ourNodeId)
//             where ourNodeId = UNSPECIFIED_NODE_ID (0) for PASE, else
//             our fabric node ID. Crucially this is the LOCAL node ID,
//             which on the wire becomes the *source* node ID — so for
//             our purposes the nonce node ID == header.sourceNodeId
//             (or 0 if absent).
//          3. ciphertext = AES-128-CCM(encryptKey, payload, nonce, AAD)
//          4. wire = MessageCodec.encodePacket({ header: headerBytes,
//                                                applicationPayload:
//                                                  ciphertext })
//
// We call MessageCodec directly for header bytes and use Node's native
// crypto for AES-CCM. We deliberately avoid constructing a NodeSession
// — it pulls in fabric/sessionManager/peerAddress machinery we don't
// need. Calling the static functions directly is far simpler and
// produces byte-identical output (NodeSession.encode is a thin wrapper).
//
// =====================================================================
// CONVENTIONS (must match Rust test in Task 8)
// =====================================================================
//
//   * source_node_id / destination_node_id in the JSON fixture are
//     human-readable BIG-ENDIAN hex (e.g. "DEADBEEFCAFEBABE" → the
//     u64 value 0xDEADBEEFCAFEBABE). The wire format is little-endian;
//     we convert here. Rust's test must use u64::from_be_bytes after
//     hex-decoding to obtain the same u64.
//
//   * i2r_key / r2i_key are 16-byte raw AES-128 keys (hex).
//
//   * session_id is u16, message_counter is u32, payload_hex is the
//     plaintext bytes BEFORE encryption.
//
//   * role: "Initiator" or "Responder". Initiator encrypts with
//     i2r_key, Responder encrypts with r2i_key (matter.js
//     NodeSession.create: `encryptKey = isInitiator ? keys.slice(0,16)
//     : keys.slice(16,32)`).
//
//   * The encoded wire bytes are: packet_header || AES-CCM(payload).
//     No further wrapping (no UDP framing, no exchange-layer framing
//     beyond what the caller already encoded into `payload`).

import { createRequire } from 'node:module';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { MessageCodec, SessionType } from '@matter/protocol';

const require = createRequire(import.meta.url);
const nodeCrypto = require('crypto');

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const OUT_DIR = join(REPO_ROOT, 'test-vectors', 'transport');

mkdirSync(OUT_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * AES-128-CCM encrypt with a 16-byte authentication tag.
 * Returns `ciphertext || tag` (matching matter.js NodeJsStyleCrypto.encrypt
 * and the Rust matter-crypto::aead::encrypt convention).
 */
function aesCcmEncrypt(key, plaintext, nonce, aad) {
    const cipher = nodeCrypto.createCipheriv('aes-128-ccm', key, nonce, {
        authTagLength: 16,
    });
    if (aad && aad.length > 0) {
        cipher.setAAD(aad, { plaintextLength: plaintext.length });
    }
    const ct = cipher.update(plaintext);
    cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([ct, tag]);
}

/**
 * Build the AES-CCM nonce exactly as matter.js's Session.generateNonce does:
 *   nonce = u8(securityFlags) || u32_LE(messageId) || u64_LE(nodeId)
 * (13 bytes total — the standard Matter AES-CCM nonce).
 */
function buildNonce(securityFlags, messageId, nodeIdBigInt) {
    const buf = Buffer.alloc(13);
    buf.writeUInt8(securityFlags, 0);
    buf.writeUInt32LE(messageId >>> 0, 1);
    buf.writeBigUInt64LE(BigInt.asUintN(64, nodeIdBigInt), 5);
    return buf;
}

/**
 * Parse a big-endian hex string into a BigInt. `null`/`undefined` returns null.
 * Empty string is rejected (would silently produce 0n, which collides with
 * "absent" node-id semantics).
 */
function nodeIdFromHexBE(hex) {
    if (hex === null || hex === undefined) return null;
    if (typeof hex !== 'string' || hex.length === 0) {
        throw new Error(`invalid node-id hex: ${JSON.stringify(hex)}`);
    }
    return BigInt('0x' + hex);
}

// ---------------------------------------------------------------------------
// Encode a single scenario
// ---------------------------------------------------------------------------

/**
 * Drive the matter.js secured-message encoder with fixed inputs and return
 * the final wire bytes (hex).
 *
 * Implementation mirrors NodeSession.encode in matter.js (see entry-point
 * notes at the top of this file). We sidestep NodeSession itself so we
 * don't need to construct a fabric / session manager / peer address.
 */
function captureScenario(inputs) {
    const i2rKey = Buffer.from(inputs.i2r_key, 'hex');
    const r2iKey = Buffer.from(inputs.r2i_key, 'hex');
    if (i2rKey.length !== 16) throw new Error('i2r_key must be 16 bytes');
    if (r2iKey.length !== 16) throw new Error('r2i_key must be 16 bytes');

    const sourceNodeId = nodeIdFromHexBE(inputs.source_node_id);   // BigInt|null
    const destNodeId = nodeIdFromHexBE(inputs.destination_node_id); // BigInt|null

    // Build the PacketHeader struct matter.js expects.
    // We use SessionType.Unicast (= 0). securityFlags on the wire equals
    // (sessionType | privacy | control | extensions); with only Unicast
    // selected and no other flags set, securityFlags = 0x00. This also
    // means the byte fed into Session.generateNonce is 0x00.
    //
    // matter.js's MessageCodec.encodePacketHeader checks `!== undefined`
    // for sourceNodeId/destNodeId presence (not `!= null`), so we MUST
    // pass `undefined` (not `null`) when the field is absent.
    const packetHeader = {
        sessionId: inputs.session_id,
        sessionType: SessionType.Unicast,
        hasPrivacyEnhancements: false,
        isControlMessage: false,
        hasMessageExtensions: false,
        messageId: inputs.message_counter >>> 0,
        sourceNodeId: sourceNodeId === null ? undefined : sourceNodeId, // BigInt|undefined
        destNodeId: destNodeId === null ? undefined : destNodeId,
        destGroupId: undefined,
    };

    // 1. Encode the packet header to obtain (a) the wire-format header bytes
    //    and (b) the AES-CCM AAD (same bytes — matter.js feeds the encoded
    //    header straight into AES-CCM as AAD).
    const headerBytes = Buffer.from(MessageCodec.encodePacketHeader(packetHeader));
    const securityFlagsByte = headerBytes[3]; // byte index 3 per the spec layout.

    // 2. Build the nonce. matter.js uses the LOCAL node ID — for an Initiator
    //    this is our own (i.e. the source) node ID. For PASE the local node
    //    ID is UNSPECIFIED (0). In both cases this is what
    //    `packetHeader.sourceNodeId ?? 0` evaluates to here. The Rust
    //    `build_nonce` does exactly the same: source absent → zero in the
    //    nonce.
    const nonceNodeId = sourceNodeId ?? 0n;
    const nonce = buildNonce(securityFlagsByte, packetHeader.messageId, nonceNodeId);

    // 3. Pick the encryption key based on role.
    let encryptKey;
    if (inputs.role === 'Initiator') {
        encryptKey = i2rKey;
    } else if (inputs.role === 'Responder') {
        encryptKey = r2iKey;
    } else {
        throw new Error(`unknown role: ${inputs.role}`);
    }

    // 4. AES-CCM encrypt the payload. AAD = the encoded packet header.
    const payload = Buffer.from(inputs.payload_hex, 'hex');
    const ciphertext = aesCcmEncrypt(encryptKey, payload, nonce, headerBytes);

    // 5. Concatenate header || ciphertext for the final wire bytes.
    //    (MessageCodec.encodePacket would do this for us if we built a
    //    Packet struct, but the concat is trivial and avoids re-encoding.)
    const wire = Buffer.concat([headerBytes, ciphertext]);

    return {
        inputs,
        expected: {
            wire_hex: wire.toString('hex'),
        },
    };
}

// ---------------------------------------------------------------------------
// Scenarios — see the plan (docs/superpowers/plans/...transport-phase-1.md
// "Task 7: capture-framing") for the rationale behind each set of inputs.
// ---------------------------------------------------------------------------

const scenarios = [
    {
        id: 'framing-pase-session',
        inputs: {
            i2r_key: '00112233445566778899aabbccddeeff',
            r2i_key: 'ffeeddccbbaa99887766554433221100',
            session_id: 0x4242,
            message_counter: 1,
            source_node_id: null,            // PASE: no operational identity
            destination_node_id: null,
            role: 'Initiator',               // encoder uses i2r_key
            payload_hex: '052102d10a0001003501290218',
        },
    },
    {
        id: 'framing-case-session',
        inputs: {
            i2r_key: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
            r2i_key: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
            session_id: 0x0001,
            message_counter: 0x80000001,     // CASE starts above 1<<31
            source_node_id: 'DEADBEEFCAFEBABE', // BE hex → u64 0xDEADBEEFCAFEBABE
            destination_node_id: null,
            role: 'Initiator',
            payload_hex: '052102d10a0001003501290218',
        },
    },
    {
        id: 'framing-with-mrp-ack',
        inputs: {
            i2r_key: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
            r2i_key: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
            session_id: 0x1234,
            message_counter: 100,
            source_node_id: 'DEADBEEFCAFEBABE',
            destination_node_id: null,
            role: 'Responder',               // encoder uses r2i_key
            // The framing layer just encrypts the bytes — the protocol-
            // header MRP fields (ack-piggyback bit + ack counter) live
            // inside this opaque payload and exercise the same code path
            // as the others, just with a different byte sequence.
            payload_hex: '052102d10a0001003501290218aa0bbb0c',
        },
    },
];

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

for (const scenario of scenarios) {
    try {
        const out = captureScenario(scenario.inputs);
        const outPath = join(OUT_DIR, `${scenario.id}.json`);
        writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
        const byteLen = out.expected.wire_hex.length / 2;
        console.log(`captured ${scenario.id} -> ${outPath} (wire ${byteLen} bytes)`);
    } catch (err) {
        console.error(`failed ${scenario.id}: ${err.message}`);
        if (err.stack) console.error(err.stack);
        process.exitCode = 1;
    }
}
