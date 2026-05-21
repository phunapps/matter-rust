// xtask/scripts/capture-protocol-header/index.js
//
// Drive matter.js's MessageCodec.encodePayloadHeader with FIXED inputs
// for three Matter MRP scenarios. Output JSON fixtures consumed by
// crates/matter-transport/tests/protocol_header_byte_parity.rs.
//
// =====================================================================
// MATTER.JS ENTRY POINT
// =====================================================================
//
// `@matter/protocol/src/codec/MessageCodec.ts`:
//
//   MessageCodec.encodePayloadHeader({
//       exchangeId, protocolId, messageType,
//       isInitiatorMessage, requiresAck, ackedMessageId,
//   }) → application protocol header bytes (Matter Core Spec §4.4.5)
//
// `encodePayloadHeader` is declared `private` in TypeScript but compiles
// down to a plain static method that JavaScript will happily call.
//
// =====================================================================
// CRITICAL: matter.js's protocolId encoding (verified by reading source)
// =====================================================================
//
// matter.js represents `protocolId` as a single 32-bit number where
// the HIGH 16 bits hold the vendor and the LOW 16 bits hold the
// protocol short ID:  protocolId = (vendor << 16) | protocol_short.
//
// On encode (encodePayloadHeader, MessageCodec.ts:333-359):
//   * `vendorId = (protocolId & 0xffff0000) >> 16`
//   * If vendorId !== 0:
//       - sets PayloadHeaderFlag.HasVendorId (bit 4) in the flag byte
//       - writes `protocolId` as a u32 LE  (4 bytes, vendor in high bytes)
//   * If vendorId === 0:
//       - leaves V flag clear
//       - writes ONLY the protocol short ID as u16 LE (2 bytes — vendor
//         is OMITTED from the wire)
//
// This means the wire format DIFFERS depending on whether a vendor is
// set: the 8-byte fixed portion described in the Matter spec text is
// actually only 8 bytes when V=1; with V=0 the protocol-id portion is 2
// bytes shorter (so the fixed portion is 6 bytes total — flags(1) +
// opcode(1) + exchangeId(2) + protocol_short(2)).
//
// =====================================================================
// CONVENTIONS (must match the Rust test in Task 7)
// =====================================================================
//
//   * JSON fixture shape:
//       { inputs: { exchange_id, protocol_id: { vendor, protocol },
//                   opcode, is_initiator, requires_ack, ack_counter },
//         expected: { wire_hex } }
//
//   * `protocol_id` is split into { vendor, protocol } for clarity even
//     though matter.js takes a packed u32. We combine here before
//     calling matter.js.
//
//   * `ack_counter` is null/undefined when A=0, a u32 when A=1.
//
//   * matter.js's PayloadHeader field name is `ackedMessageId` (not
//     `ackedMessageCounter`); we map our `ack_counter` to that.

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { MessageCodec } from '@matter/protocol';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const OUT_DIR = join(REPO_ROOT, 'test-vectors', 'transport');

mkdirSync(OUT_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// Scenarios — each is the exact input set we want byte-parity for.
// ---------------------------------------------------------------------------

const scenarios = [
    {
        id: 'protocol-header-initiator-reliable',
        inputs: {
            exchange_id: 0x4242,
            protocol_id: { vendor: 0, protocol: 0x0001 }, // InteractionModel
            opcode: 0x02,                                  // ReadRequest
            is_initiator: true,
            requires_ack: true,
            ack_counter: null,
        },
    },
    {
        id: 'protocol-header-responder-ack',
        inputs: {
            exchange_id: 0x4242,
            protocol_id: { vendor: 0, protocol: 0x0000 }, // SecureChannel
            opcode: 0x40,                                  // StatusReport
            is_initiator: false,
            requires_ack: false,
            ack_counter: 0xAABBCCDD,
        },
    },
    {
        id: 'protocol-header-standalone-ack',
        inputs: {
            exchange_id: 0x4242,
            protocol_id: { vendor: 0, protocol: 0x0000 }, // SecureChannel
            opcode: 0x10,                                  // STANDALONE_ACK
            is_initiator: true,
            requires_ack: false,
            ack_counter: 100,
        },
    },
];

function captureScenario(scenario) {
    const i = scenario.inputs;

    // Pack vendor + protocol_short into matter.js's u32 representation.
    // High 16 bits = vendor, low 16 bits = protocol short ID.
    const packedProtocolId =
        (((i.protocol_id.vendor >>> 0) & 0xffff) << 16) |
        ((i.protocol_id.protocol >>> 0) & 0xffff);

    const payloadHeader = {
        exchangeId: i.exchange_id,
        protocolId: packedProtocolId,
        messageType: i.opcode,
        isInitiatorMessage: i.is_initiator,
        requiresAck: i.requires_ack,
        ackedMessageId: i.ack_counter === null ? undefined : (i.ack_counter >>> 0),
    };

    // `encodePayloadHeader` is `private` in TypeScript but is exposed at
    // runtime in the compiled JavaScript (TS access modifiers are erased
    // at compile time).
    const encoded = MessageCodec.encodePayloadHeader(payloadHeader);
    const wireHex = Buffer.from(encoded).toString('hex');

    return {
        inputs: i,
        expected: { wire_hex: wireHex },
    };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

for (const scenario of scenarios) {
    try {
        const out = captureScenario(scenario);
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
