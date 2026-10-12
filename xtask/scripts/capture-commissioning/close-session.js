// xtask/scripts/capture-commissioning/close-session.js
//
// Capture the Secure Channel CloseSession message matter.js 0.17.1 sends when
// it closes a session gracefully. Output: test-vectors/transport/close-session.json,
// consumed by crates/matter-transport/tests/close_session_byte_parity.rs.
// Run it with `cargo xtask capture-close-session`.
//
// Why this directory: its node_modules holds matter.js 0.17.1 (package.json
// pins it); the other capture-* directories pin 0.16.11. Nothing new is
// installed.
//
// =====================================================================
// MATTER.JS PATH (0.17.1, @matter/protocol/src)
// =====================================================================
//
//   ExchangeManager.#sendCloseSession                 protocol/ExchangeManager.ts:632-643
//     initiateExchangeForSession(session, SECURE_CHANNEL_PROTOCOL_ID)   :134-145
//       MessageExchange.initiate(..)   isInitiator: true   protocol/MessageExchange.ts:169-187
//     new SecureChannelMessenger(exchange).sendCloseSession()
//       #sendStatusReport(Success, CloseSession, abort, requiresAck = false)
//                                securechannel/SecureChannelMessenger.ts:156-157, :172-194
//     MessageExchange.#send builds the payload header   protocol/MessageExchange.ts:566-576
//
// What runs and what is mirrored: this script EXECUTES matter.js's real
// MessageExchange.initiate, SecureChannelMessenger.sendCloseSession (and so
// #sendStatusReport and MessageExchange.#send) and
// MessageCodec.encodePayloadHeader. It MIRRORS the private
// ExchangeManager.#sendCloseSession wrapper (take an exchange id, call
// initiate), which cannot be called from outside, and replaces NodeSession
// with a stub whose channel records the outgoing Message instead of
// encrypting it. So "a new exchange" is this script's choice, made to match
// ExchangeManager.ts:632-643; the flags, opcode, protocol and payload are
// matter.js's own output. Encryption is not captured here: framing
// parity is test-vectors/transport/framing-*.json.
//
// The exchange id is an input (0xBEEF). matter.js draws a node's first exchange
// id from a random 16-bit counter (ExchangeManager.ts:645-650), so it is not
// part of what must match.

import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { MessageCodec, MessageExchange, SecureChannelMessenger, SessionType } from '@matter/protocol';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const OUT_FILE = join(REPO_ROOT, 'test-vectors', 'transport', 'close-session.json');

const PROTOCOL_PKG = join(__dirname, 'node_modules', '@matter', 'protocol', 'package.json');
const MATTER_JS_VERSION = JSON.parse(readFileSync(PROTOCOL_PKG, 'utf8')).version;
if (MATTER_JS_VERSION !== '0.17.1') {
    throw new Error(`expected @matter/protocol 0.17.1, found ${MATTER_JS_VERSION}`);
}

const EXCHANGE_ID = 0xbeef;

// The stub session: just enough of NodeSession for MessageExchange to build and
// "send" one message. `usesMrp: true` matches a UDP session, so matter.js's own
// requiresAck default would be true; the captured `requires_ack: false` is
// sendCloseSession's explicit choice.
const sent = [];
let nextCounter = 1;
const session = {
    type: SessionType.Unicast,
    usesMrp: true,
    isPeerLost: false,
    peerSessionId: 0x1234,
    nodeId: undefined,
    peerNodeId: undefined,
    parameters: {},
    via: 'capture',
    channel: {
        name: 'capture',
        maxPayloadSize: 1232,
        send: async message => {
            sent.push(message);
        },
    },
    addExchange() {},
    notifyActivity() {},
    getIncrementedMessageCounter: async () => nextCounter++,
    join() {
        return { [Symbol.dispose]() {}, join() { return this; } };
    },
};
const context = { session, localSessionParameters: {}, peerLost: async () => {}, retry() {} };

const exchange = MessageExchange.initiate(context, EXCHANGE_ID, 0x0000);
await new SecureChannelMessenger(exchange).sendCloseSession();

if (sent.length !== 1) {
    throw new Error(`expected exactly one message, recorded ${sent.length}`);
}
const { payloadHeader, payload } = sent[0];
const fixture = {
    source: `matter.js ${MATTER_JS_VERSION}: SecureChannelMessenger.sendCloseSession on a MessageExchange.initiate exchange (mirrors ExchangeManager.#sendCloseSession; stub NodeSession)`,
    inputs: { exchange_id: EXCHANGE_ID },
    expected: {
        payload_header: {
            exchange_id: payloadHeader.exchangeId,
            protocol_id: payloadHeader.protocolId,
            message_type: payloadHeader.messageType,
            is_initiator: payloadHeader.isInitiatorMessage,
            requires_ack: payloadHeader.requiresAck,
            acked_message_id: payloadHeader.ackedMessageId ?? null,
        },
        payload_header_hex: Buffer.from(MessageCodec.encodePayloadHeader(payloadHeader)).toString('hex'),
        payload_hex: Buffer.from(payload).toString('hex'),
    },
};
mkdirSync(dirname(OUT_FILE), { recursive: true });
writeFileSync(OUT_FILE, JSON.stringify(fixture, null, 2) + '\n');
console.log(`close-session: header ${fixture.expected.payload_header_hex} payload ${fixture.expected.payload_hex} -> ${OUT_FILE}`);
// The stub session has no lifecycle to close and nothing of ours is pending;
// exit rather than wait on matter.js's unref'd timers.
process.exit(0);
