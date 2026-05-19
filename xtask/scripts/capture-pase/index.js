/**
 * xtask/scripts/capture-pase/index.js
 *
 * Drive matter.js's Spake2p implementation through full PASE handshakes
 * using FIXED scalars and nonces. Emit JSON fixtures consumed by
 * crates/matter-crypto/tests/pase_byte_parity.rs (Task 2 of M3.3).
 *
 * DISCOVERY (probed 2026-05-19 against @matter/general 0.16.11):
 *
 *   The Spake2p class lives in @matter/general and is constructable
 *   directly — no session manager or network stack required.
 *
 *   Spake2p.create(crypto, context, w0) calls crypto.randomBigInt(32, curve.p)
 *   which internally calls crypto.randomBytes(32) in a rejection-sampling loop
 *   until the resulting bigint is < curve.p.  All other randomness
 *   (initiatorRandom, responderRandom) comes from direct crypto.randomBytes(32)
 *   calls in our harness, not inside matter.js itself.
 *
 *   Because we control ALL randomBytes calls (by subclassing NodeJsStyleCrypto
 *   and overriding randomBytes with a deterministic queue), the entire handshake
 *   is deterministic.
 *
 * RNG CALL ORDER per handshake (verified by code reading):
 *
 *   We call randomBytes explicitly for:
 *     [0] initiatorRandom   — 32 bytes, harness-generated
 *     [1] responderRandom   — 32 bytes, harness-generated
 *
 *   Spake2p.create calls randomBigInt(32, curve.p) which calls randomBytes(32)
 *   once per trial (rejection-sampling). With scalars chosen < curve.p the
 *   first trial always succeeds — one call each:
 *     [2] x_scalar  — 32 bytes, consumed by Spake2p.create for the prover
 *     [3] y_scalar  — 32 bytes, consumed by Spake2p.create for the verifier
 *
 *   Total deterministic calls per handshake: 4 × 32 bytes.
 *
 * SCALAR VALIDITY CONSTRAINT:
 *
 *   P-256 prime p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
 *   Any 32-byte value whose leading nibble is ≤ 0x7f is guaranteed < p.
 *   Our chosen scalars all start with 0x00 — they are unambiguously valid.
 *
 * OUTPUT FORMAT:
 *
 *   test-vectors/pase/<scenario-id>.json
 *
 *   {
 *     "scenario": "<id>",
 *     "inputs": {
 *       "pin": <number>,
 *       "iterations": <number>,
 *       "salt_hex": "<hex>",           // 16–32 bytes
 *       "initiator_session_id": <number>,
 *       "responder_session_id": <number>,
 *       "initiator_random_hex": "<hex>",
 *       "responder_random_hex": "<hex>",
 *       "x_scalar_hex": "<hex>",
 *       "y_scalar_hex": "<hex>"
 *     },
 *     "intermediates": {
 *       "w0_hex": "<hex>",             // 32-byte bigint BE
 *       "w1_hex": "<hex>",             // 32-byte bigint BE
 *       "L_hex": "<hex>",              // 65-byte uncompressed P-256 point
 *       "X_hex": "<hex>",              // 65-byte uncompressed P-256 point (prover share)
 *       "Y_hex": "<hex>",              // 65-byte uncompressed P-256 point (verifier share)
 *       "context_hex": "<hex>",        // SHA-256( SPAKE_CONTEXT || req_tlv || resp_tlv )
 *       "Ke_hex": "<hex>",             // 16-byte session key
 *       "hBX_hex": "<hex>",            // 32-byte verifier for Pake2
 *       "hAY_hex": "<hex>"             // 32-byte verifier for Pake3
 *     },
 *     "messages": {
 *       "pbkdf_param_request_hex":  "<hex>",   // TLV-encoded PbkdfParamRequest
 *       "pbkdf_param_response_hex": "<hex>",   // TLV-encoded PbkdfParamResponse
 *       "pake1_hex":                "<hex>",   // TLV-encoded Pake1
 *       "pake2_hex":                "<hex>",   // TLV-encoded Pake2
 *       "pake3_hex":                "<hex>"    // TLV-encoded Pake3
 *     }
 *   }
 */

import { createRequire } from 'node:module';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// ── Paths ──────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const OUT_DIR = join(REPO_ROOT, 'test-vectors', 'pase');
mkdirSync(OUT_DIR, { recursive: true });

// ── Node.js built-in crypto (CommonJS import required for ESM compat) ─────

const require = createRequire(import.meta.url);
const nodeCrypto = require('crypto');

// ── matter.js imports ──────────────────────────────────────────────────────

import { NodeJsStyleCrypto, Spake2p, ec } from '@matter/general';
import {
  TlvPbkdfParamRequest,
  TlvPbkdfParamResponse,
  TlvPasePake1,
  TlvPasePake2,
  TlvPasePake3,
} from '@matter/protocol';

const { numberToBytesBE, bytesToNumberBE } = ec;

// ── SPAKE_CONTEXT ─────────────────────────────────────────────────────────
// Matches PaseMessenger.ts: Bytes.fromString("CHIP PAKE V1 Commissioning")

const SPAKE_CONTEXT = new TextEncoder().encode('CHIP PAKE V1 Commissioning');

// ── Helpers ────────────────────────────────────────────────────────────────

/** Convert a Uint8Array (or Buffer) to lowercase hex. */
function toHex(buf) {
  return Buffer.from(buf).toString('hex');
}

/** Convert a hex string to Uint8Array. */
function fromHex(hex) {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/**
 * Build a NodeJsStyleCrypto subclass whose `randomBytes` method serves
 * bytes from a pre-filled queue.  All other crypto operations (PBKDF2,
 * HKDF, HMAC, hash, ECDSA, ECDH) delegate to the real Node.js implementation.
 *
 * Throws if the queue is exhausted or if a request size doesn't match the
 * next queued block's length exactly.
 */
function makeFixedCrypto(queueHex /* string[] */) {
  const crypto = new NodeJsStyleCrypto(nodeCrypto);
  const queue = queueHex.map((h) => new Uint8Array(Buffer.from(h, 'hex')));
  let idx = 0;

  crypto.randomBytes = function fixedRandomBytes(length) {
    if (idx >= queue.length) {
      throw new Error(
        `FixedCrypto: queue exhausted at call #${idx} (request for ${length} bytes)`,
      );
    }
    const buf = queue[idx++];
    if (buf.length !== length) {
      throw new Error(
        `FixedCrypto: call #${idx - 1} expected ${buf.length} bytes but got request for ${length} bytes`,
      );
    }
    return buf;
  };

  return { crypto, consumedCount: () => idx };
}

// ── Core capture function ──────────────────────────────────────────────────

/**
 * Run one full PASE handshake with fixed inputs and return the structured
 * fixture object (suitable for JSON.stringify).
 *
 * @param {object} params
 * @param {string} params.id                      — scenario ID used as filename
 * @param {number} params.pin                     — setup passcode
 * @param {number} params.iterations              — PBKDF2 iteration count
 * @param {string} params.saltHex                 — PBKDF2 salt, hex (16–32 bytes)
 * @param {number} params.initiatorSessionId      — session ID proposed by initiator
 * @param {number} params.responderSessionId      — session ID proposed by responder
 * @param {string} params.initiatorRandomHex      — 32-byte initiator nonce, hex
 * @param {string} params.responderRandomHex      — 32-byte responder nonce, hex
 * @param {string} params.xScalarHex              — 32-byte prover scalar, hex (< curve.p)
 * @param {string} params.yScalarHex              — 32-byte verifier scalar, hex (< curve.p)
 */
async function captureHandshake(params) {
  const {
    id,
    pin,
    iterations,
    saltHex,
    initiatorSessionId,
    responderSessionId,
    initiatorRandomHex,
    responderRandomHex,
    xScalarHex,
    yScalarHex,
  } = params;

  const salt = fromHex(saltHex);
  const pbkdfParameters = { iterations, salt };

  // The RNG queue must match the exact order in which randomBytes is called.
  //
  // In this harness we never call crypto.randomBytes ourselves for the session
  // randoms — instead we pass them as pre-computed Uint8Arrays directly to the
  // TLV builders.  The ONLY randomBytes calls that go through `crypto` are
  // the two Spake2p.create() calls, which each call randomBigInt(32, curve.p)
  // → randomBytes(32) once (since our scalars are < curve.p, so the first
  // trial always succeeds).
  //
  // Queue order: [ xScalar, yScalar ]
  const { crypto } = makeFixedCrypto([xScalarHex, yScalarHex]);

  // ── Step 1: compute w0, w1, L from the pin + PBKDF params ──────────────
  const { w0, w1 } = await Spake2p.computeW0W1(crypto, pbkdfParameters, pin);
  const L = ec.p256.Point.BASE.multiply(w1).toBytes(false); // w1·G, uncompressed

  // ── Step 2: build the TLV bytes for PbkdfParamRequest ──────────────────
  const initiatorRandom = fromHex(initiatorRandomHex);
  const reqObj = {
    initiatorRandom,
    initiatorSessionId,
    passcodeId: 0,
    hasPbkdfParameters: false,
    // No session params — keeps the fixture minimal and deterministic.
  };
  const pbkdfParamRequestBytes = TlvPbkdfParamRequest.encode(reqObj);

  // ── Step 3: build the TLV bytes for PbkdfParamResponse ─────────────────
  const responderRandom = fromHex(responderRandomHex);
  const respObj = {
    initiatorRandom,
    responderRandom,
    responderSessionId,
    pbkdfParameters: { iterations, salt },
    // No session params — deterministic.
  };
  const pbkdfParamResponseBytes = TlvPbkdfParamResponse.encode(respObj);

  // ── Step 4: compute the SPAKE2+ transcript context ─────────────────────
  // context = SHA-256(SPAKE_CONTEXT || PbkdfParamRequest_TLV || PbkdfParamResponse_TLV)
  // This matches PaseClient.ts and PaseServer.ts:
  //   crypto.computeHash([SPAKE_CONTEXT, requestPayload, responsePayload])
  const contextBytes = await crypto.computeHash([
    SPAKE_CONTEXT,
    pbkdfParamRequestBytes,
    pbkdfParamResponseBytes,
  ]);

  // ── Step 5: prover computes X = x·G + w0·M  (Spake2p.create consumes xScalar) ──
  const proverSpake2p = Spake2p.create(crypto, contextBytes, w0);
  const X = proverSpake2p.computeX();

  // ── Step 6: verifier computes Y = y·G + w0·N  (Spake2p.create consumes yScalar) ──
  const verifierSpake2p = Spake2p.create(crypto, contextBytes, w0);
  const Y = verifierSpake2p.computeY();

  // ── Step 7: verifier computes its confirmation tag hBX (from X, Y, L) ───
  // computeSecretAndVerifiersFromX is the verifier/server path.
  const { Ke, hAY, hBX } = await verifierSpake2p.computeSecretAndVerifiersFromX(L, X, Y);

  // Sanity-check: prover path should produce the same Ke and swapped verifiers.
  const proverResult = await proverSpake2p.computeSecretAndVerifiersFromY(w1, X, Y);
  if (toHex(proverResult.Ke) !== toHex(Ke)) {
    throw new Error(`scenario ${id}: Ke mismatch between prover and verifier paths`);
  }
  if (toHex(proverResult.hBX) !== toHex(hBX)) {
    throw new Error(`scenario ${id}: hBX mismatch`);
  }
  if (toHex(proverResult.hAY) !== toHex(hAY)) {
    throw new Error(`scenario ${id}: hAY mismatch`);
  }

  // ── Step 8: encode the remaining three TLV messages ────────────────────

  const pake1Bytes = TlvPasePake1.encode({ x: X });
  const pake2Bytes = TlvPasePake2.encode({ y: Y, verifier: hBX });
  const pake3Bytes = TlvPasePake3.encode({ verifier: hAY });

  // ── Assemble fixture ────────────────────────────────────────────────────

  return {
    scenario: id,
    inputs: {
      pin,
      iterations,
      salt_hex: saltHex,
      initiator_session_id: initiatorSessionId,
      responder_session_id: responderSessionId,
      initiator_random_hex: initiatorRandomHex,
      responder_random_hex: responderRandomHex,
      x_scalar_hex: xScalarHex,
      y_scalar_hex: yScalarHex,
    },
    intermediates: {
      w0_hex: toHex(numberToBytesBE(w0, 32)),
      w1_hex: toHex(numberToBytesBE(w1, 32)),
      L_hex: toHex(L),
      X_hex: toHex(X),
      Y_hex: toHex(Y),
      context_hex: toHex(contextBytes),
      Ke_hex: toHex(Ke),
      hBX_hex: toHex(hBX),
      hAY_hex: toHex(hAY),
    },
    messages: {
      pbkdf_param_request_hex: toHex(pbkdfParamRequestBytes),
      pbkdf_param_response_hex: toHex(pbkdfParamResponseBytes),
      pake1_hex: toHex(pake1Bytes),
      pake2_hex: toHex(pake2Bytes),
      pake3_hex: toHex(pake3Bytes),
    },
  };
}

// ── Scenarios ──────────────────────────────────────────────────────────────
//
// Three scenarios cover the meaningful parameter dimensions our Rust
// implementation must handle:
//
//   handshake-negotiation — baseline scenario with the Matter SDK default
//     passcode (20202021) and the minimum-legal iteration count (1000).
//     Salt is 16 bytes (minimum).  This is the first scenario Rust tests
//     will use.
//
//   handshake-known-params — a different passcode (123456) and a 24-byte
//     salt.  Exercises that the PBKDF2 output varies correctly with passcode
//     and that non-minimum salt lengths round-trip through the TLV codec.
//
//   handshake-max-iter — iteration count at the Matter spec maximum (100000).
//     Same passcode as the baseline but max iterations; this exercises the
//     PBKDF2 KDF under load and verifies that slow PBKDF doesn't change the
//     algebraic handshake logic.
//
// All scalars start with 0x00…, guaranteeing they are < curve.p without
// rejection-sampling retries.  The prover scalar (x) and verifier scalar (y)
// are distinct across scenarios to prevent any accidental cancellations.

const scenarios = [
  {
    id: 'handshake-negotiation',
    pin: 20202021,
    iterations: 1000,
    // 16-byte salt: all 0x42 ("B") — visually distinct, minimum length.
    saltHex: '42424242424242424242424242424242',
    initiatorSessionId: 1,
    responderSessionId: 2,
    // 32-byte initiator nonce: all 0x01.
    initiatorRandomHex:
      '0101010101010101010101010101010101010101010101010101010101010101',
    // 32-byte responder nonce: all 0x02.
    responderRandomHex:
      '0202020202020202020202020202020202020202020202020202020202020202',
    // Prover scalar: small bigint well below curve.p.
    xScalarHex:
      '000000000000000000000000000000000000000000000000000000000000002a',
    // Verifier scalar: different small bigint.
    yScalarHex:
      '000000000000000000000000000000000000000000000000000000000000002b',
  },
  {
    id: 'handshake-known-params',
    pin: 123456,
    iterations: 2000,
    // 24-byte salt: alternating 0xab / 0xcd.
    saltHex: 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
    initiatorSessionId: 10,
    responderSessionId: 11,
    initiatorRandomHex:
      '1111111111111111111111111111111111111111111111111111111111111111',
    responderRandomHex:
      '2222222222222222222222222222222222222222222222222222222222222222',
    xScalarHex:
      '0000000000000000000000000000000000000000000000000000000000000064',
    yScalarHex:
      '0000000000000000000000000000000000000000000000000000000000000065',
  },
  {
    id: 'handshake-max-iter',
    pin: 20202021,
    iterations: 100000,
    // 32-byte salt: all 0x55 — maximum legal length.
    saltHex: '5555555555555555555555555555555555555555555555555555555555555555',
    initiatorSessionId: 100,
    responderSessionId: 101,
    initiatorRandomHex:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    responderRandomHex:
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    xScalarHex:
      '00000000000000000000000000000000000000000000000000000000000000c8',
    yScalarHex:
      '00000000000000000000000000000000000000000000000000000000000000c9',
  },
];

// ── Main ───────────────────────────────────────────────────────────────────

async function main() {
  for (const scenario of scenarios) {
    const fixture = await captureHandshake(scenario);
    const outPath = join(OUT_DIR, `${scenario.id}.json`);
    writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n');
    console.log(
      `captured ${scenario.id} -> test-vectors/pase/${scenario.id}.json`,
    );
  }
  console.log(`\nAll ${scenarios.length} scenarios captured successfully.`);
  console.log('Run `cargo xtask capture-pase` (after npm install) to regenerate.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
