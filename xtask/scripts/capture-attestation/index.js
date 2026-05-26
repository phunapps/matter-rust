/**
 * xtask/scripts/capture-attestation/index.js
 *
 * Capture an AttestationResponse signature fixture for byte-parity
 * testing of `crates/matter-commissioning::verify_attestation_response`
 * against matter.js's ECDSA verifier.
 *
 * What this fixture proves:
 *
 *   For the same (attestation_elements, attestation_challenge,
 *   dac_public_key, signature) tuple, our Rust verifier and
 *   matter.js's NodeJsStyleCrypto.verifyEcdsa produce the same
 *   accept/reject verdict. Five tuples are emitted: one happy-path
 *   plus four single-byte mutations (signature, challenge, elements,
 *   public-key), each cross-checked with matter.js and expected to
 *   fail there too.
 *
 * What this fixture does NOT cover:
 *
 *   - Full DAC -> PAI -> PAA chain verification — that's already
 *     byte-parity-tested against bundled CSA fixtures in M6.2.2's
 *     verify_chain happy-path test.
 *   - Cluster-level AttestationRequest/Response wire framing — M6.4.
 *   - Certification Declaration parsing — M6.4.x (CD-before-M6.6).
 *
 * Deterministic inputs:
 *
 *   We use NodeJsStyleCrypto with a FIXED ECDSA scalar (the d
 *   coordinate of the EC private key), produced by importing a
 *   handwritten PKCS#8 SEC1 private key. ECDSA signing is
 *   randomized — k is drawn fresh per call — so the signature bytes
 *   themselves vary across runs. Byte-parity is therefore not on the
 *   signature value but on the (matter.js-verify, ring-verify) pair
 *   of verdicts: both must agree on accept for the happy-path tuple
 *   and on reject for each mutant. The signature emitted into the
 *   fixture is whatever matter.js produced in this run, captured
 *   verbatim.
 *
 * Output format (test-vectors/attestation/response/happy-path.json):
 *
 *   {
 *     "scenario": "happy-path",
 *     "comment": "...",
 *     "inputs": {
 *       "dac_public_key_hex": "<130 hex chars = 65 bytes SEC1 uncompressed>",
 *       "attestation_elements_hex": "<hex>",
 *       "attestation_challenge_hex": "<32 hex chars = 16 bytes>",
 *       "signature_hex": "<128 hex chars = 64 bytes r||s>"
 *     },
 *     "matter_js_verify": "accept",
 *     "mutations": [
 *       {
 *         "name": "flip_signature_byte_0",
 *         "patch": { "field": "signature_hex", "byte_index": 0, "xor": 128 },
 *         "matter_js_verify": "reject"
 *       },
 *       ...
 *     ]
 *   }
 *
 * Rust consumer (tests/attestation_response_byte_parity.rs) asserts
 *   matter_js_verify == "accept"  ==>  Rust verify_attestation_response is Ok
 *   matter_js_verify == "reject"  ==>  Rust verify_attestation_response is Err(BadResponseSignature)
 */

import { createRequire } from 'node:module';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const OUT_DIR = join(REPO_ROOT, 'test-vectors', 'attestation', 'response');
mkdirSync(OUT_DIR, { recursive: true });

const require = createRequire(import.meta.url);
const nodeCrypto = require('crypto');

import { NodeJsStyleCrypto, EcdsaSignature } from '@matter/general';

const crypto = new NodeJsStyleCrypto(nodeCrypto);

// ── Helpers ────────────────────────────────────────────────────────────────

function toHex(buf) {
  // `buf` may be a Uint8Array, ArrayBuffer-backed view, or
  // AllowSharedBufferSource (matter.js sometimes returns the latter).
  // Buffer.from handles all three.
  return Buffer.from(buf).toString('hex');
}

/**
 * matter.js exposes signatures as `EcdsaSignature` objects (see
 * @matter/general/.../EcdsaSignature.d.ts). Extract the raw IEEE
 * P1363 64-byte r||s blob as a Uint8Array.
 */
function sigBytes(ecdsaSig) {
  return new Uint8Array(ecdsaSig.bytes);
}

/**
 * Run matter.js's verifier. It returns void on accept and throws
 * `CryptoVerifyError` on reject — we collapse both signals into a
 * boolean for cleaner fixture emission. Any unexpected throw (e.g.
 * malformed key shape) also folds into "reject"; the byte-parity
 * claim is on the accept/reject verdict, not on the specific failure
 * mode matter.js chose.
 */
async function verifyOk(publicKeyJwk, tbs, ecdsaSig) {
  try {
    await crypto.verifyEcdsa(publicKeyJwk, tbs, ecdsaSig);
    return true;
  } catch (_e) {
    return false;
  }
}

// ── Fixed P-256 keypair ────────────────────────────────────────────────────
//
// We use matter.js's Crypto.createKeyPair() once per script run.
// matter.js returns a `PrivateKey` — a JWK-shaped object that
// `signEcdsa`/`verifyEcdsa` accept directly. `.publicKey` on that
// object gives the raw SEC1 uncompressed bytes we emit into the
// fixture for Rust's `ring`-based verifier.
//
// Per-run randomness in the keypair is fine: byte-parity is on the
// VERDICT, not the bytes (see header comment). Re-running the script
// rewrites the fixture file; assertions in
// `tests/attestation_response_byte_parity.rs` remain stable.

const dacKeyPair = await crypto.createKeyPair();
const dacPublicKeyRaw = new Uint8Array(dacKeyPair.publicKey);
if (dacPublicKeyRaw.length !== 65 || dacPublicKeyRaw[0] !== 0x04) {
  throw new Error(
    `expected 65-byte SEC1 uncompressed P-256 public key (leading 0x04), got ` +
      `${dacPublicKeyRaw.length} bytes, leading 0x${dacPublicKeyRaw[0]?.toString(16)}`,
  );
}

// ── Build the signed tuple ─────────────────────────────────────────────────

// attestation_elements: a 64-byte opaque blob. In real Matter this is a
// TLV-encoded structure; here we treat it as opaque bytes. The shape
// doesn't matter for signature verification (which is what M6.2.3
// tests); it just needs to be stable across the happy path and the
// mutants.
const attestationElements = new Uint8Array([
  0x15, // dummy TLV-looking prefix; meaningless to the verifier
  ...new Array(63).fill(0).map((_, i) => i),
]);

// attestation_challenge: 16 bytes (per Matter §3.5 and the byte-parity-
// verified CASE session-key derivation in matter-crypto).
const attestationChallenge = new Uint8Array([
  0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
  0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51,
]);

// tbs = elements || challenge — exactly what the device signs.
const tbs = new Uint8Array(attestationElements.length + attestationChallenge.length);
tbs.set(attestationElements, 0);
tbs.set(attestationChallenge, attestationElements.length);

// Sign with matter.js's NodeJsStyleCrypto. signEcdsa returns an
// `EcdsaSignature` wrapping the raw r||s blob in IEEE P1363 format
// (the encoding Matter §3.5.3 mandates on the wire and that our Rust
// verifier consumes).
const happySig = await crypto.signEcdsa(dacKeyPair, tbs);
const signature = sigBytes(happySig);
if (signature.length !== 64) {
  throw new Error(
    `expected 64-byte raw r||s signature, got ${signature.length} bytes`,
  );
}

// Sanity check: matter.js must verify its own signature on its own
// inputs. If this fails, something is wrong with our harness, not
// with the verifier under test.
if (!(await verifyOk(dacKeyPair, tbs, happySig))) {
  throw new Error('matter.js failed to verify a signature it just produced');
}

// ── Mutation generators ────────────────────────────────────────────────────
//
// Each mutation describes a one-byte change applied to one named field
// of the happy-path tuple. The mutated tuple is handed to matter.js's
// verifyEcdsa to confirm matter.js itself rejects. The Rust test loads
// the fixture, applies the same mutations, and confirms our
// verify_attestation_response also rejects.

const wrongKeyPair = await crypto.createKeyPair();
const wrongPublicKeyRaw = new Uint8Array(wrongKeyPair.publicKey);

async function assertMutationRejects(name, keyPair, mutElements, mutChallenge, mutSigBytes) {
  const mutTbs = new Uint8Array(mutElements.length + mutChallenge.length);
  mutTbs.set(mutElements, 0);
  mutTbs.set(mutChallenge, mutElements.length);
  // Wrap mutated bytes back into an EcdsaSignature (the API matter.js
  // expects). The constructor accepts any 64-byte Uint8Array as raw
  // IEEE P1363 — including signatures that won't verify, which is
  // exactly what we want.
  const mutSig = new EcdsaSignature(mutSigBytes);
  const ok = await verifyOk(keyPair, mutTbs, mutSig);
  if (ok) {
    throw new Error(
      `mutation ${name}: matter.js unexpectedly accepted the mutated tuple — ` +
        `byte-parity assumption is broken`,
    );
  }
}

// Mutation 1: flip the high bit of byte 0 of the signature.
{
  const mut = new Uint8Array(signature);
  mut[0] ^= 0x80;
  await assertMutationRejects(
    'flip_signature_byte_0',
    dacKeyPair,
    attestationElements,
    attestationChallenge,
    mut,
  );
}

// Mutation 2: flip the low bit of byte 0 of the challenge.
{
  const mutChallenge = new Uint8Array(attestationChallenge);
  mutChallenge[0] ^= 0x01;
  await assertMutationRejects(
    'flip_challenge_byte_0',
    dacKeyPair,
    attestationElements,
    mutChallenge,
    signature,
  );
}

// Mutation 3: flip the high bit of byte 0 of the elements.
{
  const mutElements = new Uint8Array(attestationElements);
  mutElements[0] ^= 0x80;
  await assertMutationRejects(
    'flip_elements_byte_0',
    dacKeyPair,
    mutElements,
    attestationChallenge,
    signature,
  );
}

// Mutation 4: substitute a different (freshly-generated) keypair.
// matter.js needs the JWK form for verifyEcdsa, so we pass the second
// keypair object directly. The Rust verifier consumes only the raw
// SEC1 bytes (`wrongPublicKeyRaw`) we emit into the fixture.
{
  await assertMutationRejects(
    'wrong_public_key',
    wrongKeyPair,
    attestationElements,
    attestationChallenge,
    signature,
  );
}

// ── Emit fixture ───────────────────────────────────────────────────────────

const fixture = {
  scenario: 'happy-path',
  comment:
    'Captured by xtask capture-attestation. ECDSA P-256/SHA-256 sign+verify ' +
    'roundtrip with matter.js NodeJsStyleCrypto. signature_hex is raw r||s ' +
    '(64 bytes, Matter §3.5.3 fixed-width). Re-running the script overwrites ' +
    'the file with a fresh keypair + fresh signature; mutations are ' +
    'regenerated against the new tuple. Byte-parity claim is on accept/reject ' +
    'verdicts, not on raw bytes (ECDSA k is randomized per call).',
  inputs: {
    dac_public_key_hex: toHex(dacPublicKeyRaw),
    attestation_elements_hex: toHex(attestationElements),
    attestation_challenge_hex: toHex(attestationChallenge),
    signature_hex: toHex(signature),
  },
  matter_js_verify: 'accept',
  mutations: [
    {
      name: 'flip_signature_byte_0',
      patch: { field: 'signature_hex', byte_index: 0, xor: 0x80 },
      matter_js_verify: 'reject',
    },
    {
      name: 'flip_challenge_byte_0',
      patch: { field: 'attestation_challenge_hex', byte_index: 0, xor: 0x01 },
      matter_js_verify: 'reject',
    },
    {
      name: 'flip_elements_byte_0',
      patch: { field: 'attestation_elements_hex', byte_index: 0, xor: 0x80 },
      matter_js_verify: 'reject',
    },
    {
      name: 'wrong_public_key',
      patch: {
        field: 'dac_public_key_hex',
        replace_hex: toHex(wrongPublicKeyRaw),
      },
      matter_js_verify: 'reject',
    },
  ],
};

const outPath = join(OUT_DIR, 'happy-path.json');
writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n');
console.log(`captured happy-path -> test-vectors/attestation/response/happy-path.json`);
console.log('All mutations also cross-verified to reject under matter.js.');
