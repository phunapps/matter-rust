// xtask/scripts/capture-case/index.js
//
// Drive matter.js's CASE primitives with FIXED scalars and capture
// every wire message as JSON fixtures consumed by
// crates/matter-crypto/tests/case_byte_parity.rs.
//
// M4.3 Task 1 ships this scaffold. Task 3 fleshes out setUpTestFabric()
// and captureHandshake() with the actual matter.js call surface
// (CaseClient / CaseServer or the lower-level math primitives) and
// runs the script to commit the captured fixtures.

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Crypto } from '@matter/general';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const OUT_DIR = join(REPO_ROOT, 'test-vectors', 'case');
mkdirSync(OUT_DIR, { recursive: true });

// === Fixed-RNG monkey-patch on Crypto.randomBytes ===
//
// Same approach as capture-pase: override the instance-level
// randomBytes on the Crypto singleton to yield fixed bytes in the
// exact order matter.js consumes them during a CASE handshake.

class FixedRng {
    constructor(chunksHex) {
        this.queue = chunksHex.map((h) => Buffer.from(h, 'hex'));
        this.idx = 0;
    }
    next(len) {
        if (this.idx >= this.queue.length) {
            throw new Error(`FixedRng exhausted at request for ${len} bytes`);
        }
        const buf = this.queue[this.idx++];
        if (buf.length !== len) {
            throw new Error(
                `FixedRng: queued ${buf.length} bytes but got request for ${len} bytes ` +
                `(index ${this.idx - 1})`
            );
        }
        return buf;
    }
}

function patchRng(rng) {
    const real = Crypto.get();
    const patched = Object.create(real);
    patched.randomBytes = (len) => rng.next(len);
    Crypto.get = () => patched;
}

// === Test fabric setup (filled in by M4.3 Task 3) ===
//
// matter.js exposes a CertificateAuthority helper (used in capture-cert)
// that generates RCAC + NOCs. Reuse it here. Task 3 wires this to the
// exact API surface.
function setUpTestFabric() {
    throw new Error(
        'TODO(M4.3 Task 3): wire setUpTestFabric to matter.js. ' +
        'Expected return shape: { rcacCert, rcacPublicKey, ipk, ' +
        'initiatorNoc, initiatorPkcs8, responderNoc, responderPkcs8 }.'
    );
}

// === Drive a single handshake scenario ===
//
// Task 3 fills in the matter.js calls. The general shape:
//   1. Set up the test fabric (above).
//   2. Patch the RNG with the scenario's fixed scalars.
//   3. Construct CaseClient (initiator) + CaseServer (responder), or
//      drive the lower-level CASE math primitives directly.
//   4. Capture each wire-format message's TLV bytes as hex.
async function captureHandshake(scenario) {
    const fabric = setUpTestFabric();
    const rng = new FixedRng(scenario.scalars_hex_in_order);
    patchRng(rng);

    const messages = {};
    // messages.sigma1 = ...
    // messages.sigma2 = ... or messages.sigma2_resume = ...
    // messages.sigma3 = ...   (skipped for resumption-accepted path)

    return {
        inputs: {
            ...scenario.inputs,
            // Include the fabric bytes so the Rust tests can reconstruct
            // CaseCredentials without re-deriving them.
            fabric_id: fabric.fabricId,
            initiator_node_id: fabric.initiatorNodeId,
            responder_node_id: fabric.responderNodeId,
            ipk: fabric.ipk.toString('hex'),
            rcac_public_key: fabric.rcacPublicKey.toString('hex'),
            initiator_noc: fabric.initiatorNoc.toString('hex'),
            initiator_pkcs8: fabric.initiatorPkcs8.toString('hex'),
            responder_noc: fabric.responderNoc.toString('hex'),
            responder_pkcs8: fabric.responderPkcs8.toString('hex'),
        },
        messages,
    };
}

// === Scenarios ===

const scenarios = [
    {
        id: 'handshake-new-session',
        inputs: {
            // Fabric/identity fields populated by setUpTestFabric().
            // Per-scenario knobs go here.
        },
        scalars_hex_in_order: [
            // Order to be confirmed in M4.3 Task 3 against matter.js source.
            // Best-guess sequence based on M4.1's CASE flow:
            //   1. initiator_random (32 bytes)
            //   2. initiator ephemeral private key (32 bytes)
            //   3. responder_random (32 bytes)
            //   4. responder ephemeral private key (32 bytes)
            'aa'.repeat(32),
            'bb'.repeat(32),
            'cc'.repeat(32),
            'dd'.repeat(32),
        ],
    },
    {
        id: 'handshake-resumption-accepted',
        inputs: {
            // resumption_record fields here (id + shared_secret) — Task 3
            // generates these by running a prior handshake or synthesises.
        },
        scalars_hex_in_order: [
            // For accepted resumption, matter.js skips ephemeral keypairs:
            //   1. initiator_random (32 bytes)
            //   2. responder_random (32 bytes)
            //   3. responder's new resumption_id (16 bytes)
            'aa'.repeat(32),
            'cc'.repeat(32),
            '11'.repeat(16),
        ],
    },
    {
        id: 'handshake-resumption-declined',
        inputs: {
            // Bogus resumption_id presented by initiator; responder's
            // store has no matching record, falls back to new-session.
        },
        scalars_hex_in_order: [
            // Same scalar sequence as new-session (ephemerals consumed
            // when responder declines and runs the full path):
            'aa'.repeat(32),
            'bb'.repeat(32),
            'cc'.repeat(32),
            'dd'.repeat(32),
        ],
    },
];

for (const scenario of scenarios) {
    try {
        const out = await captureHandshake(scenario);
        const outPath = join(OUT_DIR, `${scenario.id}.json`);
        writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
        console.log(`captured ${scenario.id} -> ${outPath}`);
    } catch (err) {
        console.error(`failed ${scenario.id}: ${err.message}`);
        process.exitCode = 1;
    }
}
