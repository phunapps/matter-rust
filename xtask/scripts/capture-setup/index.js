// xtask/scripts/capture-setup/index.js
//
// Drive matter.js's QrPairingCodeCodec and ManualPairingCodeCodec
// over a fixed set of SetupPayload values. Output JSON fixtures
// consumed by crates/matter-commissioning/tests/setup_byte_parity.rs.
//
// =====================================================================
// MATTER.JS ENTRY POINTS
// =====================================================================
//
// `@matter/protocol`:
//
//   QrPairingCodeCodec.encode(payload)  → string starting with "MT:"
//   QrPairingCodeCodec.decode(qrString) → payload
//
//   ManualPairingCodeCodec.encode(payload)  → 11- or 21-digit string
//   ManualPairingCodeCodec.decode(s)        → payload
//
// matter.js's "payload" object shape (see node_modules/@matter/protocol/
// dist/esm/codec/QrCodeCodec.js for the canonical interface):
//
//   {
//     version: number,                 // 0
//     vendorId: number,                // 16-bit
//     productId: number,               // 16-bit
//     flowType: 0 | 1 | 2,
//     discriminator: number,           // 12-bit
//     discoveryCapabilities: { ble?: boolean, softAccessPoint?: boolean,
//                              onIpNetwork?: boolean },
//     passcode: number,                // 27-bit
//   }
//
// Verify these names against the installed matter.js. If matter.js
// disagrees, the Rust integration test in Task 22 will detect mismatches
// — fix names here, not in Rust.

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Both codecs live in @matter/protocol/dist/esm/codec/ — names verified
// at install time. If the import below fails, run
// `node -e "console.log(Object.keys(await import('@matter/protocol')))"`
// inside this directory to enumerate exports.
import { QrPairingCodeCodec, ManualPairingCodeCodec } from '@matter/protocol';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const OUT_DIR = join(REPO_ROOT, 'test-vectors', 'commissioning', 'setup');

mkdirSync(OUT_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// QR-form scenarios
// ---------------------------------------------------------------------------
//
// Each scenario carries inputs in matter-rust's `SetupPayload` shape (which
// is convenient for the Rust test) and lets the bridge translate to
// matter.js's shape inline.
//
const qrScenarios = [
    {
        id: 'qr-spec-example',
        intent: 'Matter Core Spec §5.1.3.1 worked example',
        input: {
            version: 0,
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            commissioning_flow: 'Standard',
            discovery_capabilities: ['OnNetwork'],
            discriminator: 0xF00,
            passcode: 20_202_021,
        },
    },
    {
        id: 'qr-minimal',
        intent: 'Standard flow, on-network discovery, mid-range fields',
        input: {
            version: 0,
            vendor_id: 0xFFF2,
            product_id: 0x0042,
            commissioning_flow: 'Standard',
            discovery_capabilities: ['OnNetwork'],
            discriminator: 0x500,
            passcode: 16_777_217,
        },
    },
    {
        id: 'qr-all-discovery',
        intent: 'All three discovery bits set',
        input: {
            version: 0,
            vendor_id: 0xFFF3,
            product_id: 0x0100,
            commissioning_flow: 'Standard',
            discovery_capabilities: ['SoftAp', 'Ble', 'OnNetwork'],
            discriminator: 0x123,
            passcode: 50_005_000,
        },
    },
    {
        id: 'qr-user-intent',
        intent: 'UserIntent commissioning flow',
        input: {
            version: 0,
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            commissioning_flow: 'UserIntent',
            discovery_capabilities: ['Ble', 'OnNetwork'],
            discriminator: 0xABC,
            passcode: 33_333_334,
        },
    },
    {
        id: 'qr-high-vid-pid',
        intent: 'VID/PID near the 16-bit ceiling',
        input: {
            version: 0,
            vendor_id: 0xFFF4,
            product_id: 0xFFFF,
            commissioning_flow: 'Standard',
            discovery_capabilities: ['OnNetwork'],
            discriminator: 0x789,
            passcode: 70_707_070,
        },
    },
    {
        id: 'qr-edge-discriminator-0',
        intent: 'discriminator = 0',
        input: {
            version: 0,
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            commissioning_flow: 'Standard',
            discovery_capabilities: ['OnNetwork'],
            discriminator: 0x000,
            passcode: 20_202_021,
        },
    },
    {
        id: 'qr-edge-discriminator-fff',
        intent: 'discriminator = 0xFFF (max 12-bit)',
        input: {
            version: 0,
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            commissioning_flow: 'Standard',
            discovery_capabilities: ['OnNetwork'],
            discriminator: 0xFFF,
            passcode: 20_202_021,
        },
    },
    {
        id: 'qr-edge-passcode-min',
        intent: 'smallest allowed passcode (1)',
        input: {
            version: 0,
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            commissioning_flow: 'Standard',
            discovery_capabilities: ['OnNetwork'],
            discriminator: 0x100,
            passcode: 1,
        },
    },
    {
        id: 'qr-edge-passcode-max',
        intent: 'largest 27-bit passcode that is not on the disallowed list',
        input: {
            version: 0,
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            commissioning_flow: 'Standard',
            discovery_capabilities: ['OnNetwork'],
            discriminator: 0x200,
            // 2^27 - 2 = 134_217_726
            passcode: 134_217_726,
        },
    },
];

// ---------------------------------------------------------------------------
// Manual-form scenarios — 11-digit (no VID/PID) and 21-digit (with).
// ---------------------------------------------------------------------------

const manualScenarios = [
    {
        id: 'manual-11-minimal',
        intent: '11-digit form, mid-range short discriminator, test passcode',
        input: {
            version: 0,
            vendor_id: null,
            product_id: null,
            commissioning_flow: 'Standard',
            discovery_capabilities: [],
            // Short = 0x05 → long = 0x500
            discriminator: 0x500,
            passcode: 20_202_021,
        },
    },
    {
        id: 'manual-11-mid',
        intent: '11-digit form, another value',
        input: {
            version: 0,
            vendor_id: null,
            product_id: null,
            commissioning_flow: 'Standard',
            discovery_capabilities: [],
            discriminator: 0xA00,
            passcode: 12_345_679, // not on disallowed list
        },
    },
    {
        id: 'manual-21-with-vidpid',
        intent: '21-digit form, with VID/PID',
        input: {
            version: 0,
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            commissioning_flow: 'Standard',
            discovery_capabilities: [],
            discriminator: 0xF00,
            passcode: 20_202_021,
        },
    },
    {
        id: 'manual-21-edges',
        intent: 'short=0xF, passcode near max, VID/PID near max',
        input: {
            version: 0,
            vendor_id: 0xFFF4,
            product_id: 0xFFFF,
            commissioning_flow: 'Standard',
            discovery_capabilities: [],
            discriminator: 0xF00,
            passcode: 134_217_726,
        },
    },
];

// ---------------------------------------------------------------------------
// Translation: matter-rust shape → matter.js shape
// ---------------------------------------------------------------------------

const FLOW = { Standard: 0, UserIntent: 1, Custom: 2 };

function toMatterJsPayload(input) {
    const cap = new Set(input.discovery_capabilities ?? []);
    return {
        version: input.version,
        vendorId: input.vendor_id ?? 0,
        productId: input.product_id ?? 0,
        flowType: FLOW[input.commissioning_flow],
        discriminator: input.discriminator,
        discoveryCapabilities: {
            ble: cap.has('Ble'),
            softAccessPoint: cap.has('SoftAp'),
            onIpNetwork: cap.has('OnNetwork'),
        },
        passcode: input.passcode,
    };
}

// ---------------------------------------------------------------------------
// Drive matter.js and write the JSON files
// ---------------------------------------------------------------------------

for (const scenario of qrScenarios) {
    const mjs = toMatterJsPayload(scenario.input);
    const expected_qr = QrPairingCodeCodec.encode(mjs);
    const fixture = {
        intent: scenario.intent,
        input: scenario.input,
        expected: { qr: expected_qr },
    };
    const outPath = join(OUT_DIR, `${scenario.id}.json`);
    writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n');
    console.log(`wrote ${outPath}: ${expected_qr}`);
}

for (const scenario of manualScenarios) {
    const mjs = toMatterJsPayload(scenario.input);
    const expected_manual = ManualPairingCodeCodec.encode(mjs);
    const fixture = {
        intent: scenario.intent,
        input: scenario.input,
        expected: { manual: expected_manual },
    };
    const outPath = join(OUT_DIR, `${scenario.id}.json`);
    writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n');
    console.log(`wrote ${outPath}: ${expected_manual}`);
}

console.log('\nDone. Inspect test-vectors/commissioning/setup/ before committing.');
