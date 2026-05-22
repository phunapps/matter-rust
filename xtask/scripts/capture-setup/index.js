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
// `@matter/types` (NOT `@matter/protocol` — verified by enumerating the
// installed package's exports):
//
//   QrPairingCodeCodec.encode(payloads)       → "MT:..." string
//   QrPairingCodeCodec.decode(qrString)       → QrCodeData[]
//   ManualPairingCodeCodec.encode(payload)    → 11- or 21-digit string
//   ManualPairingCodeCodec.decode(s)          → ManualPairingData
//
// QR codec input is an ARRAY of QrCodeData (it supports multi-payload
// concatenation separated by '*'). Each entry is:
//
//   {
//     version: number,                 // 0..7
//     vendorId: number,                // 16-bit
//     productId: number,               // 16-bit
//     flowType: 0 | 1 | 2,             // Standard | UserIntent | Custom
//     discoveryCapabilities: number,   // 8-bit RAW bitmap (NOT object)
//     discriminator: number,           // 12-bit
//     passcode: number,                // 27-bit
//     // optional tlvData?: Bytes — we do not use it
//   }
//
// `discoveryCapabilities` is fed to a `BitField(37, 8)` in
// QrCodeDataSchema — i.e. an opaque 8-bit integer. Matter-rust's
// `DiscoveryCapabilities` bitflags (SOFT_AP=bit0, BLE=bit1,
// ON_NETWORK=bit2) define the wire layout; we compute that bitmap
// here and pass the resulting integer.
//
// Manual codec input is a single object:
//
//   {
//     discriminator: number,           // 12-bit
//     passcode: number,                // 27-bit
//     vendorId?: number,               // present iff long form
//     productId?: number,              // present iff long form
//   }
//
// The codec emits the 21-digit (long) form iff BOTH vendorId AND
// productId are defined; otherwise the 11-digit (short) form. It
// ignores flowType and discoveryCapabilities entirely.

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { QrPairingCodeCodec, ManualPairingCodeCodec } from '@matter/types';

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

// matter-rust `DiscoveryCapabilities` bitflag layout — this is the byte
// that gets stored in the QR payload's 8-bit `discoveryCapabilities` field.
// Keep in sync with `crates/matter-commissioning/src/setup/mod.rs`.
const DISCOVERY_BIT = {
    SoftAp: 1 << 0,
    Ble: 1 << 1,
    OnNetwork: 1 << 2,
};

function discoveryBitmap(caps) {
    let v = 0;
    for (const c of caps ?? []) {
        if (!(c in DISCOVERY_BIT)) {
            throw new Error(`unknown discovery capability: ${c}`);
        }
        v |= DISCOVERY_BIT[c];
    }
    return v;
}

function toQrPayload(input) {
    return {
        version: input.version,
        vendorId: input.vendor_id ?? 0,
        productId: input.product_id ?? 0,
        flowType: FLOW[input.commissioning_flow],
        discriminator: input.discriminator,
        discoveryCapabilities: discoveryBitmap(input.discovery_capabilities),
        passcode: input.passcode,
    };
}

function toManualPayload(input) {
    const has_vid_pid = input.vendor_id != null && input.product_id != null;
    const payload = {
        discriminator: input.discriminator,
        passcode: input.passcode,
    };
    if (has_vid_pid) {
        payload.vendorId = input.vendor_id;
        payload.productId = input.product_id;
    }
    return payload;
}

// ---------------------------------------------------------------------------
// Drive matter.js and write the JSON files
// ---------------------------------------------------------------------------

for (const scenario of qrScenarios) {
    const mjs = toQrPayload(scenario.input);
    // QR codec encodes an ARRAY of payloads; we always pass a singleton.
    const expected_qr = QrPairingCodeCodec.encode([mjs]);
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
    const mjs = toManualPayload(scenario.input);
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
