// xtask/scripts/capture-im/index.js
//
// Drive matter.js's Interaction Model TLV schemas with FIXED inputs and
// emit JSON byte-parity fixtures consumed by
// crates/matter-interaction/tests/im_byte_parity.rs.
//
// Fixture conventions (must match the Rust test structs):
//   invoke/*.json : { endpoint, cluster, command, command_fields_b64,
//                     expected_message_b64 }
//   read/*.json   : { paths: [{endpoint, cluster, attribute}],
//                     expected_message_b64 }
//   write/*.json  : { writes: [{endpoint, cluster, attribute,
//                     value_tlv_b64}], expected_message_b64 }
//   write/*_response.json : { response_message_b64,
//                     expected: [{endpoint, cluster, attribute, status}] }
//
// All byte fields are base64. IM revision is whatever matter.js 0.16.11
// emits (Rust side pins IM_REVISION = 11; a mismatch fails parity, which
// is the point).

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { TlvString, TlvUInt16, TlvUInt64, TlvObject, TlvField } from '@matter/types';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const OUT_ROOT = join(REPO_ROOT, 'test-vectors', 'commissioning', 'im');

// ---------------------------------------------------------------------
// Resolve the IM message schemas across 0.16.x packaging variants.
// ---------------------------------------------------------------------
async function loadImSchemas() {
    const candidates = ['@matter/types/interaction', '@matter/types', '@matter/protocol'];
    for (const mod of candidates) {
        try {
            const m = await import(mod);
            if (m.TlvInvokeRequest && m.TlvReadRequest && m.TlvWriteRequest && m.TlvWriteResponse) {
                console.log(`IM TLV schemas resolved from ${mod}`);
                return m;
            }
        } catch {
            // try next candidate
        }
    }
    throw new Error(
        'TlvInvokeRequest/TlvReadRequest/TlvWriteRequest/TlvWriteResponse not found in ' +
        candidates.join(', ') + ' — inspect node_modules/@matter/types exports and update candidates.'
    );
}

const {
    TlvInvokeRequest,
    TlvReadRequest,
    TlvWriteRequest,
    TlvWriteResponse,
    TlvSubscribeRequest,
    TlvSubscribeResponse,
    TlvStatusResponse,
    TlvDataReport,
    TlvBoolean,
} = await loadImSchemas();

// encodeTlv (TlvStream form, for TlvAny fields) must exist on schemas.
if (typeof TlvString.encodeTlv !== 'function') {
    throw new Error('TlvSchema.encodeTlv missing — matter.js packaging changed; fixture capture needs the TlvStream API.');
}

const b64 = (bytes) => Buffer.from(bytes).toString('base64');

function writeFixture(subdir, name, obj) {
    const dir = join(OUT_ROOT, subdir);
    mkdirSync(dir, { recursive: true });
    const path = join(dir, name);
    writeFileSync(path, JSON.stringify(obj, null, 2) + '\n');
    console.log(`wrote ${path}`);
}

// ---------------------------------------------------------------------
// INVOKE fixtures
// ---------------------------------------------------------------------

// ArmFailSafe (GeneralCommissioning 0x30, command 0x00):
// fields { 0: expiryLengthSeconds u16, 1: breadcrumb u64 } per spec §11.10.
// Built with generic combinators so this script has no cluster deps; the
// hand-written Rust encoder for the same payload is already parity-tested
// elsewhere — here the envelope (TlvInvokeRequest) is the oracle.
const TlvArmFailSafeFields = TlvObject({
    expiryLengthSeconds: TlvField(0, TlvUInt16),
    breadcrumb: TlvField(1, TlvUInt64),
});
const armFailSafeFields = { expiryLengthSeconds: 60, breadcrumb: 0 };

writeFixture('invoke', 'arm_fail_safe.json', {
    endpoint: 0,
    cluster: 0x30,
    command: 0x00,
    command_fields_b64: b64(TlvArmFailSafeFields.encode(armFailSafeFields)),
    expected_message_b64: b64(TlvInvokeRequest.encode({
        suppressResponse: false,
        timedRequest: false,
        invokeRequests: [{
            commandPath: { endpointId: 0, clusterId: 0x30, commandId: 0x00 },
            commandFields: TlvArmFailSafeFields.encodeTlv(armFailSafeFields),
        }],
        interactionModelRevision: 11,
    })),
});

// CommissioningComplete (0x30, command 0x04): NO fields. Captures what
// matter.js emits for an empty commandFields struct — if it omits the
// member entirely while our builder embeds an empty struct, parity FAILS
// and that divergence must be surfaced, not patched silently.
const TlvNoFields = TlvObject({});

writeFixture('invoke', 'commissioning_complete.json', {
    endpoint: 0,
    cluster: 0x30,
    command: 0x04,
    command_fields_b64: b64(TlvNoFields.encode({})),
    expected_message_b64: b64(TlvInvokeRequest.encode({
        suppressResponse: false,
        timedRequest: false,
        invokeRequests: [{
            commandPath: { endpointId: 0, clusterId: 0x30, commandId: 0x04 },
            commandFields: TlvNoFields.encodeTlv({}),
        }],
        interactionModelRevision: 11,
    })),
});

// OnOff Toggle (0x06, command 0x02) on endpoint 1 — the M7.5 control path.
writeFixture('invoke', 'on_off_toggle.json', {
    endpoint: 1,
    cluster: 0x06,
    command: 0x02,
    command_fields_b64: b64(TlvNoFields.encode({})),
    expected_message_b64: b64(TlvInvokeRequest.encode({
        suppressResponse: false,
        timedRequest: false,
        invokeRequests: [{
            commandPath: { endpointId: 1, clusterId: 0x06, commandId: 0x02 },
            commandFields: TlvNoFields.encodeTlv({}),
        }],
        interactionModelRevision: 11,
    })),
});

// ---------------------------------------------------------------------
// READ fixtures
// ---------------------------------------------------------------------

writeFixture('read', 'basic_information_names.json', {
    paths: [
        { endpoint: 0, cluster: 0x28, attribute: 0x01 }, // VendorName
        { endpoint: 0, cluster: 0x28, attribute: 0x03 }, // ProductName
    ],
    expected_message_b64: b64(TlvReadRequest.encode({
        attributeRequests: [
            { endpointId: 0, clusterId: 0x28, attributeId: 0x01 },
            { endpointId: 0, clusterId: 0x28, attributeId: 0x03 },
        ],
        isFabricFiltered: false,
        interactionModelRevision: 11,
    })),
});

writeFixture('read', 'network_commissioning_feature_map.json', {
    paths: [{ endpoint: 0, cluster: 0x31, attribute: 0xFFFC }],
    expected_message_b64: b64(TlvReadRequest.encode({
        attributeRequests: [
            { endpointId: 0, clusterId: 0x31, attributeId: 0xFFFC },
        ],
        isFabricFiltered: false,
        interactionModelRevision: 11,
    })),
});

// Wildcard: ALL attributes of OnOff (0x06) on endpoint 1 (attributeId omitted).
writeFixture('read', 'onoff_wildcard_attributes.json', {
    paths: [{ endpoint: 1, cluster: 0x06 }],
    expected_message_b64: b64(TlvReadRequest.encode({
        attributeRequests: [
            { endpointId: 1, clusterId: 0x06 },
        ],
        isFabricFiltered: false,
        interactionModelRevision: 11,
    })),
});

// Wildcard: BasicInformation.NodeLabel (0x28 / 0x05) across ALL endpoints
// (endpointId omitted).
writeFixture('read', 'endpoint_wildcard_basic_info.json', {
    paths: [{ cluster: 0x28, attribute: 0x05 }],
    expected_message_b64: b64(TlvReadRequest.encode({
        attributeRequests: [
            { clusterId: 0x28, attributeId: 0x05 },
        ],
        isFabricFiltered: false,
        interactionModelRevision: 11,
    })),
});

// ---------------------------------------------------------------------
// WRITE fixtures (gate matter-interaction::write — Task 6)
// ---------------------------------------------------------------------

// Single write: BasicInformation.NodeLabel (0x28 / 0x05, string) — the
// exact write the M7.5 device validation performs.
const nodeLabel = 'matter-rust';
writeFixture('write', 'node_label.json', {
    writes: [{
        endpoint: 0,
        cluster: 0x28,
        attribute: 0x05,
        value_tlv_b64: b64(TlvString.encode(nodeLabel)),
    }],
    expected_message_b64: b64(TlvWriteRequest.encode({
        suppressResponse: false,
        timedRequest: false,
        writeRequests: [{
            path: { endpointId: 0, clusterId: 0x28, attributeId: 0x05 },
            data: TlvString.encodeTlv(nodeLabel),
        }],
        interactionModelRevision: 11,
    })),
});

// Batch write: two attributes in one message (NodeLabel + Location).
const location = 'XX';
writeFixture('write', 'node_label_and_location.json', {
    writes: [
        {
            endpoint: 0,
            cluster: 0x28,
            attribute: 0x05,
            value_tlv_b64: b64(TlvString.encode(nodeLabel)),
        },
        {
            endpoint: 0,
            cluster: 0x28,
            attribute: 0x06,
            value_tlv_b64: b64(TlvString.encode(location)),
        },
    ],
    expected_message_b64: b64(TlvWriteRequest.encode({
        suppressResponse: false,
        timedRequest: false,
        writeRequests: [
            {
                path: { endpointId: 0, clusterId: 0x28, attributeId: 0x05 },
                data: TlvString.encodeTlv(nodeLabel),
            },
            {
                path: { endpointId: 0, clusterId: 0x28, attributeId: 0x06 },
                data: TlvString.encodeTlv(location),
            },
        ],
        interactionModelRevision: 11,
    })),
});

// WriteResponse parse fixture: success for NodeLabel.
writeFixture('write', 'node_label_response.json', {
    response_message_b64: b64(TlvWriteResponse.encode({
        writeResponses: [{
            path: { endpointId: 0, clusterId: 0x28, attributeId: 0x05 },
            status: { status: 0 },
        }],
        interactionModelRevision: 11,
    })),
    expected: [{ endpoint: 0, cluster: 0x28, attribute: 0x05, status: 0 }],
});

// WriteResponse parse fixture: one success + one failure. The non-zero
// code choice (0x01 FAILURE) is arbitrary; the parser preserves raw codes.
writeFixture('write', 'mixed_status_response.json', {
    response_message_b64: b64(TlvWriteResponse.encode({
        writeResponses: [
            {
                path: { endpointId: 0, clusterId: 0x28, attributeId: 0x05 },
                status: { status: 0 },
            },
            {
                path: { endpointId: 0, clusterId: 0x28, attributeId: 0x06 },
                status: { status: 0x01 },
            },
        ],
        interactionModelRevision: 11,
    })),
    expected: [
        { endpoint: 0, cluster: 0x28, attribute: 0x05, status: 0 },
        { endpoint: 0, cluster: 0x28, attribute: 0x06, status: 1 },
    ],
});

// ---------------------------------------------------------------------
// SUBSCRIBE fixtures (gate matter-interaction::subscription — M8.5)
// ---------------------------------------------------------------------

// SubscribeRequest: OnOff.OnOff on ep 1, min 1s / max 30s.
writeFixture('subscribe', 'subscribe_onoff.json', {
    keep_subscriptions: false,
    min_interval_floor: 1,
    max_interval_ceiling: 30,
    paths: [{ endpoint: 1, cluster: 0x06, attribute: 0x0000 }],
    expected_message_b64: b64(TlvSubscribeRequest.encode({
        keepSubscriptions: false,
        minIntervalFloorSeconds: 1,
        maxIntervalCeilingSeconds: 30,
        attributeRequests: [{ endpointId: 1, clusterId: 0x06, attributeId: 0x0000 }],
        isFabricFiltered: false,
        interactionModelRevision: 11,
    })),
});

// SubscribeResponse parse: subscriptionId + maxInterval.
writeFixture('subscribe', 'subscribe_response.json', {
    subscription_id: 0x1234_5678,
    max_interval: 30,
    response_message_b64: b64(TlvSubscribeResponse.encode({
        subscriptionId: 0x1234_5678,
        maxInterval: 30,
        interactionModelRevision: 11,
    })),
});

// StatusResponse: success ack (the controller's per-report ack).
writeFixture('subscribe', 'status_response_success.json', {
    status: 0,
    expected_message_b64: b64(TlvStatusResponse.encode({
        status: 0,
        interactionModelRevision: 11,
    })),
});

// Steady-state ReportData: subscriptionId + OnOff.OnOff(ep 1) = true.
writeFixture('subscribe', 'report_data_subscribed.json', {
    subscription_id: 0x1234_5678,
    attributes: [{ endpoint: 1, cluster: 0x06, attribute: 0x0000, bool: true }],
    response_message_b64: b64(TlvDataReport.encode({
        subscriptionId: 0x1234_5678,
        attributeReports: [{
            attributeData: {
                path: { endpointId: 1, clusterId: 0x06, attributeId: 0x0000 },
                data: TlvBoolean.encodeTlv(true),
            },
        }],
        interactionModelRevision: 11,
    })),
});

console.log('capture-im: all fixtures written.');
