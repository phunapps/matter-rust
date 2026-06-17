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

import { TlvString, TlvUInt16, TlvUInt32, TlvUInt64, TlvObject, TlvField, TlvArray } from '@matter/types';

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
    TlvTimedRequest,
    TlvInvokeResponse,
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

// Multi-command InvokeRequest: OnOff.Toggle(ep1) + OnOff.Off(ep2), each with a
// commandRef (CommandDataIB tag 2). No fields. Gates M9-B5 batched invoke.
writeFixture('invoke', 'batch_request.json', {
    commands: [
        { endpoint: 1, cluster: 0x06, command: 0x02, command_ref: 0 },
        { endpoint: 2, cluster: 0x06, command: 0x00, command_ref: 1 },
    ],
    expected_message_b64: b64(TlvInvokeRequest.encode({
        suppressResponse: false,
        timedRequest: false,
        invokeRequests: [
            {
                commandPath: { endpointId: 1, clusterId: 0x06, commandId: 0x02 },
                commandFields: TlvNoFields.encodeTlv({}),
                commandRef: 0,
            },
            {
                commandPath: { endpointId: 2, clusterId: 0x06, commandId: 0x00 },
                commandFields: TlvNoFields.encodeTlv({}),
                commandRef: 1,
            },
        ],
        interactionModelRevision: 11,
    })),
});

// Multi-response InvokeResponse: two CommandStatusIB(SUCCESS), commandRef 0 and 1.
writeFixture('invoke', 'batch_response.json', {
    expected: [
        { command_ref: 0, status: 0 },
        { command_ref: 1, status: 0 },
    ],
    response_message_b64: b64(TlvInvokeResponse.encode({
        suppressResponse: false,
        invokeResponses: [
            {
                status: {
                    commandPath: { endpointId: 1, clusterId: 0x06, commandId: 0x02 },
                    status: { status: 0 },
                    commandRef: 0,
                },
            },
            {
                status: {
                    commandPath: { endpointId: 2, clusterId: 0x06, commandId: 0x00 },
                    status: { status: 0 },
                    commandRef: 1,
                },
            },
        ],
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
// EVENT READ fixtures (gate M9-B1 event reads). ReadRequest event tags:
// eventRequests[1] (EventPathIB: nodeId 0, endpointId 1, clusterId 2,
// eventId 3, isUrgent 4), eventFilters[2] (EventFilterIB: nodeId 0,
// eventMin 1). Field names + tags confirmed against @matter/types schema.
// ---------------------------------------------------------------------

// ReadRequest carrying an EVENT path: BasicInformation.StartUp (0x28 / event
// 0x00) on endpoint 0, plus an event filter (eventMin = 0 ⇒ from the beginning).
writeFixture('read', 'events_basic_information.json', {
    event_paths: [{ endpoint: 0, cluster: 0x28, event: 0x00 }],
    event_filters: [{ event_min: 0 }],
    expected_message_b64: b64(TlvReadRequest.encode({
        eventRequests: [{ endpointId: 0, clusterId: 0x28, eventId: 0x00 }],
        eventFilters: [{ eventMin: 0 }],
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

// SubscribeRequest carrying BOTH an attribute path (OnOff.OnOff ep1) and an
// event path (BasicInformation.StartUp ep0) + an event filter, min 1s/max 30s.
// Event tags: eventRequests[4] (EventPathIB list), eventFilters[5]
// (EventFilterIB struct) — both before isFabricFiltered[7].
writeFixture('subscribe', 'subscribe_with_events.json', {
    keep_subscriptions: false,
    min_interval_floor: 1,
    max_interval_ceiling: 30,
    paths: [{ endpoint: 1, cluster: 0x06, attribute: 0x0000 }],
    event_paths: [{ endpoint: 0, cluster: 0x28, event: 0x00 }],
    event_filters: [{ event_min: 0 }],
    expected_message_b64: b64(TlvSubscribeRequest.encode({
        keepSubscriptions: false,
        minIntervalFloorSeconds: 1,
        maxIntervalCeilingSeconds: 30,
        attributeRequests: [{ endpointId: 1, clusterId: 0x06, attributeId: 0x0000 }],
        eventRequests: [{ endpointId: 0, clusterId: 0x28, eventId: 0x00 }],
        eventFilters: [{ eventMin: 0 }],
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

// ---------------------------------------------------------------------
// CHUNKED ReportData fixtures (CR.1) — written under report/.
// matter.js TlvDataReport: subscriptionId[0], attributeReports[1],
// eventReports[2], moreChunkedMessages[3], suppressResponse[4], imRev[0xFF].
// ---------------------------------------------------------------------

// Message-level chunking: a non-final chunk (moreChunkedMessages=true)
// carrying ep0/BasicInformation.VendorID, then a final chunk carrying
// ep1/OnOff.OnOff. Reassembly must yield BOTH attributes.
const chunkA = TlvDataReport.encode({
    attributeReports: [{
        attributeData: {
            path: { endpointId: 0, clusterId: 0x28, attributeId: 0x0002 },
            data: TlvUInt16.encodeTlv(0x1392), // VendorID = 5010
        },
    }],
    moreChunkedMessages: true,
    interactionModelRevision: 11,
});
const chunkB = TlvDataReport.encode({
    attributeReports: [{
        attributeData: {
            path: { endpointId: 1, clusterId: 0x06, attributeId: 0x0000 },
            data: TlvBoolean.encodeTlv(true), // OnOff = true
        },
    }],
    suppressResponse: true,
    interactionModelRevision: 11,
});
writeFixture('report', 'report_data_chunked_message.json', {
    chunks_b64: [b64(chunkA), b64(chunkB)],
    expected: [
        { endpoint: 0, cluster: 0x28, attribute: 0x0002 },
        { endpoint: 1, cluster: 0x06, attribute: 0x0000 },
    ],
});

// List-level chunking: a single list attribute split across chunks. Chunk 1
// replaces the list with empty ([] array data); chunk 2 appends an element via
// path.listIndex = null. Target: ep0/Descriptor.PartsList (0x1d / 0x0003).
const listReplace = TlvDataReport.encode({
    attributeReports: [{
        attributeData: {
            path: { endpointId: 0, clusterId: 0x1d, attributeId: 0x0003 },
            data: TlvArray(TlvUInt32).encodeTlv([]), // replace with empty list
        },
    }],
    moreChunkedMessages: true,
    interactionModelRevision: 11,
});
const listAppend1 = TlvDataReport.encode({
    attributeReports: [{
        attributeData: {
            path: { endpointId: 0, clusterId: 0x1d, attributeId: 0x0003, listIndex: null },
            data: TlvUInt32.encodeTlv(1),
        },
    }],
    suppressResponse: true,
    interactionModelRevision: 11,
});
writeFixture('report', 'report_data_chunked_list.json', {
    chunks_b64: [b64(listReplace), b64(listAppend1)],
    expected_path: { endpoint: 0, cluster: 0x1d, attribute: 0x0003 },
    expected_list: [1],
});

// ---------------------------------------------------------------------
// EVENT REPORT fixture (gate M9-B1 event parse). DataReport.eventReports[2]
// carrying one EventData (EventDataIB tags: path 0, eventNumber 1, priority 2,
// epochTimestamp 3, ... data 7). Event: BasicInformation.StartUp on ep0.
// ---------------------------------------------------------------------
const TlvStartUpFields = TlvObject({ softwareVersion: TlvField(0, TlvUInt32) });
writeFixture('report', 'report_data_event.json', {
    event: {
        endpoint: 0, cluster: 0x28, event: 0x00,
        event_number: 1, priority: 2 /* Critical */,
        epoch_timestamp: 0,
    },
    response_message_b64: b64(TlvDataReport.encode({
        eventReports: [{
            eventData: {
                path: { endpointId: 0, clusterId: 0x28, eventId: 0x00 },
                eventNumber: 1,
                priority: 2,
                epochTimestamp: 0,
                data: TlvStartUpFields.encodeTlv({ softwareVersion: 1 }),
            },
        }],
        interactionModelRevision: 11,
    })),
});

// ---------------------------------------------------------------------
// TIMED fixtures (gate M9-B3). TimedRequest opcode 0x0a: {0: timeout, 0xFF}.
// WriteRequest/InvokeRequest with timedRequest=true (tag 1). StatusResponse
// with NEEDS_TIMED_INTERACTION (0xc6) for parse_status_response.
// ---------------------------------------------------------------------
writeFixture('timed', 'timed_request.json', {
    timeout_ms: 10000,
    expected_message_b64: b64(TlvTimedRequest.encode({
        timeout: 10000,
        interactionModelRevision: 11,
    })),
});

writeFixture('timed', 'write_request_timed.json', {
    writes: [{
        endpoint: 0,
        cluster: 0x28,
        attribute: 0x05,
        value_tlv_b64: b64(TlvString.encode('matter-rust')),
    }],
    expected_message_b64: b64(TlvWriteRequest.encode({
        suppressResponse: false,
        timedRequest: true,
        writeRequests: [{
            path: { endpointId: 0, clusterId: 0x28, attributeId: 0x05 },
            data: TlvString.encodeTlv('matter-rust'),
        }],
        interactionModelRevision: 11,
    })),
});

writeFixture('timed', 'invoke_request_timed.json', {
    endpoint: 1,
    cluster: 0x06,
    command: 0x02,
    command_fields_b64: b64(TlvNoFields.encode({})),
    expected_message_b64: b64(TlvInvokeRequest.encode({
        suppressResponse: false,
        timedRequest: true,
        invokeRequests: [{
            commandPath: { endpointId: 1, clusterId: 0x06, commandId: 0x02 },
            commandFields: TlvNoFields.encodeTlv({}),
        }],
        interactionModelRevision: 11,
    })),
});

writeFixture('timed', 'status_needs_timed.json', {
    status: 0xc6,
    response_message_b64: b64(TlvStatusResponse.encode({
        status: 0xc6,
        interactionModelRevision: 11,
    })),
});

console.log('capture-im: all fixtures written.');
