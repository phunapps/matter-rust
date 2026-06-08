// xtask/scripts/capture-clusters/index.js
//
// Encode a curated set of cluster attribute values and command requests with
// matter.js 0.16.11 TLV combinators, emitting byte-parity vectors under
// test-vectors/clusters/<cluster>/*.json. The bytes are the oracle; inputs
// are hardcoded here (NOT read from our own clusters.json) so a dump bug
// cannot hide behind a codec bug. Consumed by matter-clusters' generated
// codec byte-parity tests in M7.4b.
//
// Vector shapes:
//   attribute: { cluster, cluster_id, attribute, attribute_id, type,
//                writable, note, value_tlv_b64 }
//   command:   { cluster, cluster_id, command, command_id,
//                fields: [{ name, id, value }], note, payload_tlv_b64 }

import {
  TlvUInt8, TlvUInt16, TlvUInt32, TlvInt16,
  TlvBoolean, TlvString, TlvByteString,
  TlvArray, TlvNullable,
  TlvObject, TlvField, TlvOptionalField,
} from '@matter/types';

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..'); // capture-clusters -> scripts -> xtask -> root
const OUT_ROOT = join(REPO_ROOT, 'test-vectors', 'clusters');

const b64 = (bytes) => Buffer.from(bytes).toString('base64');

function writeVector(clusterSnake, name, obj) {
  const dir = join(OUT_ROOT, clusterSnake);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify(obj, null, 2) + '\n');
  console.log(`wrote ${path}`);
}

function attr(clusterSnake, file, meta, tlvBytes) {
  writeVector(clusterSnake, file, { ...meta, value_tlv_b64: b64(tlvBytes) });
}

function cmd(clusterSnake, file, meta, tlvBytes) {
  writeVector(clusterSnake, file, { ...meta, payload_tlv_b64: b64(tlvBytes) });
}

// ---------------------------------------------------------------------------
// OnOff (0x0006)
// ---------------------------------------------------------------------------

attr('on_off', 'attr_on_off.json',
  { cluster: 'OnOff', cluster_id: 0x06, attribute: 'OnOff', attribute_id: 0x00,
    type: 'bool', writable: false, note: 'boolean attribute value' },
  TlvBoolean.encode(true));

attr('on_off', 'attr_on_time.json',
  { cluster: 'OnOff', cluster_id: 0x06, attribute: 'OnTime', attribute_id: 0x4001,
    type: 'uint16', writable: true, note: 'plain uint16 writable attribute' },
  TlvUInt16.encode(60));

attr('on_off', 'attr_start_up_on_off_present.json',
  { cluster: 'OnOff', cluster_id: 0x06, attribute: 'StartUpOnOff', attribute_id: 0x4003,
    type: 'enum8', writable: true, note: 'nullable enum, present (StartUpOnOffEnum::Toggle = 2)' },
  TlvNullable(TlvUInt8).encode(2));

attr('on_off', 'attr_start_up_on_off_null.json',
  { cluster: 'OnOff', cluster_id: 0x06, attribute: 'StartUpOnOff', attribute_id: 0x4003,
    type: 'enum8', writable: true, note: 'nullable enum, TLV null' },
  TlvNullable(TlvUInt8).encode(null));

cmd('on_off', 'cmd_toggle.json',
  { cluster: 'OnOff', cluster_id: 0x06, command: 'Toggle', command_id: 0x02, fields: [],
    note: 'fieldless command (empty anonymous struct)' },
  TlvObject({}).encode({}));

cmd('on_off', 'cmd_on_with_timed_off.json',
  { cluster: 'OnOff', cluster_id: 0x06, command: 'OnWithTimedOff', command_id: 0x42,
    fields: [
      { name: 'OnOffControl', id: 0, value: 1 },
      { name: 'OnTime', id: 1, value: 60 },
      { name: 'OffWaitTime', id: 2, value: 0 },
    ],
    note: 'command with bitmap(map8) + two uint16 fields' },
  TlvObject({
    onOffControl: TlvField(0, TlvUInt8),
    onTime: TlvField(1, TlvUInt16),
    offWaitTime: TlvField(2, TlvUInt16),
  }).encode({ onOffControl: 1, onTime: 60, offWaitTime: 0 }));

// ---------------------------------------------------------------------------
// BasicInformation (0x0028)
// ---------------------------------------------------------------------------

attr('basic_information', 'attr_node_label.json',
  { cluster: 'BasicInformation', cluster_id: 0x28, attribute: 'NodeLabel', attribute_id: 0x05,
    type: 'string', writable: true, note: 'writable UTF-8 string attribute' },
  TlvString.encode('matter-rust'));

attr('basic_information', 'attr_capability_minima.json',
  { cluster: 'BasicInformation', cluster_id: 0x28, attribute: 'CapabilityMinima', attribute_id: 0x13,
    type: 'CapabilityMinimaStruct', writable: false,
    note: 'struct attribute: { CaseSessionsPerFabric(0)=3, SubscriptionsPerFabric(1)=4 }' },
  TlvObject({
    caseSessionsPerFabric: TlvField(0, TlvUInt16),
    subscriptionsPerFabric: TlvField(1, TlvUInt16),
  }).encode({ caseSessionsPerFabric: 3, subscriptionsPerFabric: 4 }));

// ---------------------------------------------------------------------------
// LevelControl (0x0008)
// ---------------------------------------------------------------------------

attr('level_control', 'attr_current_level_present.json',
  { cluster: 'LevelControl', cluster_id: 0x08, attribute: 'CurrentLevel', attribute_id: 0x00,
    type: 'uint8', writable: false, note: 'nullable uint8, present' },
  TlvNullable(TlvUInt8).encode(254));

cmd('level_control', 'cmd_move_to_level.json',
  { cluster: 'LevelControl', cluster_id: 0x08, command: 'MoveToLevel', command_id: 0x00,
    fields: [
      { name: 'Level', id: 0, value: 128 },
      { name: 'TransitionTime', id: 1, value: 10 },
      { name: 'OptionsMask', id: 2, value: 0 },
      { name: 'OptionsOverride', id: 3, value: 0 },
    ],
    note: 'command with a nullable uint16 field (TransitionTime present)' },
  TlvObject({
    level: TlvField(0, TlvUInt8),
    transitionTime: TlvField(1, TlvNullable(TlvUInt16)),
    optionsMask: TlvField(2, TlvUInt8),
    optionsOverride: TlvField(3, TlvUInt8),
  }).encode({ level: 128, transitionTime: 10, optionsMask: 0, optionsOverride: 0 }));

// ---------------------------------------------------------------------------
// TemperatureMeasurement (0x0402)
// ---------------------------------------------------------------------------

attr('temperature_measurement', 'attr_measured_value.json',
  { cluster: 'TemperatureMeasurement', cluster_id: 0x402, attribute: 'MeasuredValue', attribute_id: 0x00,
    type: 'int16', writable: false, note: 'nullable signed int16 (temperature), present negative' },
  TlvNullable(TlvInt16).encode(-1234));

// ---------------------------------------------------------------------------
// Descriptor (0x001D)
// ---------------------------------------------------------------------------

attr('descriptor', 'attr_server_list.json',
  { cluster: 'Descriptor', cluster_id: 0x1d, attribute: 'ServerList', attribute_id: 0x01,
    type: 'list[uint32]', writable: false, note: 'list of scalars (cluster-id -> u32)' },
  TlvArray(TlvUInt32).encode([0x06, 0x1d, 0x28]));

attr('descriptor', 'attr_device_type_list.json',
  { cluster: 'Descriptor', cluster_id: 0x1d, attribute: 'DeviceTypeList', attribute_id: 0x00,
    type: 'list[DeviceTypeStruct]', writable: false,
    note: 'list of structs: [{ DeviceType(0)=256, Revision(1)=1 }]' },
  TlvArray(TlvObject({
    deviceType: TlvField(0, TlvUInt32),
    revision: TlvField(1, TlvUInt16),
  })).encode([{ deviceType: 256, revision: 1 }]));

// ---------------------------------------------------------------------------
// ColorControl (0x0300)
// ---------------------------------------------------------------------------

attr('color_control', 'attr_color_capabilities.json',
  { cluster: 'ColorControl', cluster_id: 0x300, attribute: 'ColorCapabilities', attribute_id: 0x400a,
    type: 'map16', writable: false, note: 'bitmap (map16) raw value 0b10101 = 21' },
  TlvUInt16.encode(0b10101));

// ---------------------------------------------------------------------------
// DoorLock (0x0101) — optional command field present/absent
// ---------------------------------------------------------------------------

const lockDoorSchema = TlvObject({ pinCode: TlvOptionalField(0, TlvByteString) });

cmd('door_lock', 'cmd_lock_door_with_pin.json',
  { cluster: 'DoorLock', cluster_id: 0x101, command: 'LockDoor', command_id: 0x00,
    fields: [{ name: 'PinCode', id: 0, value: [1, 2, 3, 4] }],
    note: 'command with optional octstr field PRESENT' },
  lockDoorSchema.encode({ pinCode: Uint8Array.from([1, 2, 3, 4]) }));

cmd('door_lock', 'cmd_lock_door_no_pin.json',
  { cluster: 'DoorLock', cluster_id: 0x101, command: 'LockDoor', command_id: 0x00,
    fields: [],
    note: 'command with optional octstr field ABSENT (tag omitted)' },
  lockDoorSchema.encode({}));

console.log('capture-clusters: all vectors written.');
