import { TlvUInt8, TlvBoolean, TlvObject, TlvArray, TlvField } from "./api.js";

// Tier-2 vectors: input structures defined here, bytes recorded from matter.js.
// We do NOT pre-declare `expectedBytes` — that is the point of Tier-2, which
// exists to cover the dimensions Tier-1 has not transcribed yet (non-anonymous
// tags, containers, nested compositions).
//
// Every entry MUST include an `encode` description rich enough that the Rust
// harness can rebuild the same structure for round-trip verification.
//
// The `encode` descriptions below reflect what matter.js actually produces,
// verified by spot-decoding against Matter spec §A.7 TLV control byte layout:
//   bits 7:5 = tag form (000=anonymous, 001=context, ...)
//   bits 4:0 = element type
// All element types used here:
//   0x04 = anonymous-tag UInt8 (1-byte value follows)
//   0x09 = anonymous-tag bool-true (no value bytes)
//   0x15 = anonymous-tag Structure (End-of-Container closes)
//   0x16 = anonymous-tag Array (End-of-Container closes)
//   0x18 = anonymous-tag End-of-Container
//   0x24 = context-tag UInt8 (tag byte follows, then 1-byte value)
//   0x29 = context-tag bool-true (tag byte follows, no value bytes)

const EmptyStruct = TlvObject({});
const EmptyArrayOfU8 = TlvArray(TlvUInt8);
const StructWithU8AtCtxTag0 = TlvObject({
  a: TlvField(0, TlvUInt8),
});
const StructWithBoolAtCtxTag7 = TlvObject({
  flag: TlvField(7, TlvBoolean),
});
const ArrayOfU8 = TlvArray(TlvUInt8);

export const matterjsVectors = [
  {
    id: "0019-structure-empty-anonymous",
    description: "Empty structure, anonymous tag",
    source: "matter.js capture",
    codec: EmptyStruct,
    input: {},
    encode: {
      tag: { kind: "anonymous" },
      value: { kind: "structure", members: [] },
    },
  },
  {
    id: "0020-array-empty-anonymous",
    description: "Empty array, anonymous tag",
    source: "matter.js capture",
    codec: EmptyArrayOfU8,
    input: [],
    encode: {
      tag: { kind: "anonymous" },
      value: { kind: "array", elements: [] },
    },
  },
  {
    id: "0021-structure-uint8-at-context-0",
    description: "Structure containing a single uint8=42 at context tag 0",
    source: "matter.js capture",
    codec: StructWithU8AtCtxTag0,
    input: { a: 42 },
    encode: {
      tag: { kind: "anonymous" },
      value: {
        kind: "structure",
        members: [
          {
            tag: { kind: "context", number: 0 },
            value: { kind: "uint", width: 1, value: 42 },
          },
        ],
      },
    },
  },
  {
    id: "0022-array-of-three-uint8-anonymous",
    description: "Array of three uint8 values [1, 2, 3], anonymous tag",
    source: "matter.js capture",
    codec: ArrayOfU8,
    input: [1, 2, 3],
    encode: {
      tag: { kind: "anonymous" },
      value: {
        kind: "array",
        // Array elements in matter.js use anonymous tags inside the container.
        // Each element control byte is 0x04 (anonymous-tag UInt8, 1-byte value).
        elements: [
          { tag: { kind: "anonymous" }, value: { kind: "uint", width: 1, value: 1 } },
          { tag: { kind: "anonymous" }, value: { kind: "uint", width: 1, value: 2 } },
          { tag: { kind: "anonymous" }, value: { kind: "uint", width: 1, value: 3 } },
        ],
      },
    },
  },
  {
    id: "0023-structure-bool-at-context-7",
    description: "Structure containing a single bool=true at context tag 7",
    source: "matter.js capture",
    codec: StructWithBoolAtCtxTag7,
    input: { flag: true },
    encode: {
      tag: { kind: "anonymous" },
      value: {
        kind: "structure",
        members: [
          {
            // Control byte 0x29 = 0b001_01001: context-tag form, bool-true element type.
            // The tag byte 0x07 follows the control byte; no value bytes (bool is in the type).
            tag: { kind: "context", number: 7 },
            value: { kind: "bool", value: true },
          },
        ],
      },
    },
  },
];
