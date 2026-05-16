import {
  TlvBoolean,
  TlvUInt8, TlvUInt16, TlvUInt32, TlvUInt64,
  TlvInt8, TlvInt16, TlvInt32, TlvInt64,
  TlvFloat, TlvDouble,
  TlvString, TlvByteString,
} from "./api.js";

// Tier-1 vectors: bytes are pre-declared from the Matter Core Specification.
// The driver cross-checks each entry by running matter.js's codec and
// asserting the output matches `expectedBytes` exactly. If matter.js
// disagrees with the spec, the driver exits non-zero and we file a finding.
//
// Encoding rules used to derive `expectedBytes`:
//   spec §A.2 lists the element-type field (low 5 bits of the control octet)
//   and tag-control bits (top 3 bits). For anonymous tags, control octet = type.
//   Integer payloads are little-endian. String payloads are length-prefixed
//   with a width determined by the element-type variant.
//
// Note: the null element (0x14) is omitted from this tier-1 set.
// Neither TlvVoid nor TlvAny in matter.js encodes a standalone null element:
//   TlvVoid.encode(null)      — ValidationDatatypeMismatchError
//   TlvVoid.encode(undefined) — returns Uint8Array(0) [], not Uint8Array.of(0x14)
//   TlvAny.encode(null)       — ValidationDatatypeMismatchError
// The null vector will be added in a later task once a working codec is found.

const u8 = (...n) => Uint8Array.of(...n);

export const specVectors = [
  // -- booleans --
  {
    id: "0001-bool-true-anonymous",
    description: "Boolean true, anonymous tag",
    source: "Matter Core 1.4 §A.2 (Boolean true)",
    codec: TlvBoolean, input: true,
    expectedBytes: u8(0x09),
    encode: { tag: { kind: "anonymous" }, value: { kind: "bool", value: true } },
  },
  {
    id: "0002-bool-false-anonymous",
    description: "Boolean false, anonymous tag",
    source: "Matter Core 1.4 §A.2 (Boolean false)",
    codec: TlvBoolean, input: false,
    expectedBytes: u8(0x08),
    encode: { tag: { kind: "anonymous" }, value: { kind: "bool", value: false } },
  },

  // -- unsigned integers --
  {
    id: "0003-uint8-42-anonymous",
    description: "Unsigned 8-bit integer 42, anonymous tag",
    source: "Matter Core 1.4 §A.2 (Unsigned 1-byte 42)",
    codec: TlvUInt8, input: 42,
    expectedBytes: u8(0x04, 0x2A),
    encode: { tag: { kind: "anonymous" }, value: { kind: "uint", width: 1, value: 42 } },
  },
  {
    id: "0004-uint8-max-anonymous",
    description: "Unsigned 8-bit integer 255 (max), anonymous tag",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvUInt8, input: 255,
    expectedBytes: u8(0x04, 0xFF),
    encode: { tag: { kind: "anonymous" }, value: { kind: "uint", width: 1, value: 255 } },
  },
  {
    id: "0005-uint16-0x1234-anonymous",
    description: "Unsigned 16-bit integer 0x1234, anonymous tag (little-endian payload)",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvUInt16, input: 0x1234,
    expectedBytes: u8(0x05, 0x34, 0x12),
    encode: { tag: { kind: "anonymous" }, value: { kind: "uint", width: 2, value: 0x1234 } },
  },
  {
    id: "0006-uint32-0xcafebabe-anonymous",
    description: "Unsigned 32-bit integer 0xCAFEBABE, anonymous tag",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvUInt32, input: 0xCAFEBABE,
    expectedBytes: u8(0x06, 0xBE, 0xBA, 0xFE, 0xCA),
    encode: { tag: { kind: "anonymous" }, value: { kind: "uint", width: 4, value: 0xCAFEBABE } },
  },
  {
    id: "0007-uint64-0x0123456789abcdef-anonymous",
    description: "Unsigned 64-bit integer 0x0123456789ABCDEF, anonymous tag",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvUInt64, input: 0x0123456789ABCDEFn,
    expectedBytes: u8(0x07, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01),
    encode: { tag: { kind: "anonymous" }, value: { kind: "uint", width: 8, value: "0x0123456789abcdef" } },
  },

  // -- signed integers --
  {
    id: "0008-int8-neg17-anonymous",
    description: "Signed 8-bit integer -17, anonymous tag",
    source: "Matter Core 1.4 §A.2 (Signed 1-byte -17)",
    codec: TlvInt8, input: -17,
    expectedBytes: u8(0x00, 0xEF),
    encode: { tag: { kind: "anonymous" }, value: { kind: "int", width: 1, value: -17 } },
  },
  {
    id: "0009-int8-min-anonymous",
    description: "Signed 8-bit integer -128 (min), anonymous tag",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvInt8, input: -128,
    expectedBytes: u8(0x00, 0x80),
    encode: { tag: { kind: "anonymous" }, value: { kind: "int", width: 1, value: -128 } },
  },
  {
    id: "0010-int16-neg129-anonymous",
    description: "Signed 16-bit integer -129, anonymous tag (forces 2-byte encoding; -1 fits in 1 byte and matter.js minimises)",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvInt16, input: -129,
    expectedBytes: u8(0x01, 0x7F, 0xFF),
    encode: { tag: { kind: "anonymous" }, value: { kind: "int", width: 2, value: -129 } },
  },
  {
    id: "0011-int32-min-anonymous",
    description: "Signed 32-bit integer -2147483648 (min), anonymous tag",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvInt32, input: -2147483648,
    expectedBytes: u8(0x02, 0x00, 0x00, 0x00, 0x80),
    encode: { tag: { kind: "anonymous" }, value: { kind: "int", width: 4, value: -2147483648 } },
  },
  {
    id: "0012-int64-min-anonymous",
    description: "Signed 64-bit integer -9223372036854775808 (min i64), anonymous tag (forces 8-byte encoding; -1 fits in 1 byte and matter.js minimises)",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvInt64, input: -9223372036854775808n,
    expectedBytes: u8(0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80),
    encode: { tag: { kind: "anonymous" }, value: { kind: "int", width: 8, value: "-9223372036854775808" } },
  },

  // -- floats --
  // Float values are stored as strings in the manifest because `@iarna/toml`
  // serialises JS `0.0` as the integer `0`, losing the float type. Storing as
  // strings makes the precision and type unambiguous when the Rust harness
  // deserialises them. Same rationale as 64-bit integers (see below).
  {
    id: "0013-float32-0-anonymous",
    description: "Single-precision float 0.0, anonymous tag",
    source: "Matter Core 1.4 §A.2 (Single-precision 0.0)",
    codec: TlvFloat, input: 0.0,
    expectedBytes: u8(0x0A, 0x00, 0x00, 0x00, 0x00),
    encode: { tag: { kind: "anonymous" }, value: { kind: "float", width: 4, value: "0.0" } },
  },
  {
    id: "0014-float64-0-anonymous",
    description: "Double-precision float 0.0, anonymous tag",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvDouble, input: 0.0,
    expectedBytes: u8(0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
    encode: { tag: { kind: "anonymous" }, value: { kind: "float", width: 8, value: "0.0" } },
  },

  // -- strings --
  {
    id: "0015-utf8-hello-anonymous",
    description: "UTF-8 string \"Hello!\", 1-byte length, anonymous tag",
    source: "Matter Core 1.4 §A.2 (UTF-8 1-byte length \"Hello!\")",
    codec: TlvString, input: "Hello!",
    expectedBytes: u8(0x0C, 0x06, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21),
    encode: { tag: { kind: "anonymous" }, value: { kind: "utf8", value: "Hello!" } },
  },
  {
    id: "0016-utf8-empty-anonymous",
    description: "Empty UTF-8 string, 1-byte length, anonymous tag",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvString, input: "",
    expectedBytes: u8(0x0C, 0x00),
    encode: { tag: { kind: "anonymous" }, value: { kind: "utf8", value: "" } },
  },

  // -- byte strings --
  {
    id: "0017-bytes-five-bytes-anonymous",
    description: "Octet string [00 01 02 03 04], 1-byte length, anonymous tag",
    source: "Matter Core 1.4 §A.2 (Octet string 1-byte length)",
    codec: TlvByteString, input: Uint8Array.of(0x00, 0x01, 0x02, 0x03, 0x04),
    expectedBytes: u8(0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04),
    encode: { tag: { kind: "anonymous" }, value: { kind: "bytes", value: "0001020304" } },
  },
  {
    id: "0018-bytes-empty-anonymous",
    description: "Empty octet string, 1-byte length, anonymous tag",
    source: "derived from spec §A.2 encoding rules",
    codec: TlvByteString, input: new Uint8Array(0),
    expectedBytes: u8(0x10, 0x00),
    encode: { tag: { kind: "anonymous" }, value: { kind: "bytes", value: "" } },
  },
];
