import { TlvBoolean } from "./api.js";

// Tier-1 vectors: bytes are pre-declared from the Matter Core Specification.
// The driver cross-checks each entry by running matter.js's codec and
// asserting the output matches `expectedBytes` exactly. If matter.js
// disagrees with the spec, the driver exits non-zero and we file a finding.

export const specVectors = [
  {
    id: "0001-bool-true-anonymous",
    description: "Boolean true, anonymous tag",
    source: "Matter Core 1.4 §A.2 (Boolean true)",
    codec: TlvBoolean,
    input: true,
    expectedBytes: Uint8Array.of(0x09),
    encode: {
      tag: { kind: "anonymous" },
      value: { kind: "bool", value: true },
    },
  },
];
