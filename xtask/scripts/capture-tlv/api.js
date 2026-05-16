// The matter.js TLV codec entry points, isolated in one file so a future
// matter.js API rename is a one-place fix.
import * as mjs from "@matter/types/tlv";

// Re-export each codec object we use, asserting at load time that it exists.
function pick(name) {
  if (!mjs[name]) {
    throw new Error(
      `matter.js does not export '${name}' from @matter/types/tlv. ` +
      `Did the matter.js API move? See the plan's Task 1 Step 4 for the discovery procedure.`,
    );
  }
  return mjs[name];
}

export const TlvBoolean = pick("TlvBoolean");
export const TlvUInt8 = pick("TlvUInt8");
export const TlvUInt16 = pick("TlvUInt16");
export const TlvUInt32 = pick("TlvUInt32");
export const TlvUInt64 = pick("TlvUInt64");
export const TlvInt8 = pick("TlvInt8");
export const TlvInt16 = pick("TlvInt16");
export const TlvInt32 = pick("TlvInt32");
export const TlvInt64 = pick("TlvInt64");
export const TlvFloat = pick("TlvFloat");
export const TlvDouble = pick("TlvDouble");
export const TlvString = pick("TlvString");
export const TlvByteString = pick("TlvByteString");
// Note: TlvNull is NOT exported. Neither TlvVoid nor TlvAny encodes a standalone
// Matter null element (0x14) — TlvVoid.encode(null) errors, TlvVoid.encode(undefined)
// returns empty bytes, TlvAny.encode(null) errors. The null vector is omitted.

// Encode a value via a matter.js TLV codec and return raw bytes as a Uint8Array.
export function encode(codec, value) {
  const encoded = codec.encode(value);
  if (encoded instanceof Uint8Array) return encoded;
  if (encoded?.bytes instanceof Uint8Array) return encoded.bytes; // matter.js ByteArray
  if (typeof encoded?.toBuffer === "function") return new Uint8Array(encoded.toBuffer());
  throw new Error(`matter.js codec.encode returned an unrecognised type: ${typeof encoded}`);
}
