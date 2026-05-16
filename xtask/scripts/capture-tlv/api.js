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

// Encode a value via a matter.js TLV codec and return raw bytes as a Uint8Array.
export function encode(codec, value) {
  const encoded = codec.encode(value);
  if (encoded instanceof Uint8Array) return encoded;
  if (encoded?.bytes instanceof Uint8Array) return encoded.bytes; // matter.js ByteArray
  if (typeof encoded?.toBuffer === "function") return new Uint8Array(encoded.toBuffer());
  throw new Error(`matter.js codec.encode returned an unrecognised type: ${typeof encoded}`);
}
