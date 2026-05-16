import { encode } from "./api.js";
import { specVectors } from "./spec-vectors.js";
import { matterjsVectors } from "./matterjs-vectors.js";
import { ensureOutDir, writeBin, writeManifest } from "./manifest.js";

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(" ");
}

async function main() {
  await ensureOutDir();
  const errors = [];
  const written = [];

  // Tier-1: cross-check matter.js against pre-declared bytes.
  for (const v of specVectors) {
    const actual = encode(v.codec, v.input);
    if (!bytesEqual(actual, v.expectedBytes)) {
      errors.push(
        `vector ${v.id} (${v.source}):\n  expected: ${toHex(v.expectedBytes)}\n  matter.js: ${toHex(actual)}`,
      );
      continue;
    }
    await writeBin(v.id, v.expectedBytes);
    written.push({
      id: v.id,
      description: v.description,
      source: v.source,
      encode: v.encode,
    });
  }

  // Abort before touching Tier-2 if Tier-1 had any disagreements.
  if (errors.length > 0) {
    console.error("matter.js disagreed with spec on the following vectors:");
    for (const e of errors) console.error(e);
    process.exit(1);
  }

  // Tier-2: matter.js bytes are the source of truth — no pre-declared expectation.
  for (const v of matterjsVectors) {
    const actual = encode(v.codec, v.input);
    await writeBin(v.id, actual);
    written.push({
      id: v.id,
      description: v.description,
      source: v.source,
      encode: v.encode,
    });
  }

  await writeManifest(written);
  console.log(`wrote ${written.length} vector(s) to test-vectors/tlv/`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
