import { writeFile, mkdir } from "node:fs/promises";
import toml from "@iarna/toml";

const OUT_DIR = new URL("../../../test-vectors/tlv/", import.meta.url);

export async function ensureOutDir() {
  await mkdir(OUT_DIR, { recursive: true });
}

export function vectorFilename(id) {
  return `${id}.bin`;
}

export async function writeBin(id, bytes) {
  const path = new URL(vectorFilename(id), OUT_DIR);
  await writeFile(path, bytes);
}

// `entries` is an array of objects with: id, description, source, encode.
// `encode` is the structured description (tag + value) that future tooling
// (the Rust harness) will re-serialise to verify byte equality.
export async function writeManifest(entries) {
  const ordered = [...entries].sort((a, b) => a.id.localeCompare(b.id));
  const doc = {
    vector: ordered.map((e) => ({
      id: e.id,
      description: e.description,
      source: e.source,
      file: vectorFilename(e.id),
      encode: e.encode,
    })),
  };
  const path = new URL("manifest.toml", OUT_DIR);
  await writeFile(path, toml.stringify(doc));
}
