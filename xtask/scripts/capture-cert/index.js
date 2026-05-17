/**
 * Captures a coherent RCAC → ICAC → NOC chain from matter.js into
 * test-vectors/certs/.
 *
 * DISCOVERY (probed 2026-05-17 against @matter/protocol 0.16.11):
 *
 *   `@matter/protocol` exposes `CertificateAuthority`. When created with
 *   `generateIntermediateCert = true`, a single CA instance holds:
 *
 *     ca.rootCert  — the RCAC (Root CA cert, self-signed), Uint8Array, 0x15
 *     ca.icacCert  — the ICAC (Intermediate CA cert, signed by rootCert), 0x15
 *     ca.generateNoc(pubKey, fabricId, nodeId) — NOC signed by the ICAC, 0x15
 *
 *   All three TLV buffers come from one CA, so they form a verifiable chain:
 *
 *     RCAC  (self-signed)
 *       └── ICAC  (signed by RCAC)
 *             └── NOC  (signed by ICAC)
 *
 *   The manifest records `is_self_signed = true` on the root and
 *   `signed_by_id = "<parent-id>"` on each descendant. The M2.2 integration
 *   test uses these annotations to pair certs and exercise verify_signed_by.
 *
 * NOTE: Because keys are generated fresh each run, the binary output changes
 * on every invocation. The committed .bin files are the source of truth for
 * the integration test; regenerate with `cargo xtask capture-cert` whenever
 * the test-vector set needs refreshing.
 */

import { createRequire } from "node:module";
import { writeFile, mkdir, readdir, unlink } from "node:fs/promises";
import toml from "@iarna/toml";
import { NodeJsStyleCrypto } from "@matter/general";
import { CertificateAuthority } from "@matter/protocol";
import { FabricId, NodeId } from "@matter/types";

// node:crypto is a CommonJS built-in; import it via createRequire so ESM
// modules that live inside node_modules can still reference it.
const require = createRequire(import.meta.url);
const nodeCrypto = require("crypto");

const OUT_DIR = new URL("../../../test-vectors/certs/", import.meta.url);

async function clearExistingBins() {
  await mkdir(OUT_DIR, { recursive: true });
  const entries = await readdir(OUT_DIR);
  for (const e of entries) {
    if (e.endsWith(".bin")) {
      await unlink(new URL(e, OUT_DIR));
    }
  }
}

async function main() {
  await clearExistingBins();

  const crypto = new NodeJsStyleCrypto(nodeCrypto);
  const written = [];

  // Build a single 3-tier CA so all three certs form one verifiable chain.
  // generateIntermediateCert=true makes the CA emit both rootCert and icacCert
  // from the same key material.  generateNoc() then signs the leaf with the
  // ICAC key.
  const ca = await CertificateAuthority.create(crypto, undefined, true);
  await ca.construction;

  // ── 1. RCAC (Root CA certificate, self-signed) ───────────────────────────
  const rcacBytes = ca.rootCert;
  if (!rcacBytes || rcacBytes[0] !== 0x15) {
    console.error(
      `rootCert is invalid: ${rcacBytes ? `first byte 0x${rcacBytes[0].toString(16)}` : "undefined"}`,
    );
    process.exit(1);
  }
  await writeFile(new URL("rcac.bin", OUT_DIR), rcacBytes);
  written.push({
    id: "rcac",
    description: "Root CA certificate (self-signed)",
    source: "@matter/protocol CertificateAuthority (3-tier) → ca.rootCert",
    file: "rcac.bin",
    kind: "rcac",
    is_self_signed: true,
  });

  // ── 2. ICAC (Intermediate CA certificate, signed by RCAC) ────────────────
  const icacBytes = ca.icacCert;
  if (!icacBytes || icacBytes[0] !== 0x15) {
    console.error(
      `icacCert is invalid: ${icacBytes ? `first byte 0x${icacBytes[0].toString(16)}` : "undefined"}`,
    );
    process.exit(1);
  }
  await writeFile(new URL("icac.bin", OUT_DIR), icacBytes);
  written.push({
    id: "icac",
    description: "Intermediate CA certificate (signed by RCAC)",
    source: "@matter/protocol CertificateAuthority (3-tier) → ca.icacCert",
    file: "icac.bin",
    kind: "icac",
    signed_by_id: "rcac",
  });

  // ── 3. NOC (Node Operational Certificate, signed by ICAC) ─────────────────
  // generateNoc signs the leaf cert with the ICAC key when the CA was created
  // with generateIntermediateCert=true.
  const nodeKeyPair = await crypto.createKeyPair();
  const fabricId = FabricId(BigInt("0x0000000000000001"));
  const nodeId = NodeId(BigInt("0x0000000000000001"));
  const nocBytes = await ca.generateNoc(
    nodeKeyPair.publicKey,
    fabricId,
    nodeId,
    undefined,
  );
  if (!nocBytes || nocBytes[0] !== 0x15) {
    console.error(
      `noc is invalid: ${nocBytes ? `first byte 0x${nocBytes[0].toString(16)}` : "undefined"}`,
    );
    process.exit(1);
  }
  await writeFile(new URL("noc.bin", OUT_DIR), nocBytes);
  written.push({
    id: "noc",
    description: "Node Operational Certificate (signed by ICAC)",
    source:
      "@matter/protocol CertificateAuthority.generateNoc() → Noc TLV bytes",
    file: "noc.bin",
    kind: "noc",
    signed_by_id: "icac",
  });

  if (written.length === 0) {
    console.error("extraction yielded zero certificates; investigate.");
    process.exit(1);
  }

  // ── Write manifest ────────────────────────────────────────────────────────
  const manifest = { certificate: written };
  await writeFile(new URL("manifest.toml", OUT_DIR), toml.stringify(manifest));

  console.log(
    `wrote ${written.length} certificate(s) to test-vectors/certs/`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
