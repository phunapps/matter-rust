/**
 * Captures Matter operational certificate test vectors from matter.js.
 *
 * DISCOVERY (probed 2026-05-17 against @matter/protocol 0.16.11):
 *
 *   Probe A  (@matter/types top-level) — no cert bytes, only pairing-code
 *            codecs and SoftwareVersionCertificationStatus.
 *   Probe B  (@project-chip/matter.js top-level) — no cert-related keys.
 *   Probe C  (@matter/protocol) — exports `CertificateAuthority`, `Rcac`,
 *            `Noc`, `Icac`, `TestCert_PAA_FFF1_Cert`, etc.  The TestCert_*
 *            exports are DER-encoded X.509 (first byte 0x30), not Matter TLV.
 *   Probe D  (filesystem grep) — no ready-to-use TLV cert bytes found.
 *
 * OUTCOME: Outcome B (API-based generation).
 *
 *   `@matter/protocol` exposes `CertificateAuthority` which — given a
 *   `NodeJsStyleCrypto` instance — can generate RCAC, ICAC, and NOC
 *   certificates and serialise them as Matter TLV (first byte 0x15).
 *
 *   We generate three certs:
 *     rcac-no-icac   — Root CA cert for a fabric without an intermediate CA.
 *     icac           — Intermediate CA cert in a chain that also has an RCAC.
 *     noc            — Node Operational Cert signed by a root-only CA.
 *
 *   These cover the three operational cert types the matter-cert crate parses
 *   (MatterCertificate::from_tlv → to_tlv round-trip).
 *
 * NOTE: Because keys are generated fresh each run, the binary output changes
 * on every invocation.  The committed .bin files are the source of truth for
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

  // ── 1. RCAC (Root CA certificate, no intermediate) ────────────────────────
  // CertificateAuthority with generateIntermediateCert=false produces only a
  // root cert.  This is the most common operational fabric topology.
  const caRoot = await CertificateAuthority.create(crypto, undefined, false);
  await caRoot.construction;

  const rcacBytes = caRoot.rootCert;
  await writeFile(new URL("rcac-no-icac.bin", OUT_DIR), rcacBytes);
  written.push({
    id: "rcac-no-icac",
    description: "Matter RCAC (Root CA certificate) for a fabric with no intermediate CA",
    source:
      "@matter/protocol CertificateAuthority (root-only) → Rcac.asSignedTlv()",
    kind: "rcac",
  });

  // ── 2. ICAC (Intermediate CA certificate) ────────────────────────────────
  // CertificateAuthority with generateIntermediateCert=true produces both an
  // RCAC and an ICAC.  We capture only the ICAC here because its RCAC is
  // structurally identical to the one above.
  const caWithIcac = await CertificateAuthority.create(crypto, undefined, true);
  await caWithIcac.construction;

  const icacBytes = caWithIcac.icacCert;
  if (!icacBytes) {
    console.error("CertificateAuthority with ICAC returned undefined icacCert");
    process.exit(1);
  }
  await writeFile(new URL("icac.bin", OUT_DIR), icacBytes);
  written.push({
    id: "icac",
    description: "Matter ICAC (Intermediate CA certificate) in a three-tier fabric chain",
    source:
      "@matter/protocol CertificateAuthority (with ICAC) → Icac.asSignedTlv()",
    kind: "icac",
  });

  // ── 3. NOC (Node Operational Certificate) ─────────────────────────────────
  // generateNoc signs a leaf cert with the root CA key.
  const nodeKeyPair = await crypto.createKeyPair();
  const fabricId = FabricId(BigInt("0x0000000000000001"));
  const nodeId = NodeId(BigInt("0x0000000000000001"));
  const nocBytes = await caRoot.generateNoc(
    nodeKeyPair.publicKey,
    fabricId,
    nodeId,
    undefined,
  );
  await writeFile(new URL("noc.bin", OUT_DIR), nocBytes);
  written.push({
    id: "noc",
    description:
      "Matter NOC (Node Operational Certificate) for node 1 in fabric 1",
    source:
      "@matter/protocol CertificateAuthority.generateNoc() → Noc.asSignedTlv()",
    kind: "noc",
  });

  // ── Write manifest ────────────────────────────────────────────────────────
  const manifest = {
    certificate: written.map((e) => ({
      id: e.id,
      description: e.description,
      source: e.source,
      file: `${e.id}.bin`,
      kind: e.kind,
    })),
  };
  await writeFile(new URL("manifest.toml", OUT_DIR), toml.stringify(manifest));

  console.log(
    `wrote ${written.length} certificate(s) to test-vectors/certs/`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
