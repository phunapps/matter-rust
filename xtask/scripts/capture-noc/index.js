// capture-noc — drive matter.js to mint reference NOC + OpCreds command
// payload fixtures for matter-commissioning M6.3.3 byte-parity.
//
// Status: scaffolding. The `@matter/protocol` NOC-mint API surface shifts
// between matter.js minor versions (0.16.x in particular). Wiring the
// capture against the current symbol path is an operator-touch step —
// see TODO-1.0.md and the M6.3.3 plan task list.
//
// Output (when fully wired):
//   test-vectors/commissioning/noc/csr_request/<n>.json
//   test-vectors/commissioning/noc/csr_response/<n>.json
//   test-vectors/commissioning/noc/noc_chains/<n>.json
//   test-vectors/commissioning/noc/add_noc/<n>.json
//
// Each NOC-chain fixture carries:
//   - rcac_pkcs8_b64        — fabric root signing key (PKCS#8)
//   - rcac_matter_tlv_b64   — Matter-TLV encoded RCAC certificate
//   - csr_public_key_b64    — 65-byte SEC1 uncompressed device CSR pubkey
//   - node_id               — u64 NodeId picked for the NOC
//   - fabric_id             — u64 FabricId
//   - cats                  — number[] CAT values
//   - validity              — { not_before_unix: number, not_after_unix: number | "NO_EXPIRY" }
//   - serial_hex            — 19-byte serial as hex (matter.js convention)
//   - expected_noc_matter_tlv_b64 — matter.js's signed NOC, Matter-TLV
//
// RFC 6979 deterministic signing makes the captured bytes reproducible
// across runs (matter.js's @noble/curves uses RFC 6979 by default, and
// matter-rust's RingSigner uses p256's RFC 6979 deterministic path).

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

function out(sub, name) {
  return resolve(REPO_ROOT, "test-vectors", "commissioning", "noc", sub, `${name}.json`);
}

function writeFixture(sub, name, doc) {
  const path = out(sub, name);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  console.log(`wrote ${path}`);
}

async function main() {
  // Placeholder: write a single CSRRequest fixture with an empty
  // `expected_tlv_b64`. The Rust byte-parity test (noc_byte_parity.rs)
  // skips fixtures whose `expected_*_b64` is empty, so this scaffold
  // keeps CI green while the matter.js capture wiring lands.
  writeFixture("csr_request", "stable-nonce", {
    nonce_hex: "11".repeat(32),
    is_for_update_noc: false,
    expected_tlv_b64: "",
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
