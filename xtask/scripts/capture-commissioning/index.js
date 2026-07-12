/**
 * xtask capture-commissioning — matter.js half of the M6.4.6 byte-parity gate.
 *
 * Runs a matter.js VIRTUAL DEVICE (ServerNode, ethernet-only network
 * commissioning) and a matter.js commissioner (CommissioningController) in the
 * SAME process over loopback UDP + mDNS, and captures:
 *
 *   trace.jsonl   every decrypted wire message, in the trace-diff schema
 *                 ({seq, dir, session_id, exchange, protocol, opcode,
 *                 payload-hex}) — recorded at the MessageCodec boundary.
 *                 Both peers live in-process and share the patched statics,
 *                 so every message appears once as "tx" (sender side) and
 *                 once as "rx" (receiver side); the Rust post-processor
 *                 consumes only the "tx" records.
 *   meta.json     out-of-wire inputs the Rust fixture needs:
 *                 pase_attestation_challenge_b64 (from the PASE
 *                 NodeSession's attestationChallengeKey) and
 *                 cd_signing_spki_pem (the SPKI of matter.js's CD signing
 *                 key — chip's official TestCMS signer — so the parity test
 *                 can trust the captured Certification Declaration).
 *
 * The Rust side (`cargo xtask capture-commissioning`) then maps the trace
 * onto the Rust Commissioner's stage sequence and writes
 * test-vectors/commissioning/e2e/happy-path.json.
 *
 * Notes:
 *   - Storage is in-memory on both nodes: every run is factory-fresh.
 *   - The commissioner is configured with regulatoryLocation=Indoor and
 *     country "XX" to match the Rust state machine's SetRegulatoryConfig.
 *   - The device advertises vendorId 0xFFF1 / productId 0x8001, passcode
 *     20202021, discriminator 0xF00 — the same values hardcoded in
 *     crates/matter-commissioning/tests/commissioning_byte_parity.rs.
 */

import { mkdirSync, writeFileSync, appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Side-effect import: registers Node.js platform services (Crypto, Network,
// mDNS) on Environment.default.
import "@matter/nodejs";

import { Environment, Logger, MockStorageService, StorageService } from "@matter/general";
import { MessageCodec, NodeSession } from "@matter/protocol";
import { GeneralCommissioning } from "@matter/types/clusters";
import { CommissioningController } from "@project-chip/matter.js";
import { ServerNode } from "@matter/main";
import { OnOffLightDevice } from "@matter/main/devices/on-off-light";
import { NetworkCommissioningServer } from "@matter/main/behaviors/network-commissioning";
import { NetworkCommissioning } from "@matter/main/clusters/network-commissioning";

const OUT_DIR = dirname(fileURLToPath(import.meta.url));
const TRACE_PATH = join(OUT_DIR, "out", "trace.jsonl");
const META_PATH = join(OUT_DIR, "out", "meta.json");

const PASSCODE = 20202021;
const DISCRIMINATOR = 0xf00;

// --- wire capture (same MessageCodec boundary as capture-commission-trace) ---

function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function installCapture(outPath) {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, "");
  let seq = 0;

  function record(dir, message) {
    const line = {
      seq: seq++,
      // Monotonic milliseconds — lets post-analysis derive protocol-phase
      // wall-clock durations (e.g. the full CASE handshake) from the trace.
      ts_ms: performance.now(),
      dir,
      session_id: message.packetHeader.sessionId,
      exchange: message.payloadHeader.exchangeId,
      protocol: message.payloadHeader.protocolId & 0xffff,
      opcode: message.payloadHeader.messageType,
      payload: toHex(message.payload),
    };
    appendFileSync(outPath, JSON.stringify(line) + "\n");
  }

  const origEncode = MessageCodec.encodePayload.bind(MessageCodec);
  const origDecode = MessageCodec.decodePayload.bind(MessageCodec);
  MessageCodec.encodePayload = (message) => {
    try {
      record("tx", message);
    } catch (e) {
      process.stderr.write(`warn: trace record failed (tx): ${e?.message}\n`);
    }
    return origEncode(message);
  };
  MessageCodec.decodePayload = (decodedPacket) => {
    const decoded = origDecode(decodedPacket);
    try {
      record("rx", decoded);
    } catch (e) {
      process.stderr.write(`warn: trace record failed (rx): ${e?.message}\n`);
    }
    return decoded;
  };
}

// --- PASE attestation-challenge capture ---------------------------------------

const paseChallenges = [];

function installSessionCapture() {
  const origCreate = NodeSession.create.bind(NodeSession);
  NodeSession.create = async (config) => {
    const session = await origCreate(config);
    try {
      // PASE sessions have no fabric; both in-process peers create their
      // half of the same session, so the same challenge appears twice.
      if (config?.fabric === undefined || config?.fabric === null) {
        paseChallenges.push(Buffer.from(session.attestationChallengeKey).toString("base64"));
      }
    } catch (e) {
      process.stderr.write(`warn: session capture failed: ${e?.message}\n`);
    }
    return session;
  };
}

// --- CD signing key ------------------------------------------------------------

/**
 * matter.js signs virtual-device Certification Declarations with chip's
 * official test CMS signer key. Reproduce the public key as an SPKI PEM so
 * the Rust parity test can build a CdSigningRoots trusting exactly this
 * signer. The scalar is public knowledge (it ships in every matter.js and
 * connectedhomeip checkout); no secret is captured here.
 */
async function cdSigningSpkiPem() {
  const scalarHex = "AEF3484116E9481EC57BE0472DF41BF499064E5024AD869ECA5E889802D48075";
  const { createECDH } = await import("node:crypto");
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(scalarHex, "hex"));
  const point = ecdh.getPublicKey(); // 65-byte uncompressed SEC1
  // SPKI = fixed P-256 ecPublicKey header + uncompressed point.
  const header = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
  const spki = Buffer.concat([header, point]);
  const lines = spki.toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----\n`;
}

// --- main -----------------------------------------------------------------------

async function main() {
  if (Logger.destinations.default != null) {
    Logger.destinations.default.write = (text) => process.stderr.write(text + "\n");
  }

  installCapture(TRACE_PATH);
  installSessionCapture();
  process.stderr.write(`capturing trace to ${TRACE_PATH}\n`);

  // In-memory storage for BOTH nodes (set before either is created): every
  // run is factory-fresh, nothing persists under ~/.matter.
  const environment = Environment.default;
  environment.set(StorageService, new MockStorageService(environment));

  // ---- virtual device -----------------------------------------------------
  // Root endpoint carries an ETHERNET-flavoured Network Commissioning
  // cluster, mirroring chip's IP example apps: the Rust state machine's
  // ReadNetworkCommissioningInfo stage reads its FeatureMap (ethernet →
  // no Wi-Fi setup stages), so the fixture needs the cluster present.
  const EthernetNetworkCommissioningServer = NetworkCommissioningServer.with(
    NetworkCommissioning.Feature.EthernetNetworkInterface,
  );
  const networkId = new Uint8Array(32);
  const device = await ServerNode.create(
    ServerNode.RootEndpoint.with(EthernetNetworkCommissioningServer),
    {
      id: "capture-device",
      network: { port: 5541 },
      commissioning: { passcode: PASSCODE, discriminator: DISCRIMINATOR },
      productDescription: { name: "capture dev", deviceType: 0x0100 },
      basicInformation: {
        vendorName: "matter-rust",
        vendorId: 0xfff1,
        productName: "capture dev",
        productId: 0x8001,
        serialNumber: "capture-0001",
      },
      networkCommissioning: {
        maxNetworks: 1,
        interfaceEnabled: true,
        lastConnectErrorValue: 0,
        lastNetworkId: networkId,
        lastNetworkingStatus: NetworkCommissioning.NetworkCommissioningStatus.Success,
        networks: [{ networkId, connected: true }],
      },
    },
  );
  await device.add(OnOffLightDevice);
  await device.start();
  process.stderr.write("virtual device started\n");

  // ---- commissioner ---------------------------------------------------------
  const controller = new CommissioningController({
    environment: { environment, id: "matter-rust-capture" },
    autoConnect: false,
    adminFabricLabel: "matter-rust capture",
  });

  try {
    await controller.start();
    process.stderr.write("controller started; commissioning...\n");
    const nodeId = await controller.commissionNode(
      {
        discovery: { identifierData: { longDiscriminator: DISCRIMINATOR } },
        passcode: PASSCODE,
        commissioning: {
          regulatoryLocation: GeneralCommissioning.RegulatoryLocationType.Indoor,
          regulatoryCountryCode: "XX",
        },
      },
      { connectNodeAfterCommissioning: false },
    );
    process.stderr.write(`commissioned node ${nodeId}\n`);
  } catch (err) {
    process.stderr.write(`commissioning failed: ${err?.stack ?? err}\n`);
    try {
      await controller.close();
      await device.close();
    } catch {
      // best-effort shutdown on the failure path
    }
    process.exit(1);
  }

  const meta = {
    captured_at_unix: Math.floor(Date.now() / 1000),
    pase_attestation_challenge_b64: paseChallenges[0] ?? null,
    pase_challenge_samples: paseChallenges,
    cd_signing_spki_pem: await cdSigningSpkiPem(),
  };
  writeFileSync(META_PATH, JSON.stringify(meta, null, 2));
  process.stderr.write(`meta written to ${META_PATH}\n`);

  await controller.close();
  await device.close();
  process.stderr.write("done\n");
  process.exit(0);
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err?.stack ?? err}\n`);
  process.exit(1);
});
