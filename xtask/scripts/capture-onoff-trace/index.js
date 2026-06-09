/**
 * matter.js half of the M7.5 OPERATIONAL trace cross-verification pair.
 *
 * Sibling of `capture-commission-trace`. That script stops after
 * commissioning ("keep the trace clean"); THIS one continues: it connects to
 * the just-commissioned node and performs the same five operations the Rust
 * `control_onoff` example does — read OnOff.OnOff, invoke OnOff.Toggle, read
 * OnOff.OnOff again, write BasicInformation.NodeLabel = "matter-rust", read it
 * back — so the operational Read/Invoke/Write dialogue lands in the trace for
 * `cargo xtask trace-diff` against the Rust side.
 *
 * Dumps EVERY decrypted wire message as JSON lines, in the trace-diff schema
 * consumed by the Rust side (`cargo xtask trace-diff`):
 *
 *   {"seq":N,"dir":"tx"|"rx","session_id":N,"exchange":N,
 *    "protocol":N,"opcode":N,"payload":"<lowercase hex>"}
 *
 * `protocol` is the 16-bit protocol short id (0 = SecureChannel,
 * 1 = InteractionModel). `opcode` is the message type. We capture
 * everything, including MRP acks; the Rust differ filters those itself.
 *
 * Usage:
 *   node index.js --manual 12345678901 [--out <path>]
 *   node index.js --qr "MT:..."        [--out <path>]
 *
 * --out defaults to trace.jsonl in the current directory. The output
 * directory is created automatically (including missing parents), so
 * you can pass a path like ../../../runs/matterjs-p110m.jsonl without
 * pre-creating the runs/ directory.
 *
 * Notes for the operator:
 *   - Run AFTER the Rust `control_onoff` example on the same (re-reset) device,
 *     then diff the two traces: `cargo xtask trace-diff <rust> <matterjs>`.
 *   - Storage is IN-MEMORY: every run is factory-fresh, nothing persists
 *     between runs. There is no controller state on disk to clean up.
 *   - On success the script REMOVES ITS OWN FABRIC from the device
 *     (removeNode with tryDecommissioning=true) before exiting, so the
 *     device's fabric slot is freed and it can be re-commissioned next run.
 *   - The trace contains the operational Read/Invoke/Write dialogue on top of
 *     the commissioning exchange. matter.js may emit a few extra structure
 *     reads on connect; trace-diff reports those as TheirsOnly, not failures.
 *   - Progress is logged to STDERR. STDOUT is kept clean.
 *   - The trace file is written synchronously line-by-line, so a crash
 *     mid-run still leaves the partial trace on disk for inspection.
 *   - Decrypted traces contain DAC chains, NOCs and fabric ids — keep the
 *     output under /runs/ (gitignored). Do not commit captured traces.
 *   - Bad pairing codes (wrong checksum, wrong format) are reported to
 *     STDERR and the script exits 2 — no network activity is started.
 */

import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

// Side-effect import: registers the Node.js platform services (Crypto,
// Network, mDNS) on Environment.default. Without this the controller throws
// "Required dependency Network is not available" during start().
import "@matter/nodejs";

import { Environment, Logger, MockStorageService, StorageService } from "@matter/general";
import { MessageCodec } from "@matter/protocol";
import { EndpointNumber, ManualPairingCodeCodec, QrPairingCodeCodec } from "@matter/types";
import {
  BasicInformation,
  GeneralCommissioning,
  OnOff,
} from "@matter/types/clusters";
import { CommissioningController } from "@project-chip/matter.js";

// --- CLI ---------------------------------------------------------------------

function usage() {
  process.stderr.write(
    [
      "capture-commission-trace — matter.js half of the M6 trace pair",
      "",
      "Usage:",
      "  node index.js --manual <11-digit-code> [--out <path>]",
      "  node index.js --qr <MT:...>            [--out <path>]",
      "",
      "Exactly one of --manual / --qr is required.",
      "--out defaults to trace.jsonl (current directory).",
      "The output directory is created automatically if it does not exist.",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const args = { manual: undefined, qr: undefined, out: "trace.jsonl" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--manual") args.manual = argv[++i];
    else if (a === "--qr") args.qr = argv[++i];
    else if (a === "--out") args.out = argv[++i];
    else {
      process.stderr.write(`unknown argument: ${a}\n`);
      return undefined;
    }
  }
  // Exactly one pairing input.
  if ((args.manual === undefined) === (args.qr === undefined)) return undefined;
  if (args.out === undefined) return undefined;
  return args;
}

// --- pairing-code parsing ----------------------------------------------------

/**
 * Returns { passcode, identifierData } where identifierData is a
 * CommissionableDeviceIdentifiers (shortDiscriminator for a manual code,
 * longDiscriminator for a QR code).
 */
function parsePairing(args) {
  if (args.manual !== undefined) {
    // ManualPairingCodeCodec.decode -> { passcode, shortDiscriminator?, ... }
    // (see PairingCodeSchema.d.ts: ManualPairingData). A manual code only
    // carries the *short* (4-bit) discriminator.
    const data = ManualPairingCodeCodec.decode(args.manual);
    return {
      passcode: data.passcode,
      identifierData: { shortDiscriminator: data.shortDiscriminator },
    };
  }
  // QrPairingCodeCodec.decode -> QrCodeData[] (one payload per device in the
  // code). We commission the first payload. A QR code carries the full
  // (12-bit) discriminator.
  const payloads = QrPairingCodeCodec.decode(args.qr);
  const data = payloads[0];
  return {
    passcode: data.passcode,
    identifierData: { longDiscriminator: data.discriminator },
  };
}

// --- wire capture ------------------------------------------------------------

function toHex(bytes) {
  // `bytes` is a Uint8Array (matter.js `Bytes`).
  return Buffer.from(bytes).toString("hex");
}

/**
 * Installs the trace patches on the MessageCodec statics. Returns nothing;
 * patches stay installed for the lifetime of the process.
 *
 * encodePayload(message)         is the TX boundary — plaintext just before
 *                                the payload is serialized + encrypted. We
 *                                read the *argument* (a `Message`).
 * decodePayload(decodedPacket)   is the RX boundary — it returns the decrypted
 *                                `DecodedMessage`. We read the *return value*.
 *
 * matter.js stores `protocolId` as a 32-bit (vendorId << 16 | protocolShortId)
 * value (see MessageCodec.js: `protocolId = vendorId << 16 | readUInt16()`).
 * The trace-diff schema's `protocol` field is the 16-bit protocol short id, so
 * we mask to the low 16 bits.
 */
function installCapture(outPath) {
  // Ensure the output directory exists (creates all missing parents).
  mkdirSync(dirname(outPath), { recursive: true });
  // Truncate/create the output file up front.
  writeFileSync(outPath, "");

  let seq = 0;

  function record(dir, message) {
    const line = {
      seq: seq++,
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

  // TX record is optimistic — captured before encode; if encode throws, the
  // trace carries a final TX entry for a message that was never actually sent.
  MessageCodec.encodePayload = (message) => {
    try {
      record("tx", message);
    } catch (e) {
      process.stderr.write(`warn: trace record failed (tx): ${e?.message}\n`);
    }
    return origEncode(message);
  };

  MessageCodec.decodePayload = (decodedPacket) => {
    // origDecode throwing is a real codec failure — let it propagate.
    const decoded = origDecode(decodedPacket);
    try {
      record("rx", decoded);
    } catch (e) {
      process.stderr.write(`warn: trace record failed (rx): ${e?.message}\n`);
    }
    return decoded;
  };
}

// --- main --------------------------------------------------------------------

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args === undefined) {
    usage();
    process.exit(2);
  }

  // Route matter.js's own logging to STDERR so STDOUT stays clean (STDOUT is
  // reserved for nothing here, but a clean stdout makes this safe to pipe).
  if (Logger.destinations.default != null) {
    Logger.destinations.default.write = (text) => process.stderr.write(text + "\n");
  }

  // Parse the pairing code first — fail fast on a bad code before touching
  // the network or installing patches.
  let passcode, identifierData;
  try {
    ({ passcode, identifierData } = parsePairing(args));
  } catch (e) {
    process.stderr.write(
      `error: could not parse pairing code (bad checksum or wrong format): ${e?.message}\n`,
    );
    process.exit(2);
  }
  process.stderr.write(
    `parsed pairing: passcode set, identifier=${JSON.stringify(identifierData)}\n`,
  );

  // Install the wire-capture patches and truncate the out file. From here on
  // the partial trace survives even if commissioning crashes.
  installCapture(args.out);
  process.stderr.write(`capturing trace to ${args.out}\n`);

  // Use the default Node environment so the platform services (Crypto,
  // network, mDNS) are wired up — a bare `new Environment(...)` has no Crypto
  // and the controller constructor throws. We then swap the StorageService for
  // a MockStorageService, which is matter.js's pure in-memory storage service
  // (defaults to MemoryStorageDriver, no disk drivers registered). Nothing is
  // read from or written to disk, so every run starts factory-fresh.
  const environment = Environment.default;
  environment.set(StorageService, new MockStorageService(environment));

  const controller = new CommissioningController({
    environment: { environment, id: "matter-rust-capture" },
    // We connect manually after commissioning (getNode) and issue discrete
    // operations. autoConnect/autoSubscribe are OFF so matter.js does NOT
    // start a subscribe-all storm — that would flood the trace with reports
    // the minimal Rust example never sends. Some structure-discovery reads
    // still occur on connect; trace-diff tolerates those as TheirsOnly extras.
    autoConnect: false,
    autoSubscribe: false,
    adminFabricLabel: "matter-rust capture",
  });

  let nodeId;
  try {
    await controller.start();
    process.stderr.write("controller started; commissioning...\n");

    nodeId = await controller.commissionNode(
      {
        // IP-network discovery using the identifier from the pairing code.
        discovery: { identifierData },
        passcode,
        // Regulatory config is mandatory in matter.js's commissioning flow
        // (step 8.1 SetRegulatoryConfig fails with a missing-field error
        // otherwise — observed on the P110M first run). IndoorOutdoor + "XX"
        // (unknown country) — matching what our Rust driver sends, so the
        // SetRegulatoryConfig invokes pair byte-for-byte in trace-diff
        // (modulo the run-specific breadcrumb counter).
        commissioning: {
          regulatoryLocation:
            GeneralCommissioning.RegulatoryLocationType.IndoorOutdoor,
          regulatoryCountryCode: "XX",
        },
      },
      // Do not connect to the node after commissioning — keep the trace clean.
      { connectNodeAfterCommissioning: false },
    );

    process.stderr.write(`commissioned node ${nodeId}\n`);

    // ---- Operational phase: connect and run the five operations the Rust
    // ---- control_onoff example performs, so they land in the trace. ---------
    //
    // matter.js high-level controller API (@matter 0.17.1):
    //   - controller.getNode(nodeId)                → PairedNode
    //   - node.getClusterClientForDevice(ep, OnOff.Complete)
    //   - client.get<Attr>Attribute(true)           → forced remote read (on the wire)
    //   - client.<command>()                         → invoke (e.g. toggle())
    //   - client.set<Attr>Attribute(value)           → write
    // OPERATOR: confirm these five exchanges appear in the trace on the device
    // run; the accessor names follow matter.js's stable generated convention.
    process.stderr.write("connecting to node for operational ops...\n");
    const node = await controller.getNode(nodeId);
    // Wait until the node model is built (endpoints/clusters known) before
    // resolving cluster clients.
    if (!node.initialized) {
      await node.events.initialized;
    }

    const onOff = node.getClusterClientForDevice(EndpointNumber(1), OnOff.Complete);
    if (!onOff) throw new Error("OnOff cluster client not found on endpoint 1");
    const before = await onOff.getOnOffAttribute(/* requestFromRemote */ true);
    process.stderr.write(`read OnOff.OnOff = ${before}\n`);
    await onOff.toggle();
    process.stderr.write("invoked OnOff.Toggle\n");
    const after = await onOff.getOnOffAttribute(true);
    process.stderr.write(`read OnOff.OnOff = ${after} (was ${before})\n`);

    const basicInfo = node.getRootClusterClient(BasicInformation.Complete);
    if (!basicInfo)
      throw new Error("BasicInformation cluster client not found on the root endpoint");
    await basicInfo.setNodeLabelAttribute("matter-rust");
    process.stderr.write('wrote BasicInformation.NodeLabel = "matter-rust"\n');
    const label = await basicInfo.getNodeLabelAttribute(true);
    process.stderr.write(`read BasicInformation.NodeLabel = ${JSON.stringify(label)}\n`);
  } catch (err) {
    process.stderr.write(`commissioning/operations failed: ${err?.stack ?? err}\n`);
    // Partial trace is already on disk. Best-effort close, then exit nonzero.
    try {
      await controller.close();
    } catch {
      // ignore close errors on the failure path
    }
    process.exit(1);
  }

  // Success: remove our own fabric from the device so its slot is freed.
  try {
    process.stderr.write("removing node (decommissioning our fabric)...\n");
    await controller.removeNode(nodeId, /* tryDecommissioning */ true);
    process.stderr.write("node removed\n");
  } catch (err) {
    // Non-fatal: the trace is captured. Surface the error but still exit 0.
    process.stderr.write(`warning: removeNode failed: ${err?.stack ?? err}\n`);
  }

  await controller.close();
  process.stderr.write("done\n");
  process.exit(0);
}

main().catch((err) => {
  // Last-resort handler. The partial trace (if any) is already on disk.
  process.stderr.write(`fatal: ${err?.stack ?? err}\n`);
  process.exit(1);
});
