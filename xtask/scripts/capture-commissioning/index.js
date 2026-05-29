// xtask capture-commissioning — placeholder.
//
// To wire: pin against the current `@matter/protocol`
// `CommissioningManager` (or `CommissionerNode`) API in this directory's
// `package.json`, then implement a script that:
//
// 1. Constructs a CommissionerNode (or whatever the current symbol is).
// 2. Monkey-patches the device-network layer to capture every outgoing
//    Invoke / ReadAttribute payload (the raw TLV bytes, not the parsed
//    struct — byte-parity is the whole point).
// 3. Runs commissioning against matter.js's device-simulator (or a real
//    device's IP + setup code, behind an env-var gate).
// 4. Writes test-vectors/commissioning/e2e/happy-path.json with:
//    {
//      "fabric_id":                       "0x0000000000000001",
//      "commissioner_node_id":            "0x...",
//      "assigned_node_id":                "0x...",
//      "ipk_epoch_key_b64":               "...",            // 16 bytes
//      "pase_attestation_challenge_b64":  "...",            // 16 bytes
//      "stages": [
//        { "stage": "ReadCommissioningInfo", "action": "ReadAttribute",
//          "cluster": "0x0030", "attribute_ids": [0, 1, 2, 4],
//          "expected_payload_b64": null,
//          "response_payload_b64": "..." },
//        { "stage": "ArmFailsafe", "action": "Invoke",
//          "cluster": "0x0030", "command": "0x00",
//          "expected_payload_b64": "FSQAPCQBAA4=",
//          "response_payload_b64": "FSQAABg=" },
//        ...
//      ]
//    }
//
// See TODO-1.0.md "matter.js capture-commissioning — operator wiring"
// for the current pinning instructions.
//
// Until this is wired the `commissioning_byte_parity.rs` integration test
// skips with `eprintln!` (the fixture file is missing/empty).

// M6.5 capture points (operator wiring required):
//   1. NetworkCommissioning::FeatureMap attribute read on endpoint 0.
//      Hook into matter.js's `commissioner.readAttribute({ endpointId: 0,
//      clusterId: 0x0031, attributeId: 0xFFFC })` call and record the
//      outbound request bytes.
//   2. AddOrUpdateWiFiNetwork invoke. Hook into the
//      `NetworkCommissioning.commands.addOrUpdateWiFiNetwork({ssid,
//      credentials, breadcrumb})` call; record the encoded payload bytes.
//   3. Second ArmFailSafe invoke (re-arm before ConnectNetwork). Identical
//      shape to the first ArmFailSafe — caller distinguishes by stage.
//   4. ConnectNetwork invoke. Hook into
//      `NetworkCommissioning.commands.connectNetwork({networkId,
//      breadcrumb})`; record the encoded payload bytes.
//
// Write the captured bytes into the corresponding `expected_payload_b64`
// fields in `test-vectors/commissioning/e2e/happy-path.json` (or its
// successor schema). The byte-parity test stops skipping when those
// fields are non-empty.

console.error(
  "capture-commissioning placeholder: wire against current @matter/protocol API",
);
process.exit(2);
