# Devices tested against `matter-rust`

CLAUDE.md asks us to record which Matter devices we have commissioned/controlled.
Fill a row each time you run `docs/runbooks/m6.6-first-commission.md` against a device.

| Device (make/model) | VID:PID | Path (A real / B rs-matter) | Date | matter.js trace diff | Notes |
|---|---|---|---|---|---|
| TP-Link Tapo P110M smart plug | 0x1392:0x0109 (TXT `VP=5010+265`) | A (real, production attestation: PAA `Tapo Matter PAA`, CD signed by CSA `Key 003`) | 2026-06-06 | **PASSED 2026-06-07** — 10 MATCH / 16 MATCH* / 0 DIVERGENT vs matter.js 0.17.1; see `docs/m6-cross-verification.md` | Second-fabric commission over IP via ECM window; Wi-Fi device already on-network (network setup skipped). Full flow: PASE → DAC/PAI chain → CD → CSR → AddTrustedRoot → AddNOC → CASE → CommissioningComplete. Surfaced 11 real-device conformance fixes (see M6.6.5 commit). |
| TP-Link Tapo P110M smart plug | 0x1392:0x0109 | A (real, production attestation) | 2026-06-09 | commissioning 0 DIVERGENT vs matter.js 0.17.1 (re-confirmed); see `docs/m7.5-control-onoff-verification.md` | **M7.5 `control_onoff`:** commissioned, then over a fresh operational CASE session read `OnOff` (`true`) → `Toggle` → read (`false`) → write `BasicInformation.NodeLabel` (`"matter-rust"`) → read it back. Device accepted + acted on our exact operational bytes (the C++-reference runtime conformance check). Surfaced + fixed the `UnknownSession` recv-loop straggler bug. |

| chip-lighting-app (connectedhomeip reference example) | 0xFFF1:0x8000 | BLE (`commission_ble`, factory-fresh Wi-Fi provisioning over BTP) | pending morning validation | not yet run | M9-C1: implementation + byte-parity BTP vectors done; live central-vs-Pi-DUT handshake not yet run. See `docs/runbooks/ble-commissioning.md` (morning checklist) / `docs/runbooks/ble-dut-pi.md` (Pi DUT bring-up). |
| ESP32-C6 Matter-over-Thread light (esp-matter reference example) | 0xFFF1:0x8000 (disc 3840 / passcode 20202021) | BLE (`commission_ble`, Thread provisioning via `NetworkCredentials::Thread(ThreadDataset)` over BTP) through a Pi OTBR border router | **PASSED 2026-07-17** | chip-tool `pairing ble-thread` against the same DUT+OTBR is the reference; no byte-level diff captured (trace diff not run) | ★ **First pure-Rust Matter-over-Thread commission.** Commissioned from the Pi (BlueZ) with `examples/commission_ble_thread`: `node 0x…02`, `OnOff false → Toggle → true`, and the C6 attached to our mesh as router **`0x0c00`** (`ot-ctl neighbor table`, RSSI -18) — Thread-layer proof, independent of our own logs. Full path: BLE scan → BTP → PASE → attestation → NOC → `AddOrUpdateThreadNetwork` → `ConnectNetwork` → CASE over Thread → operational control. **Needed `--paa-dir` + `--cd-dir` (production `cd-certs`)** — see the CD-signer trap below. Surfaced 2 real bugs (`a8e07c72`, `0bc55173`). See `docs/runbooks/c2-thread-commission.md`. |

M9 sub-project C (BLE commissioning transport) is implemented in both halves: C1 (Wi-Fi) and C2
(Thread). **C2 is live-validated (row above); C1's Wi-Fi path is still landed-pending-live-validation.**
Both bugs the C2 run surfaced live in the BLE path C1 shares, so C1's live run should now get much
further than it would have before 2026-07-17.

## Attestation roots: what real devices actually need

The bundled `AttestationTrust::csa_test_roots()` default carries a **synthetic** CD signing root and
verifies **no real device** — it exists for our own tests. Any live run needs `--paa-dir` and
`--cd-dir` (mutually required), and the two do not come from the same place:

- **PAA** — chip's *test* PAA (`Chip-Test-PAA-FFF1`, vendored at
  `crates/matter-commissioning/src/attestation/csa_test_roots/`) for test DACs like the C6's;
  `credentials/production/paa-root-certs/` for certified retail devices (e.g. the Tapo P110M).
- **CD** — `credentials/production/cd-certs/`. **Yes, production, even for the test C6:** the
  VID=0xFFF1 CD that every `CONFIG_EXAMPLE_DAC_PROVIDER` device serves is signed by the CSA's
  production "CD Signing Key 001" (SKID `FE:34:3F:95:…`), *not* by chip's test CD authority
  (`62:FA:82:33:…`). chip's own verifier trusts both, so chip-tool never surfaces the distinction.
  Pinned by `crates/matter-commissioning/tests/chip_cd_vector.rs`.
