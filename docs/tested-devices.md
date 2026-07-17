# Devices tested against `matter-rust`

CLAUDE.md asks us to record which Matter devices we have commissioned/controlled.
Fill a row each time you run `docs/runbooks/m6.6-first-commission.md` against a device.

| Device (make/model) | VID:PID | Path (A real / B rs-matter) | Date | matter.js trace diff | Notes |
|---|---|---|---|---|---|
| TP-Link Tapo P110M smart plug | 0x1392:0x0109 (TXT `VP=5010+265`) | A (real, production attestation: PAA `Tapo Matter PAA`, CD signed by CSA `Key 003`) | 2026-06-06 | **PASSED 2026-06-07** — 10 MATCH / 16 MATCH* / 0 DIVERGENT vs matter.js 0.17.1; see `docs/m6-cross-verification.md` | Second-fabric commission over IP via ECM window; Wi-Fi device already on-network (network setup skipped). Full flow: PASE → DAC/PAI chain → CD → CSR → AddTrustedRoot → AddNOC → CASE → CommissioningComplete. Surfaced 11 real-device conformance fixes (see M6.6.5 commit). |
| TP-Link Tapo P110M smart plug | 0x1392:0x0109 | A (real, production attestation) | 2026-06-09 | commissioning 0 DIVERGENT vs matter.js 0.17.1 (re-confirmed); see `docs/m7.5-control-onoff-verification.md` | **M7.5 `control_onoff`:** commissioned, then over a fresh operational CASE session read `OnOff` (`true`) → `Toggle` → read (`false`) → write `BasicInformation.NodeLabel` (`"matter-rust"`) → read it back. Device accepted + acted on our exact operational bytes (the C++-reference runtime conformance check). Surfaced + fixed the `UnknownSession` recv-loop straggler bug. |

| ESP32-C6 Matter-over-Wi-Fi light (esp-matter reference example, `sdkconfig.defaults.esp32c6`) | 0xFFF1:0x8000 (disc 3840 / passcode 20202021) | BLE (`commission_ble`, Wi-Fi provisioning via `NetworkCredentials::WiFi` over BTP) | **PASSED 2026-07-17** | not run (no chip-tool Wi-Fi reference captured against this DUT) | **M9-C1 live-validated.** Commissioned from the Pi (BlueZ) with `examples/commission_ble_wifi`: `node 0x…02`, `OnOff true → Toggle → false`, and the C6 joined the `matrixiot` WLAN — `192.168.1.147` / `fe80::4af6:eeff:fec7:1914`, lladdr `48:f6:ee:c7:19:14` (its Wi-Fi STA MAC), `REACHABLE` in the Pi's neigh table — i.e. IP-layer proof, independent of our own logs. Full path: BLE scan → BTP → PASE → attestation → NOC → `AddOrUpdateWiFiNetwork` → `ConnectNetwork` (keyed by SSID) → operational CASE over IP. Passed first try, on the fixes the C2 run surfaced. Needed `--paa-dir` + `--cd-dir` (production `cd-certs`), same as C2. |
| chip-lighting-app on a Raspberry Pi (connectedhomeip reference example) | 0xFFF1:0x8000 | BLE (`commission_ble`, Wi-Fi over BTP) | superseded — not run | n/a | The originally-planned C1 DUT. The ESP32-C6 (row above) served this role instead once it arrived, so the Pi never needed to act as a BLE peripheral. `docs/runbooks/ble-dut-pi.md` is retained for the Pi-as-DUT path if a second BLE DUT is ever wanted. |
| ESP32-C6 Matter-over-Thread light (esp-matter reference example) | 0xFFF1:0x8000 (disc 3840 / passcode 20202021) | BLE (`commission_ble`, Thread provisioning via `NetworkCredentials::Thread(ThreadDataset)` over BTP) through a Pi OTBR border router | **PASSED 2026-07-17** | chip-tool `pairing ble-thread` against the same DUT+OTBR is the reference; no byte-level diff captured (trace diff not run) | ★ **First pure-Rust Matter-over-Thread commission.** Commissioned from the Pi (BlueZ) with `examples/commission_ble_thread`: `node 0x…02`, `OnOff false → Toggle → true`, and the C6 attached to our mesh as router **`0x0c00`** (`ot-ctl neighbor table`, RSSI -18) — Thread-layer proof, independent of our own logs. Full path: BLE scan → BTP → PASE → attestation → NOC → `AddOrUpdateThreadNetwork` → `ConnectNetwork` → CASE over Thread → operational control. **Needed `--paa-dir` + `--cd-dir` (production `cd-certs`)** — see the CD-signer trap below. Surfaced 2 real bugs (`a8e07c72`, `0bc55173`). See `docs/runbooks/c2-thread-commission.md`. |

**M9 sub-project C (BLE commissioning transport) is live-validated in both halves** as of
2026-07-17: C1 (BLE→Wi-Fi) and C2 (BLE→Thread), both against the ESP32-C6, both commissioned from
the Pi over BlueZ. C2 went first and surfaced the two BLE bugs (`a8e07c72`, `0bc55173`); C1 then
passed first try on those fixes.

### Known limitation: the BLE central hangs on macOS

Both live runs were driven from the **Pi (Linux/BlueZ)**. Commissioning from **macOS
(CoreBluetooth) hangs** and is not usable: on 2026-07-17 a `commission_ble_wifi` run from the Mac got
past the scan and far enough to install a NOC (the device's NVS held a fabric afterwards), then
stalled indefinitely — over 5 minutes, blowing through every deadline in the commissioning driver,
which means a stalled BTP pump rather than a rejected response (our timeouts only bound *awaited*
responses). Root cause unknown; not investigated. It rhymes with the long-standing "macOS chip-tool
BLE is broken (0x407 GATT write fail)" behaviour on this same rig, so the platform is suspect, but we
have no evidence either way — macOS has no `btmon`, and the examples emit no tracing mid-commission.

**Scanning on macOS works** (`ble_scan` finds the C6 reliably); it is GATT/BTP that hangs. Until this
is understood, drive live BLE commissioning from Linux.

★ Operational note: a failed attempt that reaches AddNOC leaves a fabric in the device's NVS, so it
boots "already commissioned" and stops advertising. Recovering needs an NVS erase over USB
(`esptool erase-region 0x10000 0xC000`) **plus a re-flash** — erasing alone leaves the app unbootable.

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
