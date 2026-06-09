# Devices tested against `matter-rust`

CLAUDE.md asks us to record which Matter devices we have commissioned/controlled.
Fill a row each time you run `docs/runbooks/m6.6-first-commission.md` against a device.

| Device (make/model) | VID:PID | Path (A real / B rs-matter) | Date | matter.js trace diff | Notes |
|---|---|---|---|---|---|
| TP-Link Tapo P110M smart plug | 0x1392:0x0109 (TXT `VP=5010+265`) | A (real, production attestation: PAA `Tapo Matter PAA`, CD signed by CSA `Key 003`) | 2026-06-06 | **PASSED 2026-06-07** — 10 MATCH / 16 MATCH* / 0 DIVERGENT vs matter.js 0.17.1; see `docs/m6-cross-verification.md` | Second-fabric commission over IP via ECM window; Wi-Fi device already on-network (network setup skipped). Full flow: PASE → DAC/PAI chain → CD → CSR → AddTrustedRoot → AddNOC → CASE → CommissioningComplete. Surfaced 11 real-device conformance fixes (see M6.6.5 commit). |
| TP-Link Tapo P110M smart plug | 0x1392:0x0109 | A (real, production attestation) | 2026-06-09 | commissioning 0 DIVERGENT vs matter.js 0.17.1 (re-confirmed); see `docs/m7.5-control-onoff-verification.md` | **M7.5 `control_onoff`:** commissioned, then over a fresh operational CASE session read `OnOff` (`true`) → `Toggle` → read (`false`) → write `BasicInformation.NodeLabel` (`"matter-rust"`) → read it back. Device accepted + acted on our exact operational bytes (the C++-reference runtime conformance check). Surfaced + fixed the `UnknownSession` recv-loop straggler bug. |

**Deferred:** factory-fresh Tuya Wi-Fi plug over BLE — blocked on BLE transport (post-v1.0).
