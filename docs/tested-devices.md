# Devices tested against `matter-rust`

CLAUDE.md asks us to record which Matter devices we have commissioned/controlled.
Fill a row each time you run `docs/runbooks/m6.6-first-commission.md` against a device.

| Device (make/model) | VID:PID | Path (A real / B rs-matter) | Date | matter.js trace diff | Notes |
|---|---|---|---|---|---|
| TP-Link Tapo P110M smart plug | 0x1392:0x0109 (TXT `VP=5010+265`) | A (real, production attestation: PAA `Tapo Matter PAA`, CD signed by CSA `Key 003`) | 2026-06-06 | pending (M6.6 cross-verification step) | Second-fabric commission over IP via ECM window; Wi-Fi device already on-network (network setup skipped). Full flow: PASE → DAC/PAI chain → CD → CSR → AddTrustedRoot → AddNOC → CASE → CommissioningComplete. Surfaced 11 real-device conformance fixes (see M6.6.5 commit). |

**Deferred:** factory-fresh Tuya Wi-Fi plug over BLE — blocked on BLE transport (post-v1.0).
