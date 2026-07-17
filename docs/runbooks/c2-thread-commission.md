# Runbook: BLE→Thread commissioning (`commission_ble`, M9-C2)

This covers the **live** validation of Matter-over-Thread commissioning: our
controller (the central) commissions a Thread device over BLE/BTP, provisions
it onto an existing Thread network from an operational dataset, and confirms
it joins the mesh and answers operational Thread traffic.

> `commission_ble` scans for the device by discriminator, opens a BTP
> (Bluetooth Transport Protocol) session, and drives PASE + attestation + NOC
> install + network provisioning all over BLE. For a Thread device, "network
> provisioning" means `AddOrUpdateThreadNetwork` with the operational
> dataset bytes, then `ConnectNetwork` keyed by the dataset's Extended
> PAN ID — see D3/D5 in
> `docs/superpowers/specs/2026-07-17-m9-c2-thread-commissioning-design.md`.
> Everything else (BTP handshake, PASE, attestation, CSR/NOC, the operational
> CASE handshake once the device is reachable) is identical to the C1
> Wi-Fi path — see `docs/runbooks/ble-commissioning.md` for that shared
> groundwork (macOS TCC handling in particular, if you run from a Mac).

This is the Thread counterpart to `docs/runbooks/ble-commissioning.md` (C1,
Wi-Fi). Read that runbook first if you haven't driven `commission_ble` at
all yet — this one only covers what's different for Thread.

## Rig (validated 2026-07-17)

- **Pi OTBR border router** — an nRF52840 RCP attached to a Raspberry Pi
  running `otbr-agent`, formed as the Thread network leader.
- **ESP32-C6 Matter-over-Thread light** (esp-matter reference firmware) —
  the DUT. Discriminator `3840` (`0xF00`), passcode `20202021` (chip's
  standard example defaults, same as the C1 `chip-lighting-app` DUT).
- A chip-tool `pairing ble-thread` reference commission has already
  succeeded end-to-end against this rig (from the Pi's BlueZ), and the C6
  was controlled over Thread afterward. That trace is the byte-parity
  reference for step 6 below.

**Why the Pi, not the Mac, drives the live commission:** macOS chip-tool's
BLE stack is broken against this rig (`0x407` GATT write failures observed
during rig validation). `matter-ble`'s `btleplug` central role is a
different BLE stack and *may* work from macOS (it already works for the
`ble_scan` diagnostic per the C1 runbook) — but it's unproven for a full
BTP handshake against the C6. The Pi's BlueZ path is the one that's
actually been proven end-to-end (by chip-tool) against this hardware, so it
is the safe path for the first live matter-rust commission. Once this run
is validated, retrying from macOS is a reasonable follow-up, not a
prerequisite.

## 1. Bring the OTBR up and capture the current dataset

SSH to the Pi (`admin@192.168.1.30`) and confirm the border router is
leading its Thread network:

```sh
sudo ot-ctl state
```

**Pass:** prints `leader`. If it prints anything else (`disabled`,
`detached`, `child`), the OTBR isn't formed/attached — fix that before
continuing (out of scope for this runbook; see the OTBR's own setup docs).

Capture the **current** active operational dataset as hex:

```sh
sudo ot-ctl dataset active -x
```

This prints a single hex blob — the Thread Operational Dataset TLV bytes
(the exact input `ThreadDataset::new` expects, hex-decoded).

**Important — the Extended PAN ID rotates if the network re-forms.** Every
prior capture of this dataset (including the one frozen into
`crates/matter-commissioning/src/thread_dataset.rs`'s unit test and
`test-vectors/thread/network_commissioning.json`) is only valid for that
run of the OTBR. **Always re-run `ot-ctl dataset active -x` immediately
before a live attempt** and derive the expected Extended PAN ID from *that*
output, not from a stale copy-pasted value. The Extended PAN ID is the
Thread TLV `type 0x02, length 8` element inside the dataset blob — the
first `02 08 <16 hex chars>` you see walking the dataset from offset 0 (see
`ThreadDataset::ext_pan_id`'s doc comment for the exact walk).

## 2. Factory-reset the C6 so it BLE-advertises fresh

Same rule as the C1 DUT (`docs/runbooks/ble-dut-pi.md` §5): a device that
was previously commissioned (by chip-tool's reference run, or a prior
matter-rust attempt) is **not advertising** and has state to clear before
it will answer a new BLE scan.

- If the C6 is currently commissioned to a fabric (e.g. still holding the
  chip-tool reference commission), unpair it via chip-tool:
  ```sh
  chip-tool pairing unpair <node-id>
  ```
- If that's not available or the device is in an unknown state, re-flash
  the esp-matter firmware (clears NVS-persisted fabric/commissioning
  state) or use the device's factory-reset button/sequence per the
  esp-matter example's documentation.
- Confirm it's advertising again — either watch for it in a live scan
  (step 4 below) or check the device's own log output for "commissioning
  window open" / BLE advertising start.

Like the C1 Pi DUT, expect a bounded advertising window (device-dependent;
don't assume it stays open indefinitely) and expect it to **stop
advertising the instant a central connects** — a failed/aborted attempt
leaves it not advertising and with an armed failsafe, so re-run this step
between attempts.

## 3. Build matter-rust on the Pi

The Pi is the safe BLE path (step above), so the commissioner binary runs
there too. Source is already staged at `~/matter-rust` on the Pi and this
combination (Linux arm64 + BlueZ) is cross-platform-validated per the M9-C2
design doc.

```sh
ssh admin@192.168.1.30
cd ~/matter-rust
git pull   # pick up this runbook + the C2 code if not already present
cargo build -p matter-controller --example ble_scan --features ble --release
```

(`ble_scan` first, to confirm BLE + TCC-equivalent permissions work on the
Pi before attempting the full commission — BlueZ on Linux has no macOS-style
TCC prompt, but confirming `bluetoothd -E -P battery` is running per
`docs/runbooks/ble-dut-pi.md` §2 is still worth doing here since the Pi is
now acting as commissioner rather than peripheral.)

```sh
MATTER_BLE_LIVE=1 cargo run -p matter-controller --example ble_scan --features ble --release
```

**Pass:** it finds the C6 by discriminator (`0xF00` / `3840`) once step 2's
factory-reset has it advertising.

Then build the packaged commission binary:

```sh
cargo build -p matter-controller --example commission_ble_thread --features ble --release
```

### Attestation roots (required — the defaults do NOT work)

The bundled `AttestationTrust::csa_test_roots()` carries a **synthetic** CD
signing root that verifies no real device. The C6 serves chip's
`ExampleDACProvider` VID=0xFFF1 CD, which is signed by the CSA's
**production** "CD Signing Key 001" (SKID `FE:34:3F:95:…`) — *not* by
chip's test CD authority. Trusting only the test authority fails the run
with `certification declaration signature does not verify against any
trusted root`. (chip-tool trusts test + production keys, so it never
noticed.) Pinned by `crates/matter-commissioning/tests/chip_cd_vector.rs`.

From a connectedhomeip checkout, stage both stores on the Pi:

```sh
# CD roots: the CSA production mirror is the one that matters for the C6.
scp <chip>/credentials/production/cd-certs/*.der admin@<pi>:~/cd-roots/
# PAA roots: the C6's DAC chains to chip's test PAA (vendored in our repo).
scp crates/matter-commissioning/src/attestation/csa_test_roots/*.der \
    admin@<pi>:~/paa-roots/
```

`--paa-dir` and `--cd-dir` are mutually required; both take a directory of
`.der` files (non-`.der` entries are skipped).

## 4. Commission the C6 with `NetworkCredentials::Thread`

This is the exact command from the first successful live run (2026-07-17):

```sh
# Capture the dataset FRESH — the Ext-PAN-ID rotates if the network re-forms.
DS=$(sudo ot-ctl dataset active -x | head -1 | tr -d '\r')

MATTER_BLE_LIVE=1 ~/matter-rust/target/release/examples/commission_ble_thread \
    --store /tmp/matter-c6.bin \
    --commission "MT:-24J0AFN00KA0648G00" \
    --dataset "$DS" \
    --paa-dir ~/paa-roots \
    --cd-dir ~/cd-roots
```

`MT:-24J0AFN00KA0648G00` is the standard test QR payload for discriminator
`3840` / passcode `20202021` / VID `0xFFF1` / PID `0x8000`. Prefer the QR
code over the manual pairing code: the manual code carries only the *short*
(4-bit) discriminator, so the scan sweeps all 16 nibbles and takes longer.
A fresh `--store` path mints a new fabric; reusing one reuses its identity.

Expected output:

```text
Thread dataset accepted (111 bytes); expecting Ext-PAN-ID [78, 96, …]
created a new fabric (stable commissioner identity persisted)
commissioning over BLE→Thread (this can take up to ~90 s at network-enable …)
commissioned over BLE as node 0x0000000000000002
OnOff = false
OnOff after Toggle = true (flipped: true)
SUCCESS — commissioned and controlled node 0x… over Thread
```

**Pass:** the call returns `Ok(node_id)`. Internally this means: BTP
session → PASE → attestation → NOC install all completed over BLE, then
the device's `NetworkCommissioning.FeatureMap` read routed to the Thread
arm (`Stage::NetworkSetup` → `AddOrUpdateThreadNetwork` carrying the full
dataset bytes → `Stage::FailsafeBeforeNetworkEnable` → `Stage::NetworkEnable`
→ `ConnectNetwork` keyed by the dataset's Extended PAN ID), the device
attached to the Thread mesh and registered its operational service via
SRP, and the operational CASE handshake completed over IP through the
OTBR's border-routed prefix.

If it hangs or times out at the network-enable step: Thread attach + SRP
registration is slower than Wi-Fi association, so the failsafe/response
deadline is sized from the device's advertised
`NetworkCommissioning.ConnectMaxTimeSeconds` (falling back to a 90 s
default if unread/zero — see `DEFAULT_CONNECT_MAX_TIME_SECONDS` in
`crates/matter-commissioning/src/state_machine/commissioner.rs`). A
genuine attach failure (bad dataset, C6 out of Thread range of the OTBR)
surfaces as a `NetworkConfigResponse`/`ConnectNetworkResponse` error
status, not a bare timeout, once that deadline is hit.

## 5. Verify the C6 joined the mesh

On the Pi (or wherever `ot-ctl` reaches the OTBR):

```sh
sudo ot-ctl neighbor table
```

**Pass:** the C6 appears as a child (or router, if it promotes) in the
neighbor table — this is Thread-layer proof the device actually attached
to the mesh using the provisioned dataset, independent of whether Matter
commissioning itself reports success.

## 6. Verify operational control over Thread

Using the returned `node_id`, confirm the operational CASE session is
healthy over the Thread-routed path (same pattern as
`ble-commissioning.md` step 6, and `controller_quickstart.rs` steps 4–5):
read `OnOff`, invoke `Toggle`, read it back and confirm it flipped. Either
matter-rust (a second small script/example against the same `node_id`) or
chip-tool's `onoff toggle <node-id> 1` both work for this check — the point
is confirming the device is reachable and controllable through the OTBR's
IPv6 border-routing, not re-testing commissioning itself.

## 7. Diff the trace against the chip-tool reference

The chip-tool `pairing ble-thread` reference commission (already captured
against this rig, per the M9-C2 design doc's "Rig" section) is the
byte-parity oracle. Compare matter-rust's BTP/commissioning trace against
it, focused on the network-provisioning fork (everything else is shared
with the already-verified C1 path):

- `AddOrUpdateThreadNetwork` (cluster `0x0031`, command `0x03`) payload —
  should carry the exact same operational dataset bytes captured in step 1,
  TLV-wrapped as `{ ctx0: dataset octet-string, ctx1: breadcrumb uint }`
  (see `encode_add_or_update_thread_network` in
  `crates/matter-commissioning/src/clusters/network_commissioning.rs`).
- `ConnectNetwork` (command `0x06`) — `network_id` should be the dataset's
  Extended PAN ID (8 bytes), not a Wi-Fi SSID.
- `NetworkConfigResponse` / `ConnectNetworkResponse` status codes on both
  sides should agree (both success, on a clean run).

If matter-rust's bytes disagree with the chip-tool reference here, per
CLAUDE.md the reference wins by default — investigate and fix rather than
rationalize the difference.

## 8. Record the device

Add/update the ESP32-C6 row in `docs/tested-devices.md` once this live run
passes, noting the live matter-rust commission date alongside the existing
chip-tool reference entry.

## Known carry-forward: Wi-Fi failsafe sizing recheck

Unrelated to Thread specifically, but surfaced during the M9-C2 design
review: `Stage::FailsafeBeforeNetworkEnable`'s default extension (used when
`ConnectMaxTimeSeconds` is unread/zero) moved from 60 s to 90 s
(`DEFAULT_CONNECT_MAX_TIME_SECONDS` in `commissioner.rs`) as part of
genericizing the network stages for Thread. This is a strictly larger
failsafe window and should be harmless for the C1 Wi-Fi path, but it
hasn't been re-exercised live against a real Wi-Fi device since the
change. Worth a quick real-device Wi-Fi recheck
(`docs/runbooks/ble-commissioning.md`) at some point — not blocking, just
flagged so it isn't forgotten.

## Reference

- Design: `docs/superpowers/specs/2026-07-17-m9-c2-thread-commissioning-design.md`.
- Shared BLE/BTP groundwork (macOS TCC, BTP capture, Pi DUT bring-up): C1's
  `docs/runbooks/ble-commissioning.md` and `docs/runbooks/ble-dut-pi.md`.
- API: `MatterController::commission_ble`
  (`crates/matter-controller/src/controller.rs`);
  `NetworkCredentials`/`ThreadDataset`
  (`crates/matter-commissioning/src/state_machine/commissioner.rs`,
  `crates/matter-commissioning/src/thread_dataset.rs`).
- In-process hermetic proof of the Thread fork (BTP mock, no hardware):
  `crates/matter-commissioning/tests/commission_ble_loopback.rs`'s "M9-C2
  Task 7" section.
- Byte-parity vectors: `test-vectors/thread/network_commissioning.json`.
