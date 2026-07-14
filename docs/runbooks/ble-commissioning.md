# Runbook: BLE commissioning on macOS (`commission_ble`, M9-C1)

This covers the **central** (our controller) side of BLE/BTP commissioning:
one-time macOS Bluetooth permission handling, then the full morning
validation checklist to exercise `MatterController::commission_ble` against
a real device for the first time.

> `commission_ble` scans for the device by discriminator, opens a BTP
> (Bluetooth Transport Protocol) session, and drives PASE + attestation + NOC
> install + Wi-Fi provisioning all over BLE, then completes the operational
> CASE session over IP once the device joins Wi-Fi and is reachable by mDNS.
> It requires a **Wi-Fi device with no BTP peripheral of its own to talk to
> yet** — see `docs/runbooks/ble-dut-pi.md` to stand one up.

## macOS Bluetooth permission (TCC)

`matter-ble`'s `central` feature uses `btleplug`, which on macOS wraps
CoreBluetooth. **`Manager::adapters()` — not `Manager::new()` — is the
actual TCC (Transparency, Consent, and Control) trigger**: the first call
that touches it instantiates a `CBCentralManager`, and if Bluetooth
permission has never been decided for the requesting app, macOS raises the
one-time system permission prompt and blocks until it's answered.

The critical thing to understand before you run anything: **the prompt is
attributed to the terminal application you're running in — Terminal.app,
iTerm2, VS Code's integrated terminal, etc. — not to the `cargo`-built
binary itself.** Whichever app owns the process that ends up calling
`CBCentralManager` is the one macOS will remember granting/denying
Bluetooth to. If you routinely switch terminal apps, you'll need to grant
this once per app.

### One-time approval

Because of the above, and because a denied/never-decided permission would
otherwise make BLE scanning **silently find nothing** (`btleplug` has a
known gap here — it does not surface "no permission" as a distinct error
from "no devices found"), `matter-ble`'s `BleCentral::new()` explicitly
checks `adapter_state() == PoweredOn` and returns an error pointing back at
this runbook rather than failing silently.

Run the diagnostic example, gated behind `MATTER_BLE_LIVE=1` so a plain
`cargo test`/CI run never touches Bluetooth:

```sh
MATTER_BLE_LIVE=1 cargo run -p matter-controller --example ble_scan --features ble
```

- If this is the first time *this terminal app* has asked for Bluetooth,
  macOS shows the permission dialog — **Allow**.
- Confirm it stuck: **System Settings → Privacy & Security → Bluetooth** —
  your terminal app should be listed and toggled on.

Once approved for a given terminal app, every later `cargo run`/`cargo
test` invocation from that same app needs no further prompt for the life of
the permission grant.

### Recovery if previously denied

If you clicked "Don't Allow" (or the app is listed but toggled off) in
**System Settings → Privacy & Security → Bluetooth**, re-enable it there
directly — toggle your terminal app **on**. macOS does not always re-prompt
after a denial; `tccutil reset Bluetooth` (as an admin) clears the decision
system-wide so the next `MATTER_BLE_LIVE=1` run prompts again, if you'd
rather start clean.

### Why this stays out of CI / nightly

Unattended runners have no one to answer a TCC dialog, and a first-time
Bluetooth prompt blocks the calling thread indefinitely. `MATTER_BLE_LIVE=1`
is the same opt-in-gate pattern as `MATTER_INTEGRATION_DUT`
(`crates/integration-tests/src/lib.rs`) for exactly this reason: BLE-live
tests are **operator-gated only** and will never run in default `cargo
test`, CI, or the nightly integration workflow.

---

## Morning validation checklist

Run these in order against a fresh factory Pi DUT
(`docs/runbooks/ble-dut-pi.md`). Each step should pass before moving to the
next — this is the first real end-to-end BLE commission, so treat any
failure as "investigate before continuing," not "retry and hope."

- [ ] **1. TCC approve.** `MATTER_BLE_LIVE=1 cargo run -p matter-controller
      --example ble_scan --features ble`, answer the Bluetooth prompt, verify
      under System Settings → Privacy & Security → Bluetooth (see above).

- [ ] **2. Bring the Pi DUT up.** Follow
      `docs/runbooks/ble-dut-pi.md` end to end: `bluetoothd -E -P battery`,
      `wpa_supplicant` in D-Bus mode, build, factory-reset (`rm -f
      /tmp/chip_*`), then launch:
      ```sh
      sudo ./out/linux-arm64-lighting/chip-lighting-app --wifi \
          --discriminator 3840 --passcode 20202021
      ```
      It's now advertising (discriminator `3840` / `0xF00`) for ~15 minutes.

- [ ] **3. Live scan finds it.** Re-run `ble_scan` (same TCC-approved
      terminal app):
      ```sh
      MATTER_BLE_LIVE=1 cargo run -p matter-controller --example ble_scan --features ble
      ```
      **Pass:** it prints `found: discriminator=0xf00 vid=... pid=... id=...`
      for the Pi. If nothing answers, re-check `bluetoothd` flags and that
      the Pi is still within its ~15-minute advertising window (factory-reset
      and relaunch it if the window lapsed).

- [ ] **4. `btmon` capture → de-provisionalize the BTP vectors → commit.**
      With `btmon` running on the Pi (`ble-dut-pi.md` §6), drive one more
      scan or a partial handshake attempt from the Mac so a real BTP
      handshake happens over the air, then extract the C2 handshake-response
      indication and compare it against
      `test-vectors/btp/handshake.json`'s `expected_chip_peripheral_response`
      (currently `"provisional": true` — its fragment-size assumption of 244
      is unconfirmed). Update the vector (flip `provisional` to `false`, or
      correct the bytes if the real capture disagrees) and, for extra
      confidence, sanity-check the captured raw advertisement against
      `test-vectors/btp/advert.json`'s `pi_default_disc` entry (already
      `provisional: false`; no edit expected there). Run `cargo test -p
      matter-ble` to confirm the vector-driven tests still pass, then commit
      the updated vector(s).

- [ ] **5. End-to-end `commission_ble` with real Wi-Fi credentials.** There
      is no packaged CLI example yet for the BLE path (only the `ble_scan`
      diagnostic exists) — adapt `examples/controller_quickstart.rs`'s
      controller setup, swapping its `controller.commission(code)` call for
      `commission_ble`:
      ```rust
      // operator pseudocode — not compiled by `cargo test`
      use matter_commissioning::WiFiCredentials;

      let wifi = WiFiCredentials {
          ssid: b"<your-2.4GHz-SSID>".to_vec(),
          credentials: b"<your-wifi-password>".to_vec(),
      };
      let node_id = controller
          .commission_ble("MT:Y.K90AFN00KA0648G00", wifi)
          .await?;
      println!("commissioned over BLE as node 0x{node_id:016X}");
      ```
      The setup code above is chip's standard example QR (discriminator
      `3840` / passcode `20202021`, matching step 2's `chip-lighting-app`
      invocation) — substitute the Pi's actual manual/QR code if you changed
      either flag. Use a **2.4 GHz** network; `chip-lighting-app`'s Wi-Fi
      stack does not associate to 5 GHz-only SSIDs.
      **Pass:** the call returns `Ok(node_id)` — PASE, attestation, NOC
      install, and Wi-Fi provisioning all completed over BTP, and the
      operational CASE handshake completed over IP once the device
      associated and announced over mDNS.

- [ ] **6. Verify operational CASE + an OnOff toggle post-commission.**
      Using the returned `node_id` (same pattern as
      `controller_quickstart.rs` steps 4–5): read `OnOff`, invoke `Toggle`,
      read it back and confirm it flipped. This proves the **IP** path is
      healthy after a **BLE**-driven commission — the resumed/fresh CASE
      session targets the device's real operational address (see the
      CHANGELOG behavior-change note: post-CASE traffic now targets the
      mDNS-resolved operational address rather than the commissionable one).

- [ ] **7. Record the device.** Add a row to `docs/tested-devices.md` for
      the Pi DUT / `chip-lighting-app`, noting the BLE path explicitly (VID
      `0xFFF1` / PID `0x8000`, the chip example defaults) and the date.

## Reference

- Design: `docs/superpowers/specs/2026-07-13-m9-c1-ble-btp-design.md`, §D9
  and "Overnight / morning split".
- Peripheral-side runbook: `docs/runbooks/ble-dut-pi.md`.
- API: `MatterController::commission_ble`
  (`crates/matter-controller/src/controller.rs`).
