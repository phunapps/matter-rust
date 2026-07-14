# Runbook: Raspberry Pi as a factory-fresh BLE DUT (M9-C1)

This sets up a Raspberry Pi as a **factory-fresh, BLE-advertising chip
device-under-test** — the peripheral side of BLE/BTP commissioning. It is the
counterpart to `docs/runbooks/ble-commissioning.md`, which drives our
controller (the central) against this device.

> No real Matter product is required for this. `chip-lighting-app` is
> connectedhomeip's reference example device, built natively for the Pi. BLE
> commissioning is identical across every chip example (shared `Options.cpp`),
> so `lighting-app` was picked only because it is the smallest.

## Hardware / OS

- Raspberry Pi (3B+ or later; needs onboard or USB BLE) with **Ubuntu Server
  22.04 arm64** flashed via Raspberry Pi Imager. Headless is fine (SSH in).
- The board's native architecture is `arm64` — build **on the Pi itself**.
  Cross-compiling connectedhomeip's Linux examples from an x64/macOS host is
  documented territory for `x64`, not `arm64`; don't fight that here.

## 1. System dependencies

```sh
sudo apt update
sudo apt install -y \
    git gcc g++ pkg-config libssl-dev libdbus-1-dev libglib2.0-dev \
    ninja-build python3-venv python3-dev unzip bluez pi-bluetooth avahi-utils
```

- `libdbus-1-dev` / `libglib2.0-dev` — chip's BLE layer on Linux talks to
  BlueZ over D-Bus.
- `bluez` / `pi-bluetooth` — the BlueZ stack and the Pi's onboard-BLE
  firmware/systemd units.
- `avahi-utils` — mDNS (`avahi-browse`), useful to confirm the device's
  operational advertisement after it joins Wi-Fi.
- `python3-venv` / `python3-dev` / `ninja-build` / `unzip` — chip's GN/Ninja
  build pulls a Python virtualenv and toolchain archives.

## 2. `bluetoothd` override: `-E -P battery`

Matter's BLE transport needs BlueZ's **experimental** interface, and the
**battery** plugin has a failure mode that kills BLE mid-commissioning. Fix
both with a systemd override:

```sh
sudo systemctl edit bluetooth.service
```

Add:

```ini
[Service]
ExecStart=
ExecStart=/usr/lib/bluetooth/bluetoothd -E -P battery
```

- **`-E`** — enables BlueZ's experimental D-Bus interface. Matter's BLE
  transport (`chip::Ble`) depends on experimental GATT APIs that are not
  exposed without this flag.
- **`-P battery`** — disables the battery-reporting plugin. That plugin
  attempts a GATT auth exchange with the connecting central that has no
  bearing on Matter commissioning; when it fails (which it reliably does
  against a commissioner that never asked for it), BlueZ tears down the
  underlying connection — taking the BTP session with it, mid-handshake.
  Disabling the plugin removes the failure path entirely.

Apply it:

```sh
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
```

Verify the flags took (look for `-E` and `-P battery` in the process args):

```sh
ps aux | grep bluetoothd
```

## 3. `wpa_supplicant` in D-Bus control mode

The device joins Wi-Fi as the last commissioning stage (network
commissioning cluster), and chip drives that through `wpa_supplicant`'s
D-Bus API — not `nmcli`/NetworkManager. Run `wpa_supplicant` standalone,
under D-Bus control:

```sh
sudo systemctl stop wpa_supplicant   # if a distro unit already owns wlan0
```

`/etc/wpa_supplicant/wpa_supplicant.conf`:

```
ctrl_interface=DIR=/run/wpa_supplicant
update_config=1
```

Start it:

```sh
sudo wpa_supplicant -u -s -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf -B
```

- **`-u`** — enable the D-Bus control interface (`fi.w1.wpa_supplicant1`) —
  this is the interface chip's `ConnectivityManagerImpl` drives to add a
  network and associate.
- **`-s`** — log to syslog (so `journalctl` shows association attempts).
- **`-i wlan0`** — the Wi-Fi interface to manage.
- `-B` backgrounds it; leave it running for the whole session — it must
  already be up and idle (no configured network) before you launch
  `chip-lighting-app --wifi`.

## 4. Build connectedhomeip natively

```sh
git clone https://github.com/project-chip/connectedhomeip.git
cd connectedhomeip
git submodule update --init --recursive   # first time only, slow

source scripts/bootstrap.sh   # first time only: builds the Python venv + toolchain
source scripts/activate.sh    # every new shell after that

./scripts/build/build_examples.py --target linux-arm64-lighting build
```

`linux-arm64-lighting` is a single target string (`linux-arm64` platform,
`lighting` app) — `build_examples.py` resolves it to the right GN args
without any manual cross-toolchain setup, because this is native `arm64`.
The binary lands at `out/linux-arm64-lighting/chip-lighting-app`.

## 5. Factory-fresh run loop

chip persists commissioning state (fabric, keys, an **armed failsafe** after
a partial attempt) under `/tmp/chip_*`. For a repeatable "just advertised,
nothing commissioned yet" BLE run, wipe that state before every attempt:

```sh
sudo rm -f /tmp/chip_*
sudo ./out/linux-arm64-lighting/chip-lighting-app --wifi \
    --discriminator 3840 --passcode 20202021
```

- `--wifi` enables the Wi-Fi network-commissioning cluster (paired with the
  `wpa_supplicant` D-Bus setup in step 3).
- `--discriminator 3840` / `--passcode 20202021` are chip's standard example
  defaults (discriminator `0xF00`) — the same defaults `chip-lighting-app`,
  `chip-all-clusters-app`, etc. all ship with, and the value the BTP test
  vectors (`test-vectors/btp/advert.json`, `pi_default_disc`) were encoded
  against.

### Notes / gotchas

- The device advertises over BLE for **~15 minutes** after it starts, then
  stops on its own if nothing connects.
- It **stops advertising the moment a central connects** — a failed/aborted
  attempt (central disconnects, handshake error, PASE failure) leaves the
  device **not advertising** and with an **armed failsafe** that blocks a
  second commissioning attempt outright.
- Because of both of the above, **factory reset between attempts is the
  reliable loop**: `sudo rm -f /tmp/chip_*` then re-launch, every single
  time you want a clean BLE run — don't try to reuse a device instance
  across attempts.

## 6. `btmon` capture — de-provisionalizing the BTP test vectors

`test-vectors/btp/handshake.json` carries one entry
(`expected_chip_peripheral_response`) marked `"provisional": true` — its
`packet_hex` is a **hand-encoded assumption** (fragment size 244, a common
BLE default MTU) rather than an observed value from real BlueZ. Capture a
live handshake against this DUT to confirm or correct it.

1. Start a raw HCI capture on the Pi, then immediately drive a handshake
   from the central side (`docs/runbooks/ble-commissioning.md`, morning
   checklist step 4):

   ```sh
   sudo btmon -w /tmp/btp.snoop
   ```

   Leave it running, then from the Mac run the live scan / a BLE
   commissioning attempt so a real BTP handshake happens over the air.
   Stop `btmon` (Ctrl-C) once you see the handshake complete.

2. Open `/tmp/btp.snoop` (`btmon -r /tmp/btp.snoop`, or pull it to a host
   with Wireshark for GATT dissection) and find:
   - The **C2 handshake-response indication** — BlueZ's
     `BleTransportCapabilitiesResponseMessage` write on the C2
     characteristic, sent in reply to our capabilities request on C1. This
     is the 6-byte `BleTransportCapabilitiesResponseMessage::Encode` layout
     (`0x65 0x6c`, selected version, fragment size u16 LE, window) —
     compare its `packet_hex` byte-for-byte against
     `expected_chip_peripheral_response` in `handshake.json`.
   - The **raw commissionable advertisement** (BLE advertising report,
     Matter service-data AD structure) — compare against
     `test-vectors/btp/advert.json`'s `pi_default_disc` entry (already
     `"provisional": false`, since it is a pure spec-layout encode of the
     known discriminator/VID/PID — this capture is a sanity check, not a
     required edit, unless the real bytes disagree).

3. **De-provisionalize:** if the captured C2 response bytes match the
   existing `packet_hex`, flip `expected_chip_peripheral_response`'s
   `"provisional"` to `false` and add a `"source"` note pointing at this
   capture (date + DUT). If they differ (e.g. a different negotiated
   fragment size), update `packet_hex` and `expect` to the observed values,
   note the real MTU in the `note` field, and re-run
   `cargo test -p matter-ble` to confirm the vector-driven tests still pass
   against the corrected bytes. Per CLAUDE.md, "if our output differs from
   the reference, we are wrong by default" applies here too — chip's real
   on-wire bytes win over our hand-encoded assumption.

## Reference

- Design: `docs/superpowers/specs/2026-07-13-m9-c1-ble-btp-design.md`, §D10.
- Central-side runbook: `docs/runbooks/ble-commissioning.md`.
