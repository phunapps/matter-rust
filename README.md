# matter-rust

[![CI](https://github.com/phunapps/matter-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/phunapps/matter-rust/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Rust implementation of the **Matter** protocol — controller side.

> Status: **feature-complete against Matter 1.4 and published to crates.io**
> (`matter-controller` `0.3.0`; the lower-level crates `0.2.0`). The controller
> commissions and controls real Matter devices over IP, and over BLE onto Wi-Fi
> or Thread — all validated against hardware, not just tests.

## What this is

`matter-rust` is a workspace of small, focused crates that together let a Rust
application act as a Matter **controller** — commissioning devices, establishing
secure sessions, and reading, writing, invoking, and subscribing to clusters.

The Rust ecosystem already has [`rs-matter`](https://github.com/project-chip/rs-matter)
for the **device** side. The controller side is the gap we are filling.

## What this is not

- Not a Matter device implementation — see `rs-matter`.
- Not a smart-home platform — this is a protocol library.
- Not a fork of `rs-matter`. The two projects may converge later; for now we ship
  separately because the design goals differ.
- Not a quick MVP. Matter is a security-sensitive protocol. Cutting corners here
  causes broken homes and leaked credentials. The v1.0 API took roughly eighteen
  months, as planned, and the pace has not been compressed since.

## Workspace layout

```
matter-rust/
├── crates/
│   ├── matter-codec/           # M1 — TLV encode/decode
│   ├── matter-cert/            # M2 — Matter certificate format
│   ├── matter-crypto/          # M3, M4 — PASE (SPAKE2+), CASE (SIGMA), ICD check-in
│   ├── matter-transport/       # M5 — UDP, mDNS, framing, MRP
│   ├── matter-interaction/     # M7 — Interaction Model message framing
│   ├── matter-commissioning/   # M6 — full commissioning state machine
│   ├── matter-clusters/        # M7 — typed cluster definitions (generated)
│   ├── matter-ble/             # M9 — BLE transport: BTP engine + central role
│   ├── matter-ota/             # M9 — OTA Software Update Provider
│   ├── matter-bdx/             # M9 — BDX (bulk data exchange, carries OTA images)
│   └── matter-controller/      # M8 — high-level controller API
├── test-vectors/               # binary fixtures captured from matter.js / chip / spec
├── examples/                   # how to use the crates
├── xtask/                      # codegen, vector capture, integration harness
└── docs/                       # protocol notes, runbooks, spec references, ADRs
```

Each crate is independently versioned and independently publishable, and depends
only on the layers below it — so a consumer who only wants TLV decoding can take
`matter-codec` without pulling in commissioning, BLE, or a Tokio runtime.

## Roadmap

The work is sequenced so each milestone validates the previous.

| Milestone | Crate                  | Goal                                                | Target |
| --------- | ---------------------- | --------------------------------------------------- | ------ |
| M0        | —                      | Repo, workspace, CI, roadmap                        | ✓ done |
| M1        | `matter-codec`         | Matter TLV encode/decode                            | ✓ done |
| M2        | `matter-cert`          | Matter certificate parsing and chain validation     | ✓ done |
| M3        | `matter-crypto` v0.1   | PASE / SPAKE2+ (commissioning session establishment)| ✓ done |
| M4        | `matter-crypto` v0.2   | CASE / SIGMA (operational session establishment)    | ✓ done |
| M5        | `matter-transport`     | IPv6 UDP, mDNS discovery, message framing, MRP      | ✓ done |
| M6        | `matter-commissioning` | End-to-end commissioning of a real Matter device    | ✓ done |
| M7        | `matter-clusters`      | Generated cluster definitions (OnOff, Level, …)     | ✓ done |
| M8        | `matter-controller`    | High-level controller API. **v1.0.**                | ✓ done |
| M9        | (all)                  | Completeness against **Matter 1.4** — see below     | ✓ done |

### M9 — what "Matter 1.4 completeness" covered

Everything the original roadmap deferred past v1.0 has since landed:

- **BLE commissioning** (`matter-ble`) — BTP engine + central role, commissioning
  a factory-fresh device onto **Wi-Fi** or **Thread** over Bluetooth.
- **Thread network commissioning** — `AddOrUpdateThreadNetwork` from an operational
  dataset, through a border router.
- **OTA** (`matter-ota` + `matter-bdx`) — this controller can act as an OTA
  Provider: announce, serve an image over BDX, and drive Apply.
- **Multi-admin, ACL, groups** — fabric management, `AccessControl`, and group
  messaging including multicast.
- **ICD** (intermittently-connected devices), TimeSync, Binding.
- **Full Interaction Model** — events, chunked reads, subscriptions with
  chip-faithful auto-resubscribe.
- **37 generated clusters**, up from the initial ten.

Still deferred: Scenes Management, `no_std` (see
[ADR 0002](docs/decisions/0002-no-std-posture.md)), React Native, and Matter 1.5+
features.

Known limitation: **live BLE commissioning is Linux-only.** On macOS, scanning
works but GATT does not: `btleplug` 0.12.0 / CoreBluetooth reject the CHIPoBLE
characteristics' descriptor discovery and C1 write with `CBError.uuidNotAllowed`,
and btleplug drops the errored delegate events so the operation used to hang.
That hang is now **bounded to a fast, clear failure** rather than an indefinite
stall, but macOS BLE commissioning still cannot complete — it needs an upstream
btleplug/CoreBluetooth fix. Root-cause writeup in
[`docs/superpowers/audits/`](docs/) and [`TODO-1.0.md`](TODO-1.0.md).

## Commissioning a real device

All three commissioning paths are validated against real hardware — see
[`docs/tested-devices.md`](docs/tested-devices.md) for what was run, when, and how
it was independently confirmed.

| Path | Device | Proof |
| --- | --- | --- |
| **IP** (already on-network) | TP-Link Tapo P110M | trace cross-verified against matter.js: 0 divergent |
| **BLE → Wi-Fi** | ESP32-C6 (esp-matter) | device joined the WLAN; `OnOff` toggled over CASE |
| **BLE → Thread** | ESP32-C6 + Raspberry Pi border router | device joined the mesh as a router; `OnOff` toggled over CASE |

```bash
# IP: a device already on your network
cargo run -p matter-commissioning --example commission_ip --features driver -- --help

# BLE → Wi-Fi, and BLE → Thread (run these from Linux; see the note above)
cargo run -p matter-controller --example commission_ble_wifi   --features ble -- --help
cargo run -p matter-controller --example commission_ble_thread --features ble -- --help
```

In-process loopback E2E tests prove each flow with no hardware; the runbooks under
[`docs/runbooks/`](docs/runbooks/) perform the real-device runs.

**Attestation roots:** commissioning any real device requires the PAA and CD trust
roots, and they do not come from the same place — `AttestationTrust::csa_test_roots()`
is for our own tests and verifies no real device. The runbooks give the specifics.

## How we verify correctness

Matter is well-specified but full of edge cases. We do not trust our own reading
of the spec. For every protocol layer:

1. Capture binary inputs and outputs from
   [`matter.js`](https://github.com/matter-js/matter.js) running a real
   operation. Save them under `test-vectors/`.
2. Implement the Rust version.
3. Assert byte-for-byte equality with the captured matter.js output.

We also use:

- `connectedhomeip` (the C++ reference) as a second source, both for test vectors
  and as a live peer — `just integration` runs the suite against chip's
  `all-clusters-app`, `lock-app`, and `evse-app`,
- official spec test vectors where they exist (notably PASE/SPAKE2+ in spec §3.10),
- [`proptest`](https://docs.rs/proptest) for roundtrip properties,
- [`cargo-fuzz`](https://rust-fuzz.github.io/book/) for parsers,
- real Matter hardware ([`docs/tested-devices.md`](docs/tested-devices.md)).

Hardware earns its place here. The first BLE→Thread commission surfaced two bugs
that every local test had passed: a scan filter that silently blinded the Linux
Bluetooth backend, and a handshake ordering our own loopback peer was too
forgiving to catch.

If Rust output diverges from matter.js, **we are wrong by default**. Investigate
before changing the test.

## Cryptographic posture

- We do not implement cryptographic primitives. AES, ECDSA, ECDH, SHA, HKDF, HMAC
  come from [`ring`](https://docs.rs/ring) (or `aws-lc-rs` if a switch becomes
  justified). We implement the Matter-defined **protocols** on top — SPAKE2+,
  SIGMA — not the math underneath.
- Correctness is verified by byte-parity against matter.js and
  connectedhomeip, plus validation against real devices.

## Using the crates

Published on crates.io — depend on the high-level crate directly:

```toml
[dependencies]
matter-controller = "0.3"
```

Each crate is independently usable: take `matter-codec` alone for TLV, or
`matter-cert` for Matter certificates, without pulling in the higher layers.

The high-level API (M8, `matter-controller`) looks like:

```rust,ignore
let controller = MatterController::builder(store)
    // Real devices need real roots — csa_test_roots() is for our own tests only.
    .attestation_trust(AttestationTrust::from_dirs(&paa_dir, &cd_dir)?)
    .build()
    .await?;
controller.create_fabric(fabric_config).await?;
let info = controller.commission("MT:...", Some("kitchen plug".into())).await?;
let node = controller.node(info.node_id);

node.invoke(toggle_path, Value::Structure(vec![])).await?;       // commands
let report = node.read(&[ReadPath::cluster(1, 0x0006)]).await?;   // wildcard read
let mut sub = node.subscribe(&[ReadPath::cluster(1, 0x0006)], 1, 30).await?;
while let Some(change) = sub.next().await { /* live reports */ }
```

See [`crates/matter-controller`](crates/matter-controller/) and the
[matter.js migration guide](docs/matter-js-migration-guide.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version:

- Issues labelled `good-first-issue` and `help-wanted` are open.
- Any PR that changes protocol behaviour must include matter.js test vectors.
- No `unwrap()` or `expect()` in library code. Test code is fine with a comment
  justifying the assumption.

## Relationship to `rs-matter`

`rs-matter` is the CSA-affiliated Rust Matter project, device-focused. We
collaborate where it helps (spec ambiguity reports, test vectors), and we may
converge eventually. Until then, `matter-rust` is the controller-focused option.

## License

[Apache 2.0](LICENSE).

## Was this written with AI help?

Yes. The maintainer used AI assistance throughout. Every design decision was
made by a human; every line was reviewed; correctness is verified against
matter.js and (where applicable) spec test vectors. The code stands on its own
merits — read it.
