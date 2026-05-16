# matter-rust

[![CI](https://github.com/phunapps/matter-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/phunapps/matter-rust/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Rust implementation of the **Matter** protocol — controller side.

> Status: **pre-release, Milestone 0.** Nothing here is publishable yet. The repository
> exists so the roadmap, workspace layout, and contribution model are visible from day one.

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
  causes broken homes and leaked credentials. The project is paced at roughly
  eighteen months to v1.0.

## Workspace layout

```
matter-rust/
├── crates/
│   ├── matter-codec/           # M1 — TLV encode/decode
│   ├── matter-cert/            # M2 — Matter certificate format
│   ├── matter-crypto/          # M3, M4 — PASE (SPAKE2+), CASE (SIGMA)
│   ├── matter-transport/       # M5 — UDP, mDNS, framing, MRP
│   ├── matter-commissioning/   # M6 — full commissioning state machine
│   ├── matter-clusters/        # M7 — typed cluster definitions
│   └── matter-controller/      # M8 — high-level controller API
├── test-vectors/               # binary fixtures captured from matter.js / spec
├── examples/                   # how to use the published crates
├── xtask/                      # codegen, vector capture, release helpers
└── docs/                       # protocol notes, spec references, ADRs
```

Each crate is independently versioned and independently publishable. A consumer
who only wants TLV decoding can depend on `matter-codec` without pulling in any
of the higher layers.

## Roadmap

The work is sequenced so each milestone validates the previous. Each milestone
ends with a `cargo publish` to crates.io.

| Milestone | Crate                  | Goal                                                | Target |
| --------- | ---------------------- | --------------------------------------------------- | ------ |
| M0        | —                      | Repo, workspace, CI, roadmap                        | now    |
| M1        | `matter-codec`         | Matter TLV encode/decode                            | mo 2-3 |
| M2        | `matter-cert`          | Matter certificate parsing and chain validation     | mo 4-5 |
| M3        | `matter-crypto` v0.1   | PASE / SPAKE2+ (commissioning session establishment)| mo 6-7 |
| M4        | `matter-crypto` v0.2   | CASE / SIGMA (operational session establishment)    | mo 8-9 |
| M5        | `matter-transport`     | IPv6 UDP, mDNS discovery, message framing, MRP      | mo 10-11 |
| M6        | `matter-commissioning` | End-to-end commissioning of a real Matter device    | mo 12-14 |
| M7        | `matter-clusters`      | Generated cluster definitions (OnOff, Level, …)     | mo 15-16 |
| M8        | `matter-controller`    | High-level controller API. **v1.0.**                | mo 17-18 |

Features deferred past v1.0: Thread network commissioning, BLE commissioning
transport, OTA (BDX), multi-admin, groups, Scenes, Thermostat, advanced ACL,
`no_std`, and clusters beyond the initial set. These ship in 1.x.

## How we verify correctness

Matter is well-specified but full of edge cases. We do not trust our own reading
of the spec. For every protocol layer:

1. Capture binary inputs and outputs from
   [`matter.js`](https://github.com/matter-js/matter.js) running a real
   operation. Save them under `test-vectors/`.
2. Implement the Rust version.
3. Assert byte-for-byte equality with the captured matter.js output.

We also use:

- official spec test vectors where they exist (notably PASE/SPAKE2+ in spec §3.10),
- [`proptest`](https://docs.rs/proptest) for roundtrip properties,
- [`cargo-fuzz`](https://rust-fuzz.github.io/book/) for parsers,
- real Matter hardware from Milestone 6 onwards.

If Rust output diverges from matter.js, **we are wrong by default**. Investigate
before changing the test.

## Cryptographic posture

- We do not implement cryptographic primitives. AES, ECDSA, ECDH, SHA, HKDF, HMAC
  come from [`ring`](https://docs.rs/ring) (or `aws-lc-rs` if a switch becomes
  justified). We implement the Matter-defined **protocols** on top — SPAKE2+,
  SIGMA — not the math underneath.
- The `matter-crypto` crate will not be released without external review by a
  cryptographic engineer for any change that touches the PASE or CASE wire
  protocol. This is enforced by the maintainer, not by CI.

## Using the published crates

Nothing is published yet. When M1 ships:

```toml
[dependencies]
matter-codec = "0.1"
```

The high-level API (M8) will look approximately like:

```rust,ignore
let controller = MatterController::new(fabric_store).await?;
let device = controller.commission_with_qr_code("MT:...").await?;
device.on_off().on().await?;
```

The exact API will be locked in at M8.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version:

- Issues labelled `good-first-issue` and `help-wanted` are open.
- Any PR that changes protocol behaviour must include matter.js test vectors.
- Any PR that changes cryptographic protocol code is flagged for external review
  before the next release.
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
