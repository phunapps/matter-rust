# matter-controller

The high-level Matter controller API — the single crate a consumer depends on
to commission and control Matter devices from pure Rust. It wraps every other
`matter-*` crate behind a small, async (Tokio) surface.

Part of [`matter-rust`](https://github.com/phunapps/matter-rust). Milestone 8
(the v1.0 release).

> Status: **pre-release (`0.0.0`)**. M8.1–M8.5 implemented: persistence + stable
> commissioner identity, transparent CASE, commissioning + attestation trust,
> typed read/write/invoke (raw `Value`, wildcard reads), and live subscriptions.

## What it does

- **Fabric & identity** — `create_fabric` mints and persists the controller's
  stable operational identity once per fabric, through a pluggable
  `ControllerStore` (a default `FileStore` ships).
- **Commissioning** — `commission("MT:…" | "<manual-code>")` brings a device
  onto the fabric, verifying device attestation against an `AttestationTrust`
  (bundled CSA test roots, or production PAA/CD roots loaded `from_dirs`).
- **Interaction** — `Node::read` / `write` / `invoke` over raw
  `matter_codec::Value`, including **wildcard reads** (`ReadPath::cluster`,
  `ReadPath::all`) for reading every attribute off a device.
- **Subscriptions** — `Node::subscribe` returns a `Subscription` stream of
  `AttributeReport`s (`next().await` + `cancel()`).

The operational CASE session is established, cached, and reused transparently —
callers address a device by node id and never manage sessions.

## Quickstart

```rust
use std::sync::Arc;
use matter_controller::{AttestationTrust, FabricConfig, FileStore, MatterController, MatterTime, ReadPath};

let store = Arc::new(FileStore::new("controller-state.bin"));
let controller = MatterController::builder(store)
    .attestation_trust(AttestationTrust::csa_test_roots())
    .build()
    .await?;

let _fabric = controller.create_fabric(FabricConfig {
    fabric_id: 1, rcac_id: 1, commissioner_node_id: 1,
    validity: (MatterTime::from_unix_secs(0), MatterTime::NO_EXPIRY),
}).await?;

let node_id = controller.commission("MT:Y.K90AFN00KA0648G00").await?;
let node = controller.node(node_id);

// Read all OnOff attributes; subscribe to changes.
let report = node.read(&[ReadPath::cluster(1, 0x0006)]).await?;
let mut sub = node.subscribe(&[ReadPath::cluster(1, 0x0006)], &[], 1, 30).await?;
while let Some(change) = sub.next().await { /* … */ }
```

See `examples/controller_quickstart.rs` for an end-to-end run, and
[`docs/matter-js-migration-guide.md`](../../docs/matter-js-migration-guide.md)
if you're coming from matter.js.

## Known limitations (v1.0)

Subscription hardening is a tracked follow-up: liveness-driven auto-resubscribe
on staleness/session-loss is not yet implemented, and a steady-state report that
arrives while a concurrent round-trip on the same node owns the socket is acked
but not delivered to the consumer (a pure subscription stream loses nothing).

## License

Apache-2.0.
