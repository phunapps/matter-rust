# Migrating from matter.js to matter-rust

This guide maps [matter.js](https://github.com/project-chip/matter.js)
controller concepts to the `matter-controller` crate. The two libraries
implement the same Matter protocol, so the mental model carries over directly;
the differences are in language idiom (async Rust vs. TypeScript), explicitness
(matter-rust makes persistence and trust configuration explicit), and that
matter-rust returns **raw `Value`s** rather than runtime-typed cluster objects.

> matter-rust cross-verifies its wire output byte-for-byte against matter.js, so
> a device that works with one works with the other.

## At a glance

| matter.js | matter-rust | Notes |
| --- | --- | --- |
| `new CommissioningController({ … })` | `MatterController::builder(store).…​.build().await?` | Builder; async; persistence + trust are explicit inputs |
| storage backend (auto) | `ControllerStore` trait (`FileStore` default) | You choose where state lives |
| `controller.commissionNode(passcode/qr)` | `controller.commission("MT:…" \| "<manual>").await?` → `node_id` | Returns the **node id**, not a node object |
| `controller.getNode(nodeId)` | `controller.node(node_id)` | Cheap handle; no session state |
| `node.getClusterClient(OnOff)` + typed getters | `node.read(&[ReadPath])` → `Vec<(AttributePath, Value)>` | Raw `Value`; decode with `matter-clusters` codecs |
| `clusterClient.toggle()` | `node.invoke(CommandPath, Value)` | Raw command fields as a `Value` |
| `clusterClient.setX(v)` | `node.write(&[(AttributePath, Value)])` | Returns per-path `ImStatus` |
| `node.subscribeAllAttributes(…)` / `subscribeMultiple` / `subscribeEvents` | `node.subscribe(&[ReadPath], &[EventPath], min, max)` → `Subscription` | One subscription carries attrs **and** events; pull stream (`next().await`), not an `EventEmitter` |
| `subscription` callback | `while let Some(event) = sub.next().await { … }` | `event: SubscriptionEvent::{Report(AttributeReport), Event(EventReport), Established, Resubscribing, Lagged}` |
| wildcard read | `ReadPath::cluster(ep, cl)` / `ReadPath::all()` | `None` fields = wildcard |
| `node.readEvent(...)` | `node.read_events(&[EventPath], &[EventFilter])` → `Vec<EventReport>` | Raw event payloads as `Value`; `EventFilter::from_event_min(n)` resumes after event `n` |

## Construction & persistence

matter.js wires storage implicitly through its environment. matter-rust makes
the store an explicit input via the `ControllerStore` trait, with a file-backed
default:

```ts
// matter.js
const controller = await CommissioningController.create({
  environment: { storage },
  autoConnect: false,
});
```

```rust
// matter-rust
let store = std::sync::Arc::new(FileStore::new("controller-state.bin"));
let controller = MatterController::builder(store)
    .attestation_trust(AttestationTrust::csa_test_roots()) // production: from_dirs(paa, cd)
    .build()
    .await?;
```

Attestation trust (the PAA roots that anchor DAC/PAI verification and the CD
signing roots) is configured **once on the controller** — the same place
matter.js / chip hold the device-attestation verifier. Real certified devices
require production roots: `AttestationTrust::from_dirs(paa_dir, cd_dir)`.

## Fabric & commissioner identity

In matter.js the commissioner's operational identity is managed for you inside
the fabric. matter-rust surfaces it: `create_fabric` mints and **persists** the
controller's stable operational identity (its own NOC under the fabric RCAC)
once, and every later operational session reuses it. Call it once; on restart,
load the snapshot rather than re-creating.

```rust
let fabric_id = controller.create_fabric(FabricConfig {
    fabric_id: 1, rcac_id: 1, commissioner_node_id: 1,
    validity: (MatterTime::from_unix_secs(0), MatterTime::NO_EXPIRY),
})?;
```

## Commissioning

```ts
// matter.js
const nodeId = await controller.commissionNode({
  commissioning: { regulatoryLocation, … },
  discovery: { identifierData: { longDiscriminator } },
  passcode,
});
```

```rust
// matter-rust — QR (MT:…) or manual pairing code
let node_id: u64 = controller.commission("MT:Y.K90AFN00KA0648G00").await?;
```

The controller discovers the commissionable device over mDNS, runs PASE,
verifies attestation against the configured trust, issues the device's NOC, and
persists a `DeviceEntry`. Wi-Fi/Thread network provisioning is deferred past
v1.0 (Ethernet / already-on-network devices today).

## Reading, writing, invoking

matter.js returns typed cluster objects; matter-rust returns raw
`matter_codec::Value`s keyed by the concrete path the device reports. Decode
with the `matter-clusters` codecs when you want typed values.

```ts
// matter.js
const onOff = node.getClusterClient(OnOffCluster);
const state = await onOff.getOnOffAttribute();
await onOff.toggle();
```

```rust
// matter-rust
use matter_controller::{CommandPath, ReadPath, Value};

// Read OnOff.OnOff (0x0006/0x0000) on endpoint 1.
let report = node.read(&[ReadPath::concrete(1, 0x0006, 0x0000)]).await?;
let on = matches!(report.first().map(|(_, v)| v), Some(Value::Bool(true)));

// Invoke OnOff.Toggle (command 0x02), no fields.
node.invoke(CommandPath { endpoint: 1, cluster: 0x0006, command: 0x02 }, Value::Structure(vec![])).await?;
```

**Timed interactions** (DoorLock lock/unlock, certain "Timed" attributes) are
handled transparently: plain `write`/`invoke` auto-retry as a timed interaction
if the device rejects the action with `NEEDS_TIMED_INTERACTION`, and remember the
path so later calls skip the wasted attempt — matter.js does this from its
compiled-in model; matter-rust learns it at runtime (so it also works for
manufacturer clusters). To force the timed path explicitly:

```rust
node.write_timed(&[(path, value)], None).await?;        // None ⇒ default 10s window
node.invoke_timed(CommandPath { .. }, fields, None).await?;
```

Wildcard reads — matter.js's "read everything" — map to `ReadPath` with `None`
components:

```rust
let everything = node.read(&[ReadPath::all()]).await?;            // all attrs, all clusters
let basic = node.read(&[ReadPath::cluster(0, 0x0028)]).await?;     // all of BasicInformation
```

Events (matter.js's `readEvent`) are a separate verb. `EventPath::concrete(ep,
cl, ev)` / `EventPath::cluster(ep, cl)` select events; an `EventFilter` resumes
after a known event number. Each `EventReport` carries the event path, number,
priority, timestamp, and a raw `Value` payload (decode with `matter-clusters`):

```rust
use matter_controller::{EventPath, EventFilter, EventReport};

// All BasicInformation events on endpoint 0, from the beginning.
let events = node.read_events(&[EventPath::cluster(0, 0x0028)], &[]).await?;
for e in &events {
    if let EventReport::Data(it) = e {
        // it.event_number, it.priority, it.timestamp, it.value
    }
}

// Resume: only events newer than the last one seen.
let newer = node
    .read_events(&[EventPath::cluster(0, 0x0028)], &[EventFilter::from_event_min(42)])
    .await?;
```

## Subscriptions

matter.js exposes subscriptions as callbacks/events; matter-rust exposes a pull
stream you await:

```ts
// matter.js
await node.subscribeAllAttributes({ minIntervalFloorSeconds: 1, maxIntervalCeilingSeconds: 30 });
node.events.attributeChanged.on(data => { … });
```

```rust
// matter-rust — ONE subscription carries attributes AND events. Pass an empty
// slice for either to subscribe to only the other (here: DoorLock state attrs +
// LockOperation events on one subscription).
let mut sub = node
    .subscribe(&[ReadPath::cluster(1, 0x0101)], &[EventPath::cluster(1, 0x0101)], 1, 30)
    .await?;
while let Some(event) = sub.next().await {
    match event {
        SubscriptionEvent::Report(report) => println!("attr {:?} = {:?}", report.path, report.value),
        SubscriptionEvent::Event(ev) => println!("event {ev:?}"),
        SubscriptionEvent::Established { subscription_id } => println!("established {subscription_id:#x}"),
        SubscriptionEvent::Resubscribing { cause } => println!("resubscribing: {cause}"),
        _ => {} // SubscriptionEvent is non_exhaustive (e.g. Lagged)
    }
}
sub.cancel().await?; // or just drop `sub`
```

## Error handling

matter.js throws; matter-rust returns `Result<_, matter_controller::Error>` (a
`#[non_exhaustive]` enum wrapping the lower-layer errors plus controller-level
variants like `NoTrust`, `NotCommissioned`, `SetupCode`, `ControllerStopped`).
Use `?` and match on the variants you care about.

## What's intentionally different

- **Raw values, not runtime cluster typing.** matter-rust generates cluster
  codecs at build time (`matter-clusters`); the controller surface stays
  value-typed so it can read *any* attribute, including manufacturer-specific
  ones, without a codec.
- **Explicit persistence and trust.** You pick the store and the attestation
  roots; nothing is implicit.
- **Pull-based subscription streams** rather than event emitters.

## Current limitations (v1.0)

- Subscriptions are hardened: an always-listening demux delivers steady-state
  reports even during a concurrent round-trip on the same node, and a subscription
  that goes silent past its liveness deadline is transparently auto-resubscribed
  on a chip-faithful backoff (`SubscriptionEvent::Resubscribing` → `Established` →
  re-primed reports, behind the same handle).
- Wi-Fi/Thread network commissioning, BLE commissioning transport, OTA,
  multi-admin, and groups are deferred past v1.0.
