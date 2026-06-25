# M9-D2 Runbook — Fabric management (multi-admin loop closure)

Operator-gated validation for M9-D2: confirm `Node::list_fabrics`,
`Node::remove_fabric`, and `Node::update_fabric_label` work against a real device,
and that two independent `MatterController` instances can co-exist on the same
device on separate fabrics.

**This runbook is the continuation of `m9-d1-open-commissioning-window.md`.**
Step 1–3 here assume the D1 runbook was already run and the device is on Fabric A.
The second leg it described ("Option B — second instance of our own controller")
is the harness used here.

**Status: TO BE RUN FOR REAL.** (User chose the full hardware loop.)

---

## Device

Tapo P110M (the device validated throughout M6.6 / M7.5 / M8 / M9-B1 / M9-D1).
The device must already be commissioned onto Fabric A. Do **not** factory-reset.

Trust material (production PAA/CD roots):

- PAA roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/paa-root-certs`
- CD roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/cd-certs`

Two stores are used throughout:

- `controller-state.bin` — Fabric A (the existing snapshot from M8 / D1).
- `controller-state-fabric-b.bin` — Fabric B (created fresh in Step 2 below).

---

## Steps

### Step 1 — Load controller A and confirm the device is reachable

Load Fabric A from the existing snapshot and confirm a basic read works before
proceeding.

```rust
// operator pseudocode — not compiled by `cargo test`
use std::sync::Arc;
use matter_controller::{AttestationTrust, FileStore, MatterController, ReadPath};

let store_a = Arc::new(FileStore::new("controller-state.bin"));
let ctrl_a = MatterController::builder(store_a)
    .attestation_trust(AttestationTrust::from_dirs(paa_dir, cd_dir)?)
    .build()
    .await?;
let node_id_a = /* the node_id stored from commissioning */;
let node_a = ctrl_a.node(node_id_a);

// Sanity: read the OnOff attribute so we know the session is alive.
let _ = node_a.read(&[ReadPath::cluster(1, 0x0006)]).await?;
println!("controller A: device reachable");
```

**Expected:** read returns without error.

### Step 2 — Open an enhanced commissioning window from controller A

Open a window using the D1 API so controller B can commission the same device.

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::{OpenWindowOpts, CommissioningWindow};

let win: CommissioningWindow = node_a.open_commissioning_window(OpenWindowOpts {
    timeout_s: 180,
    iterations: 1000,
    vendor_id: Some(0x1217),  // TP-Link; adjust if your firmware differs
    product_id: Some(0x0123), // read from BasicInformation if unsure (see D1 runbook)
    ..Default::default()
}).await?;
println!("manual_code: {}", win.manual_code);
// Expected: "XXXXX-XXXXX-XXXXX" (11 digits, see CommissioningWindow::manual_code)
```

**Expected:** `Ok(win)`, `win.manual_code` is an 11-digit string.

### Step 3 — Stand up controller B and commission via the manual code

Controller B is a second `MatterController` instance with a **distinct** store
file, a **different** fabric id, and its own commissioner identity. It uses the
same attestation trust as controller A (same PAA/CD roots).

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::{
    AttestationTrust, FabricConfig, FileStore, MatterController, MatterTime,
};

let store_b = Arc::new(FileStore::new("controller-state-fabric-b.bin"));
let ctrl_b = MatterController::builder(store_b)
    .attestation_trust(AttestationTrust::from_dirs(paa_dir, cd_dir)?)
    .build()
    .await?;

// Fabric 2, vendor 2, node 1 — must be different from Fabric A's fabric_id.
ctrl_b.create_fabric(FabricConfig::new(
    2,
    2,
    1,
    (MatterTime::from_unix_secs(0), MatterTime::NO_EXPIRY),
)).await?;

let node_id_b = ctrl_b.commission(&win.manual_code).await?;
println!("controller B commissioned device as node_id={node_id_b}");
```

> **Note:** Controller B needs its own `FileStore` (distinct path) and its own
> `create_fabric` call. The attestation trust configuration is the same as A
> because the device has the same DAC regardless of which fabric is commissioning it.
> The window is open for 180 s — run this promptly after Step 2.

**Expected:** `commission` returns `Ok(node_id_b)`. The device now carries two
fabric entries (one from A, one from B).

### Step 4 — List fabrics from controller A; confirm both entries appear

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::FabricDescriptor;

let fabrics: Vec<FabricDescriptor> = node_a.list_fabrics().await?;
println!("fabric count: {}", fabrics.len());
for f in &fabrics {
    println!(
        "  fabric_index={} fabric_id={:#018x} node_id={} label={:?}",
        f.fabric_index, f.fabric_id, f.node_id, f.label
    );
}
assert_eq!(fabrics.len(), 2, "expected exactly 2 fabrics after D2 commissioning");
```

**Expected:**

- `fabrics.len() == 2`.
- Both entries have distinct `fabric_index` values (e.g. `1` and `2`).
- Both entries have distinct `fabric_id` values (A's id vs. B's id).
- Record `b_fabric_index` — the `fabric_index` from B's entry. You will need it
  in Step 6.

Also confirm that both controllers can drive the OnOff cluster independently:

```rust
// operator pseudocode — not compiled by `cargo test`
let node_b = ctrl_b.node(node_id_b);

// Toggle from A, then toggle back from B.
node_a.invoke(matter_controller::CommandPath { endpoint: 1, cluster: 0x0006, command: 2 },
    matter_controller::Value::Struct(vec![])).await?;
node_b.invoke(matter_controller::CommandPath { endpoint: 1, cluster: 0x0006, command: 2 },
    matter_controller::Value::Struct(vec![])).await?;
println!("both fabrics can drive the device");
```

**Expected:** both invokes succeed without error.

### Step 5 — Relabel controller A's fabric entry on the device

`update_fabric_label` acts on the accessing fabric (our own fabric entry) — it
takes a label string and no index argument.

```rust
// operator pseudocode — not compiled by `cargo test`
node_a.update_fabric_label("home").await?;
println!("label updated");

let fabrics_after_label: Vec<FabricDescriptor> = node_a.list_fabrics().await?;
let a_entry = fabrics_after_label.iter()
    .find(|f| f.fabric_id == /* A's fabric_id */)
    .expect("A's fabric entry must still exist");
assert_eq!(a_entry.label, "home", "label should be visible via list_fabrics");
println!("A's fabric label is now {:?}", a_entry.label);
```

**Expected:** `update_fabric_label` returns `Ok(())`; the subsequent
`list_fabrics` call shows the updated label on A's entry.

### Step 6 — Remove fabric B from controller A

```rust
// operator pseudocode — not compiled by `cargo test`
// b_fabric_index captured in Step 4.
node_a.remove_fabric(b_fabric_index).await?;
println!("fabric B removed");

let fabrics_after_remove: Vec<FabricDescriptor> = node_a.list_fabrics().await?;
assert_eq!(fabrics_after_remove.len(), 1, "only fabric A should remain");
println!("fabric count after removal: {}", fabrics_after_remove.len());
```

**Expected:** `remove_fabric` returns `Ok(())`; `list_fabrics` now shows exactly
one entry (Fabric A).

Verify that controller B's session is now invalid — any subsequent operation from
B should fail (the device rejects B's CASE session because the NOC has been
revoked):

```rust
// operator pseudocode — not compiled by `cargo test`
let result = node_b.read(&[ReadPath::cluster(1, 0x0006)]).await;
println!("controller B read after fabric removal: {result:?}");
// Expected: Err(...) — exact error variant depends on transport (CASE failure or
// status-report rejection); the key property is that it is NOT Ok.
```

### Step 7 — Verify the self-protection guard

Confirm that `remove_fabric` refuses to remove our own fabric with
`Error::WouldRemoveSelf`. Use controller A's own `fabric_index` (from
`list_fabrics`; the single remaining entry after Step 6).

```rust
// operator pseudocode — not compiled by `cargo test`
let a_fabric_index = fabrics_after_remove[0].fabric_index;
let self_remove_result = node_a.remove_fabric(a_fabric_index).await;
println!("remove own fabric: {self_remove_result:?}");
assert!(
    matches!(self_remove_result, Err(matter_controller::Error::WouldRemoveSelf)),
    "remove_fabric must return WouldRemoveSelf for our own fabric index"
);
```

**Expected:** `Err(Error::WouldRemoveSelf)`. The device must **not** receive a
`RemoveFabric` invoke — the guard fires before any network traffic.

---

## Pass criteria

1. `list_fabrics` after Step 3 returns exactly 2 entries with distinct
   `fabric_index` and `fabric_id` values.
2. Both controller A and controller B can invoke commands on the device
   independently (Step 4).
3. `update_fabric_label("home")` returns `Ok(())`; the new label is visible via
   the subsequent `list_fabrics` call on A's entry.
4. `remove_fabric(b_fabric_index)` returns `Ok(())`; `list_fabrics` then shows
   exactly 1 entry.
5. Controller B's session is invalid after Step 6 (any operation returns an error).
6. `remove_fabric(<A's own index>)` returns `Err(Error::WouldRemoveSelf)` (the
   self-protection guard fires on hardware).

---

## Notes

- **In-process 2-fabric commissioning is not gated in CI.** This is an
  operator-run path. The CI gate covers unit tests and the `commission_loopback`
  integration test on a single fabric. Running two controllers in the same process
  against a real device is intentionally kept to the operator loop.
- **Store independence:** the two controllers must use different `FileStore` paths.
  The snapshot format is keyed to the fabric identity; sharing a store would
  corrupt both.
- **The self-protection guard reads `CurrentFabricIndex` (attr 0x0005) from
  `OperationalCredentials` before any invoke.** If that read fails (offline
  device, permission denied), `remove_fabric` fails closed with an error rather
  than risking an accidental self-removal. There is no force flag.
- The `OperationalCredentialsRejected(u8)` error variant carries the raw
  `NocStatus` code from the device. If the device rejects `RemoveFabric` or
  `UpdateFabricLabel`, log the code to cross-reference against Matter Core Spec
  §11.18.6.2 (`NocStatus`).
- Record: the date, which pass criteria were observed, and any deviations. Update
  `docs/tested-devices.md`.
