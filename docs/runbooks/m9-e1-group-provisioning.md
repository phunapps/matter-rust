# M9-E1 Runbook — Group provisioning

Operator-gated validation for M9-E1: confirm `Node::write_group_key_set`,
`Node::write_group_key_map`, `Node::add_group`, and `Node::remove_group` work
against a real device, leaving the device with a provisioned group key set and
a group binding on endpoint 1.

**This runbook continues from `m9-d3-acl.md`.** The device must already be
commissioned onto our fabric and the `controller-state.bin` snapshot must be
present.

**Status: TO BE RUN FOR REAL.**

> **Scope:** this is the **provisioning leg only** — it provisions a key set,
> binds a group, and adds the endpoint to that group. The multicast group
> command that *uses* the provisioned group lands in E3. These steps are the
> required foundation for the E3 multicast hardware validation loop.

---

## Device

Tapo P110M (the device validated throughout M6.6 / M7.5 / M8 / M9-B1 / M9-D1
/ M9-D2 / M9-D3). The device must already be commissioned onto our fabric. Do
**not** factory-reset.

Trust material (production PAA/CD roots):

- PAA roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/paa-root-certs`
- CD roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/cd-certs`

---

## Steps

### Step 1 — Reconnect to the device (node 2)

Load the persisted controller state and obtain a `Node` handle for node 2.
No new commissioning is needed — the fabric is already on the device.

```rust
// operator pseudocode — not compiled by `cargo test`
use std::sync::Arc;
use matter_controller::{AttestationTrust, FileStore, MatterController};

let store = Arc::new(FileStore::new("controller-state.bin"));
let ctrl = MatterController::builder(store)
    .attestation_trust(AttestationTrust::from_dirs(paa_dir, cd_dir)?)
    .build()
    .await?;

let node_id = 2; // the node_id stored from commissioning
let node = ctrl.node(node_id);
```

### Step 2 — Provision the key set (`write_group_key_set`)

Write a `GroupKeySet` to the device's `GroupKeyManagement` cluster (0x003F,
endpoint 0) using key set id 42. The 16-byte epoch key can be any
cryptographically random value; for operator testing a fixed value is fine.
`epoch_start_time = 0` means "use immediately" (no deferred activation).

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::GroupKeySet;

// 16-byte epoch key (use a random value in production).
let epoch_key = vec![
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
let key_set = GroupKeySet::new(42, epoch_key, 0);

node.write_group_key_set(&key_set).await?;
println!("KeySetWrite succeeded (key set 42 provisioned)");
```

**Expected:** `Ok(())`. The device accepts the key set write and the key set id
42 is now present in its `GroupKeyTable`.

If the device returns a non-success status the call returns
`Err(Error::GroupCommandRejected(status))` with the raw Matter status code.

### Step 3 — Bind group 7 → key set 42 (`write_group_key_map`)

Write a `GroupKeyMap` entry that binds group id 7 to key set id 42. This is a
`WriteRequest` against the `GroupKeyMap` attribute (cluster 0x003F, attribute
0x0000, endpoint 0) using the chunked list-write mechanism — the entry list is
small here (single entry, single chunk) so the write path is byte-identical to
a plain `write` call.

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::GroupKeyMapEntry;

let entries = vec![GroupKeyMapEntry::new(7, 42)];
let statuses = node.write_group_key_map(&entries).await?;
for (path, status) in &statuses {
    println!("GroupKeyMap write status: {:?} → {:?}", path, status);
}
// Expected: one entry, status = Success.
```

**Expected:** `Ok(statuses)` with a single entry, status `Success` (or
`ImStatus::Success`). Group 7 is now bound to key set 42 on the device.

### Step 4 — Add endpoint 1 to group 7 (`add_group`)

Invoke `AddGroup` on the `Groups` cluster (0x0004) at endpoint 1 to enrol
endpoint 1 into group 7 under the name `"test-group"`.

```rust
// operator pseudocode — not compiled by `cargo test`
node.add_group(1, 7, "test-group").await?;
println!("AddGroup succeeded (ep1 is now in group 7)");
```

**Expected:** `Ok(())`. The device confirms that endpoint 1 is now a member of
group 7.

If the device rejects the command (e.g. the group table is full), the call
returns `Err(Error::GroupCommandRejected(status))`.

### Step 5 — Verify the bindings (read GroupKeyMap + GroupTable)

Read back `GroupKeyManagement.GroupKeyMap` (cluster 0x003F, attribute 0x0000,
endpoint 0) and `Groups.GroupTable` (cluster 0x0004, attribute 0x0000, endpoint
1) to confirm the expected bindings are visible on the device.

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::ReadPath;

// Read the GroupKeyMap attribute (GroupKeyManagement cluster, ep0).
let gkm_report = node.read(&[ReadPath::attribute(0, 0x003F, 0x0000)]).await?;
println!("GroupKeyMap entries:");
for (path, value) in &gkm_report {
    println!("  {:?} = {:?}", path, value);
}

// Read the GroupTable attribute (Groups cluster, ep1).
let gt_report = node.read(&[ReadPath::attribute(1, 0x0004, 0x0000)]).await?;
println!("GroupTable entries:");
for (path, value) in &gt_report {
    println!("  {:?} = {:?}", path, value);
}
```

**Expected for GroupKeyMap:** the decoded list contains at least one entry with
`group_id = 7` and `group_key_set_id = 42` (and `fabric_index` set to our
fabric's index by the device).

**Expected for GroupTable:** the decoded list contains at least one entry with
`group_id = 7` and `name = "test-group"`.

---

## Pass criteria

1. `write_group_key_set` returns `Ok(())` for key set id 42.
2. `write_group_key_map` returns `Ok(statuses)` with all statuses `Success`,
   binding group 7 → key set 42.
3. `add_group` returns `Ok(())` enrolling endpoint 1 into group 7.
4. The `GroupKeyMap` read-back contains an entry with `group_id = 7` and
   `group_key_set_id = 42`.
5. The `GroupTable` read-back (endpoint 1) contains an entry with `group_id = 7`.

---

## Notes

- **Key set id and group id are caller-chosen.** Key set id 42 and group id 7
  are illustrative; use any values that do not conflict with existing entries on
  your device. Matter reserves key set id 0 (`IPKKeySetID`) for the fabric's
  IPK — do not overwrite it.
- **`epoch_start_time = 0`** is valid and means the key is active immediately.
  A non-zero value schedules deferred key activation (group key rotation);
  that use case is out of scope for E1.
- **GroupKeyMap fabric-scoping:** the device stores `GroupKeyMap` per-fabric.
  The entries returned by a read carry `fabric_index` filled in by the device;
  leave it absent (or `None`) when writing — the device substitutes the
  accessing fabric's index.
- **Removing the group:** `node.remove_group(1, 7).await?` removes endpoint 1
  from group 7 (`RemoveGroup` on the `Groups` cluster). The key set and key map
  entries remain; they are not automatically cleaned up. Issue a subsequent
  `write_group_key_map(&[])` to clear the binding if needed.
- Record: the date, which pass criteria were observed, and any deviations.
  Update `docs/tested-devices.md`.
