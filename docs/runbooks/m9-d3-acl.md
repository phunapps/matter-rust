# M9-D3 Runbook — ACL read/write

Operator-gated validation for M9-D3: confirm `Node::read_acl` and
`Node::write_acl` work against a real device, and that the lockout guard fires
client-side when an accidental admin-dropping write is attempted.

**This runbook continues from `m9-d2-fabric-management.md`.** The device must
already be commissioned onto Fabric A. Use the same `controller-state.bin`
snapshot.

**Status: TO BE RUN FOR REAL.**

---

## Device

Tapo P110M (the device validated throughout M6.6 / M7.5 / M8 / M9-B1 / M9-D1
/ M9-D2). The device must already be commissioned onto our fabric. Do **not**
factory-reset.

Trust material (production PAA/CD roots):

- PAA roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/paa-root-certs`
- CD roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/cd-certs`

---

## Steps

### Step 1 — Read the current ACL (always safe)

`read_acl` is a plain read against `AccessControl.Acl` (cluster 0x001F,
attribute 0x0000, endpoint 0). It carries no write risk and is always the right
first step.

```rust
// operator pseudocode — not compiled by `cargo test`
use std::sync::Arc;
use matter_controller::{AclAuthMode, AclEntry, AclPrivilege, AttestationTrust, FileStore, MatterController};

let store = Arc::new(FileStore::new("controller-state.bin"));
let ctrl = MatterController::builder(store)
    .attestation_trust(AttestationTrust::from_dirs(paa_dir, cd_dir)?)
    .build()
    .await?;
let node_id = /* the node_id stored from commissioning */;
let node = ctrl.node(node_id);

let entries: Vec<AclEntry> = node.read_acl().await?;
println!("ACL entry count: {}", entries.len());
for e in &entries {
    println!(
        "  privilege={:?}  auth_mode={:?}  subjects={:?}  targets={:?}  fabric_index={:?}",
        e.privilege, e.auth_mode, e.subjects, e.targets, e.fabric_index
    );
}
```

**Expected:** at least one entry with `privilege = Administer`, `auth_mode = Case`,
and `fabric_index = Some(<our fabric index>)`. That entry is what allows us to
manage the device. For a freshly commissioned Tapo P110M the list will typically
contain a single Administer/CASE entry covering our commissioner node id (or a
wildcard `subjects = None`).

Record the full entry list — you will need it in Step 2.

### Step 2 — Single-chunk `write_acl` round-trip

Add one benign `Operate`/CASE entry to the list returned in Step 1, keeping the
existing Administer entry intact. Then write the modified list and read it back
to confirm the new entry is visible on the device.

> **The lockout guard is always active.** `write_acl` checks — before sending
> any bytes — that the proposed list contains an Administer/CASE entry covering
> our commissioner node id. If you accidentally drop the Administer entry, the
> call returns `Error::AclWouldLockOut` immediately and nothing is sent to the
> device.

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::{AclAuthMode, AclEntry, AclPrivilege, AclTarget};

// Step 1 returned this list. Keep it exactly as-is, then append one entry.
let mut new_entries: Vec<AclEntry> = entries.clone();

// Add a benign Operate/CASE entry with wildcard subjects and targets.
// This grants Operate access to any CASE principal on the accessing fabric —
// useful for a restricted sub-controller or observer.
new_entries.push(AclEntry {
    privilege: AclPrivilege::Operate,
    auth_mode: AclAuthMode::Case,
    subjects: None,  // wildcard: any CASE subject on this fabric
    targets: None,   // wildcard: all clusters and endpoints
    fabric_index: None, // omit on write; device fills this in
});

// write_acl runs the lockout guard here:
//   - reads our commissioner node id from the actor
//   - checks that `new_entries` retains Administer/CASE covering our node id
//   - only then sends the write to the device
let statuses = node.write_acl(&new_entries).await?;
for (path, status) in &statuses {
    println!("write status: {:?} → {:?}", path, status);
}
// Expected: one status per entry path, all Success.
```

**Expected:** `write_acl` returns `Ok(statuses)` without error, all statuses
are `Success` (or `ImStatus::Success`).

Then confirm the new entry is present:

```rust
// operator pseudocode — not compiled by `cargo test`
let entries_after: Vec<AclEntry> = node.read_acl().await?;
println!("ACL entry count after write: {}", entries_after.len());
for e in &entries_after {
    println!("  {:?}  {:?}  subjects={:?}", e.privilege, e.auth_mode, e.subjects);
}
assert_eq!(
    entries_after.len(),
    entries.len() + 1,
    "expected one more entry than before"
);
let administer_entry = entries_after
    .iter()
    .find(|e| e.privilege == AclPrivilege::Administer && e.auth_mode == AclAuthMode::Case);
assert!(administer_entry.is_some(), "Administer/CASE entry must still be present");
let operate_entry = entries_after
    .iter()
    .find(|e| e.privilege == AclPrivilege::Operate && e.auth_mode == AclAuthMode::Case);
assert!(operate_entry.is_some(), "Operate/CASE entry must now be present");
```

**Expected:** the device now holds N+1 entries (where N was the original count),
both the original Administer entry and the new Operate entry are present.

### Step 3 — Restore the original ACL

Write back the original entry list from Step 1 to leave the device in its
starting state.

```rust
// operator pseudocode — not compiled by `cargo test`
// `entries` is the list captured in Step 1 (before the extra entry was added).
let restore_statuses = node.write_acl(&entries).await?;
for (path, status) in &restore_statuses {
    println!("restore status: {:?} → {:?}", path, status);
}
let entries_restored: Vec<AclEntry> = node.read_acl().await?;
assert_eq!(entries_restored.len(), entries.len(), "ACL should be back to the original count");
println!("ACL restored successfully");
```

**Expected:** `write_acl` returns `Ok`, all statuses are `Success`, and the
subsequent `read_acl` returns the original entry count.

### Step 4 — Verify the lockout guard fires client-side

Attempt a write that drops the Administer/CASE entry. The guard must intercept
it before any bytes are sent to the device.

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::Error;

// Build a list with ONLY an Operate entry — no Administer/CASE.
let lockout_attempt = vec![AclEntry {
    privilege: AclPrivilege::Operate,
    auth_mode: AclAuthMode::Case,
    subjects: None,
    targets: None,
    fabric_index: None,
}];

let result = node.write_acl(&lockout_attempt).await;
println!("lockout-attempt result: {result:?}");
assert!(
    matches!(result, Err(Error::AclWouldLockOut)),
    "write_acl must return AclWouldLockOut when the list drops our Administer/CASE entry"
);
```

**Expected:** `Err(Error::AclWouldLockOut)`. The device must **not** receive a
`WriteRequest` — the guard fires before any network I/O. The ACL on the device
remains unchanged (confirm with a `read_acl` if in doubt).

---

## Multi-chunk path: hardware scope

**Multi-chunk `write_acl` is NOT attempted on real hardware in this runbook.**

The multi-chunk path (more entries than fit in one `WriteRequestMessage`) is
validated against a synthetic in-process fixture via `write_acl_with_budget`
tests (injected small budget, loopback transport) and the
`build_list_write_chunks` unit tests and proptest suite in `matter-interaction`.
A real device's ACL table is bounded by its `SubjectsPerAccessControlEntry` /
`TargetsPerAccessControlEntry` / `AccessControlEntriesPerFabric` limits, which
typically allow only a handful of entries — far below the threshold where the
single 800-byte chunk budget would be exceeded. Sending a synthetic >MTU ACL to
a real device risks hitting device-side entry-count limits and may leave the
device in an unexpected state. Hardware validation is therefore restricted to
the single-chunk path (Steps 1–4 above).

---

## Pass criteria

1. `read_acl` returns at least one `Administer`/`Case` entry with a `fabric_index`
   matching our fabric.
2. `write_acl` with the original entries + one new `Operate`/CASE entry returns
   `Ok`, all statuses are `Success`.
3. The subsequent `read_acl` shows the new entry alongside the original
   Administer entry.
4. Restoring the original ACL via `write_acl` returns `Ok` and `read_acl`
   confirms the entry count is back to the original.
5. `write_acl` with a list that omits the Administer entry returns
   `Err(Error::AclWouldLockOut)` — no bytes sent to the device.

---

## Notes

- **The lockout guard fetches our commissioner node id** from the actor
  (`CommissionerNodeId` command) before evaluating the proposed entry list. If
  the actor is unavailable (e.g. the controller is shutting down) the call fails
  with a transport error rather than proceeding unguarded.
- **An entry retains admin** when: `privilege == Administer` AND `auth_mode ==
  Case` AND (`subjects == None` OR `subjects` contains our node id). A wildcard
  `subjects = None` is the most common form on a freshly commissioned device —
  it grants access to all CASE principals on the fabric, including ours.
- **`fabric_index` on write:** leave `fabric_index: None` in every entry you
  write. The device fills in the accessing fabric index for each entry. If you
  copy entries from a `read_acl` result and leave `fabric_index: Some(n)`, the
  device will accept it (the field is fabric-scoped and the device ignores the
  supplied value, substituting its own).
- **ACL interaction with multi-admin:** if the device is on multiple fabrics
  (after the D2 runbook), `read_acl` on Fabric A returns only Fabric A's entries
  (the ACL attribute is fabric-scoped). Writing via Fabric A does not touch
  Fabric B's ACL entries.
- Record: the date, which pass criteria were observed, and any deviations.
  Update `docs/tested-devices.md`.
