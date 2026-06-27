# M9-E3 Runbook — Full group multicast loop (the E hardware proof)

Operator-gated validation for M9-E3: the end-to-end proof that the complete
E1+E2+E3 stack works — `create_group` (key generation + persistence), device
provisioning (E1 verbs), and `invoke_group` (multicast group command) — with
the physical response as the only delivery confirmation.

**This runbook continues from `m9-e1-group-provisioning.md`.** The device must
already be commissioned onto our fabric and the `controller-state.bin` snapshot
must be present.

**Status: TO BE RUN FOR REAL.**

> **Scope:** this is the full E group loop — controller-side key generation,
> device provisioning, and multicast group command — in one operator session.
> A physical toggle of the Tapo P110M (endpoint 1 turns ON then OFF) is the
> only confirmation that every layer is correct: the epoch key, the operational
> group key derivation, the group session id, the AES-CCM group framing, the
> IPv6 multicast routing, and the device's group membership.

---

## Device

Tapo P110M (node 2 — the device validated throughout M6.6 / M7.5 / M8 /
M9-B1 / M9-D1 / M9-D2 / M9-D3 / M9-E1). The device must already be
commissioned onto our fabric. Do **not** factory-reset.

Trust material (production PAA/CD roots):

- PAA roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/paa-root-certs`
- CD roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/cd-certs`

---

## Steps

### Step 1 — Reconnect to the device (node 2)

Load the persisted controller state and obtain both a controller handle (for
`create_group`) and a `Node` handle for node 2 (for the E1 provisioning verbs).

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

### Step 2 — Create the group key set (controller side)

Call `create_group` to generate a fresh 16-byte epoch key, persist it in the
controller snapshot under key set id 42, and retrieve the `GroupKeySet` that
will be programmed onto the device in Step 3.

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::GroupKeySet;

// generate + persist the epoch key; epoch_start_time = 0 (use immediately)
let group_key_set: GroupKeySet = ctrl.create_group(42, 0).await?;
println!("GroupKeySet created: key_set_id={}", group_key_set.key_set_id);
// group_key_set.epoch_key is the generated 16-byte key — will be written
// to the device in the next step.
```

**Expected:** `Ok(group_key_set)` with `key_set_id = 42`. The controller
snapshot now contains the epoch key at t6 and the outbound counter seed at t7.
`Error::NotCommissioned` means no fabric exists — check the snapshot path.

### Step 3 — Provision the device (E1 verbs)

Use the `GroupKeySet` returned by `create_group` to write the key set to the
device, bind group 7 → key set 42, and enrol endpoint 1 in group 7. These are
the E1 provisioning verbs; the steps are identical to `m9-e1-group-provisioning.md`
except that the key bytes now come from `create_group` rather than a hardcoded
constant.

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::GroupKeyMapEntry;

// 3a. Write the key set to the device's GroupKeyManagement cluster (0x003F, ep0).
node.write_group_key_set(&group_key_set).await?;
println!("KeySetWrite succeeded (key set 42 provisioned on device)");

// 3b. Bind group 7 → key set 42 in the device's GroupKeyMap attribute.
let entries = vec![GroupKeyMapEntry::new(7, 42)];
let statuses = node.write_group_key_map(&entries).await?;
for (path, status) in &statuses {
    println!("GroupKeyMap write: {:?} → {:?}", path, status);
}

// 3c. Add endpoint 1 to group 7 on the device's Groups cluster (0x0004).
node.add_group(1, 7, "test-group").await?;
println!("AddGroup succeeded (ep1 is now in group 7)");
```

**Expected for 3a:** `Ok(())`. Key set 42 is in the device's `GroupKeyTable`.

**Expected for 3b:** `Ok(statuses)` with a single entry, status `Success`.
Group 7 is bound to key set 42 in the device's `GroupKeyMap`.

**Expected for 3c:** `Ok(())`. Endpoint 1 is a member of group 7. The device
now joins the Matter per-group multicast address for group 7 on this fabric
(`ff35:0040:fd<fabric_id_be>:0007`).

### Step 4 — Send a multicast group command (On)

Call `invoke_group` with group 7, key set 42, and the `OnOff.On` command
(cluster 0x0006, command 0x01) to the On command. The call returns `Ok` once
the datagram is sent — there is no acknowledgement at the protocol level.

```rust
// operator pseudocode — not compiled by `cargo test`
use matter_controller::{CommandPath, Value};

// OnOff cluster 0x0006, On command 0x01, no fields.
ctrl.invoke_group(
    7,   // group_id
    42,  // key_set_id
    CommandPath { endpoint: 1, cluster: 0x0006, command: 0x01 },
    Value::Structure(vec![]),
).await?;
println!("invoke_group(On) sent — watch the plug");
```

**Expected:** `Ok(())`. **The plug should physically turn ON** within a
second or two of the call returning.

If the plug does not react, see the **Troubleshooting** section below before
concluding that the stack is broken.

### Step 5 — Send Off command to confirm bidirectional control

Send the Off command (command 0x00) to confirm the group can be driven in both
directions.

```rust
// operator pseudocode — not compiled by `cargo test`
ctrl.invoke_group(
    7,
    42,
    CommandPath { endpoint: 1, cluster: 0x0006, command: 0x00 },
    Value::Structure(vec![]),
).await?;
println!("invoke_group(Off) sent — watch the plug");
```

**Expected:** the plug physically turns OFF.

### Step 6 — Cleanup: remove the endpoint from the group

Remove endpoint 1 from group 7 to leave the device in a clean state.

```rust
// operator pseudocode — not compiled by `cargo test`
node.remove_group(1, 7).await?;
println!("RemoveGroup succeeded (ep1 removed from group 7)");
```

**Expected:** `Ok(())`. The device's `GroupTable` no longer lists group 7 for
endpoint 1. The key set and key map entries remain on the device (they are not
automatically cleaned up by `remove_group`); issue a subsequent
`write_group_key_map(&[])` to clear the binding if needed.

---

## Pass criteria

1. `create_group(42, 0)` returns `Ok(group_key_set)` with `key_set_id = 42`.
2. `write_group_key_set(&group_key_set)` returns `Ok(())`.
3. `write_group_key_map(&[GroupKeyMapEntry::new(7, 42)])` returns `Ok(statuses)`
   with all statuses `Success`.
4. `add_group(1, 7, "test-group")` returns `Ok(())`.
5. `invoke_group(7, 42, OnOff.On)` returns `Ok(())` and **the plug physically
   turns ON**.
6. `invoke_group(7, 42, OnOff.Off)` returns `Ok(())` and **the plug physically
   turns OFF**.
7. `remove_group(1, 7)` returns `Ok(())`.

Criteria 5 and 6 (physical toggle) are the headline proof of the complete
E1+E2+E3 stack. The other criteria confirm each layer is wired correctly but
do not by themselves prove that the multicast path works.

---

## Troubleshooting

### The plug does not react to `invoke_group`

`invoke_group` returns `Ok` as soon as the datagram leaves the socket — it
does **not** wait for any device response. A non-reacting plug means the
multicast datagram did not reach the device. Work through the following checks
in order:

**Check 1 — Multicast interface (most likely cause on a multi-NIC host).**

On a host with multiple network interfaces (e.g. macOS with Wi-Fi + Ethernet
+ VPN), the OS picks the outgoing interface for `ff35:…` sends via its routing
table. If the Matter device is on a different L2 segment from the interface the
OS chooses, the datagram never arrives.

`TokioUdpTransport` does **not** call `set_multicast_if_v6`: macOS rejects
interface index 0 with `EINVAL`, and the kernel default selects the interface
automatically. On a host with a single interface that reaches the device this
is correct; on a multi-NIC host the OS may choose the wrong interface.

To diagnose: run `netstat -rn -f inet6` (macOS) and look for the route to
`ff35::/16` or `ff00::/8`. The interface shown is the one the OS will use. If
it is not the interface connected to the device's LAN, the datagram is going
the wrong way.

The fix is a `bind_addr_with_if` variant of `TokioUdpTransport` that calls
`set_multicast_if_v6(interface_index)` explicitly — this is the noted follow-up
in `crates/matter-transport/src/tokio_udp.rs`. For now, the workaround is to
disable or deprioritize the competing interface so the OS picks the right one.

**Check 2 — Same L2 segment.**

Matter group multicast (`ff35:…`, site-local scope) does not route between
subnets. The host and the device must be on the same L2 segment (same Wi-Fi
network or same Ethernet switch). A NAT boundary, a separate VLAN, or a Wi-Fi
↔ Ethernet bridge that does not forward multicast will silently drop the
datagram.

**Check 3 — Device group membership.**

Confirm that Step 3 (provisioning) completed successfully — specifically that
`add_group` returned `Ok` and that a read of the device's `GroupTable`
attribute shows group 7 on endpoint 1. If the endpoint was not added to the
group the device has no reason to listen on the group's multicast address.

**Check 4 — Key set consistency.**

The controller and the device must agree on the epoch key. If you ran
`create_group` after `write_group_key_set` (i.e. in the wrong order), the
controller and device have different keys and the AES-CCM decryption will
silently fail on the device side. Re-run Steps 2–3 in order, calling
`create_group` before `write_group_key_set`.

**Check 5 — Counter overflow.**

The outbound group counter is a 32-bit value persisted at t7. Counter exhaustion
(`Error::Operational("group counter exhausted")`) is not expected in testing but
would prevent any send. In that case the key set must be re-created
(`create_group` again with a new key set id or the same id, then re-provision
the device).

---

## Notes

- **Fire-and-forget:** `invoke_group` returns `Ok` the moment the datagram is
  sent. There is no Matter-level delivery confirmation for group commands. The
  physical plug toggle is the only proof of delivery.
- **Counter persistence:** the outbound group counter is incremented and
  persisted **before** the UDP send. If the process crashes between the counter
  write and the send, one counter value is wasted — the next send will use the
  following counter. This is the correct trade-off for counter reuse avoidance.
- **Group id and key set id are caller-chosen.** Group 7 and key set id 42 are
  illustrative; any values that do not conflict with existing entries on the
  device are fine. Key set id 0 (`IPKKeySetID`) is reserved for the fabric IPK
  — never overwrite it.
- **Multiple group members.** The same `invoke_group` call reaches *all* devices
  that are members of the group (all have been provisioned with the same key set
  and have added the same group via `add_group`). Validate with a single Tapo
  P110M first; multi-device validation is a natural follow-up.
- Record: the date, which pass criteria were observed (especially criteria 5
  and 6), the interface used for multicast egress (from `netstat -rn -f inet6`),
  and any deviations. Update `docs/tested-devices.md`.
