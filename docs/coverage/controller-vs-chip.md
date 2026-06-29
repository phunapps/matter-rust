# Controller ↔ chip integration coverage matrix

Tracks which `matter-controller` operations are exercised **live** against
connectedhomeip's `all-clusters-app` by the `just integration` harness
(`crates/integration-tests/`). Status legend:

- ✓-live — a gated integration test drives this against the live DUT and asserts behavior.
- pending H2–H4 — planned for the per-cluster behavioral batches.
- pending H5 — planned for the nightly CI + coverage-reporting milestone.

See the runbook: `docs/runbooks/m9-h1-integration-harness.md`.

---

## H1 — vertical slice (this milestone)

### Commissioning & session

| Operation | Test | Status |
|---|---|---|
| Commission (PASE → dev-cert attestation → NOC → CASE) | `fixture::connect` (first call) + `integration.rs` | ✓-live |
| Reconnect / lazy CASE re-establish | `fixture::connect` (later calls) | ✓-live |

### Interaction Model (`im_ops.rs`)

| Operation | Test | Status |
|---|---|---|
| Read attribute | `read_basic_information_vendor_name` | ✓-live |
| Write attribute + read-back | `write_and_read_back_node_label` | ✓-live |
| Invoke command | `invoke_identify` | ✓-live |
| Subscribe (priming + steady-state report) | `subscribe_onoff_attribute` | ✓-live |
| Read events | `read_startup_event` | ✓-live |
| Timed invoke (TimedRequest handshake) | `invoke_timed_identify` | ✓-live |
| Timed write | — | pending H2–H4 |
| Chunked read reassembly (wildcard) | — | pending H2–H4 |
| Subscription auto-resubscribe | — | pending H2–H4 |

### Cluster behavior

| Cluster | Test | Status |
|---|---|---|
| OnOff (On / Off / Toggle) | `clusters_onoff::onoff_on_off_toggle` | ✓-live |
| BasicInformation (read/write attrs, StartUp event) | `im_ops.rs` | ✓-live |
| Identify (command) | `im_ops.rs` | ✓-live |
| LevelControl, ColorControl, Descriptor, OccupancySensing, TemperatureMeasurement, RelativeHumidityMeasurement, DoorLock, … | — | pending H2–H4 |

### Groups, ACL & access enforcement

| Operation | Test | Status |
|---|---|---|
| Create group key set + map + membership | `groups_acl::group_provision_acl_and_multicast` | ✓-live |
| Group ACL grant (Operate / Group) | `groups_acl` | ✓-live |
| Group-cast actuation (OnOff via multicast) | `groups_acl` | ✓-live |
| ACE: group-cast denied without the ACL grant | `enforcement::group_cast_denied_without_acl_then_allowed_with_it` | ✓-live |
| ACE: group-cast allowed with the ACL grant | `enforcement` | ✓-live |

### Administration / multi-admin (`multi_admin.rs`)

| Operation | Test | Status |
|---|---|---|
| Open commissioning window (enhanced) | `open_window_second_controller_and_remove_fabric` | ✓-live |
| Second controller commissions via the window manual code | `multi_admin` | ✓-live |
| List fabrics (≥ 2 admins) | `multi_admin` | ✓-live |
| Remove a fabric by index (with self-removal guard) | `multi_admin` | ✓-live |

> Note: the T9-flagged risk (whether `commission` consumes an open-window manual
> code directly) is **resolved** — the full multi-admin loop runs live, no
> fallback. The test retains the fallback for resilience.

---

## H2–H4 — per-cluster behavioral batches (planned)

One behavioral test per typed cluster (the `clusters_onoff.rs` template), across
the ~33 clusters `matter-clusters` generates. Tracked in their own plans.

## H5 — nightly CI + coverage reporting (planned)

- Nightly job runs `just integration` against a freshly built all-clusters-app.
- This matrix is regenerated / checked as part of that job.
