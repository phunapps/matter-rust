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
| LevelControl (MoveToLevel → CurrentLevel) | `clusters_level_control::level_control_move_to_level` | ✓-live |
| ColorControl (MoveToColorTemperature → ColorTemperatureMireds) | `clusters_color_control::color_control_move_to_color_temperature` | ✓-live |
| Thermostat (setpoint write + SetpointRaiseLower) | `clusters_thermostat::thermostat_setpoint_write_then_raise` | ✓-live |
| WindowCovering (GoToLiftPercentage → TargetPositionLiftPercent100ths) | `clusters_window_covering::window_covering_go_to_lift_percentage` | ✓-live |
| FanControl (FanMode + PercentSetting write/read-back) | `clusters_fan_control::fan_control_mode_and_percent` | ✓-live |
| DoorLock | — | **gap: not in all-clusters-app** (needs a `lock-app` DUT; candidate future H phase) |
| OccupancySensing, TemperatureMeasurement, RelativeHumidityMeasurement, the measurement/energy set | — | pending H3 |
| Descriptor, GeneralDiagnostics, Binding, Labels, AccessControl, GroupKeyManagement, AdministratorCommissioning, OtaRequestor | — | pending H4 |

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
> fallback. A 2nd-controller commission failure is now a hard test error, so the
> loop cannot pass vacuously.

---

## H2 — actuator clusters (DONE)

Behavioral sequences for the actuator clusters present on all-clusters-app
(LevelControl, ColorControl, Thermostat, WindowCovering, FanControl), all on
endpoint 1, following the `clusters_onoff.rs` template. **DoorLock is absent from
all-clusters-app** and is recorded as a gap (needs a `lock-app` DUT). See the
"Cluster behavior" table above for per-cluster test names.

## H3–H4 — sensor/measurement + utility/mgmt clusters (planned)

The remaining per-cluster behavioral / typed-decode coverage across the ~33
clusters `matter-clusters` generates. Tracked in their own plans (H3 = sensor /
measurement read + typed-decode; H4 = utility / mgmt).

## H5 — nightly CI + coverage reporting (planned)

- Nightly job runs `just integration` against a freshly built all-clusters-app.
- This matrix is regenerated / checked as part of that job.
