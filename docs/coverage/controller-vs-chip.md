# Controller ↔ chip integration coverage matrix

Tracks which `matter-controller` operations are exercised **live** against
connectedhomeip's `all-clusters-app` by the `just integration` harness
(`crates/integration-tests/`). Status legend:

- ✓-live — a gated integration test drives this against the live DUT and asserts behavior.

See the runbook: `docs/runbooks/m9-h1-integration-harness.md`.

## Status summary

The harness commissions connectedhomeip's `all-clusters-app` with pure-Rust
matter-controller (dev-cert attestation) and exercises, **live against the
device**: commissioning + reconnect; the full Interaction-Model op set
(read / write / invoke / subscribe / events / timed); behavioral actuator
sequences (OnOff, LevelControl, ColorControl, Thermostat, WindowCovering,
FanControl); typed-decode of every sensor/measurement and utility/management
cluster the DUT exposes, run against **real device bytes** through the generated
`matter_clusters::gen::*::decode_*` codecs; groups + ACL + group-cast actuation;
AccessControl enforcement (deny/grant); and a multi-admin loop (open window →
second controller → fabric removal).

Run locally with `just integration`; run on a schedule via the
`Integration (nightly)` GitHub Actions workflow
(`.github/workflows/integration-nightly.yml`).

## Multi-DUT

`all-clusters-app` omits a few clusters, so the harness can drive other
connectedhomeip example apps as additional DUTs (`xtask integration <app>`),
each with its own `just` recipe. The app-specific tests skip unless their DUT is
running, so the default `just integration` (all-clusters) sweep is unaffected.

- **`just integration-lock`** — `lock-app` → DoorLock (0x0101) lock/unlock
  behavioral.
- **`just integration-energy`** — `evse-app` → ElectricalPowerMeasurement
  (0x0090) + ElectricalEnergyMeasurement (0x0091) typed-decode (incl. the
  composite `MeasurementAccuracyStruct`). At-rest readings are null/zero (no
  energy event trigger fired), so the test validates the typed *decoders* against
  real bytes — the gap that needed closing; firing the energy event trigger for
  non-null magnitudes is a possible future enhancement.

There are **no remaining cluster DUT gaps** for the clusters matter-clusters
generates. Out of scope by the matter-rust roadmap (not coverage holes): CNET
network commissioning, OTA/BDX transfer, ICD, BLE/Thread transport.

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
| DoorLock (lock/unlock → LockState, on lock-app) | `clusters_door_lock::door_lock_lock_unlock` | ✓-live (`just integration-lock`) |
| TemperatureMeasurement (typed-decode vs real bytes) | `clusters_measurement::temperature_measurement_typed_decode` | ✓-live |
| RelativeHumidityMeasurement (typed-decode) | `clusters_measurement::relative_humidity_measurement_typed_decode` | ✓-live |
| IlluminanceMeasurement (typed-decode) | `clusters_measurement::illuminance_measurement_typed_decode` | ✓-live |
| PressureMeasurement (typed-decode) | `clusters_measurement::pressure_measurement_typed_decode` | ✓-live |
| FlowMeasurement (typed-decode) | `clusters_measurement::flow_measurement_typed_decode` | ✓-live |
| OccupancySensing (typed-decode) | `clusters_sensors::occupancy_sensing_typed_decode` | ✓-live |
| BooleanState (typed-decode) | `clusters_sensors::boolean_state_typed_decode` | ✓-live |
| AirQuality (typed-decode) | `clusters_sensors::air_quality_typed_decode` | ✓-live |
| PowerSource (typed-decode of scalar attrs) | `clusters_power_source::power_source_typed_decode` | ✓-live |
| ElectricalPowerMeasurement / ElectricalEnergyMeasurement (typed-decode incl. composite Accuracy, on evse-app) | `clusters_electrical::electrical_measurement_typed_decode` | ✓-live (`just integration-energy`) |
| Descriptor (ServerList behavioral + list typed-decode) | `clusters_descriptor::descriptor_lists_typed_decode` | ✓-live |
| GeneralDiagnostics (typed-decode) | `clusters_diagnostics::general_diagnostics_typed_decode` | ✓-live |
| FixedLabel (typed-decode) | `clusters_labels_binding::fixed_label_typed_decode` | ✓-live |
| Binding (typed-decode) | `clusters_labels_binding::binding_typed_decode` | ✓-live |
| UserLabel (write + read-back) | `clusters_labels_binding::user_label_write_read_back` | ✓-live |
| AccessControl (typed-decode) | `clusters_mgmt::access_control_typed_decode` | ✓-live |
| GroupKeyManagement (typed-decode) | `clusters_mgmt::group_key_management_typed_decode` | ✓-live |
| AdministratorCommissioning (typed-decode) | `clusters_mgmt::administrator_commissioning_typed_decode` | ✓-live |
| OtaSoftwareUpdateRequestor (typed-decode) | `clusters_mgmt::ota_requestor_typed_decode` | ✓-live |
| TimeSynchronization (SetUTCTime + read-back, SetTimeZone→DSTOffsetRequired, SetDSTOffset) | `clusters_time_sync::time_sync_set_and_read` | ✓-live (G-a) |

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

## H3 — sensor / measurement clusters (DONE)

Reads every sensor/measurement cluster all-clusters-app exposes (the 5
measurement clusters + OccupancySensing, BooleanState, AirQuality, PowerSource —
all on endpoint 1) and feeds the real device bytes through the generated
`matter_clusters::gen::*::decode_*` typed decoders, asserting `Ok` (plus the exact
deterministic Min/Max defaults). This closes the long-standing "validate typed
decoders against real device bytes" follow-up. **ElectricalPowerMeasurement /
ElectricalEnergyMeasurement are absent from all-clusters-app** and recorded as a
gap (need `energy-management-app` or a real energy device). See the "Cluster
behavior" table above for per-cluster test names.

## H4 — utility / mgmt clusters (DONE)

Reads a representative attribute from every utility/mgmt cluster all-clusters-app
exposes (Descriptor, GeneralDiagnostics, Binding, FixedLabel, UserLabel,
AccessControl, GroupKeyManagement, AdministratorCommissioning, OtaRequestor) and
runs the real device bytes through the generated typed decoders — exercising the
list/struct decoders (ServerList, DeviceTypeList, NetworkInterfaces, Acl,
GroupKeyMap, LabelList, Binding) on real container bytes. Descriptor adds a
behavioral assertion (ep1 ServerList contains OnOff; ep0 PartsList contains
endpoint 1), and UserLabel exercises a writable list-of-struct attribute
end-to-end (write a label, read it back through the typed decoder). No DUT gaps.
See the "Cluster behavior" table above for per-cluster test names.

## H5 — nightly CI + coverage matrix (DONE)

- `.github/workflows/integration-nightly.yml` runs `just integration` against a
  freshly built `all-clusters-app` on a nightly schedule (07:00 UTC) and on
  manual `workflow_dispatch`. It is **not** a per-PR check (the connectedhomeip
  build is heavy; the fast per-PR gate is untouched).
- **First-run caveat:** the connectedhomeip pigweed bootstrap + build is
  environment-sensitive; the workflow must be manually dispatched once to
  validate on a GitHub runner before the nightly schedule is relied upon.
- This document is the standing coverage record (see the "Status summary" and
  "Known DUT gaps" at the top, and the per-cluster tables above).
