# Controller ↔ chip integration coverage matrix

Tracks which `matter-controller` operations are exercised **live** against
connectedhomeip's example apps by the `just integration` harness
(`crates/integration-tests/`): `all-clusters-app` (locally and in the
nightly), `lock-app` and `evse-app` (local only), `tv-app` (in the nightly at
v1.4.2.0 from its next run, and on a Raspberry Pi locally), and `rvc-app` and
`microwave-oven-app` (on a Raspberry Pi, local only). Status legend:

- ✓-live — a gated integration test drives this against the live DUT and asserts behavior.
- ✓-nightly — the `Integration (nightly)` workflow has run that test green
  against chip v1.4.2.0 (its pinned `CHIP_REF`); the named run is the proof.
  "nightly (v1.4.2.0) from the next run" means it is in the suite but no
  nightly has run it yet.

See the runbook: `docs/runbooks/m9-h1-integration-harness.md`.

## Status summary

The harness commissions connectedhomeip's `all-clusters-app` with pure-Rust
matter-controller (dev-cert attestation) and exercises, **live against the
device**: commissioning + reconnect; the full Interaction-Model op set
(read / write / invoke / subscribe / events / timed); behavioral actuator
sequences (OnOff, LevelControl, ColorControl, Thermostat, WindowCovering,
FanControl); typed-decode of every sensor/measurement and utility/management
cluster the DUT exposes, run against **real device bytes** through the generated
`matter_clusters::clusters::*::decode_*` codecs; groups + ACL + group-cast actuation;
AccessControl enforcement (deny/grant); and a multi-admin loop (open window →
second controller → fabric removal).

Run locally with `just integration`; run on a schedule via the
`Integration (nightly)` GitHub Actions workflow
(`.github/workflows/integration-nightly.yml`).

**Actor concurrency (M9-G-d).** The controller's long protocol handlers —
commission and CASE connect — run off the single actor loop on spawned tasks, so
one session's multi-round-trip handshake does not stall every other session's
MRP retransmits / subscription liveness (2026-06-12 audit item #1, resolved). A
CASE connect's handshake I/O still flows through the actor's own socket (no
second socket, no session migration). This guarantee is proven by hermetic
concurrency unit tests in `crates/matter-controller/src/actor.rs`
(`commission_completion_drains_while_loop_stays_responsive`,
`connect_handshake_runs_off_loop_which_stays_responsive`), not by this live
harness. See the `Actor::run` rustdoc for the full model.

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
| Binding (write + read-back + restore) | `clusters_binding::binding_write_read_restore` | ✓-live (G-b) |
| UserLabel (write + read-back) | `clusters_labels_binding::user_label_write_read_back` | ✓-live |
| AccessControl (typed-decode) | `clusters_mgmt::access_control_typed_decode` | ✓-live |
| GroupKeyManagement (typed-decode) | `clusters_mgmt::group_key_management_typed_decode` | ✓-live |
| AdministratorCommissioning (typed-decode) | `clusters_mgmt::administrator_commissioning_typed_decode` | ✓-live |
| OtaSoftwareUpdateRequestor (typed-decode) | `clusters_mgmt::ota_requestor_typed_decode` | ✓-live |
| TimeSynchronization (SetUTCTime + read-back, SetTimeZone→DSTOffsetRequired, SetDSTOffset) | `clusters_time_sync::time_sync_set_and_read` | ✓-live (G-a) |
| IcdManagement (register + check-in receive/verify + stay-active) | `checkin` byte-parity + `icd_listener` fake-ICD (in-process); `examples/icd_register_listen` + runbook (live lit-icd-app) | ✓ in-process (G-c); live via runbook |
| LevelControl MoveToLevelWithOnOff (M9-A3 B2 encoder fix: the regenerated encoder turns the light on at level 90) | `clusters_level_control::level_control_move_to_level_with_on_off_turns_on` | ✓-live |
| LevelControl MoveToLevelWithOnOff with the old empty payload (`15 18`): chip answers Success and leaves the light off at MinLevel, the released bug's documented impact | `clusters_level_control::level_control_move_to_level_with_on_off_empty_payload_turns_off` | ✓-live |
| OvenMode, LaundryWasherMode, RefrigeratorAndTemperatureControlledCabinetMode, RvcRunMode, RvcCleanMode, DishwasherMode (attributes + ChangeToMode); MicrowaveOvenMode (attributes) | `clusters_modes_alarms::mode_base_clusters_decode_and_change_to_current_mode` | ✓-live |
| EnergyEvseMode, WaterHeaterMode, DeviceEnergyManagementMode on all-clusters (required where the checkout's `all-clusters-app.matter` serves them on ep1) | `clusters_modes_alarms::energy_mode_clusters_decode_where_served` | ✓-live on the nightly (v1.4.2.0); skipped on local master, which does not serve them |
| ModeBase ChangeToMode to an unsupported mode (no StatusText; spec §3.1) | `clusters_modes_alarms::change_to_an_unsupported_mode_decodes_without_status_text` | ✓-live |
| ModeSelect (attributes + ChangeToMode) | `clusters_modes_alarms::mode_select_decodes_and_changes_to_current_mode` | ✓-live |
| DishwasherAlarm (attributes + Reset → Notify event) | `clusters_modes_alarms::dishwasher_alarm_reset_emits_notify` | ✓-live |
| RefrigeratorAlarm (attributes + app-pipe door open → Notify event) | `clusters_modes_alarms::refrigerator_alarm_door_open_emits_notify` | ✓-live |
| HepaFilterMonitoring, ActivatedCarbonFilterMonitoring (attributes + ResetCondition) | `clusters_modes_alarms::filter_monitoring_clusters_decode_and_reset_condition` | ✓-live |
| WaterTankLevelMonitoring | — no connectedhomeip example app serves it (decode smoke + `chip-xml-conformance.py` only) | unit only |
| EnergyEvseMode, DeviceEnergyManagementMode (attributes + ChangeToMode, on evse-app) | `clusters_electrical::energy_mode_clusters_decode_and_change_to_current_mode` | ✓-live, **local only** (`just integration-energy`) |
| RvcRunMode, RvcCleanMode on rvc-app (attributes + ChangeToMode; a refused run-mode or clean-mode change carries StatusText) | `clusters_rvc::rvc_mode_clusters_decode_and_change_to_current_mode`, `clusters_rvc::refused_run_mode_change_decodes_its_status_text` | ✓-live (Linux arm64 Pi, chip master 5cd2917a; rvc 8/8, microwave-oven 3/3); not in the nightly, and not run on the Mac (rvc-app needs Rosetta 2 to build on Apple Silicon). Each test starts from rvc-app's `Reset` pipe command (M9-A3 B3) |
| OperationalState on all-clusters (attributes; Stop / Pause / Resume from Stopped; app-pipe OnFault → OperationalError event; Stop → OperationCompletion event) | `clusters_appliances::operational_state_decodes_and_answers_commands_when_stopped`, `clusters_appliances::operational_state_fault_and_stop_emit_their_events` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38043935752 on 1bc8571) — pipe command and chip sources identical at both refs |
| OvenCavityOperationalState on all-clusters (attributes; Stop; app-pipe OnFault with a manufacturer error id → OperationalError event) | `clusters_appliances::oven_cavity_operational_state_decodes_and_reports_a_manufacturer_error` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38043935752 on 1bc8571) — pipe command and chip sources identical at both refs |
| RvcOperationalState on all-clusters (attributes; Pause / Resume refused when Stopped; events decoded if present — all-clusters cannot stimulate them) | `clusters_appliances::rvc_operational_state_decodes_and_refuses_pause_and_resume_when_stopped` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38043935752 on 1bc8571) — chip sources identical at both refs |
| TemperatureControl on all-clusters (TL attributes; SetTemperature accepted, ConstraintError, InvalidCommand; level restored) | `clusters_appliances::temperature_control_decodes_and_set_temperature_selects_a_level` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38043935752 on 1bc8571) — chip sources identical at both refs |
| LaundryWasherControls, LaundryDryerControls on all-clusters (attributes; writes accepted and refused with ConstraintError / InvalidInState; restored) | `clusters_appliances::laundry_washer_controls_decode_and_validate_writes`, `clusters_appliances::laundry_dryer_controls_decode_and_validate_writes` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38043935752 on 1bc8571) — chip sources identical at both refs |
| RvcOperationalState on rvc-app (attributes; Pause / Resume / GoHome through Stopped → SeekingCharger → Paused → SeekingCharger; pipe ErrorEvent → OperationalError event, ClearError; a cleaning run ended by pipe ActivityComplete → OperationCompletion event) | `clusters_rvc::rvc_operational_state_decodes_and_goes_home`, `clusters_rvc::rvc_operational_error_event_carries_the_rvc_error`, `clusters_rvc::rvc_operation_completion_event_ends_a_cleaning_run` | ✓-live (Linux arm64 Pi, chip master 5cd2917a; rvc 8/8, microwave-oven 3/3); not in the nightly, and not run on the Mac (rvc-app needs Rosetta 2 to build on Apple Silicon) |
| ServiceArea on rvc-app, its only chip host at master and v1.4.2.0 (exact attributes and rvc-app's two-map topology; SelectAreas / SkipArea accepted and refused; Progress through a cleaning run) | `clusters_rvc::service_area_decodes_rvc_app_topology`, `clusters_rvc::service_area_validates_selection_and_skips`, `clusters_rvc::service_area_progress_follows_a_cleaning_run` | ✓-live (Linux arm64 Pi, chip master 5cd2917a; rvc 8/8, microwave-oven 3/3); not in the nightly, and not run on the Mac (rvc-app needs Rosetta 2 to build on Apple Silicon) |
| MicrowaveOvenControl on microwave-oven-app, its only chip host at master and v1.4.2.0 (exact attributes, fixed and boot values; SetCookingParameters accepted, refused off the power grid, with a zero cook time and with a watt index; AddMoreTime; restored) and that app's OperationalState (exact attributes, four states, no phases, CountdownTime = CookTime, Stop from Stopped) | `clusters_microwave_oven::microwave_oven_control_decodes_its_attributes`, `clusters_microwave_oven::microwave_oven_control_validates_cooking_parameters`, `clusters_microwave_oven::microwave_oven_operational_state_counts_down_the_cook_time` | ✓-live (Linux arm64 Pi, chip master 5cd2917a; rvc 8/8, microwave-oven 3/3); not in the nightly, and not run on the Mac (microwave-oven-app needs Rosetta 2 to build on Apple Silicon) |
| SmokeCoAlarm on all-clusters (exact attributes incl. master's `unmounted`; SmokeSensitivityLevel write and restore; TestEventTrigger: smoke critical/warning, CO, low battery, smoke and CO interconnect, malfunction, end of life → their events and AllClear; mute → AlarmMuted / MuteEnded; SelfTestRequest → Testing, Busy, SelfTestComplete) | `clusters_safety::smoke_co_alarm_decodes_every_attribute_and_writes_its_sensitivity`, `…_forced_alarms_emit_their_events_and_clear`, `…_mute_and_unmute_emit_their_events`, `…_self_test_reports_testing_then_completes` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38068348470 on 1ab98ec) — trigger codes and server identical at both refs |
| BooleanStateConfiguration on all-clusters (exact attributes; sensitivity ConstraintError; SuppressAlarm InvalidInState, sensor trigger / suppress / untrigger → AlarmsStateChanged; EnableDisableAlarm ConstraintError, restored; SensorFault via app pipe) | `clusters_safety::boolean_state_configuration_decodes_and_validates_its_sensitivity`, `…_alarms_follow_triggers_and_commands`, `…_sensor_fault_via_app_pipe` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38068348470 on 1ab98ec); SensorFault master only (no pipe command at v1.4.2.0, skipped there with a log) |
| ValveConfigurationAndControl on all-clusters (exact attributes; both defaults written and restored; Open(null, 50) / Close → ValveStateChanged sequences; a 2 s Open closes itself; Open(level 0) ConstraintError, with v1.4.2.0's ValveFault event) | `clusters_safety::valve_decodes_every_attribute_and_writes_its_defaults`, `…_open_and_close_emit_state_changes`, `…_open_duration_counts_down_and_closes`, `…_refuses_a_zero_target_level` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38068348470 on 1ab98ec) — the server differs between refs and the test asks the checkout which one it has |
| ScenesManagement on all-clusters (exact attributes; AddScene → ViewScene returns it; RecallScene applies OnOff and FabricSceneInfo records it (chip's OnOff server marks the scene invalid when the recall changes OnOff; a recall that changes nothing leaves it valid); StoreScene, CopyScene, GetSceneMembership; RemoveScene → ViewScene / RecallScene NotFound; RemoveAllScenes empties; a pair without exactly one value refused; OnOff restored) | `clusters_scenes::scenes_management_decodes_both_attributes`, `…_commands_round_trip`, `…_add_scene_refuses_a_pair_without_exactly_one_value` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38068348470 on 1ab98ec) — server statuses identical at both refs |
| WindowCovering Matter 1.4 ABS on all-clusters (the eight ABS attributes decode; GoToLiftValue / GoToTiltValue reach chip's handler and are refused with Failure without the ABS feature bit; target unchanged) | `clusters_window_covering::window_covering_absolute_position_decodes_and_go_to_value_is_refused` | ✓-live (local master); ✓-nightly (v1.4.2.0: nightly 38068348470 on 1ab98ec) |
| Thermostat Matter 1.4 SCH | — | **not run**: no app the harness drives serves SCH at master or v1.4.2.0 (chip's YAML-test placeholder apps `app1` / `app2` set the SCH bit and serve its three attributes but handle no Thermostat command, and the harness does not drive them); decode smoke, the SetWeeklySchedule matter.js vector and `chip-xml-conformance.py` class S only |
| EnergyEvse on evse-app (exact attributes, all 23 with all five features; RandomizationDelayWindow written, refused above 86400 s, restored; ApproximateEvEfficiency written, nulled, restored; triggers: plug in → EvConnected with a new session (SessionID incremented, or 0 from null; the attribute agrees), demand + EnableCharging at 40 A → EnergyTransferStarted clamped to 32 A, Disable → EnergyTransferStopped (EvseStopped), unplug → EvNotDetected, one session id throughout; ground fault → Fault, State Fault, EnableCharging refused, clear → Fault; RFID → Rfid; SetTargets / GetTargets round trip, a target without TargetSoC refused (InvalidCommand at master; v1.4.2.0's server answers Failure), ClearTargets) | `clusters_evse::energy_evse_decodes_every_attribute_and_writes_its_settings`, `…_charging_session_emits_its_events`, `…_fault_and_rfid_emit_their_events`, `…_targets_round_trip_and_clear` | ✓-live (local master 5cd2917a), **local only** (`just integration-energy`; evse-app is not in the nightly) |
| DeviceEnergyManagement on evse-app (exact attributes, all eight with features 0x7B, EVSEManufacturerImpl.cpp's values; PowerAdjustRequest refused outside the trigger's capability and after a local opt-out, accepted → PowerAdjustStart and PowerAdjustActive, CancelPowerAdjustRequest → PowerAdjustEnd (Cancelled), a second cancel InvalidInState; PauseRequest refused below MinPauseDuration, accepted → Paused, ResumeRequest → Resumed (Cancelled), a second resume InvalidInState) | `clusters_evse::device_energy_management_decodes_every_attribute`, `…_power_adjustment_starts_and_cancels`, `…_pause_and_resume` | ✓-live (local master 5cd2917a), **local only** (`just integration-energy`) |
| PowerTopology on evse-app (NODE only: no attribute beyond the globals) | `clusters_evse::power_topology_serves_node_topology_only` | ✓-live (local master 5cd2917a), **local only** (`just integration-energy`) |
| EnergyPreference on all-clusters (exact attributes; the delegate's three balances, two priorities and three sensitivities; both current levels written, refused at the list length, restored) | `clusters_energy::energy_preference_decodes_every_attribute_and_writes_its_levels` | ✓-live (local master 5cd2917a); ✓-nightly (v1.4.2.0: nightly 38093808826 on 3925050) — delegate and server the same at both refs |
| WaterHeaterManagement on all-clusters (exact attributes; Boost to 80 % with a 20 % reheat → BoostState Active and BoostStarted echoing the BoostInfo; CancelBoost → BoostEnded, Inactive; a TargetReheat without TargetPercentage, and one with OneShot, refused with InvalidCommand — chip's server checks both only with the TankPercent feature, which all-clusters sets; without it, it refuses any TargetPercentage or TargetReheat) | `clusters_energy::water_heater_management_boosts_and_cancels`, `clusters_energy::water_heater_boost_refuses_a_reheat_that_breaks_its_rules` | ✓-nightly (v1.4.2.0: nightly 38093808826 on 3925050); **skipped locally**: master's all-clusters no longer serves it. Master's server (WaterHeaterManagementCluster.cpp) has no live run: water-heater-app, its master host, is not built |
| DeviceEnergyManagement, EnergyEvse (17 attributes, PREF and RFID; GetTargets), PowerTopology (SET and DYPF, empty lists) on all-clusters | `clusters_energy::energy_clusters_decode_on_all_clusters` | ✓-nightly (v1.4.2.0: nightly 38093808826 on 3925050); **skipped locally** (master's all-clusters no longer serves them; evse-app covers them live, above). v1.4.2.0's server answers GetTargets with GetTargetsResponse followed by a Success status for the same path (energy-evse-server.cpp:487-488; master sends only the response); we read the first InvokeResponseIB |
| Messages on tv-app, its only chip host at master and v1.4.2.0 (exact attributes, FeatureMap 0x0F; two messages presented arrive in order with every field and no FabricIndex; CancelMessagesRequest with a `list<octstr>` of both and an unknown id empties both lists; a 15-byte id, a response id 0, five responses and a 15-byte cancel id refused with ConstraintError) | `clusters_messages::messages_present_and_cancel_round_trip`, `clusters_messages::messages_refuse_malformed_requests` | ✓-live on a Linux arm64 Pi (`just integration-tv`, tv-app built at chip master 5cd2917a and at v1.4.2.0): 2 of 2 at both refs since M9-A3 B7 paces each exchange (`fixture::settle_acks`); unpaced, master's 15-buffer tv-app dropped the second test's response. Nightly (v1.4.2.0) from the next run. The §5.4 multi-fabric step does not apply: chip does not fabric-scope MessageStruct, so tv-app sends every entry in full to every fabric |
| LocalizationConfiguration, TimeFormatLocalization, UnitLocalization on all-clusters (exact attributes; another supported locale, hour format and temperature unit written, read back and restored; a locale, calendar, hour format and unit outside the supported values refused with ConstraintError and nothing changed) | `clusters_configuration::localization_configuration_writes_only_a_supported_locale`, `clusters_configuration::time_format_localization_writes_hour_format_and_calendar`, `clusters_configuration::unit_localization_writes_only_a_supported_unit` | ✓-live (local master 5cd2917a); ✓-nightly (v1.4.2.0: nightly 38120287902 on 9fe51d8) |
| PowerSourceConfiguration on all-clusters (Sources = [2, 1, 0], the PowerSource endpoints by Order) | `clusters_configuration::power_source_configuration_lists_sources_by_order` | ✓-live (local master 5cd2917a); ✓-nightly (v1.4.2.0: nightly 38120287902 on 9fe51d8) |
| Actions on all-clusters endpoint 1 (exact attributes; the stub's three scene actions and three endpoint lists; InstantAction on a known action refused with InvalidCommand (no supported commands), on an unknown one with NotFound; StartActionWithDuration on a known action refused with InvalidCommand) | `clusters_configuration::actions_decode_the_stub_and_refuse_its_commands` | ✓-live (local master 5cd2917a); ✓-nightly (v1.4.2.0: nightly 38120287902 on 9fe51d8). all-clusters never emits Actions' events (chip's server refuses every command before the stub's delegate runs); bridge-app's `runOnOffRoomAction` logs StateChanged, but bridge-app was not built, so the events are covered by decode smoke only |
| GeneralCommissioning on all-clusters, already commissioned (exact attributes; BasicCommissioningInfo 60 s / 900 s; Breadcrumb written; ArmFailSafe(10, 7) arms and sets the breadcrumb, ArmFailSafe(0) disarms and resets it; SetRegulatoryConfig with a location above IndoorOutdoor → ValueOutsideRange, with a one-character country code → ConstraintError, nothing stored) | `clusters_commissioning::general_commissioning_decodes_and_arms_and_disarms_the_fail_safe`, `clusters_commissioning::general_commissioning_refuses_bad_regulatory_configs` | ✓-live (local master 5cd2917a); ✓-nightly (v1.4.2.0: nightly 38120287902 on 9fe51d8). No CommissioningComplete; `matter-commissioning`'s hand-written codecs, which commission every DUT, are pinned byte-equal to these by `generated_codec_parity.rs` |
| NetworkCommissioning on all-clusters endpoint 0 (FeatureMap ET; exactly Ethernet's six attributes, each decoded; MaxNetworks 1, one network) | `clusters_commissioning::network_commissioning_decodes_the_ethernet_interface` | ✓-live (local master 5cd2917a); ✓-nightly (v1.4.2.0: nightly 38120287902 on 9fe51d8). No network command and no write (they would reconfigure the DUT; an Ethernet interface accepts none) |
| SoftwareDiagnostics on all-clusters (exact attributes, ThreadMetrics included; ResetWatermarks; TestEventTrigger → SoftwareFault with the process id as Id and Name) | `clusters_node_diagnostics::software_diagnostics_decodes_resets_and_reports_a_fault` | ✓-live (local master 5cd2917a, and v1.4.2.0 linux-arm64 on a Pi); ✓-nightly (v1.4.2.0 linux-x64: nightly 38120287902 on 9fe51d8) |
| WiFiNetworkDiagnostics on all-clusters (all 13 attributes; ResetCounts; TestEventTrigger → Disconnection (reason 3), AssociationFailure (AuthenticationFailed, status 4), ConnectionStatus (NotConnected)) | `clusters_node_diagnostics::wifi_diagnostics_decode_reset_and_report_their_events` | ✓-live (local master 5cd2917a, and v1.4.2.0 linux-arm64 on a Pi); ✓-nightly (v1.4.2.0 linux-x64: nightly 38120287902 on 9fe51d8) |
| ThreadNetworkDiagnostics, EthernetNetworkDiagnostics on all-clusters (every served attribute decodes: Thread 0x00–0x40 at master (revision 3), 0x00–0x3E at v1.4.2.0 (revision 2), the list chosen by the revision in the checkout's `all-clusters-app.matter` and checked against the DUT's ClusterRevision; Ethernet all nine; both ResetCounts) | `clusters_node_diagnostics::thread_and_ethernet_diagnostics_decode_and_reset` | ✓-live (local master 5cd2917a, and v1.4.2.0 linux-arm64 on a Pi); ✓-nightly (v1.4.2.0 linux-x64: nightly 38120287902 on 9fe51d8). ThreadNetworkDiagnostics' events have no stimulus in any chip app (decode smoke only) |
| DiagnosticLogs on all-clusters (each intent's ResponsePayload request → NoLogs, empty LogContent, no timestamps; BDX without a designator and an unknown intent → InvalidCommand) | `clusters_node_diagnostics::diagnostic_logs_answer_no_logs_and_refuse_bad_requests` | ✓-live (local master 5cd2917a, and v1.4.2.0 linux-arm64 on a Pi); ✓-nightly (v1.4.2.0 linux-x64: nightly 38120287902 on 9fe51d8). No BDX log transfer (not implemented) |
| EcosystemInformation | — | **not run**: no app the harness drives serves it. chip's fabric-bridge-app and fabric-sync serve it (on their dynamic bridged-device endpoints, at master and v1.4.2.0) with empty directories; neither has been run against this library. Decode smoke (both fabrics' entry shapes) and `chip-xml-conformance.py` only |
| CommissionerControl on fabric-bridge-app or fabric-sync | — | **not run**: fabric-bridge-app and fabric-sync, its chip hosts at master and v1.4.2.0 (`fabric-bridge-app/linux/CommissionerControlDelegate.cpp`, `fabric-sync/bridge/CommissionerControlDelegate.cpp`), need ZAP at build time (fabric-sync builds on fabric-bridge-app's generated code; ZAP is x86_64-only on macOS; no Rosetta 2 here). fabric-bridge-app builds on a Linux arm64 Pi (chip master 5cd2917a), but no test has run against either yet, and it is an optional host for this project's validation; decode smoke and `chip-xml-conformance.py` only |
| WiFiNetworkManagement, ThreadBorderRouterManagement, ThreadNetworkDirectory on network-manager-app | — | **not run**: network-manager-app, the chip host of all three at master and v1.4.2.0 (ThreadBorderRouterManagement is also served by thread-br-app and a few others), needs ZAP at build time (x86_64-only on macOS; no Rosetta 2 here). It builds on a Linux arm64 Pi (chip master 5cd2917a), but no test has run against it yet, and it is an optional host for this project's validation; decode smoke and `chip-xml-conformance.py` only |
| WakeOnLan, LowPower on all-clusters endpoint 1 (WakeOnLan serves MACAddress only, an empty string all-clusters never sets; LowPower has no attributes, and Sleep succeeds: all-clusters' `LowPowerManager` returns true) | `clusters_wake_and_power::wake_on_lan_and_low_power_on_all_clusters` | ✓-live (local master 5cd2917a on macOS arm64, and v1.4.2.0 linux-arm64 on a Pi); nightly (v1.4.2.0 linux-x64) from the next run |
| WakeOnLan, LowPower, KeypadInput on tv-app endpoint 1 (WakeOnLan serves MACAddress only, 12 hex digits; Sleep succeeds; KeypadInput has no attributes, Select answers Success and an unknown key code UnsupportedKey) | `clusters_media::wake_on_lan_mac_and_low_power_sleep`, `clusters_media::keypad_input_sends_a_key_and_refuses_an_unknown_one` | ✓-live on a Linux arm64 Pi (tv-app at chip master 5cd2917a and v1.4.2.0); nightly (v1.4.2.0) from the next run |
| MediaInput, AudioOutput on tv-app endpoint 1 (the delegate's two inputs and three outputs; select and rename change the attributes and are put back; an index outside the list answers Failure) | `clusters_media::media_input_and_audio_output_select_and_rename` | ✓-live on a Linux arm64 Pi (both refs); nightly (v1.4.2.0) from the next run |
| TargetNavigator on tv-app endpoint 1 (two targets; NavigateTarget(2) succeeds and moves CurrentTarget; targets 0 and 3 answer TargetNotFound) | `clusters_media::target_navigator_navigates_and_refuses_unknown_targets` | ✓-live on a Linux arm64 Pi (both refs); nightly (v1.4.2.0) from the next run. TargetUpdated has no stimulus that reaches the log (chip's server logs it on endpoint 0 only when an ember attribute changes): decode smoke only |
| MediaPlayback on tv-app endpoint 1 (all eleven attributes, ActiveTextTrack with a null TrackAttributes: the class-N relaxation; DisplayName at chip's tag 1 skipped; Play / Pause change CurrentState; Seek in range and past SeekRangeEnd (SeekOutOfRange); text track activated and refused (InvalidInState); audio track with index 0 accepted and with a null index refused (InvalidCommand)) | `clusters_media::media_playback_decodes_tv_apps_tracks`, `clusters_media::media_playback_plays_seeks_and_switches_tracks` | ✓-live on a Linux arm64 Pi (both refs); nightly (v1.4.2.0) from the next run. StateChanged has no stimulus (decode smoke only) |
| ContentLauncher on tv-app endpoint 1 (AcceptHeader, SupportedStreamingProtocols 0; LaunchContent with the nested search and every preference non-null succeeds, a null TextTrack is refused (InvalidCommand); LaunchURL with BrandingInformation's doubles succeeds, the delegate's two test URLs answer UrlNotAvailable and AuthFailed) | `clusters_media::content_launcher_launches_content_and_urls` | ✓-live on a Linux arm64 Pi (both refs); nightly (v1.4.2.0) from the next run |
| Channel on tv-app endpoint 1 (the four channels and the Comcast lineup; ChangeChannel by name (Success), by a shared affiliate call sign (MultipleMatches) and unknown (NoMatches); ChangeChannelByNumber to a channel and to none (Failure); SkipChannel wraps forward past World Channel and back past ABC; ends on ABC) | `clusters_tv_apps::channel_lists_and_changes_channels` | ✓-live on a Linux arm64 Pi (tv-app at chip master 5cd2917a and v1.4.2.0); nightly (v1.4.2.0) from the next run |
| Channel GetProgramGuide on tv-app (the four programs in the window 0-3600; StartTime 1800 keeps only abc2 and EndTime 1800 only abc1 and pbs1; a channel list keeps pbs1; a RecordingFlag at the specification's tag 5 refused with InvalidCommand: chip numbers it 4. The requests that succeed leave out RecordingFlag, ExternalIDList and PageToken: chip also refuses a null PageToken) | `clusters_tv_apps::channel_program_guide_filters_and_chips_field_numbering` | ✓-live on a Linux arm64 Pi (both refs); nightly (v1.4.2.0) from the next run |
| ApplicationLauncher on tv-app endpoint 1 (CatalogList 123, 456; CurrentApp null; LaunchApp, HideApp, StopApp, which chip's server hands to the named Content App (Vendor1), answer Success with "data"; LaunchApp without an Application refused with InvalidCommand) | `clusters_tv_apps::application_launcher_launches_hides_and_stops` | ✓-live on a Linux arm64 Pi (both refs); nightly (v1.4.2.0) from the next run |
| ContentControl (provisional) on tv-app endpoint 1 (six attributes: the two rating lists fail to read (FAILURE: chip's server registers no attribute-access handler for them); seven commands answer Success, Enable / Disable as timed invokes at master; ResetPIN answers Failure (tv-app's handler never responds); AddBlockChannels UnsupportedCommand (not handled; absent from v1.4.2.0's codegen)) | `clusters_tv_apps::content_control_stub_answers_its_commands` | ✓-live on a Linux arm64 Pi (both refs); nightly (v1.4.2.0) from the next run. Neither chip's server nor tv-app logs either event (decode smoke only) |
| ApplicationBasic on tv-app's five Content App endpoints, found by VendorID (static endpoint 3 with all eight attributes; the four installed apps with seven, Application not declared; identities and Stopped status) | `clusters_tv_apps::content_apps_identify_themselves` | ✓-live on a Linux arm64 Pi (both refs); nightly (v1.4.2.0) from the next run |
| AccountLogin on tv-app's Vendor3 Content App (GetSetupPIN returns the PIN, redacted in `Debug`; Login with a wrong PIN UnsupportedAccess, with the right one Success; Logout Success; all three timed) | `clusters_tv_apps::account_login_issues_and_checks_a_setup_pin` | ✓-live on a Linux arm64 Pi (both refs); nightly (v1.4.2.0) from the next run. chip's server never logs LoggedOut (it leaves the event's FabricIndex unset, and `LogEvent` refuses it): decode smoke only |
| ContentAppObserver | — | **not run**: of chip's example apps only tv-casting-app serves it (both refs; tv-app's static Content App endpoint 3 is its client), and the harness does not drive tv-casting-app (an optional host for this project's validation); decode smoke and `chip-xml-conformance.py` only |

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

### Events and fabric-sensitive decode (M9-A3 B1)

Generated `<Name>Event` decoders run against events read from the live DUT;
the multi-fabric step runs the §5.4 fabric-sensitive decoders against chip's
real withheld-field encoding.

| Operation | Test | Status |
|---|---|---|
| Event sweep on all-clusters: BasicInformation + GeneralDiagnostics (boot + app-pipe fault events), OccupancySensing + BooleanState (app pipe), AccessControl (our own ACL/Extension writes), and TimeSynchronization / PowerSource / PumpConfigurationAndControl / OtaSoftwareUpdateRequestor (decode whatever is reported) | `clusters_events::{basic_information_and_general_diagnostics_events_decode, occupancy_and_boolean_state_events_decode, access_control_events_decode, time_sync_power_source_pump_and_ota_events_decode}` | ✓-live |
| DoorLock events: LockOperation, DoorLockAlarm, DoorStateChange, LockUserChange, LockOperationError (on lock-app) | `clusters_door_lock::door_lock_events_from_lock_app` | ✓-live, **local only** (`just integration-lock`) |
| ElectricalEnergyMeasurement energy-reporting events: CumulativeEnergyMeasured + PeriodicEnergyMeasured from the fake-load test event trigger; ElectricalPowerMeasurement `MeasurementPeriodRanges` decoded if reported (on evse-app) | `clusters_electrical::energy_reporting_events_decode` | ✓-live, **local only** (`just integration-energy`) |
| Multi-fabric §5.4: another fabric's AccessControl `Acl` / `Extension` and ScenesManagement `FabricSceneInfo` entries decode with every fabric-sensitive field `None`; a withheld Extension entry refuses to re-encode; `read_acl` → `write_acl` round trip leaves the other fabric's access intact | `multi_admin::open_window_second_controller_and_remove_fabric` (`assert_acl_entries_withheld`, `assert_acl_round_trip_keeps_other_fabric`, `assert_fabric_scene_info_withheld`) | ✓-live |

Limits of this coverage, stated so they are not mistaken for gaps closed:

- The lock-app, evse-app, rvc-app and microwave-oven-app suites are **local
  only** (rvc-app and microwave-oven-app on a Raspberry Pi): they are not in
  `.github/workflows/integration-nightly.yml`, which runs the all-clusters,
  ICD and OTA sweeps, and the tv-app sweep from its next run. Locally, the
  tv-app sweep runs on a Raspberry Pi.
- bridge-app was not built, so BridgedDeviceBasicInformation events are
  validated only by decode smoke and `scripts/chip-xml-conformance.py`.
- all-clusters has no stimulus for PowerSource, PumpConfigurationAndControl or
  OtaSoftwareUpdateRequestor events, and the live run decoded 0 of them: those
  decoders are covered by decode smoke only.
- IcdManagement `RegisteredClients` and AccessControl `Arl` (the other
  fabric-sensitive lists) are not covered live: no B1 host serves ICD, and
  all-clusters lacks the MNGD feature that carries `Arl`.

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
`matter_clusters::clusters::*::decode_*` typed decoders, asserting `Ok` (plus the exact
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
- **Validated on a GitHub runner (2026-07-03, run 28670513815):** the workflow
  builds all-clusters-app on Linux, launches it as the DUT, and runs the full
  sweep green end to end. The first dispatches surfaced two missing apt build
  deps (`libevent-dev` for ot-commissioner, `libavahi-client-dev` for mDNS),
  now installed by the prerequisites step.
- This document is the standing coverage record (see the "Status summary" and
  "Known DUT gaps" at the top, and the per-cluster tables above).
