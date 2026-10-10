//! Freezes `xtask/model/clusters.json` — the committed codegen input.
//!
//! Reads the committed JSON (no Node), so it runs in CI and catches a
//! malformed or under-covered regen before it can land. Typed
//! deserialization + semantic validation is M7.3's `codegen/model.rs`;
//! this is a shape-and-coverage gate only.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

/// The M7 target clusters (CLAUDE.md milestone / spec §8) plus the M9-A2.1
/// pilot batch (read-only sensors + Switch), the M9-A2.2 energy batch,
/// M9-A2.3 actuator batch, M9-A2.4 utility batch, M9-A2.5 mgmt batch, M9-D2
/// operational credentials, and the concentration measurement family (#112).
const TARGET_CLUSTERS: [&str; 72] = [
    "BasicInformation",
    "Descriptor",
    "Identify",
    "OnOff",
    "LevelControl",
    "ColorControl",
    "OccupancySensing",
    "TemperatureMeasurement",
    "RelativeHumidityMeasurement",
    "DoorLock",
    // M9-A2.1 pilot batch:
    "IlluminanceMeasurement",
    "PressureMeasurement",
    "FlowMeasurement",
    "BooleanState",
    "Switch",
    // M9-A2.2 energy batch:
    "PowerSource",
    "ElectricalPowerMeasurement",
    "ElectricalEnergyMeasurement",
    "AirQuality",
    // M9-A2.3 actuators batch:
    "Thermostat",
    "FanControl",
    "ThermostatUserInterfaceConfiguration",
    "PumpConfigurationAndControl",
    "WindowCovering",
    // M9-A2.4 utility batch:
    "Groups",
    "Binding",
    "GeneralDiagnostics",
    "FixedLabel",
    "UserLabel",
    // M9-A2.5 mgmt batch:
    "AccessControl",
    "GroupKeyManagement",
    "AdministratorCommissioning",
    "OtaSoftwareUpdateRequestor",
    // M9-D2 operational credentials:
    "OperationalCredentials",
    // M9-F1 OTA Provider:
    "OtaSoftwareUpdateProvider",
    // M9-G-a Time Synchronization:
    "TimeSynchronization",
    // M9-G-c ICD Management:
    "IcdManagement",
    // Concentration measurement family (Matter 1.2), #112:
    "CarbonMonoxideConcentrationMeasurement",
    "CarbonDioxideConcentrationMeasurement",
    "NitrogenDioxideConcentrationMeasurement",
    "OzoneConcentrationMeasurement",
    "Pm25ConcentrationMeasurement",
    "FormaldehydeConcentrationMeasurement",
    "Pm1ConcentrationMeasurement",
    "Pm10ConcentrationMeasurement",
    "TotalVolatileOrganicCompoundsConcentrationMeasurement",
    "RadonConcentrationMeasurement",
    // Matter bridge support (Phase 0):
    "BridgedDeviceBasicInformation",
    // M9-A3 B2, ModeBase-derived:
    "OvenMode",
    "LaundryWasherMode",
    "RefrigeratorAndTemperatureControlledCabinetMode",
    "RvcRunMode",
    "RvcCleanMode",
    "DishwasherMode",
    "MicrowaveOvenMode",
    "EnergyEvseMode",
    "WaterHeaterMode",
    "DeviceEnergyManagementMode",
    // M9-A3 B2, ModeSelect:
    "ModeSelect",
    // M9-A3 B2, AlarmBase-derived:
    "RefrigeratorAlarm",
    "DishwasherAlarm",
    // M9-A3 B2, ResourceMonitoring-derived:
    "HepaFilterMonitoring",
    "ActivatedCarbonFilterMonitoring",
    "WaterTankLevelMonitoring",
    // M9-A3 B3, OperationalState family:
    "OperationalState",
    "OvenCavityOperationalState",
    "RvcOperationalState",
    // M9-A3 B3, appliance controls:
    "TemperatureControl",
    "LaundryWasherControls",
    "LaundryDryerControls",
    "MicrowaveOvenControl",
    // M9-A3 B3, ServiceArea:
    "ServiceArea",
];

fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("model/clusters.json");
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("clusters.json must be valid JSON")
}

fn clusters(v: &Value) -> &Vec<Value> {
    v["clusters"].as_array().expect("clusters array")
}

#[test]
fn covers_exactly_the_target_clusters() {
    let v = load();
    let names: Vec<&str> = clusters(&v)
        .iter()
        .map(|c| c["name"].as_str().expect("cluster name"))
        .collect();
    for want in TARGET_CLUSTERS {
        assert!(names.contains(&want), "missing target cluster {want}");
    }
    assert_eq!(
        clusters(&v).len(),
        TARGET_CLUSTERS.len(),
        "expected exactly {} clusters, got {names:?}",
        TARGET_CLUSTERS.len()
    );
}

#[test]
fn every_cluster_has_id_revision_and_attributes() {
    let v = load();
    for c in clusters(&v) {
        let name = c["name"].as_str().unwrap();
        assert!(c["id"].is_number(), "{name}: missing numeric id");
        assert!(
            c["revision"].is_number(),
            "{name}: missing numeric revision"
        );
        // A cluster must expose at least one attribute OR one command. Most are
        // attribute-bearing; OtaSoftwareUpdateProvider (0x0029) is command-only
        // (QueryImage/ApplyUpdateRequest/NotifyUpdateApplied, no server attrs).
        let attrs = c["attributes"].as_array().expect("attributes array");
        let cmds = c["commands"].as_array().map_or(0, Vec::len);
        assert!(
            !attrs.is_empty() || cmds > 0,
            "{name}: expected at least one attribute or command"
        );
    }
}

#[test]
fn header_is_populated_and_every_exclusion_has_a_reason() {
    let v = load();
    let meta = &v["meta"];
    assert!(
        meta["matterJsModelVersion"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "meta.matterJsModelVersion missing"
    );
    assert!(
        meta["specRevision"].as_str().is_some_and(|s| !s.is_empty()),
        "meta.specRevision missing"
    );
    let excluded = meta["excluded"].as_array().expect("meta.excluded array");
    for e in excluded {
        assert!(
            e["reason"].as_str().is_some_and(|r| !r.is_empty()),
            "exclusion without a reason: {e}"
        );
    }
}

#[test]
fn no_global_attributes_leaked_into_clusters() {
    let v = load();
    for c in clusters(&v) {
        let name = c["name"].as_str().unwrap();
        for a in c["attributes"].as_array().unwrap() {
            let id = a["id"].as_u64().expect("attribute id");
            assert!(id < 0xFFF8, "{name}: global attribute {id:#x} leaked");
        }
    }
}

#[test]
fn doorlock_aliro_surface_is_excluded_and_recorded() {
    let v = load();
    let dl = clusters(&v)
        .iter()
        .find(|c| c["name"] == "DoorLock")
        .expect("DoorLock present");

    // No Aliro command survived (SetAliroReaderConfig / ClearAliroReaderConfig).
    for cmd in dl["commands"].as_array().unwrap() {
        let cname = cmd["name"].as_str().unwrap();
        assert!(!cname.contains("Aliro"), "Aliro command leaked: {cname}");
    }
    // No Aliro attribute survived.
    for a in dl["attributes"].as_array().unwrap() {
        let aname = a["name"].as_str().unwrap();
        assert!(!aname.contains("Aliro"), "Aliro attribute leaked: {aname}");
    }
    // And the exclusion was recorded with an aliro reason.
    let recorded = v["meta"]["excluded"].as_array().unwrap().iter().any(|e| {
        e["cluster"] == "DoorLock" && e["reason"].as_str().is_some_and(|r| r.contains("aliro"))
    });
    assert!(recorded, "DoorLock Aliro exclusions not recorded in header");
}

// ---- M9-A3 B1: fabric-sensitive fields (spec §5.4) ---------------------------

/// Every datatype-struct field the dump relaxes because a device withholds it
/// for other fabrics' entries: `(cluster, struct, field)`. Each is
/// `fabricSensitive`, `optional` (for decode) and `mandatoryOnWrite`. A model
/// change that adds or drops one must be reviewed, so the set is pinned exactly.
const FABRIC_SENSITIVE_RELAXED: [(&str, &str, &str); 11] = [
    ("AccessControl", "AccessControlEntryStruct", "AuthMode"),
    ("AccessControl", "AccessControlEntryStruct", "Privilege"),
    ("AccessControl", "AccessControlEntryStruct", "Subjects"),
    ("AccessControl", "AccessControlEntryStruct", "Targets"),
    ("AccessControl", "AccessControlExtensionStruct", "Data"),
    ("AccessControl", "AccessRestrictionEntryStruct", "Cluster"),
    ("AccessControl", "AccessRestrictionEntryStruct", "Endpoint"),
    (
        "AccessControl",
        "AccessRestrictionEntryStruct",
        "Restrictions",
    ),
    (
        "IcdManagement",
        "MonitoringRegistrationStruct",
        "CheckInNodeId",
    ),
    (
        "IcdManagement",
        "MonitoringRegistrationStruct",
        "ClientType",
    ),
    (
        "IcdManagement",
        "MonitoringRegistrationStruct",
        "MonitoredSubject",
    ),
];

#[test]
fn level_control_with_on_off_commands_carry_their_base_fields() {
    // The dump reads command `members`: the four *WithOnOff commands declare
    // no fields of their own and take MoveToLevel / Move / Step / Stop's.
    // Read from `children` they came out empty (released bug, M9-A3 B2).
    let v = load();
    let lc = clusters(&v)
        .iter()
        .find(|c| c["name"] == "LevelControl")
        .unwrap();
    // (id, name, type, optional, nullable): the id is the field's context tag,
    // so a renumbering regression is caught as well as a missing field.
    let fields = |name: &str| -> Vec<(u64, String, String, bool, bool)> {
        lc["commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("LevelControl.{name} not dumped"))["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["id"].as_u64().unwrap(),
                    f["name"].as_str().unwrap().to_string(),
                    f["type"].as_str().unwrap().to_string(),
                    f["optional"].as_bool().unwrap(),
                    f["nullable"].as_bool().unwrap(),
                )
            })
            .collect()
    };
    for (base, with) in [
        ("MoveToLevel", "MoveToLevelWithOnOff"),
        ("Move", "MoveWithOnOff"),
        ("Step", "StepWithOnOff"),
        ("Stop", "StopWithOnOff"),
    ] {
        assert_ne!(fields(with), [], "{with} has no fields");
        assert_eq!(fields(with), fields(base), "{with}");
    }
}

#[test]
fn dump_script_version_is_5() {
    assert_eq!(load()["meta"]["dumpScriptVersion"], 5);
}

#[test]
fn relaxed_fabric_sensitive_fields_are_optional_mandatory_on_write_and_recorded() {
    let v = load();
    let mut marked = Vec::new();
    for c in clusters(&v) {
        let cname = c["name"].as_str().unwrap();
        for d in c["datatypes"].as_array().unwrap() {
            for f in d["fields"].as_array().into_iter().flatten() {
                if f["mandatoryOnWrite"] == true {
                    let fname = f["name"].as_str().unwrap();
                    assert_eq!(
                        f["optional"], true,
                        "{cname}.{}.{fname} not optional",
                        d["name"]
                    );
                    assert_eq!(
                        f["fabricSensitive"], true,
                        "{cname}.{}.{fname} mandatoryOnWrite but not fabricSensitive",
                        d["name"]
                    );
                    marked.push((
                        cname.to_string(),
                        d["name"].as_str().unwrap().to_string(),
                        fname.to_string(),
                    ));
                }
                if f["id"] == 254 {
                    assert!(
                        f.get("fabricSensitive").is_none() && f.get("mandatoryOnWrite").is_none(),
                        "{cname}.{}: FabricIndex marked",
                        d["name"]
                    );
                }
            }
        }
    }
    marked.sort();
    let want: Vec<(String, String, String)> = FABRIC_SENSITIVE_RELAXED
        .iter()
        .map(|(c, d, f)| ((*c).to_string(), (*d).to_string(), (*f).to_string()))
        .collect();
    assert_eq!(marked, want);

    let relaxed = v["meta"]["relaxed"].as_array().expect("meta.relaxed array");
    let fabric_sensitive = relaxed
        .iter()
        .filter(|r| r["reason"] == "fabric-sensitive (withheld for other fabrics)")
        .count();
    assert_eq!(fabric_sensitive, FABRIC_SENSITIVE_RELAXED.len());
    for (c, d, f) in FABRIC_SENSITIVE_RELAXED {
        let element = format!("{d}.{f}");
        assert!(
            relaxed.iter().any(|r| r["cluster"] == c
                && r["element"] == element.as_str()
                && r["class"] == "P"
                && r["reason"] == "fabric-sensitive (withheld for other fabrics)"),
            "meta.relaxed lacks {c}.{element}"
        );
    }
}

#[test]
fn no_event_or_command_field_is_marked_fabric_sensitive() {
    // Spec §5.4 "Events are exempt": the marker is for datatype structs only.
    let v = load();
    for c in clusters(&v) {
        let cname = c["name"].as_str().unwrap();
        let payloads = c["events"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(c["commands"].as_array().into_iter().flatten());
        for p in payloads {
            for f in p["fields"].as_array().unwrap() {
                assert!(
                    f.get("fabricSensitive").is_none() && f.get("mandatoryOnWrite").is_none(),
                    "{cname}.{}.{}: payload field carries a write marker",
                    p["name"],
                    f["name"]
                );
            }
        }
    }
}

// ---- M9-A3: event codegen roll-out -------------------------------------------

/// The clusters whose events are dumped (`EVENT_ALLOWLIST` in the dump script),
/// grown batch by batch.
const EVENT_CLUSTERS: [&str; 19] = [
    "Switch",
    // M9-A3 B1, scalar-field payloads:
    "BasicInformation",
    "BooleanState",
    "OccupancySensing",
    "PumpConfigurationAndControl",
    "TimeSynchronization",
    "OtaSoftwareUpdateRequestor",
    // M9-A3 B1, list-of-enum payloads:
    "GeneralDiagnostics",
    "PowerSource",
    // M9-A3 B1, composite-field payloads:
    "AccessControl",
    "ElectricalEnergyMeasurement",
    "ElectricalPowerMeasurement",
    "DoorLock",
    // M9-A3 B1, derived cluster:
    "BridgedDeviceBasicInformation",
    // M9-A3 B2, AlarmBase-derived:
    "RefrigeratorAlarm",
    "DishwasherAlarm",
    // M9-A3 B3, OperationalState family (OperationalError, OperationCompletion):
    "OperationalState",
    "OvenCavityOperationalState",
    "RvcOperationalState",
];

#[test]
fn event_enabled_clusters_are_exactly_the_allowlist() {
    let v = load();
    let mut have: Vec<&str> = clusters(&v)
        .iter()
        .filter(|c| c["events"].as_array().is_some_and(|e| !e.is_empty()))
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    have.sort_unstable();
    let mut want = EVENT_CLUSTERS.to_vec();
    want.sort_unstable();
    assert_eq!(have, want);
    for e in v["meta"]["excluded"].as_array().unwrap() {
        if e["reason"] == "event dump not enabled for this cluster" {
            let cname = e["cluster"].as_str().unwrap();
            assert!(
                !EVENT_CLUSTERS.contains(&cname),
                "{cname} has events dumped AND an 'event dump not enabled' exclusion"
            );
        }
    }
}

#[test]
fn access_control_event_payloads_keep_model_optionality() {
    let v = load();
    let acl = clusters(&v)
        .iter()
        .find(|c| c["name"] == "AccessControl")
        .unwrap();
    let ev = acl["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "AccessControlEntryChanged")
        .expect("AccessControlEntryChanged dumped");
    for f in ev["fields"].as_array().unwrap() {
        assert_eq!(
            f["optional"], false,
            "AccessControlEntryChanged.{} relaxed",
            f["name"]
        );
    }
}

// ---- M9-A3 B2: modes ---------------------------------------------------------

/// ModeBase-derived clusters whose `ChangeToMode` / `ChangeToModeResponse` are
/// generated.
const MODE_BASE_WITH_CHANGE_TO_MODE: [&str; 9] = [
    "OvenMode",
    "LaundryWasherMode",
    "RefrigeratorAndTemperatureControlledCabinetMode",
    "RvcRunMode",
    "RvcCleanMode",
    "DishwasherMode",
    "EnergyEvseMode",
    "WaterHeaterMode",
    "DeviceEnergyManagementMode",
];

fn cluster<'a>(v: &'a Value, name: &str) -> &'a Value {
    clusters(v)
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("{name} not generated"))
}

fn datatype<'a>(c: &'a Value, name: &str) -> &'a Value {
    c["datatypes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .unwrap_or_else(|| panic!("{}: no datatype {name}", c["name"]))
}

fn command<'a>(c: &'a Value, name: &str) -> &'a Value {
    c["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .unwrap_or_else(|| panic!("{}: no command {name}", c["name"]))
}

/// `(name, optional)` for each field of a struct or command.
fn field_optionality(fields: &Value) -> Vec<(&str, bool)> {
    fields
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap(),
                f["optional"].as_bool().unwrap(),
            )
        })
        .collect()
}

fn enum_values(d: &Value) -> Vec<u64> {
    d["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["value"].as_u64().unwrap())
        .collect()
}

#[test]
fn mode_base_derived_clusters_carry_inherited_fields_and_values() {
    // The dump reads `members`: a derived cluster inherits ModeOptionStruct
    // whole (no children of its own) and adds ModeChangeStatus values to the
    // base's Success / UnsupportedMode / GenericFailure / InvalidInMode.
    let v = load();
    for name in MODE_BASE_WITH_CHANGE_TO_MODE {
        let c = cluster(&v, name);
        assert_eq!(
            field_optionality(&datatype(c, "ModeOptionStruct")["fields"]),
            [("Label", false), ("Mode", false), ("ModeTags", false)],
            "{name}"
        );
        let status = enum_values(datatype(c, "ModeChangeStatus"));
        for base in 0..=3 {
            assert!(
                status.contains(&base),
                "{name}: ModeChangeStatus lacks {base}"
            );
        }
        // ModeBase's DEPONOFF (OnOff dependency) is disallowed in every
        // derivative: no Feature flag, and a recorded exclusion.
        assert!(
            !c["features"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["code"] == "DEPONOFF"),
            "{name} kept DEPONOFF"
        );
        assert!(
            v["meta"]["excluded"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["cluster"] == name
                    && e["element"] == "DEPONOFF"
                    && e["kind"] == "feature"
                    && e["reason"] == "disallowed"),
            "{name}: DEPONOFF exclusion missing"
        );
    }
    let run = enum_values(datatype(cluster(&v, "RvcRunMode"), "ModeChangeStatus"));
    assert!((0x41..=0x48).all(|x| run.contains(&x)), "{run:?}");
    let clean = enum_values(datatype(cluster(&v, "RvcCleanMode"), "ModeChangeStatus"));
    assert!(clean.contains(&0x40), "{clean:?}");
}

#[test]
fn only_an_unconditional_m_is_mandatory() {
    // Spec §3.1: StatusText's conformance is "[Status == Success], M", which
    // chip never satisfies (it sends no StatusText), so it is optional.
    // Status ("M") and the request's NewMode ("M") stay mandatory.
    let v = load();
    for name in MODE_BASE_WITH_CHANGE_TO_MODE {
        let c = cluster(&v, name);
        assert_eq!(
            field_optionality(&command(c, "ChangeToModeResponse")["fields"]),
            [("Status", false), ("StatusText", true)],
            "{name}"
        );
        assert_eq!(
            field_optionality(&command(c, "ChangeToMode")["fields"]),
            [("NewMode", false)],
            "{name}"
        );
    }
}

#[test]
fn microwave_oven_mode_has_inherited_fields_and_no_commands() {
    // ChangeToMode and its response are disallowed (X) in MicrowaveOvenMode;
    // both are recorded exclusions, and ModeOptionStruct is still inherited.
    let v = load();
    let c = cluster(&v, "MicrowaveOvenMode");
    assert_eq!(c["commands"], serde_json::json!([]));
    // Its only feature, DEPONOFF, is disallowed (see the derived-cluster test).
    assert_eq!(c["features"], serde_json::json!([]));
    assert_eq!(
        field_optionality(&datatype(c, "ModeOptionStruct")["fields"]),
        [("Label", false), ("Mode", false), ("ModeTags", false)]
    );
    for cmd in ["ChangeToMode", "ChangeToModeResponse"] {
        assert!(
            v["meta"]["excluded"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["cluster"] == "MicrowaveOvenMode"
                    && e["element"] == cmd
                    && e["kind"] == "command"
                    && e["reason"] == "disallowed"),
            "MicrowaveOvenMode.{cmd} exclusion missing"
        );
    }
}

#[test]
fn every_relaxation_is_fabric_sensitive_widened_or_conditional() {
    // meta.relaxed holds exactly the §5.4 presence relaxations (class P), the
    // §5.3 widenings (class W) and the §3.1 conditional-conformance
    // relaxations (class C, decode-only: codegen's model.rs refuses one on a
    // field we send). The one W today is ModeSelect StandardNamespace: model
    // `namespace` is enum8, 1.4.2 is enum16.
    let v = load();
    let relaxed = v["meta"]["relaxed"].as_array().unwrap();
    let widened: Vec<(&str, &str)> = relaxed
        .iter()
        .filter(|r| r["class"] == "W")
        .map(|r| {
            (
                r["cluster"].as_str().unwrap(),
                r["element"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(widened, [("ModeSelect", "Attribute.StandardNamespace")]);
    for r in relaxed {
        assert!(
            r["class"] == "W"
                || r["class"] == "C"
                || (r["class"] == "P"
                    && r["reason"] == "fabric-sensitive (withheld for other fabrics)"),
            "unexpected relaxation {r}"
        );
    }
    let ms = cluster(&v, "ModeSelect");
    let ns = ms["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "StandardNamespace")
        .unwrap();
    assert_eq!(
        (ns["type"].as_str(), ns["nullable"].as_bool()),
        (Some("enum16"), Some(true))
    );
    // The lowercase global `namespace` enum is never inlined as a datatype.
    assert!(
        !ms["datatypes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["name"] == "namespace"),
        "namespace inlined into ModeSelect"
    );
}

#[test]
fn refrigerator_alarm_drops_what_its_disallowed_reset_feature_gates() {
    // RefrigeratorAlarm disallows AlarmBase's RESET feature (1.4.2
    // RefrigeratorAlarm.xml), so Latch and Reset (RESET-gated) can never be
    // implemented, and ModifyEnabledAlarms is disallowed outright. DishwasherAlarm
    // keeps all of them.
    let v = load();
    let names = |c: &Value, key: &str| -> Vec<String> {
        c[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap().to_string())
            .collect()
    };
    let fridge = cluster(&v, "RefrigeratorAlarm");
    assert_eq!(names(fridge, "attributes"), ["Mask", "State", "Supported"]);
    assert_eq!(names(fridge, "commands"), Vec::<String>::new());
    assert_eq!(fridge["features"], serde_json::json!([]));
    let washer = cluster(&v, "DishwasherAlarm");
    assert_eq!(
        names(washer, "attributes"),
        ["Mask", "Latch", "State", "Supported"]
    );
    assert_eq!(names(washer, "commands"), ["Reset", "ModifyEnabledAlarms"]);
    let excluded = v["meta"]["excluded"].as_array().unwrap();
    for (element, kind, reason) in [
        ("RESET", "feature", "disallowed"),
        ("Latch", "attribute", "feature-disallowed (RESET)"),
        ("Reset", "command", "feature-disallowed (RESET)"),
        ("ModifyEnabledAlarms", "command", "disallowed"),
    ] {
        assert!(
            excluded.iter().any(|e| e["cluster"] == "RefrigeratorAlarm"
                && e["element"] == element
                && e["kind"] == kind
                && e["reason"] == reason),
            "RefrigeratorAlarm {kind} {element} exclusion missing"
        );
    }
}

// ---- M9-A3 B3: §3.1 relaxations are recorded and never touch what we send ----

#[test]
fn conditional_conformance_relaxations_are_exactly_the_mode_base_status_texts() {
    // Spec §3.1 relaxes a field whose conformance is mandatory but not an
    // unconditional M. The dump records each one in meta.relaxed with class C
    // and stops if one is a field we send (a request field, or a field of an
    // encoded struct). Today: ChangeToModeResponse.StatusText ("[Status ==
    // Success], M") in the nine generated ModeBase derivatives with
    // ChangeToMode, and nothing else. A new entry here (a later batch, a
    // model upgrade) is a decoder change to review.
    let v = load();
    let mut got: Vec<(&str, &str)> = v["meta"]["relaxed"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["class"] == "C")
        .map(|r| {
            assert_eq!(
                r["reason"],
                "conditional conformance \"[Status == Success], M\" (spec §3.1: only an unconditional M is mandatory)",
                "{r}"
            );
            (
                r["cluster"].as_str().unwrap(),
                r["element"].as_str().unwrap(),
            )
        })
        .collect();
    got.sort_unstable();
    let mut want: Vec<(&str, &str)> = MODE_BASE_WITH_CHANGE_TO_MODE
        .iter()
        .map(|c| (*c, "ChangeToModeResponse.StatusText"))
        .collect();
    want.sort_unstable();
    assert_eq!(got, want);
}

// ---- M9-A3 B3: the OperationalState family ---------------------------------

/// Element names under `key` (`attributes`, `commands`, `events`, ...), in
/// dump order.
fn element_names<'a>(c: &'a Value, key: &str) -> Vec<&'a str> {
    c[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect()
}

#[test]
fn operational_state_derived_clusters_carry_inherited_commands_fields_and_values() {
    // OvenCavityOperationalState and RvcOperationalState inherit their
    // commands, structs, enums and events from OperationalState. Read from
    // `members` (B2's dump fix), the inherited OperationalCommandResponse keeps
    // CommandResponseState and the derived enums keep the base values; on
    // `children` the response came out empty. The disallowed commands
    // (OvenCavity Pause/Resume, Rvc Start/Stop) are excluded, not generated.
    let v = load();
    let excluded = v["meta"]["excluded"].as_array().unwrap();
    for (name, commands, disallowed) in [
        (
            "OperationalState",
            vec![
                "Pause",
                "Stop",
                "Start",
                "Resume",
                "OperationalCommandResponse",
            ],
            vec![],
        ),
        (
            "OvenCavityOperationalState",
            vec!["Stop", "Start", "OperationalCommandResponse"],
            vec!["Pause", "Resume"],
        ),
        (
            "RvcOperationalState",
            vec!["Pause", "Resume", "OperationalCommandResponse", "GoHome"],
            vec!["Start", "Stop"],
        ),
    ] {
        let c = cluster(&v, name);
        assert_eq!(element_names(c, "commands"), commands, "{name}");
        for cmd in disallowed {
            assert!(
                excluded.iter().any(|e| e["cluster"] == name
                    && e["element"] == cmd
                    && e["kind"] == "command"
                    && e["reason"] == "disallowed"),
                "{name}.{cmd} exclusion missing"
            );
        }
        let resp = command(c, "OperationalCommandResponse");
        assert_eq!(
            field_optionality(&resp["fields"]),
            [("CommandResponseState", false)],
            "{name}"
        );
        assert_eq!(resp["fields"][0]["type"], "ErrorStateStruct", "{name}");
        assert_eq!(
            field_optionality(&datatype(c, "ErrorStateStruct")["fields"]),
            [
                ("ErrorStateId", false),
                ("ErrorStateLabel", true),
                ("ErrorStateDetails", true)
            ],
            "{name}"
        );
        assert_eq!(
            field_optionality(&datatype(c, "OperationalStateStruct")["fields"]),
            [
                ("OperationalStateId", false),
                ("OperationalStateLabel", true)
            ],
            "{name}"
        );
        for e in ["OperationalStateEnum", "ErrorStateEnum"] {
            let values = enum_values(datatype(c, e));
            assert!(
                (0..=3).all(|x| values.contains(&x)),
                "{name}.{e}: {values:?}"
            );
        }
        assert_eq!(
            element_names(c, "events"),
            ["OperationalError", "OperationCompletion"],
            "{name}"
        );
        let completion = &c["events"][1]["fields"];
        assert_eq!(
            field_optionality(completion),
            [
                ("CompletionErrorCode", false),
                ("TotalOperationalTime", true),
                ("PausedTime", true)
            ],
            "{name}"
        );
    }
    let rvc = cluster(&v, "RvcOperationalState");
    let states = enum_values(datatype(rvc, "OperationalStateEnum"));
    assert!((0x40..=0x46).all(|x| states.contains(&x)), "{states:?}");
    let errors = enum_values(datatype(rvc, "ErrorStateEnum"));
    assert!((0x40..=0x4E).all(|x| errors.contains(&x)), "{errors:?}");
    // The RVC values are RvcOperationalState's own additions: they must not
    // leak into the base cluster or its other derived cluster (0x40..=0x7F is
    // each derived cluster's own range; 0x80+ is manufacturer-specific and
    // never in the model).
    for name in ["OperationalState", "OvenCavityOperationalState"] {
        let c = cluster(&v, name);
        for e in ["OperationalStateEnum", "ErrorStateEnum"] {
            let values = enum_values(datatype(c, e));
            let high: Vec<u64> = values.into_iter().filter(|x| *x >= 0x40).collect();
            assert_eq!(high, Vec::<u64>::new(), "{name}.{e}");
        }
    }
}

// ---- M9-A3 B3: appliance controls -----------------------------------------------

#[test]
fn appliance_control_commands_have_only_optional_fields_and_watts_are_kept() {
    // SetTemperature's two fields are each gated on a feature (TN, TL), and
    // every SetCookingParameters field is optional or feature-gated, so all of
    // them are Option in the encoders. MicrowaveOvenControl's SupportedWatts
    // and SelectedWattIndex ("P, WATTS" in 1.4.2 and the model) are kept:
    // chip's controller-clusters.matter generates them (as provisional).
    let v = load();
    // Exact names, so an empty field list cannot pass as "all optional".
    let set_temperature = command(cluster(&v, "TemperatureControl"), "SetTemperature");
    assert_eq!(
        field_optionality(&set_temperature["fields"]),
        [
            ("TargetTemperature", true),
            ("TargetTemperatureLevel", true)
        ]
    );
    let cooking = command(cluster(&v, "MicrowaveOvenControl"), "SetCookingParameters");
    assert_eq!(
        field_optionality(&cooking["fields"]),
        [
            ("CookMode", true),
            ("CookTime", true),
            ("PowerSetting", true),
            ("WattSettingIndex", true),
            ("StartAfterSetting", true)
        ]
    );
    assert_eq!(
        element_names(cluster(&v, "MicrowaveOvenControl"), "attributes"),
        [
            "CookTime",
            "MaxCookTime",
            "PowerSetting",
            "MinPower",
            "MaxPower",
            "PowerStep",
            "SupportedWatts",
            "SelectedWattIndex",
            "WattRating"
        ]
    );
}

// ---- M9-A3 B3: ServiceArea ---------------------------------------------------------

#[test]
fn service_area_location_struct_takes_chips_name_and_tags_stay_raw() {
    // The Matter-global `locationdesc` is inlined as LocationDescriptorStruct
    // (chip's name: zap global-structs.xml, controller-clusters.matter), never
    // under its lowercase model name, and every reference points at it. `tag`
    // stays a raw type token (the emitter maps it to u8).
    let v = load();
    let sa = cluster(&v, "ServiceArea");
    let names = element_names(sa, "datatypes");
    assert!(names.contains(&"LocationDescriptorStruct"), "{names:?}");
    assert!(!names.contains(&"locationdesc"), "{names:?}");
    let fields = |d: &str| -> Vec<(String, String, bool, bool)> {
        datatype(sa, d)["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["name"].as_str().unwrap().to_string(),
                    f["type"].as_str().unwrap().to_string(),
                    f["optional"].as_bool().unwrap(),
                    f["nullable"].as_bool().unwrap(),
                )
            })
            .collect()
    };
    let row = |n: &str, t: &str, o: bool, nl: bool| (n.to_string(), t.to_string(), o, nl);
    assert_eq!(
        fields("LocationDescriptorStruct"),
        [
            row("LocationName", "string", false, false),
            row("FloorNumber", "int16", false, true),
            row("AreaType", "tag", false, true),
        ]
    );
    assert_eq!(
        fields("AreaInfoStruct"),
        [
            row("LocationInfo", "LocationDescriptorStruct", false, true),
            row("LandmarkInfo", "LandmarkInfoStruct", false, true),
        ]
    );
    assert_eq!(
        fields("LandmarkInfoStruct"),
        [
            row("LandmarkTag", "tag", false, false),
            row("RelativePositionTag", "tag", false, true),
        ]
    );
    for resp in ["SelectAreasResponse", "SkipAreaResponse"] {
        assert_eq!(
            field_optionality(&command(sa, resp)["fields"]),
            [("Status", false), ("StatusText", false)],
            "{resp}: StatusText is an unconditional M"
        );
    }
}

// ---- M9-A3 B4: provisional and choice-group notes for generated rustdoc ----

/// Every element the dump marks `provisional`, as `(cluster, kind, path)`:
/// kind `feature` (path = code), `attribute`, `command`, `event` (path =
/// name) or `field` (path = `<Owner>.<Field>`, owner a command, event or
/// datatype). Sorted.
fn provisional_elements(v: &Value) -> Vec<(String, &'static str, String)> {
    let mut out = Vec::new();
    for c in clusters(v) {
        let cname = c["name"].as_str().unwrap().to_string();
        for f in c["features"].as_array().unwrap() {
            if f["provisional"] == true {
                out.push((cname.clone(), "feature", f["code"].as_str().unwrap().into()));
            }
        }
        for (key, kind) in [
            ("attributes", "attribute"),
            ("commands", "command"),
            ("events", "event"),
            ("datatypes", ""),
        ] {
            for e in c[key].as_array().unwrap() {
                let name = e["name"].as_str().unwrap();
                if !kind.is_empty() && e["provisional"] == true {
                    out.push((cname.clone(), kind, name.into()));
                }
                for f in e["fields"].as_array().into_iter().flatten() {
                    if f["provisional"] == true {
                        let path = format!("{name}.{}", f["name"].as_str().unwrap());
                        out.push((cname.clone(), "field", path));
                    }
                }
            }
        }
    }
    out.sort();
    out
}

/// Every field the dump gives a `choice` group, as `(cluster, "<Owner>.<Field>",
/// "<group>/<count>[+]")`. Sorted.
fn choice_fields(v: &Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for c in clusters(v) {
        let cname = c["name"].as_str().unwrap();
        for key in ["commands", "events", "datatypes"] {
            for e in c[key].as_array().unwrap() {
                for f in e["fields"].as_array().into_iter().flatten() {
                    let ch = &f["choice"];
                    if ch.is_null() {
                        continue;
                    }
                    let plus = match (ch["orMore"] == true, ch["orLess"] == true) {
                        (true, _) => "+",
                        (_, true) => "-",
                        _ => "",
                    };
                    out.push((
                        cname.to_string(),
                        format!(
                            "{}.{}",
                            e["name"].as_str().unwrap(),
                            f["name"].as_str().unwrap()
                        ),
                        format!("{}/{}{plus}", ch["group"].as_str().unwrap(), ch["count"]),
                    ));
                }
            }
        }
    }
    out.sort();
    out
}

/// The provisional elements of the generated clusters: features, attributes,
/// commands, events and fields whose conformance is `P` or starts with `P`
/// (`P, WATTS`). Each gets a generated "Provisional" rustdoc line. A new entry
/// (a widening, a model upgrade) is a doc change to review.
const PROVISIONAL: [(&str, &str, &str); 14] = [
    ("BasicInformation", "attribute", "ConfigurationVersion"),
    (
        "BridgedDeviceBasicInformation",
        "attribute",
        "ConfigurationVersion",
    ),
    ("DoorLock", "feature", "FACE"),
    ("DoorLock", "feature", "FGP"),
    ("DoorLock", "feature", "RID"),
    ("ElectricalEnergyMeasurement", "feature", "APPE"),
    ("ElectricalEnergyMeasurement", "feature", "REAE"),
    (
        "ElectricalEnergyMeasurement",
        "field",
        "EnergyMeasurementStruct.ApparentEnergy",
    ),
    (
        "ElectricalEnergyMeasurement",
        "field",
        "EnergyMeasurementStruct.ReactiveEnergy",
    ),
    ("GroupKeyManagement", "feature", "CS"),
    ("LevelControl", "feature", "FQ"),
    ("MicrowaveOvenControl", "attribute", "SelectedWattIndex"),
    ("MicrowaveOvenControl", "attribute", "SupportedWatts"),
    ("MicrowaveOvenControl", "feature", "WATTS"),
];

/// Fields in a choice-conformance group (`O.a`, `O.a+`, `[F].b+`): the
/// encoders take each as an `Option` and do not enforce the group, so it is
/// documented on the generated type or encoder.
const CHOICE: [(&str, &str, &str); 11] = [
    (
        "ElectricalEnergyMeasurement",
        "MeasurementAccuracyRangeStruct.FixedMax",
        "a/1+",
    ),
    (
        "ElectricalEnergyMeasurement",
        "MeasurementAccuracyRangeStruct.PercentMax",
        "a/1+",
    ),
    (
        "ElectricalPowerMeasurement",
        "MeasurementAccuracyRangeStruct.FixedMax",
        "a/1+",
    ),
    (
        "ElectricalPowerMeasurement",
        "MeasurementAccuracyRangeStruct.PercentMax",
        "a/1+",
    ),
    (
        "MicrowaveOvenControl",
        "SetCookingParameters.CookMode",
        "b/1+",
    ),
    (
        "MicrowaveOvenControl",
        "SetCookingParameters.CookTime",
        "b/1+",
    ),
    (
        "MicrowaveOvenControl",
        "SetCookingParameters.PowerSetting",
        "b/1+",
    ),
    (
        "MicrowaveOvenControl",
        "SetCookingParameters.WattSettingIndex",
        "b/1+",
    ),
    (
        "OperationalCredentials",
        "SetVidVerificationStatement.VendorId",
        "a/1+",
    ),
    (
        "OperationalCredentials",
        "SetVidVerificationStatement.VidVerificationStatement",
        "a/1+",
    ),
    (
        "OperationalCredentials",
        "SetVidVerificationStatement.Vvsc",
        "a/1+",
    ),
];

#[test]
fn provisional_and_choice_notes_are_exactly_these() {
    let v = load();
    let provisional = provisional_elements(&v);
    let got: Vec<(&str, &str, &str)> = provisional
        .iter()
        .map(|(c, k, p)| (c.as_str(), *k, p.as_str()))
        .collect();
    let mut want = PROVISIONAL.to_vec();
    want.sort_unstable();
    assert_eq!(got, want);
    let choices = choice_fields(&v);
    let got: Vec<(&str, &str, &str)> = choices
        .iter()
        .map(|(c, f, g)| (c.as_str(), f.as_str(), g.as_str()))
        .collect();
    let mut want = CHOICE.to_vec();
    want.sort_unstable();
    assert_eq!(got, want);
}

#[test]
fn service_area_location_struct_records_its_global_name() {
    let v = load();
    let d = datatype(cluster(&v, "ServiceArea"), "LocationDescriptorStruct");
    assert_eq!(d["globalName"], "locationdesc");
    let named: Vec<&str> = clusters(&v)
        .iter()
        .flat_map(|c| c["datatypes"].as_array().unwrap())
        .filter(|d| !d["globalName"].is_null())
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(named, ["LocationDescriptorStruct"]);
}

// ---- M9-A3 B4: the Matter 1.4 supplement ------------------------------------

/// Matter 1.4 elements the 1.5.1 model removed, added by the dump from
/// `xtask/scripts/dump-model/supplement-1.4.json` (spec §2, rev 6), as
/// `(cluster, "<Feature|Attribute|Command>.<name>")`. Each is checked against
/// chip's 1.4.2 XML by `scripts/chip-xml-conformance.py` (class S).
const SUPPLEMENTED: [(&str, &str); 8] = [
    ("Thermostat", "Attribute.NumberOfDailyTransitions"),
    ("Thermostat", "Attribute.NumberOfWeeklyTransitions"),
    ("Thermostat", "Attribute.StartOfWeek"),
    ("Thermostat", "Command.ClearWeeklySchedule"),
    ("Thermostat", "Command.GetWeeklySchedule"),
    ("Thermostat", "Command.GetWeeklyScheduleResponse"),
    ("Thermostat", "Command.SetWeeklySchedule"),
    ("Thermostat", "Feature.SCH"),
];

#[test]
fn supplemented_elements_are_exactly_these_and_cite_a_source() {
    let v = load();
    let rows = v["meta"]["supplemented"]
        .as_array()
        .expect("meta.supplemented is an array");
    let mut got: Vec<(&str, &str)> = rows
        .iter()
        .map(|r| {
            assert!(
                r["source"]
                    .as_str()
                    .is_some_and(|s| s.contains("data_model/1.4.2")),
                "{r}"
            );
            (
                r["cluster"].as_str().unwrap(),
                r["element"].as_str().unwrap(),
            )
        })
        .collect();
    got.sort_unstable();
    let mut want = SUPPLEMENTED.to_vec();
    want.sort_unstable();
    assert_eq!(got, want);
}

#[test]
fn thermostat_weekly_schedule_uses_the_models_own_datatypes() {
    // The supplement adds SCH's feature, attributes and commands only; the
    // datatypes they name are the model's own (kept by the 1.5.1 model), so
    // each exists exactly once and the request and response share
    // WeeklyScheduleTransitionStruct.
    let v = load();
    let c = cluster(&v, "Thermostat");
    for name in [
        "ScheduleDayOfWeekBitmap",
        "ScheduleModeBitmap",
        "StartOfWeekEnum",
        "WeeklyScheduleTransitionStruct",
    ] {
        let count = c["datatypes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| d["name"] == name)
            .count();
        assert_eq!(count, 1, "{name}");
    }
    let sch: Vec<_> = c["features"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "SCH")
        .map(|f| f["bit"].as_u64().unwrap())
        .collect();
    assert_eq!(sch, [3]);
    for name in ["SetWeeklySchedule", "GetWeeklyScheduleResponse"] {
        let cmd = command(c, name);
        assert_eq!(
            field_optionality(&cmd["fields"]),
            [
                ("NumberOfTransitionsForSequence", false),
                ("DayOfWeekForSequence", false),
                ("ModeForSequence", false),
                ("Transitions", false)
            ],
            "{name}"
        );
        assert_eq!(
            cmd["fields"][3]["entryType"],
            "WeeklyScheduleTransitionStruct"
        );
    }
    assert_eq!(command(c, "GetWeeklySchedule")["responseId"], 0);
    assert_eq!(
        field_optionality(&datatype(c, "WeeklyScheduleTransitionStruct")["fields"]),
        [
            ("TransitionTime", false),
            ("HeatSetpoint", false),
            ("CoolSetpoint", false)
        ]
    );
}
