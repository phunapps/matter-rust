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
const TARGET_CLUSTERS: [&str; 113] = [
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
    // M9-A3 B4, safety sensors:
    "SmokeCoAlarm",
    "BooleanStateConfiguration",
    "ValveConfigurationAndControl",
    // M9-A3 B4, ScenesManagement (no events):
    "ScenesManagement",
    // M9-A3 B5, energy management with attributes only:
    "EnergyPreference",
    "PowerTopology",
    // M9-A3 B5, WaterHeaterManagement:
    "WaterHeaterManagement",
    // M9-A3 B5, DeviceEnergyManagement:
    "DeviceEnergyManagement",
    // M9-A3 B5, EnergyEvse:
    "EnergyEvse",
    // M9-A3 B5, Messages:
    "Messages",
    // M9-A3 B6, localization and power-source configuration:
    "LocalizationConfiguration",
    "TimeFormatLocalization",
    "UnitLocalization",
    "PowerSourceConfiguration",
    // M9-A3 B6, flat diagnostics and DiagnosticLogs:
    "DiagnosticLogs",
    "SoftwareDiagnostics",
    "WiFiNetworkDiagnostics",
    "EthernetNetworkDiagnostics",
    // M9-A3 B6, ThreadNetworkDiagnostics:
    "ThreadNetworkDiagnostics",
    // M9-A3 B6, commissioning (codecs only):
    "GeneralCommissioning",
    "NetworkCommissioning",
    // M9-A3 B6, Actions:
    "Actions",
    // M9-A3 B6, Fabric Synchronization:
    "EcosystemInformation",
    "CommissionerControl",
    // M9-A3 B6, network infrastructure:
    "WiFiNetworkManagement",
    "ThreadBorderRouterManagement",
    "ThreadNetworkDirectory",
    // M9-A3 B7, media basics:
    "WakeOnLan",
    "TargetNavigator",
    "MediaInput",
    "LowPower",
    "KeypadInput",
    "AudioOutput",
    // M9-A3 B7, the Content App platform:
    "ApplicationLauncher",
    "ApplicationBasic",
    "AccountLogin",
    "ContentAppObserver",
    // M9-A3 B7, MediaPlayback:
    "MediaPlayback",
    // M9-A3 B7, ContentLauncher:
    "ContentLauncher",
    // M9-A3 B7, Channel:
    "Channel",
    // M9-A3 B7, ContentControl (provisional):
    "ContentControl",
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
const FABRIC_SENSITIVE_RELAXED: [(&str, &str, &str); 26] = [
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
    // M9-A3 B6: born with the rule (DeviceName, DeviceNameLastEdit,
    // BridgedEndpoint and OriginalEndpoint are optional in the model, so they
    // are not relaxed).
    (
        "EcosystemInformation",
        "EcosystemDeviceStruct",
        "DeviceTypes",
    ),
    (
        "EcosystemInformation",
        "EcosystemDeviceStruct",
        "UniqueLocationIDs",
    ),
    (
        "EcosystemInformation",
        "EcosystemDeviceStruct",
        "UniqueLocationIDsLastEdit",
    ),
    (
        "EcosystemInformation",
        "EcosystemLocationStruct",
        "LocationDescriptor",
    ),
    (
        "EcosystemInformation",
        "EcosystemLocationStruct",
        "LocationDescriptorLastEdit",
    ),
    (
        "EcosystemInformation",
        "EcosystemLocationStruct",
        "UniqueLocationId",
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
    // M9-A3 B5: born with the rule (Responses is optional in the model, so it
    // is not relaxed).
    ("Messages", "MessageStruct", "Duration"),
    ("Messages", "MessageStruct", "MessageControl"),
    ("Messages", "MessageStruct", "MessageId"),
    ("Messages", "MessageStruct", "MessageText"),
    ("Messages", "MessageStruct", "Priority"),
    ("Messages", "MessageStruct", "StartTime"),
    // M9-A3 B4: born with the rule.
    ("ScenesManagement", "SceneInfoStruct", "CurrentGroup"),
    ("ScenesManagement", "SceneInfoStruct", "CurrentScene"),
    ("ScenesManagement", "SceneInfoStruct", "SceneValid"),
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
fn dump_script_version_is_11() {
    assert_eq!(load()["meta"]["dumpScriptVersion"], 11);
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
const EVENT_CLUSTERS: [&str; 35] = [
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
    // M9-A3 B4, safety sensors:
    "SmokeCoAlarm",
    "BooleanStateConfiguration",
    "ValveConfigurationAndControl",
    // M9-A3 B5, WaterHeaterManagement:
    "WaterHeaterManagement",
    // M9-A3 B5, DeviceEnergyManagement:
    "DeviceEnergyManagement",
    // M9-A3 B5, EnergyEvse:
    "EnergyEvse",
    // M9-A3 B5, Messages:
    "Messages",
    // M9-A3 B6, flat diagnostics:
    "SoftwareDiagnostics",
    "WiFiNetworkDiagnostics",
    // M9-A3 B6, ThreadNetworkDiagnostics:
    "ThreadNetworkDiagnostics",
    // M9-A3 B6, Actions:
    "Actions",
    // M9-A3 B6, CommissionerControl:
    "CommissionerControl",
    // M9-A3 B7, TargetNavigator:
    "TargetNavigator",
    // M9-A3 B7, AccountLogin:
    "AccountLogin",
    // M9-A3 B7, MediaPlayback:
    "MediaPlayback",
    // M9-A3 B7, ContentControl:
    "ContentControl",
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

/// `(name, id, type, optional, nullable)` for each field of a struct: the
/// whole wire shape of a field, for comparing a copied datatype with its owner.
fn field_shapes(fields: &Value) -> Vec<(&str, u64, &str, bool, bool)> {
    fields
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap(),
                f["id"].as_u64().unwrap(),
                f["type"].as_str().unwrap(),
                f["optional"].as_bool().unwrap(),
                f["nullable"].as_bool().unwrap(),
            )
        })
        .collect()
}

/// `(name, value)` for each value of an enum.
fn enum_members(d: &Value) -> Vec<(&str, u64)> {
    d["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["name"].as_str().unwrap(), v["value"].as_u64().unwrap()))
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
fn every_relaxation_is_fabric_sensitive_widened_conditional_or_chip_nullable() {
    // meta.relaxed holds exactly the §5.4 presence relaxations (class P), the
    // fields chip's servers leave out (class P, FIELD_RELAXATIONS: see
    // `fields_chip_omits_are_optional_and_recorded`), the §5.3 widenings
    // (class W), the §3.1 conditional-conformance relaxations (class C,
    // decode-only: codegen's model.rs refuses one on a field we send) and the
    // fields chip's servers send null (class N, FIELD_RELAXATIONS: see
    // `fields_chip_sends_null_are_nullable_and_recorded`). The one W today is ModeSelect StandardNamespace: model `namespace` is enum8,
    // 1.4.2 is enum16.
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
                    && (r["reason"] == "fabric-sensitive (withheld for other fabrics)"
                        || r["reason"].as_str().unwrap().starts_with("chip does not ")))
                || (r["class"] == "N"
                    && r["reason"]
                        .as_str()
                        .unwrap()
                        .starts_with("chip declares it nullable")),
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
const PROVISIONAL: [(&str, &str, &str); 31] = [
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
    // M9-A3 B6: Matter 1.5's network recovery (model-only, absent from 1.4.2).
    (
        "GeneralCommissioning",
        "attribute",
        "IsCommissioningWithoutPower",
    ),
    ("GeneralCommissioning", "attribute", "NetworkRecoveryReason"),
    ("GeneralCommissioning", "attribute", "RecoveryIdentifier"),
    ("GeneralCommissioning", "feature", "NR"),
    ("GroupKeyManagement", "feature", "CS"),
    ("LevelControl", "feature", "FQ"),
    ("MicrowaveOvenControl", "attribute", "SelectedWattIndex"),
    ("MicrowaveOvenControl", "attribute", "SupportedWatts"),
    ("MicrowaveOvenControl", "feature", "WATTS"),
    // M9-A3 B6 (provisional in 1.4.2 too: DiagnosticsThread.xml
    // `<otherwiseConform><provisionalConform/>...`):
    ("ThreadNetworkDiagnostics", "attribute", "ExtAddress"),
    ("ThreadNetworkDiagnostics", "attribute", "Rloc16"),
    // M9-A3 B4, WindowCovering ABS (supplemented; provisional in 1.4.2):
    ("WindowCovering", "attribute", "CurrentPositionLift"),
    ("WindowCovering", "attribute", "CurrentPositionTilt"),
    ("WindowCovering", "attribute", "InstalledClosedLimitLift"),
    ("WindowCovering", "attribute", "InstalledClosedLimitTilt"),
    ("WindowCovering", "attribute", "InstalledOpenLimitLift"),
    ("WindowCovering", "attribute", "InstalledOpenLimitTilt"),
    ("WindowCovering", "attribute", "PhysicalClosedLimitLift"),
    ("WindowCovering", "attribute", "PhysicalClosedLimitTilt"),
    ("WindowCovering", "command", "GoToLiftValue"),
    ("WindowCovering", "command", "GoToTiltValue"),
    ("WindowCovering", "feature", "ABS"),
];

/// Fields in a choice-conformance group (`O.a`, `O.a+`, `[F].b+`): the
/// encoders take each as an `Option` and do not enforce the group, so it is
/// documented on the generated type or encoder.
const CHOICE: [(&str, &str, &str); 23] = [
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
    // M9-A3 B5, EnergyEvse (`SOC, O.a+` and `[SOC], O.a+`: at least one;
    // chip's 1.4.2 XML has the same):
    ("EnergyEvse", "ChargingTargetStruct.AddedEnergy", "a/1+"),
    ("EnergyEvse", "ChargingTargetStruct.TargetSoC", "a/1+"),
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
    // M9-A3 B4, ScenesManagement (O.a: exactly one value field):
    (
        "ScenesManagement",
        "AttributeValuePairStruct.ValueSigned16",
        "a/1",
    ),
    (
        "ScenesManagement",
        "AttributeValuePairStruct.ValueSigned32",
        "a/1",
    ),
    (
        "ScenesManagement",
        "AttributeValuePairStruct.ValueSigned64",
        "a/1",
    ),
    (
        "ScenesManagement",
        "AttributeValuePairStruct.ValueSigned8",
        "a/1",
    ),
    (
        "ScenesManagement",
        "AttributeValuePairStruct.ValueUnsigned16",
        "a/1",
    ),
    (
        "ScenesManagement",
        "AttributeValuePairStruct.ValueUnsigned32",
        "a/1",
    ),
    (
        "ScenesManagement",
        "AttributeValuePairStruct.ValueUnsigned64",
        "a/1",
    ),
    (
        "ScenesManagement",
        "AttributeValuePairStruct.ValueUnsigned8",
        "a/1",
    ),
    // M9-A3 B5, WaterHeaterManagement ([!TP], [TP].a- and [TP].a-: at most
    // one):
    (
        "WaterHeaterManagement",
        "WaterHeaterBoostInfoStruct.OneShot",
        "a/1-",
    ),
    (
        "WaterHeaterManagement",
        "WaterHeaterBoostInfoStruct.TargetReheat",
        "a/1-",
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
    // ServiceArea (B3) and EcosystemInformation (B6) each inline their own
    // copy of the global `locationdesc` under chip's name.
    let named: Vec<(&str, &str)> = clusters(&v)
        .iter()
        .flat_map(|c| {
            c["datatypes"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|d| !d["globalName"].is_null())
                .map(move |d| (c["name"].as_str().unwrap(), d["name"].as_str().unwrap()))
        })
        .collect();
    assert_eq!(
        named,
        [
            ("ServiceArea", "LocationDescriptorStruct"),
            ("EcosystemInformation", "LocationDescriptorStruct")
        ]
    );
    for c in ["ServiceArea", "EcosystemInformation"] {
        let d = datatype(cluster(&v, c), "LocationDescriptorStruct");
        assert_eq!(d["globalName"], "locationdesc", "{c}");
        assert_eq!(
            field_optionality(&d["fields"]),
            [
                ("LocationName", false),
                ("FloorNumber", false),
                ("AreaType", false)
            ],
            "{c}"
        );
    }
}

// ---- M9-A3 B4: the Matter 1.4 supplement ------------------------------------

/// Matter 1.4 elements the 1.5.1 model removed, added by the dump from
/// `xtask/scripts/dump-model/supplement-1.4.json` (spec §2, rev 6), as
/// `(cluster, "<Feature|Attribute|Command>.<name>")`. Each is checked against
/// chip's 1.4.2 XML by `scripts/chip-xml-conformance.py` (class S).
const SUPPLEMENTED: [(&str, &str); 19] = [
    ("Thermostat", "Attribute.NumberOfDailyTransitions"),
    ("Thermostat", "Attribute.NumberOfWeeklyTransitions"),
    ("Thermostat", "Attribute.StartOfWeek"),
    ("Thermostat", "Command.ClearWeeklySchedule"),
    ("Thermostat", "Command.GetWeeklySchedule"),
    ("Thermostat", "Command.GetWeeklyScheduleResponse"),
    ("Thermostat", "Command.SetWeeklySchedule"),
    ("Thermostat", "Feature.SCH"),
    ("WindowCovering", "Attribute.CurrentPositionLift"),
    ("WindowCovering", "Attribute.CurrentPositionTilt"),
    ("WindowCovering", "Attribute.InstalledClosedLimitLift"),
    ("WindowCovering", "Attribute.InstalledClosedLimitTilt"),
    ("WindowCovering", "Attribute.InstalledOpenLimitLift"),
    ("WindowCovering", "Attribute.InstalledOpenLimitTilt"),
    ("WindowCovering", "Attribute.PhysicalClosedLimitLift"),
    ("WindowCovering", "Attribute.PhysicalClosedLimitTilt"),
    ("WindowCovering", "Command.GoToLiftValue"),
    ("WindowCovering", "Command.GoToTiltValue"),
    ("WindowCovering", "Feature.ABS"),
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

/// Each supplemented cluster's provenance, as stamped on its elements:
/// `(cluster, removedIn, removedInRevision, feature)`, from chip's `data_model`
/// revision histories (Thermostat.xml revision 10 in 1.5.1 "Removed Zigbee
/// related elements"; WindowCovering.xml revision 7 in 1.5 "Removed ABS
/// feature and all associated elements").
const PROVENANCE: [(&str, &str, u64, &str); 2] = [
    ("Thermostat", "1.5.1", 10, "SCH"),
    ("WindowCovering", "1.5", 7, "ABS"),
];

#[test]
fn every_supplemented_element_is_stamped_with_its_provenance() {
    // The per-element stamp (dump v6) drives the generated rustdoc line: the
    // stamped set is exactly meta.supplemented, each stamp carries its
    // cluster's provenance and the 1.4.2 conformance, and only SCH (1.4.2
    // `[Zigbee], D`) is deprecated.
    let v = load();
    let mut stamped = Vec::new();
    let mut deprecated = Vec::new();
    for c in clusters(&v) {
        let cname = c["name"].as_str().unwrap();
        for (key, label, name_key) in [
            ("features", "Feature", "code"),
            ("attributes", "Attribute", "name"),
            ("commands", "Command", "name"),
        ] {
            for e in c[key].as_array().unwrap() {
                let element = format!("{label}.{}", e[name_key].as_str().unwrap());
                if e["deprecated"] == true {
                    deprecated.push((cname, element.clone()));
                }
                let s = &e["supplemented"];
                if s.is_null() {
                    assert!(e["deprecated"].is_null(), "{cname}.{element}: {e}");
                    continue;
                }
                let (_, removed_in, revision, feature) = PROVENANCE
                    .iter()
                    .find(|p| p.0 == cname)
                    .unwrap_or_else(|| panic!("{cname} has no supplement provenance"));
                assert_eq!(s["from"], "1.4.2", "{cname}.{element}");
                assert_eq!(s["removedIn"], *removed_in, "{cname}.{element}");
                assert_eq!(s["removedInRevision"], *revision, "{cname}.{element}");
                assert_eq!(s["feature"], *feature, "{cname}.{element}");
                assert!(
                    s["conformance"].as_str().is_some_and(|t| !t.is_empty()),
                    "{cname}.{element}"
                );
                assert_eq!(s.as_object().unwrap().len(), 5, "{cname}.{element}: {s}");
                stamped.push((cname, element));
            }
        }
    }
    stamped.sort_unstable();
    let mut want: Vec<(&str, String)> = SUPPLEMENTED
        .iter()
        .map(|(c, e)| (*c, (*e).to_string()))
        .collect();
    want.sort_unstable();
    assert_eq!(stamped, want);
    assert_eq!(deprecated, [("Thermostat", "Feature.SCH".to_string())]);
    assert_eq!(
        cluster(&v, "Thermostat")["features"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["code"] == "SCH")
            .unwrap()["supplemented"]["conformance"],
        "[Zigbee], D"
    );
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

// ---- M9-A3 B4: unreferenced datatypes are pruned ----------------------------

/// The datatypes the dump dropped because no generated attribute, command or
/// event uses them (the user's pruning rule), as `(cluster, datatype)`.
const PRUNED_DATATYPES: [(&str, &str); 6] = [
    ("BridgedDeviceBasicInformation", "CapabilityMinimaStruct"),
    ("DoorLock", "AlarmMaskBitmap"),
    ("DoorLock", "EventTypeEnum"),
    ("MicrowaveOvenMode", "ModeChangeStatus"),
    // M9-A3 B5: model-only (chip's 1.4.2 XML and v1.4.2.0 controller codegen
    // have no such struct; it arrives in the 1.5 XML), and no PowerTopology
    // attribute names it.
    ("PowerTopology", "CircuitNodeStruct"),
    // M9-A3 B4: the specification's descriptive Logical Scene Table, not a
    // wire type (chip's controller codegen has no such struct).
    ("ScenesManagement", "LogicalSceneTable"),
];

/// Datatypes kept although no field names them (`KEEP_DATATYPES` in
/// index.js): each gives meaning to a raw integer a generated item carries.
const KEPT_UNREFERENCED: [(&str, &str); 4] = [
    ("IlluminanceMeasurement", "LightSensorTypeEnum"),
    ("OnOff", "DelayedAllOffEffectVariantEnum"),
    ("OnOff", "DyingLightEffectVariantEnum"),
    ("WindowCovering", "MovementStatus"),
];

#[test]
fn unreferenced_datatypes_are_pruned_except_the_keep_list() {
    let v = load();
    let mut pruned: Vec<(&str, &str)> = v["meta"]["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "datatype")
        .map(|e| {
            assert_eq!(
                e["reason"],
                "unreferenced (no generated attribute, command or event uses it)"
            );
            (
                e["cluster"].as_str().unwrap(),
                e["element"].as_str().unwrap(),
            )
        })
        .collect();
    pruned.sort_unstable();
    assert_eq!(pruned, PRUNED_DATATYPES);
    for (c, d) in PRUNED_DATATYPES {
        assert!(
            cluster(&v, c)["datatypes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|x| x["name"] != d),
            "{c}.{d} still dumped"
        );
    }
    // Each kept datatype says what it interprets (`keptFor`, its rustdoc
    // line), and nothing else carries a `keptFor`.
    let mut kept_for: Vec<(&str, &str)> = clusters(&v)
        .iter()
        .flat_map(|c| {
            c["datatypes"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|d| !d["keptFor"].is_null())
                .map(|d| (c["name"].as_str().unwrap(), d["name"].as_str().unwrap()))
        })
        .collect();
    kept_for.sort_unstable();
    assert_eq!(kept_for, KEPT_UNREFERENCED);
    for (c, d) in KEPT_UNREFERENCED {
        let dt = datatype(cluster(&v, c), d);
        assert_eq!(dt["kind"], "enum", "{c}.{d}");
        assert!(
            dt["keptFor"]
                .as_str()
                .is_some_and(|t| t.starts_with("The value of ")),
            "{c}.{d}: {dt}"
        );
    }
    assert_eq!(
        datatype(cluster(&v, "WindowCovering"), "MovementStatus")["keptFor"],
        "The value of each two-bit field (Global, Lift, Tilt) of `OperationalStatusBitmap`."
    );
    // Every StatusCodeEnum stays: the cluster-specific status codes no field
    // names. A model StatusCodeEnum the prune dropped would be recorded as a
    // `datatype` exclusion (checked above against PRUNED_DATATYPES, and here by
    // name), and the clusters that carry one are exactly the allowlisted
    // clusters whose @matter/model 0.17.1 cluster has one.
    assert!(
        pruned.iter().all(|(_, d)| *d != "StatusCodeEnum"),
        "{pruned:?}"
    );
    let mut with_status_codes: Vec<&str> = clusters(&v)
        .iter()
        .filter(|c| {
            c["datatypes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["name"] == "StatusCodeEnum")
        })
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    with_status_codes.sort_unstable();
    assert_eq!(
        with_status_codes,
        [
            "AdministratorCommissioning",
            "ContentControl",
            "DoorLock",
            "TimeSynchronization",
            "ValveConfigurationAndControl",
        ]
    );
}

// ---- M9-A3 B4: safety sensors ---------------------------------------------------

#[test]
fn safety_sensor_events_keep_their_payload_shapes() {
    // SmokeCoAlarm's eleven events: five carry a mandatory AlarmSeverityLevel,
    // six carry nothing. BooleanStateConfiguration's AlarmsSuppressed is
    // SPRS-gated, so optional.
    let v = load();
    let smoke = cluster(&v, "SmokeCoAlarm");
    let events: Vec<(&str, Vec<(&str, bool)>)> = smoke["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["name"].as_str().unwrap(), field_optionality(&e["fields"])))
        .collect();
    let sev = || vec![("AlarmSeverityLevel", false)];
    assert_eq!(
        events,
        [
            ("SmokeAlarm", sev()),
            ("CoAlarm", sev()),
            ("LowBattery", sev()),
            ("HardwareFault", vec![]),
            ("EndOfService", vec![]),
            ("SelfTestComplete", vec![]),
            ("AlarmMuted", vec![]),
            ("MuteEnded", vec![]),
            ("InterconnectSmokeAlarm", sev()),
            ("InterconnectCoAlarm", sev()),
            ("AllClear", vec![]),
        ]
    );
    let bsc = cluster(&v, "BooleanStateConfiguration");
    assert_eq!(
        field_optionality(&bsc["events"][0]["fields"]),
        [("AlarmsActive", false), ("AlarmsSuppressed", true)]
    );
    assert_eq!(
        field_optionality(&bsc["events"][1]["fields"]),
        [("SensorFault", false)]
    );
}

#[test]
fn valve_open_fields_are_optional_and_open_duration_nullable() {
    // OpenDuration and TargetLevel are both optional in 1.4.2 and the model;
    // OpenDuration is also nullable (null = stay open until Close), so the
    // encoder takes `Option<Nullable<u32>>`. The event's ValveLevel is
    // LVL-gated, so optional.
    let v = load();
    let c = cluster(&v, "ValveConfigurationAndControl");
    let open = command(c, "Open");
    assert_eq!(
        field_optionality(&open["fields"]),
        [("OpenDuration", true), ("TargetLevel", true)]
    );
    assert_eq!(open["fields"][0]["nullable"], true);
    assert_eq!(open["fields"][1]["nullable"], false);
    assert_eq!(
        field_optionality(&c["events"][0]["fields"]),
        [("ValveState", false), ("ValveLevel", true)]
    );
}

#[test]
fn scenes_management_shape_follows_1_4() {
    // FabricSceneInfo is a list of the fabric-scoped SceneInfoStruct (field
    // 254): its three fabric-sensitive fields are relaxed for decode and
    // mandatory on write (spec §5.4, asserted with the other relaxations).
    // ViewSceneResponse's and GetSceneMembershipResponse's success-only fields
    // ("Status == Success") are optional, so a NotFound reply decodes. The
    // descriptive DoNotUse attribute (0x0000, conformance X) is excluded. No
    // events.
    let v = load();
    let c = cluster(&v, "ScenesManagement");
    assert_eq!(
        element_names(c, "attributes"),
        ["SceneTableSize", "FabricSceneInfo"]
    );
    assert_eq!(c["attributes"][1]["entryType"], "SceneInfoStruct");
    assert_eq!(element_names(c, "events"), Vec::<&str>::new());
    assert_eq!(
        field_optionality(&command(c, "ViewSceneResponse")["fields"]),
        [
            ("Status", false),
            ("GroupId", false),
            ("SceneId", false),
            ("TransitionTime", true),
            ("SceneName", true),
            ("ExtensionFieldSetStructs", true)
        ]
    );
    assert_eq!(
        field_optionality(&command(c, "GetSceneMembershipResponse")["fields"]),
        [
            ("Status", false),
            ("Capacity", false),
            ("GroupId", false),
            ("SceneList", true)
        ]
    );
    let excluded = v["meta"]["excluded"].as_array().unwrap();
    assert!(excluded.iter().any(|e| e["cluster"] == "ScenesManagement"
        && e["element"] == "DoNotUse"
        && e["kind"] == "attribute"
        && e["reason"] == "disallowed"));
}

// ---- M9-A3 B5: provisional clusters and presence dependencies -------------

/// Clusters the Matter specification marks provisional as a whole (spec §2:
/// `EnergyPreference` and `ContentControl`, included and marked provisional), from
/// the dump's `PROVISIONAL_CLUSTERS`. Each gets a module rustdoc paragraph;
/// `scripts/chip-xml-conformance.py` checks the marking against chip's 1.4.2
/// XML both ways (class V).
const PROVISIONAL_CLUSTERS: [&str; 2] = ["EnergyPreference", "ContentControl"];

/// Datatype struct fields whose presence depends on a sibling field
/// (`requiredWhen`), as `(cluster, "<Struct>.<Field>", sibling, present,
/// exclusive)`. `exclusive` is a bare conformance (`Endpoint`, `!Group`):
/// mandatory when it holds and disallowed when it does not; an otherwise-form
/// (`TargetReheat, [TP]`) is not exclusive. Each gets a generated "Required
/// when ..." rustdoc line; nothing enforces it.
const REQUIRED_WHEN: [(&str, &str, &str, bool, bool); 11] = [
    ("Binding", "TargetStruct.Endpoint", "Group", false, true),
    ("Binding", "TargetStruct.Group", "Endpoint", false, true),
    ("Binding", "TargetStruct.Node", "Endpoint", true, true),
    // M9-A3 B6 (`DeviceName`: a bare name, so exclusive):
    (
        "EcosystemInformation",
        "EcosystemDeviceStruct.DeviceNameLastEdit",
        "DeviceName",
        true,
        true,
    ),
    (
        "ElectricalPowerMeasurement",
        "MeasurementRangeStruct.MaxSystime",
        "EndSystime",
        true,
        true,
    ),
    (
        "ElectricalPowerMeasurement",
        "MeasurementRangeStruct.MaxTimestamp",
        "EndTimestamp",
        true,
        true,
    ),
    (
        "ElectricalPowerMeasurement",
        "MeasurementRangeStruct.MinSystime",
        "EndSystime",
        true,
        true,
    ),
    (
        "ElectricalPowerMeasurement",
        "MeasurementRangeStruct.MinTimestamp",
        "EndTimestamp",
        true,
        true,
    ),
    (
        "ElectricalPowerMeasurement",
        "MeasurementRangeStruct.StartSystime",
        "EndSystime",
        true,
        true,
    ),
    (
        "ElectricalPowerMeasurement",
        "MeasurementRangeStruct.StartTimestamp",
        "EndTimestamp",
        true,
        true,
    ),
    // M9-A3 B5 (`TargetReheat, [TP]`: an otherwise-form, so not exclusive):
    (
        "WaterHeaterManagement",
        "WaterHeaterBoostInfoStruct.TargetPercentage",
        "TargetReheat",
        true,
        false,
    ),
];

#[test]
fn provisional_clusters_are_exactly_these() {
    let v = load();
    let got: Vec<&str> = clusters(&v)
        .iter()
        .filter(|c| c["provisional"] == true)
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(got, PROVISIONAL_CLUSTERS);
    // The key is written only when true.
    assert!(clusters(&v).iter().all(|c| c["provisional"] != false));
}

#[test]
fn presence_dependencies_are_exactly_these() {
    let v = load();
    let mut got: Vec<(String, String, String, bool, bool)> = Vec::new();
    for c in clusters(&v) {
        for d in c["datatypes"].as_array().unwrap() {
            for f in d["fields"].as_array().into_iter().flatten() {
                let dep = &f["requiredWhen"];
                if dep.is_null() {
                    continue;
                }
                got.push((
                    c["name"].as_str().unwrap().to_string(),
                    format!(
                        "{}.{}",
                        d["name"].as_str().unwrap(),
                        f["name"].as_str().unwrap()
                    ),
                    dep["field"].as_str().unwrap().to_string(),
                    dep["present"].as_bool().unwrap(),
                    dep["exclusive"].as_bool().unwrap(),
                ));
            }
        }
    }
    got.sort();
    let got: Vec<(&str, &str, &str, bool, bool)> = got
        .iter()
        .map(|(c, f, s, p, excl)| (c.as_str(), f.as_str(), s.as_str(), *p, *excl))
        .collect();
    let mut want = REQUIRED_WHEN.to_vec();
    want.sort_unstable();
    assert_eq!(got, want);
    // Never on a command or event field (the emitter documents struct fields
    // only, and the dump stops on any other).
    for c in clusters(&v) {
        for kind in ["commands", "events"] {
            for e in c[kind].as_array().into_iter().flatten() {
                for f in e["fields"].as_array().unwrap() {
                    assert!(f["requiredWhen"].is_null(), "{}.{}", e["name"], f["name"]);
                }
            }
        }
    }
}

#[test]
fn energy_preference_and_power_topology_are_attribute_only() {
    // 1.4.2 EnergyPreference.xml / PowerTopology.xml: attributes only. The two
    // Current* levels are the only writable attributes; both lists of
    // BalanceStruct are read-only, so BalanceStruct has no encoder.
    let v = load();
    let pref = cluster(&v, "EnergyPreference");
    assert_eq!(
        element_names(pref, "attributes"),
        [
            "EnergyBalances",
            "CurrentEnergyBalance",
            "EnergyPriorities",
            "LowPowerModeSensitivities",
            "CurrentLowPowerModeSensitivity"
        ]
    );
    let writable: Vec<&str> = pref["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["writable"] == true)
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        writable,
        ["CurrentEnergyBalance", "CurrentLowPowerModeSensitivity"]
    );
    assert_eq!(
        field_optionality(&datatype(pref, "BalanceStruct")["fields"]),
        [("Step", false), ("Label", true)]
    );
    let topo = cluster(&v, "PowerTopology");
    assert_eq!(
        element_names(topo, "attributes"),
        ["AvailableEndpoints", "ActiveEndpoints"]
    );
    assert_eq!(element_names(topo, "datatypes"), Vec::<&str>::new());
    for c in [pref, topo] {
        assert_eq!(element_names(c, "commands"), Vec::<&str>::new());
        assert_eq!(element_names(c, "events"), Vec::<&str>::new());
    }
}

#[test]
fn water_heater_management_keeps_its_boost_shapes() {
    // 1.4.2 WaterHeaterManagement.xml: Boost carries one mandatory
    // WaterHeaterBoostInfoStruct; only Duration is mandatory in it.
    // BoostStarted carries the same struct; BoostEnded carries nothing.
    let v = load();
    let c = cluster(&v, "WaterHeaterManagement");
    assert_eq!(
        field_optionality(&command(c, "Boost")["fields"]),
        [("BoostInfo", false)]
    );
    assert_eq!(
        command(c, "Boost")["fields"][0]["type"],
        "WaterHeaterBoostInfoStruct"
    );
    assert_eq!(
        field_optionality(&datatype(c, "WaterHeaterBoostInfoStruct")["fields"]),
        [
            ("Duration", false),
            ("OneShot", true),
            ("EmergencyBoost", true),
            ("TemporarySetpoint", true),
            ("TargetPercentage", true),
            ("TargetReheat", true)
        ]
    );
    assert_eq!(element_names(c, "events"), ["BoostStarted", "BoostEnded"]);
    assert_eq!(
        field_optionality(&c["events"][0]["fields"]),
        [("BoostInfo", false)]
    );
    assert_eq!(field_optionality(&c["events"][1]["fields"]), []);
}

#[test]
fn device_energy_management_keeps_its_shapes() {
    // 1.4.2 DeviceEnergyManagement.xml: eight requests, every one answered
    // with a status; the two list-carrying requests take scalar structs whose
    // feature-gated fields are optional; four events, two of them fieldless.
    let v = load();
    let c = cluster(&v, "DeviceEnergyManagement");
    let requests: Vec<(&str, bool)> = c["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|cmd| (cmd["name"].as_str().unwrap(), cmd["responseId"].is_null()))
        .collect();
    assert_eq!(
        requests,
        [
            ("PowerAdjustRequest", true),
            ("CancelPowerAdjustRequest", true),
            ("StartTimeAdjustRequest", true),
            ("PauseRequest", true),
            ("ResumeRequest", true),
            ("ModifyForecastRequest", true),
            ("RequestConstraintBasedForecast", true),
            ("CancelRequest", true)
        ]
    );
    assert_eq!(
        field_optionality(&datatype(c, "SlotAdjustmentStruct")["fields"]),
        [
            ("SlotIndex", false),
            ("NominalPower", true),
            ("Duration", false)
        ]
    );
    assert_eq!(
        field_optionality(&datatype(c, "ConstraintsStruct")["fields"]),
        [
            ("StartTime", false),
            ("Duration", false),
            ("NominalPower", true),
            ("MaximumEnergy", true),
            ("LoadControl", true)
        ]
    );
    let cap = datatype(c, "PowerAdjustCapabilityStruct");
    assert_eq!(cap["fields"][0]["name"], "PowerAdjustCapability");
    assert_eq!(cap["fields"][0]["nullable"], true);
    let events: Vec<(&str, Vec<(&str, bool)>)> = c["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["name"].as_str().unwrap(), field_optionality(&e["fields"])))
        .collect();
    assert_eq!(
        events,
        [
            ("PowerAdjustStart", vec![]),
            (
                "PowerAdjustEnd",
                vec![("Cause", false), ("Duration", false), ("EnergyUse", false)]
            ),
            ("Paused", vec![]),
            ("Resumed", vec![("Cause", false)]),
        ]
    );
}

#[test]
fn energy_evse_keeps_its_shapes() {
    // 1.4.2 EnergyEVSE.xml: GetTargets is answered by GetTargetsResponse,
    // every other request by a status. SetTargets and the response carry the
    // same list of ChargingTargetScheduleStruct. EnergyTransferStopped's field
    // ids skip 3 (reserved), and Fault's skip 3 too.
    let v = load();
    let c = cluster(&v, "EnergyEvse");
    assert_eq!(
        command(c, "GetTargets")["responseId"],
        command(c, "GetTargetsResponse")["id"]
    );
    for name in [
        "Disable",
        "EnableCharging",
        "EnableDischarging",
        "StartDiagnostics",
        "SetTargets",
        "ClearTargets",
    ] {
        assert!(command(c, name)["responseId"].is_null(), "{name}");
    }
    assert_eq!(
        command(c, "SetTargets")["fields"][0]["entryType"],
        "ChargingTargetScheduleStruct"
    );
    assert_eq!(
        command(c, "GetTargetsResponse")["fields"][0]["entryType"],
        "ChargingTargetScheduleStruct"
    );
    assert_eq!(
        field_optionality(&datatype(c, "ChargingTargetStruct")["fields"]),
        [
            ("TargetTimeMinutesPastMidnight", false),
            ("TargetSoC", true),
            ("AddedEnergy", true)
        ]
    );
    let ids = |event: &str| -> Vec<u64> {
        c["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == event)
            .unwrap()["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["id"].as_u64().unwrap())
            .collect()
    };
    assert_eq!(ids("EnergyTransferStopped"), [0, 1, 2, 4, 5]);
    assert_eq!(ids("Fault"), [0, 1, 2, 4]);
    assert_eq!(
        element_names(c, "events"),
        [
            "EvConnected",
            "EvNotDetected",
            "EnergyTransferStarted",
            "EnergyTransferStopped",
            "Fault",
            "Rfid"
        ]
    );
}

// ---- M9-A3 B5: fields a real chip server leaves out (FIELD_RELAXATIONS) -----

/// Fields the dump relaxed to optional because chip's servers leave them out
/// although the model and the 1.4.2 XML make them mandatory (spec §5.1 step
/// 3), as `(cluster, "<Struct|Event>.<Field>")`. Recorded in `meta.relaxed`
/// with class P.
const CHIP_OMITS_RELAXED: [(&str, &str); 4] = [
    ("Messages", "MessageComplete.FabricIndex"),
    ("Messages", "MessagePresented.FabricIndex"),
    ("Messages", "MessageQueued.FabricIndex"),
    ("Messages", "MessageStruct.FabricIndex"),
];

#[test]
fn fields_chip_omits_are_optional_and_recorded() {
    let v = load();
    let relaxed = v["meta"]["relaxed"].as_array().unwrap();
    let mut got: Vec<(&str, &str)> = relaxed
        .iter()
        .filter(|r| r["reason"].as_str().unwrap().starts_with("chip does not "))
        .map(|r| {
            assert_eq!(r["class"], "P");
            (
                r["cluster"].as_str().unwrap(),
                r["element"].as_str().unwrap(),
            )
        })
        .collect();
    got.sort_unstable();
    assert_eq!(got, CHIP_OMITS_RELAXED);
    let c = cluster(&v, "Messages");
    let fabric_index = |fields: &Value| -> bool {
        fields
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == 254)
            .unwrap()["optional"]
            .as_bool()
            .unwrap()
    };
    assert!(fabric_index(&datatype(c, "MessageStruct")["fields"]));
    for e in c["events"].as_array().unwrap() {
        assert!(fabric_index(&e["fields"]), "{}", e["name"]);
    }
}

/// The per-field `relaxedReason` of every `FIELD_RELAXATIONS` field, as
/// `(cluster, owner, field, relaxedReason)`, sorted (M9-A3 B5 fix wave, T7
/// M3): the emitter renders it as "Optional: <reason>." on the field. No
/// other field carries one.
const RELAXED_REASONS: [(&str, &str, &str, &str); 4] = [
    (
        "Messages",
        "MessageComplete",
        "FabricIndex",
        "chip's servers do not send it (the event is not fabric-scoped in chip)",
    ),
    (
        "Messages",
        "MessagePresented",
        "FabricIndex",
        "chip's servers do not send it (the event is not fabric-scoped in chip)",
    ),
    (
        "Messages",
        "MessageQueued",
        "FabricIndex",
        "chip's servers do not send it (the event is not fabric-scoped in chip)",
    ),
    (
        "Messages",
        "MessageStruct",
        "FabricIndex",
        "chip's servers do not send it (the struct is not fabric-scoped in chip)",
    ),
];

#[test]
fn fields_chip_omits_carry_a_relaxed_reason() {
    let v = load();
    let mut got: Vec<(&str, &str, &str, &str)> = Vec::new();
    for c in clusters(&v) {
        let cname = c["name"].as_str().unwrap();
        let owners = c["commands"]
            .as_array()
            .unwrap()
            .iter()
            .chain(c["events"].as_array().unwrap())
            .chain(c["datatypes"].as_array().unwrap());
        for o in owners {
            for f in o["fields"].as_array().into_iter().flatten() {
                if let Some(reason) = f.get("relaxedReason") {
                    assert_eq!(f["optional"], true, "{cname}.{}.{}", o["name"], f["name"]);
                    got.push((
                        cname,
                        o["name"].as_str().unwrap(),
                        f["name"].as_str().unwrap(),
                        reason.as_str().unwrap(),
                    ));
                }
            }
        }
    }
    got.sort_unstable();
    assert_eq!(got, RELAXED_REASONS);
}

#[test]
fn messages_keeps_its_shapes() {
    // 1.4.2 Messages.xml: both requests are answered with a status;
    // CancelMessagesRequest takes a list<octstr>; PresentMessagesRequest's
    // Responses is RESP-gated (optional). MessageStruct is decode-only: the
    // Messages attribute is read-only and no request carries it.
    let v = load();
    let c = cluster(&v, "Messages");
    let cancel = command(c, "CancelMessagesRequest");
    assert!(cancel["responseId"].is_null());
    assert_eq!(cancel["fields"][0]["name"], "MessageIDs");
    assert_eq!(cancel["fields"][0]["entryType"], "octstr");
    let present = command(c, "PresentMessagesRequest");
    assert!(present["responseId"].is_null());
    assert_eq!(
        field_optionality(&present["fields"]),
        [
            ("MessageId", false),
            ("Priority", false),
            ("MessageControl", false),
            ("StartTime", false),
            ("Duration", false),
            ("MessageText", false),
            ("Responses", true)
        ]
    );
    assert_eq!(
        element_names(c, "events"),
        ["MessageQueued", "MessagePresented", "MessageComplete"]
    );
    assert_eq!(
        field_optionality(&datatype(c, "MessageResponseOptionStruct")["fields"]),
        [("MessageResponseId", false), ("Label", false)]
    );
}

// ---- M9-A3 B6: diagnostics and infrastructure ------------------------------

/// The names of `c`'s writable attributes, in id order.
fn writable_attributes(c: &Value) -> Vec<&str> {
    c["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["writable"] == true)
        .map(|a| a["name"].as_str().unwrap())
        .collect()
}

#[test]
fn localization_and_power_source_configuration_are_attribute_only() {
    // 1.4.2 LocalizationConfiguration.xml, LocalizationTimeFormat.xml,
    // LocalizationUnit.xml, PowerSourceConfigurationCluster.xml: attributes
    // only. The four settings are writable; the lists are read-only.
    let v = load();
    let shapes: [(&str, &[&str], &[&str]); 4] = [
        (
            "LocalizationConfiguration",
            &["ActiveLocale", "SupportedLocales"],
            &["ActiveLocale"],
        ),
        (
            "TimeFormatLocalization",
            &["HourFormat", "ActiveCalendarType", "SupportedCalendarTypes"],
            &["HourFormat", "ActiveCalendarType"],
        ),
        (
            "UnitLocalization",
            &["TemperatureUnit", "SupportedTemperatureUnits"],
            &["TemperatureUnit"],
        ),
        ("PowerSourceConfiguration", &["Sources"], &[]),
    ];
    for (name, attributes, writable) in shapes {
        let c = cluster(&v, name);
        assert_eq!(element_names(c, "attributes"), attributes, "{name}");
        assert_eq!(writable_attributes(c), writable, "{name}");
        assert_eq!(element_names(c, "commands"), Vec::<&str>::new(), "{name}");
        assert_eq!(element_names(c, "events"), Vec::<&str>::new(), "{name}");
    }
    // Optionality: LocalizationConfiguration, HourFormat and Sources are
    // mandatory; the calendar attributes hang on CALFMT and the temperature
    // attributes on TEMP, so they are optional.
    let optionality: [(&str, &[(&str, bool)]); 4] = [
        (
            "LocalizationConfiguration",
            &[("ActiveLocale", false), ("SupportedLocales", false)],
        ),
        (
            "TimeFormatLocalization",
            &[
                ("HourFormat", false),
                ("ActiveCalendarType", true),
                ("SupportedCalendarTypes", true),
            ],
        ),
        (
            "UnitLocalization",
            &[
                ("TemperatureUnit", true),
                ("SupportedTemperatureUnits", true),
            ],
        ),
        ("PowerSourceConfiguration", &[("Sources", false)]),
    ];
    for (name, expected) in optionality {
        assert_eq!(
            field_optionality(&cluster(&v, name)["attributes"]),
            expected,
            "{name}"
        );
    }
    // UnitLocalization is at revision 2 (1.4.2 LocalizationUnit.xml); the
    // other three at 1.
    for (name, revision) in [
        ("LocalizationConfiguration", 1),
        ("TimeFormatLocalization", 1),
        ("UnitLocalization", 2),
        ("PowerSourceConfiguration", 1),
    ] {
        assert_eq!(cluster(&v, name)["revision"], revision, "{name}");
    }
    // HourFormatEnum and CalendarTypeEnum keep UseActiveLocale (0xFF).
    let tf = cluster(&v, "TimeFormatLocalization");
    assert_eq!(enum_values(datatype(tf, "HourFormatEnum")), [0, 1, 0xFF]);
    assert_eq!(
        enum_values(datatype(tf, "CalendarTypeEnum")),
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0xFF]
    );
}

#[test]
fn flat_diagnostics_and_diagnostic_logs_keep_their_shapes() {
    // 1.4.2 DiagnosticsSoftware.xml, DiagnosticsWiFi.xml,
    // DiagnosticsEthernet.xml, DiagnosticLogsCluster.xml.
    let v = load();
    let sw = cluster(&v, "SoftwareDiagnostics");
    assert_eq!(element_names(sw, "commands"), ["ResetWatermarks"]);
    assert_eq!(element_names(sw, "events"), ["SoftwareFault"]);
    assert_eq!(
        field_optionality(&datatype(sw, "ThreadMetricsStruct")["fields"]),
        [
            ("Id", false),
            ("Name", true),
            ("StackFreeCurrent", true),
            ("StackFreeMinimum", true),
            ("StackSize", true)
        ]
    );
    let wifi = cluster(&v, "WiFiNetworkDiagnostics");
    assert_eq!(element_names(wifi, "commands"), ["ResetCounts"]);
    assert_eq!(
        element_names(wifi, "events"),
        ["Disconnection", "AssociationFailure", "ConnectionStatus"]
    );
    // Every Wi-Fi attribute is nullable (null when not connected), all 13.
    let wifi_attributes = wifi["attributes"].as_array().unwrap();
    assert_eq!(wifi_attributes.len(), 13);
    assert!(wifi_attributes.iter().all(|a| a["nullable"] == true));
    let eth = cluster(&v, "EthernetNetworkDiagnostics");
    // Ethernet: exactly PhyRate, FullDuplex and CarrierDetect are nullable;
    // the counters and TimeSinceReset are not.
    let eth_nullable: Vec<&str> = eth["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["nullable"] == true)
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(eth_nullable, ["PhyRate", "FullDuplex", "CarrierDetect"]);
    assert_eq!(element_names(eth, "commands"), ["ResetCounts"]);
    assert_eq!(element_names(eth, "events"), Vec::<&str>::new());
    let logs = cluster(&v, "DiagnosticLogs");
    assert_eq!(element_names(logs, "attributes"), Vec::<&str>::new());
    assert_eq!(
        field_optionality(&command(logs, "RetrieveLogsRequest")["fields"]),
        [
            ("Intent", false),
            ("RequestedProtocol", false),
            ("TransferFileDesignator", true)
        ]
    );
    assert_eq!(
        field_optionality(&command(logs, "RetrieveLogsResponse")["fields"]),
        [
            ("Status", false),
            ("LogContent", false),
            ("UtcTimeStamp", true),
            ("TimeSinceBoot", true)
        ]
    );
    for c in [sw, wifi, eth, logs] {
        assert_eq!(writable_attributes(c), Vec::<&str>::new());
    }
}

#[test]
fn thread_network_diagnostics_keeps_its_shapes() {
    // 1.4.2 DiagnosticsThread.xml, cluster revision 3.
    let v = load();
    let c = cluster(&v, "ThreadNetworkDiagnostics");
    assert_eq!(c["revision"], 3);
    let attributes = c["attributes"].as_array().unwrap();
    assert_eq!(attributes.len(), 65);
    assert_eq!(attributes[0]["name"], "Channel");
    assert_eq!(attributes[64]["name"], "Rloc16");
    // MeshLocalPrefix keeps the model's `ipv6pre` token (a byte string).
    let prefix = attributes
        .iter()
        .find(|a| a["name"] == "MeshLocalPrefix")
        .unwrap();
    assert_eq!(
        (&prefix["type"], &prefix["metatype"], &prefix["nullable"]),
        (
            &Value::from("ipv6pre"),
            &Value::from("bytes"),
            &Value::from(true)
        )
    );
    assert_eq!(element_names(c, "commands"), ["ResetCounts"]);
    assert_eq!(
        element_names(c, "events"),
        ["ConnectionStatus", "NetworkFaultChange"]
    );
    assert_eq!(
        field_optionality(&datatype(c, "SecurityPolicy")["fields"]),
        [("RotationTime", false), ("Flags", false)]
    );
    // Every neighbor and route table field is mandatory; two RSSIs are
    // nullable.
    for name in ["NeighborTableStruct", "RouteTableStruct"] {
        let fields = datatype(c, name)["fields"].as_array().unwrap();
        assert!(fields.iter().all(|f| f["optional"] == false), "{name}");
    }
    let nullable: Vec<&str> = datatype(c, "NeighborTableStruct")["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["nullable"] == true)
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(nullable, ["AverageRssi", "LastRssi"]);
    assert_eq!(writable_attributes(c), Vec::<&str>::new());
}

#[test]
fn commissioning_clusters_follow_the_specification() {
    // 1.4.2 GeneralCommissioningCluster.xml, NetworkCommissioningCluster.xml.
    // matter-commissioning's hand-written decoders are more lenient (DebugText
    // and ErrorValue optional); these follow the specification, chip's
    // controller codegen and matter.js.
    let v = load();
    let gc = cluster(&v, "GeneralCommissioning");
    for response in [
        "ArmFailSafeResponse",
        "SetRegulatoryConfigResponse",
        "CommissioningCompleteResponse",
    ] {
        assert_eq!(
            field_optionality(&command(gc, response)["fields"]),
            [("ErrorCode", false), ("DebugText", false)],
            "{response}"
        );
    }
    // Breadcrumb is mandatory in GeneralCommissioning's requests ...
    assert_eq!(
        field_optionality(&command(gc, "ArmFailSafe")["fields"]),
        [("ExpiryLengthSeconds", false), ("Breadcrumb", false)]
    );
    assert_eq!(writable_attributes(gc), ["Breadcrumb"]);
    let nc = cluster(&v, "NetworkCommissioning");
    // ... and optional in NetworkCommissioning's.
    assert_eq!(
        field_optionality(&command(nc, "ConnectNetwork")["fields"]),
        [("NetworkId", false), ("Breadcrumb", true)]
    );
    let connect = command(nc, "ConnectNetworkResponse")["fields"]
        .as_array()
        .unwrap();
    let error_value = connect.iter().find(|f| f["name"] == "ErrorValue").unwrap();
    assert_eq!(
        (&error_value["optional"], &error_value["nullable"]),
        (&Value::from(false), &Value::from(true))
    );
    // ScanNetworks' Ssid is optional and nullable ([WI], nullable).
    let ssid = &command(nc, "ScanNetworks")["fields"][0];
    assert_eq!(
        (&ssid["name"], &ssid["optional"], &ssid["nullable"]),
        (&Value::from("Ssid"), &Value::from(true), &Value::from(true))
    );
    // The scan result fields are feature-gated (WI / TH), so every one is
    // optional on decode.
    for name in [
        "WiFiInterfaceScanResultStruct",
        "ThreadInterfaceScanResultStruct",
    ] {
        let fields = datatype(nc, name)["fields"].as_array().unwrap();
        assert!(fields.iter().all(|f| f["optional"] == true), "{name}");
    }
    assert_eq!(writable_attributes(nc), ["InterfaceEnabled"]);
    for c in [gc, nc] {
        assert_eq!(element_names(c, "events"), Vec::<&str>::new());
    }
}

#[test]
fn actions_keeps_its_shapes() {
    // 1.4.2 ActionsCluster.xml: twelve requests, every one an ActionID with an
    // optional InvokeID; no responses (each answers with a status).
    let v = load();
    let c = cluster(&v, "Actions");
    let commands = c["commands"].as_array().unwrap();
    assert_eq!(commands.len(), 12);
    for cmd in commands {
        assert_eq!(cmd["direction"], "request");
        assert!(cmd["responseId"].is_null(), "{}", cmd["name"]);
        let fields = field_optionality(&cmd["fields"]);
        assert_eq!(fields[..2], [("ActionId", false), ("InvokeId", true)]);
    }
    assert_eq!(element_names(c, "events"), ["StateChanged", "ActionFailed"]);
    // The event's InvokeID is mandatory (1.4.2, chip and matter.js).
    assert_eq!(
        field_optionality(&c["events"][0]["fields"]),
        [
            ("ActionId", false),
            ("InvokeId", false),
            ("NewState", false)
        ]
    );
    assert_eq!(
        field_optionality(&datatype(c, "EndpointListStruct")["fields"]),
        [
            ("EndpointListId", false),
            ("Name", false),
            ("Type", false),
            ("Endpoints", false)
        ]
    );
    assert_eq!(writable_attributes(c), Vec::<&str>::new());
}

#[test]
fn fabric_synchronization_clusters_keep_their_shapes() {
    // 1.4.2 EcosystemInformationCluster.xml, CommissionerControlCluster.xml.
    let v = load();
    let eco = cluster(&v, "EcosystemInformation");
    assert_eq!(
        element_names(eco, "attributes"),
        ["DeviceDirectory", "LocationDirectory"]
    );
    assert_eq!(element_names(eco, "commands"), Vec::<&str>::new());
    assert_eq!(writable_attributes(eco), Vec::<&str>::new());
    // Every field but FabricIndex is fabric-sensitive (§5.4: all Option).
    for name in ["EcosystemDeviceStruct", "EcosystemLocationStruct"] {
        for f in datatype(eco, name)["fields"].as_array().unwrap() {
            let fabric_index = f["id"] == 254;
            assert_eq!(
                f["fabricSensitive"] == true,
                !fabric_index,
                "{name}.{}",
                f["name"]
            );
            assert_eq!(f["optional"] == true, !fabric_index, "{name}.{}", f["name"]);
        }
    }
    let cc = cluster(&v, "CommissionerControl");
    assert_eq!(
        field_optionality(&command(cc, "RequestCommissioningApproval")["fields"]),
        [
            ("RequestId", false),
            ("VendorId", false),
            ("ProductId", false),
            ("Label", true)
        ]
    );
    // CommissionNode answers with ReverseOpenCommissioningWindow (0x02).
    assert_eq!(command(cc, "CommissionNode")["responseId"], 2);
    assert_eq!(element_names(cc, "events"), ["CommissioningRequestResult"]);
    // The event's fields are fabric-sensitive in the specification, but
    // events are exempt (§5.4): chip sends them only to their own fabric.
    let payload = cc["events"][0]["fields"].as_array().unwrap();
    assert!(payload.iter().all(|f| f["fabricSensitive"].is_null()));
    assert!(payload.iter().all(|f| f["optional"] == false));
}

#[test]
fn network_infrastructure_clusters_keep_their_shapes() {
    // 1.4.2 WiFiNetworkManagement.xml, ThreadBorderRouterManagement.xml,
    // ThreadNetworkDirectory.xml. No events in any of them.
    let v = load();
    let wifi = cluster(&v, "WiFiNetworkManagement");
    assert_eq!(
        element_names(wifi, "commands"),
        ["NetworkPassphraseRequest", "NetworkPassphraseResponse"]
    );
    let tbrm = cluster(&v, "ThreadBorderRouterManagement");
    // Both Get*DatasetRequest commands answer with DatasetResponse (0x02).
    for request in ["GetActiveDatasetRequest", "GetPendingDatasetRequest"] {
        assert_eq!(command(tbrm, request)["responseId"], 2, "{request}");
    }
    assert_eq!(
        field_optionality(&command(tbrm, "SetActiveDatasetRequest")["fields"]),
        [("ActiveDataset", false), ("Breadcrumb", true)]
    );
    let tnd = cluster(&v, "ThreadNetworkDirectory");
    assert_eq!(writable_attributes(tnd), ["PreferredExtendedPanId"]);
    assert_eq!(command(tnd, "GetOperationalDataset")["responseId"], 3);
    assert_eq!(
        field_optionality(&datatype(tnd, "ThreadNetworkStruct")["fields"]),
        [
            ("ExtendedPanId", false),
            ("NetworkName", false),
            ("Channel", false),
            ("ActiveTimestamp", false)
        ]
    );
    for c in [wifi, tbrm, tnd] {
        assert_eq!(element_names(c, "events"), Vec::<&str>::new());
    }
    for c in [wifi, tbrm] {
        assert_eq!(writable_attributes(c), Vec::<&str>::new());
    }
}

/// The fields the dump marks `secret` (`SECRET_FIELDS`), as `(cluster,
/// "<Owner>.<Field>")`: their structs keep them out of the generated `Debug`
/// output. A new one (a widening, a model upgrade) is a review item.
const SECRET: [(&str, &str); 9] = [
    ("AccountLogin", "GetSetupPinResponse.SetupPin"),
    (
        "CommissionerControl",
        "ReverseOpenCommissioningWindow.PakePasscodeVerifier",
    ),
    ("ContentControl", "ResetPinResponse.PinCode"),
    ("GroupKeyManagement", "GroupKeySetStruct.EpochKey0"),
    ("GroupKeyManagement", "GroupKeySetStruct.EpochKey1"),
    ("GroupKeyManagement", "GroupKeySetStruct.EpochKey2"),
    ("ThreadBorderRouterManagement", "DatasetResponse.Dataset"),
    (
        "ThreadNetworkDirectory",
        "OperationalDatasetResponse.OperationalDataset",
    ),
    (
        "WiFiNetworkManagement",
        "NetworkPassphraseResponse.Passphrase",
    ),
];

#[test]
fn secret_fields_are_exactly_these() {
    let v = load();
    let mut got: Vec<(String, String)> = Vec::new();
    for c in clusters(&v) {
        for key in ["commands", "events", "datatypes"] {
            for e in c[key].as_array().unwrap() {
                for f in e["fields"].as_array().into_iter().flatten() {
                    if f["secret"] == true {
                        assert!(
                            f["metatype"] == "bytes" || f["metatype"] == "string",
                            "{}.{}",
                            e["name"],
                            f["name"]
                        );
                        got.push((
                            c["name"].as_str().unwrap().to_string(),
                            format!(
                                "{}.{}",
                                e["name"].as_str().unwrap(),
                                f["name"].as_str().unwrap()
                            ),
                        ));
                    }
                    // The key is written only when true.
                    assert!(f["secret"] != false, "{}.{}", e["name"], f["name"]);
                }
            }
        }
    }
    got.sort();
    let got: Vec<(&str, &str)> = got.iter().map(|(c, f)| (c.as_str(), f.as_str())).collect();
    assert_eq!(got, SECRET);
}

// ---- M9-A3 B7: media and TV-platform clusters ------------------------------

#[test]
fn every_generated_cluster_with_events_has_them_dumped() {
    // M9-A3 spec §1 success criterion 2: once A3 is done, no generated cluster
    // keeps the "event dump not enabled" exclusion; every one with events has
    // them in clusters.json. EVENT_ALLOWLIST stays, to gate later additions.
    let v = load();
    let off: Vec<&str> = v["meta"]["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["reason"] == "event dump not enabled for this cluster")
        .map(|e| e["cluster"].as_str().unwrap())
        .collect();
    assert_eq!(off, Vec::<&str>::new());
    // The structural marker too: only the "events not enabled" branch of the
    // dump records `kind: "events"`, so a reworded reason cannot hide one.
    let whole_cluster: Vec<&str> = v["meta"]["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "events")
        .map(|e| e["cluster"].as_str().unwrap())
        .collect();
    assert_eq!(whole_cluster, Vec::<&str>::new());
}

#[test]
fn media_basics_keep_their_shapes() {
    // 1.4.2 WakeOnLAN.xml, LowPower.xml, KeypadInput.xml, MediaInput.xml,
    // AudioOutput.xml, TargetNavigator.xml.
    let v = load();
    let wol = cluster(&v, "WakeOnLan");
    assert_eq!(
        element_names(wol, "attributes"),
        ["MacAddress", "LinkLocalAddress"]
    );
    assert_eq!(element_names(wol, "commands"), Vec::<&str>::new());
    assert_eq!(
        element_names(cluster(&v, "LowPower"), "commands"),
        ["Sleep"]
    );
    let keypad = cluster(&v, "KeypadInput");
    assert_eq!(
        element_names(keypad, "commands"),
        ["SendKey", "SendKeyResponse"]
    );
    assert_eq!(element_names(keypad, "attributes"), Vec::<&str>::new());
    // CecKeyCodeEnum is not contiguous: 0x00..=0x0D, 0x10, 0x11, 0x1D..=0x2C,
    // 0x2F..=0x38, 0x40..=0x4E, 0x50..=0x57, 0x60..=0x6D, 0x71..=0x76. The
    // 1.4.2 XML also lists 0x4F as `Reserved`, which is not a key (the model
    // leaves it out; it decodes as Unknown(0x4F)).
    assert_eq!(enum_values(datatype(keypad, "CecKeyCodeEnum")).len(), 85);
    for name in ["MediaInput", "AudioOutput"] {
        let c = cluster(&v, name);
        assert_eq!(writable_attributes(c), Vec::<&str>::new(), "{name}");
        assert!(
            c["commands"]
                .as_array()
                .unwrap()
                .iter()
                .all(|cmd| cmd["responseId"].is_null()),
            "{name}: every request answers with a status"
        );
    }
    assert_eq!(
        field_optionality(&datatype(cluster(&v, "MediaInput"), "InputInfoStruct")["fields"]),
        [
            ("Index", false),
            ("InputType", false),
            ("Name", false),
            ("Description", false)
        ]
    );
    let tn = cluster(&v, "TargetNavigator");
    assert_eq!(element_names(tn, "events"), ["TargetUpdated"]);
    assert_eq!(
        field_optionality(&tn["events"][0]["fields"]),
        [
            ("TargetList", true),
            ("CurrentTarget", true),
            ("Data", true)
        ]
    );
    assert_eq!(
        field_optionality(&command(tn, "NavigateTargetResponse")["fields"]),
        [("Status", false), ("Data", true)]
    );
}

#[test]
fn content_app_platform_keeps_its_shapes() {
    // 1.4.2 ApplicationBasic.xml, ApplicationLauncher.xml, AccountLogin.xml,
    // ContentAppObserver.xml.
    let v = load();
    let ab = cluster(&v, "ApplicationBasic");
    assert_eq!(
        element_names(ab, "attributes"),
        [
            "VendorName",
            "VendorId",
            "ApplicationName",
            "ProductId",
            "Application",
            "Status",
            "ApplicationVersion",
            "AllowedVendorList"
        ]
    );
    assert_eq!(element_names(ab, "commands"), Vec::<&str>::new());
    let al = cluster(&v, "ApplicationLauncher");
    for name in ["LaunchApp", "StopApp", "HideApp"] {
        let cmd = command(al, name);
        assert_eq!(cmd["responseId"], 3, "{name} answers LauncherResponse");
        assert_eq!(
            field_optionality(&cmd["fields"])[0],
            ("Application", true),
            "{name}"
        );
    }
    assert_eq!(
        field_optionality(&datatype(al, "ApplicationEPStruct")["fields"]),
        [("Application", false), ("Endpoint", true)]
    );
    let login = cluster(&v, "AccountLogin");
    assert_eq!(
        element_names(login, "commands"),
        ["GetSetupPin", "GetSetupPinResponse", "Login", "Logout"]
    );
    assert_eq!(element_names(login, "events"), ["LoggedOut"]);
    // The model leaves out LoggedOut's implicit FabricIndex (chip-xml-
    // conformance.ack); only Node.
    assert_eq!(
        field_optionality(&login["events"][0]["fields"]),
        [("Node", true)]
    );
    assert_eq!(
        field_optionality(
            &command(cluster(&v, "ContentAppObserver"), "ContentAppMessage")["fields"]
        ),
        [("Data", false), ("EncodingHint", true)]
    );
}

/// The class-N `FIELD_RELAXATIONS` fields, as `(cluster, "<Owner>.<Field>",
/// nullableReason)` (M9-A3 B7): fields chip's servers send null although the
/// model makes them non-nullable. The test checks that each is `nullable`,
/// is in `meta.relaxed`, and has exactly this `nullableReason`. That a class-N
/// field is decode-only is enforced elsewhere: by the dump and by codegen's
/// `check_chip_omits_relaxations` (`xtask/src/codegen/model.rs`), which refuse
/// one on a request field or a field of an encoded struct. A new one is a
/// review item.
const CHIP_NULLS_RELAXED: [(&str, &str, &str); 1] = [(
    "MediaPlayback",
    "TrackStruct.TrackAttributes",
    "chip's servers may send it null (tv-app does in ActiveTextTrack while no text track is active)",
)];

#[test]
fn fields_chip_sends_null_are_nullable_and_recorded() {
    let v = load();
    let relaxed: Vec<(&str, &str)> = v["meta"]["relaxed"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["class"] == "N")
        .map(|r| {
            (
                r["cluster"].as_str().unwrap(),
                r["element"].as_str().unwrap(),
            )
        })
        .collect();
    let mut got: Vec<(&str, String, &str)> = Vec::new();
    for c in clusters(&v) {
        let cname = c["name"].as_str().unwrap();
        for key in ["commands", "events", "datatypes"] {
            for o in c[key].as_array().unwrap() {
                for f in o["fields"].as_array().into_iter().flatten() {
                    if let Some(reason) = f.get("nullableReason") {
                        assert_eq!(f["nullable"], true, "{cname}.{}.{}", o["name"], f["name"]);
                        let at = format!(
                            "{}.{}",
                            o["name"].as_str().unwrap(),
                            f["name"].as_str().unwrap()
                        );
                        assert!(
                            relaxed.contains(&(cname, at.as_str())),
                            "{cname}.{at} not in meta.relaxed"
                        );
                        got.push((cname, at, reason.as_str().unwrap()));
                    }
                }
            }
        }
    }
    got.sort();
    let got: Vec<(&str, &str, &str)> = got.iter().map(|(c, f, r)| (*c, f.as_str(), *r)).collect();
    assert_eq!(got, CHIP_NULLS_RELAXED);
    assert_eq!(relaxed.len(), CHIP_NULLS_RELAXED.len());
}

#[test]
fn media_playback_keeps_its_shapes() {
    // 1.4.2 MediaPlayback.xml: eleven attributes, fourteen requests (eleven
    // answered by PlaybackResponse, three by a status), StateChanged.
    let v = load();
    let c = cluster(&v, "MediaPlayback");
    assert_eq!(element_names(c, "attributes").len(), 11);
    let answered: Vec<&str> = c["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|cmd| cmd["responseId"] == 10)
        .map(|cmd| cmd["name"].as_str().unwrap())
        .collect();
    assert_eq!(answered.len(), 11, "{answered:?}");
    for name in [
        "ActivateAudioTrack",
        "ActivateTextTrack",
        "DeactivateTextTrack",
    ] {
        assert!(command(c, name)["responseId"].is_null(), "{name}");
    }
    // AudioOutputIndex is nullable in the specification, and optional in the
    // model and matter.js (its 1.4.2 conformance is the AudioTracks feature);
    // chip's codegen has it mandatory and non-nullable.
    let audio = &command(c, "ActivateAudioTrack")["fields"][1];
    assert_eq!(
        (audio["optional"].as_bool(), audio["nullable"].as_bool()),
        (Some(true), Some(true))
    );
    assert_eq!(
        field_optionality(&datatype(c, "TrackAttributesStruct")["fields"]),
        [
            ("LanguageCode", false),
            ("Characteristics", true),
            ("DisplayName", true)
        ]
    );
    assert_eq!(element_names(c, "events"), ["StateChanged"]);
}

#[test]
fn content_launcher_keeps_its_shapes_and_copies_characteristic_enum() {
    // 1.4.2 ContentLauncher.xml. TrackPreferenceStruct.Characteristics is a
    // list of MediaPlayback's CharacteristicEnum: the dump copies the enum in
    // (`copiedFrom`) and the reference names the copy.
    let v = load();
    let c = cluster(&v, "ContentLauncher");
    let copied = datatype(c, "CharacteristicEnum");
    assert_eq!(copied["copiedFrom"], "MediaPlayback");
    // Names and values both: a copy that kept the values but shuffled the
    // names would decode every Characteristic as the wrong one.
    assert_eq!(
        enum_members(copied),
        enum_members(datatype(cluster(&v, "MediaPlayback"), "CharacteristicEnum"))
    );
    let characteristics = &datatype(c, "TrackPreferenceStruct")["fields"][1];
    assert_eq!(characteristics["entryType"], "CharacteristicEnum");
    // No datatype the cluster owns carries copiedFrom.
    for d in c["datatypes"].as_array().unwrap() {
        assert_eq!(
            d.get("copiedFrom").is_some(),
            d["name"] == "CharacteristicEnum",
            "{}",
            d["name"]
        );
    }
    assert_eq!(
        field_optionality(&datatype(c, "PlaybackPreferencesStruct")["fields"]),
        [
            ("PlaybackPosition", true),
            ("TextTrack", true),
            ("AudioTracks", true)
        ]
    );
    let dimension = datatype(c, "DimensionStruct")["fields"].as_array().unwrap();
    assert_eq!(
        (dimension[0]["type"].as_str(), dimension[1]["type"].as_str()),
        (Some("double"), Some("double"))
    );
    assert_eq!(
        element_names(c, "commands"),
        ["LaunchContent", "LaunchUrl", "LauncherResponse"]
    );
}

#[test]
fn channel_keeps_the_specifications_field_ids_and_copies_additional_info() {
    // 1.4.2 Channel.xml. GetProgramGuide's fields are 0-3 and 5-7 (4 is not
    // used); chip's codegen renumbers RecordingFlag, ExternalIDList and Data
    // to 4, 5, 6 (both refs), matter.js keeps 5, 6, 7. The ExternalIdList
    // fields reference ContentLauncher's AdditionalInfoStruct: the dump copies
    // it into Channel (`copiedFrom`).
    let v = load();
    let c = cluster(&v, "Channel");
    let ids: Vec<u64> = command(c, "GetProgramGuide")["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, [0, 1, 2, 3, 5, 6, 7]);
    let copied = datatype(c, "AdditionalInfoStruct");
    assert_eq!(copied["copiedFrom"], "ContentLauncher");
    // Every field's name, id, type, optionality and nullability: a copy that
    // kept the names but moved an id or changed a type would encode an
    // ExternalIdList entry differently from ContentLauncher's.
    assert_eq!(
        field_shapes(&copied["fields"]),
        field_shapes(&datatype(cluster(&v, "ContentLauncher"), "AdditionalInfoStruct")["fields"])
    );
    // No datatype the cluster owns carries copiedFrom.
    for d in c["datatypes"].as_array().unwrap() {
        assert_eq!(
            d.get("copiedFrom").is_some(),
            d["name"] == "AdditionalInfoStruct",
            "{}",
            d["name"]
        );
    }
    for owner in ["GetProgramGuide", "RecordProgram", "CancelRecordProgram"] {
        let f = command(c, owner)["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "ExternalIdList")
            .unwrap();
        assert_eq!(f["entryType"], "AdditionalInfoStruct", "{owner}");
    }
    assert_eq!(
        field_optionality(&command(c, "ProgramGuideResponse")["fields"]),
        [("Paging", false), ("ProgramList", false)]
    );
}

#[test]
fn content_control_is_provisional_and_keeps_its_shapes() {
    // 1.4.2 ContentControl.xml: the cluster id carries <provisionalConform/>
    // (PROVISIONAL_CLUSTERS; class V checks it against the XML). No element is
    // provisional on its own.
    let v = load();
    let c = cluster(&v, "ContentControl");
    assert_eq!(c["provisional"], true);
    assert_eq!(c["features"].as_array().unwrap().len(), 8);
    assert_eq!(
        element_names(c, "events"),
        [
            "RemainingScreenTimeExpired",
            "EnteringBlockContentTimeWindow"
        ]
    );
    for e in c["events"].as_array().unwrap() {
        assert_eq!(e["fields"].as_array().unwrap().len(), 0, "{}", e["name"]);
    }
    assert_eq!(
        field_optionality(&command(c, "UpdatePin")["fields"]),
        [("OldPin", false), ("NewPin", false)]
    );
    assert_eq!(
        field_optionality(&command(c, "AddBonusTime")["fields"]),
        [("PinCode", true), ("BonusTime", false)]
    );
    let window = datatype(c, "TimeWindowStruct");
    assert_eq!(window["fields"][0]["nullable"], true);
    assert_eq!(window["fields"][2]["entryType"], "TimePeriodStruct");
    // ContentControl's own cluster-specific status codes (2-11) are kept.
    assert_eq!(
        enum_values(datatype(c, "StatusCodeEnum")),
        [2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    );
}
