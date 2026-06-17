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
/// pilot batch (read-only sensors + Switch), the M9-A2.2 energy batch, and the
/// M9-A2.3 actuator batch.
const TARGET_CLUSTERS: [&str; 33] = [
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
fn covers_exactly_the_ten_target_clusters() {
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
        let attrs = c["attributes"].as_array().expect("attributes array");
        assert!(!attrs.is_empty(), "{name}: expected at least one attribute");
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
