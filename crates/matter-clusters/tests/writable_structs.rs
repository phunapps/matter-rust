//! The structs a writable attribute carries are constructible outside this
//! crate: a caller builds a new entry with a struct literal and encodes it,
//! not only re-encodes a decoded one. This file is its own crate, so a
//! `#[non_exhaustive]` on any of the eight would stop it compiling (E0639).

// Test code: a failed encode or decode is a test failure.
#![allow(clippy::unwrap_used)]

use matter_clusters::clusters::{
    access_control, binding, group_key_management, ota_software_update_requestor, thermostat,
    user_label,
};
use matter_clusters::error::ClusterError;
use matter_clusters::types::Nullable;

#[test]
fn binding_target_builds_encodes_and_decodes() {
    let t = binding::TargetStruct {
        node: Some(0x1122),
        group: None,
        endpoint: Some(1),
        cluster: Some(0x0006),
        fabric_index: 1,
    };
    assert_eq!(binding::TargetStruct::decode(&t.encode()).unwrap(), t);
}

#[test]
fn user_label_builds_encodes_and_decodes() {
    let l = user_label::LabelStruct {
        label: "room".to_string(),
        value: "kitchen".to_string(),
    };
    assert_eq!(user_label::LabelStruct::decode(&l.encode()).unwrap(), l);
}

#[test]
fn group_key_map_builds_encodes_and_decodes() {
    let m = group_key_management::GroupKeyMapStruct {
        group_id: 0x0101,
        group_key_set_id: 0x01a1,
        fabric_index: 1,
    };
    assert_eq!(
        group_key_management::GroupKeyMapStruct::decode(&m.encode()).unwrap(),
        m
    );
}

#[test]
fn provider_location_builds_encodes_and_decodes() {
    let p = ota_software_update_requestor::ProviderLocation {
        provider_node_id: 0x0102_0304,
        endpoint: 0,
        fabric_index: 2,
    };
    assert_eq!(
        ota_software_update_requestor::ProviderLocation::decode(&p.encode()).unwrap(),
        p
    );
}

#[test]
fn thermostat_preset_and_schedule_transition_build_encode_and_decode() {
    let preset = thermostat::PresetStruct {
        preset_handle: Nullable::Null,
        preset_scenario: thermostat::PresetScenarioEnum::Sleep,
        name: Some(Nullable::Value("night".to_string())),
        cooling_setpoint: None,
        heating_setpoint: Some(1800),
        built_in: Nullable::Value(false),
    };
    assert_eq!(
        thermostat::PresetStruct::decode(&preset.encode()).unwrap(),
        preset
    );
    let transition = thermostat::ScheduleTransitionStruct {
        day_of_week: thermostat::ScheduleDayOfWeekBitmap::MONDAY,
        transition_time: 420,
        preset_handle: Some(vec![1]),
        system_mode: None,
        cooling_setpoint: None,
        heating_setpoint: None,
    };
    assert_eq!(
        thermostat::ScheduleTransitionStruct::decode(&transition.encode()).unwrap(),
        transition
    );
}

#[test]
fn access_control_extension_and_target_build_encode_and_decode() {
    let ext = access_control::AccessControlExtensionStruct {
        data: Some(vec![0x15, 0x18]),
        fabric_index: 1,
    };
    assert_eq!(
        access_control::AccessControlExtensionStruct::decode(&ext.encode().unwrap()).unwrap(),
        ext
    );
    let target = access_control::AccessControlTargetStruct {
        cluster: Nullable::Value(0x0006),
        endpoint: Nullable::Null,
        device_type: Nullable::Null,
    };
    assert_eq!(
        access_control::AccessControlTargetStruct::decode(&target.encode()).unwrap(),
        target
    );
}

#[test]
fn a_built_extension_without_its_fabric_sensitive_data_is_refused() {
    // `Data` is `Option` only so another fabric's withheld entry decodes; an
    // entry we write must carry it.
    let ext = access_control::AccessControlExtensionStruct {
        data: None,
        fabric_index: 1,
    };
    assert!(matches!(
        ext.encode(),
        Err(ClusterError::MissingField("Data"))
    ));
}
