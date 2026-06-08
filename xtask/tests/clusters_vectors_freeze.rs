//! Freezes `test-vectors/clusters/` — the matter.js 0.16.11 byte-parity
//! oracle for the generated cluster codecs (consumed in M7.4b).
//!
//! Reads the committed JSON (no Node), so it runs in CI and catches a
//! malformed or under-covered re-capture before it can land.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/clusters")
}

fn read(rel: &str) -> Value {
    let path = vectors_root().join(rel);
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Every attribute vector this milestone must capture (relative path).
const ATTR_VECTORS: [&str; 11] = [
    "on_off/attr_on_off.json",
    "on_off/attr_on_time.json",
    "on_off/attr_start_up_on_off_present.json",
    "on_off/attr_start_up_on_off_null.json",
    "basic_information/attr_node_label.json",
    "basic_information/attr_capability_minima.json",
    "level_control/attr_current_level_present.json",
    "temperature_measurement/attr_measured_value.json",
    "descriptor/attr_server_list.json",
    "descriptor/attr_device_type_list.json",
    "color_control/attr_color_capabilities.json",
];

/// Every command vector this milestone must capture (relative path).
const CMD_VECTORS: [&str; 5] = [
    "on_off/cmd_toggle.json",
    "on_off/cmd_on_with_timed_off.json",
    "level_control/cmd_move_to_level.json",
    "door_lock/cmd_lock_door_with_pin.json",
    "door_lock/cmd_lock_door_no_pin.json",
];

#[test]
fn all_attribute_vectors_present_and_well_formed() {
    for rel in ATTR_VECTORS {
        let v = read(rel);
        for key in ["cluster", "attribute", "type", "note"] {
            assert!(
                v[key].as_str().is_some_and(|s| !s.is_empty()),
                "{rel}: missing {key}"
            );
        }
        assert!(v["cluster_id"].is_number(), "{rel}: cluster_id");
        assert!(v["attribute_id"].is_number(), "{rel}: attribute_id");
        assert!(v["writable"].is_boolean(), "{rel}: writable");
        assert!(
            v["value_tlv_b64"].as_str().is_some_and(|s| !s.is_empty()),
            "{rel}: value_tlv_b64"
        );
    }
}

#[test]
fn all_command_vectors_present_and_well_formed() {
    for rel in CMD_VECTORS {
        let v = read(rel);
        for key in ["cluster", "command", "note"] {
            assert!(
                v[key].as_str().is_some_and(|s| !s.is_empty()),
                "{rel}: missing {key}"
            );
        }
        assert!(v["command_id"].is_number(), "{rel}: command_id");
        assert!(v["fields"].is_array(), "{rel}: fields array");
        assert!(
            v["payload_tlv_b64"].as_str().is_some_and(|s| !s.is_empty()),
            "{rel}: payload_tlv_b64"
        );
    }
}

#[test]
fn type_matrix_branches_are_covered() {
    // nullable-null carries the TLV Null element (base64 "FA==" = 0x14).
    let null_vec = read("on_off/attr_start_up_on_off_null.json");
    assert_eq!(
        null_vec["value_tlv_b64"].as_str().unwrap(),
        "FA==",
        "nullable-null must encode the bare TLV null element"
    );
    // optional-absent: the LockDoor-no-pin payload is the empty anonymous
    // struct (base64 "FRg=" = 0x15 0x18).
    let absent = read("door_lock/cmd_lock_door_no_pin.json");
    assert_eq!(
        absent["payload_tlv_b64"].as_str().unwrap(),
        "FRg=",
        "optional-absent command must omit the field (empty struct)"
    );
    // optional-present differs from optional-absent.
    let present = read("door_lock/cmd_lock_door_with_pin.json");
    assert_ne!(
        present["payload_tlv_b64"].as_str().unwrap(),
        absent["payload_tlv_b64"].as_str().unwrap(),
        "optional-present must include the field"
    );
    // list-of-structs is captured.
    let list = read("descriptor/attr_device_type_list.json");
    assert!(list["type"].as_str().unwrap().contains("list["));
}
