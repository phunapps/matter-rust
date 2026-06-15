//! Byte-parity of generated cluster codecs vs the matter.js 0.16.11 vectors
//! captured in `test-vectors/clusters/` (M7.4a).
//!
//! Writable attributes: decode the vector bytes, re-encode, assert equal —
//! proving our decode accepts matter.js bytes and our encode reproduces them.
//! Read-only attributes: decode succeeds (+ spot checks). Commands: build the
//! typed args and assert `encode_<cmd>` equals the captured payload.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use matter_clusters::gen;
use matter_clusters::types::Nullable;
use std::fs;
use std::path::PathBuf;

fn vec_bytes(rel: &str, key: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test-vectors/clusters")
        .join(rel);
    let v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    base64::engine::general_purpose::STANDARD
        .decode(v[key].as_str().unwrap())
        .unwrap()
}

fn attr(rel: &str) -> Vec<u8> {
    vec_bytes(rel, "value_tlv_b64")
}
fn cmd(rel: &str) -> Vec<u8> {
    vec_bytes(rel, "payload_tlv_b64")
}

// ---- writable attributes: decode -> re-encode -> equal -------------------

#[test]
fn on_time_roundtrips() {
    let bytes = attr("on_off/attr_on_time.json");
    let v = gen::on_off::decode_on_time(&bytes).unwrap();
    assert_eq!(gen::on_off::encode_on_time(v), bytes);
}

#[test]
fn start_up_on_off_present_roundtrips() {
    let bytes = attr("on_off/attr_start_up_on_off_present.json");
    let v = gen::on_off::decode_start_up_on_off(&bytes).unwrap();
    assert_eq!(gen::on_off::encode_start_up_on_off(v), bytes);
}

#[test]
fn start_up_on_off_null_roundtrips() {
    let bytes = attr("on_off/attr_start_up_on_off_null.json");
    let v = gen::on_off::decode_start_up_on_off(&bytes).unwrap();
    assert!(matches!(v, Nullable::Null));
    assert_eq!(gen::on_off::encode_start_up_on_off(v), bytes);
}

#[test]
fn node_label_roundtrips() {
    let bytes = attr("basic_information/attr_node_label.json");
    let v = gen::basic_information::decode_node_label(&bytes).unwrap();
    assert_eq!(v, "matter-rust");
    assert_eq!(gen::basic_information::encode_node_label(&v), bytes);
}

// ---- read-only attributes: decode succeeds (+ spot checks) ---------------

#[test]
fn bool_and_nullable_uint_decode() {
    assert!(gen::on_off::decode_on_off(&attr("on_off/attr_on_off.json")).unwrap());
    let lvl = gen::level_control::decode_current_level(&attr(
        "level_control/attr_current_level_present.json",
    ))
    .unwrap();
    assert_eq!(lvl, Nullable::Value(254));
}

#[test]
fn temperature_signed_decode() {
    let t = gen::temperature_measurement::decode_measured_value(&attr(
        "temperature_measurement/attr_measured_value.json",
    ))
    .unwrap();
    assert_eq!(t, Nullable::Value(-1234));
}

#[test]
fn bitmap_u16_decode() {
    // ColorCapabilities is a map16 bitmap — proves the u16-backing fix.
    let caps = gen::color_control::decode_color_capabilities(&attr(
        "color_control/attr_color_capabilities.json",
    ))
    .unwrap();
    assert_eq!(caps.bits(), 0b10101);
}

#[test]
fn struct_attribute_decode() {
    let m = gen::basic_information::decode_capability_minima(&attr(
        "basic_information/attr_capability_minima.json",
    ))
    .unwrap();
    assert_eq!(m.case_sessions_per_fabric, 3);
    assert_eq!(m.subscriptions_per_fabric, 4);
}

#[test]
fn list_of_scalars_and_structs_decode() {
    let server =
        gen::descriptor::decode_server_list(&attr("descriptor/attr_server_list.json")).unwrap();
    assert_eq!(server, vec![0x06, 0x1d, 0x28]);

    let dts =
        gen::descriptor::decode_device_type_list(&attr("descriptor/attr_device_type_list.json"))
            .unwrap();
    assert_eq!(dts.len(), 1);
    assert_eq!(dts[0].device_type, 256);
    assert_eq!(dts[0].revision, 1);
}

#[test]
fn measurement_accuracy_struct_decodes() {
    // M9-A2.2: EEM.Accuracy is a MeasurementAccuracyStruct whose AccuracyRanges
    // is a list-of-struct with optional fields present/absent — the genuinely-new
    // nested wire shape. Decode the matter.js-captured bytes and assert structure.
    let acc = gen::electrical_energy_measurement::decode_accuracy(&attr(
        "electrical_energy_measurement/attr_accuracy.json",
    ))
    .unwrap();
    assert_eq!(acc.measurement_type.to_raw(), 0); // ActivePower
    assert!(acc.measured);
    assert_eq!(acc.min_measured_value, 1000);
    assert_eq!(acc.max_measured_value, 50000);
    assert_eq!(acc.accuracy_ranges.len(), 2);

    let r0 = &acc.accuracy_ranges[0];
    assert_eq!(r0.range_min, 0);
    assert_eq!(r0.range_max, 10000);
    assert_eq!(r0.percent_max, Some(500));
    assert_eq!(r0.fixed_max, None);

    let r1 = &acc.accuracy_ranges[1];
    assert_eq!(r1.range_min, 10001);
    assert_eq!(r1.fixed_max, Some(100));
    assert_eq!(r1.percent_max, None);
}

// ---- commands: build typed args -> encode -> equal -----------------------

#[test]
fn toggle_command() {
    assert_eq!(gen::on_off::encode_toggle(), cmd("on_off/cmd_toggle.json"));
}

#[test]
fn on_with_timed_off_command() {
    let got = gen::on_off::encode_on_with_timed_off(
        gen::on_off::OnOffControlBitmap::from_bits_truncate(1),
        60,
        0,
    );
    assert_eq!(got, cmd("on_off/cmd_on_with_timed_off.json"));
}

#[test]
fn move_to_level_command() {
    let got = gen::level_control::encode_move_to_level(
        128,
        Nullable::Value(10),
        gen::level_control::OptionsBitmap::from_bits_truncate(0),
        gen::level_control::OptionsBitmap::from_bits_truncate(0),
    );
    assert_eq!(got, cmd("level_control/cmd_move_to_level.json"));
}

#[test]
fn lock_door_optional_field() {
    let with = gen::door_lock::encode_lock_door(Some(vec![1, 2, 3, 4]));
    assert_eq!(with, cmd("door_lock/cmd_lock_door_with_pin.json"));
    let without = gen::door_lock::encode_lock_door(None);
    assert_eq!(without, cmd("door_lock/cmd_lock_door_no_pin.json"));
}

#[test]
fn atomic_request_command_encodes() {
    // Thermostat.AtomicRequest with a populated list<attrib-id> — proves the
    // list-typed-command-field encode matches matter.js byte-for-byte.
    assert_eq!(
        gen::thermostat::encode_atomic_request(0, &vec![5, 6], Some(1000)),
        cmd("thermostat/cmd_atomic_request.json")
    );
}
