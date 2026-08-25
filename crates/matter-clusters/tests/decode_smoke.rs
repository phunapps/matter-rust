//! Decode-smoke for the M9-A2.1 pilot and M9-A2.2 energy clusters: each
//! generated decoder reads a representative attribute's wire value. These
//! clusters are read-only; A2.1 reuses datatype shapes already byte-parity-proven
//! by the M7 clusters, and A2.2's one genuinely-new nested shape
//! (`MeasurementAccuracyStruct`) gets a dedicated matter.js byte-parity vector in
//! `byte_parity.rs`. Here a synthetic decode (construct TLV → decode → assert) is
//! the gate. (Roundtrip applies to writable attrs in later batches.)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use matter_clusters::gen;
use matter_clusters::types::Nullable;
use matter_codec::{Tag, TlvWriter};

/// Encode a single anonymous-tagged unsigned scalar (the wire shape of a
/// read-only scalar attribute value).
fn uint_attr(v: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    TlvWriter::new(&mut buf)
        .put_uint(Tag::Anonymous, v)
        .unwrap();
    buf
}
fn int_attr(v: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    TlvWriter::new(&mut buf).put_int(Tag::Anonymous, v).unwrap();
    buf
}
fn bool_attr(v: bool) -> Vec<u8> {
    let mut buf = Vec::new();
    TlvWriter::new(&mut buf)
        .put_bool(Tag::Anonymous, v)
        .unwrap();
    buf
}
fn null_attr() -> Vec<u8> {
    let mut buf = Vec::new();
    TlvWriter::new(&mut buf).put_null(Tag::Anonymous).unwrap();
    buf
}

#[test]
fn illuminance_measured_value_decodes() {
    // MeasuredValue: nullable uint16.
    assert_eq!(
        gen::illuminance_measurement::decode_measured_value(&uint_attr(12345)).unwrap(),
        Nullable::Value(12345)
    );
    assert_eq!(
        gen::illuminance_measurement::decode_measured_value(&null_attr()).unwrap(),
        Nullable::Null
    );
}

#[test]
fn pressure_measured_value_decodes() {
    // MeasuredValue: nullable int16.
    assert_eq!(
        gen::pressure_measurement::decode_measured_value(&int_attr(-50)).unwrap(),
        Nullable::Value(-50)
    );
}

#[test]
fn flow_measured_value_decodes() {
    // MeasuredValue: nullable uint16.
    assert_eq!(
        gen::flow_measurement::decode_measured_value(&uint_attr(200)).unwrap(),
        Nullable::Value(200)
    );
}

#[test]
fn boolean_state_state_value_decodes() {
    // StateValue: bool.
    assert!(gen::boolean_state::decode_state_value(&bool_attr(true)).unwrap());
}

#[test]
fn switch_current_position_decodes() {
    // CurrentPosition: uint8 (not nullable).
    assert_eq!(
        gen::switch::decode_current_position(&uint_attr(2)).unwrap(),
        2
    );
}

// ---- M9-A2.2 energy batch -------------------------------------------------
// These exercise the new shapes A2.2 added to the emitter: a list of named
// enums (gap 6), a nullable struct-valued attribute (gap 7), a nullable list
// (gap 8), the energy semantic scalars (gap 3), and an `Unknown`-member enum
// with its renamed `Unrecognized` catch-all (gaps 1/5).

/// Encode an anonymous-tagged array of anonymous unsigned scalars (the wire
/// shape of a `list<enum8>` / `list<endpoint-no>` attribute value).
fn uint_array_attr(values: &[u64]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_array(Tag::Anonymous).unwrap();
        for &v in values {
            w.put_uint(Tag::Anonymous, v).unwrap();
        }
        w.end_container().unwrap();
    }
    buf
}

#[test]
fn air_quality_decodes() {
    use gen::air_quality::AirQualityEnum;
    assert_eq!(
        gen::air_quality::decode_air_quality(&uint_attr(1)).unwrap(),
        AirQualityEnum::Good
    );
    // The model member named `Unknown` (value 0) is a fieldless variant…
    assert_eq!(
        gen::air_quality::decode_air_quality(&uint_attr(0)).unwrap(),
        AirQualityEnum::Unknown
    );
    // …and an out-of-range discriminant lands in the renamed catch-all.
    assert_eq!(
        gen::air_quality::decode_air_quality(&uint_attr(99)).unwrap(),
        AirQualityEnum::Unrecognized(99)
    );
}

#[test]
fn power_source_status_and_lists_decode() {
    use gen::power_source::{PowerSourceStatusEnum, WiredFaultEnum};
    // Status: mandatory enum8.
    assert_eq!(
        gen::power_source::decode_status(&uint_attr(1)).unwrap(),
        PowerSourceStatusEnum::Active
    );
    // ActiveWiredFaults: list<WiredFaultEnum> -> Vec<WiredFaultEnum> (gap 6).
    assert_eq!(
        gen::power_source::decode_active_wired_faults(&uint_array_attr(&[1])).unwrap(),
        vec![WiredFaultEnum::OverVoltage]
    );
    // EndpointList: list<endpoint-no> -> Vec<u16>.
    assert_eq!(
        gen::power_source::decode_endpoint_list(&uint_array_attr(&[1, 2])).unwrap(),
        vec![1u16, 2u16]
    );
}

#[test]
fn electrical_power_measurement_decodes() {
    use gen::electrical_power_measurement as epm;
    // PowerMode: mandatory enum8 (model has an `Unknown` member -> renamed catch-all).
    assert_eq!(
        epm::decode_power_mode(&uint_attr(2)).unwrap(),
        epm::PowerModeEnum::Ac
    );
    // Voltage: nullable voltage-mV -> Nullable<i64> (gap 3).
    assert_eq!(
        epm::decode_voltage(&int_attr(230_000)).unwrap(),
        Nullable::Value(230_000)
    );
    // Accuracy: list<MeasurementAccuracyStruct> -> Vec<…>; empty array -> empty Vec.
    assert!(epm::decode_accuracy(&uint_array_attr(&[]))
        .unwrap()
        .is_empty());
    // HarmonicCurrents: nullable list -> Nullable<Vec<…>> (gap 8); null decodes to Null.
    assert!(matches!(
        epm::decode_harmonic_currents(&null_attr()).unwrap(),
        Nullable::Null
    ));
}

#[test]
fn electrical_energy_measurement_nullable_struct_attr_decodes() {
    // CumulativeEnergyImported: nullable EnergyMeasurementStruct -> Nullable<…>
    // (gap 7); a TLV null decodes to Nullable::Null.
    assert!(matches!(
        gen::electrical_energy_measurement::decode_cumulative_energy_imported(&null_attr())
            .unwrap(),
        Nullable::Null
    ));
}

// ---- M9-A2.3 actuator batch ----------------------------------------------

#[test]
fn thermostat_system_mode_decodes() {
    use gen::thermostat::SystemModeEnum;
    // SystemMode: enum8; raw 4 = Heat (spot-check a known member).
    assert_eq!(
        gen::thermostat::decode_system_mode(&uint_attr(4)).unwrap(),
        SystemModeEnum::Heat
    );
}

#[test]
fn thermostat_atomic_response_decodes_synth_struct() {
    use matter_codec::{ContainerKind, Element, TlvReader};
    // Hand-build an AtomicResponse payload: anon struct {
    //   ctx0 = StatusCode(0),
    //   ctx1 = array[ struct{ ctx0=AttributeId(0x1234), ctx1=StatusCode(0) } ],
    //   ctx2 = Timeout(1000) }.
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 0).unwrap();
        w.start_array(Tag::Context(1)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 0x1234).unwrap();
        w.put_uint(Tag::Context(1), 0).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(2), 1000).unwrap();
        w.end_container().unwrap();
    }
    let mut r = TlvReader::new(&buf);
    // Consume the opening anonymous structure, then decode the fields.
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart {
            kind: ContainerKind::Structure,
            ..
        })
    ));
    let resp = gen::thermostat::AtomicResponse::decode_from(&mut r).unwrap();
    assert_eq!(resp.status_code, 0);
    assert_eq!(resp.attribute_status.len(), 1);
    assert_eq!(resp.attribute_status[0].attribute_id, 0x1234);
    assert_eq!(resp.attribute_status[0].status_code, 0);
    assert_eq!(resp.timeout, Some(1000));
}

#[test]
fn fan_control_fan_mode_decodes() {
    use gen::fan_control::FanModeEnum;
    // FanMode: enum8; raw 3 = High.
    assert_eq!(
        gen::fan_control::decode_fan_mode(&uint_attr(3)).unwrap(),
        FanModeEnum::High
    );
}

#[test]
fn tuic_keypad_lockout_decodes() {
    use gen::thermostat_user_interface_configuration::KeypadLockoutEnum;
    // KeypadLockout: enum8; raw 0 = NoLockout.
    assert_eq!(
        gen::thermostat_user_interface_configuration::decode_keypad_lockout(&uint_attr(0)).unwrap(),
        KeypadLockoutEnum::NoLockout
    );
}

#[test]
fn pump_operation_mode_decodes() {
    use gen::pump_configuration_and_control::OperationModeEnum;
    // OperationMode: enum8; raw 0 = Normal.
    assert_eq!(
        gen::pump_configuration_and_control::decode_operation_mode(&uint_attr(0)).unwrap(),
        OperationModeEnum::Normal
    );
}

#[test]
fn window_covering_mode_decodes() {
    // Mode: map8 bitmap; bit0 = MotorDirectionReversed (raw 1).
    let m = gen::window_covering::decode_mode(&uint_attr(1)).unwrap();
    assert_eq!(m.bits(), 1);
}

// ---- M9-A2.4 utility batch ------------------------------------------------

#[test]
fn binding_target_struct_decodes_fabric_index() {
    use matter_codec::{ContainerKind, Element, TlvReader};
    // TargetStruct { Cluster(4)=0x0006, FabricIndex(254)=1 } — proves the
    // global FabricIndex typedef de-aliases to u8 (gap 1).
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(4), 0x0006).unwrap();
        w.put_uint(Tag::Context(254), 1).unwrap();
        w.end_container().unwrap();
    }
    let mut r = TlvReader::new(&buf);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart {
            kind: ContainerKind::Structure,
            ..
        })
    ));
    let t = gen::binding::TargetStruct::decode_from(&mut r).unwrap();
    assert_eq!(t.cluster, Some(0x0006));
    assert_eq!(t.fabric_index, 1u8);
}

#[test]
fn fixed_label_label_struct_decodes() {
    use matter_codec::{ContainerKind, Element, TlvReader};
    // LabelStruct { Label(0)="room", Value(1)="kitchen" }.
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_utf8(Tag::Context(0), "room").unwrap();
        w.put_utf8(Tag::Context(1), "kitchen").unwrap();
        w.end_container().unwrap();
    }
    let mut r = TlvReader::new(&buf);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart {
            kind: ContainerKind::Structure,
            ..
        })
    ));
    let l = gen::fixed_label::LabelStruct::decode_from(&mut r).unwrap();
    assert_eq!(l.label, "room");
    assert_eq!(l.value, "kitchen");
}

#[test]
fn groups_add_group_command_encodes_wellformed() {
    use matter_codec::{Element, TlvReader, Value};
    // encode_add_group(group_id, group_name) -> anon struct { ctx0=uint, ctx1=utf8 }.
    let bytes = gen::groups::encode_add_group(0x0007, &"den".to_string());
    let mut r = TlvReader::new(&bytes);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart { .. })
    ));
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::Scalar {
            tag: Tag::Context(0),
            value: Value::Uint(7)
        })
    ));
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::Scalar { tag: Tag::Context(1), value: Value::Utf8(ref s) }) if s == "den"
    ));
}

#[test]
fn groups_get_group_membership_command_encodes_list() {
    use matter_codec::{ContainerKind, Element, TlvReader, Value};
    // encode_get_group_membership(list<group-id>) -> anon struct { ctx0=array[uint,uint] }
    // (reuses the A2.3 list-typed-command-field encode codepath).
    let bytes = gen::groups::encode_get_group_membership(&vec![1u16, 2u16]);
    let mut r = TlvReader::new(&bytes);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart { .. })
    ));
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart {
            tag: Tag::Context(0),
            kind: ContainerKind::Array
        })
    ));
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::Scalar {
            value: Value::Uint(1),
            ..
        })
    ));
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::Scalar {
            value: Value::Uint(2),
            ..
        })
    ));
}

// ---- M9-A2.5 management batch ----------------------------------------------

#[test]
fn access_control_entry_decodes_subjects_u64() {
    use matter_codec::{ContainerKind, Element, TlvReader};
    // AccessControlEntryStruct { Privilege(1)=5, AuthMode(2)=2,
    //   Subjects(3)=[0x1122334455667788], Targets(4)=null, FabricIndex(254)=1 }.
    // Proves subject-id -> u64 (gap 1) and nullable list-of-scalar decode.
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(1), 5).unwrap();
        w.put_uint(Tag::Context(2), 2).unwrap();
        w.start_array(Tag::Context(3)).unwrap();
        w.put_uint(Tag::Anonymous, 0x1122_3344_5566_7788).unwrap();
        w.end_container().unwrap();
        w.put_null(Tag::Context(4)).unwrap();
        w.put_uint(Tag::Context(254), 1).unwrap();
        w.end_container().unwrap();
    }
    let mut r = TlvReader::new(&buf);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart {
            kind: ContainerKind::Structure,
            ..
        })
    ));
    let e = gen::access_control::AccessControlEntryStruct::decode_from(&mut r).unwrap();
    assert_eq!(e.subjects, Nullable::Value(vec![0x1122_3344_5566_7788u64]));
    assert!(matches!(e.targets, Nullable::Null));
    assert_eq!(e.fabric_index, 1u8);
}

#[test]
fn group_key_set_write_encodes_wellformed() {
    use matter_codec::{Element, TlvReader};
    // KeySetWrite wraps a GroupKeySetStruct at ctx0 (single struct command field,
    // a shape DoorLock's SetCredential already proves). Smoke: encode is a
    // well-formed anon struct holding a nested struct.
    let gks = gen::group_key_management::GroupKeySetStruct {
        group_key_set_id: 0x0042,
        group_key_security_policy: gen::group_key_management::GroupKeySecurityPolicyEnum::from_raw(
            0,
        ),
        epoch_key0: Nullable::Value(vec![0xab; 16]),
        epoch_start_time0: Nullable::Value(1234),
        epoch_key1: Nullable::Null,
        epoch_start_time1: Nullable::Null,
        epoch_key2: Nullable::Null,
        epoch_start_time2: Nullable::Null,
        group_key_multicast_policy: None,
        fabric_index: None,
    };
    let bytes = gen::group_key_management::encode_key_set_write(gks);
    let mut r = TlvReader::new(&bytes);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart { .. })
    ));
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart {
            tag: Tag::Context(0),
            ..
        })
    ));
}

#[test]
fn admin_open_basic_commissioning_window_encodes() {
    use matter_codec::{Element, TlvReader, Value};
    let bytes = gen::administrator_commissioning::encode_open_basic_commissioning_window(180);
    let mut r = TlvReader::new(&bytes);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart { .. })
    ));
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::Scalar {
            tag: Tag::Context(0),
            value: Value::Uint(180)
        })
    ));
}

#[test]
fn ota_announce_provider_encodes_scalars_and_enum() {
    use gen::ota_software_update_requestor::AnnouncementReasonEnum;
    use matter_codec::{Element, TlvReader, Value};
    // metadata_for_node is optional -> None skips ctx3; ctx0 is the node id.
    let bytes = gen::ota_software_update_requestor::encode_announce_ota_provider(
        0x0000_0000_0000_1234,
        0xFFF1,
        AnnouncementReasonEnum::SimpleAnnouncement,
        None,
        1,
    );
    let mut r = TlvReader::new(&bytes);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart { .. })
    ));
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::Scalar {
            tag: Tag::Context(0),
            value: Value::Uint(0x1234)
        })
    ));
}

#[test]
fn ota_provider_query_image_encodes_scalars() {
    use gen::ota_software_update_provider::{encode_query_image, DownloadProtocolEnum};
    use matter_codec::{Element, TlvReader, Value};
    let bytes = encode_query_image(
        0xFFF1,
        0x8000,
        5,
        &vec![DownloadProtocolEnum::BdxSynchronous],
        None,
        None,
        None,
        None,
    );
    let mut r = TlvReader::new(&bytes);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart { .. })
    ));
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::Scalar {
            tag: Tag::Context(0),
            value: Value::Uint(0xFFF1)
        })
    ));
}

#[test]
fn ota_provider_query_image_response_decodes() {
    use gen::ota_software_update_provider::{QueryImageResponse, StatusEnum};
    use matter_codec::{Element, Tag, TlvReader, TlvWriter};
    // Hand-build a minimal QueryImageResponse: ctx0 Status = UpdateAvailable(0).
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).unwrap();
    w.put_uint(Tag::Context(0), 0).unwrap(); // Status = UpdateAvailable
    w.end_container().unwrap();
    let mut r = TlvReader::new(&buf);
    assert!(matches!(
        r.next().unwrap(),
        Some(Element::ContainerStart { .. })
    ));
    let decoded = QueryImageResponse::decode_from(&mut r).expect("decode QueryImageResponse");
    assert_eq!(decoded.status, StatusEnum::UpdateAvailable);
}

#[test]
fn time_sync_utc_time_and_granularity_decode() {
    use gen::time_synchronization::{decode_granularity, decode_utc_time, GranularityEnum};
    // UTCTime is nullable epoch_us; a present value decodes to Nullable::Some.
    let decoded = decode_utc_time(&uint_attr(780_000_000_000_000)).unwrap();
    assert_eq!(decoded, Nullable::Value(780_000_000_000_000));
    // Granularity enum8 = SecondsGranularity(2).
    let g = decode_granularity(&uint_attr(2)).unwrap();
    assert_eq!(g, GranularityEnum::SecondsGranularity);
}

#[test]
fn icd_register_client_response_and_operating_mode_decode() {
    use gen::icd_management::{decode_operating_mode, OperatingModeEnum, RegisterClientResponse};
    use matter_codec::{Tag, TlvWriter};
    // RegisterClientResponse: ctx0 ICDCounter = 7.
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).unwrap();
    w.put_uint(Tag::Context(0), 7).unwrap();
    w.end_container().unwrap();
    let decoded = RegisterClientResponse::decode(&buf).expect("decode RegisterClientResponse");
    assert_eq!(decoded.icd_counter, 7);
    // OperatingMode enum8 = Lit(1).
    let m = decode_operating_mode(&uint_attr(1)).unwrap();
    assert_eq!(m, OperatingModeEnum::Lit);
}

#[test]
fn time_sync_set_time_zone_response_decodes() {
    use gen::time_synchronization::SetTimeZoneResponse;
    use matter_codec::{Tag, TlvWriter};
    // Hand-build SetTimeZoneResponse: ctx0 DSTOffsetRequired = true.
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous).unwrap();
    w.put_bool(Tag::Context(0), true).unwrap();
    w.end_container().unwrap();
    let decoded = SetTimeZoneResponse::decode(&buf).expect("decode SetTimeZoneResponse");
    assert!(decoded.dst_offset_required);
}

// ---- concentration measurement family (#112) -----------------------------
//
// The 10 concentration-measurement clusters (Matter 1.2) are *derived* from one
// base cluster, so they share a single shape: nullable `single` (float32)
// measurements, two `elapsed-s` windows, and three enums. That shape is the
// first FLOAT on the wire in this crate, so it also gets a matter.js
// byte-parity vector (`byte_parity.rs::float_attribute_decodes_matter_js_bytes`)
// on CarbonDioxide as the family representative; the per-cluster tests below
// are the usual synthetic decode-smoke, proving every generated module is
// wired up and decodes its float.

/// Encode a single anonymous-tagged FLOAT32 (the wire shape of a `single`
/// attribute value). These clusters are read-only, so there is no generated
/// `encode_*` to pair with — the codec writer is the encoder half here.
fn float_attr(v: f32) -> Vec<u8> {
    let mut buf = Vec::new();
    TlvWriter::new(&mut buf)
        .put_float(Tag::Anonymous, v)
        .unwrap();
    buf
}

/// Encode a single anonymous-tagged FLOAT64 — the *wrong* width for every
/// float attribute the crate generates today (all are `single`). Used only to
/// prove those decoders reject it; the control byte is `0x0B`.
fn double_attr(v: f64) -> Vec<u8> {
    let mut buf = Vec::new();
    TlvWriter::new(&mut buf)
        .put_double(Tag::Anonymous, v)
        .unwrap();
    buf
}

/// Assert two `f32`s are the same value **bit for bit**. Stricter than `==`
/// (which accepts `-0.0` for `0.0` and can never match a NaN), and it keeps
/// `clippy::float_cmp` quiet without an allow.
#[track_caller]
fn assert_f32_eq(actual: f32, expected: f32) {
    assert_eq!(
        actual.to_bits(),
        expected.to_bits(),
        "expected {expected}, got {actual}"
    );
}

#[test]
fn carbon_dioxide_concentration_full_attribute_set_decodes() {
    use co2::{LevelValueEnum, MeasurementMediumEnum, MeasurementUnitEnum};
    use gen::carbon_dioxide_concentration_measurement as co2;

    // Nullable float32 measurements: a value, and TLV null.
    assert_eq!(
        co2::decode_measured_value(&float_attr(415.5)).unwrap(),
        Nullable::Value(415.5)
    );
    assert_eq!(
        co2::decode_measured_value(&null_attr()).unwrap(),
        Nullable::Null
    );
    assert_eq!(
        co2::decode_min_measured_value(&float_attr(0.0)).unwrap(),
        Nullable::Value(0.0)
    );
    assert_eq!(
        co2::decode_max_measured_value(&float_attr(5000.0)).unwrap(),
        Nullable::Value(5000.0)
    );
    assert_eq!(
        co2::decode_peak_measured_value(&float_attr(1200.25)).unwrap(),
        Nullable::Value(1200.25)
    );
    assert_eq!(
        co2::decode_average_measured_value(&float_attr(-12.5)).unwrap(),
        Nullable::Value(-12.5)
    );
    // Non-nullable float32.
    assert_f32_eq(co2::decode_uncertainty(&float_attr(0.25)).unwrap(), 0.25);
    // elapsed-s windows are plain u32, not floats.
    assert_eq!(
        co2::decode_peak_measured_value_window(&uint_attr(3600)).unwrap(),
        3600
    );
    assert_eq!(
        co2::decode_average_measured_value_window(&uint_attr(300)).unwrap(),
        300
    );
    // The three enums.
    assert_eq!(
        co2::decode_measurement_unit(&uint_attr(0)).unwrap(),
        MeasurementUnitEnum::Ppm
    );
    assert_eq!(
        co2::decode_measurement_medium(&uint_attr(0)).unwrap(),
        MeasurementMediumEnum::Air
    );
    assert_eq!(
        co2::decode_level_value(&uint_attr(4)).unwrap(),
        LevelValueEnum::Critical
    );
    // Forward-compat: an unknown enum discriminant is preserved, not rejected.
    assert_eq!(
        co2::decode_level_value(&uint_attr(99)).unwrap(),
        LevelValueEnum::Unrecognized(99)
    );
}

#[test]
fn float_attribute_rejects_non_float_wire_types() {
    use gen::carbon_dioxide_concentration_measurement as co2;
    // A float attribute encoded as an integer (or any other type) is a type
    // mismatch, not a silent coercion — the pre-#112 emitter fallthrough would
    // have decoded these as integers.
    assert!(co2::decode_measured_value(&uint_attr(415)).is_err());
    assert!(co2::decode_uncertainty(&int_attr(-1)).is_err());
    assert!(co2::decode_uncertainty(&bool_attr(true)).is_err());
    // …and a null in a non-nullable float attribute is still an error.
    assert!(co2::decode_uncertainty(&null_attr()).is_err());
    // A FLOAT64 element in a `single` attribute is rejected too — the case
    // with real interop consequences, so it is pinned rather than assumed.
    // This is deliberate and matches chip: `TLVReader::Get(float&)`
    // (`src/lib/core/TLVReader.cpp`) accepts FLOAT32 only and errors on a
    // FLOAT64, while its `Get(double&)` accepts both. matter.js is lenient in
    // both directions; we follow the stricter reference here. Anyone widening
    // this arm is diverging from chip and must say so.
    assert_eq!(
        double_attr(415.5)[0],
        0x0B,
        "anonymous FLOAT64 control byte"
    );
    assert!(co2::decode_measured_value(&double_attr(415.5)).is_err());
    assert!(co2::decode_uncertainty(&double_attr(0.25)).is_err());
}

#[test]
fn float_wire_roundtrip_including_edge_values() {
    use gen::carbon_dioxide_concentration_measurement as co2;
    // encode (matter-codec) -> decode (generated) -> equal, across the edges of
    // the binary32 space. Compared by BITS: NaN != NaN and 0.0 == -0.0 under
    // value equality, either of which would make this test lie.
    for v in [
        0.0_f32,
        -0.0,
        1.0,
        -1.0,
        f32::MIN,
        f32::MAX,
        // Smallest positive *normal*, then the smallest subnormal — a distinct
        // encoding class (zero exponent field), and the one the uniform-bits
        // proptest is least likely to draw.
        f32::MIN_POSITIVE,
        f32::from_bits(1),
        -f32::from_bits(1),
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
    ] {
        match co2::decode_measured_value(&float_attr(v)).unwrap() {
            Nullable::Value(d) => assert_f32_eq(d, v),
            Nullable::Null => panic!("float {v} decoded as null"),
        }
    }
}

#[test]
fn every_concentration_cluster_decodes_its_measured_value() {
    // One assertion per generated module: the family was added as a batch
    // (#112) precisely so no member is left out, and this is the guard.
    macro_rules! assert_family_member {
        ($m:ident, $id:expr) => {{
            use gen::$m as m;
            assert_eq!(m::CLUSTER_ID, $id, concat!(stringify!($m), " cluster id"));
            assert_eq!(
                m::decode_measured_value(&float_attr(1.5)).unwrap(),
                Nullable::Value(1.5)
            );
            assert_eq!(
                m::decode_measured_value(&null_attr()).unwrap(),
                Nullable::Null
            );
            assert_f32_eq(m::decode_uncertainty(&float_attr(0.5)).unwrap(), 0.5);
        }};
    }
    assert_family_member!(carbon_monoxide_concentration_measurement, 0x040C);
    assert_family_member!(carbon_dioxide_concentration_measurement, 0x040D);
    assert_family_member!(nitrogen_dioxide_concentration_measurement, 0x0413);
    assert_family_member!(ozone_concentration_measurement, 0x0415);
    assert_family_member!(pm25_concentration_measurement, 0x042A);
    assert_family_member!(formaldehyde_concentration_measurement, 0x042B);
    assert_family_member!(pm1_concentration_measurement, 0x042C);
    assert_family_member!(pm10_concentration_measurement, 0x042D);
    assert_family_member!(
        total_volatile_organic_compounds_concentration_measurement,
        0x042E
    );
    assert_family_member!(radon_concentration_measurement, 0x042F);
}

// ---- Bridge support: BDBI (0x0039) + Switch events (Phase 0) ---------------
// BridgedDeviceBasicInformation reuses string/bool wire shapes already
// byte-parity-proven via BasicInformation (the two clusters share attribute
// ids per the Matter spec), so synthetic decode is the gate, per the A2.x
// convention above. Switch event payloads are hand-built TLV structures —
// the wire shape of EventDataIB's Data field.

/// Encode a single anonymous-tagged UTF-8 string (the wire shape of a
/// string attribute value).
fn str_attr(v: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    TlvWriter::new(&mut buf)
        .put_utf8(Tag::Anonymous, v)
        .unwrap();
    buf
}

#[test]
fn bridged_device_basic_information_ids_pinned() {
    use gen::bridged_device_basic_information as bdbi;
    assert_eq!(bdbi::CLUSTER_ID, 0x0039);
    // Same attribute ids as BasicInformation (0x0028), per the Matter spec.
    assert_eq!(bdbi::attribute_id::NODE_LABEL, 0x0005);
    assert_eq!(bdbi::attribute_id::REACHABLE, 0x0011);
    assert_eq!(bdbi::attribute_id::UNIQUE_ID, 0x0012);
}

#[test]
fn bridged_device_basic_information_decodes() {
    use gen::bridged_device_basic_information as bdbi;
    // NodeLabel / UniqueId: strings.
    assert_eq!(
        bdbi::decode_node_label(&str_attr("Kitchen sensor")).unwrap(),
        "Kitchen sensor"
    );
    assert_eq!(
        bdbi::decode_unique_id(&str_attr("00112233AABB")).unwrap(),
        "00112233AABB"
    );
    // Reachable: bool.
    assert!(bdbi::decode_reachable(&bool_attr(true)).unwrap());
    assert!(!bdbi::decode_reachable(&bool_attr(false)).unwrap());
    // A type mismatch is an error, never a default.
    assert!(bdbi::decode_node_label(&bool_attr(true)).is_err());
    assert!(bdbi::decode_reachable(&str_attr("x")).is_err());
}

#[test]
fn switch_event_ids_pinned() {
    use gen::switch::event_id as ev;
    assert_eq!(ev::SWITCH_LATCHED, 0x00);
    assert_eq!(ev::INITIAL_PRESS, 0x01);
    assert_eq!(ev::LONG_PRESS, 0x02);
    assert_eq!(ev::SHORT_RELEASE, 0x03);
    assert_eq!(ev::LONG_RELEASE, 0x04);
    assert_eq!(ev::MULTI_PRESS_ONGOING, 0x05);
    assert_eq!(ev::MULTI_PRESS_COMPLETE, 0x06);
}

#[test]
fn switch_multi_press_complete_event_round_trips() {
    // Hand-built MultiPressComplete payload: an anonymous structure with
    // PreviousPosition (ctx tag 0) and TotalNumberOfPressesCounted (ctx tag 1).
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.put_uint(Tag::Context(1), 2).unwrap();
        w.end_container().unwrap();
    }
    let ev = gen::switch::MultiPressCompleteEvent::decode(&buf).unwrap();
    assert_eq!(ev.previous_position, 1);
    assert_eq!(ev.total_number_of_presses_counted, 2);
}

#[test]
fn switch_multi_press_complete_event_missing_field_errors() {
    // TotalNumberOfPressesCounted (ctx tag 1) is mandatory — a payload
    // without it must be a decode error, not a silent zero.
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.end_container().unwrap();
    }
    assert!(gen::switch::MultiPressCompleteEvent::decode(&buf).is_err());
}
