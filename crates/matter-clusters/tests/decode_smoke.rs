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
    assert_eq!(
        epm::decode_accuracy(&uint_array_attr(&[])).unwrap(),
        Vec::<epm::MeasurementAccuracyStruct>::new()
    );
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
    // Subjects/Targets are fabric-sensitive, so `Option`-wrapped (M9-A3 §5.4);
    // our own fabric's entry carries them.
    assert_eq!(
        e.subjects,
        Some(Nullable::Value(vec![0x1122_3344_5566_7788u64]))
    );
    assert!(matches!(e.targets, Some(Nullable::Null)));
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

// ---- M9-A3 B1: fabric-sensitive fields withheld for other fabrics -----------
//
// Our reads are unfiltered (IsFabricFiltered=false). chip then returns every
// fabric's entries of a fabric-scoped list and, for another fabric's entry,
// encodes ONLY FabricIndex: the sensitive fields are written only when
// `includeSensitive` (connectedhomeip
// zzz_generated/app-common/clusters/AccessControl/Structs.ipp:225-251,
// IcdManagement/Structs.ipp:45-60). matter.js cannot produce this shape, so
// the bytes are hand-built to match chip.

/// A list attribute's wire value: an anonymous array of anonymous structs,
/// each written by one closure.
fn list_of(entries: &[&dyn Fn(&mut TlvWriter<'_>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_array(Tag::Anonymous).unwrap();
        for write_entry in entries {
            w.start_structure(Tag::Anonymous).unwrap();
            write_entry(&mut w);
            w.end_container().unwrap();
        }
        w.end_container().unwrap();
    }
    buf
}

/// One anonymous struct written by `write_fields` (a single entry's bytes).
fn struct_of(write_fields: &dyn Fn(&mut TlvWriter<'_>)) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        write_fields(&mut w);
        w.end_container().unwrap();
    }
    buf
}

/// Another fabric's entry as chip sends it: `FabricIndex` only.
fn other_fabric_entry(w: &mut TlvWriter<'_>) {
    w.put_uint(Tag::Context(254), 2).unwrap();
}

/// Our fabric's ACL entry: Administer / CASE / [node 0x1122], Targets null.
fn own_acl_entry(w: &mut TlvWriter<'_>) {
    w.put_uint(Tag::Context(1), 5).unwrap();
    w.put_uint(Tag::Context(2), 2).unwrap();
    w.start_array(Tag::Context(3)).unwrap();
    w.put_uint(Tag::Anonymous, 0x1122).unwrap();
    w.end_container().unwrap();
    w.put_null(Tag::Context(4)).unwrap();
    w.put_uint(Tag::Context(254), 1).unwrap();
}

#[test]
fn acl_list_with_another_fabrics_entry_decodes() {
    // The regression: before §5.4 one other-fabric entry failed the WHOLE
    // list with MissingField("Privilege").
    let acl = gen::access_control::decode_acl(&list_of(&[&own_acl_entry, &other_fabric_entry]))
        .expect("an unfiltered ACL read with a second fabric must decode");
    assert_eq!(acl.len(), 2);
}

#[test]
fn acl_other_fabric_entry_has_every_sensitive_field_none() {
    use gen::access_control::{AccessControlEntryAuthModeEnum, AccessControlEntryPrivilegeEnum};
    let acl =
        gen::access_control::decode_acl(&list_of(&[&own_acl_entry, &other_fabric_entry])).unwrap();
    let (own, other) = (&acl[0], &acl[1]);
    assert_eq!(
        own.privilege,
        Some(AccessControlEntryPrivilegeEnum::from_raw(5))
    );
    assert_eq!(
        own.auth_mode,
        Some(AccessControlEntryAuthModeEnum::from_raw(2))
    );
    assert_eq!(own.subjects, Some(Nullable::Value(vec![0x1122])));
    assert_eq!(own.targets, Some(Nullable::Null));
    assert_eq!(own.fabric_index, 1);
    assert_eq!(other.privilege, None);
    assert_eq!(other.auth_mode, None);
    assert_eq!(other.subjects, None);
    assert_eq!(other.targets, None);
    assert_eq!(other.fabric_index, 2);
}

#[test]
fn acl_entry_with_some_sensitive_fields_withheld_decodes_field_by_field() {
    // No 1.4 server does this, but nothing in the encoding forbids it: each
    // sensitive field is independently present or absent.
    let partial = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(1), 3).unwrap(); // Privilege: Operate
        w.put_null(Tag::Context(4)).unwrap(); // Targets: null (present)
        w.put_uint(Tag::Context(254), 2).unwrap();
    };
    let acl = gen::access_control::decode_acl(&list_of(&[&partial])).unwrap();
    assert_eq!(
        acl[0].privilege,
        Some(gen::access_control::AccessControlEntryPrivilegeEnum::from_raw(3))
    );
    assert_eq!(acl[0].auth_mode, None);
    assert_eq!(acl[0].subjects, None);
    // Present-but-null is distinct from withheld.
    assert_eq!(acl[0].targets, Some(Nullable::Null));
}

#[test]
fn extension_other_fabric_entry_decodes_and_refuses_reencode() {
    let own = |w: &mut TlvWriter<'_>| {
        w.put_bytes(Tag::Context(1), &[0x17, 0x18]).unwrap();
        w.put_uint(Tag::Context(254), 1).unwrap();
    };
    let ext =
        gen::access_control::decode_extension(&list_of(&[&own, &other_fabric_entry])).unwrap();
    assert_eq!(ext[0].data, Some(vec![0x17, 0x18]));
    assert_eq!(ext[1].data, None);
    assert_eq!(ext[1].fabric_index, 2);
    // Read-modify-write of the unfiltered list must not re-home the other
    // fabric's entry onto ours with its data missing.
    assert!(matches!(
        ext[1].encode(),
        Err(matter_clusters::error::ClusterError::MissingField("Data"))
    ));
    // Our own entry still encodes, byte-identical to what was read.
    assert_eq!(ext[0].encode().unwrap(), struct_of(&own));
}

#[test]
fn arl_other_fabric_entry_has_every_sensitive_field_none() {
    let own = |w: &mut TlvWriter<'_>| {
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.put_uint(Tag::Context(1), 0x0006).unwrap();
        w.start_array(Tag::Context(2)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 0).unwrap();
        w.put_uint(Tag::Context(1), 0).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(254), 1).unwrap();
    };
    let arl = gen::access_control::decode_arl(&list_of(&[&own, &other_fabric_entry])).unwrap();
    assert_eq!(arl[0].endpoint, Some(1));
    assert_eq!(arl[0].cluster, Some(0x0006));
    assert_eq!(arl[0].restrictions.as_ref().map(Vec::len), Some(1));
    assert_eq!(arl[1].endpoint, None);
    assert_eq!(arl[1].cluster, None);
    assert_eq!(arl[1].restrictions, None);
    assert_eq!(arl[1].fabric_index, 2);
}

/// Our fabric's ICD registration: `CheckInNodeId` 0x1122, `MonitoredSubject`
/// 0x3344, `ClientType` 1 (Ephemeral).
fn own_icd_entry(w: &mut TlvWriter<'_>) {
    w.put_uint(Tag::Context(1), 0x1122).unwrap();
    w.put_uint(Tag::Context(2), 0x3344).unwrap();
    w.put_uint(Tag::Context(4), 1).unwrap();
    w.put_uint(Tag::Context(254), 1).unwrap();
}

#[test]
fn icd_registered_clients_other_fabric_entry_has_every_sensitive_field_none() {
    let clients = gen::icd_management::decode_registered_clients(&list_of(&[
        &own_icd_entry,
        &other_fabric_entry,
    ]))
    .expect("an unfiltered RegisteredClients read with a second fabric must decode");
    assert_eq!(clients[0].check_in_node_id, Some(0x1122));
    assert_eq!(clients[0].monitored_subject, Some(0x3344));
    assert_eq!(
        clients[0].client_type,
        Some(gen::icd_management::ClientTypeEnum::from_raw(1))
    );
    assert_eq!(clients[1].check_in_node_id, None);
    assert_eq!(clients[1].monitored_subject, None);
    assert_eq!(clients[1].client_type, None);
    assert_eq!(clients[1].fabric_index, 2);
}

#[test]
fn icd_monitoring_registration_refuses_each_missing_sensitive_field() {
    use gen::icd_management::MonitoringRegistrationStruct;
    use matter_clusters::error::ClusterError;
    let full = MonitoringRegistrationStruct::decode(&struct_of(&own_icd_entry)).unwrap();
    assert_eq!(full.encode().unwrap(), struct_of(&own_icd_entry));

    let mut e = full.clone();
    e.check_in_node_id = None;
    assert!(matches!(
        e.encode(),
        Err(ClusterError::MissingField("CheckInNodeId"))
    ));

    let mut e = full.clone();
    e.monitored_subject = None;
    assert!(matches!(
        e.encode(),
        Err(ClusterError::MissingField("MonitoredSubject"))
    ));

    let mut e = full;
    e.client_type = None;
    assert!(matches!(
        e.encode(),
        Err(ClusterError::MissingField("ClientType"))
    ));
}

// ---- M9-A3 B1: events, scalar-field shapes ----------------------------------
//
// Each event payload is an anonymous structure of context-tagged fields (the
// same wire shape as a command response), decoded by the generated
// `<Name>Event::decode`. Field tags and types follow the 1.4.2 event tables.

#[test]
fn basic_information_event_ids_pinned() {
    use gen::basic_information::event_id as ev;
    assert_eq!(ev::START_UP, 0x00);
    assert_eq!(ev::SHUT_DOWN, 0x01);
    assert_eq!(ev::LEAVE, 0x02);
    assert_eq!(ev::REACHABLE_CHANGED, 0x03);
}

#[test]
fn basic_information_events_decode() {
    use gen::basic_information::{LeaveEvent, ReachableChangedEvent, StartUpEvent};
    let e = StartUpEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 0x0102_0304).unwrap();
    }))
    .unwrap();
    assert_eq!(e.software_version, 0x0102_0304);
    let e = LeaveEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 3).unwrap();
    }))
    .unwrap();
    assert_eq!(e.fabric_index, 3);
    let e = ReachableChangedEvent::decode(&struct_of(&|w| {
        w.put_bool(Tag::Context(0), false).unwrap();
    }))
    .unwrap();
    assert!(!e.reachable_new_value);
    // A mandatory field missing is an error, never a default.
    assert!(StartUpEvent::decode(&struct_of(&|_| {})).is_err());
}

#[test]
fn event_payload_with_an_unknown_future_field_still_decodes() {
    // A newer-revision device may add fields; the decoder skips unknown tags.
    let e = gen::basic_information::StartUpEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 5).unwrap();
        w.put_utf8(Tag::Context(9), "future").unwrap();
        w.start_structure(Tag::Context(10)).unwrap();
        w.put_bool(Tag::Context(0), true).unwrap();
        w.end_container().unwrap();
    }))
    .unwrap();
    assert_eq!(e.software_version, 5);
}

#[test]
fn boolean_state_state_change_event_decodes() {
    use gen::boolean_state::{event_id, StateChangeEvent};
    assert_eq!(event_id::STATE_CHANGE, 0x00);
    let e = StateChangeEvent::decode(&struct_of(&|w| {
        w.put_bool(Tag::Context(0), true).unwrap();
    }))
    .unwrap();
    assert!(e.state_value);
}

#[test]
fn occupancy_changed_event_decodes() {
    use gen::occupancy_sensing::{event_id, OccupancyBitmap, OccupancyChangedEvent};
    assert_eq!(event_id::OCCUPANCY_CHANGED, 0x00);
    let e = OccupancyChangedEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap();
    }))
    .unwrap();
    assert_eq!(e.occupancy, OccupancyBitmap::from_bits_retain(1));
}

#[test]
fn pump_configuration_event_ids_pinned() {
    // All 17 pump events are fieldless: only their ids are generated.
    use gen::pump_configuration_and_control::event_id as ev;
    assert_eq!(ev::SUPPLY_VOLTAGE_LOW, 0x00);
    assert_eq!(ev::DRY_RUNNING, 0x05);
    assert_eq!(ev::PUMP_BLOCKED, 0x09);
    assert_eq!(ev::TURBINE_OPERATION, 0x10);
}

#[test]
fn time_synchronization_events_decode() {
    use gen::time_synchronization::{event_id as ev, DstStatusEvent, TimeZoneStatusEvent};
    assert_eq!(ev::DST_TABLE_EMPTY, 0x00);
    assert_eq!(ev::DST_STATUS, 0x01);
    assert_eq!(ev::TIME_ZONE_STATUS, 0x02);
    assert_eq!(ev::TIME_FAILURE, 0x03);
    assert_eq!(ev::MISSING_TRUSTED_TIME_SOURCE, 0x04);
    let e = DstStatusEvent::decode(&struct_of(&|w| {
        w.put_bool(Tag::Context(0), true).unwrap();
    }))
    .unwrap();
    assert!(e.dst_offset_active);
    // Offset is int32 (negative west of UTC); Name is optional.
    let e = TimeZoneStatusEvent::decode(&struct_of(&|w| {
        w.put_int(Tag::Context(0), -18_000).unwrap();
    }))
    .unwrap();
    assert_eq!(e.offset, -18_000);
    assert_eq!(e.name, None);
    let e = TimeZoneStatusEvent::decode(&struct_of(&|w| {
        w.put_int(Tag::Context(0), 3600).unwrap();
        w.put_utf8(Tag::Context(1), "Europe/Paris").unwrap();
    }))
    .unwrap();
    assert_eq!(e.name.as_deref(), Some("Europe/Paris"));
}

#[test]
fn ota_requestor_events_decode() {
    use gen::ota_software_update_requestor::{
        event_id as ev, ChangeReasonEnum, DownloadErrorEvent, StateTransitionEvent,
        UpdateStateEnum, VersionAppliedEvent,
    };
    assert_eq!(ev::STATE_TRANSITION, 0x00);
    assert_eq!(ev::VERSION_APPLIED, 0x01);
    assert_eq!(ev::DOWNLOAD_ERROR, 0x02);
    let e = StateTransitionEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap(); // Idle
        w.put_uint(Tag::Context(1), 4).unwrap(); // Downloading
        w.put_uint(Tag::Context(2), 1).unwrap(); // Success
        w.put_null(Tag::Context(3)).unwrap();
    }))
    .unwrap();
    assert_eq!(e.previous_state, UpdateStateEnum::from_raw(1));
    assert_eq!(e.new_state, UpdateStateEnum::from_raw(4));
    assert_eq!(e.reason, ChangeReasonEnum::from_raw(1));
    assert_eq!(e.target_software_version, Nullable::Null);
    let e = VersionAppliedEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 2).unwrap();
        w.put_uint(Tag::Context(1), 0x8000).unwrap();
    }))
    .unwrap();
    assert_eq!((e.software_version, e.product_id), (2, 0x8000));
    let e = DownloadErrorEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 2).unwrap();
        w.put_uint(Tag::Context(1), 1_048_576).unwrap();
        w.put_uint(Tag::Context(2), 42).unwrap();
        w.put_int(Tag::Context(3), -7).unwrap();
    }))
    .unwrap();
    assert_eq!(e.bytes_downloaded, 1_048_576);
    assert_eq!(e.progress_percent, Nullable::Value(42));
    assert_eq!(e.platform_code, Nullable::Value(-7));
}

// ---- M9-A3 B1: events, list-of-enum shapes ----------------------------------

#[test]
fn general_diagnostics_events_decode() {
    use gen::general_diagnostics::{
        event_id as ev, BootReasonEnum, BootReasonEvent, HardwareFaultChangeEvent,
        HardwareFaultEnum, NetworkFaultChangeEvent, NetworkFaultEnum, RadioFaultChangeEvent,
        RadioFaultEnum,
    };
    assert_eq!(ev::HARDWARE_FAULT_CHANGE, 0x00);
    assert_eq!(ev::RADIO_FAULT_CHANGE, 0x01);
    assert_eq!(ev::NETWORK_FAULT_CHANGE, 0x02);
    assert_eq!(ev::BOOT_REASON, 0x03);
    // HardwareFault and NetworkFault use the lists chip's all-clusters
    // fault injection sends (`OnGeneralFaultEventHandler`): hardware
    // previous [Radio, PowerSource] → current [Radio, Sensor, PowerSource,
    // UserInterfaceFault] = [1, 5] → [1, 2, 5, 8]. RadioFault adds an empty list.
    let faults = |current: &[u64], previous: &[u64]| {
        let (current, previous) = (current.to_vec(), previous.to_vec());
        struct_of(&move |w| {
            w.start_array(Tag::Context(0)).unwrap();
            for v in &current {
                w.put_uint(Tag::Anonymous, *v).unwrap();
            }
            w.end_container().unwrap();
            w.start_array(Tag::Context(1)).unwrap();
            for v in &previous {
                w.put_uint(Tag::Anonymous, *v).unwrap();
            }
            w.end_container().unwrap();
        })
    };
    let e = HardwareFaultChangeEvent::decode(&faults(&[1, 2, 5, 8], &[1, 5])).unwrap();
    assert_eq!(
        e.current,
        [1, 2, 5, 8].map(HardwareFaultEnum::from_raw).to_vec()
    );
    assert_eq!(e.previous, [1, 5].map(HardwareFaultEnum::from_raw).to_vec());
    let e = RadioFaultChangeEvent::decode(&faults(&[1, 3], &[])).unwrap();
    assert_eq!(e.current, [1, 3].map(RadioFaultEnum::from_raw).to_vec());
    assert_eq!(e.previous, []);
    let e = NetworkFaultChangeEvent::decode(&faults(&[1, 2, 3], &[1, 2])).unwrap();
    assert_eq!(
        e.current,
        [1, 2, 3].map(NetworkFaultEnum::from_raw).to_vec()
    );
    assert_eq!(e.previous, [1, 2].map(NetworkFaultEnum::from_raw).to_vec());
    let e = BootReasonEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap(); // PowerOnReboot
    }))
    .unwrap();
    assert_eq!(e.boot_reason, BootReasonEnum::from_raw(1));
}

#[test]
fn power_source_fault_events_decode() {
    use gen::power_source::{
        event_id as ev, BatChargeFaultChangeEvent, BatChargeFaultEnum, BatFaultChangeEvent,
        BatFaultEnum, WiredFaultChangeEvent, WiredFaultEnum,
    };
    assert_eq!(ev::WIRED_FAULT_CHANGE, 0x00);
    assert_eq!(ev::BAT_FAULT_CHANGE, 0x01);
    assert_eq!(ev::BAT_CHARGE_FAULT_CHANGE, 0x02);
    let pair = |current: u64, previous: Option<u64>| {
        struct_of(&move |w| {
            w.start_array(Tag::Context(0)).unwrap();
            w.put_uint(Tag::Anonymous, current).unwrap();
            w.end_container().unwrap();
            w.start_array(Tag::Context(1)).unwrap();
            if let Some(p) = previous {
                w.put_uint(Tag::Anonymous, p).unwrap();
            }
            w.end_container().unwrap();
        })
    };
    let e = WiredFaultChangeEvent::decode(&pair(1, None)).unwrap();
    assert_eq!(e.current, vec![WiredFaultEnum::from_raw(1)]);
    assert_eq!(e.previous, []);
    let e = BatFaultChangeEvent::decode(&pair(2, Some(1))).unwrap();
    assert_eq!(e.current, vec![BatFaultEnum::from_raw(2)]);
    assert_eq!(e.previous, vec![BatFaultEnum::from_raw(1)]);
    let e = BatChargeFaultChangeEvent::decode(&pair(3, None)).unwrap();
    assert_eq!(e.current, vec![BatChargeFaultEnum::from_raw(3)]);
}

#[test]
fn list_of_enum_event_missing_list_is_an_error() {
    use matter_clusters::error::ClusterError;
    // Both lists are mandatory in 1.4.2: a missing list is MissingField,
    // never an empty-list default (an empty list is a different statement).
    let only_current = struct_of(&|w| {
        w.start_array(Tag::Context(0)).unwrap();
        w.put_uint(Tag::Anonymous, 1).unwrap();
        w.end_container().unwrap();
    });
    assert!(matches!(
        gen::general_diagnostics::HardwareFaultChangeEvent::decode(&only_current),
        Err(ClusterError::MissingField("Previous"))
    ));
    assert!(matches!(
        gen::power_source::BatFaultChangeEvent::decode(&only_current),
        Err(ClusterError::MissingField("Previous"))
    ));
    assert!(matches!(
        gen::general_diagnostics::BootReasonEvent::decode(&struct_of(&|_| {})),
        Err(ClusterError::MissingField("BootReason"))
    ));
}

// ---- M9-A3 B1: events, composite-field shapes -------------------------------

#[test]
fn access_control_event_ids_pinned() {
    use gen::access_control::event_id as ev;
    assert_eq!(ev::ACCESS_CONTROL_ENTRY_CHANGED, 0x00);
    assert_eq!(ev::ACCESS_CONTROL_EXTENSION_CHANGED, 0x01);
    assert_eq!(ev::FABRIC_RESTRICTION_REVIEW_UPDATE, 0x02);
}

#[test]
fn access_control_entry_changed_event_decodes_with_unwrapped_fields() {
    use gen::access_control::{
        AccessControlEntryChangedEvent, AccessControlEntryPrivilegeEnum, ChangeTypeEnum,
    };
    // chip (access-control-cluster.cpp OnEntryChanged): a CASE admin added an
    // entry — AdminNodeID set, AdminPasscodeID null, LatestValue the full
    // entry (our own fabric's event: chip encodes it with includeSensitive).
    let bytes = struct_of(&|w| {
        w.put_uint(Tag::Context(1), 0x0000_0000_0001_B669).unwrap();
        w.put_null(Tag::Context(2)).unwrap();
        w.put_uint(Tag::Context(3), 1).unwrap(); // Added
        w.start_structure(Tag::Context(4)).unwrap();
        own_acl_entry(w);
        w.end_container().unwrap();
        w.put_uint(Tag::Context(254), 1).unwrap();
    });
    let e = AccessControlEntryChangedEvent::decode(&bytes).unwrap();
    // §5.4 "events are exempt": the event's own fields keep the model's
    // optionality. These bindings fail to compile if a field became Option.
    let admin: Nullable<u64> = e.admin_node_id;
    let passcode: Nullable<u16> = e.admin_passcode_id;
    let change: ChangeTypeEnum = e.change_type;
    let fabric: u8 = e.fabric_index;
    assert_eq!(admin, Nullable::Value(0x1_B669));
    assert_eq!(passcode, Nullable::Null);
    assert_eq!(change, ChangeTypeEnum::from_raw(1));
    assert_eq!(fabric, 1);
    // LatestValue is the shared datatype struct, so its sensitive fields are
    // Option — and present, because chip sends our own fabric's event in full.
    match e.latest_value {
        Nullable::Value(entry) => {
            assert_eq!(
                entry.privilege,
                Some(AccessControlEntryPrivilegeEnum::from_raw(5))
            );
            assert_eq!(entry.subjects, Some(Nullable::Value(vec![0x1122])));
        }
        Nullable::Null => panic!("LatestValue should be present"),
    }
}

#[test]
fn access_control_extension_changed_and_review_events_decode() {
    use gen::access_control::{
        AccessControlExtensionChangedEvent, ChangeTypeEnum, FabricRestrictionReviewUpdateEvent,
    };
    let e = AccessControlExtensionChangedEvent::decode(&struct_of(&|w| {
        w.put_null(Tag::Context(1)).unwrap();
        w.put_uint(Tag::Context(2), 0).unwrap(); // a PASE admin
        w.put_uint(Tag::Context(3), 2).unwrap(); // Removed
        w.put_null(Tag::Context(4)).unwrap();
        w.put_uint(Tag::Context(254), 1).unwrap();
    }))
    .unwrap();
    assert_eq!(e.admin_node_id, Nullable::Null);
    assert_eq!(e.admin_passcode_id, Nullable::Value(0));
    assert_eq!(e.change_type, ChangeTypeEnum::from_raw(2));
    assert_eq!(e.latest_value, Nullable::Null);
    let e = FabricRestrictionReviewUpdateEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 77).unwrap();
        w.put_uint(Tag::Context(254), 1).unwrap();
    }))
    .unwrap();
    assert_eq!(e.token, 77);
    assert_eq!(e.instruction, None);
    assert_eq!(e.arl_request_flow_url, None);
}

#[test]
fn electrical_energy_measured_events_decode() {
    use gen::electrical_energy_measurement::{
        event_id as ev, CumulativeEnergyMeasuredEvent, PeriodicEnergyMeasuredEvent,
    };
    assert_eq!(ev::CUMULATIVE_ENERGY_MEASURED, 0x00);
    assert_eq!(ev::PERIODIC_ENERGY_MEASURED, 0x01);
    // An importing load (chip's FakeReadings 1 kW trigger): EnergyImported
    // only; EnergyExported absent (both are optional, feature-gated).
    let e = CumulativeEnergyMeasuredEvent::decode(&struct_of(&|w| {
        w.start_structure(Tag::Context(0)).unwrap();
        w.put_int(Tag::Context(0), 555).unwrap(); // Energy (mWh)
        w.put_uint(Tag::Context(1), 1_000).unwrap(); // StartTimestamp
        w.put_uint(Tag::Context(2), 1_002).unwrap(); // EndTimestamp
        w.end_container().unwrap();
    }))
    .unwrap();
    let imported = e.energy_imported.expect("EnergyImported present");
    assert_eq!(imported.energy, 555);
    assert_eq!(imported.start_timestamp, Some(1_000));
    assert_eq!(e.energy_exported, None);
    let e = PeriodicEnergyMeasuredEvent::decode(&struct_of(&|w| {
        w.start_structure(Tag::Context(1)).unwrap();
        w.put_int(Tag::Context(0), 2_500).unwrap();
        w.put_uint(Tag::Context(3), 9_000).unwrap(); // StartSystime
        w.end_container().unwrap();
    }))
    .unwrap();
    assert_eq!(e.energy_imported, None);
    assert_eq!(
        e.energy_exported.map(|x| x.start_systime),
        Some(Some(9_000))
    );
}

#[test]
fn electrical_power_measurement_period_ranges_event_decodes() {
    use gen::electrical_power_measurement::{
        event_id, MeasurementPeriodRangesEvent, MeasurementTypeEnum,
    };
    assert_eq!(event_id::MEASUREMENT_PERIOD_RANGES, 0x00);
    let e = MeasurementPeriodRangesEvent::decode(&struct_of(&|w| {
        w.start_array(Tag::Context(0)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 1).unwrap(); // Voltage
        w.put_int(Tag::Context(1), 229_000).unwrap();
        w.put_int(Tag::Context(2), 231_000).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
    }))
    .unwrap();
    assert_eq!(e.ranges.len(), 1);
    assert_eq!(
        e.ranges[0].measurement_type,
        MeasurementTypeEnum::from_raw(1)
    );
    assert_eq!((e.ranges[0].min, e.ranges[0].max), (229_000, 231_000));
}

#[test]
fn door_lock_event_ids_pinned() {
    use gen::door_lock::event_id as ev;
    assert_eq!(ev::DOOR_LOCK_ALARM, 0x00);
    assert_eq!(ev::DOOR_STATE_CHANGE, 0x01);
    assert_eq!(ev::LOCK_OPERATION, 0x02);
    assert_eq!(ev::LOCK_OPERATION_ERROR, 0x03);
    assert_eq!(ev::LOCK_USER_CHANGE, 0x04);
}

#[test]
fn door_lock_events_decode() {
    use gen::door_lock::{
        AlarmCodeEnum, DataOperationTypeEnum, DoorLockAlarmEvent, DoorStateChangeEvent,
        DoorStateEnum, LockDataTypeEnum, LockOperationErrorEvent, LockOperationEvent,
        LockOperationTypeEnum, LockUserChangeEvent, OperationErrorEnum, OperationSourceEnum,
    };
    let e = DoorLockAlarmEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 0).unwrap(); // LockJammed
    }))
    .unwrap();
    assert_eq!(e.alarm_code, AlarmCodeEnum::from_raw(0));
    let e = DoorStateChangeEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap(); // DoorClosed
    }))
    .unwrap();
    assert_eq!(e.door_state, DoorStateEnum::from_raw(1));
    // A remote unlock with no PIN (lock-app): UserIndex null, Credentials null.
    let e = LockOperationEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap(); // Unlock
        w.put_uint(Tag::Context(1), 7).unwrap(); // Remote
        w.put_null(Tag::Context(2)).unwrap();
        w.put_uint(Tag::Context(3), 1).unwrap();
        w.put_uint(Tag::Context(4), 0x1_B669).unwrap();
        w.put_null(Tag::Context(5)).unwrap();
    }))
    .unwrap();
    assert_eq!(e.lock_operation_type, LockOperationTypeEnum::from_raw(1));
    assert_eq!(e.operation_source, OperationSourceEnum::from_raw(7));
    assert_eq!(e.user_index, Nullable::Null);
    assert_eq!(e.fabric_index, Nullable::Value(1));
    assert_eq!(e.source_node, Nullable::Value(0x1_B669));
    assert_eq!(e.credentials, Some(Nullable::Null));
    // A failed operation with a credential list; Credentials may also be absent.
    let e = LockOperationErrorEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.put_uint(Tag::Context(1), 7).unwrap();
        w.put_uint(Tag::Context(2), 1).unwrap(); // InvalidCredential
        w.put_uint(Tag::Context(3), 2).unwrap();
        w.put_null(Tag::Context(4)).unwrap();
        w.put_null(Tag::Context(5)).unwrap();
        w.start_array(Tag::Context(6)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 1).unwrap(); // Pin
        w.put_uint(Tag::Context(1), 3).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
    }))
    .unwrap();
    assert_eq!(e.operation_error, OperationErrorEnum::from_raw(1));
    assert_eq!(e.user_index, Nullable::Value(2));
    match e.credentials {
        Some(Nullable::Value(creds)) => assert_eq!(creds[0].credential_index, 3),
        other => panic!("expected one credential, got {other:?}"),
    }
    let e = LockUserChangeEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 2).unwrap(); // UserIndex
        w.put_uint(Tag::Context(1), 0).unwrap(); // Add
        w.put_uint(Tag::Context(2), 7).unwrap(); // Remote
        w.put_uint(Tag::Context(3), 2).unwrap();
        w.put_uint(Tag::Context(4), 1).unwrap();
        w.put_uint(Tag::Context(5), 0x1_B669).unwrap();
        w.put_uint(Tag::Context(6), 2).unwrap();
    }))
    .unwrap();
    assert_eq!(e.lock_data_type, LockDataTypeEnum::from_raw(2));
    assert_eq!(e.data_operation_type, DataOperationTypeEnum::from_raw(0));
    assert_eq!(e.data_index, Nullable::Value(2));
}

// ---- M9-A3 B1: events, derived cluster (BridgedDeviceBasicInformation) ------

#[test]
fn bridged_device_basic_information_event_ids_pinned() {
    use gen::bridged_device_basic_information::event_id as ev;
    assert_eq!(ev::START_UP, 0x00);
    assert_eq!(ev::SHUT_DOWN, 0x01);
    assert_eq!(ev::LEAVE, 0x02);
    assert_eq!(ev::REACHABLE_CHANGED, 0x03);
    assert_eq!(ev::ACTIVE_CHANGED, 0x80);
}

#[test]
fn bridged_device_basic_information_events_decode() {
    // StartUp and ReachableChanged inherit their fields from
    // BasicInformation: the derived model elements have no children of their
    // own, so the dump must read the resolved `members`.
    use gen::bridged_device_basic_information::{
        ActiveChangedEvent, ReachableChangedEvent, StartUpEvent,
    };
    let e = StartUpEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 9).unwrap();
    }))
    .unwrap();
    assert_eq!(e.software_version, 9);
    let e = ReachableChangedEvent::decode(&struct_of(&|w| {
        w.put_bool(Tag::Context(0), true).unwrap();
    }))
    .unwrap();
    assert!(e.reachable_new_value);
    // Mandatory in 1.4.2 (BridgedDeviceBasicInformationCluster.xml event 0x03).
    assert!(matches!(
        ReachableChangedEvent::decode(&struct_of(&|_| {})),
        Err(matter_clusters::error::ClusterError::MissingField(
            "ReachableNewValue"
        ))
    ));
    assert!(matches!(
        StartUpEvent::decode(&struct_of(&|_| {})),
        Err(matter_clusters::error::ClusterError::MissingField(
            "SoftwareVersion"
        ))
    ));
    let e = ActiveChangedEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 30_000).unwrap();
    }))
    .unwrap();
    assert_eq!(e.promised_active_duration, 30_000);
}

// ---- M9-A3 B2: ModeBase-derived clusters ------------------------------------
//
// Every ModeBase derivative has one wire shape (1.4.2 ModeBase.xml):
// SupportedModes is a list of ModeOptionStruct { Label(0) string, Mode(1)
// uint8, ModeTags(2) list<ModeTagStruct { MfgCode(0) vendor-id, optional;
// Value(1) enum16 }> }; ChangeToMode is { NewMode(0) uint8 } and its response
// { Status(0) enum8, StatusText(1) string }. The field set is inherited from
// the id-less ModeBase: before the B2 `members` fix ModeOptionStruct came out
// with no fields at all.

/// `SupportedModes` as chip encodes it (`ModeBase/Structs.ipp` writes `MfgCode`
/// only when present): mode 0 "Normal" tagged [`Auto` (0x0000), the cluster's
/// first derived tag]; mode 7 "Vendor" tagged [mfg 0xFFF1 / 0x8001, a
/// manufacturer-specific value no codegen knows].
fn supported_modes(derived_tag: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_array(Tag::Anonymous).unwrap();
        for (label, mode, tags) in [
            ("Normal", 0u64, vec![(None, 0x0000u64), (None, derived_tag)]),
            ("Vendor", 7, vec![(Some(0xFFF1u64), 0x8001)]),
        ] {
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_utf8(Tag::Context(0), label).unwrap();
            w.put_uint(Tag::Context(1), mode).unwrap();
            w.start_array(Tag::Context(2)).unwrap();
            for (mfg, value) in tags {
                w.start_structure(Tag::Anonymous).unwrap();
                if let Some(mfg) = mfg {
                    w.put_uint(Tag::Context(0), mfg).unwrap();
                }
                w.put_uint(Tag::Context(1), value).unwrap();
                w.end_container().unwrap();
            }
            w.end_container().unwrap();
            w.end_container().unwrap();
        }
        w.end_container().unwrap();
    }
    buf
}

/// One test per `ModeBase` derivative: `SupportedModes` (its most complex
/// attribute), `CurrentMode`, the `ChangeToMode` request bytes, and the
/// response with and without `StatusText` (spec §3.1: chip never sends it).
macro_rules! mode_base_cluster_decodes {
    ($test:ident, $m:ident, $first_derived_tag:literal, $derived_variant:ident) => {
        #[test]
        fn $test() {
            use gen::$m::{ChangeToModeResponse, ModeChangeStatus, ModeTag};
            use matter_clusters::error::ClusterError;
            let modes =
                gen::$m::decode_supported_modes(&supported_modes($first_derived_tag)).unwrap();
            assert_eq!(modes.len(), 2);
            assert_eq!((modes[0].label.as_str(), modes[0].mode), ("Normal", 0));
            let tags: Vec<_> = modes[0]
                .mode_tags
                .iter()
                .map(|t| (t.mfg_code, t.value))
                .collect();
            assert_eq!(
                tags,
                [(None, ModeTag::Auto), (None, ModeTag::$derived_variant)]
            );
            assert_eq!((modes[1].label.as_str(), modes[1].mode), ("Vendor", 7));
            assert_eq!(modes[1].mode_tags[0].mfg_code, Some(0xFFF1));
            assert_eq!(modes[1].mode_tags[0].value, ModeTag::Unknown(0x8001));
            assert_eq!(gen::$m::decode_current_mode(&uint_attr(7)).unwrap(), 7);

            let new_mode_7 = struct_of(&|w| w.put_uint(Tag::Context(0), 7).unwrap());
            assert_eq!(gen::$m::encode_change_to_mode(7), new_mode_7);

            // What chip sends for an unsupported mode: Status only.
            let r = ChangeToModeResponse::decode(&struct_of(&|w| {
                w.put_uint(Tag::Context(0), 1).unwrap();
            }))
            .unwrap();
            assert_eq!(
                (r.status, r.status_text),
                (ModeChangeStatus::UnsupportedMode, None)
            );
            let r = ChangeToModeResponse::decode(&struct_of(&|w| {
                w.put_uint(Tag::Context(0), 0).unwrap();
                w.put_utf8(Tag::Context(1), "done").unwrap();
            }))
            .unwrap();
            assert_eq!(r.status, ModeChangeStatus::Success);
            assert_eq!(r.status_text.as_deref(), Some("done"));
            // An empty StatusText (which the spec allows) is present, not
            // absent; a manufacturer status (0x80..=0xBF) is Unknown, not an error.
            let r = ChangeToModeResponse::decode(&struct_of(&|w| {
                w.put_uint(Tag::Context(0), 0x80).unwrap();
                w.put_utf8(Tag::Context(1), "").unwrap();
            }))
            .unwrap();
            assert_eq!(r.status, ModeChangeStatus::Unknown(0x80));
            assert_eq!(r.status_text.as_deref(), Some(""));
            // Status itself stays mandatory.
            assert!(matches!(
                ChangeToModeResponse::decode(&struct_of(&|_| {})),
                Err(ClusterError::MissingField("Status"))
            ));
        }
    };
}

mode_base_cluster_decodes!(oven_mode_decodes, oven_mode, 0x4000, Bake);
mode_base_cluster_decodes!(
    laundry_washer_mode_decodes,
    laundry_washer_mode,
    0x4000,
    Normal
);
mode_base_cluster_decodes!(
    refrigerator_and_tcc_mode_decodes,
    refrigerator_and_temperature_controlled_cabinet_mode,
    0x4000,
    RapidCool
);
mode_base_cluster_decodes!(rvc_run_mode_decodes, rvc_run_mode, 0x4000, Idle);
mode_base_cluster_decodes!(rvc_clean_mode_decodes, rvc_clean_mode, 0x4000, DeepClean);
mode_base_cluster_decodes!(dishwasher_mode_decodes, dishwasher_mode, 0x4000, Normal);

#[test]
fn rvc_mode_change_status_keeps_base_and_derived_values() {
    // The derived ModeChangeStatus adds values to the base's 0..=3; on
    // `.children` the base values were missing, so a plain `Success` decoded
    // as Unknown(0).
    use gen::{rvc_clean_mode, rvc_run_mode};
    assert_eq!(
        rvc_run_mode::ModeChangeStatus::from_raw(0),
        rvc_run_mode::ModeChangeStatus::Success
    );
    assert_eq!(
        rvc_run_mode::ModeChangeStatus::from_raw(0x41),
        rvc_run_mode::ModeChangeStatus::Stuck
    );
    assert_eq!(
        rvc_run_mode::ModeChangeStatus::from_raw(0x48),
        rvc_run_mode::ModeChangeStatus::BatteryLow
    );
    assert_eq!(
        rvc_clean_mode::ModeChangeStatus::from_raw(0x40),
        rvc_clean_mode::ModeChangeStatus::CleaningInProgress
    );
    assert_eq!(
        rvc_clean_mode::ModeChangeStatus::from_raw(3),
        rvc_clean_mode::ModeChangeStatus::InvalidInMode
    );
}

#[test]
fn mode_option_missing_mode_tags_is_an_error() {
    use matter_clusters::error::ClusterError;
    // ModeTags is mandatory (an empty list is valid; an absent one is not).
    let bytes = list_of(&[&|w| {
        w.put_utf8(Tag::Context(0), "x").unwrap();
        w.put_uint(Tag::Context(1), 0).unwrap();
    }]);
    assert!(matches!(
        gen::dishwasher_mode::decode_supported_modes(&bytes),
        Err(ClusterError::MissingField("ModeTags"))
    ));
}

mode_base_cluster_decodes!(energy_evse_mode_decodes, energy_evse_mode, 0x4000, Manual);
mode_base_cluster_decodes!(water_heater_mode_decodes, water_heater_mode, 0x4000, Off);
mode_base_cluster_decodes!(
    device_energy_management_mode_decodes,
    device_energy_management_mode,
    0x4000,
    NoOptimization
);

#[test]
fn microwave_oven_mode_decodes_without_commands() {
    // MicrowaveOvenMode disallows ChangeToMode (1.4.2 MicrowaveOvenMode.xml:
    // <disallowConform/>), so only its attributes are generated; there is no
    // encode_change_to_mode and command_id is empty.
    use gen::microwave_oven_mode::{decode_current_mode, decode_supported_modes, ModeTag};
    let modes = decode_supported_modes(&supported_modes(0x4001)).unwrap();
    assert_eq!(modes[0].mode_tags[1].value, ModeTag::Defrost);
    assert_eq!(modes[1].mode_tags[0].value, ModeTag::Unknown(0x8001));
    assert_eq!(decode_current_mode(&uint_attr(0)).unwrap(), 0);
}

// ---- M9-A3 B2: ModeSelect ----------------------------------------------------
//
// ModeSelect is not a ModeBase derivative: its ModeOptionStruct carries
// SemanticTags (a cluster-local SemanticTagStruct { MfgCode(0) vendor-id,
// Value(1) enum16 }, distinct from the global `semtag`), and ChangeToMode has
// no response command.

#[test]
fn mode_select_standard_namespace_is_enum16() {
    // 1.4.2 ModeSelect.xml declares StandardNamespace enum16 (nullable); the
    // model's `namespace` is enum8, so the dump widens it (meta.relaxed, W).
    // A namespace id above 0xFF must decode, not fail as out of range.
    use gen::mode_select::decode_standard_namespace;
    assert_eq!(
        decode_standard_namespace(&uint_attr(0x0101)).unwrap(),
        Nullable::Value(0x0101_u16)
    );
    assert_eq!(
        decode_standard_namespace(&null_attr()).unwrap(),
        Nullable::Null
    );
}

#[test]
fn mode_select_supported_modes_decode_cluster_local_semantic_tags() {
    // The first entry is chip all-clusters' "Black" mode exactly
    // (static-supported-modes-manager.cpp: mode 0, one tag { MfgCode 0,
    // Value 0 }; chip always writes the non-optional MfgCode). The second is
    // synthetic: a manufacturer tag whose Value needs the full enum16.
    let tag = |w: &mut TlvWriter<'_>, mfg: u64, value: u64| {
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), mfg).unwrap();
        w.put_uint(Tag::Context(1), value).unwrap();
        w.end_container().unwrap();
    };
    let bytes = list_of(&[
        &|w| {
            w.put_utf8(Tag::Context(0), "Black").unwrap();
            w.put_uint(Tag::Context(1), 0).unwrap();
            w.start_array(Tag::Context(2)).unwrap();
            tag(w, 0, 0);
            w.end_container().unwrap();
        },
        &|w| {
            w.put_utf8(Tag::Context(0), "Vendor").unwrap();
            w.put_uint(Tag::Context(1), 9).unwrap();
            w.start_array(Tag::Context(2)).unwrap();
            tag(w, 0xFFF1, 0x0102);
            w.end_container().unwrap();
        },
    ]);
    let modes = gen::mode_select::decode_supported_modes(&bytes).unwrap();
    assert_eq!((modes[0].label.as_str(), modes[0].mode), ("Black", 0));
    let tags: Vec<(u16, u16)> = modes
        .iter()
        .flat_map(|m| m.semantic_tags.iter().map(|t| (t.mfg_code, t.value)))
        .collect();
    assert_eq!(tags, [(0, 0), (0xFFF1, 0x0102)]);
}

#[test]
fn mode_select_semantic_tag_missing_mfg_code_is_an_error() {
    // MfgCode is mandatory and non-nullable since ModeSelect revision 2.
    use matter_clusters::error::ClusterError;
    let bytes = list_of(&[&|w| {
        w.put_utf8(Tag::Context(0), "x").unwrap();
        w.put_uint(Tag::Context(1), 0).unwrap();
        w.start_array(Tag::Context(2)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(1), 1).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
    }]);
    assert!(matches!(
        gen::mode_select::decode_supported_modes(&bytes),
        Err(ClusterError::MissingField("MfgCode"))
    ));
}

#[test]
fn mode_select_writable_modes_and_change_to_mode_encode() {
    use gen::mode_select::{
        decode_description, decode_on_mode, decode_start_up_mode, encode_change_to_mode,
        encode_on_mode, encode_start_up_mode,
    };
    assert_eq!(decode_description(&str_attr("Coffee")).unwrap(), "Coffee");
    for v in [Nullable::Null, Nullable::Value(4)] {
        assert_eq!(decode_start_up_mode(&encode_start_up_mode(v)).unwrap(), v);
        assert_eq!(decode_on_mode(&encode_on_mode(v)).unwrap(), v);
    }
    assert_eq!(
        encode_change_to_mode(4),
        struct_of(&|w| w.put_uint(Tag::Context(0), 4).unwrap())
    );
}

// ---- M9-A3 B2: AlarmBase-derived clusters -------------------------------------
//
// Mask / Latch / State / Supported are map32 AlarmBitmap attributes; Notify
// carries four of them (1.4.2 AlarmBase.xml). RefrigeratorAlarm disallows the
// RESET feature, so its Latch and Reset are not generated (chip's controller
// codegen omits them too) and ModifyEnabledAlarms is disallowed outright.

#[test]
fn alarm_event_ids_pinned() {
    assert_eq!(gen::dishwasher_alarm::event_id::NOTIFY, 0x00);
    assert_eq!(gen::refrigerator_alarm::event_id::NOTIFY, 0x00);
}

#[test]
fn dishwasher_alarm_attributes_commands_and_notify_decode() {
    use gen::dishwasher_alarm::{
        decode_latch, decode_mask, decode_state, decode_supported, encode_modify_enabled_alarms,
        encode_reset, AlarmBitmap, NotifyEvent,
    };
    // chip all-clusters' boot values (dishwasher-alarm-stub.cpp): Supported
    // and Mask 0x2F, Latch 0x03, State 0x07.
    assert_eq!(
        decode_supported(&uint_attr(0x2F)).unwrap(),
        AlarmBitmap::from_bits_retain(0x2F)
    );
    assert_eq!(decode_mask(&uint_attr(0x2F)).unwrap().bits(), 0x2F);
    assert_eq!(
        decode_latch(&uint_attr(0x03)).unwrap(),
        AlarmBitmap::INFLOW_ERROR | AlarmBitmap::DRAIN_ERROR
    );
    assert_eq!(decode_state(&uint_attr(0x07)).unwrap().bits(), 0x07);
    // A bit beyond the six 1.4 alarms is kept, not dropped.
    assert_eq!(decode_state(&uint_attr(1 << 31)).unwrap().bits(), 1 << 31);

    assert_eq!(
        encode_reset(AlarmBitmap::INFLOW_ERROR),
        struct_of(&|w| w.put_uint(Tag::Context(0), 1).unwrap())
    );
    assert_eq!(
        encode_modify_enabled_alarms(AlarmBitmap::from_bits_retain(0x2F)),
        struct_of(&|w| w.put_uint(Tag::Context(0), 0x2F).unwrap())
    );

    // What chip sends after Reset(InflowError) from the boot state.
    let e = NotifyEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 0).unwrap();
        w.put_uint(Tag::Context(1), 0x01).unwrap();
        w.put_uint(Tag::Context(2), 0x06).unwrap();
        w.put_uint(Tag::Context(3), 0x2F).unwrap();
    }))
    .unwrap();
    assert_eq!(e.active, AlarmBitmap::empty());
    assert_eq!(e.inactive, AlarmBitmap::INFLOW_ERROR);
    assert_eq!(e.state, AlarmBitmap::DRAIN_ERROR | AlarmBitmap::DOOR_ERROR);
    assert_eq!(e.mask.bits(), 0x2F);
}

#[test]
fn notify_missing_a_field_is_an_error() {
    use matter_clusters::error::ClusterError;
    let three_of_four = struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.put_uint(Tag::Context(1), 0).unwrap();
        w.put_uint(Tag::Context(2), 1).unwrap();
    });
    assert!(matches!(
        gen::dishwasher_alarm::NotifyEvent::decode(&three_of_four),
        Err(ClusterError::MissingField("Mask"))
    ));
    assert!(matches!(
        gen::refrigerator_alarm::NotifyEvent::decode(&three_of_four),
        Err(ClusterError::MissingField("Mask"))
    ));
}

#[test]
fn refrigerator_alarm_decodes_and_door_open_notify() {
    use gen::refrigerator_alarm::{
        decode_mask, decode_state, decode_supported, AlarmBitmap, NotifyEvent,
    };
    // chip all-clusters' defaults (all-clusters-app.matter): Mask 1, State 0,
    // Supported 1.
    assert_eq!(decode_mask(&uint_attr(1)).unwrap(), AlarmBitmap::DOOR_OPEN);
    assert_eq!(decode_state(&uint_attr(0)).unwrap(), AlarmBitmap::empty());
    assert_eq!(
        decode_supported(&uint_attr(1)).unwrap(),
        AlarmBitmap::DOOR_OPEN
    );
    // What chip sends for app-pipe SetRefrigeratorDoorStatus DoorOpen=1.
    let e = NotifyEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.put_uint(Tag::Context(1), 0).unwrap();
        w.put_uint(Tag::Context(2), 1).unwrap();
        w.put_uint(Tag::Context(3), 1).unwrap();
    }))
    .unwrap();
    assert_eq!(
        (e.active, e.inactive),
        (AlarmBitmap::DOOR_OPEN, AlarmBitmap::empty())
    );
    assert_eq!(
        (e.state, e.mask),
        (AlarmBitmap::DOOR_OPEN, AlarmBitmap::DOOR_OPEN)
    );
}

// ---- M9-A3 B2: ResourceMonitoring-derived clusters ----------------------------
//
// HepaFilterMonitoring, ActivatedCarbonFilterMonitoring and
// WaterTankLevelMonitoring share one shape (1.4.2 ResourceMonitoring.xml):
// Condition percent, DegradationDirection / ChangeIndication enums,
// InPlaceIndicator, a writable nullable LastChangedTime (epoch-s) and
// ReplacementProductList (list<ReplacementProductStruct>). They have no events.

/// chip all-clusters' first two replacement products
/// (resource-monitoring-delegates.cpp `ImmutableReplacementProductListManager`).
fn replacement_products() -> Vec<u8> {
    list_of(&[
        &|w| {
            w.put_uint(Tag::Context(0), 0).unwrap(); // Upc
            w.put_utf8(Tag::Context(1), "111112222233").unwrap();
        },
        &|w| {
            w.put_uint(Tag::Context(0), 1).unwrap(); // Gtin8
            w.put_utf8(Tag::Context(1), "gtin8xxx").unwrap();
        },
    ])
}

macro_rules! resource_monitoring_cluster_decodes {
    ($test:ident, $m:ident) => {
        #[test]
        fn $test() {
            use gen::$m::{
                decode_change_indication, decode_condition, decode_degradation_direction,
                decode_in_place_indicator, decode_last_changed_time,
                decode_replacement_product_list, encode_last_changed_time, encode_reset_condition,
                ChangeIndicationEnum, DegradationDirectionEnum, ProductIdentifierTypeEnum,
            };
            let products = decode_replacement_product_list(&replacement_products()).unwrap();
            let got: Vec<_> = products
                .iter()
                .map(|p| {
                    (
                        p.product_identifier_type,
                        p.product_identifier_value.as_str(),
                    )
                })
                .collect();
            assert_eq!(
                got,
                [
                    (ProductIdentifierTypeEnum::Upc, "111112222233"),
                    (ProductIdentifierTypeEnum::Gtin8, "gtin8xxx"),
                ]
            );
            assert_eq!(decode_condition(&uint_attr(100)).unwrap(), 100);
            assert_eq!(
                decode_degradation_direction(&uint_attr(1)).unwrap(),
                DegradationDirectionEnum::Down
            );
            assert_eq!(
                decode_change_indication(&uint_attr(2)).unwrap(),
                ChangeIndicationEnum::Critical
            );
            assert!(decode_in_place_indicator(&bool_attr(true)).unwrap());
            for v in [Nullable::Null, Nullable::Value(788_918_400)] {
                assert_eq!(
                    decode_last_changed_time(&encode_last_changed_time(v)).unwrap(),
                    v
                );
            }
            // ResetCondition has no fields: an empty structure.
            assert_eq!(encode_reset_condition(), [0x15, 0x18]);
        }
    };
}

resource_monitoring_cluster_decodes!(hepa_filter_monitoring_decodes, hepa_filter_monitoring);
resource_monitoring_cluster_decodes!(
    activated_carbon_filter_monitoring_decodes,
    activated_carbon_filter_monitoring
);
resource_monitoring_cluster_decodes!(
    water_tank_level_monitoring_decodes,
    water_tank_level_monitoring
);

#[test]
fn replacement_product_missing_value_is_an_error() {
    use matter_clusters::error::ClusterError;
    let bytes = list_of(&[&|w| w.put_uint(Tag::Context(0), 4).unwrap()]);
    assert!(matches!(
        gen::water_tank_level_monitoring::decode_replacement_product_list(&bytes),
        Err(ClusterError::MissingField("ProductIdentifierValue"))
    ));
}
