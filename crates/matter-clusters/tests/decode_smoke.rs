//! Decode-smoke for the M9-A2.1 pilot and M9-A2.2 energy clusters: each
//! generated decoder reads a representative attribute's wire value. These
//! clusters are read-only; A2.1 reuses datatype shapes already byte-parity-proven
//! by the M7 clusters, and A2.2's one genuinely-new nested shape
//! (`MeasurementAccuracyStruct`) gets a dedicated matter.js byte-parity vector in
//! `byte_parity.rs`. Here a synthetic decode (construct TLV → decode → assert) is
//! the gate. (Roundtrip applies to writable attrs in later batches.)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use matter_clusters::clusters;
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
        clusters::illuminance_measurement::decode_measured_value(&uint_attr(12345)).unwrap(),
        Nullable::Value(12345)
    );
    assert_eq!(
        clusters::illuminance_measurement::decode_measured_value(&null_attr()).unwrap(),
        Nullable::Null
    );
}

#[test]
fn pressure_measured_value_decodes() {
    // MeasuredValue: nullable int16.
    assert_eq!(
        clusters::pressure_measurement::decode_measured_value(&int_attr(-50)).unwrap(),
        Nullable::Value(-50)
    );
}

#[test]
fn flow_measured_value_decodes() {
    // MeasuredValue: nullable uint16.
    assert_eq!(
        clusters::flow_measurement::decode_measured_value(&uint_attr(200)).unwrap(),
        Nullable::Value(200)
    );
}

#[test]
fn boolean_state_state_value_decodes() {
    // StateValue: bool.
    assert!(clusters::boolean_state::decode_state_value(&bool_attr(true)).unwrap());
}

#[test]
fn switch_current_position_decodes() {
    // CurrentPosition: uint8 (not nullable).
    assert_eq!(
        clusters::switch::decode_current_position(&uint_attr(2)).unwrap(),
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
    use clusters::air_quality::AirQualityEnum;
    assert_eq!(
        clusters::air_quality::decode_air_quality(&uint_attr(1)).unwrap(),
        AirQualityEnum::Good
    );
    // The model member named `Unknown` (value 0) is a fieldless variant…
    assert_eq!(
        clusters::air_quality::decode_air_quality(&uint_attr(0)).unwrap(),
        AirQualityEnum::Unknown
    );
    // …and an out-of-range discriminant lands in the renamed catch-all.
    assert_eq!(
        clusters::air_quality::decode_air_quality(&uint_attr(99)).unwrap(),
        AirQualityEnum::Unrecognized(99)
    );
}

#[test]
fn power_source_status_and_lists_decode() {
    use clusters::power_source::{PowerSourceStatusEnum, WiredFaultEnum};
    // Status: mandatory enum8.
    assert_eq!(
        clusters::power_source::decode_status(&uint_attr(1)).unwrap(),
        PowerSourceStatusEnum::Active
    );
    // ActiveWiredFaults: list<WiredFaultEnum> -> Vec<WiredFaultEnum> (gap 6).
    assert_eq!(
        clusters::power_source::decode_active_wired_faults(&uint_array_attr(&[1])).unwrap(),
        vec![WiredFaultEnum::OverVoltage]
    );
    // EndpointList: list<endpoint-no> -> Vec<u16>.
    assert_eq!(
        clusters::power_source::decode_endpoint_list(&uint_array_attr(&[1, 2])).unwrap(),
        vec![1u16, 2u16]
    );
}

#[test]
fn electrical_power_measurement_decodes() {
    use clusters::electrical_power_measurement as epm;
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
        clusters::electrical_energy_measurement::decode_cumulative_energy_imported(&null_attr())
            .unwrap(),
        Nullable::Null
    ));
}

// ---- M9-A2.3 actuator batch ----------------------------------------------

#[test]
fn thermostat_system_mode_decodes() {
    use clusters::thermostat::SystemModeEnum;
    // SystemMode: enum8; raw 4 = Heat (spot-check a known member).
    assert_eq!(
        clusters::thermostat::decode_system_mode(&uint_attr(4)).unwrap(),
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
    let resp = clusters::thermostat::AtomicResponse::decode_from(&mut r).unwrap();
    assert_eq!(resp.status_code, 0);
    assert_eq!(resp.attribute_status.len(), 1);
    assert_eq!(resp.attribute_status[0].attribute_id, 0x1234);
    assert_eq!(resp.attribute_status[0].status_code, 0);
    assert_eq!(resp.timeout, Some(1000));
}

#[test]
fn fan_control_fan_mode_decodes() {
    use clusters::fan_control::FanModeEnum;
    // FanMode: enum8; raw 3 = High.
    assert_eq!(
        clusters::fan_control::decode_fan_mode(&uint_attr(3)).unwrap(),
        FanModeEnum::High
    );
}

#[test]
fn tuic_keypad_lockout_decodes() {
    use clusters::thermostat_user_interface_configuration::KeypadLockoutEnum;
    // KeypadLockout: enum8; raw 0 = NoLockout.
    assert_eq!(
        clusters::thermostat_user_interface_configuration::decode_keypad_lockout(&uint_attr(0))
            .unwrap(),
        KeypadLockoutEnum::NoLockout
    );
}

#[test]
fn pump_operation_mode_decodes() {
    use clusters::pump_configuration_and_control::OperationModeEnum;
    // OperationMode: enum8; raw 0 = Normal.
    assert_eq!(
        clusters::pump_configuration_and_control::decode_operation_mode(&uint_attr(0)).unwrap(),
        OperationModeEnum::Normal
    );
}

#[test]
fn window_covering_mode_decodes() {
    // Mode: map8 bitmap; bit0 = MotorDirectionReversed (raw 1).
    let m = clusters::window_covering::decode_mode(&uint_attr(1)).unwrap();
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
    let t = clusters::binding::TargetStruct::decode_from(&mut r).unwrap();
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
    let l = clusters::fixed_label::LabelStruct::decode_from(&mut r).unwrap();
    assert_eq!(l.label, "room");
    assert_eq!(l.value, "kitchen");
}

#[test]
fn groups_add_group_command_encodes_wellformed() {
    use matter_codec::{Element, TlvReader, Value};
    // encode_add_group(group_id, group_name) -> anon struct { ctx0=uint, ctx1=utf8 }.
    let bytes = clusters::groups::encode_add_group(0x0007, &"den".to_string());
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
    let bytes = clusters::groups::encode_get_group_membership(&vec![1u16, 2u16]);
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
    let e = clusters::access_control::AccessControlEntryStruct::decode_from(&mut r).unwrap();
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
    let gks = clusters::group_key_management::GroupKeySetStruct {
        group_key_set_id: 0x0042,
        group_key_security_policy:
            clusters::group_key_management::GroupKeySecurityPolicyEnum::from_raw(0),
        epoch_key0: Nullable::Value(vec![0xab; 16]),
        epoch_start_time0: Nullable::Value(1234),
        epoch_key1: Nullable::Null,
        epoch_start_time1: Nullable::Null,
        epoch_key2: Nullable::Null,
        epoch_start_time2: Nullable::Null,
        group_key_multicast_policy: None,
        fabric_index: None,
    };
    let bytes = clusters::group_key_management::encode_key_set_write(gks);
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
    let bytes = clusters::administrator_commissioning::encode_open_basic_commissioning_window(180);
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
    use clusters::ota_software_update_requestor::AnnouncementReasonEnum;
    use matter_codec::{Element, TlvReader, Value};
    // metadata_for_node is optional -> None skips ctx3; ctx0 is the node id.
    let bytes = clusters::ota_software_update_requestor::encode_announce_ota_provider(
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
    use clusters::ota_software_update_provider::{encode_query_image, DownloadProtocolEnum};
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
    use clusters::ota_software_update_provider::{QueryImageResponse, StatusEnum};
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
    use clusters::time_synchronization::{decode_granularity, decode_utc_time, GranularityEnum};
    // UTCTime is nullable epoch_us; a present value decodes to Nullable::Some.
    let decoded = decode_utc_time(&uint_attr(780_000_000_000_000)).unwrap();
    assert_eq!(decoded, Nullable::Value(780_000_000_000_000));
    // Granularity enum8 = SecondsGranularity(2).
    let g = decode_granularity(&uint_attr(2)).unwrap();
    assert_eq!(g, GranularityEnum::SecondsGranularity);
}

#[test]
fn icd_register_client_response_and_operating_mode_decode() {
    use clusters::icd_management::{
        decode_operating_mode, OperatingModeEnum, RegisterClientResponse,
    };
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
    use clusters::time_synchronization::SetTimeZoneResponse;
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
    use clusters::carbon_dioxide_concentration_measurement as co2;
    use co2::{LevelValueEnum, MeasurementMediumEnum, MeasurementUnitEnum};

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
    use clusters::carbon_dioxide_concentration_measurement as co2;
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
    use clusters::carbon_dioxide_concentration_measurement as co2;
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
            use clusters::$m as m;
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
    use clusters::bridged_device_basic_information as bdbi;
    assert_eq!(bdbi::CLUSTER_ID, 0x0039);
    // Same attribute ids as BasicInformation (0x0028), per the Matter spec.
    assert_eq!(bdbi::attribute_id::NODE_LABEL, 0x0005);
    assert_eq!(bdbi::attribute_id::REACHABLE, 0x0011);
    assert_eq!(bdbi::attribute_id::UNIQUE_ID, 0x0012);
}

#[test]
fn bridged_device_basic_information_decodes() {
    use clusters::bridged_device_basic_information as bdbi;
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
    use clusters::switch::event_id as ev;
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
    let ev = clusters::switch::MultiPressCompleteEvent::decode(&buf).unwrap();
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
    assert!(clusters::switch::MultiPressCompleteEvent::decode(&buf).is_err());
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
    let acl =
        clusters::access_control::decode_acl(&list_of(&[&own_acl_entry, &other_fabric_entry]))
            .expect("an unfiltered ACL read with a second fabric must decode");
    assert_eq!(acl.len(), 2);
}

#[test]
fn acl_other_fabric_entry_has_every_sensitive_field_none() {
    use clusters::access_control::{
        AccessControlEntryAuthModeEnum, AccessControlEntryPrivilegeEnum,
    };
    let acl =
        clusters::access_control::decode_acl(&list_of(&[&own_acl_entry, &other_fabric_entry]))
            .unwrap();
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
    let acl = clusters::access_control::decode_acl(&list_of(&[&partial])).unwrap();
    assert_eq!(
        acl[0].privilege,
        Some(clusters::access_control::AccessControlEntryPrivilegeEnum::from_raw(3))
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
        clusters::access_control::decode_extension(&list_of(&[&own, &other_fabric_entry])).unwrap();
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
    let arl = clusters::access_control::decode_arl(&list_of(&[&own, &other_fabric_entry])).unwrap();
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
    let clients = clusters::icd_management::decode_registered_clients(&list_of(&[
        &own_icd_entry,
        &other_fabric_entry,
    ]))
    .expect("an unfiltered RegisteredClients read with a second fabric must decode");
    assert_eq!(clients[0].check_in_node_id, Some(0x1122));
    assert_eq!(clients[0].monitored_subject, Some(0x3344));
    assert_eq!(
        clients[0].client_type,
        Some(clusters::icd_management::ClientTypeEnum::from_raw(1))
    );
    assert_eq!(clients[1].check_in_node_id, None);
    assert_eq!(clients[1].monitored_subject, None);
    assert_eq!(clients[1].client_type, None);
    assert_eq!(clients[1].fabric_index, 2);
}

// ---- M9-A3 B1: events, scalar-field shapes ----------------------------------
//
// Each event payload is an anonymous structure of context-tagged fields (the
// same wire shape as a command response), decoded by the generated
// `<Name>Event::decode`. Field tags and types follow the 1.4.2 event tables.

#[test]
fn basic_information_event_ids_pinned() {
    use clusters::basic_information::event_id as ev;
    assert_eq!(ev::START_UP, 0x00);
    assert_eq!(ev::SHUT_DOWN, 0x01);
    assert_eq!(ev::LEAVE, 0x02);
    assert_eq!(ev::REACHABLE_CHANGED, 0x03);
}

#[test]
fn basic_information_events_decode() {
    use clusters::basic_information::{LeaveEvent, ReachableChangedEvent, StartUpEvent};
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
    let e = clusters::basic_information::StartUpEvent::decode(&struct_of(&|w| {
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
    use clusters::boolean_state::{event_id, StateChangeEvent};
    assert_eq!(event_id::STATE_CHANGE, 0x00);
    let e = StateChangeEvent::decode(&struct_of(&|w| {
        w.put_bool(Tag::Context(0), true).unwrap();
    }))
    .unwrap();
    assert!(e.state_value);
}

#[test]
fn occupancy_changed_event_decodes() {
    use clusters::occupancy_sensing::{event_id, OccupancyBitmap, OccupancyChangedEvent};
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
    use clusters::pump_configuration_and_control::event_id as ev;
    assert_eq!(ev::SUPPLY_VOLTAGE_LOW, 0x00);
    assert_eq!(ev::DRY_RUNNING, 0x05);
    assert_eq!(ev::PUMP_BLOCKED, 0x09);
    assert_eq!(ev::TURBINE_OPERATION, 0x10);
}

#[test]
fn time_synchronization_events_decode() {
    use clusters::time_synchronization::{event_id as ev, DstStatusEvent, TimeZoneStatusEvent};
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
    use clusters::ota_software_update_requestor::{
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
    use clusters::general_diagnostics::{
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
    use clusters::power_source::{
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
        clusters::general_diagnostics::HardwareFaultChangeEvent::decode(&only_current),
        Err(ClusterError::MissingField("Previous"))
    ));
    assert!(matches!(
        clusters::power_source::BatFaultChangeEvent::decode(&only_current),
        Err(ClusterError::MissingField("Previous"))
    ));
    assert!(matches!(
        clusters::general_diagnostics::BootReasonEvent::decode(&struct_of(&|_| {})),
        Err(ClusterError::MissingField("BootReason"))
    ));
}

// ---- M9-A3 B1: events, composite-field shapes -------------------------------

#[test]
fn access_control_event_ids_pinned() {
    use clusters::access_control::event_id as ev;
    assert_eq!(ev::ACCESS_CONTROL_ENTRY_CHANGED, 0x00);
    assert_eq!(ev::ACCESS_CONTROL_EXTENSION_CHANGED, 0x01);
    assert_eq!(ev::FABRIC_RESTRICTION_REVIEW_UPDATE, 0x02);
}

#[test]
fn access_control_entry_changed_event_decodes_with_unwrapped_fields() {
    use clusters::access_control::{
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
    use clusters::access_control::{
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
    use clusters::electrical_energy_measurement::{
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
    use clusters::electrical_power_measurement::{
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
    use clusters::door_lock::event_id as ev;
    assert_eq!(ev::DOOR_LOCK_ALARM, 0x00);
    assert_eq!(ev::DOOR_STATE_CHANGE, 0x01);
    assert_eq!(ev::LOCK_OPERATION, 0x02);
    assert_eq!(ev::LOCK_OPERATION_ERROR, 0x03);
    assert_eq!(ev::LOCK_USER_CHANGE, 0x04);
}

#[test]
fn door_lock_events_decode() {
    use clusters::door_lock::{
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
    use clusters::bridged_device_basic_information::event_id as ev;
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
    use clusters::bridged_device_basic_information::{
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
/// response with and without `StatusText` (spec §3.1: chip's `ModeBase`
/// server omits it from the replies it builds itself; an app delegate may
/// set it).
macro_rules! mode_base_cluster_decodes {
    ($test:ident, $m:ident, $first_derived_tag:literal, $derived_variant:ident) => {
        #[test]
        fn $test() {
            use clusters::$m::{ChangeToModeResponse, ModeChangeStatus, ModeTag};
            use matter_clusters::error::ClusterError;
            let modes =
                clusters::$m::decode_supported_modes(&supported_modes($first_derived_tag)).unwrap();
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
            assert_eq!(clusters::$m::decode_current_mode(&uint_attr(7)).unwrap(), 7);

            let new_mode_7 = struct_of(&|w| w.put_uint(Tag::Context(0), 7).unwrap());
            assert_eq!(clusters::$m::encode_change_to_mode(7), new_mode_7);

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
    use clusters::{rvc_clean_mode, rvc_run_mode};
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
        clusters::dishwasher_mode::decode_supported_modes(&bytes),
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
    use clusters::microwave_oven_mode::{decode_current_mode, decode_supported_modes, ModeTag};
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
    use clusters::mode_select::decode_standard_namespace;
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
    let modes = clusters::mode_select::decode_supported_modes(&bytes).unwrap();
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
        clusters::mode_select::decode_supported_modes(&bytes),
        Err(ClusterError::MissingField("MfgCode"))
    ));
}

#[test]
fn mode_select_writable_modes_and_change_to_mode_encode() {
    use clusters::mode_select::{
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
    assert_eq!(clusters::dishwasher_alarm::event_id::NOTIFY, 0x00);
    assert_eq!(clusters::refrigerator_alarm::event_id::NOTIFY, 0x00);
}

#[test]
fn dishwasher_alarm_attributes_commands_and_notify_decode() {
    use clusters::dishwasher_alarm::{
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
        clusters::dishwasher_alarm::NotifyEvent::decode(&three_of_four),
        Err(ClusterError::MissingField("Mask"))
    ));
    assert!(matches!(
        clusters::refrigerator_alarm::NotifyEvent::decode(&three_of_four),
        Err(ClusterError::MissingField("Mask"))
    ));
}

#[test]
fn refrigerator_alarm_decodes_and_door_open_notify() {
    use clusters::refrigerator_alarm::{
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
            use clusters::$m::{
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
        clusters::water_tank_level_monitoring::decode_replacement_product_list(&bytes),
        Err(ClusterError::MissingField("ProductIdentifierValue"))
    ));
}

// ---- M9-A3 B3: OperationalState and its derived clusters ---------------------
//
// OperationalState, OvenCavityOperationalState and RvcOperationalState share
// one shape (1.4.2 OperationalState.xml; the derived clusters inherit every
// field through `members`): PhaseList (nullable list<string>), CurrentPhase
// (nullable uint8), CountdownTime (nullable elapsed-s), OperationalStateList
// (list<OperationalStateStruct>), OperationalState (enum8), OperationalError
// (ErrorStateStruct); OperationalCommandResponse { CommandResponseState };
// events OperationalError { ErrorState } and OperationCompletion
// { CompletionErrorCode, TotalOperationalTime?, PausedTime? }.
// ErrorStateLabel / OperationalStateLabel have the expression conformance
// "ID >= 128 & ID <= 191", so they are optional (spec §3.1).

/// An anonymous array of anonymous UTF-8 strings.
fn str_list_attr(values: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        w.start_array(Tag::Anonymous).unwrap();
        for v in values {
            w.put_utf8(Tag::Anonymous, v).unwrap();
        }
        w.end_container().unwrap();
    }
    buf
}

/// `OperationalStateList` as chip encodes it
/// (`OperationalState/Structs.ipp` writes the label only when present):
/// Stopped and Running without labels, and a manufacturer state 0x80 with one.
fn operational_state_list() -> Vec<u8> {
    list_of(&[
        &|w| w.put_uint(Tag::Context(0), 0).unwrap(),
        &|w| w.put_uint(Tag::Context(0), 1).unwrap(),
        &|w| {
            w.put_uint(Tag::Context(0), 0x80).unwrap();
            w.put_utf8(Tag::Context(1), "Preheating").unwrap();
        },
    ])
}

/// `ErrorStateStruct` with only `ErrorStateID`: what chip's
/// `GenericOperationalError(id)` encodes (no label, no details).
fn error_state(id: u64) -> Vec<u8> {
    struct_of(&|w| w.put_uint(Tag::Context(0), id).unwrap())
}

/// Two tests per `OperationalState`-shaped cluster: every attribute, then the
/// command response and both events, including the optional and nullable
/// fields chip leaves out or sends as null.
macro_rules! operational_state_cluster_decodes {
    ($attributes_test:ident, $payloads_test:ident, $m:ident) => {
        #[test]
        fn $attributes_test() {
            use clusters::$m::{
                decode_countdown_time, decode_current_phase, decode_operational_error,
                decode_operational_state, decode_operational_state_list, decode_phase_list,
                ErrorStateEnum, OperationalStateEnum,
            };
            let states = decode_operational_state_list(&operational_state_list()).unwrap();
            let got: Vec<_> = states
                .iter()
                .map(|s| (s.operational_state_id, s.operational_state_label.as_deref()))
                .collect();
            assert_eq!(
                got,
                [
                    (OperationalStateEnum::Stopped, None),
                    (OperationalStateEnum::Running, None),
                    (OperationalStateEnum::Unknown(0x80), Some("Preheating")),
                ]
            );
            // A null PhaseList (no phases) and a real one.
            assert_eq!(decode_phase_list(&null_attr()).unwrap(), Nullable::Null);
            assert_eq!(
                decode_phase_list(&str_list_attr(&["pre-soak", "rinse"])).unwrap(),
                Nullable::Value(vec!["pre-soak".to_string(), "rinse".to_string()])
            );
            assert_eq!(decode_current_phase(&null_attr()).unwrap(), Nullable::Null);
            assert_eq!(
                decode_current_phase(&uint_attr(1)).unwrap(),
                Nullable::Value(1)
            );
            assert_eq!(decode_countdown_time(&null_attr()).unwrap(), Nullable::Null);
            assert_eq!(
                decode_countdown_time(&uint_attr(30)).unwrap(),
                Nullable::Value(30)
            );
            assert_eq!(
                decode_operational_state(&uint_attr(3)).unwrap(),
                OperationalStateEnum::Error
            );
            let err = decode_operational_error(&error_state(0)).unwrap();
            assert_eq!(
                (
                    err.error_state_id,
                    err.error_state_label,
                    err.error_state_details
                ),
                (ErrorStateEnum::NoError, None, None)
            );
            // A manufacturer error (0x80..=0xBF) with its label and details.
            let err = decode_operational_error(&struct_of(&|w| {
                w.put_uint(Tag::Context(0), 0x80).unwrap();
                w.put_utf8(Tag::Context(1), "Door ajar").unwrap();
                w.put_utf8(Tag::Context(2), "close the door").unwrap();
            }))
            .unwrap();
            assert_eq!(err.error_state_id, ErrorStateEnum::Unknown(0x80));
            assert_eq!(err.error_state_label.as_deref(), Some("Door ajar"));
            assert_eq!(err.error_state_details.as_deref(), Some("close the door"));
        }

        #[test]
        fn $payloads_test() {
            use clusters::$m::{
                ErrorStateEnum, OperationCompletionEvent, OperationalCommandResponse,
                OperationalErrorEvent,
            };
            // What chip sends for Pause from Stopped (OperationalStateCluster.cpp
            // HandlePauseState): CommandInvalidInState, no label.
            let r = OperationalCommandResponse::decode(&struct_of(&|w| {
                w.start_structure(Tag::Context(0)).unwrap();
                w.put_uint(Tag::Context(0), 3).unwrap();
                w.end_container().unwrap();
            }))
            .unwrap();
            assert_eq!(
                r.command_response_state.error_state_id,
                ErrorStateEnum::CommandInvalidInState
            );
            let e = OperationalErrorEvent::decode(&struct_of(&|w| {
                w.start_structure(Tag::Context(0)).unwrap();
                w.put_uint(Tag::Context(0), 2).unwrap();
                w.end_container().unwrap();
            }))
            .unwrap();
            assert_eq!(
                e.error_state.error_state_id,
                ErrorStateEnum::UnableToCompleteOperation
            );
            // OperationCompletion with both times (rvc-app's ActivityComplete
            // sends 100 and 10), then with one absent and one null.
            let e = OperationCompletionEvent::decode(&struct_of(&|w| {
                w.put_uint(Tag::Context(0), 0).unwrap();
                w.put_uint(Tag::Context(1), 100).unwrap();
                w.put_uint(Tag::Context(2), 10).unwrap();
            }))
            .unwrap();
            assert_eq!(
                (
                    e.completion_error_code,
                    e.total_operational_time,
                    e.paused_time
                ),
                (0, Some(Nullable::Value(100)), Some(Nullable::Value(10)))
            );
            let e = OperationCompletionEvent::decode(&struct_of(&|w| {
                w.put_uint(Tag::Context(0), 2).unwrap();
                w.put_null(Tag::Context(2)).unwrap();
            }))
            .unwrap();
            assert_eq!(
                (
                    e.completion_error_code,
                    e.total_operational_time,
                    e.paused_time
                ),
                (2, None, Some(Nullable::Null))
            );
        }
    };
}

operational_state_cluster_decodes!(
    operational_state_attributes_decode,
    operational_state_payloads_decode,
    operational_state
);
operational_state_cluster_decodes!(
    oven_cavity_operational_state_attributes_decode,
    oven_cavity_operational_state_payloads_decode,
    oven_cavity_operational_state
);
operational_state_cluster_decodes!(
    rvc_operational_state_attributes_decode,
    rvc_operational_state_payloads_decode,
    rvc_operational_state
);

#[test]
fn operational_state_event_ids_pinned() {
    for (error, completion) in [
        (
            clusters::operational_state::event_id::OPERATIONAL_ERROR,
            clusters::operational_state::event_id::OPERATION_COMPLETION,
        ),
        (
            clusters::oven_cavity_operational_state::event_id::OPERATIONAL_ERROR,
            clusters::oven_cavity_operational_state::event_id::OPERATION_COMPLETION,
        ),
        (
            clusters::rvc_operational_state::event_id::OPERATIONAL_ERROR,
            clusters::rvc_operational_state::event_id::OPERATION_COMPLETION,
        ),
    ] {
        assert_eq!((error, completion), (0x00, 0x01));
    }
}

#[test]
fn operational_state_commands_are_empty_structures() {
    // Every OperationalState-family request carries no fields (1.4.2
    // OperationalState.xml, RvcOperationalState.xml GoHome). The disallowed
    // ones are not generated: OvenCavity Pause/Resume, Rvc Start/Stop.
    const EMPTY: [u8; 2] = [0x15, 0x18];
    use clusters::{
        operational_state as os, oven_cavity_operational_state as oven,
        rvc_operational_state as rvc,
    };
    for bytes in [
        os::encode_pause(),
        os::encode_stop(),
        os::encode_start(),
        os::encode_resume(),
        oven::encode_stop(),
        oven::encode_start(),
        rvc::encode_pause(),
        rvc::encode_resume(),
        rvc::encode_go_home(),
    ] {
        assert_eq!(bytes, EMPTY);
    }
    assert_eq!(rvc::command_id::GO_HOME, 0x80);
    assert_eq!(oven::command_id::OPERATIONAL_COMMAND_RESPONSE, 0x04);
    assert_eq!(rvc::command_id::OPERATIONAL_COMMAND_RESPONSE, 0x04);
}

#[test]
fn rvc_operational_state_keeps_base_and_derived_values() {
    // The derived enums add values to the base's 0..=3; read from `members`,
    // a plain Stopped / NoError decodes as itself, not Unknown.
    use clusters::rvc_operational_state::{ErrorStateEnum, OperationalStateEnum};
    assert_eq!(
        OperationalStateEnum::from_raw(0),
        OperationalStateEnum::Stopped
    );
    assert_eq!(
        OperationalStateEnum::from_raw(0x40),
        OperationalStateEnum::SeekingCharger
    );
    assert_eq!(
        OperationalStateEnum::from_raw(0x42),
        OperationalStateEnum::Docked
    );
    assert_eq!(
        OperationalStateEnum::from_raw(0x46),
        OperationalStateEnum::UpdatingMaps
    );
    assert_eq!(ErrorStateEnum::from_raw(0), ErrorStateEnum::NoError);
    assert_eq!(ErrorStateEnum::from_raw(0x41), ErrorStateEnum::Stuck);
    assert_eq!(
        ErrorStateEnum::from_raw(0x4E),
        ErrorStateEnum::NavigationSensorObscured
    );
    assert_eq!(
        ErrorStateEnum::from_raw(0x4F),
        ErrorStateEnum::Unknown(0x4F)
    );
}

#[test]
fn operational_state_missing_mandatory_fields_are_errors() {
    use matter_clusters::error::ClusterError;
    // CommandResponseState, ErrorState and ErrorStateID are unconditional M.
    assert!(matches!(
        clusters::operational_state::OperationalCommandResponse::decode(&struct_of(&|_| {})),
        Err(ClusterError::MissingField("CommandResponseState"))
    ));
    assert!(matches!(
        clusters::rvc_operational_state::OperationalErrorEvent::decode(&struct_of(&|_| {})),
        Err(ClusterError::MissingField("ErrorState"))
    ));
    assert!(matches!(
        clusters::oven_cavity_operational_state::decode_operational_error(&struct_of(&|w| {
            w.put_utf8(Tag::Context(1), "label only").unwrap();
        })),
        Err(ClusterError::MissingField("ErrorStateId"))
    ));
    assert!(matches!(
        clusters::operational_state::OperationCompletionEvent::decode(&struct_of(&|w| {
            w.put_uint(Tag::Context(1), 5).unwrap();
        })),
        Err(ClusterError::MissingField("CompletionErrorCode"))
    ));
}

// ---- M9-A3 B3: appliance controls --------------------------------------------
//
// TemperatureControl, LaundryWasherControls, LaundryDryerControls and
// MicrowaveOvenControl: feature-gated scalar attributes, lists of strings and
// of enums, writable nullable attributes, and all-optional command fields
// (1.4.2 TemperatureControl.xml, LaundryWasherControls.xml,
// LaundryDryerControls.xml, MicrowaveOvenControl.xml). No events.

#[test]
fn temperature_control_decodes_and_set_temperature_encodes() {
    use clusters::temperature_control::{
        decode_max_temperature, decode_min_temperature, decode_selected_temperature_level,
        decode_step, decode_supported_temperature_levels, decode_temperature_setpoint,
        encode_set_temperature, Feature,
    };
    // chip all-clusters' levels (static-supported-temperature-levels.cpp).
    assert_eq!(
        decode_supported_temperature_levels(&str_list_attr(&["Hot", "Warm", "Freezing"])).unwrap(),
        ["Hot", "Warm", "Freezing"]
    );
    assert_eq!(decode_selected_temperature_level(&uint_attr(0)).unwrap(), 0);
    // Temperatures are signed 0.01 °C.
    assert_eq!(
        decode_temperature_setpoint(&int_attr(-1250)).unwrap(),
        -1250
    );
    assert_eq!(decode_min_temperature(&int_attr(-2000)).unwrap(), -2000);
    assert_eq!(decode_max_temperature(&int_attr(25000)).unwrap(), 25000);
    assert_eq!(decode_step(&int_attr(50)).unwrap(), 50);
    assert_eq!(Feature::TL.bits(), 0b010);
    // Each field is present only under its feature, so both are optional.
    assert_eq!(
        encode_set_temperature(None, Some(2)),
        struct_of(&|w| w.put_uint(Tag::Context(1), 2).unwrap())
    );
    assert_eq!(encode_set_temperature(None, None), [0x15, 0x18]);
}

#[test]
fn laundry_washer_controls_decode_and_writes_encode() {
    use clusters::laundry_washer_controls::{
        decode_number_of_rinses, decode_spin_speed_current, decode_spin_speeds,
        decode_supported_rinses, encode_number_of_rinses, encode_spin_speed_current,
        NumberOfRinsesEnum,
    };
    // chip all-clusters' options (laundry-washer-controls-delegate-impl.cpp).
    assert_eq!(
        decode_spin_speeds(&str_list_attr(&["Off", "Low", "Medium", "High"])).unwrap(),
        ["Off", "Low", "Medium", "High"]
    );
    assert_eq!(
        decode_supported_rinses(&uint_array_attr(&[1, 2])).unwrap(),
        [NumberOfRinsesEnum::Normal, NumberOfRinsesEnum::Extra]
    );
    for v in [Nullable::Null, Nullable::Value(2)] {
        assert_eq!(
            decode_spin_speed_current(&encode_spin_speed_current(v)).unwrap(),
            v
        );
    }
    assert_eq!(encode_spin_speed_current(Nullable::Value(2)), uint_attr(2));
    assert_eq!(encode_spin_speed_current(Nullable::Null), null_attr());
    assert_eq!(
        decode_number_of_rinses(&encode_number_of_rinses(NumberOfRinsesEnum::Max)).unwrap(),
        NumberOfRinsesEnum::Max
    );
    // A rinse count a newer revision adds is kept, not an error.
    assert_eq!(
        decode_number_of_rinses(&uint_attr(9)).unwrap(),
        NumberOfRinsesEnum::Unknown(9)
    );
}

#[test]
fn laundry_dryer_controls_decode_and_write_encodes() {
    use clusters::laundry_dryer_controls::{
        decode_selected_dryness_level, decode_supported_dryness_levels,
        encode_selected_dryness_level, DrynessLevelEnum,
    };
    // chip all-clusters' levels (laundry-dryer-controls-delegate-impl.cpp).
    assert_eq!(
        decode_supported_dryness_levels(&uint_array_attr(&[0, 1, 3])).unwrap(),
        [
            DrynessLevelEnum::Low,
            DrynessLevelEnum::Normal,
            DrynessLevelEnum::Max
        ]
    );
    for v in [Nullable::Null, Nullable::Value(DrynessLevelEnum::Extra)] {
        assert_eq!(
            decode_selected_dryness_level(&encode_selected_dryness_level(v)).unwrap(),
            v
        );
    }
    assert_eq!(
        encode_selected_dryness_level(Nullable::Value(DrynessLevelEnum::Normal)),
        uint_attr(1)
    );
}

#[test]
fn microwave_oven_control_decodes_and_commands_encode() {
    use clusters::microwave_oven_control::{
        decode_cook_time, decode_max_cook_time, decode_max_power, decode_min_power,
        decode_power_setting, decode_power_step, decode_selected_watt_index,
        decode_supported_watts, decode_watt_rating, encode_add_more_time,
        encode_set_cooking_parameters, Feature,
    };
    // chip microwave-oven-app's values (MicrowaveOvenControlCluster.cpp,
    // examples/microwave-oven-app/microwave-oven-common/src/
    // microwave-oven-device.cpp, and include/microwave-oven-device.h L229-233,
    // chip master 5cd2917a: power 20..=90 in steps of 10, at most 86400 s of
    // cook time, 90 by default): cook time 30 s of at most 86400 s, power
    // 20..=90 in steps of 10, set to 90, 1000 W rating (MicrowaveOvenInit's
    // non-WATTS branch, ~L48: `mWattRating = kExampleWatt5`). SupportedWatts
    // and SelectedWattIndex 4 are the WATTS-branch values (~L43-44: the last
    // index of the five-entry watt list); the app's default features are
    // PWRNUM|PWRLMTS, so it serves neither.
    assert_eq!(decode_cook_time(&uint_attr(30)).unwrap(), 30);
    assert_eq!(decode_max_cook_time(&uint_attr(86_400)).unwrap(), 86_400);
    assert_eq!(decode_power_setting(&uint_attr(90)).unwrap(), 90);
    assert_eq!(decode_min_power(&uint_attr(20)).unwrap(), 20);
    assert_eq!(decode_max_power(&uint_attr(90)).unwrap(), 90);
    assert_eq!(decode_power_step(&uint_attr(10)).unwrap(), 10);
    assert_eq!(decode_watt_rating(&uint_attr(1000)).unwrap(), 1000);
    assert_eq!(
        decode_supported_watts(&uint_array_attr(&[100, 300, 500, 800, 1000])).unwrap(),
        [100, 300, 500, 800, 1000]
    );
    assert_eq!(decode_selected_watt_index(&uint_attr(4)).unwrap(), 4);
    assert_eq!(
        (Feature::PWRNUM | Feature::PWRLMTS).bits(),
        0b101,
        "microwave-oven-app's features"
    );
    // Every SetCookingParameters field is optional; absent ones are omitted.
    assert_eq!(
        encode_set_cooking_parameters(None, Some(45), Some(60), None, None),
        struct_of(&|w| {
            w.put_uint(Tag::Context(1), 45).unwrap();
            w.put_uint(Tag::Context(2), 60).unwrap();
        })
    );
    assert_eq!(
        encode_set_cooking_parameters(Some(1), None, None, Some(4), Some(false)),
        struct_of(&|w| {
            w.put_uint(Tag::Context(0), 1).unwrap();
            w.put_uint(Tag::Context(3), 4).unwrap();
            w.put_bool(Tag::Context(4), false).unwrap();
        })
    );
    assert_eq!(
        encode_set_cooking_parameters(None, None, None, None, None),
        [0x15, 0x18]
    );
    assert_eq!(
        encode_add_more_time(10),
        struct_of(&|w| w.put_uint(Tag::Context(0), 10).unwrap())
    );
}

// ---- M9-A3 B3: ServiceArea -----------------------------------------------------
//
// SupportedAreas is a list of AreaStruct { AreaID uint32, MapID nullable
// uint32, AreaInfo AreaInfoStruct { LocationInfo nullable
// LocationDescriptorStruct, LandmarkInfo nullable LandmarkInfoStruct } }
// (1.4.2 ServiceArea.xml). LocationDescriptorStruct is the Matter-global
// `locationdesc` (LocationName string, FloorNumber nullable int16, AreaType
// nullable `tag`), generated under chip's name for it; the landmark and area
// type `tag`s are raw uint8 (their values come from the Common Landmark /
// Area namespaces).

/// One `AreaStruct` as chip writes it (`ServiceArea/Structs.ipp`: every field,
/// null where unset).
#[allow(clippy::type_complexity)]
fn area_entry(
    id: u64,
    map: u64,
    location: Option<(&str, Option<i64>, Option<u64>)>,
    landmark: Option<(u64, Option<u64>)>,
) -> impl Fn(&mut TlvWriter<'_>) + '_ {
    move |w| {
        w.put_uint(Tag::Context(0), id).unwrap();
        w.put_uint(Tag::Context(1), map).unwrap();
        w.start_structure(Tag::Context(2)).unwrap();
        match location {
            Some((name, floor, area_type)) => {
                w.start_structure(Tag::Context(0)).unwrap();
                w.put_utf8(Tag::Context(0), name).unwrap();
                match floor {
                    Some(f) => w.put_int(Tag::Context(1), f).unwrap(),
                    None => w.put_null(Tag::Context(1)).unwrap(),
                }
                match area_type {
                    Some(t) => w.put_uint(Tag::Context(2), t).unwrap(),
                    None => w.put_null(Tag::Context(2)).unwrap(),
                }
                w.end_container().unwrap();
            }
            None => w.put_null(Tag::Context(0)).unwrap(),
        }
        match landmark {
            Some((tag, position)) => {
                w.start_structure(Tag::Context(1)).unwrap();
                w.put_uint(Tag::Context(0), tag).unwrap();
                match position {
                    Some(p) => w.put_uint(Tag::Context(1), p).unwrap(),
                    None => w.put_null(Tag::Context(1)).unwrap(),
                }
                w.end_container().unwrap();
            }
            None => w.put_null(Tag::Context(1)).unwrap(),
        }
        w.end_container().unwrap();
    }
}

#[test]
fn service_area_supported_areas_decode_rvc_app_topology() {
    use clusters::service_area::{decode_supported_areas, LocationDescriptorStruct};
    // rvc-app's areas (rvc-service-area-delegate.cpp SetMapTopology): A (7)
    // and B (1234567) on map 3, C (10050) and D (0x88888888) on map 245;
    // PlayRoom 0x41, BackDoor 0x02, Couch 0x0D, NextTo 0x01.
    let area_a = area_entry(7, 3, Some(("My Location A", Some(4), None)), None);
    let area_b = area_entry(1_234_567, 3, Some(("My Location B", None, None)), None);
    let area_c = area_entry(
        10_050,
        245,
        Some(("", Some(-1), Some(0x41))),
        Some((0x02, Some(0x01))),
    );
    let area_d = area_entry(
        0x8888_8888,
        245,
        Some(("My Location D", None, None)),
        Some((0x0D, Some(0x01))),
    );
    let areas = decode_supported_areas(&list_of(&[&area_a, &area_b, &area_c, &area_d])).unwrap();
    let ids: Vec<(u32, Nullable<u32>)> = areas.iter().map(|x| (x.area_id, x.map_id)).collect();
    assert_eq!(
        ids,
        [
            (7, Nullable::Value(3)),
            (1_234_567, Nullable::Value(3)),
            (10_050, Nullable::Value(245)),
            (0x8888_8888, Nullable::Value(245)),
        ]
    );
    let location = |i: usize| -> LocationDescriptorStruct {
        match &areas[i].area_info.location_info {
            Nullable::Value(l) => l.clone(),
            Nullable::Null => panic!("area {i}: null LocationInfo"),
        }
    };
    let a_loc = location(0);
    assert_eq!(
        (
            a_loc.location_name.as_str(),
            a_loc.floor_number,
            a_loc.area_type
        ),
        ("My Location A", Nullable::Value(4), Nullable::Null)
    );
    let c_loc = location(2);
    assert_eq!(
        (
            c_loc.location_name.as_str(),
            c_loc.floor_number,
            c_loc.area_type
        ),
        ("", Nullable::Value(-1), Nullable::Value(0x41))
    );
    assert_eq!(areas[0].area_info.landmark_info, Nullable::Null);
    match &areas[3].area_info.landmark_info {
        Nullable::Value(l) => {
            assert_eq!(
                (l.landmark_tag, l.relative_position_tag),
                (0x0D, Nullable::Value(0x01))
            );
        }
        Nullable::Null => panic!("area D: null LandmarkInfo"),
    }
}

#[test]
fn service_area_maps_selection_and_progress_decode() {
    use clusters::service_area::{
        decode_current_area, decode_estimated_end_time, decode_progress, decode_selected_areas,
        decode_supported_maps, OperationalStatusEnum,
    };
    let maps = decode_supported_maps(&list_of(&[
        &|w| {
            w.put_uint(Tag::Context(0), 3).unwrap();
            w.put_utf8(Tag::Context(1), "My Map XX").unwrap();
        },
        &|w| {
            w.put_uint(Tag::Context(0), 245).unwrap();
            w.put_utf8(Tag::Context(1), "My Map YY").unwrap();
        },
    ]))
    .unwrap();
    let got: Vec<(u32, &str)> = maps.iter().map(|m| (m.map_id, m.name.as_str())).collect();
    assert_eq!(got, [(3, "My Map XX"), (245, "My Map YY")]);
    assert_eq!(
        decode_selected_areas(&uint_array_attr(&[7, 1_234_567])).unwrap(),
        [7, 1_234_567]
    );
    assert_eq!(decode_current_area(&null_attr()).unwrap(), Nullable::Null);
    assert_eq!(
        decode_current_area(&uint_attr(7)).unwrap(),
        Nullable::Value(7)
    );
    assert_eq!(
        decode_estimated_end_time(&null_attr()).unwrap(),
        Nullable::Null
    );
    // Progress during a run (service-area-server.cpp SetProgressStatus): the
    // operating area's TotalOperationalTime is null, a pending one has none.
    let progress = decode_progress(&list_of(&[
        &|w| {
            w.put_uint(Tag::Context(0), 7).unwrap();
            w.put_uint(Tag::Context(1), 1).unwrap();
            w.put_null(Tag::Context(2)).unwrap();
        },
        &|w| {
            w.put_uint(Tag::Context(0), 1_234_567).unwrap();
            w.put_uint(Tag::Context(1), 0).unwrap();
        },
    ]))
    .unwrap();
    let got: Vec<_> = progress
        .iter()
        .map(|p| {
            (
                p.area_id,
                p.status,
                p.total_operational_time,
                p.estimated_time,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                7,
                OperationalStatusEnum::Operating,
                Some(Nullable::Null),
                None
            ),
            (1_234_567, OperationalStatusEnum::Pending, None, None),
        ]
    );
}

#[test]
fn service_area_commands_encode_and_responses_decode() {
    use clusters::service_area::{
        encode_select_areas, encode_skip_area, SelectAreasResponse, SelectAreasStatus,
        SkipAreaResponse, SkipAreaStatus,
    };
    // SelectAreas carries a list<uint32>; SkipArea one uint32.
    let mut select = Vec::new();
    {
        let mut w = TlvWriter::new(&mut select);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(0)).unwrap();
        w.put_uint(Tag::Anonymous, 7).unwrap();
        w.put_uint(Tag::Anonymous, 0x8888_8888).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
    }
    assert_eq!(encode_select_areas(&vec![7, 0x8888_8888]), select);
    assert_eq!(
        encode_skip_area(7),
        struct_of(&|w| w.put_uint(Tag::Context(0), 7).unwrap())
    );
    // chip always sends StatusText, empty unless the status needs a reason.
    let r = SelectAreasResponse::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 3).unwrap();
        w.put_utf8(
            Tag::Context(1),
            "all selected areas must be in the same map",
        )
        .unwrap();
    }))
    .unwrap();
    assert_eq!(r.status, SelectAreasStatus::InvalidSet);
    assert_eq!(r.status_text, "all selected areas must be in the same map");
    let r = SkipAreaResponse::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.put_utf8(Tag::Context(1), "").unwrap();
    }))
    .unwrap();
    assert_eq!(
        (r.status, r.status_text.as_str()),
        (SkipAreaStatus::InvalidAreaList, "")
    );
}

#[test]
fn service_area_missing_mandatory_fields_are_errors() {
    use matter_clusters::error::ClusterError;
    // StatusText is an unconditional M in 1.4.2, and chip always sends it.
    assert!(matches!(
        clusters::service_area::SelectAreasResponse::decode(&struct_of(&|w| {
            w.put_uint(Tag::Context(0), 0).unwrap();
        })),
        Err(ClusterError::MissingField("StatusText"))
    ));
    // AreaInfo is mandatory in every AreaStruct.
    assert!(matches!(
        clusters::service_area::decode_supported_areas(&list_of(&[&|w| {
            w.put_uint(Tag::Context(0), 7).unwrap();
            w.put_null(Tag::Context(1)).unwrap();
        }])),
        Err(ClusterError::MissingField("AreaInfo"))
    ));
    // LocationName is mandatory inside a present LocationDescriptorStruct.
    assert!(matches!(
        clusters::service_area::LocationDescriptorStruct::decode(&struct_of(&|w| {
            w.put_null(Tag::Context(1)).unwrap();
            w.put_null(Tag::Context(2)).unwrap();
        })),
        Err(ClusterError::MissingField("LocationName"))
    ));
}

// ---- M9-A3 B4: Thermostat weekly schedule (Matter 1.4 SCH, supplemented) ----
//
// Feature SCH (bit 3): StartOfWeek / NumberOfWeeklyTransitions /
// NumberOfDailyTransitions, SetWeeklySchedule / GetWeeklySchedule /
// ClearWeeklySchedule and GetWeeklyScheduleResponse (1.4.2 Thermostat.xml).
// The 1.5.1 model removed them; the dump adds them from supplement-1.4.json and
// reuses the model's own ScheduleDayOfWeekBitmap, ScheduleModeBitmap,
// StartOfWeekEnum and WeeklyScheduleTransitionStruct.

#[test]
fn thermostat_weekly_schedule_attributes_and_response_decode() {
    use clusters::thermostat::{
        attribute_id, command_id, decode_number_of_daily_transitions,
        decode_number_of_weekly_transitions, decode_start_of_week, Feature,
        GetWeeklyScheduleResponse, ScheduleDayOfWeekBitmap, ScheduleModeBitmap, StartOfWeekEnum,
    };
    assert_eq!(Feature::SCH.bits(), 1 << 3);
    assert_eq!(
        (
            attribute_id::START_OF_WEEK,
            attribute_id::NUMBER_OF_WEEKLY_TRANSITIONS,
            attribute_id::NUMBER_OF_DAILY_TRANSITIONS
        ),
        (0x0020, 0x0021, 0x0022)
    );
    assert_eq!(
        (
            command_id::GET_WEEKLY_SCHEDULE_RESPONSE,
            command_id::SET_WEEKLY_SCHEDULE,
            command_id::GET_WEEKLY_SCHEDULE,
            command_id::CLEAR_WEEKLY_SCHEDULE
        ),
        (0x00, 0x01, 0x02, 0x03)
    );
    assert_eq!(
        decode_start_of_week(&uint_attr(1)).unwrap(),
        StartOfWeekEnum::Monday
    );
    assert_eq!(
        decode_number_of_weekly_transitions(&uint_attr(70)).unwrap(),
        70
    );
    assert_eq!(
        decode_number_of_daily_transitions(&uint_attr(10)).unwrap(),
        10
    );
    // A reply for Saturday and Sunday, heat and cool, one transition whose
    // heat setpoint is null (no heat change at 06:00).
    let r = GetWeeklyScheduleResponse::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.put_uint(Tag::Context(1), 0b0100_0001).unwrap();
        w.put_uint(Tag::Context(2), 0b11).unwrap();
        w.start_array(Tag::Context(3)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 360).unwrap();
        w.put_null(Tag::Context(1)).unwrap();
        w.put_int(Tag::Context(2), -150).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
    }))
    .unwrap();
    assert_eq!(r.number_of_transitions_for_sequence, 1);
    assert_eq!(
        r.day_of_week_for_sequence,
        ScheduleDayOfWeekBitmap::SUNDAY | ScheduleDayOfWeekBitmap::SATURDAY
    );
    assert_eq!(r.mode_for_sequence, ScheduleModeBitmap::all());
    let t = &r.transitions[..];
    assert_eq!(t.len(), 1);
    assert_eq!(
        (t[0].transition_time, t[0].heat_setpoint, t[0].cool_setpoint),
        (360, Nullable::Null, Nullable::Value(-150))
    );
}

#[test]
fn thermostat_weekly_schedule_requests_encode() {
    use clusters::thermostat::{
        encode_clear_weekly_schedule, encode_get_weekly_schedule, ScheduleDayOfWeekBitmap,
        ScheduleModeBitmap,
    };
    assert_eq!(encode_clear_weekly_schedule(), [0x15, 0x18]);
    assert_eq!(
        encode_get_weekly_schedule(
            ScheduleDayOfWeekBitmap::AWAY,
            ScheduleModeBitmap::COOL_SETPOINT_PRESENT
        ),
        struct_of(&|w| {
            w.put_uint(Tag::Context(0), 0x80).unwrap();
            w.put_uint(Tag::Context(1), 0x02).unwrap();
        })
    );
}

#[test]
fn thermostat_weekly_schedule_response_missing_list_is_an_error() {
    use matter_clusters::error::ClusterError;
    // Transitions is an unconditional M in 1.4.2 (Thermostat.xml:1293).
    assert!(matches!(
        clusters::thermostat::GetWeeklyScheduleResponse::decode(&struct_of(&|w| {
            w.put_uint(Tag::Context(0), 0).unwrap();
            w.put_uint(Tag::Context(1), 1).unwrap();
            w.put_uint(Tag::Context(2), 1).unwrap();
        })),
        Err(ClusterError::MissingField("Transitions"))
    ));
}

// ---- M9-A3 B4: WindowCovering absolute position (Matter 1.4 ABS, supplemented) ----
//
// Feature ABS (bit 3, provisional in 1.4.2): the physical and installed limits,
// CurrentPositionLift/Tilt (nullable), GoToLiftValue / GoToTiltValue
// (1.4.2 WindowCovering.xml). The 1.5.1 model removed them; the dump adds them
// from supplement-1.4.json.

#[test]
fn window_covering_absolute_position_decodes_and_encodes() {
    use clusters::window_covering::{
        attribute_id as a, command_id, decode_current_position_lift, decode_current_position_tilt,
        decode_installed_closed_limit_lift, decode_installed_closed_limit_tilt,
        decode_installed_open_limit_lift, decode_installed_open_limit_tilt,
        decode_physical_closed_limit_lift, decode_physical_closed_limit_tilt,
        encode_go_to_lift_value, encode_go_to_tilt_value, Feature,
    };
    assert_eq!(Feature::ABS.bits(), 1 << 3);
    assert_eq!(
        [
            a::PHYSICAL_CLOSED_LIMIT_LIFT,
            a::PHYSICAL_CLOSED_LIMIT_TILT,
            a::CURRENT_POSITION_LIFT,
            a::CURRENT_POSITION_TILT,
            a::INSTALLED_OPEN_LIMIT_LIFT,
            a::INSTALLED_CLOSED_LIMIT_LIFT,
            a::INSTALLED_OPEN_LIMIT_TILT,
            a::INSTALLED_CLOSED_LIMIT_TILT
        ],
        [0x0001, 0x0002, 0x0003, 0x0004, 0x0010, 0x0011, 0x0012, 0x0013]
    );
    assert_eq!(
        (command_id::GO_TO_LIFT_VALUE, command_id::GO_TO_TILT_VALUE),
        (0x04, 0x07)
    );
    // chip all-clusters' defaults (all-clusters-app.matter, both refs).
    assert_eq!(
        decode_physical_closed_limit_lift(&uint_attr(0xFFFF)).unwrap(),
        0xFFFF
    );
    assert_eq!(
        decode_physical_closed_limit_tilt(&uint_attr(0xFFFF)).unwrap(),
        0xFFFF
    );
    assert_eq!(decode_installed_open_limit_lift(&uint_attr(0)).unwrap(), 0);
    assert_eq!(
        decode_installed_closed_limit_lift(&uint_attr(0xFFFF)).unwrap(),
        0xFFFF
    );
    assert_eq!(decode_installed_open_limit_tilt(&uint_attr(0)).unwrap(), 0);
    assert_eq!(
        decode_installed_closed_limit_tilt(&uint_attr(0xFFFF)).unwrap(),
        0xFFFF
    );
    // The current positions are nullable (unknown position).
    assert_eq!(
        decode_current_position_lift(&null_attr()).unwrap(),
        Nullable::Null
    );
    assert_eq!(
        decode_current_position_tilt(&uint_attr(0x7FFF)).unwrap(),
        Nullable::Value(0x7FFF)
    );
    assert!(decode_installed_open_limit_lift(&uint_attr(0x1_0000)).is_err());
    assert_eq!(
        encode_go_to_lift_value(250),
        struct_of(&|w| w.put_uint(Tag::Context(0), 250).unwrap())
    );
    assert_eq!(
        encode_go_to_tilt_value(900),
        struct_of(&|w| w.put_uint(Tag::Context(0), 900).unwrap())
    );
}

// ---- M9-A3 B4: SmokeCoAlarm and BooleanStateConfiguration ----------------
//
// SmokeCoAlarm (1.4.2 SmokeCOAlarm.xml): enum and bool attributes, a writable
// SmokeSensitivityLevel, SelfTestRequest, and eleven events -- five carry an
// AlarmSeverityLevel, six carry nothing (those get only their `event_id`
// const, like BasicInformation `ShutDown`). BooleanStateConfiguration (1.4.2
// BooleanStateConfiguration.xml): bitmap attributes, a writable sensitivity
// level, SuppressAlarm / EnableDisableAlarm, AlarmsStateChanged and
// SensorFault.

#[test]
fn smoke_co_alarm_attributes_decode() {
    use clusters::smoke_co_alarm::{
        decode_battery_alert, decode_co_state, decode_contamination_state, decode_device_muted,
        decode_end_of_service_alert, decode_expiry_date, decode_expressed_state,
        decode_hardware_fault_alert, decode_interconnect_co_alarm, decode_interconnect_smoke_alarm,
        decode_smoke_sensitivity_level, decode_smoke_state, decode_test_in_progress,
        encode_smoke_sensitivity_level, AlarmStateEnum, ContaminationStateEnum, EndOfServiceEnum,
        ExpressedStateEnum, Feature, MuteStateEnum, SensitivityEnum,
    };
    assert_eq!(
        (Feature::SMOKE | Feature::CO).bits(),
        3,
        "all-clusters' features"
    );
    assert_eq!(
        decode_expressed_state(&uint_attr(1)).unwrap(),
        ExpressedStateEnum::SmokeAlarm
    );
    // chip master adds Inoperative (9, revision 2): kept, not an error.
    assert_eq!(
        decode_expressed_state(&uint_attr(9)).unwrap(),
        ExpressedStateEnum::Unknown(9)
    );
    assert_eq!(
        decode_smoke_state(&uint_attr(2)).unwrap(),
        AlarmStateEnum::Critical
    );
    assert_eq!(
        decode_co_state(&uint_attr(1)).unwrap(),
        AlarmStateEnum::Warning
    );
    assert_eq!(
        decode_battery_alert(&uint_attr(0)).unwrap(),
        AlarmStateEnum::Normal
    );
    assert_eq!(
        decode_device_muted(&uint_attr(1)).unwrap(),
        MuteStateEnum::Muted
    );
    assert!(decode_test_in_progress(&bool_attr(true)).unwrap());
    assert!(!decode_hardware_fault_alert(&bool_attr(false)).unwrap());
    assert_eq!(
        decode_end_of_service_alert(&uint_attr(1)).unwrap(),
        EndOfServiceEnum::Expired
    );
    assert_eq!(
        decode_interconnect_smoke_alarm(&uint_attr(1)).unwrap(),
        AlarmStateEnum::Warning
    );
    assert_eq!(
        decode_interconnect_co_alarm(&uint_attr(0)).unwrap(),
        AlarmStateEnum::Normal
    );
    assert_eq!(
        decode_contamination_state(&uint_attr(3)).unwrap(),
        ContaminationStateEnum::Critical
    );
    // all-clusters' ExpiryDate default at master (epoch-s).
    assert_eq!(
        decode_expiry_date(&uint_attr(3_976_214_400)).unwrap(),
        3_976_214_400
    );
    assert_eq!(
        decode_smoke_sensitivity_level(&encode_smoke_sensitivity_level(SensitivityEnum::Low))
            .unwrap(),
        SensitivityEnum::Low
    );
    assert_eq!(
        encode_smoke_sensitivity_level(SensitivityEnum::Standard),
        uint_attr(1)
    );
}

#[test]
fn smoke_co_alarm_events_and_self_test_decode() {
    use clusters::smoke_co_alarm::{
        encode_self_test_request, event_id, AlarmStateEnum, CoAlarmEvent, InterconnectCoAlarmEvent,
        InterconnectSmokeAlarmEvent, LowBatteryEvent, SmokeAlarmEvent,
    };
    assert_eq!(encode_self_test_request(), [0x15, 0x18]);
    let severity = |v| struct_of(&|w| w.put_uint(Tag::Context(0), v).unwrap());
    assert_eq!(
        SmokeAlarmEvent::decode(&severity(2))
            .unwrap()
            .alarm_severity_level,
        AlarmStateEnum::Critical
    );
    assert_eq!(
        CoAlarmEvent::decode(&severity(1))
            .unwrap()
            .alarm_severity_level,
        AlarmStateEnum::Warning
    );
    assert_eq!(
        LowBatteryEvent::decode(&severity(1))
            .unwrap()
            .alarm_severity_level,
        AlarmStateEnum::Warning
    );
    assert_eq!(
        InterconnectSmokeAlarmEvent::decode(&severity(1))
            .unwrap()
            .alarm_severity_level,
        AlarmStateEnum::Warning
    );
    assert_eq!(
        InterconnectCoAlarmEvent::decode(&severity(1))
            .unwrap()
            .alarm_severity_level,
        AlarmStateEnum::Warning
    );
    // The six fieldless events are ids only (no payload struct).
    assert_eq!(
        [
            event_id::SMOKE_ALARM,
            event_id::CO_ALARM,
            event_id::LOW_BATTERY,
            event_id::HARDWARE_FAULT,
            event_id::END_OF_SERVICE,
            event_id::SELF_TEST_COMPLETE,
            event_id::ALARM_MUTED,
            event_id::MUTE_ENDED,
            event_id::INTERCONNECT_SMOKE_ALARM,
            event_id::INTERCONNECT_CO_ALARM,
            event_id::ALL_CLEAR
        ],
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
    );
    assert!(matches!(
        SmokeAlarmEvent::decode(&struct_of(&|_| {})),
        Err(matter_clusters::error::ClusterError::MissingField(
            "AlarmSeverityLevel"
        ))
    ));
}

#[test]
fn boolean_state_configuration_decodes_and_commands_encode() {
    use clusters::boolean_state_configuration::{
        decode_alarms_active, decode_alarms_enabled, decode_alarms_supported,
        decode_alarms_suppressed, decode_current_sensitivity_level,
        decode_default_sensitivity_level, decode_sensor_fault, decode_supported_sensitivity_levels,
        encode_current_sensitivity_level, encode_enable_disable_alarm, encode_suppress_alarm,
        AlarmModeBitmap, AlarmsStateChangedEvent, Feature, SensorFaultBitmap, SensorFaultEvent,
    };
    // all-clusters: features 0x0F, three levels (default 2), both alarms.
    assert_eq!(Feature::all().bits(), 0x0F);
    assert_eq!(
        decode_supported_sensitivity_levels(&uint_attr(3)).unwrap(),
        3
    );
    assert_eq!(decode_default_sensitivity_level(&uint_attr(2)).unwrap(), 2);
    assert_eq!(
        decode_current_sensitivity_level(&encode_current_sensitivity_level(1)).unwrap(),
        1
    );
    assert_eq!(
        decode_alarms_supported(&uint_attr(3)).unwrap(),
        AlarmModeBitmap::all()
    );
    assert_eq!(
        decode_alarms_active(&uint_attr(0)).unwrap(),
        AlarmModeBitmap::empty()
    );
    assert_eq!(
        decode_alarms_enabled(&uint_attr(3)).unwrap(),
        AlarmModeBitmap::all()
    );
    assert_eq!(
        decode_alarms_suppressed(&uint_attr(1)).unwrap(),
        AlarmModeBitmap::VISUAL
    );
    // A bit a later revision adds survives the decode.
    assert_eq!(
        decode_sensor_fault(&uint_attr(0x8001)).unwrap().bits(),
        0x8001
    );
    assert_eq!(
        encode_suppress_alarm(AlarmModeBitmap::VISUAL),
        struct_of(&|w| w.put_uint(Tag::Context(0), 1).unwrap())
    );
    assert_eq!(
        encode_enable_disable_alarm(AlarmModeBitmap::all()),
        struct_of(&|w| w.put_uint(Tag::Context(0), 3).unwrap())
    );
    // chip sends AlarmsSuppressed only with the SPRS feature
    // (GenerateAlarmsStateChangedEvent / emitAlarmsStateChangedEvent).
    let e = AlarmsStateChangedEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 3).unwrap();
        w.put_uint(Tag::Context(1), 1).unwrap();
    }))
    .unwrap();
    assert_eq!(
        (e.alarms_active, e.alarms_suppressed),
        (AlarmModeBitmap::all(), Some(AlarmModeBitmap::VISUAL))
    );
    let e = AlarmsStateChangedEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 0).unwrap();
    }))
    .unwrap();
    assert_eq!(e.alarms_suppressed, None);
    let f = SensorFaultEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap();
    }))
    .unwrap();
    assert_eq!(f.sensor_fault, SensorFaultBitmap::GENERAL_FAULT);
}

// ---- M9-A3 B4: ValveConfigurationAndControl -------------------------------
//
// 1.4.2 ValveConfigurationControl.xml: nullable durations, states and levels,
// writable DefaultOpenDuration (nullable) and DefaultOpenLevel, Open (two
// optional fields, OpenDuration also nullable) and Close, events
// ValveStateChanged { ValveState, ValveLevel? } and ValveFault.

#[test]
fn valve_attributes_decode_and_writes_encode() {
    use clusters::valve_configuration_and_control::{
        decode_auto_close_time, decode_current_level, decode_current_state,
        decode_default_open_duration, decode_default_open_level, decode_level_step,
        decode_open_duration, decode_remaining_duration, decode_target_level, decode_target_state,
        decode_valve_fault, encode_default_open_duration, encode_default_open_level, Feature,
        StatusCodeEnum, ValveFaultBitmap, ValveStateEnum,
    };
    assert_eq!(
        (Feature::TS | Feature::LVL).bits(),
        3,
        "all-clusters' features"
    );
    // A closed valve with no countdown: chip nulls OpenDuration and
    // RemainingDuration (and AutoCloseTime with TS) on Close.
    assert_eq!(decode_open_duration(&null_attr()).unwrap(), Nullable::Null);
    assert_eq!(
        decode_remaining_duration(&null_attr()).unwrap(),
        Nullable::Null
    );
    assert_eq!(
        decode_auto_close_time(&null_attr()).unwrap(),
        Nullable::Null
    );
    assert_eq!(
        decode_auto_close_time(&uint_attr(0x0006_1A2B_3C4D_5E6F)).unwrap(),
        Nullable::Value(0x0006_1A2B_3C4D_5E6F)
    );
    assert_eq!(
        decode_remaining_duration(&uint_attr(59)).unwrap(),
        Nullable::Value(59)
    );
    assert_eq!(
        decode_current_state(&uint_attr(2)).unwrap(),
        Nullable::Value(ValveStateEnum::Transitioning)
    );
    assert_eq!(decode_target_state(&null_attr()).unwrap(), Nullable::Null);
    assert_eq!(
        decode_current_level(&uint_attr(50)).unwrap(),
        Nullable::Value(50)
    );
    assert_eq!(decode_target_level(&null_attr()).unwrap(), Nullable::Null);
    assert_eq!(decode_level_step(&uint_attr(2)).unwrap(), 2);
    assert_eq!(decode_default_open_level(&uint_attr(100)).unwrap(), 100);
    assert_eq!(
        decode_valve_fault(&uint_attr(0b10_0001)).unwrap(),
        ValveFaultBitmap::GENERAL_FAULT | ValveFaultBitmap::CURRENT_EXCEEDED
    );
    for v in [Nullable::Null, Nullable::Value(30)] {
        assert_eq!(
            decode_default_open_duration(&encode_default_open_duration(v)).unwrap(),
            v
        );
    }
    assert_eq!(encode_default_open_level(50), uint_attr(50));
    // The cluster-specific status chip answers Open/Close with during a fault.
    assert_eq!(
        StatusCodeEnum::from_raw(2),
        StatusCodeEnum::FailureDueToFault
    );
}

#[test]
fn valve_commands_encode_and_events_decode() {
    use clusters::valve_configuration_and_control::{
        encode_close, encode_open, ValveFaultBitmap, ValveFaultEvent, ValveStateChangedEvent,
        ValveStateEnum,
    };
    // OpenDuration: absent (use DefaultOpenDuration), null (open until
    // closed) and a value are three different requests.
    assert_eq!(encode_open(None, None), [0x15, 0x18]);
    assert_eq!(
        encode_open(Some(Nullable::Value(60)), None),
        struct_of(&|w| w.put_uint(Tag::Context(0), 60).unwrap())
    );
    assert_eq!(
        encode_open(Some(Nullable::Null), Some(50)),
        struct_of(&|w| {
            w.put_null(Tag::Context(0)).unwrap();
            w.put_uint(Tag::Context(1), 50).unwrap();
        })
    );
    assert_eq!(encode_close(), [0x15, 0x18]);
    // v1.4.2.0's server sends ValveState only; master adds ValveLevel with LVL.
    let e = ValveStateChangedEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap();
    }))
    .unwrap();
    assert_eq!((e.valve_state, e.valve_level), (ValveStateEnum::Open, None));
    let e = ValveStateChangedEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 0).unwrap();
        w.put_uint(Tag::Context(1), 0).unwrap();
    }))
    .unwrap();
    assert_eq!(
        (e.valve_state, e.valve_level),
        (ValveStateEnum::Closed, Some(0))
    );
    let f = ValveFaultEvent::decode(&struct_of(&|w| {
        w.put_uint(Tag::Context(0), 1).unwrap();
    }))
    .unwrap();
    assert_eq!(f.valve_fault, ValveFaultBitmap::GENERAL_FAULT);
    assert!(matches!(
        ValveStateChangedEvent::decode(&struct_of(&|_| {})),
        Err(matter_clusters::error::ClusterError::MissingField(
            "ValveState"
        ))
    ));
}
