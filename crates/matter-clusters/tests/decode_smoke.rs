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
