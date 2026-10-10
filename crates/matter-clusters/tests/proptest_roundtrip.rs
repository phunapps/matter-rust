//! Property: for codecs with both encode and decode, `decode(encode(x)) == x`
//! across the value space, including `Nullable` permutations.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use matter_clusters::gen;
use matter_clusters::types::Nullable;
use matter_codec::{Tag, TlvWriter};
use proptest::prelude::*;

proptest! {
    #[test]
    fn on_time_roundtrip(v in any::<u16>()) {
        let bytes = gen::on_off::encode_on_time(v);
        prop_assert_eq!(gen::on_off::decode_on_time(&bytes).unwrap(), v);
    }

    #[test]
    // Exclude IS1 (0x1F): the codec truncates UTF-8 at the localized-string
    // separator by design (CODEC-1), so a raw 0x1F is outside the round-trip
    // domain — mirrors matter-codec's own proptest regex.
    fn node_label_roundtrip(s in "[^\u{1F}]{0,32}") {
        let bytes = gen::basic_information::encode_node_label(&s);
        prop_assert_eq!(gen::basic_information::decode_node_label(&bytes).unwrap(), s);
    }

    #[test]
    fn start_up_on_off_roundtrip(raw in any::<u8>()) {
        // Nullable enum: null + every raw value (known variants + Unknown).
        let val = if raw == 255 {
            Nullable::Null
        } else {
            Nullable::Value(gen::on_off::StartUpOnOffEnum::from_raw(raw))
        };
        let bytes = gen::on_off::encode_start_up_on_off(val);
        prop_assert_eq!(gen::on_off::decode_start_up_on_off(&bytes).unwrap(), val);
    }

    // ---- M9-A2.3 actuator batch ------------------------------------------

    #[test]
    fn thermostat_occupied_cooling_setpoint_roundtrip(v in any::<i16>()) {
        let bytes = gen::thermostat::encode_occupied_cooling_setpoint(v);
        prop_assert_eq!(gen::thermostat::decode_occupied_cooling_setpoint(&bytes).unwrap(), v);
    }

    #[test]
    fn thermostat_local_temperature_calibration_roundtrip(v in any::<i8>()) {
        // SignedTemperature (int8) — proves the gap-4 scalar-typedef de-aliasing.
        let bytes = gen::thermostat::encode_local_temperature_calibration(v);
        prop_assert_eq!(gen::thermostat::decode_local_temperature_calibration(&bytes).unwrap(), v);
    }

    #[test]
    fn thermostat_system_mode_roundtrip(raw in any::<u8>()) {
        let v = gen::thermostat::SystemModeEnum::from_raw(raw);
        let bytes = gen::thermostat::encode_system_mode(v);
        prop_assert_eq!(gen::thermostat::decode_system_mode(&bytes).unwrap(), v);
    }

    #[test]
    fn thermostat_remote_sensing_roundtrip(raw in any::<u8>()) {
        let v = gen::thermostat::RemoteSensingBitmap::from_bits_retain(raw);
        let bytes = gen::thermostat::encode_remote_sensing(v);
        prop_assert_eq!(gen::thermostat::decode_remote_sensing(&bytes).unwrap(), v);
    }

    #[test]
    fn fan_control_fan_mode_roundtrip(raw in any::<u8>()) {
        let v = gen::fan_control::FanModeEnum::from_raw(raw);
        let bytes = gen::fan_control::encode_fan_mode(v);
        prop_assert_eq!(gen::fan_control::decode_fan_mode(&bytes).unwrap(), v);
    }

    #[test]
    fn fan_control_percent_setting_roundtrip(raw in any::<u8>()) {
        // Nullable<u8>: null + every value.
        let v = if raw == 255 { Nullable::Null } else { Nullable::Value(raw) };
        let bytes = gen::fan_control::encode_percent_setting(v);
        prop_assert_eq!(gen::fan_control::decode_percent_setting(&bytes).unwrap(), v);
    }

    #[test]
    fn tuic_keypad_lockout_roundtrip(raw in any::<u8>()) {
        let v = gen::thermostat_user_interface_configuration::KeypadLockoutEnum::from_raw(raw);
        let bytes = gen::thermostat_user_interface_configuration::encode_keypad_lockout(v);
        prop_assert_eq!(
            gen::thermostat_user_interface_configuration::decode_keypad_lockout(&bytes).unwrap(),
            v
        );
    }

    #[test]
    fn pump_operation_mode_roundtrip(raw in any::<u8>()) {
        let v = gen::pump_configuration_and_control::OperationModeEnum::from_raw(raw);
        let bytes = gen::pump_configuration_and_control::encode_operation_mode(v);
        prop_assert_eq!(
            gen::pump_configuration_and_control::decode_operation_mode(&bytes).unwrap(),
            v
        );
    }

    #[test]
    fn window_covering_mode_roundtrip(raw in any::<u8>()) {
        let v = gen::window_covering::ModeBitmap::from_bits_retain(raw);
        let bytes = gen::window_covering::encode_mode(v);
        prop_assert_eq!(gen::window_covering::decode_mode(&bytes).unwrap(), v);
    }

    // ---- concentration measurement (#112): the first float on the wire ----

    #[test]
    fn co2_measured_value_wire_roundtrip(bits in any::<u32>()) {
        // These clusters are read-only, so there is no generated `encode_*`;
        // the codec's `put_float` is the encoder half. Drawing the raw BITS
        // (rather than `any::<f32>()`) draws uniformly from the *whole*
        // binary32 space — every NaN payload, infinity and subnormal is
        // reachable, which `any::<f32>()` shrinking toward tidy finite values
        // is not. It does not follow that a run hits them: at the default 256
        // cases the two infinities are essentially never drawn, and NaNs and
        // subnormals about once each. Those edges are covered explicitly, by
        // `float_wire_roundtrip_including_edge_values` in `decode_smoke.rs`;
        // what this test adds is breadth over the ordinary space.
        //
        // Compared by bits as well: `f32::NAN != f32::NAN` and `0.0 == -0.0`
        // under value equality, so a naive `prop_assert_eq!` would either flake
        // on NaN or quietly accept a lost sign.
        let v = f32::from_bits(bits);
        let mut buf = Vec::new();
        TlvWriter::new(&mut buf).put_float(Tag::Anonymous, v).unwrap();
        match gen::carbon_dioxide_concentration_measurement::decode_measured_value(&buf).unwrap() {
            Nullable::Value(d) => prop_assert_eq!(d.to_bits(), v.to_bits()),
            Nullable::Null => prop_assert!(false, "float decoded as null"),
        }
    }

    // ---- M9-A3 B2: ModeBase-derived clusters -------------------------------

    #[test]
    fn mode_tag_struct_reencodes(mfg in proptest::option::of(any::<u16>()), value in any::<u16>()) {
        // ModeTagStruct has scalar fields only, so the emitter gives it
        // write_fields/encode as well as decode. It is #[non_exhaustive], so it
        // is built by decoding chip-shaped bytes; decode -> encode must give the
        // same bytes back. Covers omitting the optional MfgCode and an enum16
        // value outside the codegen's known tags (ModeTag::Unknown). All nine
        // ModeBase derivatives emit this struct from one template.
        let mut bytes = Vec::new();
        {
            let mut w = TlvWriter::new(&mut bytes);
            w.start_structure(Tag::Anonymous).unwrap();
            if let Some(m) = mfg {
                w.put_uint(Tag::Context(0), u64::from(m)).unwrap();
            }
            w.put_uint(Tag::Context(1), u64::from(value)).unwrap();
            w.end_container().unwrap();
        }
        let t = gen::rvc_run_mode::ModeTagStruct::decode(&bytes).unwrap();
        prop_assert_eq!(t.mfg_code, mfg);
        prop_assert_eq!(t.value.to_raw(), value);
        prop_assert_eq!(t.encode(), bytes);
    }

    // ---- M9-A3 B2: AlarmBase-derived clusters -------------------------------

    #[test]
    fn alarm_bitmap_wire_roundtrip(bits in any::<u32>()) {
        // AlarmBitmap is map32: encoded by Reset/ModifyEnabledAlarms, decoded
        // from the four attributes and Notify. Every 32-bit pattern must
        // survive the wire both ways, unknown bits included (from_bits_retain).
        use gen::dishwasher_alarm::{decode_state, encode_reset, AlarmBitmap};
        let v = AlarmBitmap::from_bits_retain(bits);
        let mut attr = Vec::new();
        TlvWriter::new(&mut attr).put_uint(Tag::Anonymous, u64::from(bits)).unwrap();
        prop_assert_eq!(decode_state(&attr).unwrap(), v);
        let mut cmd = Vec::new();
        {
            let mut w = TlvWriter::new(&mut cmd);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), u64::from(bits)).unwrap();
            w.end_container().unwrap();
        }
        prop_assert_eq!(encode_reset(v), cmd);
    }

    // ---- M9-A3 B3: OperationalState family ---------------------------------

    #[test]
    fn error_state_struct_reencodes(
        id in any::<u8>(),
        label in proptest::option::of("[a-z ]{0,16}"),
        details in proptest::option::of("[a-z ]{0,16}"),
    ) {
        // ErrorStateStruct (enum8 + two optional strings) has scalar fields
        // only, so it is encodable as well as decodable; it is the payload of
        // OperationalError, OperationalCommandResponse and the OperationalError
        // event in all three OperationalState-family clusters (one template).
        // Built by decoding (it is #[non_exhaustive]); decode -> encode must
        // give the same bytes, an id outside the known set included.
        let mut bytes = Vec::new();
        {
            let mut w = TlvWriter::new(&mut bytes);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), u64::from(id)).unwrap();
            if let Some(l) = &label {
                w.put_utf8(Tag::Context(1), l).unwrap();
            }
            if let Some(d) = &details {
                w.put_utf8(Tag::Context(2), d).unwrap();
            }
            w.end_container().unwrap();
        }
        let e = gen::operational_state::ErrorStateStruct::decode(&bytes).unwrap();
        prop_assert_eq!(e.error_state_id.to_raw(), id);
        prop_assert_eq!(&e.error_state_label, &label);
        prop_assert_eq!(&e.error_state_details, &details);
        prop_assert_eq!(e.encode(), bytes);
    }
}
