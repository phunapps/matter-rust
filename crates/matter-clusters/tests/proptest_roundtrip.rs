//! Property: for codecs with both encode and decode, `decode(encode(x)) == x`
//! across the value space, including `Nullable` permutations.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use matter_clusters::gen;
use matter_clusters::types::Nullable;
use proptest::prelude::*;

proptest! {
    #[test]
    fn on_time_roundtrip(v in any::<u16>()) {
        let bytes = gen::on_off::encode_on_time(v);
        prop_assert_eq!(gen::on_off::decode_on_time(&bytes).unwrap(), v);
    }

    #[test]
    fn node_label_roundtrip(s in ".{0,32}") {
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
}
