//! Property: for codecs with both encode and decode, `decode(encode(x)) == x`
//! across the value space, including `Nullable` permutations.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use matter_clusters::clusters;
use matter_clusters::types::Nullable;
use matter_codec::{Tag, TlvWriter};
use proptest::prelude::*;

proptest! {
    #[test]
    fn on_time_roundtrip(v in any::<u16>()) {
        let bytes = clusters::on_off::encode_on_time(v);
        prop_assert_eq!(clusters::on_off::decode_on_time(&bytes).unwrap(), v);
    }

    #[test]
    // Exclude IS1 (0x1F): the codec truncates UTF-8 at the localized-string
    // separator by design (CODEC-1), so a raw 0x1F is outside the round-trip
    // domain — mirrors matter-codec's own proptest regex.
    fn node_label_roundtrip(s in "[^\u{1F}]{0,32}") {
        let bytes = clusters::basic_information::encode_node_label(&s);
        prop_assert_eq!(clusters::basic_information::decode_node_label(&bytes).unwrap(), s);
    }

    #[test]
    fn start_up_on_off_roundtrip(raw in any::<u8>()) {
        // Nullable enum: null + every raw value (known variants + Unknown).
        let val = if raw == 255 {
            Nullable::Null
        } else {
            Nullable::Value(clusters::on_off::StartUpOnOffEnum::from_raw(raw))
        };
        let bytes = clusters::on_off::encode_start_up_on_off(val);
        prop_assert_eq!(clusters::on_off::decode_start_up_on_off(&bytes).unwrap(), val);
    }

    // ---- M9-A2.3 actuator batch ------------------------------------------

    #[test]
    fn thermostat_occupied_cooling_setpoint_roundtrip(v in any::<i16>()) {
        let bytes = clusters::thermostat::encode_occupied_cooling_setpoint(v);
        prop_assert_eq!(clusters::thermostat::decode_occupied_cooling_setpoint(&bytes).unwrap(), v);
    }

    #[test]
    fn thermostat_local_temperature_calibration_roundtrip(v in any::<i8>()) {
        // SignedTemperature (int8) — proves the gap-4 scalar-typedef de-aliasing.
        let bytes = clusters::thermostat::encode_local_temperature_calibration(v);
        prop_assert_eq!(clusters::thermostat::decode_local_temperature_calibration(&bytes).unwrap(), v);
    }

    #[test]
    fn thermostat_system_mode_roundtrip(raw in any::<u8>()) {
        let v = clusters::thermostat::SystemModeEnum::from_raw(raw);
        let bytes = clusters::thermostat::encode_system_mode(v);
        prop_assert_eq!(clusters::thermostat::decode_system_mode(&bytes).unwrap(), v);
    }

    #[test]
    fn thermostat_remote_sensing_roundtrip(raw in any::<u8>()) {
        let v = clusters::thermostat::RemoteSensingBitmap::from_bits_retain(raw);
        let bytes = clusters::thermostat::encode_remote_sensing(v);
        prop_assert_eq!(clusters::thermostat::decode_remote_sensing(&bytes).unwrap(), v);
    }

    #[test]
    fn fan_control_fan_mode_roundtrip(raw in any::<u8>()) {
        let v = clusters::fan_control::FanModeEnum::from_raw(raw);
        let bytes = clusters::fan_control::encode_fan_mode(v);
        prop_assert_eq!(clusters::fan_control::decode_fan_mode(&bytes).unwrap(), v);
    }

    #[test]
    fn fan_control_percent_setting_roundtrip(raw in any::<u8>()) {
        // Nullable<u8>: null + every value.
        let v = if raw == 255 { Nullable::Null } else { Nullable::Value(raw) };
        let bytes = clusters::fan_control::encode_percent_setting(v);
        prop_assert_eq!(clusters::fan_control::decode_percent_setting(&bytes).unwrap(), v);
    }

    #[test]
    fn tuic_keypad_lockout_roundtrip(raw in any::<u8>()) {
        let v = clusters::thermostat_user_interface_configuration::KeypadLockoutEnum::from_raw(raw);
        let bytes = clusters::thermostat_user_interface_configuration::encode_keypad_lockout(v);
        prop_assert_eq!(
            clusters::thermostat_user_interface_configuration::decode_keypad_lockout(&bytes).unwrap(),
            v
        );
    }

    #[test]
    fn pump_operation_mode_roundtrip(raw in any::<u8>()) {
        let v = clusters::pump_configuration_and_control::OperationModeEnum::from_raw(raw);
        let bytes = clusters::pump_configuration_and_control::encode_operation_mode(v);
        prop_assert_eq!(
            clusters::pump_configuration_and_control::decode_operation_mode(&bytes).unwrap(),
            v
        );
    }

    #[test]
    fn window_covering_mode_roundtrip(raw in any::<u8>()) {
        let v = clusters::window_covering::ModeBitmap::from_bits_retain(raw);
        let bytes = clusters::window_covering::encode_mode(v);
        prop_assert_eq!(clusters::window_covering::decode_mode(&bytes).unwrap(), v);
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
        match clusters::carbon_dioxide_concentration_measurement::decode_measured_value(&buf).unwrap() {
            Nullable::Value(d) => prop_assert_eq!(d.to_bits(), v.to_bits()),
            Nullable::Null => prop_assert!(false, "float decoded as null"),
        }
    }

    // ---- M9-A3 B2: ModeBase-derived clusters -------------------------------

    #[test]
    fn mode_tag_struct_decodes(mfg in proptest::option::of(any::<u16>()), value in any::<u16>()) {
        // ModeTagStruct (an optional MfgCode and an enum16 value) as chip
        // sends it in SupportedModes: every field decodes, the optional MfgCode
        // omitted or present and a value outside the codegen's known tags kept
        // (ModeTag::Unknown). All nine ModeBase derivatives emit this struct
        // from one template. Decode-only since M9-A3 B4: nothing a client
        // sends carries it, so it has no encoder.
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
        let t = clusters::rvc_run_mode::ModeTagStruct::decode(&bytes).unwrap();
        prop_assert_eq!(t.mfg_code, mfg);
        prop_assert_eq!(t.value.to_raw(), value);
    }

    // ---- M9-A3 B2: AlarmBase-derived clusters -------------------------------

    #[test]
    fn alarm_bitmap_wire_roundtrip(bits in any::<u32>()) {
        // AlarmBitmap is map32: encoded by Reset/ModifyEnabledAlarms, decoded
        // from the four attributes and Notify. Every 32-bit pattern must
        // survive the wire both ways, unknown bits included (from_bits_retain).
        use clusters::dishwasher_alarm::{decode_state, encode_reset, AlarmBitmap};
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
    fn error_state_struct_decodes(
        id in any::<u8>(),
        label in proptest::option::of("[a-z ]{0,16}"),
        details in proptest::option::of("[a-z ]{0,16}"),
    ) {
        // ErrorStateStruct (enum8 + two optional strings), the payload of
        // OperationalError, OperationalCommandResponse and the OperationalError
        // event in all three OperationalState-family clusters (one template):
        // every field decodes, an id outside the known set included.
        // Decode-only since M9-A3 B4: no request or writable attribute
        // carries it.
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
        let e = clusters::operational_state::ErrorStateStruct::decode(&bytes).unwrap();
        prop_assert_eq!(e.error_state_id.to_raw(), id);
        prop_assert_eq!(&e.error_state_label, &label);
        prop_assert_eq!(&e.error_state_details, &details);
    }

    // ---- M9-A3 B3: ServiceArea ---------------------------------------------

    #[test]
    fn location_descriptor_struct_decodes(
        name in "[A-Za-z ]{0,16}",
        floor in proptest::option::of(any::<i16>()),
        area_type in proptest::option::of(any::<u8>()),
    ) {
        // The global `locationdesc` (generated as LocationDescriptorStruct):
        // a nullable signed field and a nullable `tag` (raw uint8), every
        // permutation of null, negative floors included.
        let mut bytes = Vec::new();
        {
            let mut w = TlvWriter::new(&mut bytes);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_utf8(Tag::Context(0), &name).unwrap();
            match floor {
                Some(f) => w.put_int(Tag::Context(1), i64::from(f)).unwrap(),
                None => w.put_null(Tag::Context(1)).unwrap(),
            }
            match area_type {
                Some(t) => w.put_uint(Tag::Context(2), u64::from(t)).unwrap(),
                None => w.put_null(Tag::Context(2)).unwrap(),
            }
            w.end_container().unwrap();
        }
        let l = clusters::service_area::LocationDescriptorStruct::decode(&bytes).unwrap();
        prop_assert_eq!(&l.location_name, &name);
        prop_assert_eq!(l.floor_number, floor.map_or(Nullable::Null, Nullable::Value));
        prop_assert_eq!(l.area_type, area_type.map_or(Nullable::Null, Nullable::Value));
    }

    #[test]
    fn progress_struct_decodes(
        area in any::<u32>(),
        status in any::<u8>(),
        total in proptest::option::of(proptest::option::of(any::<u32>())),
        estimated in proptest::option::of(proptest::option::of(any::<u32>())),
    ) {
        // ProgressStruct's two `Option<Nullable<u32>>` fields: absent, null
        // and a value are three different wire shapes, and all must survive.
        let put = |w: &mut TlvWriter<'_>, tag: u8, v: Option<Option<u32>>| match v {
            None => {}
            Some(None) => w.put_null(Tag::Context(tag)).unwrap(),
            Some(Some(x)) => w.put_uint(Tag::Context(tag), u64::from(x)).unwrap(),
        };
        let mut bytes = Vec::new();
        {
            let mut w = TlvWriter::new(&mut bytes);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), u64::from(area)).unwrap();
            w.put_uint(Tag::Context(1), u64::from(status)).unwrap();
            put(&mut w, 2, total);
            put(&mut w, 3, estimated);
            w.end_container().unwrap();
        }
        let as_nullable = |v: Option<Option<u32>>| v.map(|x| x.map_or(Nullable::Null, Nullable::Value));
        let p = clusters::service_area::ProgressStruct::decode(&bytes).unwrap();
        prop_assert_eq!((p.area_id, p.status.to_raw()), (area, status));
        prop_assert_eq!(p.total_operational_time, as_nullable(total));
        prop_assert_eq!(p.estimated_time, as_nullable(estimated));
    }

    // ---- M9-A3 B4: Thermostat weekly schedule (supplemented SCH) ----------

    #[test]
    fn weekly_schedule_transition_reencodes(
        time in 0u16..=1439,
        heat in proptest::option::of(any::<i16>()),
        cool in proptest::option::of(any::<i16>()),
    ) {
        // WeeklyScheduleTransitionStruct: a uint16 and two nullable signed
        // temperatures. SetWeeklySchedule sends a list of them (the first
        // request list whose entries carry null), so null and negative values
        // must survive decode -> encode byte for byte.
        let put = |w: &mut TlvWriter<'_>, tag: u8, v: Option<i16>| match v {
            None => w.put_null(Tag::Context(tag)).unwrap(),
            Some(x) => w.put_int(Tag::Context(tag), i64::from(x)).unwrap(),
        };
        let mut bytes = Vec::new();
        {
            let mut w = TlvWriter::new(&mut bytes);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), u64::from(time)).unwrap();
            put(&mut w, 1, heat);
            put(&mut w, 2, cool);
            w.end_container().unwrap();
        }
        let as_nullable = |v: Option<i16>| v.map_or(Nullable::Null, Nullable::Value);
        let t = clusters::thermostat::WeeklyScheduleTransitionStruct::decode(&bytes).unwrap();
        prop_assert_eq!(t.transition_time, time);
        prop_assert_eq!(t.heat_setpoint, as_nullable(heat));
        prop_assert_eq!(t.cool_setpoint, as_nullable(cool));
        prop_assert_eq!(t.encode(), bytes);
    }

    // ---- M9-A3 B4: ScenesManagement ----------------------------------------

    #[test]
    fn attribute_value_pair_reencodes(
        attribute in any::<u32>(),
        which in 0u8..8,
        raw in any::<u64>(),
    ) {
        // AttributeValuePairStruct: an attribute id plus exactly one of eight
        // optional value fields (choice group a), unsigned or signed, 8 to 64
        // bits. AddScene sends a list of them inside each ExtensionFieldSetStruct;
        // decode -> encode must give the same bytes for every variant.
        let mut bytes = Vec::new();
        {
            let mut w = TlvWriter::new(&mut bytes);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), u64::from(attribute)).unwrap();
            let tag = Tag::Context(which + 1);
            // Truncate `raw` to the variant's width (wrapping casts are the point).
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            match which {
                0 => w.put_uint(tag, u64::from(raw as u8)).unwrap(),
                1 => w.put_int(tag, i64::from(raw as i8)).unwrap(),
                2 => w.put_uint(tag, u64::from(raw as u16)).unwrap(),
                3 => w.put_int(tag, i64::from(raw as i16)).unwrap(),
                4 => w.put_uint(tag, u64::from(raw as u32)).unwrap(),
                5 => w.put_int(tag, i64::from(raw as i32)).unwrap(),
                6 => w.put_uint(tag, raw).unwrap(),
                _ => w.put_int(tag, raw as i64).unwrap(),
            }
            w.end_container().unwrap();
        }
        let p = clusters::scenes_management::AttributeValuePairStruct::decode(&bytes).unwrap();
        prop_assert_eq!(p.attribute_id, attribute);
        let present = [
            p.value_unsigned8.is_some(),
            p.value_signed8.is_some(),
            p.value_unsigned16.is_some(),
            p.value_signed16.is_some(),
            p.value_unsigned32.is_some(),
            p.value_signed32.is_some(),
            p.value_unsigned64.is_some(),
            p.value_signed64.is_some(),
        ];
        prop_assert_eq!(present.iter().filter(|b| **b).count(), 1);
        prop_assert!(present[usize::from(which)]);
        prop_assert_eq!(p.encode(), bytes);
    }
}
