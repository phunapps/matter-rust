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
}
