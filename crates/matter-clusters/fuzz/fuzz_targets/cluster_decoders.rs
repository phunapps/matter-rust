//! Fuzz target: a sampling of generated attribute decoders (one per metatype
//! family — scalar, enum, bitmap(u16), struct, list-of-scalars,
//! list-of-structs) must not panic on any input.
//!
//! Run locally with `cargo +nightly fuzz run cluster_decoders`. A decoder may
//! return `Err` for adversarial input — what it MUST NOT do is panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_clusters::gen;

fuzz_target!(|data: &[u8]| {
    let _ = gen::on_off::decode_on_time(data);
    let _ = gen::on_off::decode_start_up_on_off(data);
    let _ = gen::color_control::decode_color_capabilities(data);
    let _ = gen::basic_information::decode_capability_minima(data);
    let _ = gen::descriptor::decode_server_list(data);
    let _ = gen::descriptor::decode_device_type_list(data);
    let _ = gen::descriptor::decode_tag_list(data);
});
