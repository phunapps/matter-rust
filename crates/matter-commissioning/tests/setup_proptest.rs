//! Property-based roundtrip tests for `matter_commissioning::setup`.
//!
//! For every valid `SetupPayload`, the QR and manual-code encoders produce
//! strings that the corresponding decoders return back to the same value.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use matter_commissioning::setup::{
    encode_manual_code, encode_qr, parse_manual_code, parse_qr, CommissioningFlow, Discriminator,
    DiscoveryCapabilities, Passcode, SetupPayload, DISALLOWED_PASSCODES,
};
use proptest::prelude::*;

fn arb_passcode() -> impl Strategy<Value = Passcode> {
    (1u32..(1 << 27))
        .prop_filter("disallowed-trivial", |v| !DISALLOWED_PASSCODES.contains(v))
        .prop_map(|v| Passcode::new(v).expect("filtered"))
}

fn arb_discriminator() -> impl Strategy<Value = Discriminator> {
    (0u16..=0x0FFF).prop_map(|v| Discriminator::new(v).expect("range-checked"))
}

fn arb_flow_qr() -> impl Strategy<Value = CommissioningFlow> {
    // Custom is encodable per the spec but matter-rust rejects it on
    // encode (Error::CustomFlowUnsupported). Restrict QR proptests to
    // the two we can roundtrip.
    prop_oneof![
        Just(CommissioningFlow::Standard),
        Just(CommissioningFlow::UserIntent),
    ]
}

fn arb_caps() -> impl Strategy<Value = DiscoveryCapabilities> {
    // Only the three defined bits; reserved bits are tested separately
    // in setup_byte_parity.rs via the captured fixtures.
    (0u8..=0b111).prop_map(DiscoveryCapabilities::from_bits_retain)
}

fn arb_payload_qr() -> impl Strategy<Value = SetupPayload> {
    (
        any::<u16>(),
        any::<u16>(),
        arb_flow_qr(),
        arb_caps(),
        arb_discriminator(),
        arb_passcode(),
    )
        .prop_map(|(vid, pid, flow, caps, disc, pass)| SetupPayload {
            version: 0,
            vendor_id: Some(vid),
            product_id: Some(pid),
            commissioning_flow: flow,
            discovery_capabilities: caps,
            discriminator: disc,
            passcode: pass,
        })
}

fn arb_payload_manual_11() -> impl Strategy<Value = SetupPayload> {
    // Manual code zero-extends to 12-bit discriminator, so generate the
    // short form directly (upper 4 bits only).
    ((0u16..=0x0F), arb_passcode()).prop_map(|(short, passcode)| SetupPayload {
        version: 0,
        vendor_id: None,
        product_id: None,
        commissioning_flow: CommissioningFlow::Standard,
        discovery_capabilities: DiscoveryCapabilities::empty(),
        discriminator: Discriminator::new(short << 8).expect("4-bit"),
        passcode,
    })
}

fn arb_payload_manual_21() -> impl Strategy<Value = SetupPayload> {
    ((0u16..=0x0F), any::<u16>(), any::<u16>(), arb_passcode()).prop_map(
        |(short, vid, pid, passcode)| SetupPayload {
            version: 0,
            vendor_id: Some(vid),
            product_id: Some(pid),
            commissioning_flow: CommissioningFlow::Standard,
            discovery_capabilities: DiscoveryCapabilities::empty(),
            discriminator: Discriminator::new(short << 8).expect("4-bit"),
            passcode,
        },
    )
}

proptest! {
    #[test]
    fn qr_roundtrip(payload in arb_payload_qr()) {
        let s = encode_qr(&payload).expect("valid QR payload");
        let back = parse_qr(&s).expect("parse the encoded string");
        prop_assert_eq!(payload, back);
    }

    #[test]
    fn manual_11_roundtrip(payload in arb_payload_manual_11()) {
        let s = encode_manual_code(&payload);
        let back = parse_manual_code(&s).expect("parse the encoded code");
        prop_assert_eq!(payload, back);
    }

    #[test]
    fn manual_21_roundtrip(payload in arb_payload_manual_21()) {
        let s = encode_manual_code(&payload);
        let back = parse_manual_code(&s).expect("parse the encoded code");
        prop_assert_eq!(payload, back);
    }
}
