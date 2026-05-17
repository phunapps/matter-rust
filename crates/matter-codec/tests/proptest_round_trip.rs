//! Property: `decode(encode(v)) == v` for arbitrary `(Tag, Value)`.
//!
//! Phase 4 of matter-codec. Catches encoder/decoder asymmetries that the
//! M0 vector harness can't see because the vectors are a finite hand-picked
//! sample. The proptest strategies generate values with bounded depth
//! (≤ 4) and bounded string/bytes length (≤ 64 chars/bytes).
//!
//! Floats exclude NaN because `NaN != NaN` would make the equality
//! assertion meaningless. Infinity is allowed (`Inf == Inf` is true).

// CLAUDE.md test-code carve-out: unwrap / expect with documented justification.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use matter_codec::{Tag, TlvReader, TlvWriter, Value};
use proptest::prelude::*;

fn arb_tag() -> impl Strategy<Value = Tag> {
    prop_oneof![
        Just(Tag::Anonymous),
        any::<u8>().prop_map(Tag::Context),
        any::<u32>().prop_map(Tag::CommonProfile),
        any::<u32>().prop_map(Tag::ImplicitProfile),
        (any::<u16>(), any::<u16>(), any::<u32>()).prop_map(|(vendor, profile, tag)| {
            Tag::FullyQualified {
                vendor,
                profile,
                tag,
            }
        }),
    ]
}

/// Generates an arbitrary scalar `Value`. Used as the leaf for the
/// recursive container strategy in task 2.
fn arb_scalar_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        any::<u64>().prop_map(Value::Uint),
        any::<i64>().prop_map(Value::Int),
        any::<f32>()
            .prop_filter("no NaN", |f| !f.is_nan())
            .prop_map(Value::Float),
        any::<f64>()
            .prop_filter("no NaN", |f| !f.is_nan())
            .prop_map(Value::Double),
        Just(Value::Null),
        prop::string::string_regex(".{0,64}")
            .unwrap()
            .prop_map(Value::Utf8),
        prop::collection::vec(any::<u8>(), 0..=64).prop_map(Value::Bytes),
    ]
}

/// Generates an arbitrary `Value`, scalar or container, bounded to depth
/// 4. Container children also use this strategy via `prop_recursive`.
fn arb_value() -> impl Strategy<Value = Value> {
    arb_scalar_value().prop_recursive(
        4,  // max depth
        32, // max total nodes
        4,  // max children per container
        |inner| {
            prop_oneof![
                prop::collection::vec((arb_tag(), inner.clone()), 0..=4).prop_map(Value::Structure),
                prop::collection::vec(inner.clone(), 0..=4).prop_map(Value::Array),
                prop::collection::vec((arb_tag(), inner), 0..=4).prop_map(Value::List),
            ]
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Scalar round-trip identity.
    #[test]
    fn scalar_round_trip(tag in arb_tag(), value in arb_scalar_value()) {
        let mut buf = Vec::new();
        TlvWriter::new(&mut buf).write_value(tag, &value).unwrap();
        let (decoded_tag, decoded_value) = TlvReader::new(&buf).read_value().unwrap();
        prop_assert_eq!(decoded_tag, tag);
        prop_assert_eq!(decoded_value, value);
    }

    /// Full round-trip identity including containers up to depth 4.
    #[test]
    fn full_round_trip(tag in arb_tag(), value in arb_value()) {
        let mut buf = Vec::new();
        TlvWriter::new(&mut buf).write_value(tag, &value).unwrap();
        let (decoded_tag, decoded_value) = TlvReader::new(&buf).read_value().unwrap();
        prop_assert_eq!(decoded_tag, tag);
        // For Array specifically: the writer forces Tag::Anonymous on
        // every element regardless of input, and the reader discards
        // child tags. Both directions agree because `value` is the
        // outer Value, not the inner element tags. The structural
        // recursion bottoms out at scalars where tags are non-existent
        // (scalars carry no tag of their own — the tag belongs to the
        // element slot, supplied by the container parent).
        prop_assert_eq!(decoded_value, value);
    }
}
