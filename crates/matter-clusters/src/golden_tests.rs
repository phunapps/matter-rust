//! Runtime checks on the generated golden fixture (`golden.rs`).
//!
//! `codegen_golden` proves the generator's output matches and compiles; these
//! tests prove what that output *does*. They pin the fabric-sensitive encode
//! rule (M9-A3 spec §5.4) on the fixture's `ScopedEntryStruct`: `Secret` and
//! `Kind` are fabric-sensitive fields the dump relaxed for decoding only
//! (`mandatoryOnWrite`), `Alias` is fabric-sensitive but optional in the model
//! itself, and `Note` is an ordinary optional field.

// Test-code carve-out for unwrap (CLAUDE.md): a failure here is a test failure.
#![allow(clippy::unwrap_used)]

use crate::error::ClusterError;
use crate::golden::{ModeEnum, ScopedEntryStruct};
use crate::types::Nullable;
use matter_codec::TlvWriter;

/// An entry as our own fabric reads it: every sensitive field present.
fn own_entry() -> ScopedEntryStruct {
    ScopedEntryStruct {
        secret: Some(7),
        kind: Some(Nullable::Value(ModeEnum::Manual)),
        note: None,
        alias: None,
        fabric_index: 2,
    }
}

#[test]
fn sensitive_struct_with_every_sensitive_field_encodes_and_roundtrips() {
    let bytes = own_entry().encode().unwrap();
    assert_eq!(ScopedEntryStruct::decode(&bytes).unwrap(), own_entry());
}

#[test]
fn sensitive_struct_refuses_a_missing_sensitive_scalar() {
    let entry = ScopedEntryStruct {
        secret: None,
        ..own_entry()
    };
    assert!(matches!(
        entry.encode(),
        Err(ClusterError::MissingField("Secret"))
    ));
}

#[test]
fn sensitive_struct_refuses_a_missing_sensitive_nullable_enum() {
    let entry = ScopedEntryStruct {
        kind: None,
        ..own_entry()
    };
    assert!(matches!(
        entry.encode(),
        Err(ClusterError::MissingField("Kind"))
    ));
}

#[test]
fn sensitive_nullable_field_set_to_null_is_present_not_missing() {
    // `Some(Null)` is a value the caller chose to send; only `None` (withheld)
    // is refused.
    let entry = ScopedEntryStruct {
        kind: Some(Nullable::Null),
        ..own_entry()
    };
    assert!(entry.encode().is_ok());
}

#[test]
fn non_sensitive_optional_field_may_still_be_absent() {
    assert!(own_entry().note.is_none());
    assert!(own_entry().encode().is_ok());
}

#[test]
fn model_optional_sensitive_field_may_be_absent_on_write() {
    // Only fields the dump relaxed are required on write; a sensitive field
    // that is optional in the model itself keeps ordinary omit-on-None.
    assert!(own_entry().alias.is_none());
    let with_alias = ScopedEntryStruct {
        alias: Some("hall".to_string()),
        ..own_entry()
    };
    let bytes = with_alias.encode().unwrap();
    assert_eq!(ScopedEntryStruct::decode(&bytes).unwrap(), with_alias);
}

#[test]
fn refused_write_fields_writes_nothing() {
    // Every sensitive field is checked before the first write, so a refusal
    // cannot leave a half-written structure in the caller's buffer.
    let entry = ScopedEntryStruct {
        kind: None,
        ..own_entry()
    };
    let mut buf = Vec::new();
    {
        let mut w = TlvWriter::new(&mut buf);
        assert!(entry.write_fields(&mut w).is_err());
    }
    assert!(buf.is_empty(), "refused write_fields wrote {buf:02x?}");
}

// ---- M9-A3 B7: nested structs and guarded lists in an encoded struct --------
//
// The fixture's `NestStruct` (reached by the `Nest` request) carries a nested
// struct in each guard form (mandatory, optional, nullable), a list of structs
// that is optional and nullable, an optional list of integers, a nullable list
// of enums and a `double`: the shapes ContentLauncher's request structs need.

use crate::golden::{NestStruct, PointStruct};
use matter_codec::Tag;

fn point(x: u16, y: u16) -> PointStruct {
    PointStruct { x, y }
}

/// Every optional field present and every nullable field a value.
fn full_nest() -> NestStruct {
    NestStruct {
        point: point(1, 2),
        maybe_point: Some(point(3, 4)),
        null_point: Nullable::Value(point(5, 6)),
        points: Some(Nullable::Value(vec![point(7, 8), point(9, 10)])),
        ids: Some(vec![11, 12]),
        modes: Nullable::Value(vec![ModeEnum::Auto, ModeEnum::Manual]),
        scale: 1.5,
    }
}

/// The same struct with every optional field absent and every nullable one
/// null.
fn sparse_nest() -> NestStruct {
    NestStruct {
        point: point(1, 2),
        maybe_point: None,
        null_point: Nullable::Null,
        points: None,
        ids: None,
        modes: Nullable::Null,
        scale: -0.25,
    }
}

/// `PointStruct { x, y }` written by hand at `tag`.
fn write_point(w: &mut TlvWriter<'_>, tag: Tag, x: u64, y: u64) {
    w.start_structure(tag).unwrap();
    w.put_uint(Tag::Context(0), x).unwrap();
    w.put_uint(Tag::Context(1), y).unwrap();
    w.end_container().unwrap();
}

#[test]
fn nested_struct_fields_and_guarded_lists_encode_field_by_field() {
    // Built element by element, independently of the generated writer: each
    // nested struct is a sub-structure at its context tag, each list an array
    // of anonymous elements, and `scale` a FLOAT64.
    let mut want = Vec::new();
    {
        let mut w = TlvWriter::new(&mut want);
        w.start_structure(Tag::Anonymous).unwrap();
        write_point(&mut w, Tag::Context(0), 1, 2);
        write_point(&mut w, Tag::Context(1), 3, 4);
        write_point(&mut w, Tag::Context(2), 5, 6);
        w.start_array(Tag::Context(3)).unwrap();
        write_point(&mut w, Tag::Anonymous, 7, 8);
        write_point(&mut w, Tag::Anonymous, 9, 10);
        w.end_container().unwrap();
        w.start_array(Tag::Context(4)).unwrap();
        w.put_uint(Tag::Anonymous, 11).unwrap();
        w.put_uint(Tag::Anonymous, 12).unwrap();
        w.end_container().unwrap();
        w.start_array(Tag::Context(5)).unwrap();
        w.put_uint(Tag::Anonymous, 0).unwrap();
        w.put_uint(Tag::Anonymous, 1).unwrap();
        w.end_container().unwrap();
        w.put_double(Tag::Context(6), 1.5).unwrap();
        w.end_container().unwrap();
    }
    assert_eq!(full_nest().encode(), want);
    assert_eq!(NestStruct::decode(&want).unwrap(), full_nest());
}

#[test]
fn absent_and_null_composite_fields_encode_differently() {
    // An absent optional field is left out; a null one is a TLV null at its
    // tag. Here MaybePoint, Points and Ids are absent, NullPoint and Modes
    // null.
    let mut want = Vec::new();
    {
        let mut w = TlvWriter::new(&mut want);
        w.start_structure(Tag::Anonymous).unwrap();
        write_point(&mut w, Tag::Context(0), 1, 2);
        w.put_null(Tag::Context(2)).unwrap();
        w.put_null(Tag::Context(5)).unwrap();
        w.put_double(Tag::Context(6), -0.25).unwrap();
        w.end_container().unwrap();
    }
    assert_eq!(sparse_nest().encode(), want);
    assert_eq!(NestStruct::decode(&want).unwrap(), sparse_nest());
    // A null list of structs is not an absent one.
    let null_points = NestStruct {
        points: Some(Nullable::Null),
        ..sparse_nest()
    };
    let bytes = null_points.encode();
    assert_ne!(bytes, want);
    assert_eq!(NestStruct::decode(&bytes).unwrap(), null_points);
}

#[test]
fn the_nest_request_carries_the_struct_at_its_context_tag() {
    // The command encoder opens the request field as a sub-structure and the
    // nested writes follow (the generated `encode_nest`).
    let bytes = crate::golden::encode_nest(full_nest());
    let mut want = Vec::new();
    {
        let mut w = TlvWriter::new(&mut want);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_structure(Tag::Context(0)).unwrap();
        full_nest().write_fields(&mut w);
        w.end_container().unwrap();
        w.end_container().unwrap();
    }
    assert_eq!(bytes, want);
}
