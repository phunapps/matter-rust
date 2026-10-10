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
