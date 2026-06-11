//! Matter Interaction Model (IM) message framing — Matter Core Spec §10.
//!
//! Builders for the IM message envelopes the wire carries
//! (`InvokeRequestMessage`, `ReadRequestMessage`, `WriteRequestMessage`,
//! `SubscribeRequestMessage`, `StatusResponseMessage`)
//! and parsers for the responses (`InvokeResponseMessage`,
//! `ReportDataMessage`, `WriteResponseMessage`, `SubscribeResponseMessage`).
//! Callers supply already-encoded cluster TLV payloads (e.g. from
//! `matter-clusters` codecs) and compose them with the concrete paths in
//! [`path`].
//!
//! Scope is a deliberate subset: one command per invoke, concrete
//! (non-wildcard) paths, no events, no timed actions, no chunked writes.
//!
//! Lifted from `matter-commissioning` in M7.1 (the M6.6 design kept this
//! module free of state-machine dependencies for exactly this move).
//! Byte-parity with matter.js is enforced by `tests/im_byte_parity.rs`
//! against fixtures captured via `cargo xtask capture-im`.

#![forbid(unsafe_code)]

pub mod error;
pub mod invoke;
pub mod path;
pub mod read;
pub mod status;
pub mod subscription;
pub mod write;

pub use error::ImError;
pub use invoke::{build_invoke_request, parse_invoke_response, InvokeResponse};
pub use path::{AttributePath, CommandPath, ReadPath};
pub use read::{build_read_request, build_read_request_paths, parse_report_data, ReportData};
pub use status::ImStatus;
pub use subscription::{
    build_status_response, build_subscribe_request, parse_subscribe_response, SubscribeRequest,
    SubscribeResponse,
};
pub use write::{build_write_request, parse_write_response, AttributeWriteRequest};

/// Interaction Model protocol revision emitted at context tag `0xFF` in
/// every top-level IM message. Confirmed against the matter.js byte-parity
/// fixture (see `tests/im_byte_parity.rs`); bump only when a captured
/// fixture proves matter.js changed it.
pub const IM_REVISION: u8 = 11;

use matter_codec::{ContainerKind, Element, Tag, TlvReader, Value};

/// Assert the reader's first element is an anonymous message struct and
/// consume its start.
///
/// # Errors
///
/// Returns [`error::ImError::NotAStruct`] if the first element is not an
/// anonymous structure start, or propagates any [`error::ImError::Codec`]
/// error from the reader.
pub fn expect_message_struct(r: &mut TlvReader<'_>) -> Result<(), error::ImError> {
    match r.next()? {
        Some(Element::ContainerStart {
            tag: Tag::Anonymous,
            kind: ContainerKind::Structure,
        }) => Ok(()),
        Some(_) | None => Err(error::ImError::NotAStruct),
    }
}

/// Reader positioned just after a container start: consume to its matching
/// end, returning the members as `(tag, value)` pairs (for List/Structure).
/// Calling this with the reader in any other position yields an
/// [`error::ImError`] or misattributed members — never a panic or UB.
///
/// # Errors
///
/// Returns [`error::ImError::Codec`] wrapping
/// [`matter_codec::Error::UnclosedContainer`] if the input ends before a
/// matching end-of-container, or propagates any other codec error.
pub fn read_container_members(r: &mut TlvReader<'_>) -> Result<Vec<(Tag, Value)>, error::ImError> {
    let mut out = Vec::new();
    loop {
        match r.next()? {
            None => {
                return Err(error::ImError::Codec(
                    matter_codec::Error::UnclosedContainer,
                ))
            }
            Some(Element::ContainerEnd) => return Ok(out),
            Some(Element::Scalar { tag, value }) => out.push((tag, value)),
            Some(Element::ContainerStart { tag, kind }) => {
                let v = read_container_value(r, kind)?;
                out.push((tag, v));
            }
            Some(_) => {}
        }
    }
}

/// Reader positioned just after a container start (of `kind`): read the
/// whole sub-tree into a [`Value`]. Calling this with the reader in any other
/// position yields an [`error::ImError`] or misattributed members — never a
/// panic or UB.
///
/// # Errors
///
/// Propagates any error from [`read_container_members`].
pub fn read_container_value(
    r: &mut TlvReader<'_>,
    kind: ContainerKind,
) -> Result<Value, error::ImError> {
    let members = read_container_members(r)?;
    Ok(match kind {
        ContainerKind::Structure => Value::Structure(members),
        ContainerKind::Array => Value::Array(members.into_iter().map(|(_, v)| v).collect()),
        // ContainerKind::List and any future non-exhaustive variants: preserve as List.
        _ => Value::List(members),
    })
}

/// Reader positioned just after a container start: discard the whole
/// sub-tree (used to skip fields we do not consume). Calling this with the
/// reader in any other position yields an [`error::ImError`] or misattributed
/// members — never a panic or UB.
///
/// # Errors
///
/// Propagates any error from [`read_container_members`].
pub fn skip_container(r: &mut TlvReader<'_>) -> Result<(), error::ImError> {
    let _ = read_container_members(r)?;
    Ok(())
}
