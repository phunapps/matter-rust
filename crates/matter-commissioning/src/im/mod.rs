//! Interaction Model (IM) message framing — Matter Core Spec §10.
//!
//! The commissioning state machine ([`crate::state_machine`]) emits bare
//! cluster command/attribute TLV payloads. This module wraps them in the
//! IM message envelopes the wire actually carries (`InvokeRequestMessage`,
//! `ReadRequestMessage`) and parses the responses (`InvokeResponseMessage`,
//! `ReportDataMessage`).
//!
//! It implements only the subset commissioning needs: one command per
//! invoke, concrete (non-wildcard) attribute paths, no subscriptions, no
//! timed invoke, no batched commands. The full IM engine is M7/M8 work.
//!
//! This module depends only on [`matter_codec`] and imports nothing from
//! [`crate::state_machine`], so it can be lifted into a standalone
//! `matter-interaction` crate later as a file move (M6.6 design §3).

#![forbid(unsafe_code)]

pub mod error;
pub mod invoke;
pub mod read;
pub mod status;

pub use error::ImError;

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
pub(crate) fn expect_message_struct(r: &mut TlvReader<'_>) -> Result<(), error::ImError> {
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
///
/// # Errors
///
/// Returns [`error::ImError::Codec`] wrapping
/// [`matter_codec::Error::UnclosedContainer`] if the input ends before a
/// matching end-of-container, or propagates any other codec error.
pub(crate) fn read_container_members(
    r: &mut TlvReader<'_>,
) -> Result<Vec<(Tag, Value)>, error::ImError> {
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
/// whole sub-tree into a [`Value`].
///
/// # Errors
///
/// Propagates any error from [`read_container_members`].
pub(crate) fn read_container_value(
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
/// sub-tree (used to skip fields we do not consume).
///
/// # Errors
///
/// Propagates any error from [`read_container_members`].
pub(crate) fn skip_container(r: &mut TlvReader<'_>) -> Result<(), error::ImError> {
    let _ = read_container_members(r)?;
    Ok(())
}

/// A concrete command path: `(endpoint, cluster, command)`.
///
/// Encoded as a `CommandPathIB` TLV **list** (Matter Appendix A.6):
/// context tag 0 = endpoint, 1 = cluster, 2 = command.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CommandPath {
    /// Matter endpoint (always 0 for commissioning).
    pub endpoint: u16,
    /// Cluster ID.
    pub cluster: u32,
    /// Command ID.
    pub command: u32,
}
