//! Server-side `Invoke` framing — the inverse of [`crate::invoke`]'s client
//! codecs. A controller never had to *read* an inbound `InvokeRequestMessage` or
//! *write* an `InvokeResponseMessage`; an OTA Provider (M9-F) does both.

#![forbid(unsafe_code)]

use crate::invoke::{command_path_from_value, reencode_anonymous, write_command_path};
use crate::path::CommandPath;
use crate::status::ImStatus;
use crate::{expect_message_struct, skip_container, IM_REVISION};
use matter_codec::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

/// One command parsed out of an inbound `InvokeRequestMessage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokedCommand {
    /// `(endpoint, cluster, command)` the requester invoked.
    pub path: CommandPath,
    /// The command-fields struct, re-encoded with an anonymous tag (ready to
    /// hand to a `matter-clusters` decoder).
    pub fields_tlv: Vec<u8>,
    /// The `CommandRef` (`CommandDataIB` tag 2), present only in batched invokes.
    pub command_ref: Option<u16>,
}

/// A parsed inbound `InvokeRequestMessage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedInvokeRequest {
    /// `SuppressResponse` — set for group (multicast) invokes.
    pub suppress_response: bool,
    /// `TimedRequest` — the action half of a timed interaction.
    pub timed: bool,
    /// The invoked commands (one for a normal invoke; more for a batch).
    pub commands: Vec<InvokedCommand>,
}

/// Parse an inbound `InvokeRequestMessage` (Matter Core §10.7) — the message a
/// device sends to a server (e.g. a Requestor's `QueryImage` to an OTA Provider).
///
/// # Errors
///
/// Returns [`crate::ImError`] if the message is not a struct or lacks the
/// `InvokeRequests` array, or a `CommandDataIB` lacks a `CommandPath`.
pub fn parse_invoke_request(bytes: &[u8]) -> Result<ParsedInvokeRequest, crate::ImError> {
    let mut r = TlvReader::new(bytes);
    expect_message_struct(&mut r)?;

    let mut suppress_response = false;
    let mut timed = false;
    let mut commands = Vec::new();

    loop {
        match r.next()? {
            None | Some(Element::ContainerEnd) => break,
            Some(Element::Scalar {
                tag: Tag::Context(0),
                value: Value::Bool(b),
            }) => suppress_response = b,
            Some(Element::Scalar {
                tag: Tag::Context(1),
                value: Value::Bool(b),
            }) => timed = b,
            Some(Element::ContainerStart {
                tag: Tag::Context(2),
                kind: ContainerKind::Array,
            }) => {
                read_invoke_requests(&mut r, &mut commands)?;
            }
            Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
            Some(_) => {}
        }
    }

    Ok(ParsedInvokeRequest {
        suppress_response,
        timed,
        commands,
    })
}

/// Read the `InvokeRequests` array body: a sequence of `CommandDataIB` structs,
/// until the array's `ContainerEnd`.
fn read_invoke_requests(
    r: &mut TlvReader<'_>,
    out: &mut Vec<InvokedCommand>,
) -> Result<(), crate::ImError> {
    loop {
        match r.next()? {
            None | Some(Element::ContainerEnd) => return Ok(()),
            Some(Element::ContainerStart {
                kind: ContainerKind::Structure,
                ..
            }) => out.push(read_command_data(r)?),
            Some(Element::ContainerStart { .. }) => skip_container(r)?,
            Some(_) => {}
        }
    }
}

/// Read one `CommandDataIB` body (reader positioned just after its struct start):
/// ctx0 `CommandPath` (list), ctx1 `CommandFields` (struct), opt ctx2 `CommandRef`.
fn read_command_data(r: &mut TlvReader<'_>) -> Result<InvokedCommand, crate::ImError> {
    let mut path = None;
    let mut fields_tlv = None;
    let mut command_ref = None;

    loop {
        match r.next()? {
            None | Some(Element::ContainerEnd) => break,
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::List,
            }) => {
                let members = read_list_members(r)?;
                path = Some(command_path_from_value(&members)?);
            }
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Structure,
            }) => {
                // Re-anonymise the CommandFields struct as a standalone blob.
                let value = read_struct_value(r)?;
                fields_tlv = Some(reencode_anonymous(&value));
            }
            Some(Element::Scalar {
                tag: Tag::Context(2),
                value: Value::Uint(n),
            }) => {
                command_ref = u16::try_from(n).ok();
            }
            Some(Element::ContainerStart { .. }) => skip_container(r)?,
            Some(_) => {}
        }
    }

    Ok(InvokedCommand {
        path: path.ok_or(crate::ImError::MissingField("CommandDataIB.CommandPath"))?,
        fields_tlv: fields_tlv
            .ok_or(crate::ImError::MissingField("CommandDataIB.CommandFields"))?,
        command_ref,
    })
}

/// Read a `Value::List`'s members (reader positioned after the list start).
fn read_list_members(r: &mut TlvReader<'_>) -> Result<Vec<(Tag, Value)>, crate::ImError> {
    match crate::read_container_value(r, ContainerKind::List)? {
        Value::List(members) => Ok(members),
        _ => Err(crate::ImError::UnexpectedValue("expected a list")),
    }
}

/// Read a `Value::Structure` (reader positioned after the struct start) and
/// return it as a `Value::Structure` for re-anonymising.
fn read_struct_value(r: &mut TlvReader<'_>) -> Result<Value, crate::ImError> {
    crate::read_container_value(r, ContainerKind::Structure)
}

/// Build a single-response `InvokeResponseMessage` carrying a response **command**
/// (`InvokeResponseIB` → ctx0 `Command` → `CommandDataIB`: path + fields).
/// `SuppressResponse = false`.
///
/// `response_fields_tlv` must be an anonymous-tagged struct (a `matter-clusters`
/// response encoder output).
///
/// # Panics
///
/// Panics if `response_fields_tlv` is not valid anonymous-tagged TLV (as
/// [`crate::build_invoke_request`]).
#[must_use]
#[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible.
pub fn build_invoke_response_command(path: CommandPath, response_fields_tlv: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.put_bool(Tag::Context(0), false)
        .expect("infallible: vec writer"); // SuppressResponse
    w.start_array(Tag::Context(1))
        .expect("infallible: vec writer"); // InvokeResponses
    {
        w.start_structure(Tag::Anonymous)
            .expect("infallible: vec writer"); // InvokeResponseIB
        w.start_structure(Tag::Context(0))
            .expect("infallible: vec writer"); // Command = CommandDataIB
        write_command_path(&mut w, Tag::Context(0), path);
        w.put_preencoded(Tag::Context(1), response_fields_tlv)
            .expect("infallible: caller passes a valid anonymous-tagged struct");
        w.end_container().expect("infallible: vec writer"); // CommandDataIB
        w.end_container().expect("infallible: vec writer"); // InvokeResponseIB
    }
    w.end_container().expect("infallible: vec writer"); // InvokeResponses array
    w.put_uint(Tag::Context(0xFF), u64::from(IM_REVISION))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer"); // message struct
    buf
}

/// Build a single-response `InvokeResponseMessage` carrying a bare **status**
/// for `path` (`InvokeResponseIB` → ctx1 `Status` → `CommandStatusIB`: path +
/// `StatusIB` with `Status = status`). `SuppressResponse = false`.
#[must_use]
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.
pub fn build_invoke_response_status(path: CommandPath, status: ImStatus) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.put_bool(Tag::Context(0), false)
        .expect("infallible: vec writer"); // SuppressResponse
    w.start_array(Tag::Context(1))
        .expect("infallible: vec writer"); // InvokeResponses
    {
        w.start_structure(Tag::Anonymous)
            .expect("infallible: vec writer"); // InvokeResponseIB
        w.start_structure(Tag::Context(1))
            .expect("infallible: vec writer"); // Status = CommandStatusIB
        write_command_path(&mut w, Tag::Context(0), path);
        w.start_structure(Tag::Context(1))
            .expect("infallible: vec writer"); // StatusIB
        w.put_uint(Tag::Context(0), u64::from(status.to_u8()))
            .expect("infallible: vec writer"); // Status
        w.end_container().expect("infallible: vec writer"); // StatusIB
        w.end_container().expect("infallible: vec writer"); // CommandStatusIB
        w.end_container().expect("infallible: vec writer"); // InvokeResponseIB
    }
    w.end_container().expect("infallible: vec writer"); // InvokeResponses array
    w.put_uint(Tag::Context(0xFF), u64::from(IM_REVISION))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer"); // message struct
    buf
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md carve-out.
    use super::*;
    use crate::invoke::{build_invoke_request, parse_invoke_response, InvokeResponse};

    fn anon_struct_ctx0(value: u64) -> Vec<u8> {
        let mut b = Vec::new();
        let mut w = TlvWriter::new(&mut b);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), value).unwrap();
        w.end_container().unwrap();
        b
    }

    #[test]
    fn parse_invoke_request_roundtrips_builder() {
        let fields = anon_struct_ctx0(0xFFF1);
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x0029,
            command: 0x00,
        };
        let msg = build_invoke_request(path, &fields);
        let parsed = parse_invoke_request(&msg).expect("parse");
        assert!(!parsed.suppress_response);
        assert!(!parsed.timed);
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].path, path);
        assert_eq!(parsed.commands[0].fields_tlv, fields);
        assert_eq!(parsed.commands[0].command_ref, None);
    }

    #[test]
    fn build_invoke_response_command_roundtrips() {
        let fields = anon_struct_ctx0(7);
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x0029,
            command: 0x01,
        };
        let msg = build_invoke_response_command(path, &fields);
        match parse_invoke_response(&msg).expect("parse") {
            InvokeResponse::Command {
                path: p,
                fields_tlv,
            } => {
                assert_eq!(p, path);
                assert_eq!(fields_tlv, fields);
            }
            InvokeResponse::Status(s) => panic!("expected Command, got Status({s:?})"),
        }
    }

    #[test]
    fn build_invoke_response_status_roundtrips() {
        let path = CommandPath {
            endpoint: 0,
            cluster: 0x0029,
            command: 0x04,
        };
        let msg = build_invoke_response_status(path, ImStatus::Success);
        assert!(matches!(
            parse_invoke_response(&msg),
            Ok(InvokeResponse::Status(ImStatus::Success))
        ));
    }
}
