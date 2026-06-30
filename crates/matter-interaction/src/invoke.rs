//! `InvokeRequestMessage` / `InvokeResponseMessage` framing — Matter §10.7.

#![forbid(unsafe_code)]

use crate::error::ImError;
use crate::path::CommandPath;
use crate::status::ImStatus;
use crate::{
    expect_message_struct, read_container_members, read_container_value, skip_container,
    IM_REVISION,
};
use matter_codec::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

/// Write a `CommandPathIB` (a TLV **list**: 0=endpoint, 1=cluster,
/// 2=command) under `tag`.
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.
pub(crate) fn write_command_path(w: &mut TlvWriter<'_>, tag: Tag, path: CommandPath) {
    w.start_list(tag).expect("infallible: vec writer");
    w.put_uint(Tag::Context(0), u64::from(path.endpoint))
        .expect("infallible: vec writer");
    w.put_uint(Tag::Context(1), u64::from(path.cluster))
        .expect("infallible: vec writer");
    w.put_uint(Tag::Context(2), u64::from(path.command))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer");
}

/// Build an `InvokeRequestMessage` carrying a single command.
///
/// `command_fields_tlv` is the already-encoded command-fields struct
/// (e.g. the output of `crate::noc::encode_csr_request`); it is embedded
/// verbatim as the `CommandFields` member. `SuppressResponse` and
/// `TimedRequest` are both `false`.
///
/// # Panics
///
/// Panics if `command_fields_tlv` is not a valid anonymous-tagged TLV
/// element (i.e. not the output of a codec encode call). The function is
/// otherwise infallible; `Vec`-backed `TlvWriter` never fails.
#[must_use]
pub fn build_invoke_request(path: CommandPath, command_fields_tlv: &[u8]) -> Vec<u8> {
    build_invoke_request_inner(path, command_fields_tlv, false, false)
}

/// Like [`build_invoke_request`] but sets `TimedRequest = true` — the action half
/// of a timed interaction, sent on the same exchange after a `TimedRequest`
/// message (see [`crate::build_timed_request`]).
///
/// # Panics
///
/// As [`build_invoke_request`] (invalid `command_fields_tlv`).
#[must_use]
pub fn build_invoke_request_timed(path: CommandPath, command_fields_tlv: &[u8]) -> Vec<u8> {
    build_invoke_request_inner(path, command_fields_tlv, true, false)
}

/// Like [`build_invoke_request`] but sets `SuppressResponse = true` — the form
/// used for **group** (multicast) invokes. Group commands are unacknowledged at
/// the IM layer: there is no return path for a multicast send, so the request
/// must instruct the receiving devices to suppress any `InvokeResponse`
/// (Matter Core Spec §8.9.2 / §10.7.2 — group commands carry `SuppressResponse`).
/// `TimedRequest` is `false` (timed interactions are not available on group
/// sends).
///
/// # Panics
///
/// As [`build_invoke_request`] (invalid `command_fields_tlv`).
#[must_use]
pub fn build_invoke_request_group(path: CommandPath, command_fields_tlv: &[u8]) -> Vec<u8> {
    build_invoke_request_inner(path, command_fields_tlv, false, true)
}

#[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible.
fn build_invoke_request_inner(
    path: CommandPath,
    command_fields_tlv: &[u8],
    timed: bool,
    suppress_response: bool,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.put_bool(Tag::Context(0), suppress_response)
        .expect("infallible: vec writer"); // SuppressResponse
    w.put_bool(Tag::Context(1), timed)
        .expect("infallible: vec writer"); // TimedRequest
    w.start_array(Tag::Context(2))
        .expect("infallible: vec writer"); // InvokeRequests
    {
        w.start_structure(Tag::Anonymous)
            .expect("infallible: vec writer"); // CommandDataIB
        write_command_path(&mut w, Tag::Context(0), path);
        w.put_preencoded(Tag::Context(1), command_fields_tlv)
            .expect("infallible: caller passes a valid anonymous-tagged struct");
        w.end_container().expect("infallible: vec writer"); // CommandDataIB
    }
    w.end_container().expect("infallible: vec writer"); // InvokeRequests array
    w.put_uint(Tag::Context(0xFF), u64::from(IM_REVISION))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer"); // message struct
    buf
}

/// Build an `InvokeRequestMessage` carrying **multiple** commands, each tagged
/// with a sequential `CommandRef` (`CommandDataIB` tag 2) so the device's
/// responses can be matched back. `SuppressResponse` and `TimedRequest` are
/// `false`. Each tuple is `(path, command_fields_tlv)`, the fields an
/// anonymous-tagged TLV blob (e.g. a `matter-clusters` command encoder output).
///
/// NB: the wire format permits a batch, but a device only accepts more than one
/// command if it advertises `MaxPathsPerInvoke > 1` in its `SessionParameters`;
/// the controller-side gating is deferred (M9-B5 scope) — callers must respect it.
///
/// # Panics
///
/// As [`build_invoke_request`] (a `command_fields_tlv` that is not a valid
/// anonymous-tagged TLV element).
#[must_use]
#[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible.
pub fn build_invoke_request_batch(commands: &[(CommandPath, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.put_bool(Tag::Context(0), false)
        .expect("infallible: vec writer"); // SuppressResponse
    w.put_bool(Tag::Context(1), false)
        .expect("infallible: vec writer"); // TimedRequest
    w.start_array(Tag::Context(2))
        .expect("infallible: vec writer"); // InvokeRequests
    for (i, (path, fields)) in commands.iter().enumerate() {
        w.start_structure(Tag::Anonymous)
            .expect("infallible: vec writer"); // CommandDataIB
        write_command_path(&mut w, Tag::Context(0), *path);
        w.put_preencoded(Tag::Context(1), fields)
            .expect("infallible: caller passes a valid anonymous-tagged struct");
        // CommandRef (tag 2): the index. `try_from` is total for any realistic
        // batch; cap defensively rather than panic on an absurd one.
        let cref = u16::try_from(i).unwrap_or(u16::MAX);
        w.put_uint(Tag::Context(2), u64::from(cref))
            .expect("infallible: vec writer");
        w.end_container().expect("infallible: vec writer"); // CommandDataIB
    }
    w.end_container().expect("infallible: vec writer"); // InvokeRequests array
    w.put_uint(Tag::Context(0xFF), u64::from(IM_REVISION))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer"); // message struct
    buf
}

/// Outcome of parsing a single-command `InvokeResponseMessage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvokeResponse {
    /// The device returned a response command. `fields_tlv` is the
    /// re-anonymised `CommandFields` struct, ready to hand to
    /// `Commissioner::on_response`.
    Command {
        /// Path of the response command (`(endpoint, cluster, command)`).
        path: CommandPath,
        /// The command-fields struct, re-encoded with an anonymous tag.
        fields_tlv: Vec<u8>,
    },
    /// The device returned a bare status (no response command payload).
    Status(ImStatus),
}

/// One parsed `InvokeResponseIB` from a batched response, with its `CommandRef`
/// (`CommandDataIB` / `CommandStatusIB` tag 2) for matching to the request command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeResponseEntry {
    /// The `CommandRef` echoed by the device, if present.
    pub command_ref: Option<u16>,
    /// The response: a command payload or a status.
    pub response: InvokeResponse,
}

/// Re-encode a [`Value`] as a standalone, anonymous-tagged TLV blob. Used
/// to lift an embedded `CommandFields` struct back out as bytes the state
/// machine can consume.
///
/// Integer wire widths are normalized to the minimal width, so the re-encoded
/// bytes are not guaranteed byte-identical to the device's original encoding
/// (this path is consumed locally, never retransmitted).
pub(crate) fn reencode_anonymous(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    #[allow(clippy::expect_used)] // Vec-backed writer is infallible.
    w.write_value(Tag::Anonymous, value)
        .expect("infallible: vec writer");
    buf
}

/// Read a `CommandPathIB` list (`Value::List` members) into a [`CommandPath`].
pub(crate) fn command_path_from_value(members: &[(Tag, Value)]) -> Result<CommandPath, ImError> {
    let mut endpoint = None;
    let mut cluster = None;
    let mut command = None;
    for (tag, v) in members {
        match (tag, v) {
            (Tag::Context(0), Value::Uint(n)) => {
                endpoint =
                    Some(u16::try_from(*n).map_err(|_| {
                        ImError::UnexpectedValue("CommandPath.endpoint exceeds u16")
                    })?);
            }
            (Tag::Context(1), Value::Uint(n)) => {
                cluster =
                    Some(u32::try_from(*n).map_err(|_| {
                        ImError::UnexpectedValue("CommandPath.cluster exceeds u32")
                    })?);
            }
            (Tag::Context(2), Value::Uint(n)) => {
                command =
                    Some(u32::try_from(*n).map_err(|_| {
                        ImError::UnexpectedValue("CommandPath.command exceeds u32")
                    })?);
            }
            _ => {}
        }
    }
    Ok(CommandPath {
        endpoint: endpoint.ok_or(ImError::MissingField("CommandPath.endpoint"))?,
        cluster: cluster.ok_or(ImError::MissingField("CommandPath.cluster"))?,
        command: command.ok_or(ImError::MissingField("CommandPath.command"))?,
    })
}

/// Parse a single-command `InvokeResponseMessage`.
///
/// Reads the first `InvokeResponseIB` in the `InvokeResponses` array and
/// returns either its response-command payload or its status. Additional
/// `InvokeResponseIB`s (not produced by commissioning) are ignored.
///
/// # Errors
///
/// Returns [`ImError`] if the message is not a struct, lacks the
/// `InvokeResponses` array, or the first IB has neither Command nor Status.
pub fn parse_invoke_response(bytes: &[u8]) -> Result<InvokeResponse, ImError> {
    let mut r = TlvReader::new(bytes);
    expect_message_struct(&mut r)?;

    loop {
        match r.next()? {
            None | Some(Element::ContainerEnd) => {
                return Err(ImError::MissingField("InvokeResponses"))
            }
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Array,
            }) => break,
            Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
            Some(_) => {}
        }
    }

    match r.next()? {
        Some(Element::ContainerStart {
            kind: ContainerKind::Structure,
            ..
        }) => {}
        _ => return Err(ImError::MissingField("InvokeResponseIB")),
    }

    loop {
        match r.next()? {
            None | Some(Element::ContainerEnd) => return Err(ImError::EmptyInvokeResponse),
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::Structure,
            }) => {
                return parse_command_data(&mut r).map(|(path, fields)| InvokeResponse::Command {
                    path,
                    fields_tlv: fields,
                });
            }
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Structure,
            }) => {
                return parse_command_status(&mut r).map(InvokeResponse::Status);
            }
            Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
            Some(_) => {}
        }
    }
}

/// Parse a multi-command `InvokeResponseMessage`: every `InvokeResponseIB`, each
/// with its `CommandRef`. The single-command [`parse_invoke_response`] is retained
/// for the commissioning path (reads only the first IB, ignores `CommandRef`).
///
/// # Errors
///
/// Returns [`ImError`] if the message is not a struct, lacks the
/// `InvokeResponses` array, or an IB has neither Command nor Status.
pub fn parse_invoke_response_batch(bytes: &[u8]) -> Result<Vec<InvokeResponseEntry>, ImError> {
    let mut r = TlvReader::new(bytes);
    expect_message_struct(&mut r)?;
    // Advance to the InvokeResponses array (context tag 1).
    loop {
        match r.next()? {
            None | Some(Element::ContainerEnd) => {
                return Err(ImError::MissingField("InvokeResponses"))
            }
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Array,
            }) => break,
            Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
            Some(_) => {}
        }
    }
    let mut out = Vec::new();
    loop {
        match r.next()? {
            None => return Err(ImError::Codec(matter_codec::Error::UnclosedContainer)),
            Some(Element::ContainerEnd) => return Ok(out), // end of array
            Some(Element::ContainerStart {
                kind: ContainerKind::Structure,
                ..
            }) => out.push(parse_invoke_response_ib(&mut r)?),
            Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
            Some(_) => {}
        }
    }
}

/// Parse one `InvokeResponseIB` body into an [`InvokeResponseEntry`] (reader
/// positioned just after its struct start). Drains the **entire** IB (through its
/// matching `ContainerEnd`) so the caller's array walk stays in sync.
fn parse_invoke_response_ib(r: &mut TlvReader<'_>) -> Result<InvokeResponseEntry, ImError> {
    let mut entry: Option<InvokeResponseEntry> = None;
    loop {
        match r.next()? {
            None => return Err(ImError::Codec(matter_codec::Error::UnclosedContainer)),
            Some(Element::ContainerEnd) => break, // end of this InvokeResponseIB
            // Command = CommandDataIB
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::Structure,
            }) => {
                let (path, fields, command_ref) = parse_command_data_ref(r)?;
                entry = Some(InvokeResponseEntry {
                    command_ref,
                    response: InvokeResponse::Command {
                        path,
                        fields_tlv: fields,
                    },
                });
            }
            // Status = CommandStatusIB
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Structure,
            }) => {
                let (status, command_ref) = parse_command_status_ref(r)?;
                entry = Some(InvokeResponseEntry {
                    command_ref,
                    response: InvokeResponse::Status(status),
                });
            }
            Some(Element::ContainerStart { .. }) => skip_container(r)?,
            Some(_) => {}
        }
    }
    entry.ok_or(ImError::EmptyInvokeResponse)
}

/// Parse a `CommandDataIB` body (reader positioned just after its struct
/// start), returning `(path, anonymous-tagged CommandFields bytes)`. The single-
/// command path ignores the `CommandRef`; [`parse_command_data_ref`] captures it.
fn parse_command_data(r: &mut TlvReader<'_>) -> Result<(CommandPath, Vec<u8>), ImError> {
    let (path, fields, _ref) = parse_command_data_ref(r)?;
    Ok((path, fields))
}

/// Like [`parse_command_data`] but also captures the `CommandRef` (tag 2).
fn parse_command_data_ref(
    r: &mut TlvReader<'_>,
) -> Result<(CommandPath, Vec<u8>, Option<u16>), ImError> {
    let mut path = None;
    let mut fields = Vec::new();
    let mut command_ref = None;
    loop {
        match r.next()? {
            None => return Err(ImError::MissingField("CommandDataIB.body")),
            Some(Element::ContainerEnd) => break,
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::List,
            }) => {
                let body = read_container_members(r)?;
                path = Some(command_path_from_value(&body)?);
            }
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind,
            }) => {
                let v = read_container_value(r, kind)?;
                fields = reencode_anonymous(&v);
            }
            // CommandRef (tag 2), a scalar uint.
            Some(Element::Scalar {
                tag: Tag::Context(2),
                value: Value::Uint(n),
            }) => command_ref = u16::try_from(n).ok(),
            Some(Element::ContainerStart { .. }) => skip_container(r)?,
            Some(_) => {}
        }
    }
    // If no CommandFields member was present, `fields` is an empty Vec, which
    // is not valid TLV. Canonicalize to an anonymous empty struct so callers
    // always receive a valid TLV blob.
    let fields = if fields.is_empty() {
        reencode_anonymous(&Value::Structure(Vec::new()))
    } else {
        fields
    };
    Ok((
        path.ok_or(ImError::MissingField("CommandDataIB.CommandPath"))?,
        fields,
        command_ref,
    ))
}

/// Parse a `CommandStatusIB` body, returning the `StatusIB.Status` mapped
/// to [`ImStatus`]. The single-command path ignores the `CommandRef`;
/// [`parse_command_status_ref`] captures it.
fn parse_command_status(r: &mut TlvReader<'_>) -> Result<ImStatus, ImError> {
    let (status, _ref) = parse_command_status_ref(r)?;
    Ok(status)
}

/// Like [`parse_command_status`] but also captures the `CommandRef` (tag 2).
fn parse_command_status_ref(r: &mut TlvReader<'_>) -> Result<(ImStatus, Option<u16>), ImError> {
    // `None` ⇒ the Status member was never seen (genuinely missing).
    // `Some(raw)` ⇒ the member was present; `raw` is the verbatim wire value,
    // which we range-check to a `u8` only after the parse loop so an
    // out-of-range value reports as `InvalidStatusCode`, not `MissingField`.
    let mut status: Option<u64> = None;
    let mut command_ref = None;
    loop {
        match r.next()? {
            None => return Err(ImError::MissingField("CommandStatusIB.body")),
            Some(Element::ContainerEnd) => break,
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Structure,
            }) => {
                let members = read_container_members(r)?;
                // Last value wins for duplicate tags (lenient parsing); real devices never duplicate Status.
                for (tag, v) in &members {
                    if let (Tag::Context(0), Value::Uint(n)) = (tag, v) {
                        status = Some(*n);
                    }
                }
            }
            // CommandRef (tag 2), a scalar uint.
            Some(Element::Scalar {
                tag: Tag::Context(2),
                value: Value::Uint(n),
            }) => command_ref = u16::try_from(n).ok(),
            Some(Element::ContainerStart { .. }) => skip_container(r)?,
            Some(_) => {}
        }
    }
    let raw = status.ok_or(ImError::MissingField("StatusIB.Status"))?;
    let code = u8::try_from(raw).map_err(|_| ImError::InvalidStatusCode { code: raw })?;
    Ok((ImStatus::from_u8(code), command_ref))
}

#[cfg(test)]
mod tests {
    // Test-code carve-out: see CLAUDE.md.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use matter_codec::{ContainerKind, Element, Tag, TlvReader, Value};

    #[test]
    fn invoke_request_has_expected_structure() {
        // ArmFailSafe-like: endpoint 0, cluster 0x0030, command 0x00,
        // command fields = an empty anonymous struct (0x15 0x18).
        let fields = vec![0x15, 0x18];
        let bytes = build_invoke_request(
            CommandPath {
                endpoint: 0,
                cluster: 0x0030,
                command: 0x00,
            },
            &fields,
        );

        let mut r = TlvReader::new(&bytes);
        // Top-level InvokeRequestMessage struct (anonymous).
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure
            })
        ));
        // SuppressResponse = false.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(0),
                value: Value::Bool(false)
            })
        ));
        // TimedRequest = false.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(1),
                value: Value::Bool(false)
            })
        ));
        // InvokeRequests array start.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Context(2),
                kind: ContainerKind::Array
            })
        ));
        // CommandDataIB anonymous struct start.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure
            })
        ));
        // CommandPathIB list at context tag 0.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::List
            })
        ));
        // Endpoint = 0 at context tag 0.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(0),
                value: Value::Uint(0)
            })
        ));
        // Cluster = 0x0030 at context tag 1.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(1),
                value: Value::Uint(0x0030)
            })
        ));
        // Command = 0x00 at context tag 2.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(2),
                value: Value::Uint(0)
            })
        ));
        // End CommandPathIB list.
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // CommandFields (empty struct) at context tag 1 — ContainerStart then end.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Structure
            })
        ));
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // End CommandDataIB struct.
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // End InvokeRequests array.
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // InteractionModelRevision = IM_REVISION at context tag 0xFF.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar { tag: Tag::Context(0xFF), value: Value::Uint(v) })
                if v == u64::from(IM_REVISION)
        ));
        // End top-level struct.
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        // No more elements.
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn invoke_request_carries_command_path_and_fields() {
        // `put_preencoded` re-tags the anonymous-struct control byte (0x15)
        // to a context-1 struct (0x35 0x01), then appends the body (0x18).
        // Verify that the re-tagged representation [0x35, 0x01, 0x18] is
        // present in the output (i.e. the fields blob was embedded).
        let fields = vec![0x15u8, 0x18]; // anonymous empty struct
        let bytes = build_invoke_request(
            CommandPath {
                endpoint: 1,
                cluster: 0x0031,
                command: 0x06,
            },
            &fields,
        );
        // Retagged form: context-1 struct start (0x35, 0x01) then body (0x18).
        let retagged = [0x35u8, 0x01, 0x18];
        assert!(
            bytes.windows(retagged.len()).any(|w| w == retagged),
            "command fields not embedded (expected retagged bytes {retagged:02X?} in {bytes:02X?})",
        );
    }

    #[test]
    fn parses_command_response_payload() {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap(); // SuppressResponse
        w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
        {
            w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
            w.start_structure(Tag::Context(0)).unwrap(); // Command = CommandDataIB
            w.start_list(Tag::Context(0)).unwrap(); // CommandPath
            w.put_uint(Tag::Context(0), 0).unwrap();
            w.put_uint(Tag::Context(1), 0x0030).unwrap();
            w.put_uint(Tag::Context(2), 0x05).unwrap();
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap(); // CommandFields (empty)
            w.end_container().unwrap();
            w.end_container().unwrap(); // CommandDataIB
            w.end_container().unwrap(); // InvokeResponseIB
        }
        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let parsed = parse_invoke_response(&buf).unwrap();
        match parsed {
            InvokeResponse::Command { path, fields_tlv } => {
                assert_eq!(path.endpoint, 0);
                assert_eq!(path.cluster, 0x0030);
                assert_eq!(path.command, 0x05);
                assert_eq!(fields_tlv, vec![0x15, 0x18]); // re-anonymised empty struct
            }
            InvokeResponse::Status(_) => panic!("expected Command, got Status"),
        }
    }

    #[test]
    fn parses_command_with_nonempty_fields() {
        use matter_codec::{Tag, TlvWriter};

        // Build the expected anonymous struct bytes independently for comparison:
        // anonymous struct containing one scalar: Context(0) = 0x2A (uint).
        let mut expected_buf = Vec::new();
        {
            let mut w = TlvWriter::new(&mut expected_buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(0), 0x2A).unwrap();
            w.end_container().unwrap();
        }

        // Build an InvokeResponseMessage whose CommandFields is that same struct.
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap(); // SuppressResponse
        w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
        {
            w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
            w.start_structure(Tag::Context(0)).unwrap(); // CommandDataIB
            w.start_list(Tag::Context(0)).unwrap(); // CommandPath
            w.put_uint(Tag::Context(0), 1).unwrap(); // endpoint
            w.put_uint(Tag::Context(1), 0x0050).unwrap(); // cluster
            w.put_uint(Tag::Context(2), 0x01).unwrap(); // command
            w.end_container().unwrap(); // CommandPath
                                        // CommandFields at Context(1): a struct with one member
            w.start_structure(Tag::Context(1)).unwrap();
            w.put_uint(Tag::Context(0), 0x2A).unwrap();
            w.end_container().unwrap(); // CommandFields
            w.end_container().unwrap(); // CommandDataIB
            w.end_container().unwrap(); // InvokeResponseIB
        }
        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let parsed = parse_invoke_response(&buf).unwrap();
        match parsed {
            InvokeResponse::Command { path, fields_tlv } => {
                assert_eq!(path.endpoint, 1);
                assert_eq!(path.cluster, 0x0050);
                assert_eq!(path.command, 0x01);
                assert_eq!(
                    fields_tlv, expected_buf,
                    "fields_tlv should decode to the same struct content as the original"
                );
            }
            InvokeResponse::Status(_) => panic!("expected Command, got Status"),
        }
    }

    #[test]
    fn rejects_out_of_range_endpoint() {
        use crate::error::ImError;
        use matter_codec::{Tag, TlvWriter};

        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap();
        w.start_array(Tag::Context(1)).unwrap();
        {
            w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
            w.start_structure(Tag::Context(0)).unwrap(); // CommandDataIB
            w.start_list(Tag::Context(0)).unwrap(); // CommandPath
            w.put_uint(Tag::Context(0), 0x0001_0000).unwrap(); // endpoint exceeds u16
            w.put_uint(Tag::Context(1), 0x0030).unwrap();
            w.put_uint(Tag::Context(2), 0x00).unwrap();
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap(); // CommandFields (empty)
            w.end_container().unwrap();
            w.end_container().unwrap(); // CommandDataIB
            w.end_container().unwrap(); // InvokeResponseIB
        }
        w.end_container().unwrap();
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let result = parse_invoke_response(&buf);
        assert!(
            matches!(result, Err(ImError::UnexpectedValue(_))),
            "expected UnexpectedValue for out-of-range endpoint, got {result:?}"
        );
    }

    #[test]
    fn empty_invoke_responses_array_errors() {
        use crate::error::ImError;
        use matter_codec::{Tag, TlvWriter};

        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap();
        w.start_array(Tag::Context(1)).unwrap(); // empty InvokeResponses array
        w.end_container().unwrap();
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let result = parse_invoke_response(&buf);
        assert!(
            matches!(result, Err(ImError::MissingField(_))),
            "expected MissingField for empty InvokeResponses, got {result:?}"
        );
    }

    #[test]
    fn parses_status_response() {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap();
        w.start_array(Tag::Context(1)).unwrap();
        {
            w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
            w.start_structure(Tag::Context(1)).unwrap(); // Status = CommandStatusIB
            w.start_list(Tag::Context(0)).unwrap(); // CommandPath
            w.put_uint(Tag::Context(0), 0).unwrap();
            w.put_uint(Tag::Context(1), 0x0030).unwrap();
            w.put_uint(Tag::Context(2), 0x00).unwrap();
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
            w.put_uint(Tag::Context(0), 0x01).unwrap(); // Status = FAILURE
            w.end_container().unwrap();
            w.end_container().unwrap(); // CommandStatusIB
            w.end_container().unwrap(); // InvokeResponseIB
        }
        w.end_container().unwrap();
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let parsed = parse_invoke_response(&buf).unwrap();
        assert!(matches!(
            parsed,
            InvokeResponse::Status(ImStatus::Failure(0x01))
        ));
    }

    /// Build an `InvokeResponseMessage` whose single `InvokeResponseIB` carries
    /// a `CommandStatusIB`. `status` controls the `StatusIB.Status` member:
    /// `Some(v)` writes that raw uint, `None` omits the member entirely.
    fn invoke_status_response(status: Option<u64>) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap();
        w.start_array(Tag::Context(1)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
        w.start_structure(Tag::Context(1)).unwrap(); // Status = CommandStatusIB
        w.start_list(Tag::Context(0)).unwrap(); // CommandPath
        w.put_uint(Tag::Context(0), 0).unwrap();
        w.put_uint(Tag::Context(1), 0x0030).unwrap();
        w.put_uint(Tag::Context(2), 0x00).unwrap();
        w.end_container().unwrap();
        w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
        if let Some(v) = status {
            w.put_uint(Tag::Context(0), v).unwrap();
        }
        w.end_container().unwrap();
        w.end_container().unwrap(); // CommandStatusIB
        w.end_container().unwrap(); // InvokeResponseIB
        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();
        buf
    }

    #[test]
    fn command_status_out_of_range_is_invalid_status_code() {
        // StatusIB.Status = 0x100 — present on the wire but exceeds the single
        // octet a Matter status code occupies. Must surface as the distinct
        // InvalidStatusCode error, NOT MissingField.
        let buf = invoke_status_response(Some(0x100));
        match parse_invoke_response(&buf) {
            Err(ImError::InvalidStatusCode { code }) => assert_eq!(code, 0x100),
            other => panic!("expected InvalidStatusCode {{ code: 0x100 }}, got {other:?}"),
        }
    }

    #[test]
    fn command_status_valid_code_still_parses() {
        let buf = invoke_status_response(Some(0x88));
        assert!(matches!(
            parse_invoke_response(&buf),
            Ok(InvokeResponse::Status(ImStatus::Failure(0x88)))
        ));
    }

    #[test]
    fn command_status_missing_field_still_missing_field() {
        // No Status member at all — genuinely missing, so MissingField is right.
        let buf = invoke_status_response(None);
        assert!(matches!(
            parse_invoke_response(&buf),
            Err(ImError::MissingField("StatusIB.Status"))
        ));
    }

    #[test]
    fn invoke_response_ib_with_no_command_or_status_errors() {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap();
        w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
        w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB with no Command/Status
        w.put_uint(Tag::Context(7), 0).unwrap(); // unrelated field
        w.end_container().unwrap();
        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        assert!(matches!(
            parse_invoke_response(&buf),
            Err(ImError::EmptyInvokeResponse)
        ));
    }

    #[test]
    fn batch_request_carries_command_refs() {
        let fields = vec![0x15u8, 0x18]; // anonymous empty struct
        let bytes = build_invoke_request_batch(&[
            (
                CommandPath {
                    endpoint: 1,
                    cluster: 0x06,
                    command: 0x02,
                },
                &fields,
            ),
            (
                CommandPath {
                    endpoint: 2,
                    cluster: 0x06,
                    command: 0x00,
                },
                &fields,
            ),
        ]);
        // The InvokeRequests array (ctx 2) holds two CommandDataIB structs, each
        // ending with CommandRef (ctx 2) = 0 then 1. Parse the whole thing back
        // through the batch response parser shape is not applicable (this is a
        // request), so just confirm both refs appear in order in the stream.
        let mut r = TlvReader::new(&bytes);
        let mut refs = Vec::new();
        let mut depth = 0i32;
        while let Some(el) = r.next().unwrap() {
            match el {
                Element::ContainerStart { .. } => depth += 1,
                Element::ContainerEnd => depth -= 1,
                // CommandRef sits at depth 2 (struct > array > CommandDataIB), tag 2.
                Element::Scalar {
                    tag: Tag::Context(2),
                    value: Value::Uint(n),
                } if depth == 3 => refs.push(n),
                _ => {}
            }
        }
        assert_eq!(refs, vec![0, 1], "CommandRefs must be 0 then 1");
    }

    #[test]
    fn batch_response_parses_all_ibs_with_refs() {
        use matter_codec::{Tag, TlvWriter};
        // Two InvokeResponseIBs: a Command (ref 0) and a Status (ref 1).
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap(); // SuppressResponse
        w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
        {
            // IB 1: Command = CommandDataIB { path, fields(empty), ref=0 }
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_structure(Tag::Context(0)).unwrap(); // Command
            w.start_list(Tag::Context(0)).unwrap();
            w.put_uint(Tag::Context(0), 1).unwrap();
            w.put_uint(Tag::Context(1), 0x06).unwrap();
            w.put_uint(Tag::Context(2), 0x02).unwrap();
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap();
            w.end_container().unwrap(); // empty fields
            w.put_uint(Tag::Context(2), 0).unwrap(); // CommandRef
            w.end_container().unwrap(); // Command
            w.end_container().unwrap(); // IB 1
                                        // IB 2: Status = CommandStatusIB { path, status=SUCCESS, ref=1 }
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_structure(Tag::Context(1)).unwrap(); // Status
            w.start_list(Tag::Context(0)).unwrap();
            w.put_uint(Tag::Context(0), 2).unwrap();
            w.put_uint(Tag::Context(1), 0x06).unwrap();
            w.put_uint(Tag::Context(2), 0x00).unwrap();
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
            w.put_uint(Tag::Context(0), 0).unwrap(); // SUCCESS
            w.end_container().unwrap();
            w.put_uint(Tag::Context(2), 1).unwrap(); // CommandRef
            w.end_container().unwrap(); // Status
            w.end_container().unwrap(); // IB 2
        }
        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let entries = parse_invoke_response_batch(&buf).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command_ref, Some(0));
        assert!(matches!(
            entries[0].response,
            InvokeResponse::Command { ref path, .. } if path.endpoint == 1 && path.command == 0x02
        ));
        assert_eq!(entries[1].command_ref, Some(1));
        assert_eq!(
            entries[1].response,
            InvokeResponse::Status(ImStatus::Success)
        );

        // Back-compat: the single-command parser reads the first IB only.
        match parse_invoke_response(&buf).unwrap() {
            InvokeResponse::Command { path, .. } => assert_eq!(path.endpoint, 1),
            InvokeResponse::Status(_) => panic!("expected the first IB (a Command)"),
        }
    }
}
