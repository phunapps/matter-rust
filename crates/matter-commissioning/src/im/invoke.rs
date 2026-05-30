//! `InvokeRequestMessage` / `InvokeResponseMessage` framing — Matter §10.7.

#![forbid(unsafe_code)]

use crate::im::error::ImError;
use crate::im::status::ImStatus;
use crate::im::{
    expect_message_struct, read_container_members, read_container_value, skip_container,
    CommandPath, IM_REVISION,
};
use matter_codec::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

/// Write a `CommandPathIB` (a TLV **list**: 0=endpoint, 1=cluster,
/// 2=command) under `tag`.
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.
fn write_command_path(w: &mut TlvWriter<'_>, tag: Tag, path: CommandPath) {
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
/// # Errors
///
/// This function is infallible; `Vec`-backed `TlvWriter` never fails.
/// The `command_fields_tlv` slice must be a valid anonymous-tagged TLV
/// element (panics otherwise — callers pass codec-generated output).
#[must_use]
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.
pub fn build_invoke_request(path: CommandPath, command_fields_tlv: &[u8]) -> Vec<u8> {
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

/// Re-encode a [`Value`] as a standalone, anonymous-tagged TLV blob. Used
/// to lift an embedded `CommandFields` struct back out as bytes the state
/// machine can consume.
///
/// Integer wire widths are normalized to the minimal width, so the re-encoded
/// bytes are not guaranteed byte-identical to the device's original encoding
/// (this path is consumed locally, never retransmitted).
fn reencode_anonymous(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    #[allow(clippy::expect_used)] // Vec-backed writer is infallible.
    w.write_value(Tag::Anonymous, value)
        .expect("infallible: vec writer");
    buf
}

/// Read a `CommandPathIB` list (`Value::List` members) into a [`CommandPath`].
fn command_path_from_value(members: &[(Tag, Value)]) -> Result<CommandPath, ImError> {
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

/// Parse a `CommandDataIB` body (reader positioned just after its struct
/// start), returning `(path, anonymous-tagged CommandFields bytes)`.
fn parse_command_data(r: &mut TlvReader<'_>) -> Result<(CommandPath, Vec<u8>), ImError> {
    let mut path = None;
    let mut fields = Vec::new();
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
    ))
}

/// Parse a `CommandStatusIB` body, returning the `StatusIB.Status` mapped
/// to [`ImStatus`].
fn parse_command_status(r: &mut TlvReader<'_>) -> Result<ImStatus, ImError> {
    let mut status = None;
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
                        status = u8::try_from(*n).ok();
                    }
                }
            }
            Some(Element::ContainerStart { .. }) => skip_container(r)?,
            Some(_) => {}
        }
    }
    Ok(ImStatus::from_u8(
        status.ok_or(ImError::MissingField("StatusIB.Status"))?,
    ))
}

#[cfg(test)]
mod tests {
    // Test-code carve-out: see CLAUDE.md.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::im::CommandPath;
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
        use crate::im::error::ImError;
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
        use crate::im::error::ImError;
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
}
