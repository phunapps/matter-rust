//! `WriteRequestMessage` / `WriteResponseMessage` framing — Matter §10.6.

#![forbid(unsafe_code)]

use crate::error::ImError;
use crate::path::{attribute_path_from_value, AttributePath};
use crate::status::ImStatus;
use crate::{expect_message_struct, read_container_members, skip_container, IM_REVISION};
use matter_codec::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

/// One attribute write: a concrete path plus the pre-encoded data value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributeWriteRequest {
    /// Concrete attribute path to write.
    pub path: AttributePath,
    /// The attribute value as a standalone anonymous-tagged TLV element
    /// (e.g. the output of a `matter-clusters` attribute encoder).
    pub value_tlv: Vec<u8>,
}

/// Build a `WriteRequestMessage` for one or more concrete attribute writes.
///
/// `SuppressResponse` and `TimedRequest` are both `false`; `DataVersion`
/// and `MoreChunkedMessages` are omitted (no chunking — single-MTU writes
/// only, per the M7 scope).
///
/// # Panics
///
/// Panics if a `value_tlv` is not a valid anonymous-tagged TLV element
/// (i.e. not the output of a codec encode call). The function is
/// otherwise infallible; `Vec`-backed `TlvWriter` never fails.
#[must_use]
pub fn build_write_request(writes: &[AttributeWriteRequest]) -> Vec<u8> {
    build_write_request_inner(writes, false)
}

/// Like [`build_write_request`] but sets `TimedRequest = true` — the action half
/// of a timed interaction, sent on the same exchange after a `TimedRequest`
/// message (see [`crate::build_timed_request`]).
#[must_use]
pub fn build_write_request_timed(writes: &[AttributeWriteRequest]) -> Vec<u8> {
    build_write_request_inner(writes, true)
}

#[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible.
fn build_write_request_inner(writes: &[AttributeWriteRequest], timed: bool) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.put_bool(Tag::Context(0), false)
        .expect("infallible: vec writer"); // SuppressResponse
    w.put_bool(Tag::Context(1), timed)
        .expect("infallible: vec writer"); // TimedRequest
    w.start_array(Tag::Context(2))
        .expect("infallible: vec writer"); // WriteRequests
    for wr in writes {
        w.start_structure(Tag::Anonymous)
            .expect("infallible: vec writer"); // AttributeDataIB
        w.start_list(Tag::Context(1))
            .expect("infallible: vec writer"); // Path (AttributePathIB)
        w.put_uint(Tag::Context(2), u64::from(wr.path.endpoint))
            .expect("infallible: vec writer");
        w.put_uint(Tag::Context(3), u64::from(wr.path.cluster))
            .expect("infallible: vec writer");
        w.put_uint(Tag::Context(4), u64::from(wr.path.attribute))
            .expect("infallible: vec writer");
        w.end_container().expect("infallible: vec writer"); // Path
        w.put_preencoded(Tag::Context(2), &wr.value_tlv)
            .expect("infallible: caller passes a valid anonymous-tagged element"); // Data
        w.end_container().expect("infallible: vec writer"); // AttributeDataIB
    }
    w.end_container().expect("infallible: vec writer"); // WriteRequests array
    w.put_uint(Tag::Context(0xFF), u64::from(IM_REVISION))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer"); // message struct
    buf
}

/// Parse a `WriteResponseMessage` into per-path statuses.
///
/// The write response carries one `AttributeStatusIB` per written path —
/// **including the success case** — so the result is a status per path,
/// not a single message-level status. A message with no `WriteResponses`
/// member yields an empty result.
///
/// # Errors
///
/// Returns [`ImError`] if the message is not a struct, an
/// `AttributeStatusIB` is missing its path or status, or a path value is
/// out of range.
pub fn parse_write_response(bytes: &[u8]) -> Result<Vec<(AttributePath, ImStatus)>, ImError> {
    let mut r = TlvReader::new(bytes);
    expect_message_struct(&mut r)?;

    let mut out = Vec::new();

    // Find WriteResponses [0] (array). Absent → empty result.
    loop {
        match r.next()? {
            None | Some(Element::ContainerEnd) => return Ok(out),
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::Array,
            }) => break,
            Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
            Some(_) => {}
        }
    }

    // Iterate AttributeStatusIB structs in the array.
    loop {
        match r.next()? {
            None => return Err(ImError::Codec(matter_codec::Error::UnclosedContainer)),
            Some(Element::ContainerEnd) => break, // end of array
            Some(Element::ContainerStart {
                kind: ContainerKind::Structure,
                ..
            }) => out.push(parse_attribute_status_ib(&mut r)?),
            Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
            Some(_) => {}
        }
    }

    Ok(out)
}

/// Parse one `AttributeStatusIB` body (reader positioned just after the
/// struct start): `{ 0: Path(list), 1: StatusIB struct { 0: Status } }`.
fn parse_attribute_status_ib(r: &mut TlvReader<'_>) -> Result<(AttributePath, ImStatus), ImError> {
    let mut path = None;
    let mut status = None;
    loop {
        match r.next()? {
            None => return Err(ImError::Codec(matter_codec::Error::UnclosedContainer)),
            Some(Element::ContainerEnd) => break,
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::List,
            }) => {
                let members = read_container_members(r)?;
                path = Some(attribute_path_from_value(&members)?);
            }
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Structure,
            }) => {
                // StatusIB = { 0: Status (uint), 1: ClusterStatus (ignored) }
                let members = read_container_members(r)?;
                // Last value wins for duplicate tags (lenient parsing); real devices never duplicate Status.
                for (tag, v) in &members {
                    if let (Tag::Context(0), Value::Uint(n)) = (tag, v) {
                        let code = u8::try_from(*n)
                            .map_err(|_| ImError::InvalidStatusCode { code: *n })?;
                        status = Some(ImStatus::from_u8(code));
                    }
                }
            }
            Some(Element::ContainerStart { .. }) => skip_container(r)?,
            Some(_) => {}
        }
    }
    Ok((
        path.ok_or(ImError::MissingField("AttributeStatusIB.Path"))?,
        status.ok_or(ImError::MissingField("AttributeStatusIB.Status"))?,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use matter_codec::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

    /// Encode a string as a standalone anonymous TLV element (stand-in for
    /// a matter-clusters attribute encoder).
    fn anon_string(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_utf8(Tag::Anonymous, s).unwrap();
        buf
    }

    #[test]
    fn write_request_has_expected_structure() {
        let bytes = build_write_request(&[AttributeWriteRequest {
            path: AttributePath {
                endpoint: 0,
                cluster: 0x28,
                attribute: 0x05, // NodeLabel
            },
            value_tlv: anon_string("matter-rust"),
        }]);
        let mut r = TlvReader::new(&bytes);
        // message struct
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure
            })
        ));
        // SuppressResponse [0] = false
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(0),
                value: Value::Bool(false)
            })
        ));
        // TimedRequest [1] = false
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(1),
                value: Value::Bool(false)
            })
        ));
        // WriteRequests [2] array
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Context(2),
                kind: ContainerKind::Array
            })
        ));
        // AttributeDataIB struct
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure
            })
        ));
        // Path [1] list with 2/3/4
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::List
            })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(2),
                value: Value::Uint(0)
            })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(3),
                value: Value::Uint(0x28)
            })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(4),
                value: Value::Uint(0x05)
            })
        ));
    }

    /// Build a `WriteResponseMessage` by hand and parse it back.
    fn echo_write_response(entries: &[(AttributePath, u8)]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(0)).unwrap(); // WriteResponses
        for (p, code) in entries {
            w.start_structure(Tag::Anonymous).unwrap(); // AttributeStatusIB
            w.start_list(Tag::Context(0)).unwrap(); // Path
            w.put_uint(Tag::Context(2), u64::from(p.endpoint)).unwrap();
            w.put_uint(Tag::Context(3), u64::from(p.cluster)).unwrap();
            w.put_uint(Tag::Context(4), u64::from(p.attribute)).unwrap();
            w.end_container().unwrap();
            w.start_structure(Tag::Context(1)).unwrap(); // StatusIB
            w.put_uint(Tag::Context(0), u64::from(*code)).unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap(); // AttributeStatusIB
        }
        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();
        buf
    }

    #[test]
    fn parses_success_and_failure_statuses() {
        let p1 = AttributePath {
            endpoint: 0,
            cluster: 0x28,
            attribute: 0x05,
        };
        let p2 = AttributePath {
            endpoint: 0,
            cluster: 0x28,
            attribute: 0x06,
        };
        let msg = echo_write_response(&[(p1, 0x00), (p2, 0x01)]);
        let statuses = parse_write_response(&msg).unwrap();
        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0], (p1, ImStatus::Success));
        assert_eq!(statuses[1], (p2, ImStatus::Failure(0x01)));
    }

    #[test]
    fn missing_status_is_an_error() {
        // AttributeStatusIB with a path but no StatusIB.
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(0)).unwrap();
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_list(Tag::Context(0)).unwrap();
        w.put_uint(Tag::Context(2), 0).unwrap();
        w.put_uint(Tag::Context(3), 0x28).unwrap();
        w.put_uint(Tag::Context(4), 0x05).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let result = parse_write_response(&buf);
        assert!(
            matches!(
                result,
                Err(ImError::MissingField("AttributeStatusIB.Status"))
            ),
            "expected MissingField, got {result:?}"
        );
    }

    #[test]
    fn empty_message_yields_empty_statuses() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();
        let statuses = parse_write_response(&buf).unwrap();
        assert!(statuses.is_empty());
    }
}
