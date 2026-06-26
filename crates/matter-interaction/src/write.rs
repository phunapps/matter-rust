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

/// Reserve for the `MoreChunkedMessages`(ctx3) bool we may add after packing.
const CHUNK_FLAG_RESERVE: usize = 4;

/// Build one or more `WriteRequestMessage`s that write `element_tlvs` (each a
/// pre-encoded anonymous-tagged list element) to `path` as a list, splitting
/// across messages so each stays within `budget` unencrypted bytes.
///
/// Chunk 0 is a `ReplaceAll` (path without `ListIndex`; `Data` = an array of
/// the elements that fit). Remaining elements are emitted as `AppendItem` IBs
/// (path with `ListIndex`=null). `MoreChunkedMessages` (ctx3) is set on every
/// message except the last.
///
/// When everything fits one message the result is a single `ReplaceAll`
/// byte-identical to `build_write_request(&[AttributeWriteRequest{path,
/// value_tlv: <the full array encoded>}])`.
///
/// An empty `element_tlvs` yields a single empty-array `ReplaceAll`.
#[must_use]
pub fn build_list_write_chunks(
    path: AttributePath,
    element_tlvs: &[Vec<u8>],
    budget: usize,
    timed: bool,
) -> Vec<Vec<u8>> {
    // 1) Greedily fill chunk 0's ReplaceAll array.
    let mut idx = 0usize;
    let mut first_batch: Vec<&[u8]> = Vec::new();
    while idx < element_tlvs.len() {
        let candidate: Vec<&[u8]> = first_batch
            .iter()
            .copied()
            .chain(std::iter::once(element_tlvs[idx].as_slice()))
            .collect();
        if encoded_replace_all_len(path, &candidate, timed) + CHUNK_FLAG_RESERVE > budget
            && !first_batch.is_empty()
        {
            break;
        }
        first_batch.push(element_tlvs[idx].as_slice());
        idx += 1;
    }

    // Collect remaining elements as AppendItem batches.
    let mut append_batches: Vec<Vec<&[u8]>> = Vec::new();
    while idx < element_tlvs.len() {
        let mut batch: Vec<&[u8]> = Vec::new();
        while idx < element_tlvs.len() {
            let candidate: Vec<&[u8]> = batch
                .iter()
                .copied()
                .chain(std::iter::once(element_tlvs[idx].as_slice()))
                .collect();
            if encoded_append_len(path, &candidate, timed) + CHUNK_FLAG_RESERVE > budget
                && !batch.is_empty()
            {
                break;
            }
            batch.push(element_tlvs[idx].as_slice());
            idx += 1;
        }
        append_batches.push(batch);
    }

    // 2) Encode each chunk, setting MoreChunkedMessages on all but the last.
    let total = 1 + append_batches.len();
    let mut messages: Vec<Vec<u8>> = Vec::with_capacity(total);
    let first_more = total > 1;
    messages.push(encode_replace_all(path, &first_batch, timed, first_more));
    for (i, batch) in append_batches.iter().enumerate() {
        let more = i + 1 < append_batches.len();
        messages.push(encode_append_items(path, batch, timed, more));
    }
    messages
}

/// Encode a `ReplaceAll` `WriteRequestMessage` containing one `AttributeDataIB`
/// whose `Data` is an anonymous array of `elems`.
#[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible.
fn encode_replace_all(
    path: AttributePath,
    elems: &[&[u8]],
    timed: bool,
    more_chunked: bool,
) -> Vec<u8> {
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

    // One AttributeDataIB — ReplaceAll (no ListIndex in path).
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.start_list(Tag::Context(1))
        .expect("infallible: vec writer"); // Path (AttributePathIB)
    w.put_uint(Tag::Context(2), u64::from(path.endpoint))
        .expect("infallible: vec writer");
    w.put_uint(Tag::Context(3), u64::from(path.cluster))
        .expect("infallible: vec writer");
    w.put_uint(Tag::Context(4), u64::from(path.attribute))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer"); // Path
                                                        // Data = anonymous array containing the pre-encoded elements.
    w.start_array(Tag::Context(2))
        .expect("infallible: vec writer");
    for e in elems {
        w.put_preencoded(Tag::Anonymous, e)
            .expect("infallible: caller passes valid anonymous-tagged elements");
    }
    w.end_container().expect("infallible: vec writer"); // Data array
    w.end_container().expect("infallible: vec writer"); // AttributeDataIB

    w.end_container().expect("infallible: vec writer"); // WriteRequests array
    if more_chunked {
        w.put_bool(Tag::Context(3), true)
            .expect("infallible: vec writer"); // MoreChunkedMessages
    }
    w.put_uint(Tag::Context(0xFF), u64::from(IM_REVISION))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer"); // message struct
    buf
}

/// Encode an `AppendItem` `WriteRequestMessage` containing one
/// `AttributeDataIB` per element — each IB has `ListIndex`=null in its path.
#[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible.
fn encode_append_items(
    path: AttributePath,
    elems: &[&[u8]],
    timed: bool,
    more_chunked: bool,
) -> Vec<u8> {
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

    for e in elems {
        w.start_structure(Tag::Anonymous)
            .expect("infallible: vec writer"); // AttributeDataIB
        w.start_list(Tag::Context(1))
            .expect("infallible: vec writer"); // Path (AttributePathIB)
        w.put_uint(Tag::Context(2), u64::from(path.endpoint))
            .expect("infallible: vec writer");
        w.put_uint(Tag::Context(3), u64::from(path.cluster))
            .expect("infallible: vec writer");
        w.put_uint(Tag::Context(4), u64::from(path.attribute))
            .expect("infallible: vec writer");
        w.put_null(Tag::Context(5)).expect("infallible: vec writer"); // ListIndex=null → AppendItem
        w.end_container().expect("infallible: vec writer"); // Path
        w.put_preencoded(Tag::Context(2), e)
            .expect("infallible: caller passes valid anonymous-tagged elements"); // Data
        w.end_container().expect("infallible: vec writer"); // AttributeDataIB
    }

    w.end_container().expect("infallible: vec writer"); // WriteRequests array
    if more_chunked {
        w.put_bool(Tag::Context(3), true)
            .expect("infallible: vec writer"); // MoreChunkedMessages
    }
    w.put_uint(Tag::Context(0xFF), u64::from(IM_REVISION))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer"); // message struct
    buf
}

fn encoded_replace_all_len(path: AttributePath, elems: &[&[u8]], timed: bool) -> usize {
    encode_replace_all(path, elems, timed, false).len()
}

fn encoded_append_len(path: AttributePath, elems: &[&[u8]], timed: bool) -> usize {
    encode_append_items(path, elems, timed, false).len()
}

/// Parse the element TLVs out of a sequence of `WriteRequestMessage`s produced
/// by [`build_list_write_chunks`], returning them in order.
///
/// For a `ReplaceAll` IB (no `ListIndex` in path) the `Data` is an array;
/// each anonymous array element is re-encoded and pushed. For `AppendItem`
/// IBs (`ListIndex`=null) the `Data` element (ctx2-tagged) is re-encoded as
/// anonymous and pushed.
///
/// This function is provided for test validation only.
#[cfg(test)]
pub(crate) fn reassemble_list_write(chunks: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for chunk in chunks {
        collect_elements_from_chunk(chunk, &mut out);
    }
    out
}

/// Extract element TLVs from one `WriteRequestMessage` chunk into `out`.
///
/// Uses `read_value` to decode each `AttributeDataIB` as a typed `Value`,
/// then walks the structure to extract elements without needing raw-byte seeks.
#[cfg(test)]
#[allow(clippy::expect_used)]
fn collect_elements_from_chunk(chunk: &[u8], out: &mut Vec<Vec<u8>>) {
    let mut r = TlvReader::new(chunk);
    // Enter anonymous message struct.
    let Ok(Some(Element::ContainerStart {
        tag: Tag::Anonymous,
        kind: ContainerKind::Structure,
    })) = r.next()
    else {
        return;
    };

    // Find WriteRequests (ctx2 array).
    loop {
        match r.next() {
            Ok(Some(Element::ContainerStart {
                tag: Tag::Context(2),
                kind: ContainerKind::Array,
            })) => break,
            Ok(Some(Element::ContainerStart { .. })) => {
                let _ = skip_container(&mut r);
            }
            Ok(Some(Element::ContainerEnd) | None) | Err(_) => return,
            Ok(Some(_)) => {}
        }
    }

    // Iterate AttributeDataIBs — read each as a full Value so we can inspect
    // the path and data without a forward-only byte-position API.
    loop {
        match r.next() {
            Ok(Some(Element::ContainerStart {
                kind: ContainerKind::Structure,
                ..
            })) => {
                if let Ok(members) = read_container_members(&mut r) {
                    collect_elements_from_ib_members(&members, out);
                }
            }
            Ok(Some(Element::ContainerEnd) | None) => break,
            Ok(Some(Element::ContainerStart { .. })) => {
                let _ = skip_container(&mut r);
            }
            Ok(Some(_)) | Err(_) => {}
        }
    }
}

/// Walk the decoded `AttributeDataIB` members `[(Tag, Value)]` and push
/// re-encoded anonymous element TLVs into `out`.
///
/// An `AttributeDataIB` has:
/// - `ctx1` → Path (list): may include `ctx5 Null` (`ListIndex`=null) for `AppendItem`
/// - `ctx2` → Data
#[cfg(test)]
#[allow(clippy::expect_used)]
fn collect_elements_from_ib_members(members: &[(Tag, Value)], out: &mut Vec<Vec<u8>>) {
    // Determine whether this is ReplaceAll or AppendItem by inspecting path (ctx1).
    let mut is_append = false;
    let mut data_value: Option<&Value> = None;

    for (tag, value) in members {
        match tag {
            Tag::Context(1) => {
                // Path is a list: check for ListIndex=null (ctx5).
                if let Value::List(path_members) = value {
                    for (pt, pv) in path_members {
                        if *pt == Tag::Context(5) && *pv == Value::Null {
                            is_append = true;
                        }
                    }
                }
            }
            Tag::Context(2) => {
                data_value = Some(value);
            }
            _ => {}
        }
    }

    let Some(data) = data_value else { return };

    if is_append {
        // AppendItem: Data is the element itself (re-tagged ctx2 by put_preencoded).
        // Re-encode it as anonymous-tagged.
        let mut elem_bytes = Vec::new();
        let mut w = TlvWriter::new(&mut elem_bytes);
        w.write_value(Tag::Anonymous, data)
            .expect("infallible: vec writer");
        out.push(elem_bytes);
    } else {
        // ReplaceAll: Data is an Array; each element is a list element.
        if let Value::Array(elems) = data {
            for elem in elems {
                let mut elem_bytes = Vec::new();
                let mut w = TlvWriter::new(&mut elem_bytes);
                w.write_value(Tag::Anonymous, elem)
                    .expect("infallible: vec writer");
                out.push(elem_bytes);
            }
        }
    }
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

#[cfg(test)]
mod chunk_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use matter_codec::{Tag, TlvWriter, Value};
    use proptest::prelude::*;

    fn entry_tlv(n: u64) -> Vec<u8> {
        // a small anonymous-tagged struct standing in for an ACL entry
        let mut b = Vec::new();
        let mut w = TlvWriter::new(&mut b);
        w.write_value(
            Tag::Anonymous,
            &Value::Structure(vec![(Tag::Context(1), Value::Uint(n))]),
        )
        .unwrap();
        b
    }

    fn p() -> AttributePath {
        AttributePath {
            endpoint: 0,
            cluster: 0x001F,
            attribute: 0x0000,
        }
    }

    #[test]
    fn single_chunk_equals_replace_all_build_write_request() {
        let elems = vec![entry_tlv(1), entry_tlv(2)];
        let chunks = build_list_write_chunks(p(), &elems, 4096, false);
        assert_eq!(chunks.len(), 1);
        // Byte-identical to a single ReplaceAll write of the full array.
        let mut arr = Vec::new();
        let mut w = TlvWriter::new(&mut arr);
        w.write_value(
            Tag::Anonymous,
            &Value::Array(vec![
                Value::Structure(vec![(Tag::Context(1), Value::Uint(1))]),
                Value::Structure(vec![(Tag::Context(1), Value::Uint(2))]),
            ]),
        )
        .unwrap();
        let expected = build_write_request(&[AttributeWriteRequest {
            path: p(),
            value_tlv: arr,
        }]);
        assert_eq!(
            chunks[0], expected,
            "single-chunk output must be byte-identical to build_write_request"
        );
    }

    #[test]
    fn overflow_splits_and_sets_more_chunked() {
        // tiny budget forces one element per message
        let elems = vec![entry_tlv(1), entry_tlv(2), entry_tlv(3)];
        let chunks = build_list_write_chunks(p(), &elems, 40, false);
        assert!(
            chunks.len() >= 2,
            "expected multiple chunks, got {}",
            chunks.len()
        );
        // all but last carry MoreChunkedMessages (ctx3 == true); last does not
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(has_more_chunked(c), i + 1 != chunks.len(), "chunk {i}");
        }
    }

    #[test]
    fn reassemble_roundtrips() {
        let elems: Vec<Vec<u8>> = (0..7).map(entry_tlv).collect();
        let chunks = build_list_write_chunks(p(), &elems, 48, false);
        assert_eq!(reassemble_list_write(&chunks), elems);
    }

    // test helper: does this WriteRequestMessage carry MoreChunkedMessages(ctx3)=true?
    fn has_more_chunked(msg: &[u8]) -> bool {
        use matter_codec::{Element, TlvReader};
        let mut r = TlvReader::new(msg);
        // enter the anonymous message struct
        let _ = r.next();
        loop {
            match r.next() {
                Ok(Some(Element::Scalar {
                    tag: Tag::Context(3),
                    value: Value::Bool(b),
                })) => return b,
                Ok(Some(Element::ContainerStart { .. })) => {
                    let _ = super::skip_container(&mut r);
                }
                Ok(Some(Element::ContainerEnd) | None) | Err(_) => return false,
                Ok(Some(_)) => {}
            }
        }
    }

    proptest! {
        #[test]
        fn split_reassemble_identity(count in 0usize..30, budget in 30usize..200) {
            let elems: Vec<Vec<u8>> = (0..count as u64).map(entry_tlv).collect();
            let chunks = build_list_write_chunks(p(), &elems, budget, false);
            prop_assert_eq!(reassemble_list_write(&chunks), elems.clone());
            // MoreChunked invariant
            for (i, c) in chunks.iter().enumerate() {
                prop_assert_eq!(has_more_chunked(c), i + 1 != chunks.len());
            }
        }
    }
}
