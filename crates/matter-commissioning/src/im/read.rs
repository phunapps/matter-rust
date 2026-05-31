//! `ReadRequestMessage` / `ReportDataMessage` framing — Matter §10.6.

#![forbid(unsafe_code)]

use crate::im::error::ImError;
use crate::im::{
    expect_message_struct, read_container_members, read_container_value, skip_container,
    IM_REVISION,
};
use matter_codec::{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value};

/// A concrete attribute path: `(endpoint, cluster, attribute)`.
///
/// Encoded as an `AttributePathIB` TLV **list** (Matter Appendix A.6):
/// context tag 2 = endpoint, 3 = cluster, 4 = attribute. Commissioning
/// reads only concrete attributes, so no wildcard/list-index fields are
/// emitted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AttributePath {
    /// Matter endpoint.
    pub endpoint: u16,
    /// Cluster ID.
    pub cluster: u32,
    /// Attribute ID.
    pub attribute: u32,
}

/// Build a `ReadRequestMessage` for one or more concrete attribute paths.
///
/// `FabricFiltered` is `false` (commissioning reads global attributes).
#[must_use]
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.
pub fn build_read_request(paths: &[AttributePath]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)
        .expect("infallible: vec writer");
    w.start_array(Tag::Context(0))
        .expect("infallible: vec writer"); // AttributeRequests
    for p in paths {
        w.start_list(Tag::Anonymous)
            .expect("infallible: vec writer");
        w.put_uint(Tag::Context(2), u64::from(p.endpoint))
            .expect("infallible: vec writer");
        w.put_uint(Tag::Context(3), u64::from(p.cluster))
            .expect("infallible: vec writer");
        w.put_uint(Tag::Context(4), u64::from(p.attribute))
            .expect("infallible: vec writer");
        w.end_container().expect("infallible: vec writer");
    }
    w.end_container().expect("infallible: vec writer"); // AttributeRequests array
    w.put_bool(Tag::Context(3), false)
        .expect("infallible: vec writer"); // FabricFiltered
    w.put_uint(Tag::Context(0xFF), u64::from(IM_REVISION))
        .expect("infallible: vec writer");
    w.end_container().expect("infallible: vec writer");
    buf
}

/// Parsed `ReportDataMessage`: concrete `(path, value)` attribute pairs.
#[derive(Clone, Debug, PartialEq)]
pub struct ReportData {
    /// One entry per `AttributeReportIB` that carried `AttributeData`.
    /// `AttributeStatus` (error) reports are skipped.
    pub attributes: Vec<(AttributePath, Value)>,
}

/// Read an `AttributePathIB` list (`Value::List` members) into an
/// [`AttributePath`]. Out-of-range values surface as
/// [`ImError::UnexpectedValue`] (not as a missing field).
fn attribute_path_from_value(members: &[(Tag, Value)]) -> Result<AttributePath, ImError> {
    let mut endpoint = None;
    let mut cluster = None;
    let mut attribute = None;
    for (tag, v) in members {
        match (tag, v) {
            (Tag::Context(2), Value::Uint(n)) => {
                endpoint =
                    Some(u16::try_from(*n).map_err(|_| {
                        ImError::UnexpectedValue("AttributePath.endpoint exceeds u16")
                    })?);
            }
            (Tag::Context(3), Value::Uint(n)) => {
                cluster =
                    Some(u32::try_from(*n).map_err(|_| {
                        ImError::UnexpectedValue("AttributePath.cluster exceeds u32")
                    })?);
            }
            (Tag::Context(4), Value::Uint(n)) => {
                attribute = Some(u32::try_from(*n).map_err(|_| {
                    ImError::UnexpectedValue("AttributePath.attribute exceeds u32")
                })?);
            }
            _ => {}
        }
    }
    Ok(AttributePath {
        endpoint: endpoint.ok_or(ImError::MissingField("AttributePath.endpoint"))?,
        cluster: cluster.ok_or(ImError::MissingField("AttributePath.cluster"))?,
        attribute: attribute.ok_or(ImError::MissingField("AttributePath.attribute"))?,
    })
}

/// Parse a `ReportDataMessage` into concrete `(path, value)` pairs.
///
/// Walks the `AttributeReports` array; for each `AttributeReportIB` that
/// carries `AttributeData [1]`, extracts the path (`AttributePathIB [1]`)
/// and the data value (`[2]`). `AttributeStatus` error reports are
/// skipped. A message with no `AttributeReports` yields an empty result.
///
/// # Errors
///
/// Returns [`ImError`] if the message is not a struct, a present
/// `AttributeData` is missing its path or data, or a path value is out of
/// range.
pub fn parse_report_data(bytes: &[u8]) -> Result<ReportData, ImError> {
    let mut r = TlvReader::new(bytes);
    expect_message_struct(&mut r)?;

    let mut attributes = Vec::new();

    // Find AttributeReports [1] (array). Absent → empty result.
    loop {
        match r.next()? {
            None | Some(Element::ContainerEnd) => return Ok(ReportData { attributes }),
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Array,
            }) => break,
            Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
            Some(_) => {}
        }
    }

    // Iterate AttributeReportIB structs in the array.
    loop {
        match r.next()? {
            None => return Err(ImError::Codec(matter_codec::Error::UnclosedContainer)),
            Some(Element::ContainerEnd) => break, // end of array
            Some(Element::ContainerStart {
                kind: ContainerKind::Structure,
                ..
            }) => {
                if let Some((path, value)) = parse_attribute_report_ib(&mut r)? {
                    attributes.push((path, value));
                }
            }
            Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
            Some(_) => {}
        }
    }

    Ok(ReportData { attributes })
}

/// Parse one `AttributeReportIB` body. Returns `Some((path, value))` if it
/// carried `AttributeData`, `None` if it was an `AttributeStatus` report.
fn parse_attribute_report_ib(
    r: &mut TlvReader<'_>,
) -> Result<Option<(AttributePath, Value)>, ImError> {
    let mut path = None;
    let mut value = None;
    loop {
        match r.next()? {
            None => return Err(ImError::Codec(matter_codec::Error::UnclosedContainer)),
            Some(Element::ContainerEnd) => break,
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::Structure,
            }) => {
                // AttributeData = struct { 1:Path(list), 2:Data(any) }
                parse_attribute_data(r, &mut path, &mut value)?;
            }
            // AttributeStatus [0] → skip (error entry).
            Some(Element::ContainerStart { .. }) => skip_container(r)?,
            Some(_) => {}
        }
    }
    match (path, value) {
        (Some(p), Some(v)) => Ok(Some((p, v))),
        (None, None) => Ok(None), // no AttributeData present (AttributeStatus report or empty IB)
        (Some(_), None) => Err(ImError::MissingField("AttributeData.Data")),
        (None, Some(_)) => Err(ImError::MissingField("AttributeData.Path")),
    }
}

/// Parse an `AttributeData` body (reader positioned just after the struct
/// start at context tag 1 inside `AttributeReportIB`).
///
/// Populates `path` from the `AttributePathIB` list at tag `[1]` and
/// `value` from the data element at tag `[2]`. Either out-param may be left
/// `None` if absent; the caller (`parse_attribute_report_ib`) treats a
/// partial result as a protocol error.
fn parse_attribute_data(
    r: &mut TlvReader<'_>,
    path: &mut Option<AttributePath>,
    value: &mut Option<Value>,
) -> Result<(), ImError> {
    loop {
        match r.next()? {
            None => return Err(ImError::Codec(matter_codec::Error::UnclosedContainer)),
            Some(Element::ContainerEnd) => return Ok(()),
            Some(Element::ContainerStart {
                tag: Tag::Context(1),
                kind: ContainerKind::List,
            }) => {
                let members = read_container_members(r)?;
                *path = Some(attribute_path_from_value(&members)?);
            }
            Some(Element::Scalar {
                tag: Tag::Context(2),
                value: v,
            }) => *value = Some(v),
            Some(Element::ContainerStart {
                tag: Tag::Context(2),
                kind,
            }) => *value = Some(read_container_value(r, kind)?),
            Some(Element::ContainerStart { .. }) => skip_container(r)?,
            Some(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use matter_codec::{ContainerKind, Element, Tag, TlvReader, Value};

    #[test]
    fn read_request_has_attribute_requests_array() {
        let bytes = build_read_request(&[AttributePath {
            endpoint: 0,
            cluster: 0x0031,
            attribute: 0xFFFC, // FeatureMap
        }]);
        let mut r = TlvReader::new(&bytes);
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure
            })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Context(0),
                kind: ContainerKind::Array
            })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
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
                value: Value::Uint(0x0031)
            })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(4),
                value: Value::Uint(0xFFFC)
            })
        ));
    }

    #[test]
    fn parses_single_attribute_value() {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(1)).unwrap(); // AttributeReports
        {
            w.start_structure(Tag::Anonymous).unwrap(); // AttributeReportIB
            w.start_structure(Tag::Context(1)).unwrap(); // AttributeData
            w.start_list(Tag::Context(1)).unwrap(); // Path (AttributePathIB)
            w.put_uint(Tag::Context(2), 0).unwrap();
            w.put_uint(Tag::Context(3), 0x0031).unwrap();
            w.put_uint(Tag::Context(4), 0xFFFC).unwrap();
            w.end_container().unwrap();
            w.put_uint(Tag::Context(2), 0x0001).unwrap(); // Data
            w.end_container().unwrap(); // AttributeData
            w.end_container().unwrap(); // AttributeReportIB
        }
        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let report = parse_report_data(&buf).unwrap();
        assert_eq!(report.attributes.len(), 1);
        let (path, value) = &report.attributes[0];
        assert_eq!(path.endpoint, 0);
        assert_eq!(path.cluster, 0x0031);
        assert_eq!(path.attribute, 0xFFFC);
        assert_eq!(*value, matter_codec::Value::Uint(0x0001));
    }

    #[test]
    fn attribute_status_report_is_skipped() {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(1)).unwrap(); // AttributeReports
        w.start_structure(Tag::Anonymous).unwrap(); // AttributeReportIB
        w.start_structure(Tag::Context(0)).unwrap(); // AttributeStatus (no AttributeData)
        w.put_uint(Tag::Context(0), 0x01).unwrap(); // some status field
        w.end_container().unwrap();
        w.end_container().unwrap(); // AttributeReportIB
        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let report = parse_report_data(&buf).unwrap();
        assert!(report.attributes.is_empty());
    }

    #[test]
    fn multi_attribute_report_accumulates_all_entries() {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(1)).unwrap(); // AttributeReports

        // First AttributeReportIB: endpoint=0, cluster=0x0028, attribute=0x0000, value=42
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_structure(Tag::Context(1)).unwrap(); // AttributeData
        w.start_list(Tag::Context(1)).unwrap(); // Path
        w.put_uint(Tag::Context(2), 0).unwrap();
        w.put_uint(Tag::Context(3), 0x0028).unwrap();
        w.put_uint(Tag::Context(4), 0x0000).unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(2), 42).unwrap(); // Data
        w.end_container().unwrap(); // AttributeData
        w.end_container().unwrap(); // AttributeReportIB

        // Second AttributeReportIB: endpoint=1, cluster=0x0006, attribute=0x0000, value=1
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_structure(Tag::Context(1)).unwrap(); // AttributeData
        w.start_list(Tag::Context(1)).unwrap(); // Path
        w.put_uint(Tag::Context(2), 1).unwrap();
        w.put_uint(Tag::Context(3), 0x0006).unwrap();
        w.put_uint(Tag::Context(4), 0x0000).unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(2), 1).unwrap(); // Data
        w.end_container().unwrap(); // AttributeData
        w.end_container().unwrap(); // AttributeReportIB

        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let report = parse_report_data(&buf).unwrap();
        assert_eq!(report.attributes.len(), 2);

        let (path0, val0) = &report.attributes[0];
        assert_eq!(path0.endpoint, 0);
        assert_eq!(path0.cluster, 0x0028);
        assert_eq!(path0.attribute, 0x0000);
        assert_eq!(*val0, matter_codec::Value::Uint(42));

        let (path1, val1) = &report.attributes[1];
        assert_eq!(path1.endpoint, 1);
        assert_eq!(path1.cluster, 0x0006);
        assert_eq!(path1.attribute, 0x0000);
        assert_eq!(*val1, matter_codec::Value::Uint(1));
    }

    #[test]
    fn out_of_range_endpoint_yields_unexpected_value() {
        use crate::im::error::ImError;
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.start_array(Tag::Context(1)).unwrap(); // AttributeReports
        w.start_structure(Tag::Anonymous).unwrap(); // AttributeReportIB
        w.start_structure(Tag::Context(1)).unwrap(); // AttributeData
        w.start_list(Tag::Context(1)).unwrap(); // Path
        w.put_uint(Tag::Context(2), 0x0001_0000).unwrap(); // endpoint exceeds u16
        w.put_uint(Tag::Context(3), 0x0031).unwrap();
        w.put_uint(Tag::Context(4), 0xFFFC).unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(2), 0x0001).unwrap(); // Data
        w.end_container().unwrap(); // AttributeData
        w.end_container().unwrap(); // AttributeReportIB
        w.end_container().unwrap(); // array
        w.put_uint(Tag::Context(0xFF), 11).unwrap();
        w.end_container().unwrap();

        let result = parse_report_data(&buf);
        assert!(
            matches!(result, Err(ImError::UnexpectedValue(_))),
            "expected UnexpectedValue, got {result:?}"
        );
    }
}
