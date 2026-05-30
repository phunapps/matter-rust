//! `ReadRequestMessage` / `ReportDataMessage` framing — Matter §10.6.

#![forbid(unsafe_code)]

use crate::im::IM_REVISION;
use matter_codec::{Tag, TlvWriter};

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
}
