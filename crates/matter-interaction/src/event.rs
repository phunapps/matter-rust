//! Matter event paths, filters, and reports — `EventPathIB` / `EventFilterIB` /
//! `EventDataIB` / `EventReportIB` (Matter §10.6 / Appendix A).
//!
//! Distinct from the attribute path/report code: `EventPathIB` uses tag base 0
//! (Node), not 2. Wire shapes are pinned by the matter.js byte-parity fixtures
//! (`test-vectors/commissioning/im/{read/events_basic_information,report/report_data_event}.json`)
//! and cross-checked against connectedhomeip `src/app/MessageDef/Event*IB.h`:
//! `EventPathIB` is a TLV **list**, `EventFilterIB` is a TLV **structure**.

#![forbid(unsafe_code)]

use matter_codec::{Tag, TlvWriter};

/// A read/subscribe event path with optional (wildcard) components. A `None`
/// field is omitted from the encoded `EventPathIB`, which the IM interprets as a
/// wildcard. `node` is normally `None` for a controller addressing the connected
/// node; `is_urgent` requests urgent reporting on a subscription (B2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct EventPath {
    /// Node, or `None` (the connected node / wildcard).
    pub node: Option<u64>,
    /// Endpoint, or `None` for all endpoints.
    pub endpoint: Option<u16>,
    /// Cluster, or `None` for all clusters.
    pub cluster: Option<u32>,
    /// Event, or `None` for all events of the cluster.
    pub event: Option<u32>,
    /// Urgent-reporting hint (subscriptions); omitted when `None`.
    pub is_urgent: Option<bool>,
}

impl EventPath {
    /// A concrete `(endpoint, cluster, event)` path (no node, no urgent flag).
    #[must_use]
    pub fn concrete(endpoint: u16, cluster: u32, event: u32) -> Self {
        Self {
            node: None,
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            event: Some(event),
            is_urgent: None,
        }
    }

    /// All events of `cluster` on `endpoint`.
    #[must_use]
    pub fn cluster(endpoint: u16, cluster: u32) -> Self {
        Self {
            node: None,
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            event: None,
            is_urgent: None,
        }
    }

    /// Encode this path as an anonymous-tagged `EventPathIB` **list** element.
    ///
    /// Tags: Node 0, Endpoint 1, Cluster 2, Event 3, IsUrgent 4 (Matter
    /// Appendix A). Omitted (`None`) fields are wildcards.
    pub(crate) fn write(&self, w: &mut TlvWriter<'_>) -> Result<(), matter_codec::Error> {
        w.start_list(Tag::Anonymous)?;
        if let Some(n) = self.node {
            w.put_uint(Tag::Context(0), n)?;
        }
        if let Some(e) = self.endpoint {
            w.put_uint(Tag::Context(1), u64::from(e))?;
        }
        if let Some(c) = self.cluster {
            w.put_uint(Tag::Context(2), u64::from(c))?;
        }
        if let Some(ev) = self.event {
            w.put_uint(Tag::Context(3), u64::from(ev))?;
        }
        if let Some(u) = self.is_urgent {
            w.put_bool(Tag::Context(4), u)?;
        }
        w.end_container()
    }
}

/// An `EventFilterIB`: only events with `event_number >= event_min` are reported
/// (used to resume after the last seen event). `node` is omitted when `None`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EventFilter {
    /// Node scope, or `None`.
    pub node: Option<u64>,
    /// Minimum event number to report (inclusive).
    pub event_min: u64,
}

impl EventFilter {
    /// A filter reporting events with number `>= event_min`.
    #[must_use]
    pub fn from_event_min(event_min: u64) -> Self {
        Self {
            node: None,
            event_min,
        }
    }

    /// Encode this filter as an anonymous-tagged `EventFilterIB` element.
    ///
    /// NB: `EventFilterIB` is a TLV **structure** (`0x15`), unlike `EventPathIB`
    /// which is a **list** (`0x17`). Confirmed by the captured matter.js bytes
    /// (`events_basic_information.json`): array[2] holds a struct, not a list.
    pub(crate) fn write(&self, w: &mut TlvWriter<'_>) -> Result<(), matter_codec::Error> {
        w.start_structure(Tag::Anonymous)?;
        if let Some(n) = self.node {
            w.put_uint(Tag::Context(0), n)?;
        }
        w.put_uint(Tag::Context(1), self.event_min)?;
        w.end_container()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md test-code carve-out.
    use super::*;
    use matter_codec::{ContainerKind, Element, Tag, TlvReader, Value};

    #[test]
    fn event_path_encodes_as_list_with_tags_1_2_3() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        EventPath::concrete(0, 0x28, 0x00).write(&mut w).unwrap();
        let mut r = TlvReader::new(&buf);
        // EventPathIB is a LIST (not a struct).
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::List
            })
        ));
        // Endpoint=tag 1, Cluster=tag 2, Event=tag 3 (NOT 2/3/4 like AttributePath).
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(1),
                value: Value::Uint(0)
            })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(2),
                value: Value::Uint(0x28)
            })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(3),
                value: Value::Uint(0x00)
            })
        ));
    }

    #[test]
    fn event_filter_encodes_as_struct() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        EventFilter::from_event_min(0).write(&mut w).unwrap();
        let mut r = TlvReader::new(&buf);
        // EventFilterIB is a STRUCTURE (not a list) — vectors-confirmed.
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure
            })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::Scalar {
                tag: Tag::Context(1),
                value: Value::Uint(0)
            })
        ));
    }
}
