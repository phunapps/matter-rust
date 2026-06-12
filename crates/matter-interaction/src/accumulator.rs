//! Reassembles chunked `ReportData` messages — the controller-side analogue
//! of chip's `ClusterStateCache`. Merges [`AttributeReportItem`](crate::AttributeReportItem)s
//! across one or more chunks keyed by `(endpoint, cluster, attribute)`.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use matter_codec::Value;

use crate::path::AttributePath;
use crate::read::{ReportData, ReportOp};

/// Accumulates attribute reports across chunked `ReportData` messages and
/// produces the final concrete `(path, value)` set.
///
/// - `Replace` items set the attribute's value; the newest `DataVersion`
///   wins when the same attribute is replaced more than once.
/// - `Append` items (`ListIndex` = null) push one element onto the
///   attribute's list, starting from an empty list if none was seen.
///
/// First-seen attribute order is preserved by [`finish`](Self::finish).
///
/// This accumulator is **unbounded** — it has no view of how many chunks a
/// transport has received. A caller driving it from an untrusted peer must
/// enforce its own chunk / total-size cap before pushing (the read-transaction
/// layer does this); do not feed it directly from a hostile device assuming it
/// self-limits.
///
/// # Examples
///
/// ```
/// use matter_interaction::{parse_report_data, ReportAccumulator};
///
/// # fn demo(chunk_bytes: &[Vec<u8>]) -> Result<(), matter_interaction::ImError> {
/// let mut acc = ReportAccumulator::new();
/// for chunk in chunk_bytes {
///     acc.push(parse_report_data(chunk)?);
/// }
/// let attributes = acc.finish(); // every attribute across all chunks
/// # let _ = attributes;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct ReportAccumulator {
    order: Vec<AttributePath>,
    values: HashMap<(u16, u32, u32), Value>,
    versions: HashMap<(u16, u32, u32), Option<u32>>,
}

impl ReportAccumulator {
    /// Create an empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge one parsed `ReportData` chunk's items into the accumulated state.
    pub fn push(&mut self, report: ReportData) {
        for item in report.items {
            let key = (item.path.endpoint, item.path.cluster, item.path.attribute);
            match item.op {
                ReportOp::Replace => {
                    let newer = match (self.versions.get(&key), item.data_version) {
                        (Some(Some(old)), Some(new)) => new >= *old,
                        _ => true, // unknown versions ⇒ last write wins
                    };
                    if newer {
                        if !self.values.contains_key(&key) {
                            self.order.push(item.path);
                        }
                        self.values.insert(key, item.value);
                        self.versions.insert(key, item.data_version);
                    }
                }
                ReportOp::Append => {
                    if !self.values.contains_key(&key) {
                        self.order.push(item.path);
                        self.values.insert(key, Value::Array(Vec::new()));
                        self.versions.insert(key, item.data_version);
                    }
                    match self.values.get_mut(&key) {
                        Some(Value::Array(list)) => list.push(item.value),
                        // Malformed: an append targeting a non-list value (e.g.
                        // a prior scalar `Replace` for the same path). A
                        // conformant device never does this; coerce to a fresh
                        // single-element list rather than silently dropping the
                        // element.
                        Some(slot) => *slot = Value::Array(vec![item.value]),
                        None => {}
                    }
                }
            }
        }
    }

    /// Consume the accumulator, yielding `(path, value)` in first-seen order.
    ///
    /// Each [`Value`] is **moved** out of the consumed accumulator rather than
    /// cloned: `self.order` records every accumulated path exactly once (a path
    /// is pushed only on the first insert for its key — see [`push`](Self::push)),
    /// so a single [`HashMap::remove`] per path drains the map without aliasing.
    /// This avoids a full deep copy of every attribute subtree on the
    /// chunked-read / subscription completion path.
    #[must_use]
    pub fn finish(mut self) -> Vec<(AttributePath, Value)> {
        let mut out = Vec::with_capacity(self.order.len());
        for path in std::mem::take(&mut self.order) {
            let key = (path.endpoint, path.cluster, path.attribute);
            if let Some(v) = self.values.remove(&key) {
                out.push((path, v));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::read::AttributeReportItem;

    fn report(items: Vec<AttributeReportItem>) -> ReportData {
        ReportData {
            items,
            subscription_id: None,
            more_chunked_messages: false,
            suppress_response: false,
        }
    }

    fn ap(endpoint: u16, cluster: u32, attribute: u32) -> AttributePath {
        AttributePath {
            endpoint,
            cluster,
            attribute,
        }
    }

    fn replace(p: AttributePath, v: Value) -> AttributeReportItem {
        AttributeReportItem {
            path: p,
            op: ReportOp::Replace,
            value: v,
            data_version: None,
        }
    }

    fn append(p: AttributePath, v: Value) -> AttributeReportItem {
        AttributeReportItem {
            path: p,
            op: ReportOp::Append,
            value: v,
            data_version: None,
        }
    }

    #[test]
    fn message_level_merge_preserves_order() {
        let mut acc = ReportAccumulator::new();
        acc.push(report(vec![replace(
            ap(0, 0x28, 0x0002),
            Value::Uint(5010),
        )]));
        acc.push(report(vec![replace(
            ap(1, 0x06, 0x0000),
            Value::Bool(true),
        )]));
        let out = acc.finish();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, ap(0, 0x28, 0x0002));
        assert_eq!(out[0].1, Value::Uint(5010));
        assert_eq!(out[1].0, ap(1, 0x06, 0x0000));
        assert_eq!(out[1].1, Value::Bool(true));
    }

    #[test]
    fn list_append_after_empty_replace() {
        let mut acc = ReportAccumulator::new();
        let p = ap(0, 0x1d, 0x0003);
        acc.push(report(vec![replace(p, Value::Array(Vec::new()))]));
        acc.push(report(vec![append(p, Value::Uint(1))]));
        acc.push(report(vec![append(p, Value::Uint(2))]));
        let out = acc.finish();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1, Value::Array(vec![Value::Uint(1), Value::Uint(2)]));
    }

    #[test]
    fn append_without_base_starts_empty() {
        let mut acc = ReportAccumulator::new();
        let p = ap(0, 0x1d, 0x0003);
        acc.push(report(vec![append(p, Value::Uint(9))]));
        assert_eq!(acc.finish()[0].1, Value::Array(vec![Value::Uint(9)]));
    }

    #[test]
    fn append_onto_non_array_coerces_instead_of_dropping() {
        // Malformed input: a scalar Replace then an Append on the same path.
        // The element must not vanish — the slot coerces to a fresh list.
        let mut acc = ReportAccumulator::new();
        let p = ap(0, 0x1d, 0x0003);
        acc.push(report(vec![replace(p, Value::Uint(1))]));
        acc.push(report(vec![append(p, Value::Uint(2))]));
        assert_eq!(acc.finish()[0].1, Value::Array(vec![Value::Uint(2)]));
    }

    #[test]
    fn newest_data_version_wins() {
        let mut acc = ReportAccumulator::new();
        let p = ap(0, 0x28, 0x0000);
        acc.push(report(vec![AttributeReportItem {
            path: p,
            op: ReportOp::Replace,
            value: Value::Uint(1),
            data_version: Some(5),
        }]));
        acc.push(report(vec![AttributeReportItem {
            path: p,
            op: ReportOp::Replace,
            value: Value::Uint(2),
            data_version: Some(3),
        }]));
        assert_eq!(
            acc.finish()[0].1,
            Value::Uint(1),
            "older DataVersion must not overwrite"
        );
    }

    /// `finish()` now MOVES values out of the consumed accumulator rather than
    /// cloning them. Drive it with heap-bearing values (strings, byte strings,
    /// nested lists) and assert the resulting `(path, value)` set is exactly
    /// what was inserted — proving the move preserves content and order and
    /// drops nothing.
    #[test]
    fn finish_moves_values_preserving_content_and_order() {
        let mut acc = ReportAccumulator::new();
        let p0 = ap(0, 0x28, 0x0001);
        let p1 = ap(1, 0x06, 0x0000);
        let p2 = ap(2, 0x1d, 0x0003);
        let v0 = Value::Utf8(String::from("VendorName"));
        let v1 = Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let v2 = Value::Array(vec![Value::Uint(1), Value::Utf8(String::from("x"))]);
        acc.push(report(vec![
            replace(p0, v0.clone()),
            replace(p1, v1.clone()),
            replace(p2, v2.clone()),
        ]));

        let out = acc.finish();
        assert_eq!(
            out,
            vec![(p0, v0), (p1, v1), (p2, v2)],
            "moved-out set must match inserted (path, value) pairs in first-seen order"
        );
    }

    use proptest::prelude::*;

    proptest! {
        // Splitting a set of whole-attribute Replace items across N chunks
        // yields the same final set as one chunk (message-level chunking is
        // transparent to reassembly), with first-seen order preserved.
        #[test]
        fn message_chunking_is_order_preserving(
            attrs in proptest::collection::vec((0u16..4, 0u32..8, 0u32..8, 0u64..1000), 1..20),
        ) {
            // Dedup by key keeping first occurrence (matches accumulator semantics).
            let mut seen = std::collections::HashSet::new();
            let unique: Vec<_> = attrs.into_iter()
                .filter(|(e, c, a, _)| seen.insert((*e, *c, *a)))
                .collect();

            // All items in one chunk.
            let mut whole = ReportAccumulator::new();
            whole.push(report(
                unique.iter().map(|&(e, c, a, v)| replace(ap(e, c, a), Value::Uint(v))).collect(),
            ));
            let whole_out = whole.finish();

            // Same items, one per chunk.
            let mut split = ReportAccumulator::new();
            for &(e, c, a, v) in &unique {
                split.push(report(vec![replace(ap(e, c, a), Value::Uint(v))]));
            }
            let split_out = split.finish();

            prop_assert_eq!(&whole_out, &split_out);
            // Order matches first-seen.
            for (i, &(e, c, a, _)) in unique.iter().enumerate() {
                prop_assert_eq!(split_out[i].0, ap(e, c, a));
            }
        }

        // Appends accumulate into a list of exactly the pushed elements, in order.
        #[test]
        fn appends_build_list_in_order(elems in proptest::collection::vec(0u64..1000, 0..30)) {
            let p = ap(0, 0x1d, 0x0003);
            let mut acc = ReportAccumulator::new();
            acc.push(report(vec![replace(p, Value::Array(Vec::new()))]));
            for &v in &elems {
                acc.push(report(vec![append(p, Value::Uint(v))]));
            }
            let out = acc.finish();
            let want: Vec<Value> = elems.iter().map(|&v| Value::Uint(v)).collect();
            prop_assert_eq!(&out[0].1, &Value::Array(want));
        }
    }
}
