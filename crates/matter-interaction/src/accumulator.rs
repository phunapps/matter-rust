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
                    if let Some(Value::Array(list)) = self.values.get_mut(&key) {
                        list.push(item.value);
                    }
                }
            }
        }
    }

    /// Consume the accumulator, yielding `(path, value)` in first-seen order.
    #[must_use]
    pub fn finish(self) -> Vec<(AttributePath, Value)> {
        let mut out = Vec::with_capacity(self.order.len());
        for path in self.order {
            let key = (path.endpoint, path.cluster, path.attribute);
            if let Some(v) = self.values.get(&key) {
                out.push((path, v.clone()));
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
            attributes: Vec::new(),
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
