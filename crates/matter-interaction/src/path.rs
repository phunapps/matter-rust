//! Concrete IM paths: `CommandPathIB` and `AttributePathIB` — Matter
//! Appendix A.6.

#![forbid(unsafe_code)]

use crate::error::ImError;
use matter_codec::{Tag, Value};

/// A concrete command path: `(endpoint, cluster, command)`.
///
/// Encoded as a `CommandPathIB` TLV **list** (Matter Appendix A.6):
/// context tag 0 = endpoint, 1 = cluster, 2 = command.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CommandPath {
    /// Matter endpoint (always 0 for commissioning).
    pub endpoint: u16,
    /// Cluster ID.
    pub cluster: u32,
    /// Command ID.
    pub command: u32,
}

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

/// A read-request attribute path with optional (wildcard) components. A `None`
/// field is **omitted** from the encoded `AttributePathIB`, which the Matter IM
/// interprets as a wildcard (Appendix A.6): omit `attribute` → all attributes of
/// the cluster; omit `endpoint` → all endpoints; etc. Responses are always keyed
/// by a concrete [`AttributePath`].
///
/// `#[non_exhaustive]`: a read/subscribe path may gain optional spec components
/// (e.g. a data-version filter); marking it keeps such additions non-breaking.
/// Build via [`ReadPath::concrete`] / [`ReadPath::cluster`] / [`ReadPath::all`]
/// / [`ReadPath::new`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ReadPath {
    /// Endpoint, or `None` for all endpoints.
    pub endpoint: Option<u16>,
    /// Cluster, or `None` for all clusters.
    pub cluster: Option<u32>,
    /// Attribute, or `None` for all attributes.
    pub attribute: Option<u32>,
}

impl ReadPath {
    /// A read path from raw optional components (a `None` component is a
    /// wildcard). Prefer [`Self::concrete`] / [`Self::cluster`] / [`Self::all`]
    /// for the common shapes.
    #[must_use]
    pub fn new(endpoint: Option<u16>, cluster: Option<u32>, attribute: Option<u32>) -> Self {
        Self {
            endpoint,
            cluster,
            attribute,
        }
    }

    /// A concrete `(endpoint, cluster, attribute)` path (no wildcards).
    #[must_use]
    pub fn concrete(endpoint: u16, cluster: u32, attribute: u32) -> Self {
        Self {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attribute: Some(attribute),
        }
    }

    /// All attributes of `cluster` on `endpoint`.
    #[must_use]
    pub fn cluster(endpoint: u16, cluster: u32) -> Self {
        Self {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attribute: None,
        }
    }

    /// Every attribute on every endpoint/cluster (full wildcard).
    #[must_use]
    pub fn all() -> Self {
        Self {
            endpoint: None,
            cluster: None,
            attribute: None,
        }
    }
}

impl From<AttributePath> for ReadPath {
    fn from(p: AttributePath) -> Self {
        Self {
            endpoint: Some(p.endpoint),
            cluster: Some(p.cluster),
            attribute: Some(p.attribute),
        }
    }
}

/// Read an `AttributePathIB` list (`Value::List` members) into an
/// [`AttributePath`]. Out-of-range values surface as
/// [`ImError::UnexpectedValue`] (not as a missing field).
pub(crate) fn attribute_path_from_value(
    members: &[(Tag, Value)],
) -> Result<AttributePath, ImError> {
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

/// Like [`attribute_path_from_value`], but also reports whether the path
/// carried a `ListIndex` (context tag 5) equal to `null`, which in a
/// `ReportData` signals a list **append** (Matter §10.6.4). Returns
/// `(path, list_index_is_null_append)`.
pub(crate) fn attribute_path_and_append_from_value(
    members: &[(Tag, Value)],
) -> Result<(AttributePath, bool), ImError> {
    let path = attribute_path_from_value(members)?;
    let append = members
        .iter()
        .any(|(tag, v)| matches!(tag, Tag::Context(5)) && matches!(v, Value::Null));
    Ok((path, append))
}
