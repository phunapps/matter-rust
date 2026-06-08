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
