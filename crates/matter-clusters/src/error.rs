//! Error type for cluster encode/decode operations.

use thiserror::Error;

/// Errors that can occur when decoding or encoding a cluster attribute, command,
/// or struct field.
#[derive(Debug, Error)]
pub enum ClusterError {
    /// The TLV element was present but carried an unexpected type.
    #[error("unexpected TLV type for {context}")]
    UnexpectedType {
        /// Which field or attribute triggered the error.
        context: &'static str,
    },

    /// A value could not be narrowed to the expected integer width.
    #[error("value out of range for {0}")]
    InvalidLength(&'static str),

    /// A required struct field was absent from the TLV container.
    #[error("required field missing: {0}")]
    MissingField(&'static str),

    /// A low-level TLV decode error propagated up from `matter-codec`.
    #[error("TLV error: {0}")]
    Tlv(#[from] matter_codec::Error),
}
