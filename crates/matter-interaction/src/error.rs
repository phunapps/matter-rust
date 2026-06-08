//! Error type for Interaction Model framing.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Errors produced while building or parsing Interaction Model messages.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ImError {
    /// Underlying TLV decode failure.
    #[error("TLV codec error: {0}")]
    Codec(#[from] matter_codec::Error),

    /// The message's outermost element was not the expected anonymous struct.
    #[error("expected anonymous structure at message root")]
    NotAStruct,

    /// A required field was absent from the message.
    #[error("missing required IM field: {0}")]
    MissingField(&'static str),

    /// A field held a TLV value of an unexpected type.
    #[error("unexpected TLV value for IM field: {0}")]
    UnexpectedValue(&'static str),

    /// An `InvokeResponseIB` contained neither a Command nor a Status member.
    #[error("InvokeResponseIB had neither Command nor Status")]
    EmptyInvokeResponse,
}
