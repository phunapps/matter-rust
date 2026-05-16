//! Streaming TLV decoder. Phase 1 stub — full implementation lands in a
//! later task. The public types `Element` and `TlvReader` are declared here
//! so that `lib.rs` can re-export them before the decoder is implemented.

use crate::tag::Tag;
use crate::value::Value;

/// A single decoded TLV element: a tag paired with its value.
#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    /// The tag associated with this element.
    pub tag: Tag,
    /// The decoded value.
    pub value: Value,
}

/// A streaming TLV decoder (stub — not yet implemented).
///
/// Will be fully implemented in a later phase. Declared now so that the
/// crate's public API surface is stable.
pub struct TlvReader<'a> {
    _data: &'a [u8],
}

impl<'a> TlvReader<'a> {
    /// Construct a reader over the given byte slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { _data: data }
    }
}
