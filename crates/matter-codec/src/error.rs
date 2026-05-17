//! Error type for `matter-codec`.
//!
//! `Error` covers every failure mode of `TlvReader` and `TlvWriter`. Use the
//! crate's [`Result`] alias for return types.

use thiserror::Error;

/// All errors `matter-codec` can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The reader reached the end of the input before completing an element.
    #[error("unexpected end of input")]
    UnexpectedEof,

    /// The reader encountered a tag-control byte that does not match any
    /// defined tag form.
    #[error("invalid tag control bits 0x{0:02x}")]
    InvalidTagControl(u8),

    /// The reader encountered an element-type code that is not defined by
    /// the spec or is not yet supported by this crate.
    #[error("invalid element type 0x{0:02x}")]
    InvalidElementType(u8),

    /// A UTF-8 string element contained an invalid byte sequence.
    ///
    /// Produced by `TlvReader::next` when reading a UTF-8 element whose
    /// payload bytes fail `core::str::from_utf8` validation.
    #[error("invalid UTF-8 in TLV string: {0}")]
    InvalidUtf8(#[from] core::str::Utf8Error),

    /// An integer payload could not be represented in the declared width.
    #[error("integer value out of range for declared width")]
    IntegerOutOfRange,

    /// The writer was asked to emit into a buffer that has no room.
    ///
    /// Reserved for the fixed-buffer writer variant; the `Vec<u8>`-backed
    /// writer used in phase 1 cannot trigger this.
    #[error("output buffer too small")]
    BufferTooSmall,

    /// A length field would exceed `usize::MAX`.
    #[error("length field overflows usize")]
    LengthOverflow,

    /// A bare end-of-container marker (`0x18`) was read at the top level,
    /// with no container open.
    #[error("unexpected end-of-container marker at top level")]
    UnexpectedEndOfContainer,

    /// End of input was reached while reading the children of a container,
    /// before a closing end-of-container marker arrived.
    #[error("container body truncated before end-of-container marker")]
    UnclosedContainer,

    /// A container was opened at a depth that exceeds the reader's nesting
    /// limit (32 levels per the Matter spec recommendation).
    #[error("container nesting exceeds depth limit")]
    ContainerTooDeep,
}

/// `Result<T, Error>` for convenience.
pub type Result<T> = core::result::Result<T, Error>;
