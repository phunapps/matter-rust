//! Matter TLV element values.
//!
//! Phase 2 of `matter-codec` adds UTF-8 string and octet-string variants.
//! Container variants (`Structure`, `Array`, `List`) ship in phase 3.

/// A decoded Matter TLV value, collapsed across wire widths.
///
/// Integer widths and float widths are erased from the public type — the
/// encoder chooses the minimal wire width per the spec, and the decoder
/// produces the same Rust type regardless of the width the bytes used. If
/// you need exact-byte round-trip for non-minimal inputs, that capability
/// will land as a low-level `RawElement` API in a later release.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// A boolean.
    Bool(bool),

    /// An unsigned integer, encoded on the wire in 1, 2, 4, or 8 bytes
    /// (minimal width).
    Uint(u64),

    /// A signed integer, encoded on the wire in 1, 2, 4, or 8 bytes
    /// (minimal width).
    Int(i64),

    /// A 4-byte IEEE 754 single-precision float.
    Float(f32),

    /// An 8-byte IEEE 754 double-precision float.
    Double(f64),

    /// A UTF-8 string. The wire format is a 1/2/4/8-byte little-endian
    /// length field (writer picks the minimal width) followed by the
    /// raw UTF-8 bytes. The reader rejects invalid UTF-8 with
    /// [`crate::Error::InvalidUtf8`].
    Utf8(String),

    /// An octet string. The wire format is a 1/2/4/8-byte little-endian
    /// length field (writer picks the minimal width) followed by the
    /// raw bytes.
    Bytes(Vec<u8>),

    /// The TLV null value (element type `0x14`).
    Null,
}
