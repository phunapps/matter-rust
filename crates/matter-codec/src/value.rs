//! Matter TLV element values.
//!
//! Phase 1 of `matter-codec` defines only the scalar variants. Strings
//! (`Utf8`, `Bytes`) ship in phase 2; container variants
//! (`Structure`, `Array`, `List`) ship in phase 3.

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

    /// The TLV null value (element type `0x14`).
    Null,
}
