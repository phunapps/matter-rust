//! Streaming TLV encoder. Appends to a caller-provided `Vec<u8>`.

use crate::error::Result;
use crate::tag::Tag;
use crate::value::Value;
use crate::{element_type as et, tag_control as tc};

/// A streaming TLV encoder that appends to a caller-provided `Vec<u8>`.
pub struct TlvWriter<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> TlvWriter<'a> {
    /// Construct a writer that appends to `out`. The writer borrows `out`
    /// mutably; release the borrow by dropping the writer.
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    /// Write a control octet (tag form bits OR'd with element type bits)
    /// followed by any tag bytes the tag form requires.
    fn write_tag(&mut self, tag: Tag, element_type: u8) {
        match tag {
            Tag::Anonymous => {
                self.out.push(tc::ANONYMOUS | element_type);
            }
            Tag::Context(n) => {
                self.out.push(tc::CONTEXT | element_type);
                self.out.push(n);
            }
        }
    }

    /// Emit a boolean value with the given tag.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Ok(())` always. The `Result` return
    /// type is reserved for future I/O-backed writers.
    pub fn put_bool(&mut self, tag: Tag, v: bool) -> Result<()> {
        let et = if v { et::BOOL_TRUE } else { et::BOOL_FALSE };
        self.write_tag(tag, et);
        Ok(())
    }

    /// Emit a null value with the given tag.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Ok(())` always. The `Result` return
    /// type is reserved for future I/O-backed writers.
    pub fn put_null(&mut self, tag: Tag) -> Result<()> {
        self.write_tag(tag, et::NULL);
        Ok(())
    }

    /// Emit an unsigned integer with the given tag. The minimum-width
    /// encoding (1, 2, 4, or 8 bytes) is chosen automatically per
    /// Matter Core Spec §A.2.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Ok(())` always. The `Result` return
    /// type is reserved for future I/O-backed writers.
    pub fn put_uint(&mut self, tag: Tag, v: u64) -> Result<()> {
        if let Ok(n) = u8::try_from(v) {
            self.write_tag(tag, et::UINT8);
            self.out.push(n);
        } else if let Ok(n) = u16::try_from(v) {
            self.write_tag(tag, et::UINT16);
            self.out.extend_from_slice(&n.to_le_bytes());
        } else if let Ok(n) = u32::try_from(v) {
            self.write_tag(tag, et::UINT32);
            self.out.extend_from_slice(&n.to_le_bytes());
        } else {
            self.write_tag(tag, et::UINT64);
            self.out.extend_from_slice(&v.to_le_bytes());
        }
        Ok(())
    }

    /// Emit a signed integer with the given tag. The minimum-width
    /// encoding (1, 2, 4, or 8 bytes) is chosen automatically per
    /// Matter Core Spec §A.2.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Ok(())` always. The `Result` return
    /// type is reserved for future I/O-backed writers.
    pub fn put_int(&mut self, tag: Tag, v: i64) -> Result<()> {
        if let Ok(n) = i8::try_from(v) {
            self.write_tag(tag, et::INT8);
            self.out.push(n.to_le_bytes()[0]);
        } else if let Ok(n) = i16::try_from(v) {
            self.write_tag(tag, et::INT16);
            self.out.extend_from_slice(&n.to_le_bytes());
        } else if let Ok(n) = i32::try_from(v) {
            self.write_tag(tag, et::INT32);
            self.out.extend_from_slice(&n.to_le_bytes());
        } else {
            self.write_tag(tag, et::INT64);
            self.out.extend_from_slice(&v.to_le_bytes());
        }
        Ok(())
    }

    /// Emit a single-precision IEEE 754 float with the given tag.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Ok(())` always. The `Result` return
    /// type is reserved for future I/O-backed writers.
    pub fn put_float(&mut self, tag: Tag, v: f32) -> Result<()> {
        self.write_tag(tag, et::FLOAT32);
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }

    /// Emit a double-precision IEEE 754 float with the given tag.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Ok(())` always. The `Result` return
    /// type is reserved for future I/O-backed writers.
    pub fn put_double(&mut self, tag: Tag, v: f64) -> Result<()> {
        self.write_tag(tag, et::FLOAT64);
        self.out.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }

    /// Walk a [`Value`] tree and emit the appropriate sequence of TLV
    /// elements. Phase 1 only handles scalar variants; container variants
    /// arrive in phase 3.
    ///
    /// # Errors
    ///
    /// Propagates any error returned by the underlying `put_*` method. In
    /// phase 1, all `put_*` methods are infallible; the `Result` return type
    /// is reserved for future I/O-backed writers and container variants.
    pub fn write_value(&mut self, tag: Tag, value: &Value) -> Result<()> {
        match value {
            Value::Bool(v) => self.put_bool(tag, *v),
            Value::Null => self.put_null(tag),
            Value::Uint(v) => self.put_uint(tag, *v),
            Value::Int(v) => self.put_int(tag, *v),
            Value::Float(v) => self.put_float(tag, *v),
            Value::Double(v) => self.put_double(tag, *v),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test code: CLAUDE.md allows unwrap with
                              // a documented justification.
mod tests {
    use super::*;

    // --- Cycle 1: put_bool ---

    #[test]
    fn put_bool_true_anonymous_matches_vector_0001() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_bool(Tag::Anonymous, true).unwrap();
        assert_eq!(buf, [0x09]);
    }

    #[test]
    fn put_bool_false_anonymous_matches_vector_0002() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_bool(Tag::Anonymous, false).unwrap();
        assert_eq!(buf, [0x08]);
    }

    // --- Cycle 2: put_null ---

    #[test]
    fn put_null_anonymous_emits_0x14() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_null(Tag::Anonymous).unwrap();
        assert_eq!(buf, [0x14]);
    }

    // --- Cycle 3: put_uint ---

    #[test]
    fn put_uint_42_anonymous_picks_1_byte_width_matches_vector_0003() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_uint(Tag::Anonymous, 42).unwrap();
        assert_eq!(buf, [0x04, 0x2A]);
    }

    #[test]
    fn put_uint_max_u8_anonymous_still_1_byte() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_uint(Tag::Anonymous, 255).unwrap();
        assert_eq!(buf, [0x04, 0xFF]);
    }

    #[test]
    fn put_uint_0x1234_anonymous_2_byte_le() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_uint(Tag::Anonymous, 0x1234).unwrap();
        assert_eq!(buf, [0x05, 0x34, 0x12]);
    }

    #[test]
    fn put_uint_0xcafebabe_anonymous_4_byte_le() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_uint(Tag::Anonymous, 0xCAFE_BABE).unwrap();
        assert_eq!(buf, [0x06, 0xBE, 0xBA, 0xFE, 0xCA]);
    }

    #[test]
    fn put_uint_big_anonymous_8_byte_le() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_uint(Tag::Anonymous, 0x0123_4567_89AB_CDEF).unwrap();
        assert_eq!(buf, [0x07, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]);
    }

    // --- Cycle 4: put_int ---

    #[test]
    fn put_int_neg17_anonymous_matches_vector_0008() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_int(Tag::Anonymous, -17).unwrap();
        assert_eq!(buf, [0x00, 0xEF]);
    }

    #[test]
    fn put_int_neg128_anonymous_1_byte() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_int(Tag::Anonymous, -128).unwrap();
        assert_eq!(buf, [0x00, 0x80]);
    }

    #[test]
    fn put_int_neg129_anonymous_2_byte() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_int(Tag::Anonymous, -129).unwrap();
        assert_eq!(buf, [0x01, 0x7F, 0xFF]);
    }

    #[test]
    fn put_int_i32_min_anonymous_4_byte() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_int(Tag::Anonymous, i64::from(i32::MIN)).unwrap();
        assert_eq!(buf, [0x02, 0x00, 0x00, 0x00, 0x80]);
    }

    #[test]
    fn put_int_i64_min_anonymous_8_byte() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_int(Tag::Anonymous, i64::MIN).unwrap();
        assert_eq!(buf, [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
    }

    // --- Cycle 5: put_float and put_double ---

    #[test]
    fn put_float_zero_anonymous_matches_vector_0013() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_float(Tag::Anonymous, 0.0).unwrap();
        assert_eq!(buf, [0x0A, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn put_double_zero_anonymous_matches_vector_0014() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_double(Tag::Anonymous, 0.0).unwrap();
        assert_eq!(buf, [0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    // --- Cycle 6: context tag emission ---

    #[test]
    fn put_uint_with_context_tag_5_emits_tag_byte() {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.put_uint(Tag::Context(5), 42).unwrap();
        // 0b001_00100 = 0x24 (context-tag form | UINT8 element type),
        // then tag number 0x05, then payload 0x2A.
        assert_eq!(buf, [0x24, 0x05, 0x2A]);
    }

    // --- Cycle 7: write_value dispatch ---

    #[test]
    fn write_value_dispatches_on_variant() {
        // One sanity case per variant. Bytes are taken from earlier per-method tests.
        for (value, expected) in [
            (Value::Bool(true), vec![0x09]),
            (Value::Null, vec![0x14]),
            (Value::Uint(42), vec![0x04, 0x2A]),
            (Value::Int(-17), vec![0x00, 0xEF]),
            (Value::Float(0.0), vec![0x0A, 0x00, 0x00, 0x00, 0x00]),
            (
                Value::Double(0.0),
                vec![0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ),
        ] {
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            w.write_value(Tag::Anonymous, &value).unwrap();
            assert_eq!(buf, expected, "value={value:?}");
        }
    }
}
