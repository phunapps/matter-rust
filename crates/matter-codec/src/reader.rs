//! Streaming TLV decoder.
//!
//! [`TlvReader::next`] walks the input one element at a time. Scalars are
//! materialised in one call; container elements (phase 3) will yield separate
//! `ContainerStart`/`ContainerEnd` markers. A `read_value` convenience method
//! that materialises a single element as a [`Value`] tree is planned for a
//! later phase.

use crate::error::{Error, Result};
use crate::tag::Tag;
use crate::value::Value;
use crate::{element_type as et, tag_control as tc};

/// One step of the streaming reader.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Element {
    /// A complete scalar element. Phase 1 always produces this variant.
    Scalar {
        /// The tag that identifies this element within its enclosing context.
        tag: Tag,
        /// The decoded scalar value.
        value: Value,
    },
    // ContainerStart / ContainerEnd arrive in phase 3.
}

/// A streaming TLV decoder over a borrowed byte slice.
pub struct TlvReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> TlvReader<'a> {
    /// Construct a reader that walks `bytes` from the start.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Whether there is no more input to consume.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Advance one TLV element. Returns `Ok(None)` at end of input.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the input is malformed: an unrecognised tag-control
    /// form ([`Error::InvalidTagControl`]), an unknown element-type code
    /// ([`Error::InvalidElementType`]), or truncated payload bytes
    /// ([`Error::UnexpectedEof`]).
    ///
    /// # Note on naming
    ///
    /// This method is deliberately named `next` to match the streaming-reader
    /// idiom established by e.g. `serde`'s `Deserializer`. It returns
    /// `Result<Option<T>>` rather than `Option<Result<T>>` so that callers
    /// use `?` naturally. Implementing `std::iter::Iterator` is deferred to
    /// a later phase when a fallible-iterator adapter is available.
    #[allow(clippy::should_implement_trait)] // See note above; Iterator requires Option<Item>, not Result<Option<Item>>.
    pub fn next(&mut self) -> Result<Option<Element>> {
        if self.is_empty() {
            return Ok(None);
        }
        let control = self.next_byte()?;
        let tag = self.read_tag(control)?;
        let elem_type = control & et::ELEMENT_TYPE_MASK;
        let value = self.read_value_body(elem_type)?;
        Ok(Some(Element::Scalar { tag, value }))
    }

    /// Materialise one full TLV element as a `(Tag, Value)`. Scalars are
    /// returned directly; container traversal arrives in phase 3.
    ///
    /// Returns [`Error::UnexpectedEof`] if there is no element to read.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the input is empty ([`Error::UnexpectedEof`]) or if
    /// the underlying [`Self::next`] call fails for any reason.
    pub fn read_value(&mut self) -> Result<(Tag, Value)> {
        match self.next()? {
            Some(Element::Scalar { tag, value }) => Ok((tag, value)),
            None => Err(Error::UnexpectedEof),
        }
    }

    fn next_byte(&mut self) -> Result<u8> {
        let b = *self.bytes.get(self.pos).ok_or(Error::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    fn next_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::LengthOverflow)?;
        let slice = self.bytes.get(self.pos..end).ok_or(Error::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_tag(&mut self, control: u8) -> Result<Tag> {
        match control & tc::TAG_CONTROL_MASK {
            tc::ANONYMOUS => Ok(Tag::Anonymous),
            tc::CONTEXT => {
                let n = self.next_byte()?;
                Ok(Tag::Context(n))
            }
            tc::COMMON_PROFILE_2 => {
                let raw: [u8; 2] = self
                    .next_bytes(2)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Tag::CommonProfile(u32::from(u16::from_le_bytes(raw))))
            }
            tc::COMMON_PROFILE_4 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Tag::CommonProfile(u32::from_le_bytes(raw)))
            }
            tc::IMPLICIT_PROFILE_2 => {
                let raw: [u8; 2] = self
                    .next_bytes(2)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Tag::ImplicitProfile(u32::from(u16::from_le_bytes(raw))))
            }
            tc::IMPLICIT_PROFILE_4 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Tag::ImplicitProfile(u32::from_le_bytes(raw)))
            }
            tc::FULLY_QUALIFIED_6 => {
                let vendor = self.read_u16_le()?;
                let profile = self.read_u16_le()?;
                let tag = u32::from(self.read_u16_le()?);
                Ok(Tag::FullyQualified {
                    vendor,
                    profile,
                    tag,
                })
            }
            tc::FULLY_QUALIFIED_8 => {
                let vendor = self.read_u16_le()?;
                let profile = self.read_u16_le()?;
                let tag = self.read_u32_le()?;
                Ok(Tag::FullyQualified {
                    vendor,
                    profile,
                    tag,
                })
            }
            // The 3-bit tag-control field has only 8 possible values, and
            // we have arms for all 8. This arm is unreachable in practice
            // but rustc cannot prove that statically.
            other => Err(Error::InvalidTagControl(other)),
        }
    }

    fn read_u16_le(&mut self) -> Result<u16> {
        let raw: [u8; 2] = self
            .next_bytes(2)?
            .try_into()
            .map_err(|_| Error::UnexpectedEof)?;
        Ok(u16::from_le_bytes(raw))
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let raw: [u8; 4] = self
            .next_bytes(4)?
            .try_into()
            .map_err(|_| Error::UnexpectedEof)?;
        Ok(u32::from_le_bytes(raw))
    }

    #[allow(clippy::cast_possible_wrap)] // `b as i8`: reinterprets the byte pattern as signed, not truncation.
    fn read_value_body(&mut self, elem_type: u8) -> Result<Value> {
        match elem_type {
            et::BOOL_FALSE => Ok(Value::Bool(false)),
            et::BOOL_TRUE => Ok(Value::Bool(true)),
            et::NULL => Ok(Value::Null),
            et::UINT8 => Ok(Value::Uint(u64::from(self.next_byte()?))),
            et::UINT16 => {
                let raw: [u8; 2] = self
                    .next_bytes(2)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Value::Uint(u64::from(u16::from_le_bytes(raw))))
            }
            et::UINT32 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Value::Uint(u64::from(u32::from_le_bytes(raw))))
            }
            et::UINT64 => {
                let raw: [u8; 8] = self
                    .next_bytes(8)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Value::Uint(u64::from_le_bytes(raw)))
            }
            et::INT8 => {
                let b = self.next_byte()?;
                Ok(Value::Int(i64::from(b as i8)))
            }
            et::INT16 => {
                let raw: [u8; 2] = self
                    .next_bytes(2)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Value::Int(i64::from(i16::from_le_bytes(raw))))
            }
            et::INT32 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Value::Int(i64::from(i32::from_le_bytes(raw))))
            }
            et::INT64 => {
                let raw: [u8; 8] = self
                    .next_bytes(8)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Value::Int(i64::from_le_bytes(raw)))
            }
            et::FLOAT32 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Value::Float(f32::from_le_bytes(raw)))
            }
            et::FLOAT64 => {
                let raw: [u8; 8] = self
                    .next_bytes(8)?
                    .try_into()
                    .map_err(|_| Error::UnexpectedEof)?;
                Ok(Value::Double(f64::from_le_bytes(raw)))
            }
            et::UTF8_LEN8 | et::UTF8_LEN16 | et::UTF8_LEN32 | et::UTF8_LEN64 => {
                let len = self.read_payload_len(elem_type)?;
                self.read_utf8(len)
            }
            et::BYTES_LEN8 | et::BYTES_LEN16 | et::BYTES_LEN32 | et::BYTES_LEN64 => {
                let len = self.read_payload_len(elem_type)?;
                self.read_bytes(len)
            }
            other => Err(Error::InvalidElementType(other)),
        }
    }

    /// Read the variable-width length field that precedes utf8 and bytes
    /// payloads. The two low bits of the element type encode the width:
    /// `0b00` = 1 byte, `0b01` = 2 bytes, `0b10` = 4 bytes, `0b11` = 8 bytes.
    fn read_payload_len(&mut self, elem_type: u8) -> Result<usize> {
        match elem_type & 0b11 {
            0b00 => Ok(usize::from(self.next_byte()?)),
            0b01 => Ok(usize::from(self.read_u16_le()?)),
            0b10 => usize::try_from(self.read_u32_le()?).map_err(|_| Error::LengthOverflow),
            _ => usize::try_from(self.read_u64_le()?).map_err(|_| Error::LengthOverflow),
        }
    }

    fn read_u64_le(&mut self) -> Result<u64> {
        let raw: [u8; 8] = self
            .next_bytes(8)?
            .try_into()
            .map_err(|_| Error::UnexpectedEof)?;
        Ok(u64::from_le_bytes(raw))
    }

    fn read_utf8(&mut self, len: usize) -> Result<Value> {
        let bytes = self.next_bytes(len)?;
        let s = core::str::from_utf8(bytes)?;
        Ok(Value::Utf8(String::from(s)))
    }

    fn read_bytes(&mut self, len: usize) -> Result<Value> {
        let bytes = self.next_bytes(len)?;
        Ok(Value::Bytes(bytes.to_vec()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test code: CLAUDE.md allows unwrap with a documented justification.
mod tests {
    use super::*;

    #[test]
    fn next_returns_none_on_empty_input() {
        let mut r = TlvReader::new(&[]);
        assert!(r.is_empty());
        assert_eq!(r.next().unwrap(), None);
    }

    #[test]
    fn next_decodes_bool_true_anonymous_vector_0001() {
        let mut r = TlvReader::new(&[0x09]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Bool(true)
            }
        );
        assert!(r.is_empty());
    }

    #[test]
    fn next_decodes_bool_false() {
        let mut r = TlvReader::new(&[0x08]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Bool(false)
            }
        );
    }

    #[test]
    fn next_decodes_null_vector_implied() {
        let mut r = TlvReader::new(&[0x14]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Null
            }
        );
    }

    #[test]
    fn next_decodes_uint8_42_vector_0003() {
        let mut r = TlvReader::new(&[0x04, 0x2A]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Uint(42)
            }
        );
    }

    #[test]
    fn next_decodes_uint16_0x1234() {
        let mut r = TlvReader::new(&[0x05, 0x34, 0x12]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Uint(0x1234)
            }
        );
    }

    #[test]
    fn next_decodes_uint32_0xcafebabe() {
        let mut r = TlvReader::new(&[0x06, 0xBE, 0xBA, 0xFE, 0xCA]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Uint(0xCAFE_BABE)
            }
        );
    }

    #[test]
    fn next_decodes_uint64_big() {
        let bytes = [0x07, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        let mut r = TlvReader::new(&bytes);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Uint(0x0123_4567_89AB_CDEF),
            }
        );
    }

    #[test]
    fn next_decodes_int8_neg17_vector_0008() {
        let mut r = TlvReader::new(&[0x00, 0xEF]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Int(-17)
            }
        );
    }

    #[test]
    fn next_decodes_int16_neg129() {
        let mut r = TlvReader::new(&[0x01, 0x7F, 0xFF]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Int(-129)
            }
        );
    }

    #[test]
    fn next_decodes_int32_min() {
        let mut r = TlvReader::new(&[0x02, 0x00, 0x00, 0x00, 0x80]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Int(i64::from(i32::MIN))
            }
        );
    }

    #[test]
    fn next_decodes_int64_min() {
        let bytes = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        let mut r = TlvReader::new(&bytes);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Int(i64::MIN)
            }
        );
    }

    #[test]
    fn next_decodes_float32_zero_vector_0013() {
        let mut r = TlvReader::new(&[0x0A, 0x00, 0x00, 0x00, 0x00]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Float(0.0)
            }
        );
    }

    #[test]
    fn next_decodes_float64_zero_vector_0014() {
        let bytes = [0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut r = TlvReader::new(&bytes);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Double(0.0)
            }
        );
    }

    #[test]
    fn next_decodes_uint_with_context_tag_5() {
        let mut r = TlvReader::new(&[0x24, 0x05, 0x2A]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Context(5),
                value: Value::Uint(42)
            }
        );
    }

    #[test]
    fn next_errors_on_unexpected_eof_in_payload() {
        let mut r = TlvReader::new(&[0x05]); // uint16 with no payload
        assert!(matches!(r.next(), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn next_decodes_uint_with_common_profile_2_byte_tag() {
        let mut r = TlvReader::new(&[0x44, 0x07, 0x00, 0x2A]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::CommonProfile(7),
                value: Value::Uint(42)
            }
        );
    }

    #[test]
    fn next_decodes_uint_with_common_profile_4_byte_tag() {
        let mut r = TlvReader::new(&[0x64, 0x45, 0x23, 0x01, 0x00, 0x2A]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::CommonProfile(0x0001_2345),
                value: Value::Uint(42)
            }
        );
    }

    #[test]
    fn next_decodes_uint_with_implicit_profile_2_byte_tag() {
        let mut r = TlvReader::new(&[0x84, 0x07, 0x00, 0x2A]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::ImplicitProfile(7),
                value: Value::Uint(42)
            }
        );
    }

    #[test]
    fn next_decodes_uint_with_implicit_profile_4_byte_tag() {
        let mut r = TlvReader::new(&[0xA4, 0x45, 0x23, 0x01, 0x00, 0x2A]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::ImplicitProfile(0x0001_2345),
                value: Value::Uint(42)
            }
        );
    }

    #[test]
    fn next_decodes_uint_with_fully_qualified_6_byte() {
        let mut r = TlvReader::new(&[0xC4, 0xF1, 0xFF, 0x06, 0x00, 0x05, 0x00, 0x2A]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::FullyQualified {
                    vendor: 0xFFF1,
                    profile: 0x0006,
                    tag: 5
                },
                value: Value::Uint(42),
            }
        );
    }

    #[test]
    fn next_decodes_uint_with_fully_qualified_8_byte() {
        let mut r = TlvReader::new(&[0xE4, 0xF1, 0xFF, 0x06, 0x00, 0x45, 0x23, 0x01, 0x00, 0x2A]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::FullyQualified {
                    vendor: 0xFFF1,
                    profile: 0x0006,
                    tag: 0x0001_2345
                },
                value: Value::Uint(42),
            }
        );
    }

    #[test]
    fn next_errors_on_invalid_element_type() {
        let mut r = TlvReader::new(&[0x18]); // end-of-container outside container
        let err = r.next().unwrap_err();
        assert!(matches!(err, Error::InvalidElementType(0x18)));
    }

    #[test]
    fn read_value_returns_tag_and_value_for_scalar() {
        let mut r = TlvReader::new(&[0x24, 0x05, 0x2A]);
        let (tag, value) = r.read_value().unwrap();
        assert_eq!(tag, Tag::Context(5));
        assert_eq!(value, Value::Uint(42));
    }

    #[test]
    fn read_value_errors_on_empty_input() {
        let mut r = TlvReader::new(&[]);
        assert!(matches!(r.read_value(), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn next_decodes_utf8_hello_vector_0015() {
        let bytes = [0x0C, 0x06, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21];
        let mut r = TlvReader::new(&bytes);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Utf8(String::from("Hello!")),
            }
        );
    }

    #[test]
    fn next_decodes_utf8_empty_vector_0016() {
        let bytes = [0x0C, 0x00];
        let mut r = TlvReader::new(&bytes);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Utf8(String::new()),
            }
        );
    }

    #[test]
    fn next_decodes_utf8_len16_path() {
        let mut bytes = vec![0x0D, 0x00, 0x01]; // UTF8_LEN16, length 256 LE
        bytes.extend(std::iter::repeat(b'a').take(256));
        let mut r = TlvReader::new(&bytes);
        let el = r.next().unwrap().unwrap();
        let Element::Scalar {
            value: Value::Utf8(s),
            ..
        } = el
        else {
            panic!("wrong variant")
        };
        assert_eq!(s.len(), 256);
        assert!(s.bytes().all(|b| b == b'a'));
    }

    #[test]
    fn next_decodes_bytes_five_bytes_vector_0017() {
        let bytes = [0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut r = TlvReader::new(&bytes);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Bytes(vec![0x00, 0x01, 0x02, 0x03, 0x04]),
            }
        );
    }

    #[test]
    fn next_decodes_bytes_empty_vector_0018() {
        let bytes = [0x10, 0x00];
        let mut r = TlvReader::new(&bytes);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Bytes(Vec::new()),
            }
        );
    }

    #[test]
    fn next_errors_on_invalid_utf8() {
        let bytes = [0x0C, 0x01, 0xFF];
        let mut r = TlvReader::new(&bytes);
        assert!(matches!(r.next(), Err(Error::InvalidUtf8(_))));
    }

    #[test]
    fn next_errors_on_truncated_utf8_payload() {
        let bytes = [0x0C, 0x05, b'H', b'i']; // claims 5 bytes, has only 2
        let mut r = TlvReader::new(&bytes);
        assert!(matches!(r.next(), Err(Error::UnexpectedEof)));
    }
}
