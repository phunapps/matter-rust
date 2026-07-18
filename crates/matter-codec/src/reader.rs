//! Streaming TLV decoder.
//!
//! [`TlvReader::next`] walks the input one element at a time. Scalars are
//! returned as [`Element::Scalar`]; containers emit a [`Element::ContainerStart`]
//! immediately followed by the children's elements and then a matching
//! [`Element::ContainerEnd`]. Use [`TlvReader::read_value`] to materialise an
//! entire element tree in one call.

use crate::error::{Error, Result};
use crate::tag::Tag;
use crate::value::Value;
use crate::{element_type as et, tag_control as tc};

/// Which kind of TLV container a [`ContainerStart`](Element::ContainerStart)
/// announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContainerKind {
    /// `Value::Structure` — children carry their own (typically context-tagged) tags.
    Structure,
    /// `Value::Array` — children carry anonymous tags only.
    Array,
    /// `Value::List` — children may carry any tag form.
    List,
}

/// One step of the streaming reader.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Element {
    /// A complete scalar (or string/bytes) element.
    Scalar {
        /// The tag that identifies this element within its enclosing context.
        tag: Tag,
        /// The decoded scalar value.
        value: Value,
    },

    /// A container has just been opened. Subsequent `next()` calls
    /// return the container's children until a matching
    /// [`ContainerEnd`](Element::ContainerEnd).
    ContainerStart {
        /// The tag that identifies this container within its enclosing context.
        tag: Tag,
        /// Which container kind was opened.
        kind: ContainerKind,
    },

    /// The most recently-opened container has been closed.
    ContainerEnd,
}

/// Maximum container nesting depth the reader accepts. The Matter spec
/// recommends a 32-level limit to prevent stack blow-up on adversarial
/// input.
pub const MAX_DEPTH: usize = 32;

/// Default ceiling on the total number of [`Value`] elements a single
/// [`TlvReader::read_value`] call may materialise.
///
/// Tree-builder decoding allocates one `Value` (and, inside containers, one
/// `(Tag, Value)` pair) per element. A tiny scalar such as a boolean costs a
/// single wire byte but expands to a heap-resident `Value`, so an input packed
/// with millions of one-byte scalars can amplify into a large allocation. This
/// budget bounds that amplification: a decode that would produce more than this
/// many elements fails with [`Error::ElementBudgetExceeded`].
///
/// The default is deliberately generous (1,048,576 elements) — far above any
/// legitimate Matter payload, which is itself bounded by the protocol's
/// message-size limits — so it only ever trips on adversarial input. Callers
/// that need a tighter or looser bound can set their own via
/// [`TlvReader::with_element_budget`].
pub const DEFAULT_ELEMENT_BUDGET: usize = 1 << 20;

/// A streaming TLV decoder over a borrowed byte slice.
pub struct TlvReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
    /// Remaining element budget for a tree-builder decode. Decremented once
    /// per materialised [`Value`] in [`Self::read_container_body`] /
    /// [`Self::read_value`] — but only on *charged* decodes, i.e. when the
    /// remaining input is larger than this budget; a smaller input provably
    /// cannot exceed it (each element consumes ≥ 1 input byte), so the fast
    /// path skips accounting without weakening the bound (see
    /// [`Self::read_value`]). The streaming [`Self::next`] path does not
    /// touch it because it allocates nothing per element.
    element_budget: usize,
}

impl<'a> TlvReader<'a> {
    /// Construct a reader that walks `bytes` from the start, using the
    /// [`DEFAULT_ELEMENT_BUDGET`] for tree-builder decodes.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            depth: 0,
            element_budget: DEFAULT_ELEMENT_BUDGET,
        }
    }

    /// Construct a reader with a custom total-element budget for tree-builder
    /// decoding (see [`DEFAULT_ELEMENT_BUDGET`]).
    ///
    /// A [`Self::read_value`] call that would materialise more than `budget`
    /// [`Value`] elements fails with [`Error::ElementBudgetExceeded`]. The
    /// budget only affects the tree-builder path; the streaming [`Self::next`]
    /// API is unaffected because it allocates nothing per element.
    pub fn with_element_budget(bytes: &'a [u8], budget: usize) -> Self {
        Self {
            bytes,
            pos: 0,
            depth: 0,
            element_budget: budget,
        }
    }

    /// Whether there is no more input to consume.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Advance one TLV element. Returns `Ok(None)` at end of input.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the input is malformed:
    ///
    /// - [`Error::InvalidTagControl`] — unrecognised tag-control byte form.
    /// - [`Error::InvalidElementType`] — unknown element-type code.
    /// - [`Error::UnexpectedEof`] — truncated payload bytes.
    /// - [`Error::UnexpectedEndOfContainer`] — end-of-container marker (`0x18`)
    ///   at the top level, with no container open.
    /// - [`Error::ContainerTooDeep`] — a container open would exceed
    ///   [`MAX_DEPTH`] nesting levels.
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
        let elem_type = control & et::ELEMENT_TYPE_MASK;

        // End-of-container is always emitted as anonymous tag form.
        if elem_type == et::END_OF_CONTAINER {
            if control & tc::TAG_CONTROL_MASK != tc::ANONYMOUS {
                return Err(Error::InvalidTagControl(control & tc::TAG_CONTROL_MASK));
            }
            if self.depth == 0 {
                return Err(Error::UnexpectedEndOfContainer);
            }
            self.depth -= 1;
            return Ok(Some(Element::ContainerEnd));
        }

        let tag = self.read_tag(control)?;

        // Container opens — record the kind and bump depth.
        let kind = match elem_type {
            et::STRUCTURE => Some(ContainerKind::Structure),
            et::ARRAY => Some(ContainerKind::Array),
            et::LIST => Some(ContainerKind::List),
            _ => None,
        };
        if let Some(kind) = kind {
            if self.depth >= MAX_DEPTH {
                return Err(Error::ContainerTooDeep);
            }
            self.depth += 1;
            return Ok(Some(Element::ContainerStart { tag, kind }));
        }

        let value = self.read_value_body(elem_type)?;
        Ok(Some(Element::Scalar { tag, value }))
    }

    /// Skip the remaining body of the container whose
    /// [`ContainerStart`](Element::ContainerStart) was just returned by
    /// [`Self::next`], consuming through its matching
    /// [`ContainerEnd`](Element::ContainerEnd).
    ///
    /// Call this immediately after `next()` yields a `ContainerStart` you
    /// want to discard — for example an unknown field carried by a struct
    /// from a newer Matter revision. On return the reader is positioned at
    /// the first element *after* the skipped container. Scalars inside the
    /// container are walked but not materialised, so cost is bounded by the
    /// input size and nesting by [`MAX_DEPTH`] (both enforced by `next()`).
    ///
    /// # Errors
    ///
    /// - [`Error::UnclosedContainer`] — end of input before the container's
    ///   closing marker.
    /// - Any error returned by [`Self::next`] (malformed body, over-deep
    ///   nesting, or element-budget exhaustion).
    ///
    /// # Examples
    ///
    /// ```
    /// use matter_codec::{ContainerKind, Element, Tag, TlvReader, TlvWriter};
    /// let mut buf = Vec::new();
    /// let mut w = TlvWriter::new(&mut buf);
    /// w.start_structure(Tag::Anonymous)?;
    /// w.start_structure(Tag::Context(9))?; // an unknown nested field
    /// w.end_container()?;
    /// w.put_uint(Tag::Context(1), 42)?;
    /// w.end_container()?;
    ///
    /// let mut r = TlvReader::new(&buf);
    /// r.next()?; // open the outer struct
    /// // next() returns the nested ctx9 ContainerStart we want to discard:
    /// assert!(matches!(
    ///     r.next()?,
    ///     Some(Element::ContainerStart { kind: ContainerKind::Structure, .. })
    /// ));
    /// r.skip_container()?; // drain the nested struct
    /// // the field after the unknown container is still readable:
    /// assert!(matches!(r.next()?, Some(Element::Scalar { tag: Tag::Context(1), .. })));
    /// # Ok::<(), matter_codec::Error>(())
    /// ```
    pub fn skip_container(&mut self) -> Result<()> {
        let mut depth = 1usize;
        while depth > 0 {
            match self.next()? {
                Some(Element::ContainerStart { .. }) => depth += 1,
                Some(Element::ContainerEnd) => depth -= 1,
                Some(Element::Scalar { .. }) => {}
                None => return Err(Error::UnclosedContainer),
            }
        }
        Ok(())
    }

    /// Materialise one full TLV element as a `(Tag, Value)`. Scalars are
    /// returned directly; containers are read recursively up to
    /// [`MAX_DEPTH`] levels (enforced by [`Self::next`]'s depth counter).
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedEof`] — the input is empty.
    /// - [`Error::UnexpectedEndOfContainer`] — the first element is a stray
    ///   end-of-container marker.
    /// - [`Error::UnclosedContainer`] — end of input was reached before the
    ///   container's closing marker.
    /// - [`Error::NonAnonymousArrayTag`] — an array child carried a
    ///   non-anonymous tag (the spec requires array elements to be anonymous).
    /// - [`Error::ElementBudgetExceeded`] — the decode would materialise more
    ///   than the configured element budget (see [`DEFAULT_ELEMENT_BUDGET`]).
    /// - Any error returned by [`Self::next`].
    pub fn read_value(&mut self) -> Result<(Tag, Value)> {
        // Budget fast path: every materialised element consumes at least one
        // input byte (a null is one control byte; a container is a control
        // byte plus its end marker), so when the remaining input is no larger
        // than the remaining budget this decode CANNOT exceed it — decode
        // with per-element accounting compiled out entirely. Real Matter
        // payloads (≲ 1.5 KiB) against the 2^20 default budget always take
        // this path; the charged path serves oversized or custom-budget
        // inputs.
        //
        // This is observably equivalent to charging every element: a call is
        // only admitted uncharged when the byte bound proves it cannot fail,
        // and from such a call onward every future element from this reader
        // is covered by the same bound (the remaining input only shrinks), so
        // sequences of `read_value` calls fail on exactly the same element —
        // with the same error — as the always-charged implementation. The
        // lifetime invariant is unchanged: one reader never materialises more
        // than its configured budget's worth of live `Value` elements.
        let remaining_input = self.bytes.len().saturating_sub(self.pos);
        if remaining_input <= self.element_budget {
            self.read_value_inner::<false>()
        } else {
            self.read_value_inner::<true>()
        }
    }

    /// Tree-builder body of [`Self::read_value`], monomorphised over whether
    /// per-element budget accounting is active (see the fast-path comment
    /// there — `CHARGE == false` is only reachable when the byte bound proves
    /// the budget cannot be exceeded).
    fn read_value_inner<const CHARGE: bool>(&mut self) -> Result<(Tag, Value)> {
        match self.next()? {
            Some(Element::Scalar { tag, value }) => {
                if CHARGE {
                    self.charge_element()?;
                }
                Ok((tag, value))
            }
            Some(Element::ContainerStart { tag, kind }) => {
                if CHARGE {
                    self.charge_element()?;
                }
                let value = self.read_container_body::<CHARGE>(kind)?;
                Ok((tag, value))
            }
            Some(Element::ContainerEnd) => Err(Error::UnexpectedEndOfContainer),
            None => Err(Error::UnexpectedEof),
        }
    }

    /// Charge one element against the tree-builder budget. Returns
    /// [`Error::ElementBudgetExceeded`] once the budget is exhausted. Only
    /// called on charged decodes ([`Self::read_value`]'s slow path); the
    /// container loops mirror the same arithmetic in a local for speed (see
    /// [`Self::read_container_body`]).
    fn charge_element(&mut self) -> Result<()> {
        self.element_budget = self
            .element_budget
            .checked_sub(1)
            .ok_or(Error::ElementBudgetExceeded)?;
        Ok(())
    }

    /// Decode a container's children into a [`Value`] tree.
    ///
    /// # Element-budget accounting (denial-of-service bound)
    ///
    /// When `CHARGE` is false (the [`Self::read_value`] fast path: the byte
    /// bound already proves the budget cannot be exceeded) no accounting code
    /// is compiled into this copy at all.
    ///
    /// When `CHARGE` is true, the check is the hot path of tree-builder
    /// decoding, so instead of calling [`Self::charge_element`] (a
    /// read-modify-write of `self.element_budget` that the compiler cannot
    /// keep in a register across the `self.next()` calls) each loop mirrors
    /// the remaining budget in a local, charges the local per element, and
    /// syncs it back to `self.element_budget` around recursion and at
    /// container close.
    ///
    /// The preserved invariant: **a charged decode never materialises more
    /// than the configured element budget's worth of [`Value`] elements, and
    /// it fails (`Error::ElementBudgetExceeded`) on exactly the same element
    /// as a per-element field update would** — every element is still
    /// individually charged before it is pushed, and the field is up to date
    /// whenever recursion (the only other consumer) runs. The one observable
    /// difference is on *error* returns: charges made since the last sync are
    /// not written back — which cannot weaken the bound, because the failed
    /// call's partially built tree is dropped with it (the budget bounds live
    /// memory amplification, and a subsequent `read_value` on the same reader
    /// starts from a tree of zero live elements).
    fn read_container_body<const CHARGE: bool>(&mut self, kind: ContainerKind) -> Result<Value> {
        // Branch on the container kind once, before the loop, so arrays decode
        // straight into a `Vec<Value>` without first building a `Vec<(Tag,
        // Value)>` and re-collecting. Structures and lists keep their members'
        // tags.
        match kind {
            ContainerKind::Array => {
                let mut elements: Vec<Value> = Vec::new();
                let mut budget = self.element_budget;
                loop {
                    match self.next()? {
                        None => return Err(Error::UnclosedContainer),
                        Some(Element::ContainerEnd) => break,
                        Some(Element::Scalar { tag, value }) => {
                            // Spec: every array element must be anonymous. Fail
                            // closed on any other tag rather than discarding it.
                            if tag != Tag::Anonymous {
                                return Err(Error::NonAnonymousArrayTag);
                            }
                            if CHARGE {
                                budget =
                                    budget.checked_sub(1).ok_or(Error::ElementBudgetExceeded)?;
                            }
                            elements.push(value);
                        }
                        Some(Element::ContainerStart {
                            tag,
                            kind: inner_kind,
                        }) => {
                            if tag != Tag::Anonymous {
                                return Err(Error::NonAnonymousArrayTag);
                            }
                            if CHARGE {
                                budget =
                                    budget.checked_sub(1).ok_or(Error::ElementBudgetExceeded)?;
                                self.element_budget = budget;
                            }
                            elements.push(self.read_container_body::<CHARGE>(inner_kind)?);
                            if CHARGE {
                                budget = self.element_budget;
                            }
                        }
                    }
                }
                if CHARGE {
                    self.element_budget = budget;
                }
                Ok(Value::Array(elements))
            }
            ContainerKind::Structure | ContainerKind::List => {
                let mut members: Vec<(Tag, Value)> = Vec::new();
                let mut budget = self.element_budget;
                loop {
                    match self.next()? {
                        None => return Err(Error::UnclosedContainer),
                        Some(Element::ContainerEnd) => break,
                        Some(Element::Scalar { tag, value }) => {
                            if CHARGE {
                                budget =
                                    budget.checked_sub(1).ok_or(Error::ElementBudgetExceeded)?;
                            }
                            members.push((tag, value));
                        }
                        Some(Element::ContainerStart {
                            tag,
                            kind: inner_kind,
                        }) => {
                            if CHARGE {
                                budget =
                                    budget.checked_sub(1).ok_or(Error::ElementBudgetExceeded)?;
                                self.element_budget = budget;
                            }
                            let inner = self.read_container_body::<CHARGE>(inner_kind)?;
                            members.push((tag, inner));
                            if CHARGE {
                                budget = self.element_budget;
                            }
                        }
                    }
                }
                if CHARGE {
                    self.element_budget = budget;
                }
                Ok(match kind {
                    ContainerKind::List => Value::List(members),
                    // The outer match guarantees this arm is Structure.
                    _ => Value::Structure(members),
                })
            }
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
                    .map_err(|_| Error::InternalSliceConversion)?;
                Ok(Tag::CommonProfile(u32::from(u16::from_le_bytes(raw))))
            }
            tc::COMMON_PROFILE_4 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::InternalSliceConversion)?;
                Ok(Tag::CommonProfile(u32::from_le_bytes(raw)))
            }
            tc::IMPLICIT_PROFILE_2 => {
                let raw: [u8; 2] = self
                    .next_bytes(2)?
                    .try_into()
                    .map_err(|_| Error::InternalSliceConversion)?;
                Ok(Tag::ImplicitProfile(u32::from(u16::from_le_bytes(raw))))
            }
            tc::IMPLICIT_PROFILE_4 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::InternalSliceConversion)?;
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
            .map_err(|_| Error::InternalSliceConversion)?;
        Ok(u16::from_le_bytes(raw))
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let raw: [u8; 4] = self
            .next_bytes(4)?
            .try_into()
            .map_err(|_| Error::InternalSliceConversion)?;
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
                    .map_err(|_| Error::InternalSliceConversion)?;
                Ok(Value::Uint(u64::from(u16::from_le_bytes(raw))))
            }
            et::UINT32 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::InternalSliceConversion)?;
                Ok(Value::Uint(u64::from(u32::from_le_bytes(raw))))
            }
            et::UINT64 => {
                let raw: [u8; 8] = self
                    .next_bytes(8)?
                    .try_into()
                    .map_err(|_| Error::InternalSliceConversion)?;
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
                    .map_err(|_| Error::InternalSliceConversion)?;
                Ok(Value::Int(i64::from(i16::from_le_bytes(raw))))
            }
            et::INT32 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::InternalSliceConversion)?;
                Ok(Value::Int(i64::from(i32::from_le_bytes(raw))))
            }
            et::INT64 => {
                let raw: [u8; 8] = self
                    .next_bytes(8)?
                    .try_into()
                    .map_err(|_| Error::InternalSliceConversion)?;
                Ok(Value::Int(i64::from_le_bytes(raw)))
            }
            et::FLOAT32 => {
                let raw: [u8; 4] = self
                    .next_bytes(4)?
                    .try_into()
                    .map_err(|_| Error::InternalSliceConversion)?;
                Ok(Value::Float(f32::from_le_bytes(raw)))
            }
            et::FLOAT64 => {
                let raw: [u8; 8] = self
                    .next_bytes(8)?
                    .try_into()
                    .map_err(|_| Error::InternalSliceConversion)?;
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
            .map_err(|_| Error::InternalSliceConversion)?;
        Ok(u64::from_le_bytes(raw))
    }

    fn read_utf8(&mut self, len: usize) -> Result<Value> {
        let bytes = self.next_bytes(len)?;
        // Validate UTF-8 across the ENTIRE payload (a malformed suffix still
        // fails), then present only the text before the first IS1 (0x1F)
        // separator. Matter uses IS1 to separate a char string's text from an
        // optional localized-string language suffix (`"Kitchen\u{1F}0409"`);
        // chip's `TLVReader::Get(CharSpan&)` and matter.js both return only the
        // text (chip TestTLV.cpp CheckTLVCharSpan). Returning the whole payload
        // surfaced the raw separator+suffix on reads of localized labels
        // (BasicInformation NodeLabel, UserLabel) — CODEC-1. The raw suffix
        // (LSID) is not yet exposed; that is a separate additive follow-up.
        let s = core::str::from_utf8(bytes)?;
        // IS1 (0x1F) is single-byte ASCII, so the split index is a valid char
        // boundary.
        let text = match s.find('\u{1F}') {
            Some(i) => &s[..i],
            None => s,
        };
        Ok(Value::Utf8(String::from(text)))
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
        bytes.extend(std::iter::repeat_n(b'a', 256));
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

    // --- Task 4: container event tests ---

    #[test]
    fn next_decodes_structure_start_and_end_vector_0019() {
        let mut r = TlvReader::new(&[0x15, 0x18]);
        let el = r.next().unwrap().unwrap();
        assert_eq!(
            el,
            Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure,
            }
        );
        let el = r.next().unwrap().unwrap();
        assert_eq!(el, Element::ContainerEnd);
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn next_decodes_array_start_and_end_vector_0020() {
        let mut r = TlvReader::new(&[0x16, 0x18]);
        assert_eq!(
            r.next().unwrap().unwrap(),
            Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Array,
            }
        );
        assert_eq!(r.next().unwrap().unwrap(), Element::ContainerEnd);
    }

    #[test]
    fn next_decodes_list_start_and_end() {
        let mut r = TlvReader::new(&[0x17, 0x18]);
        assert_eq!(
            r.next().unwrap().unwrap(),
            Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::List,
            }
        );
        assert_eq!(r.next().unwrap().unwrap(), Element::ContainerEnd);
    }

    #[test]
    fn next_decodes_structure_with_child_streaming() {
        let mut r = TlvReader::new(&[0x15, 0x24, 0x00, 0x2A, 0x18]);
        assert_eq!(
            r.next().unwrap().unwrap(),
            Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure,
            }
        );
        assert_eq!(
            r.next().unwrap().unwrap(),
            Element::Scalar {
                tag: Tag::Context(0),
                value: Value::Uint(42),
            }
        );
        assert_eq!(r.next().unwrap().unwrap(), Element::ContainerEnd);
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn next_errors_on_end_of_container_at_top_level() {
        let mut r = TlvReader::new(&[0x18]);
        assert!(matches!(r.next(), Err(Error::UnexpectedEndOfContainer)));
    }

    #[test]
    fn next_errors_on_end_of_container_with_non_anonymous_tag_form() {
        // 0x38 = context-tag form (0b001) | END_OF_CONTAINER (0x18).
        let mut r = TlvReader::new(&[0x38, 0x05]);
        assert!(matches!(r.next(), Err(Error::InvalidTagControl(_))));
    }

    #[test]
    fn next_errors_on_excessive_nesting() {
        let bytes: Vec<u8> = std::iter::repeat_n(0x15u8, 33).collect();
        let mut r = TlvReader::new(&bytes);
        for _ in 0..32 {
            assert!(matches!(
                r.next().unwrap().unwrap(),
                Element::ContainerStart {
                    kind: ContainerKind::Structure,
                    ..
                },
            ));
        }
        assert!(matches!(r.next(), Err(Error::ContainerTooDeep)));
    }

    #[test]
    fn depth_returns_to_zero_after_balanced_close() {
        // Two readers — one balanced (depth returns to 0), then check that
        // a fresh reader sees 0x18 at top level as UnexpectedEndOfContainer.
        {
            let mut r = TlvReader::new(&[0x15, 0x18]);
            let _ = r.next(); // ContainerStart → depth = 1
            let _ = r.next(); // ContainerEnd → depth = 0
        }
        let mut r2 = TlvReader::new(&[0x18]);
        assert!(matches!(r2.next(), Err(Error::UnexpectedEndOfContainer)));
    }

    // --- Task 5: read_value tree builder tests ---

    #[test]
    fn read_value_returns_empty_structure_vector_0019() {
        let mut r = TlvReader::new(&[0x15, 0x18]);
        let (tag, value) = r.read_value().unwrap();
        assert_eq!(tag, Tag::Anonymous);
        assert_eq!(value, Value::Structure(Vec::new()));
    }

    #[test]
    fn read_value_returns_empty_array_vector_0020() {
        let mut r = TlvReader::new(&[0x16, 0x18]);
        let (tag, value) = r.read_value().unwrap();
        assert_eq!(tag, Tag::Anonymous);
        assert_eq!(value, Value::Array(Vec::new()));
    }

    #[test]
    fn read_value_returns_structure_with_ctx_member_vector_0021() {
        let mut r = TlvReader::new(&[0x15, 0x24, 0x00, 0x2A, 0x18]);
        let (tag, value) = r.read_value().unwrap();
        assert_eq!(tag, Tag::Anonymous);
        assert_eq!(
            value,
            Value::Structure(vec![(Tag::Context(0), Value::Uint(42))])
        );
    }

    #[test]
    fn read_value_returns_array_of_three_uint8_vector_0022() {
        let mut r = TlvReader::new(&[0x16, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x18]);
        let (tag, value) = r.read_value().unwrap();
        assert_eq!(tag, Tag::Anonymous);
        assert_eq!(
            value,
            Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)])
        );
    }

    #[test]
    fn read_value_returns_structure_with_bool_at_ctx7_vector_0023() {
        let mut r = TlvReader::new(&[0x15, 0x29, 0x07, 0x18]);
        let (tag, value) = r.read_value().unwrap();
        assert_eq!(tag, Tag::Anonymous);
        assert_eq!(
            value,
            Value::Structure(vec![(Tag::Context(7), Value::Bool(true))])
        );
    }

    #[test]
    fn read_value_returns_empty_list() {
        let mut r = TlvReader::new(&[0x17, 0x18]);
        let (tag, value) = r.read_value().unwrap();
        assert_eq!(tag, Tag::Anonymous);
        assert_eq!(value, Value::List(Vec::new()));
    }

    #[test]
    fn read_value_handles_nested_structure() {
        let mut r = TlvReader::new(&[0x15, 0x35, 0x00, 0x24, 0x00, 0x2A, 0x18, 0x18]);
        let (tag, value) = r.read_value().unwrap();
        assert_eq!(tag, Tag::Anonymous);
        let inner = Value::Structure(vec![(Tag::Context(0), Value::Uint(42))]);
        let outer = Value::Structure(vec![(Tag::Context(0), inner)]);
        assert_eq!(value, outer);
    }

    #[test]
    fn read_value_errors_on_unclosed_container() {
        let mut r = TlvReader::new(&[0x15]);
        assert!(matches!(r.read_value(), Err(Error::UnclosedContainer)));
    }

    #[test]
    fn read_value_errors_on_dangling_end_of_container() {
        let mut r = TlvReader::new(&[0x18]);
        assert!(matches!(
            r.read_value(),
            Err(Error::UnexpectedEndOfContainer)
        ));
    }

    // --- Task 19: fail-closed array tags, budget, conversion error ---

    #[test]
    fn read_value_rejects_array_with_context_tagged_child() {
        // 0x16 array-start, 0x24 0x00 0x2A = ctx(0) uint8=42, 0x18 end.
        // The child carries a context tag, which the spec forbids inside an
        // array. Pre-fix the decoder silently dropped the tag; now it errors.
        let mut r = TlvReader::new(&[0x16, 0x24, 0x00, 0x2A, 0x18]);
        assert!(matches!(r.read_value(), Err(Error::NonAnonymousArrayTag)));
    }

    #[test]
    fn read_value_rejects_array_with_context_tagged_container_child() {
        // 0x16 array-start, 0x35 0x00 = ctx(0) struct-start, 0x18 inner end,
        // 0x18 outer end. The nested container child is context-tagged.
        let mut r = TlvReader::new(&[0x16, 0x35, 0x00, 0x18, 0x18]);
        assert!(matches!(r.read_value(), Err(Error::NonAnonymousArrayTag)));
    }

    #[test]
    fn read_value_accepts_array_with_anonymous_children() {
        // Sanity: a well-formed array still decodes (regression guard for the
        // fail-closed change).
        let mut r = TlvReader::new(&[0x16, 0x04, 0x01, 0x04, 0x02, 0x18]);
        let (tag, value) = r.read_value().unwrap();
        assert_eq!(tag, Tag::Anonymous);
        assert_eq!(value, Value::Array(vec![Value::Uint(1), Value::Uint(2)]));
    }

    #[test]
    fn read_value_errors_when_element_budget_is_exceeded() {
        // Array of three uint8 children = 4 elements total (array + 3 scalars).
        // A budget of 3 cannot fit them. The 8-byte input is larger than the
        // budget, so this takes the CHARGED path (the fast path is provably
        // unreachable for a violating input: more elements than budget implies
        // more input bytes than budget).
        let bytes = [0x16, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x18];
        let mut r = TlvReader::with_element_budget(&bytes, 3);
        assert!(matches!(r.read_value(), Err(Error::ElementBudgetExceeded)));
    }

    #[test]
    fn read_value_fast_path_at_budget_equal_to_input_len() {
        // Boundary of the uncharged fast path: remaining input (8 bytes) equal
        // to the budget — the byte bound proves the 4 materialised elements
        // cannot exceed it, so the decode succeeds without accounting.
        let bytes = [0x16, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x18];
        let mut r = TlvReader::with_element_budget(&bytes, bytes.len());
        let (_, value) = r.read_value().unwrap();
        assert_eq!(
            value,
            Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)])
        );
    }

    #[test]
    fn read_value_charged_path_at_budget_one_below_input_len() {
        // One below the fast-path boundary: input (8 bytes) > budget (7) takes
        // the charged path, which still admits the 4-element tree.
        let bytes = [0x16, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x18];
        let mut r = TlvReader::with_element_budget(&bytes, 7);
        let (_, value) = r.read_value().unwrap();
        assert_eq!(
            value,
            Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)])
        );
    }

    #[test]
    fn read_value_succeeds_at_exactly_the_element_budget() {
        // Same input, budget of exactly 4, decodes fine.
        let bytes = [0x16, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x18];
        let mut r = TlvReader::with_element_budget(&bytes, 4);
        let (_, value) = r.read_value().unwrap();
        assert_eq!(
            value,
            Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)])
        );
    }

    #[test]
    fn read_value_budget_counts_a_single_scalar() {
        // A lone scalar costs one element; a zero budget rejects it.
        let mut r = TlvReader::with_element_budget(&[0x04, 0x2A], 0);
        assert!(matches!(r.read_value(), Err(Error::ElementBudgetExceeded)));
        let mut r = TlvReader::with_element_budget(&[0x04, 0x2A], 1);
        assert_eq!(r.read_value().unwrap(), (Tag::Anonymous, Value::Uint(42)));
    }

    #[test]
    fn fixed_width_int_decode_still_works() {
        // Guard that the InternalSliceConversion relabel did not change the
        // happy path for a fixed-width int. The conversion branch itself is
        // unreachable: `next_bytes(N)` returns exactly N bytes or `UnexpectedEof`
        // first, so the `try_into::<[u8; N]>` can never fail.
        let mut r = TlvReader::new(&[0x05, 0x34, 0x12]);
        assert_eq!(
            r.next().unwrap().unwrap(),
            Element::Scalar {
                tag: Tag::Anonymous,
                value: Value::Uint(0x1234),
            }
        );
    }

    // --- skip_container ----------------------------------------------------

    /// Build an anonymous structure: ctx0=u(7), then a nested ctx9 struct
    /// {ctx0=u(1)}, then ctx1=u(42). Returns the encoded bytes.
    fn struct_with_nested() -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = crate::writer::TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), 7).unwrap();
        w.start_structure(Tag::Context(9)).unwrap();
        w.put_uint(Tag::Context(0), 1).unwrap();
        w.end_container().unwrap();
        w.put_uint(Tag::Context(1), 42).unwrap();
        w.end_container().unwrap();
        buf
    }

    #[test]
    fn read_utf8_truncates_at_is1_separator() {
        // CODEC-1 / chip TestTLV.cpp CheckTLVCharSpan: a Matter char string is
        // presented as only the text before the first IS1 (0x1F) localized-
        // string separator. The writer keeps the raw bytes on the wire.
        fn decode_str(s: &str) -> String {
            let mut buf = Vec::new();
            let mut w = crate::writer::TlvWriter::new(&mut buf);
            w.put_utf8(Tag::Anonymous, s).unwrap();
            match TlvReader::new(&buf).next().unwrap().unwrap() {
                Element::Scalar {
                    value: Value::Utf8(t),
                    ..
                } => t,
                other => panic!("expected Utf8 scalar, got {other:?}"),
            }
        }
        // chip's two vectors: text before the separator is returned; a string
        // that STARTS with the separator presents as empty.
        assert_eq!(
            decode_str("This is a test case #1\u{1F}suffix"),
            "This is a test case #1"
        );
        assert_eq!(decode_str("\u{1F} abc \u{1F} def"), "");
        // No separator → unchanged; a real localized-label shape → just the text.
        assert_eq!(decode_str("Kitchen"), "Kitchen");
        assert_eq!(decode_str("Kitchen\u{1F}0409"), "Kitchen");
    }

    #[test]
    fn skip_container_drains_nested_struct_and_positions_after() {
        let buf = struct_with_nested();
        let mut r = TlvReader::new(&buf);
        // open the outer struct
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                kind: ContainerKind::Structure,
                ..
            })
        ));
        // consume ctx0=7
        assert!(matches!(r.next().unwrap(), Some(Element::Scalar { .. })));
        // the next element is the nested ctx9 struct — open then skip it
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart {
                kind: ContainerKind::Structure,
                ..
            })
        ));
        r.skip_container().unwrap();
        // reader must now be positioned at ctx1=42, NOT at the outer end
        match r.next().unwrap() {
            Some(Element::Scalar {
                tag: Tag::Context(1),
                value: Value::Uint(v),
            }) => {
                assert_eq!(v, 42);
            }
            other => panic!("expected ctx1=42 after skip, got {other:?}"),
        }
        // then the outer ContainerEnd, then None
        assert!(matches!(r.next().unwrap(), Some(Element::ContainerEnd)));
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn skip_container_handles_array_and_list_and_empty() {
        for kind_byte in ["array", "list", "empty"] {
            let mut buf = Vec::new();
            let mut w = crate::writer::TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).unwrap();
            match kind_byte {
                "array" => {
                    w.start_array(Tag::Context(0)).unwrap();
                    w.put_uint(Tag::Anonymous, 1).unwrap();
                    w.put_uint(Tag::Anonymous, 2).unwrap();
                    w.end_container().unwrap();
                }
                "list" => {
                    w.start_list(Tag::Context(0)).unwrap();
                    w.put_uint(Tag::Context(5), 9).unwrap();
                    w.end_container().unwrap();
                }
                _ => {
                    w.start_structure(Tag::Context(0)).unwrap();
                    w.end_container().unwrap();
                }
            }
            w.put_uint(Tag::Context(1), 99).unwrap();
            w.end_container().unwrap();

            let mut r = TlvReader::new(&buf);
            assert!(matches!(
                r.next().unwrap(),
                Some(Element::ContainerStart { .. })
            ));
            assert!(matches!(
                r.next().unwrap(),
                Some(Element::ContainerStart { .. })
            ));
            r.skip_container().unwrap();
            match r.next().unwrap() {
                Some(Element::Scalar {
                    tag: Tag::Context(1),
                    value: Value::Uint(v),
                }) => {
                    assert_eq!(v, 99, "kind {kind_byte}");
                }
                other => panic!("kind {kind_byte}: expected ctx1=99, got {other:?}"),
            }
        }
    }

    #[test]
    fn skip_container_unclosed_is_error() {
        // outer struct opened, nested struct opened but never closed (truncated)
        let mut buf = Vec::new();
        {
            let mut w = crate::writer::TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_structure(Tag::Context(0)).unwrap();
            w.put_uint(Tag::Anonymous, 1).unwrap();
            // deliberately do NOT close either container
        }
        let mut r = TlvReader::new(&buf);
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart { .. })
        ));
        assert!(matches!(
            r.next().unwrap(),
            Some(Element::ContainerStart { .. })
        ));
        assert!(matches!(r.skip_container(), Err(Error::UnclosedContainer)));
    }
}
