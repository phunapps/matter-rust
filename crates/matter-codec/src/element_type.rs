//! TLV element-type constants (low 5 bits of the control octet).
//!
//! Defined in the Matter Core Specification §A.2. Crate-internal.

#![allow(dead_code)] // Some variants land in later phases; keep them defined now.

pub(crate) const INT_1: u8 = 0x00;
pub(crate) const INT_2: u8 = 0x01;
pub(crate) const INT_4: u8 = 0x02;
pub(crate) const INT_8: u8 = 0x03;
pub(crate) const UINT_1: u8 = 0x04;
pub(crate) const UINT_2: u8 = 0x05;
pub(crate) const UINT_4: u8 = 0x06;
pub(crate) const UINT_8: u8 = 0x07;
pub(crate) const BOOL_FALSE: u8 = 0x08;
pub(crate) const BOOL_TRUE: u8 = 0x09;
pub(crate) const FLOAT_4: u8 = 0x0A;
pub(crate) const FLOAT_8: u8 = 0x0B;
pub(crate) const UTF8_1: u8 = 0x0C;
pub(crate) const UTF8_2: u8 = 0x0D;
pub(crate) const UTF8_4: u8 = 0x0E;
pub(crate) const UTF8_8: u8 = 0x0F;
pub(crate) const BYTES_1: u8 = 0x10;
pub(crate) const BYTES_2: u8 = 0x11;
pub(crate) const BYTES_4: u8 = 0x12;
pub(crate) const BYTES_8: u8 = 0x13;
pub(crate) const NULL: u8 = 0x14;
pub(crate) const STRUCTURE: u8 = 0x15;
pub(crate) const ARRAY: u8 = 0x16;
pub(crate) const LIST: u8 = 0x17;
pub(crate) const END_OF_CONTAINER: u8 = 0x18;

/// Mask isolating the element-type bits of a control octet.
pub(crate) const ELEMENT_TYPE_MASK: u8 = 0b0001_1111;
