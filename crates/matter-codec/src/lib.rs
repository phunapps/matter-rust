//! Matter TLV (Tag-Length-Value) encoding and decoding.
//!
//! This is Milestone 1 of the `matter-rust` roadmap.
//!
//! # Scope
//!
//! Phases 1-4 (complete, shipping as `matter-codec` 0.1.0): all scalar
//! element types, UTF-8 and octet strings, every tag form (anonymous,
//! context, common profile, implicit profile, fully-qualified), and
//! containers (structure, array, list) with recursive tree-builder
//! decoding and a 32-level depth limit. Verified by spec test vectors,
//! a `proptest` round-trip property, and a `cargo-fuzz` target.
//!
//! # Usage
//!
//! ```
//! use matter_codec::{Tag, TlvWriter};
//! # fn main() -> Result<(), matter_codec::Error> {
//! let mut bytes = Vec::new();
//! let mut writer = TlvWriter::new(&mut bytes);
//! writer.put_bool(Tag::Anonymous, true)?;
//! assert_eq!(bytes, [0x09]);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod element_type;
mod tag_control;

pub mod error;
pub mod reader;
pub mod tag;
pub mod value;
pub mod writer;

pub use error::{Error, Result};
pub use reader::{ContainerKind, Element, TlvReader, MAX_DEPTH};
pub use tag::Tag;
pub use value::Value;
pub use writer::TlvWriter;
