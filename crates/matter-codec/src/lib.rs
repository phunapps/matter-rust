//! Matter TLV (Tag-Length-Value) encoding and decoding.
//!
//! This is Milestone 1 of the `matter-rust` roadmap.
//!
//! # Scope
//!
//! Phase 1 (current): scalar element types (`bool`, `uint`, `int`, `float`,
//! `double`, `null`) under anonymous and context tags.
//!
//! Phase 2 adds string types and the remaining tag forms; phase 3 adds
//! containers (structure, array, list); phase 4 adds property tests, a
//! fuzz target, and the first `0.1.0` release.
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
