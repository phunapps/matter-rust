//! Matter TLV (Tag-Length-Value) encoding and decoding.
//!
//! This is Milestone 1 of the `matter-rust` roadmap.
//!
//! # Scope
//!
//! Phases 1-3 (complete): all scalar element types, UTF-8 and octet strings,
//! every tag form (anonymous, context, common profile, implicit profile,
//! fully-qualified), and containers (structure, array, list) with recursive
//! tree-builder decoding and a 32-level depth limit.
//!
//! Phase 4 (upcoming): property tests with `proptest`, a `cargo-fuzz` target
//! seeded from the M0 test-vectors corpus, and the first `0.1.0` crates.io
//! release.
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
