//! Matter TLV (Tag-Length-Value) encoding and decoding.
//!
//! This is Milestone 1 of the `matter-rust` roadmap. The crate is currently a
//! placeholder; the real implementation arrives in subsequent commits.
//!
//! # Scope
//!
//! - [`reader`]: streaming TLV decoder (`TlvReader`).
//! - [`writer`]: streaming TLV encoder (`TlvWriter`).
//! - [`tag`]: every Matter tag form (anonymous, context, common profile,
//!   implicit profile, fully qualified).
//! - [`value`]: TLV value types — signed/unsigned ints of every width, bool,
//!   float, double, UTF-8 string, byte string, null, structure, array, list.
//! - [`error`]: the crate error type.
//!
//! # Non-goals
//!
//! This crate does not implement higher-level Matter concepts (clusters,
//! certificates, sessions). Those live in their own crates.

#![forbid(unsafe_code)]
#![no_std]

pub mod error;
pub mod reader;
pub mod tag;
pub mod value;
pub mod writer;
