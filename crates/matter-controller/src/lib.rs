//! The high-level Matter controller API.
//!
//! This is Milestone 8 of the `matter-rust` roadmap — the v1.0 surface. The
//! crate is currently a placeholder.
//!
//! # Scope
//!
//! - [`controller`]: the `MatterController` entry point — fabric management,
//!   commissioning, read/write/invoke, subscriptions.
//! - [`fabric`]: fabric creation, persistence, and restore.
//! - [`error`]: the crate error type.

#![forbid(unsafe_code)]

pub mod controller;
pub mod error;
pub mod fabric;
