//! Cluster code generation (Milestone 7.3).
//!
//! Turns the frozen `xtask/model/clusters.json` (produced by `dump-model`,
//! M7.2) into the uniform per-cluster Rust module shape (M7 spec §2).
//!
//! Pipeline: [`model::load`] (deserialize + validate) → [`rustgen`] (map
//! types, emit strings) → rustfmt. The generator is pure: same JSON in →
//! same Rust out, byte-for-byte.

pub(crate) mod model;
pub(crate) mod rustgen;
