//! Commissioning state machine. Implemented in Milestone 6.4.
//!
//! Cursor + switch-on-enum design modeled on
//! `project-chip/connectedhomeip`'s `AutoCommissioner`. Transport-agnostic
//! and sans-IO — emits cluster-command-level `Action`s that a separate
//! driver (M6.6) wraps in Invoke envelopes and routes via
//! `matter-transport`.
//!
//! See `docs/superpowers/specs/2026-05-28-m6.4-commissioning-state-machine-design.md`
//! for the architectural rationale and stage table.

#![forbid(unsafe_code)]

mod action;
mod commissioner;
mod error;
mod stage;

pub(crate) use stage::next_stage;
pub use stage::Stage;
