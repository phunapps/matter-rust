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

pub use action::{Action, CommissionedFabric, Expectation, SessionContext};
#[cfg(feature = "__test_shortcuts")]
pub use commissioner::TestStateSeeds;
pub use commissioner::{Commissioner, CommissionerConfig, NetworkCredentials, WiFiCredentials};
// Re-exported so the driver (crate::driver::commission) can floor the
// BLE-path ConnectNetwork response deadline at the same value the
// state-machine failsafe extension uses (spec D7). `commissioner` itself
// stays a private module.
pub(crate) use commissioner::DEFAULT_CONNECT_MAX_TIME_SECONDS;
pub use error::{CommissioningError, NetworkKind, RemediationHint};
// Used by Commissioner::advance from M6.4.1 T6 onward.
#[allow(unused_imports)]
pub(crate) use stage::next_stage;
pub use stage::Stage;
