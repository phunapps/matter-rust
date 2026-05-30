//! Interaction Model (IM) message framing — Matter Core Spec §10.
//!
//! The commissioning state machine ([`crate::state_machine`]) emits bare
//! cluster command/attribute TLV payloads. This module wraps them in the
//! IM message envelopes the wire actually carries (`InvokeRequestMessage`,
//! `ReadRequestMessage`) and parses the responses (`InvokeResponseMessage`,
//! `ReportDataMessage`).
//!
//! It implements only the subset commissioning needs: one command per
//! invoke, concrete (non-wildcard) attribute paths, no subscriptions, no
//! timed invoke, no batched commands. The full IM engine is M7/M8 work.
//!
//! This module depends only on [`matter_codec`] and imports nothing from
//! [`crate::state_machine`], so it can be lifted into a standalone
//! `matter-interaction` crate later as a file move (M6.6 design §3).

#![forbid(unsafe_code)]

pub mod error;
pub mod invoke;
pub mod read;
pub mod status;

pub use error::ImError;

/// Interaction Model protocol revision emitted at context tag `0xFF` in
/// every top-level IM message. Confirmed against the matter.js byte-parity
/// fixture (see `tests/im_byte_parity.rs`); bump only when a captured
/// fixture proves matter.js changed it.
pub const IM_REVISION: u8 = 11;

/// A concrete command path: `(endpoint, cluster, command)`.
///
/// Encoded as a `CommandPathIB` TLV **list** (Matter Appendix A.6):
/// context tag 0 = endpoint, 1 = cluster, 2 = command.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CommandPath {
    /// Matter endpoint (always 0 for commissioning).
    pub endpoint: u16,
    /// Cluster ID.
    pub cluster: u32,
    /// Command ID.
    pub command: u32,
}
