//! Per-cluster command + attribute codecs for clusters used during
//! commissioning.
//!
//! Cluster command codecs in `noc/commands.rs` (the
//! `OperationalCredentials` cluster's NOC-issuance subset, M6.3) predate
//! this directory. Future M6.5 / M6.7 cluster work lands here.

#![forbid(unsafe_code)]

pub mod general_commissioning;
pub mod network_commissioning;
