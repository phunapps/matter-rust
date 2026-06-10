//! The high-level Matter controller API.
//!
//! Milestone 8 (v1.0). M8.1 lands the persistence + commissioner-identity
//! foundation; the networked controller/Node API arrives in later sub-phases.

#![forbid(unsafe_code)]

pub mod controller;
pub(crate) mod credentials;
pub mod error;
pub mod fabric;
pub mod snapshot;
pub mod state;
pub mod store;

pub use error::Error;
pub use fabric::{create_fabric, FabricConfig};
pub use state::{CommissionerIdentity, ControllerState, DeviceEntry, FabricEntry};
pub use store::{ControllerStore, FileStore, StoreError};
