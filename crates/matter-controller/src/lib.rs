//! The high-level Matter controller API.
//!
//! Milestone 8 (v1.0). M8.1 lands the persistence + commissioner-identity
//! foundation; M8.2 adds the `MatterController`/`Node` handles and the
//! owning actor task.

#![forbid(unsafe_code)]

pub(crate) mod actor;
pub mod builder;
pub mod controller;
pub(crate) mod credentials;
pub mod error;
pub mod fabric;
pub mod node;
pub mod snapshot;
pub mod state;
pub mod store;
pub mod trust;

pub use builder::MatterControllerBuilder;
pub use controller::MatterController;
pub use error::Error;
pub use fabric::{create_fabric, FabricConfig};
pub use node::Node;
pub use state::{CommissionerIdentity, ControllerState, DeviceEntry, FabricEntry};
pub use store::{ControllerStore, FileStore, StoreError};
pub use trust::AttestationTrust;
