//! The high-level Matter controller API — the single crate a consumer depends
//! on to commission and control Matter devices from pure Rust.
//!
//! [`MatterController`] is the entry point. It persists a fabric and a stable
//! commissioner identity through a pluggable [`ControllerStore`] (a default
//! [`FileStore`] ships), commissions devices over IP, and exposes each device
//! through a cheap [`Node`] handle that transparently establishes, caches, and
//! reuses the operational CASE session.
//!
//! # Capabilities
//!
//! - **Fabric & identity** — [`MatterController::create_fabric`] mints and
//!   persists the controller's stable operational identity once per fabric.
//! - **Commissioning** — [`MatterController::commission`] brings a device onto
//!   the fabric from a QR (`MT:…`) or manual pairing code, verifying device
//!   attestation against the configured [`AttestationTrust`].
//! - **Interaction** — [`Node::read`] / [`Node::write`] / [`Node::invoke`] work
//!   over raw [`Value`]s and support **wildcard reads** ([`ReadPath::cluster`],
//!   [`ReadPath::all`]) for reading every attribute off a device.
//! - **Subscriptions** — [`Node::subscribe`] returns a [`Subscription`] stream
//!   of [`AttributeReport`]s (`next().await` + `cancel()`).
//!
//! # Quickstart
//!
//! ```no_run
//! use std::sync::Arc;
//! use matter_controller::{
//!     AttestationTrust, FabricConfig, FileStore, MatterController, MatterTime, ReadPath,
//! };
//!
//! # async fn run() -> Result<(), matter_controller::Error> {
//! // Persisted store + attestation trust (test roots shown; use
//! // `AttestationTrust::from_dirs(..)` with production PAA/CD roots for
//! // certified devices).
//! let store = Arc::new(FileStore::new("controller-state.bin"));
//! let controller = MatterController::builder(store)
//!     .attestation_trust(AttestationTrust::csa_test_roots())
//!     .build()
//!     .await?;
//!
//! // One-time: create the fabric (idempotent across restarts — load the
//! // snapshot instead of re-creating in real apps).
//! let fabric_id = controller.create_fabric(FabricConfig {
//!     fabric_id: 1,
//!     rcac_id: 1,
//!     commissioner_node_id: 1,
//!     validity: (MatterTime::from_unix_secs(0), MatterTime::NO_EXPIRY),
//! }).await?;
//! let _ = fabric_id;
//!
//! // Commission a device, then control it.
//! let node_id = controller.commission("MT:Y.K90AFN00KA0648G00").await?;
//! let node = controller.node(node_id);
//!
//! // Read all attributes of the OnOff cluster (0x0006) on endpoint 1.
//! let report = node.read(&[ReadPath::cluster(1, 0x0006)]).await?;
//! for (path, value) in report {
//!     println!("{path:?} = {value:?}");
//! }
//!
//! // Subscribe to live changes.
//! let mut sub = node.subscribe(&[ReadPath::cluster(1, 0x0006)], 1, 30).await?;
//! while let Some(change) = sub.next().await {
//!     println!("changed: {:?} = {:?}", change.path, change.value);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Migrating from matter.js? See `docs/matter-js-migration-guide.md`.

#![forbid(unsafe_code)]

pub(crate) mod actor;
pub mod builder;
pub(crate) mod commission;
pub mod controller;
pub(crate) mod credentials;
pub mod error;
pub mod fabric;
pub mod node;
pub mod snapshot;
pub mod state;
pub mod store;
pub mod subscription;
pub mod trust;

pub use builder::MatterControllerBuilder;
pub use controller::MatterController;
pub use error::Error;
pub use fabric::{create_fabric, FabricConfig};
pub use matter_cert::MatterTime;
pub use matter_codec::Value;
pub use matter_interaction::{AttributePath, CommandPath, ImStatus, ReadPath};
pub use node::{InvokeResult, Node};
pub use state::{CommissionerIdentity, ControllerState, DeviceEntry, FabricEntry};
pub use store::{ControllerStore, FileStore, StoreError};
pub use subscription::{AttributeReport, Subscription};
pub use trust::AttestationTrust;
