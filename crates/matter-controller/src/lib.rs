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
//!   of [`SubscriptionEvent`]s (`Report` / `Established` / `Resubscribing` /
//!   `Lagged`; `next().await` + `cancel()`).
//! - **Multi-admin / commissioning windows** — [`Node::open_commissioning_window`]
//!   opens an enhanced commissioning window (generates secrets, computes the PAKE
//!   verifier, returns a [`CommissioningWindow`] with `manual_code`/`qr_code`);
//!   [`Node::open_basic_commissioning_window`] opens a basic window; and
//!   [`Node::revoke_commissioning`] closes any open window.
//!   [`Node::commissioning_window_status`] reads the current window state.
//! - **Fabric management** — [`Node::list_fabrics`] reads the device's full
//!   fabric table as [`Vec<FabricDescriptor>`]; [`Node::remove_fabric`] removes a
//!   fabric by index (self-protected: returns [`Error::WouldRemoveSelf`] for our
//!   own fabric); [`Node::update_fabric_label`] relabels the accessing fabric.
//! - **ACL management** — [`Node::read_acl`] returns the device's
//!   `AccessControl.Acl` list as [`Vec<AclEntry>`]; [`Node::write_acl`] replaces it
//!   atomically (single-chunk) or via a multi-chunk `MoreChunkedMessages` sequence
//!   (large lists), with a lockout guard that returns [`Error::AclWouldLockOut`]
//!   before sending any bytes if the new list would drop our own Administer/CASE
//!   access.
//! - **Group provisioning** — [`Node::write_group_key_set`] provisions a key set
//!   on the device (`KeySetWrite`, `GroupKeyManagement` cluster 0x003F);
//!   [`Node::write_group_key_map`] writes the `GroupKeyMap` attribute via the
//!   chunked list-write mechanism; [`Node::add_group`] / [`Node::remove_group`]
//!   add and remove an endpoint from a group (`Groups` cluster 0x0004). Public
//!   types: [`GroupKeySet`] and [`GroupKeyMapEntry`].
//!
//! # Quickstart
//!
//! ```no_run
//! use std::sync::Arc;
//! use matter_controller::{
//!     AttestationTrust, FabricConfig, FileStore, MatterController, MatterTime, ReadPath,
//!     SubscriptionEvent,
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
//! let fabric_id = controller.create_fabric(FabricConfig::new(
//!     1,
//!     1,
//!     1,
//!     (MatterTime::from_unix_secs(0), MatterTime::NO_EXPIRY),
//! )).await?;
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
//! let mut sub = node.subscribe(&[ReadPath::cluster(1, 0x0006)], &[], 1, 30).await?;
//! while let Some(event) = sub.next().await {
//!     if let SubscriptionEvent::Report(change) = event {
//!         println!("changed: {:?} = {:?}", change.path, change.value);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Migrating from matter.js? See `docs/matter-js-migration-guide.md`.

#![forbid(unsafe_code)]

pub(crate) mod acl;
pub(crate) mod actor;
pub(crate) mod admin;
pub mod builder;
pub(crate) mod commission;
pub mod controller;
pub(crate) mod credentials;
pub mod error;
pub mod fabric;
pub(crate) mod group;
pub mod node;
pub(crate) mod opcreds;
pub mod snapshot;
pub mod state;
pub mod store;
pub mod subscription;
pub mod trust;

pub use acl::{AclAuthMode, AclEntry, AclPrivilege, AclTarget};
pub use admin::{
    CommissioningWindow, CommissioningWindowStatus, OpenWindowOpts, WindowStatus,
    DEFAULT_WINDOW_ITERATIONS, DEFAULT_WINDOW_TIMEOUT_S,
};
pub use builder::MatterControllerBuilder;
pub use controller::MatterController;
pub use error::Error;
pub use fabric::{create_fabric, FabricConfig};
pub use group::{GroupKeyMapEntry, GroupKeySet};
pub use matter_cert::MatterTime;
pub use matter_codec::Value;
pub use matter_interaction::{
    AttributePath, CommandPath, EventFilter, EventPath, EventPriority, EventReport,
    EventReportItem, EventTimestamp, ImStatus, ReadPath,
};
pub use node::{InvokeResult, Node};
pub use opcreds::FabricDescriptor;
pub use state::{CommissionerIdentity, ControllerState, DeviceEntry, FabricEntry};
pub use store::{ControllerStore, FileStore, StoreError};
pub use subscription::{AttributeReport, Subscription, SubscriptionEvent};
pub use trust::AttestationTrust;
