//! Typed Matter cluster definitions — generated from the Matter spec.
//!
//! Per-cluster attribute / command / struct **codecs** (encode/decode to Matter
//! TLV), feature bitflags, enums (with an `Unknown(n)` variant for
//! forward-compatibility), bitmaps, and — for clusters whose events are
//! dumped (`Switch` today) — `event_id` consts plus decode-only
//! `<Name>Event` payload structs. The cluster modules live under
//! [`gen`]; the hand-written foundation is [`Nullable<T>`](types::Nullable)
//! (distinct from `Option`), [`ClusterError`](error::ClusterError), and
//! [`datatypes::SemanticTagStruct`].
//!
//! # Pipeline
//!
//! The `gen/` modules are generated, not hand-written: a pinned `@matter/model`
//! dump becomes the committed `xtask/model/clusters.json`, which
//! `cargo xtask codegen` turns into the committed `src/gen/*.rs`. CI gates drift
//! with `cargo xtask codegen --check`. **Do not edit `src/gen/` by hand** —
//! change the emitter in `xtask/src/codegen/` and regenerate.
//!
//! Correctness: the generated codecs are checked against matter.js 0.16.11
//! byte-parity vectors (`test-vectors/clusters/`), with `proptest` roundtrips
//! and a `cargo-fuzz` target. See [Clusters](#clusters) for what is covered
//! at which level.
//!
//! # Clusters
//!
//! 48 clusters are generated today. The full list is [`gen`]; by area:
//!
//! - **Core / identity:** `BasicInformation`, `Descriptor`, `Identify`,
//!   `Groups`, `Binding`, `FixedLabel`, `UserLabel`, `PowerSource`,
//!   `GeneralDiagnostics`, `BridgedDeviceBasicInformation` (per-bridged-
//!   endpoint identity behind a bridge/aggregator).
//! - **Lighting and actuators:** `OnOff`, `LevelControl`, `ColorControl`,
//!   `DoorLock` (Aliro features excluded), `WindowCovering`, `Thermostat`,
//!   `ThermostatUserInterfaceConfiguration`, `FanControl`,
//!   `PumpConfigurationAndControl`.
//! - **Sensing:** `OccupancySensing`, `TemperatureMeasurement`,
//!   `RelativeHumidityMeasurement`, `IlluminanceMeasurement`,
//!   `PressureMeasurement`, `FlowMeasurement`, `BooleanState`, `Switch`,
//!   `AirQuality`, and the ten `ConcentrationMeasurement` clusters
//!   (`CarbonMonoxide`, `CarbonDioxide`, `NitrogenDioxide`, `Ozone`, `Pm25`,
//!   `Formaldehyde`, `Pm1`, `Pm10`, `TotalVolatileOrganicCompounds`,
//!   `Radon`).
//! - **Energy:** `ElectricalPowerMeasurement`, `ElectricalEnergyMeasurement`.
//! - **Administration:** `AccessControl`, `GroupKeyManagement`,
//!   `AdministratorCommissioning`, `OperationalCredentials`,
//!   `IcdManagement`, `TimeSynchronization`, `OtaSoftwareUpdateRequestor`,
//!   `OtaSoftwareUpdateProvider`.
//!
//! Note that this crate holds **codecs only**. For the administration
//! clusters in particular, encoding a command is not the same as running the
//! protocol around it: ACL evaluation, group multicast, commissioning-window
//! orchestration, and OTA live in `matter-controller` and its siblings.
//!
//! Verification varies by cluster. Every cluster has decode-smoke coverage;
//! matter.js byte-parity vectors cover the core, lighting, and sensing sets
//! plus one vector for each novel wire shape the later batches introduced
//! (nested measurement-accuracy structs, list-typed commands,
//! struct-with-byte-fields, recursive list-of-struct, and floats).
//!
//! For any attribute not covered by these typed codecs — a cluster not in
//! this list, or a manufacturer-specific attribute — the generic `Value`
//! path in `matter-controller` remains the universal answer.
//!
//! # Usage
//!
//! Codecs are free functions per attribute/command. Encoders return a standalone
//! anonymous-tagged TLV element (ready to embed in an Interaction Model
//! request); decoders take the attribute value bytes from a report.
//!
//! ```
//! use matter_clusters::gen::{basic_information, on_off};
//!
//! // Command payload — embed in an InvokeRequest (see the `control_onoff` example).
//! let _toggle = on_off::encode_toggle();
//!
//! // Attribute roundtrips: encode a value, decode it back.
//! let tlv = on_off::encode_on_time(30);
//! assert_eq!(on_off::decode_on_time(&tlv)?, 30);
//!
//! let tlv = basic_information::encode_node_label(&"living room".to_string());
//! assert_eq!(basic_information::decode_node_label(&tlv)?, "living room");
//! # Ok::<(), matter_clusters::error::ClusterError>(())
//! ```
//!
//! See `crates/matter-commissioning/examples/control_onoff.rs` for an
//! end-to-end read / toggle / write against a real device.
//!
//! # Scope — reading attributes beyond these clusters
//!
//! Typed codecs exist for these clusters' **mandatory and optional** attributes
//! (a device may not implement a given optional attribute — it then returns
//! `UNSUPPORTED_ATTRIBUTE`). To read attributes of clusters NOT in this set, or
//! manufacturer-specific attributes, use the generic Interaction Model path:
//! `matter_interaction::parse_report_data` decodes any attribute to a
//! `(AttributePath, matter_codec::Value)` pair without a typed codec, and
//! `matter-controller` wraps that in a generic read/write/subscribe API with
//! wildcard paths.

#![forbid(unsafe_code)]

pub mod datatypes;
pub mod error;
pub mod types;

pub use datatypes::SemanticTagStruct;

pub mod gen;

#[cfg(test)]
mod golden;

/// Compile-checks the Rust examples in this crate's `README.md`.
///
/// `#[cfg(doctest)]` means the item exists only while rustdoc is collecting
/// doctests, so the README is compiled by `cargo test --doc` without being
/// duplicated into the rendered crate docs.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
