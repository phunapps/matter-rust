//! Typed Matter cluster definitions — generated from the Matter spec.
//!
//! Per-cluster attribute / command / struct **codecs** (encode/decode to Matter
//! TLV), feature bitflags, enums (with an `Unknown(n)` variant for
//! forward-compatibility), and bitmaps. The cluster modules live under
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
//! Correctness: the generated codecs are **byte-parity tested against matter.js
//! 0.16.11** (`test-vectors/clusters/`), with `proptest` roundtrips and a
//! `cargo-fuzz` target.
//!
//! # Clusters
//!
//! M7 (byte-parity tested): `BasicInformation`, `Descriptor`, `Identify`,
//! `OnOff`, `LevelControl`, `ColorControl`, `OccupancySensing`,
//! `TemperatureMeasurement`, `RelativeHumidityMeasurement`, and `DoorLock`
//! (Aliro features excluded). M9-A2.1 pilot (decode-smoke tested):
//! `IlluminanceMeasurement`, `PressureMeasurement`, `FlowMeasurement`,
//! `BooleanState`, and `Switch`. M9-A2.2 energy (decode-smoke + one nested
//! byte-parity vector): `PowerSource`, `ElectricalPowerMeasurement`,
//! `ElectricalEnergyMeasurement`, and `AirQuality`. M9-A2.3 actuators
//! (roundtrip + decode-smoke, with a byte-parity vector for the list-typed
//! `AtomicRequest` command): `Thermostat`, `FanControl`,
//! `ThermostatUserInterfaceConfiguration`, `PumpConfigurationAndControl`, and
//! `WindowCovering`. M9-A2.4 utility (decode-smoke + one struct-with-byte-fields
//! byte-parity vector for `GeneralDiagnostics` `NetworkInterface`): `Groups`,
//! `Binding`, `GeneralDiagnostics`, `FixedLabel`, and `UserLabel`. M9-A2.5
//! management (codecs only — protocol logic deferred to later milestones;
//! decode-smoke + a byte-parity vector for the recursive list-of-struct command
//! encode `AccessControl::ReviewFabricRestrictions`): `AccessControl`,
//! `GroupKeyManagement`, `AdministratorCommissioning`, and
//! `OtaSoftwareUpdateRequestor`.
//!
//! For any attribute not covered by these typed codecs — optional,
//! manufacturer-specific, or a cluster not in this list — the generic `Value`
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
//! `(AttributePath, matter_codec::Value)` pair without a typed codec. A
//! high-level generic + wildcard read API, and more typed clusters, arrive in
//! later milestones.

#![forbid(unsafe_code)]

pub mod datatypes;
pub mod error;
pub mod types;

pub use datatypes::SemanticTagStruct;

pub mod gen;

#[cfg(test)]
mod golden;
