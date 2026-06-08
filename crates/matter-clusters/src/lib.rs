//! Typed Matter cluster definitions.
//!
//! This is Milestone 7 of the `matter-rust` roadmap. The crate is currently a
//! placeholder.
//!
//! The cluster source-of-truth is the Matter Device Library Specification. The
//! `xtask` codegen tool will turn those definitions into Rust types and place
//! them in this crate.
//!
//! Initial clusters planned for the M7 release:
//!
//! - `BasicInformation`
//! - `Descriptor`
//! - `Identify`
//! - `OnOff`
//! - `LevelControl`
//! - `ColorControl`
//! - `OccupancySensing`
//! - `TemperatureMeasurement`
//! - `RelativeHumidityMeasurement`
//! - `DoorLock` (limited — Aliro features deferred)

#![forbid(unsafe_code)]

pub mod datatypes;
pub mod error;
pub mod types;

pub use datatypes::SemanticTagStruct;

#[cfg(test)]
mod golden;
