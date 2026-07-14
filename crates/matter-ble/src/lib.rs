//! Matter BLE commissioning transport.
//!
//! Sans-IO BTP (Bluetooth Transport Protocol, Matter spec 4.18/4.19) engine —
//! handshake codec, segmentation/reassembly, ack windows — plus, behind the
//! `central` feature, a btleplug-based BLE central for macOS/Linux.
//!
//! Byte-grounded against connectedhomeip `src/ble/` (`BtpEngine`, `BLEEndPoint`,
//! `BleLayer`) and `test-vectors/btp/`.

pub mod advert;
pub mod handshake;
pub mod session;

/// btleplug-based BLE central role: scan for commissionable devices, open a GATT
/// C1/C2 BTP session, and drive it via an async pump task. Behind the `central`
/// feature because btleplug is heavy and platform-specific.
#[cfg(feature = "central")]
pub mod central;

mod error;
pub use error::BtpError;
