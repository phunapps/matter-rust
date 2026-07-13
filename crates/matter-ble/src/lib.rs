//! Matter BLE commissioning transport.
//!
//! Sans-IO BTP (Bluetooth Transport Protocol, Matter spec 4.18/4.19) engine —
//! handshake codec, segmentation/reassembly, ack windows — plus, behind the
//! `central` feature, a btleplug-based BLE central for macOS/Linux.
//!
//! Byte-grounded against connectedhomeip `src/ble/` (`BtpEngine`, `BLEEndPoint`,
//! `BleLayer`) and `test-vectors/btp/`.

pub mod advert;

mod error;
pub use error::BtpError;
