//! Matter application protocol header codec (Matter Core Spec §4.4.5).
//!
//! The bytes inside every encrypted payload that carry Exchange Flags,
//! Opcode, Exchange ID, Protocol ID, and optional Acknowledged Message
//! Counter / Secure Extensions / Vendor data. Pure codec — no state, no
//! clock.
//!
//! Task 2 of the M5.2 plan replaces these stubs with real bodies.

#![allow(missing_docs, dead_code, clippy::missing_errors_doc)]

use bitflags::bitflags;

use crate::error::Result;
use crate::framing::MessageCounter;

bitflags! {
    /// First byte of the Matter application protocol header. Bit positions
    /// are matter.js's `ExchangeFlag` — verified byte-parity in Task 3.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExchangeFlags: u8 {
        const INITIATOR        = 0b0000_0001;
        const ACK              = 0b0000_0010;
        const RELIABLE         = 0b0000_0100;
        const SECURE_EXTENSION = 0b0000_1000;
        const VENDOR           = 0b0001_0000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolId {
    pub vendor: u16,
    pub protocol: u16,
}

impl ProtocolId {
    pub const SECURE_CHANNEL: Self = Self {
        vendor: 0,
        protocol: 0x0000,
    };
    pub const INTERACTION_MODEL: Self = Self {
        vendor: 0,
        protocol: 0x0001,
    };
    pub const BDX: Self = Self {
        vendor: 0,
        protocol: 0x0002,
    };
}

pub mod opcode {
    pub mod secure_channel {
        /// MRP standalone acknowledgement (Matter Core Spec §4.11.5).
        pub const STANDALONE_ACK: u8 = 0x10;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolHeader {
    pub exchange_flags: ExchangeFlags,
    pub opcode: u8,
    pub exchange_id: u16,
    pub protocol_id: ProtocolId,
    pub ack_counter: Option<MessageCounter>,
}

pub fn encode_protocol_header(_h: &ProtocolHeader, _out: &mut Vec<u8>) {
    unimplemented!("filled in by Task 2")
}

pub fn decode_protocol_header(_bytes: &[u8]) -> Result<(ProtocolHeader, &[u8])> {
    unimplemented!("filled in by Task 2")
}

pub fn build_standalone_ack_header(
    _exchange_id: u16,
    _ack_counter: MessageCounter,
    _is_local_initiator: bool,
) -> ProtocolHeader {
    unimplemented!("filled in by Task 2")
}
