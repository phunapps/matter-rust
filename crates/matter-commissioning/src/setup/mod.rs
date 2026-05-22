//! Setup payload parsing and encoding for Matter QR codes and manual
//! pairing codes (Matter Core Spec §5.1).
//!
//! This is Milestone 6 phase 1 of the `matter-rust` roadmap. See
//! `docs/superpowers/specs/2026-05-22-matter-commissioning-setup-payload-design.md`
//! for design rationale and `docs/superpowers/specs/2026-05-22-matter-commissioning-design.md`
//! for the M6 umbrella.
//!
//! # Phase status
//!
//! - **M6.1 (this revision):** QR-code and manual-pairing-code codec, no
//!   vendor TLV (deferred to a later phase). `SetupPayload` is the
//!   canonical in-memory representation.

#![forbid(unsafe_code)]

mod base38;
mod manual_packer;
mod qr_packer;
mod verhoeff;
