//! Matter commissioning state machine.
//!
//! This is Milestone 6 of the `matter-rust` roadmap. The crate is currently
//! shipping in phases:
//!
//! - **M6.1:** setup payload codec — see [`setup`].
//! - **M6.2.1:** typed attestation cert wrappers ([`Dac`], [`Pai`],
//!   [`Paa`]) and [`PaaTrustStore`] — see [`attestation`].
//! - **M6.2.2 (current):** [`verify_chain`] — `rustls-webpki` path
//!   validation with `KeyUsage::client_auth()`, plus a Matter
//!   VID/PID equality overlay. Six new [`AttestationError`] variants.
//! - **M6.2.3:** `verify_attestation_response` + matter.js
//!   byte-parity capture.
//! - **M6.2.4–M6.2.6:** see [`attestation`].
//! - **M6.3:** Node Operational Certificate issuance — see [`noc`].
//! - **M6.4.1 (current):** ten-stage commissioning state machine — see
//!   [`state_machine`]. M6.4.1 ships `SecurePairing` →
//!   `ReadCommissioningInfo` → `ArmFailsafe` → `ConfigRegulatory`;
//!   further stages short-circuit to `Failed { CdVerificationUnavailable }`
//!   until M6.4.2 lands.
//! - **M6.5:** Wi-Fi network commissioning.
//! - **M6.6:** Tokio driver + first real-device commission.
//!
//! ## Quick-start (M6.1 only)
//!
//! ```
//! use matter_commissioning::setup::{parse_qr, parse_manual_code};
//! # fn run() -> Result<(), matter_commissioning::setup::Error> {
//! let from_qr = parse_qr("MT:Y.K90AFN00KA0648G00")?;
//! let from_manual = parse_manual_code("11693312331")?;
//! assert_eq!(from_qr.vendor_id, Some(0xFFF1));
//! assert_eq!(from_manual.passcode.as_u32(), 20_202_021);
//! # Ok(())
//! # }
//! # let _ = run;
//! ```
//!
//! Replace the QR string + manual code above with values captured for
//! your own devices via `cargo xtask capture-setup` if you change the
//! fixture set.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod clusters;
pub mod error;
pub mod noc;
pub mod setup;
pub mod state_machine;

pub use setup::{
    encode_manual_code, encode_qr, parse_manual_code, parse_qr, CommissioningFlow,
    DiscoveryCapabilities, Discriminator, Error as SetupError, Passcode, SetupPayload,
};

pub use attestation::{
    extract_attestation_elements_fields, verify_attestation_response, verify_chain,
    verify_dac_signed_elements, AttestationElementsFields, AttestationError, AttestationResponse,
    ChainVerification, Dac, Paa, PaaTrustStore, Pai, ProductId, VendorId,
};

pub use noc::{
    decode_attestation_response, decode_certificate_chain_response, decode_csr_response,
    decode_noc_response, encode_add_noc, encode_add_trusted_root, encode_attestation_request,
    encode_certificate_chain_request, encode_csr_request, encode_update_noc, issue_noc,
    parse_and_verify_csr, parse_nocsr, verify_csr_response, CertChainType,
    CertificateChainResponse, CsrResponse, FabricRecord, NocError, NocResponse, NocRng,
    NocsrElements, ParsedCsr, SystemNocRng, VerifiedCsr,
};

pub use state_machine::{
    Action, CommissionedFabric, Commissioner, CommissionerConfig, CommissioningError, Expectation,
    SessionContext, Stage,
};
