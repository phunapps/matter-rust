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
//! - **M6.4.2:** attestation on-wire flow + off-wire
//!   `AttestationVerification`. State machine drives
//!   `SendPaiCertRequest` → `SendDacCertRequest` →
//!   `SendAttestationRequest` → `AttestationVerification`, chaining
//!   M6.2's `verify_chain` + `verify_attestation_response` + the
//!   `extract_attestation_elements_fields` helper.
//! - **M6.4.3:** CD verification wired into
//!   `AttestationVerification`. The state machine now calls
//!   `verify_certification_declaration` against
//!   [`attestation::CdSigningRoots`] and advances past attestation on
//!   a valid CD; `CommissionerConfig` gains a `cd_signing_roots`
//!   reference.
//! - **M6.4.4 (current):** CSR + NOC issuance flow. State machine
//!   drives `SendOpCertSigningRequest` → `ValidateCsr` →
//!   `GenerateNocChain` → `SendTrustedRootCert` → `SendNoc`, then
//!   advances to `Stage::NetworkCommissioning` (a no-op slot M6.4.5
//!   expands into the Wi-Fi/Thread subgraph). Integrates M6.3's
//!   `verify_csr_response` + `issue_noc` + the `OpCreds`
//!   `AddTrustedRoot` / `AddNOC` encoders.
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
    extract_attestation_elements_fields, verify_attestation_response,
    verify_certification_declaration, verify_chain, verify_dac_signed_elements,
    AttestationElementsFields, AttestationError, AttestationResponse, CdSigningRoots,
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
