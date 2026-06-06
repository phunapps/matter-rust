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
//! - **M6.4.4:** CSR + NOC issuance flow. State machine
//!   drives `SendOpCertSigningRequest` → `ValidateCsr` →
//!   `GenerateNocChain` → `SendTrustedRootCert` → `SendNoc`, then
//!   advances to `Stage::ReadNetworkCommissioningInfo` (M6.5.2 expands
//!   the network subgraph). Integrates M6.3's
//!   `verify_csr_response` + `issue_noc` + the `OpCreds`
//!   `AddTrustedRoot` / `AddNOC` encoders.
//! - **M6.4.5:** PASE→CASE handoff + `CommissioningComplete`.
//!   The state machine drives end-to-end from `SecurePairing` through
//!   `Action::Done(CommissionedFabric)` on canned responses plus a
//!   mock `on_case_established()` callback. New public API
//!   `Commissioner::on_case_established` for the M6.6 driver's CASE
//!   handshake success signal; `Expectation::CaseFailed` for the
//!   failure path.
//! - **M6.4 (complete):** commissioning state machine. End-to-end
//!   cursor from `SecurePairing` through
//!   `Action::Done(CommissionedFabric)` on canned responses + a
//!   mock CASE-established callback. matter.js byte-parity gate
//!   infrastructure shipped — see [`state_machine`] for the API.
//! - **M6.5 (current):** Wi-Fi network commissioning. Expands the
//!   `NetworkCommissioning` no-op slot into the real Wi-Fi sub-cursor
//!   (`ReadNetworkCommissioningInfo` → `WiFiNetworkSetup` →
//!   `FailsafeBeforeWiFiEnable` → `WiFiNetworkEnable`). Ethernet-only
//!   devices skip the Wi-Fi sub-cursor entirely; Thread-only devices
//!   fail fast with a typed `NetworkFeatureUnsupported` error. New
//!   `RemediationHint` enum surfaces actionable categories for
//!   `NetworkRejected`. Failsafe-expiry now derives from
//!   `BasicCommissioningInfo` (was hardcoded 60s in M6.4). Optional
//!   `tracing` feature instruments every dispatch arm.
//! - **M6.6.1 (current):** Interaction Model framing — see [`im`].
//!   `build_invoke_request` / `parse_invoke_response`,
//!   `build_read_request` / `parse_report_data`. Pure codec over
//!   `matter-codec`; the wire-I/O driver follows in M6.6.2+.
//! - **M6.6 (next-next):** Tokio driver + first real-device
//!   commission. Wires the M6.4 state machine into `matter-transport`'s
//!   session layer + drives `matter-crypto`'s SIGMA-I CASE handshake.
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
//!
//! ## Optional `tracing` feature
//!
//! Enable the `tracing` crate feature to get per-method spans on
//! `Commissioner::poll`, `Commissioner::on_response`, and
//! `Commissioner::on_case_established`. Span fields (`stage`,
//! `expectation`) align best-effort with matter.js's log-event format
//! so operators can grep across both implementations. Compatibility
//! is not guaranteed across matter.js minor versions.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod clusters;
#[cfg(feature = "driver")]
pub mod driver;
pub mod error;
/// Lowercase-hex rendering for `tracing` debug dumps of wire bytes.
#[cfg(feature = "tracing")]
pub(crate) mod hexdump {
    use std::fmt::Write;

    /// Render `bytes` as a contiguous lowercase-hex string.
    pub(crate) fn hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
                // Vec-backed String writes are infallible.
                let _ = write!(out, "{b:02x}");
                out
            })
    }
}
pub mod im;
pub mod noc;
pub mod setup;
pub mod state_machine;
#[cfg(feature = "wiretrace")]
pub mod wiretrace;

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

pub use clusters::network_commissioning::{
    decode_connect_network_response, decode_feature_map, decode_network_config_response,
    encode_add_or_update_wifi_network, encode_connect_network, remediation_for,
    ConnectNetworkResponse, NetworkCommissioningFeature, NetworkConfigResponse,
};

pub use im::{
    build_invoke_request, build_read_request, parse_invoke_response, parse_report_data,
    AttributePath, CommandPath, ImError, ImStatus, InvokeResponse, ReportData, IM_REVISION,
};

#[cfg(feature = "__test_shortcuts")]
pub use state_machine::TestStateSeeds;
pub use state_machine::{
    Action, CommissionedFabric, Commissioner, CommissionerConfig, CommissioningError, Expectation,
    NetworkKind, RemediationHint, SessionContext, Stage, WiFiCredentials,
};
