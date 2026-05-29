//! M6.4.4 — state machine drives end-to-end through the CSR + NOC
//! flow, reaching `Stage::NetworkCommissioning` on a fully-synthetic
//! happy-path scenario.
//!
//! Currently `#[ignore]`'d because driving the public API end-to-end
//! requires real (or synthetic-but-self-consistent) DAC + PAI +
//! `AttestationResponse` + NOCSR fixtures. The in-source unit tests at
//! `src/state_machine/commissioner.rs::tests` already cover the CSR
//! and NOC stage dispatch + response handlers in isolation via
//! glass-box access. M6.4.6's `xtask capture-commissioning` will land
//! captured fixtures that let this test exercise the full
//! `matter_commissioning::*` public surface.

// Test-code carve-out: see CLAUDE.md.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
#[ignore = "needs synthetic CSR + attestation fixtures (M6.4.6 or xtask capture-attestation)"]
fn happy_path_drives_through_csr_and_noc_to_network_commissioning() {
    // Placeholder — see module doc.
    // When fixtures land:
    // 1. Construct fabric + setup + PaaTrustStore::with_csa_test_roots()
    //    + CdSigningRoots::with_csa_test_roots().
    // 2. Drive sm through SecurePairing..AttestationVerification with
    //    captured PAI/DAC/AttestationResponse fixtures.
    // 3. Feed a captured CSRResponse signed by the same DAC, with the
    //    commissioner-supplied CSR nonce.
    // 4. Verify ValidateCsr + GenerateNocChain pass off-wire.
    // 5. Feed AddTrustedRootResponse OK + NocResponse { status: 0 }.
    // 6. Assert cursor reaches Stage::NetworkCommissioning.
    //
    // Until then the inline tests in commissioner.rs cover the dispatch
    // + response shapes — see send_op_cert_signing_request_*,
    // happy_path_drives_through_csr_to_send_noc, and friends.
}
