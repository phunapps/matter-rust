//! M6.4.2 — state machine reaches `AttestationVerification` and runs
//! M6.2's verifier chain. The CD-verify step short-circuits to
//! `CommissioningError::CdVerificationUnavailable` until M6.4.3 lands.
//!
//! Currently `#[ignore]`'d because no captured DAC/PAI/`AttestationResponse`
//! fixtures exist in `test-vectors/commissioning/attestation/`. When
//! M6.4.6's `xtask capture-commissioning` script lands (or an earlier
//! `xtask capture-attestation`), drop the `#[ignore]` and point the
//! `include_bytes!` paths at the captured artefacts.

// Test-code carve-out: see CLAUDE.md.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
#[ignore = "needs captured DAC/PAI/AttestationResponse fixtures (M6.4.6 or xtask capture-attestation)"]
fn happy_path_reaches_attestation_verification_then_cd_unavailable() {
    // Placeholder — see module doc.
    // When fixtures land:
    // 1. Construct fabric + setup + PaaTrustStore::with_csa_test_roots().
    // 2. Drive sm through SecurePairing..SendAttestationRequest with canned responses.
    // 3. Feed the captured PAI/DAC/AttestationResponse fixtures.
    // 4. Poll() at the AttestationVerification stage:
    //    - With matching attestation_challenge: expect CdVerificationUnavailable,
    //      cursor = Failed.
    //    - With wrong attestation_challenge: expect AttestationError::BadResponseSignature.
}
