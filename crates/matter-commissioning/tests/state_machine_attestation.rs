//! M6.4.3 — state machine reaches `AttestationVerification`, runs the
//! full M6.2/M6.4.3 verifier chain (chain validation + attestation
//! signature + CD verification), and advances past attestation when
//! the inputs match.
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
fn happy_path_advances_past_attestation_verification() {
    // Placeholder — see module doc.
    // When fixtures land:
    // 1. Construct fabric + setup + PaaTrustStore::with_csa_test_roots()
    //    + CdSigningRoots::with_csa_test_roots().
    // 2. Drive sm through SecurePairing..SendAttestationRequest with canned responses.
    // 3. Feed captured PAI/DAC/AttestationResponse fixtures + matching
    //    attestation_challenge.
    // 4. Poll() at the AttestationVerification stage advances cursor to
    //    SendOpCertSigningRequest (M6.4.4 stub will short-circuit; that's
    //    expected at this point in the milestone progression).
}
