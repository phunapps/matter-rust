//! M6.4.5 — end-to-end public-API drive-through: `SecurePairing` →
//! `Action::Done(CommissionedFabric)` in a single test, using only the
//! re-exports at `matter_commissioning::*`.
//!
//! Currently `#[ignore]`'d because driving the full state machine
//! end-to-end via the public API requires synthetic-but-self-consistent
//! DAC + PAI + `AttestationResponse` + NOCSR fixtures. The in-source
//! glass-box tests at `src/state_machine/commissioner.rs::tests`
//! already cover every stage's dispatch + response handler in
//! isolation. M6.4.6's `xtask capture-commissioning` will land
//! captured fixtures from matter.js, at which point this test gets
//! its body and drops the `#[ignore]`.

// Test-code carve-out: see CLAUDE.md.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
#[ignore = "needs synthetic / captured fixtures (M6.4.6 xtask capture-commissioning)"]
fn happy_path_reaches_done() {
    // Placeholder — see module doc.
    //
    // When fixtures land:
    // 1. Construct fabric + setup + PaaTrustStore::with_csa_test_roots()
    //    + CdSigningRoots::with_csa_test_roots() + an RNG seed pinned to
    //    matter.js's capture-time RNG (so nonces are reproducible).
    // 2. In a `loop`, match on `sm.poll()`:
    //    - Invoke / ReadAttribute → feed the captured response bytes
    //      back via `on_response`.
    //    - EstablishCase → call `on_case_established()` (the test
    //      pretends mDNS + SIGMA succeeded instantly).
    //    - Abort → panic (unexpected).
    //    - Done(cf) → assert peer_node_id + terminated_at + break.
    //    - EvictCase → unreachable in new-fabric flow.
}
