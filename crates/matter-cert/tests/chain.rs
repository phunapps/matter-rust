//! Chain validation integration tests.
//!
//! Tier 1: positive end-to-end against the captured chain (Task 8).
//! Tier 2: hand-written negative tests, one per failure mode (Task 7).
//! Tier 3: proptest properties (Task 8).
//!
//! This file currently contains only the synthesis self-consistency
//! smoke test. The full test suite lands in Tasks 7–8.

#![allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.

mod common;

use matter_cert::CertificateChain;

#[test]
fn synthesis_produces_a_self_consistent_chain() {
    // CRITICAL: this test gates the entire negative-test suite. If
    // synthesis is broken, every Tier-2 negative test in Task 7 asserts
    // against malformed inputs and is therefore meaningless. Run this
    // first and only build on it once green.

    let (chain, anchor) = common::synthesise_two_cert_chain(0xCAFE);

    // Shape: [leaf, ica].
    assert_eq!(chain.len(), 2);

    // Issuer/subject linkage.
    assert_eq!(chain[0].issuer(), chain[1].subject());
    assert_eq!(chain[1].issuer(), anchor.subject());

    // Each cert's signature verifies against the next-level public key.
    chain[0]
        .verify_signed_by(chain[1].public_key())
        .expect("leaf signature must verify against ICA's public key");
    chain[1]
        .verify_signed_by(anchor.public_key())
        .expect("ICA signature must verify against root anchor's public key");

    // CertificateChain reports the right shape.
    let cc = CertificateChain::new(&chain);
    assert_eq!(cc.len(), 2);
    assert!(!cc.is_empty());
}
