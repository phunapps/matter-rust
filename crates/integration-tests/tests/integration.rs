// Integration tests are a binary crate; crate-level docs are not required.
#![allow(missing_docs)]

#[tokio::test]
async fn dut_gate_skips_without_env() {
    // With no MATTER_INTEGRATION_DUT this must early-return (skip), not panic.
    let _cfg = integration_tests::dut_or_skip!();
    // Reaching here means a DUT IS configured; nothing to assert in the smoke test.
}
