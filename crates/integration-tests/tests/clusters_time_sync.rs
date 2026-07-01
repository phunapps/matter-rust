// Integration tests are a binary crate; crate-level docs are not required.
// Test-code carve-out for unwrap/expect: see CLAUDE.md.
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown
)]

use matter_controller::{DstOffsetEntry, TimeGranularity, TimeZoneEntry};

/// TimeSynchronization (ep0, 0x0038) against the live DUT (G-a):
///   - SetUTCTime, then read UTCTime back and assert the clock is set;
///   - SetTimeZone (observe the returned DSTOffsetRequired);
///   - SetDSTOffset.
#[tokio::test]
async fn time_sync_set_and_read() {
    let cfg = integration_tests::dut_or_skip!();
    let (controller, node_id) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT");
    let node = controller.node(node_id);

    // A fixed, plausible epoch-µs value (well after the Matter 2000 epoch;
    // ~2024-09 expressed in microseconds since 2000-01-01 UTC).
    let when_us: u64 = 780_000_000_000_000;
    node.set_utc_time(when_us, TimeGranularity::Seconds)
        .await
        .expect("SetUTCTime");

    // The device's clock advances from ~when_us; read it back and assert it is
    // set (non-null) and not far behind the value we set (allow drift/advance).
    let read = node.read_utc_time().await.expect("read UTCTime");
    let t = read.expect("UTCTime should be set after SetUTCTime");
    assert!(
        t + 60_000_000 >= when_us,
        "clock {t} is far behind the value we set ({when_us})"
    );

    // Time zone + DST offset (single entries valid from epoch 0).
    let _dst_required = node
        .set_time_zone(&[TimeZoneEntry {
            offset_seconds: 3600,
            valid_at_us: 0,
            name: None,
        }])
        .await
        .expect("SetTimeZone");
    node.set_dst_offset(&[DstOffsetEntry {
        offset_seconds: 3600,
        valid_starting_us: 0,
        valid_until_us: None,
    }])
    .await
    .expect("SetDSTOffset");
}
