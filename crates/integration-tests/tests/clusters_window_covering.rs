// Integration tests are a binary crate; crate-level docs are not required.
// Test-code carve-out for unwrap/expect: see CLAUDE.md.
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown
)]

use std::time::Duration;

use matter_codec::Tag;
use matter_controller::{CommandPath, Node, ReadPath, Value};

const WINDOW_COVERING: u32 = 0x0102;
const CMD_GO_TO_LIFT_PERCENTAGE: u32 = 0x05;
const ATTR_TARGET_POSITION_LIFT_PERCENT100THS: u32 = 0x000B;

async fn read_attr(node: &Node, ep: u16, cluster: u32, attr: u32) -> Option<Value> {
    let r = node
        .read(&[ReadPath::concrete(ep, cluster, attr)])
        .await
        .expect("read attribute");
    r.into_iter()
        .find(|(p, _)| p.attribute == attr)
        .map(|(_, v)| v)
}

async fn go_to_lift_percentage(node: &Node, percent100ths: u64) {
    node.invoke(
        CommandPath {
            endpoint: 1,
            cluster: WINDOW_COVERING,
            command: CMD_GO_TO_LIFT_PERCENTAGE,
        },
        Value::Structure(vec![(Tag::Context(0), Value::Uint(percent100ths))]),
    )
    .await
    .expect("invoke GoToLiftPercentage");
}

/// WindowCovering behavioral: GoToLiftPercentage sets the TARGET position
/// immediately. We assert TargetPositionLiftPercent100ths (deterministic) rather
/// than CurrentPosition (which simulates movement over time on all-clusters-app).
#[tokio::test]
async fn window_covering_go_to_lift_percentage() {
    let cfg = integration_tests::dut_or_skip!();
    let (controller, node_id) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT");
    let node = controller.node(node_id);

    go_to_lift_percentage(&node, 5000).await; // 50.00 %
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        read_attr(
            &node,
            1,
            WINDOW_COVERING,
            ATTR_TARGET_POSITION_LIFT_PERCENT100THS
        )
        .await,
        Some(Value::Uint(5000)),
        "TargetPositionLiftPercent100ths did not become 5000"
    );

    go_to_lift_percentage(&node, 2500).await; // 25.00 %
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        read_attr(
            &node,
            1,
            WINDOW_COVERING,
            ATTR_TARGET_POSITION_LIFT_PERCENT100THS
        )
        .await,
        Some(Value::Uint(2500)),
        "TargetPositionLiftPercent100ths did not become 2500"
    );
}
