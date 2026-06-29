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

const LEVEL_CONTROL: u32 = 0x0008;
const CMD_MOVE_TO_LEVEL: u32 = 0x00;
const ATTR_CURRENT_LEVEL: u32 = 0x0000;

async fn read_attr(node: &Node, ep: u16, cluster: u32, attr: u32) -> Option<Value> {
    let r = node
        .read(&[ReadPath::concrete(ep, cluster, attr)])
        .await
        .expect("read attribute");
    r.into_iter()
        .find(|(p, _)| p.attribute == attr)
        .map(|(_, v)| v)
}

/// MoveToLevel with ExecuteIfOff forced (OptionsMask=1, OptionsOverride=1) so the
/// command applies regardless of the device's OnOff state.
async fn move_to_level(node: &Node, level: u64) {
    node.invoke(
        CommandPath {
            endpoint: 1,
            cluster: LEVEL_CONTROL,
            command: CMD_MOVE_TO_LEVEL,
        },
        Value::Structure(vec![
            (Tag::Context(0), Value::Uint(level)), // Level
            (Tag::Context(1), Value::Uint(0)),     // TransitionTime = 0 (immediate)
            (Tag::Context(2), Value::Uint(1)),     // OptionsMask = ExecuteIfOff
            (Tag::Context(3), Value::Uint(1)),     // OptionsOverride = ExecuteIfOff
        ]),
    )
    .await
    .expect("invoke MoveToLevel");
}

/// LevelControl behavioral: MoveToLevel(64) → CurrentLevel==64; MoveToLevel(200) → ==200.
#[tokio::test]
async fn level_control_move_to_level() {
    let cfg = integration_tests::dut_or_skip!();
    let (controller, node_id) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT");
    let node = controller.node(node_id);

    move_to_level(&node, 64).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        read_attr(&node, 1, LEVEL_CONTROL, ATTR_CURRENT_LEVEL).await,
        Some(Value::Uint(64)),
        "CurrentLevel did not become 64 after MoveToLevel(64)"
    );

    move_to_level(&node, 200).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        read_attr(&node, 1, LEVEL_CONTROL, ATTR_CURRENT_LEVEL).await,
        Some(Value::Uint(200)),
        "CurrentLevel did not become 200 after MoveToLevel(200)"
    );
}
