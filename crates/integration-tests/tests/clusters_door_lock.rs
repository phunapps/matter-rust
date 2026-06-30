// Integration tests are a binary crate; crate-level docs are not required.
// Test-code carve-out for unwrap/expect: see CLAUDE.md.
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::items_after_statements
)]

use matter_clusters::gen::door_lock::{self, LockStateEnum};
use matter_clusters::types::Nullable;
use matter_codec::{Tag, TlvWriter};
use matter_controller::{CommandPath, Node, ReadPath, Value};

const DOOR_LOCK: u32 = 0x0101;
const CMD_LOCK_DOOR: u32 = 0x00;
const CMD_UNLOCK_DOOR: u32 = 0x01;
const ATTR_LOCK_STATE: u32 = 0x0000;

fn value_to_tlv(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.write_value(Tag::Anonymous, value)
        .expect("infallible: Vec-backed TlvWriter");
    buf
}

async fn read_lock_state(node: &Node) -> Nullable<LockStateEnum> {
    let r = node
        .read(&[ReadPath::concrete(1, DOOR_LOCK, ATTR_LOCK_STATE)])
        .await
        .expect("read LockState");
    let v = r
        .into_iter()
        .find(|(p, _)| p.attribute == ATTR_LOCK_STATE)
        .map(|(_, v)| v)
        .expect("LockState present");
    door_lock::decode_lock_state(&value_to_tlv(&v)).expect("decode LockState")
}

/// DoorLock (0x0101, ep1) on lock-app: UnlockDoor → LockState == Unlocked;
/// LockDoor → LockState == Locked. DoorLock lock/unlock are timed commands; the
/// lock-app default `RequirePINforRemoteOperation = 0`, so no PIN field is sent.
#[tokio::test]
async fn door_lock_lock_unlock() {
    let cfg = integration_tests::dut_or_skip!();
    if !cfg.is_app("lock") {
        eprintln!("skipped: DoorLock test needs the lock-app DUT (`just integration-lock`)");
        return;
    }
    let (controller, node_id) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT");
    let node = controller.node(node_id);

    // UnlockDoor (timed, no PIN) → Unlocked.
    node.invoke_timed(
        CommandPath {
            endpoint: 1,
            cluster: DOOR_LOCK,
            command: CMD_UNLOCK_DOOR,
        },
        Value::Structure(vec![]),
        Some(3000),
    )
    .await
    .expect("invoke_timed UnlockDoor");
    assert_eq!(
        read_lock_state(&node).await,
        Nullable::Value(LockStateEnum::Unlocked),
        "LockState did not become Unlocked after UnlockDoor"
    );

    // LockDoor (timed, no PIN) → Locked.
    node.invoke_timed(
        CommandPath {
            endpoint: 1,
            cluster: DOOR_LOCK,
            command: CMD_LOCK_DOOR,
        },
        Value::Structure(vec![]),
        Some(3000),
    )
    .await
    .expect("invoke_timed LockDoor");
    assert_eq!(
        read_lock_state(&node).await,
        Nullable::Value(LockStateEnum::Locked),
        "LockState did not become Locked after LockDoor"
    );
}
