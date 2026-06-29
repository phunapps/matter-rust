// Integration tests are a binary crate; crate-level docs are not required.
// Test-code carve-out for unwrap/expect: see CLAUDE.md.
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown
)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use matter_controller::{
    AttestationTrust, FabricConfig, FileStore, MatterController, MatterTime, Node, OpenWindowOpts,
    ReadPath, Value,
};

const ONOFF_CLUSTER: u32 = 0x0006;

// Controller A is the fixture controller (fabric id 1). Controller B uses a
// distinct fabric id so the device's fabric table holds two unambiguous entries.
const FABRIC_B_ID: u64 = 2;

/// Read back the OnOff attribute (ep1, cluster 0x0006, attr 0x0000) over a node.
async fn read_onoff(node: &Node) -> Option<bool> {
    let r = node
        .read(&[ReadPath::concrete(1, ONOFF_CLUSTER, 0x0000)])
        .await
        .expect("read OnOff");
    r.iter().find_map(|(p, v)| {
        if p.attribute == 0x0000 {
            if let Value::Bool(b) = v {
                return Some(*b);
            }
        }
        None
    })
}

// ── Multi-admin: open window → 2nd controller → list/remove fabric ───────────

/// Drive the multi-admin loop against the live DUT:
///   1. Controller A (fixture) commissions the device (fabric 1).
///   2. A opens an enhanced commissioning window.
///   3. Controller B (its own store + fabric 2, same dev-cert trust) commissions
///      the device via the window's manual pairing code.
///   4. A.list_fabrics() shows ≥ 2 fabrics; both A and B can read OnOff.
///   5. A removes B's fabric by index; the fabric count drops back.
///
/// Plan T9 flagged a risk that `commission` might not consume an open-window
/// manual code directly. That is now validated live: the full loop runs (B
/// commissions through the window, A removes B's fabric), so a commission
/// failure here is a hard error — never silently downgraded to a weaker
/// assertion that could let a regression pass green.
#[tokio::test]
async fn open_window_second_controller_and_remove_fabric() {
    let cfg = integration_tests::dut_or_skip!();
    let (controller_a, node_id_a) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT (controller A)");
    let node_a = controller_a.node(node_id_a);

    // Sanity: A controls the device.
    assert!(
        read_onoff(&node_a).await.is_some(),
        "controller A could not read OnOff before opening the window"
    );

    // 2. A opens an enhanced commissioning window.
    let window = node_a
        .open_commissioning_window(OpenWindowOpts::default())
        .await
        .expect("open_commissioning_window");
    assert!(
        !window.manual_code.is_empty(),
        "commissioning window must yield a manual pairing code"
    );

    // 3. Build controller B: its own store under the per-run DUT dir, the same
    //    development attestation roots, and a fresh fabric (id 2).
    let trust = AttestationTrust::from_dirs(&cfg.paa_dir(), &cfg.cd_dir())
        .expect("loading development attestation roots (controller B)");
    let store_b = Arc::new(FileStore::new(cfg.dut_dir.join("controller-b-store.bin")));
    let controller_b = MatterController::builder(store_b)
        .attestation_trust(trust)
        .build()
        .await
        .expect("building controller B");
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_700_000_000, |d| d.as_secs());
    controller_b
        .create_fabric(FabricConfig::new(
            FABRIC_B_ID,
            1,
            FABRIC_B_ID,
            (
                MatterTime::from_unix_secs(now_unix.saturating_sub(3600)),
                MatterTime::NO_EXPIRY,
            ),
        ))
        .await
        .expect("creating controller B fabric");

    // 4. B commissions the device through the open window.
    match controller_b.commission(&window.manual_code).await {
        Ok(node_id_b) => {
            let node_b = controller_b.node(node_id_b);

            // Both control paths are live.
            assert!(
                read_onoff(&node_a).await.is_some(),
                "controller A lost its OnOff read path after B joined"
            );
            assert!(
                read_onoff(&node_b).await.is_some(),
                "controller B could not read OnOff after commissioning"
            );

            // A sees both fabrics.
            let fabrics = node_a.list_fabrics().await.expect("A.list_fabrics");
            assert!(
                fabrics.len() >= 2,
                "expected ≥ 2 fabrics after B joined, got {}: {fabrics:?}",
                fabrics.len()
            );

            // A removes B's fabric (the one whose fabric_id is B's, never A's).
            let b_index = fabrics
                .iter()
                .find(|f| f.fabric_id == FABRIC_B_ID)
                .map(|f| f.fabric_index)
                .expect("B's fabric must be present in A's fabric list");
            node_a
                .remove_fabric(b_index)
                .await
                .expect("A.remove_fabric(B)");

            // The fabric count drops back.
            let after = node_a
                .list_fabrics()
                .await
                .expect("A.list_fabrics after removal");
            assert!(
                after.len() < fabrics.len(),
                "fabric count did not drop after removing B: before={}, after={}",
                fabrics.len(),
                after.len()
            );
            assert!(
                after.iter().all(|f| f.fabric_id != FABRIC_B_ID),
                "B's fabric is still present after removal: {after:?}"
            );
        }
        Err(e) => {
            // The full multi-admin loop is validated live, so a 2nd-controller
            // commission failure is a real regression — fail hard rather than
            // pass vacuously.
            panic!("2nd-controller commission via the open-window manual code failed: {e:?}");
        }
    }
}
