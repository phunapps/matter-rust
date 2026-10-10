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

use matter_clusters::gen::access_control;
use matter_codec::{Tag, TlvWriter};
use matter_controller::{
    AttestationTrust, AttributePath, FabricConfig, FileStore, ImStatus, MatterController,
    MatterTime, Node, OpenWindowOpts, ReadPath, Value,
};

const ONOFF_CLUSTER: u32 = 0x0006;

/// Controller A's fabric id: the fixture's `FabricConfig::new(1, ..)`.
const FABRIC_A_ID: u64 = 1;

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

/// Read one attribute of endpoint 0 over `node`: the raw report value.
async fn read_ep0(node: &Node, cluster: u32, attribute: u32) -> Value {
    node.read(&[ReadPath::concrete(0, cluster, attribute)])
        .await
        .expect("read attribute")
        .into_iter()
        .find(|(p, _)| p.attribute == attribute)
        .map(|(_, v)| v)
        .expect("attribute present in report")
}

fn value_to_tlv(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.write_value(Tag::Anonymous, value)
        .expect("infallible: Vec-backed TlvWriter");
    buf
}

/// The field tags of each entry of an unfiltered fabric-scoped list read that
/// belongs to `fabric_index` (its tag 254).
fn tags_of_entries_for(list: &Value, fabric_index: u8) -> Vec<Vec<Tag>> {
    let Value::Array(entries) = list else {
        panic!("expected a list, got {list:?}")
    };
    entries
        .iter()
        .filter_map(|entry| {
            let Value::Structure(fields) = entry else {
                panic!("expected struct entries, got {entry:?}")
            };
            let owner = fields.iter().find_map(|(t, v)| match (t, v) {
                (Tag::Context(254), Value::Uint(i)) => Some(*i),
                _ => None,
            });
            (owner == Some(u64::from(fabric_index)))
                .then(|| fields.iter().map(|(t, _)| *t).collect())
        })
        .collect()
}

/// M9-A3 spec §5.4 against real chip encoding. With B's fabric on the
/// device, A reads AccessControl `Acl` and `Extension` unfiltered (our reads
/// always are): chip returns B's entries carrying only FabricIndex, and the
/// generated decoders must accept them with every fabric-sensitive field
/// `None` while A's own entries keep theirs.
async fn assert_other_fabric_entries_withheld(
    node_a: &Node,
    node_b: &Node,
    a_index: u8,
    b_index: u8,
) {
    const ACL: u32 = access_control::attribute_id::ACL;
    const EXTENSION: u32 = access_control::attribute_id::EXTENSION;
    // Give B an Extension entry so A's read holds one of B's (Data = an empty
    // anonymous TLV list, the shape chip's CheckExtensionEntryDataFormat takes).
    let statuses = node_b
        .write(&[(
            AttributePath {
                endpoint: 0,
                cluster: access_control::CLUSTER_ID,
                attribute: EXTENSION,
            },
            Value::Array(vec![Value::Structure(vec![(
                Tag::Context(1),
                Value::Bytes(vec![0x17, 0x18]),
            )])]),
        )])
        .await
        .expect("B writes Extension");
    assert!(
        statuses.iter().all(|(_, s)| matches!(s, ImStatus::Success)),
        "B's Extension write statuses: {statuses:?}"
    );

    // Wire level first: chip really withholds B's sensitive fields.
    let acl_raw = read_ep0(node_a, access_control::CLUSTER_ID, ACL).await;
    let ext_raw = read_ep0(node_a, access_control::CLUSTER_ID, EXTENSION).await;
    for (what, raw) in [("Acl", &acl_raw), ("Extension", &ext_raw)] {
        let b_entries = tags_of_entries_for(raw, b_index);
        assert!(
            !b_entries.is_empty(),
            "A's {what} read holds no entry of B's fabric: {raw:?}"
        );
        for tags in &b_entries {
            assert_eq!(
                tags,
                &vec![Tag::Context(254)],
                "B's {what} entry was not stripped: {raw:?}"
            );
        }
    }

    // Typed: the whole list decodes; B's entries are all-None, A's are full.
    let acl = access_control::decode_acl(&value_to_tlv(&acl_raw))
        .expect("an unfiltered Acl read with two fabrics must decode");
    for e in &acl {
        let sensitive = [
            e.privilege.is_some(),
            e.auth_mode.is_some(),
            e.subjects.is_some(),
            e.targets.is_some(),
        ];
        if e.fabric_index == b_index {
            assert_eq!(
                sensitive, [false; 4],
                "B's Acl entry has a sensitive field: {e:?}"
            );
        } else if e.fabric_index == a_index {
            assert_eq!(
                sensitive, [true; 4],
                "A's own Acl entry lost a field: {e:?}"
            );
        }
    }
    let ext = access_control::decode_extension(&value_to_tlv(&ext_raw))
        .expect("an unfiltered Extension read with two fabrics must decode");
    let b_ext: Vec<_> = ext.iter().filter(|e| e.fabric_index == b_index).collect();
    assert!(
        !b_ext.is_empty() && b_ext.iter().all(|e| e.data.is_none()),
        "B's Extension: {ext:?}"
    );
    // And writing B's withheld entry back is refused, never silently encoded.
    assert!(
        b_ext[0].encode().is_err(),
        "a withheld Extension entry must not re-encode"
    );

    // matter-controller's hand-written ACL read-modify-write (acl.rs) skips
    // the withheld entries and never writes them back: A's round trip leaves
    // B's admin entry, and so B's access, intact.
    let own = node_a.read_acl().await.expect("A.read_acl with B present");
    assert!(
        own.iter().all(|e| e.fabric_index != Some(b_index)),
        "read_acl returned B's withheld entries: {own:?}"
    );
    node_a
        .write_acl(&own)
        .await
        .expect("A.write_acl round trip");
    assert!(
        read_onoff(node_b).await.is_some(),
        "B lost access after A's ACL round trip"
    );
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
/// assertion that could let a regression pass green. (One bounded retry
/// absorbs the known transient: the window's mDNS advertisement lagging the
/// open-window response; a regression fails both attempts.)
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

    // 4. B commissions the device through the open window. The window's
    //    commissionable advertisement can lag the OpenCommissioningWindow
    //    response by a beat (mDNS propagation on a busy DUT), which showed up
    //    as a transient commission timeout in the sweep — tolerate ONE
    //    transient failure with a short pause. A real regression fails both
    //    attempts and still hard-fails the test.
    let commissioned = match controller_b.commission(&window.manual_code, None).await {
        Ok(id) => Ok(id),
        Err(first) => {
            eprintln!("[multi_admin] B's first commission attempt failed ({first}); retrying once");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            controller_b.commission(&window.manual_code, None).await
        }
    };
    match commissioned {
        Ok(info_b) => {
            let node_b = controller_b.node(info_b.node_id);

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
            let a_index = fabrics
                .iter()
                .find(|f| f.fabric_id == FABRIC_A_ID)
                .map(|f| f.fabric_index)
                .expect("A's fabric must be present in A's fabric list");

            // §5.4 regression against real chip: unfiltered reads with B present.
            assert_other_fabric_entries_withheld(&node_a, &node_b, a_index, b_index).await;

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
