// Integration tests are a binary crate; crate-level docs are not required.
// Test-code carve-out for unwrap/expect: see CLAUDE.md.
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::items_after_statements
)]

//! The RVC clusters on a live rvc-app (`just integration-rvc`), endpoint 1.
//!
//! M9-A3 B2: RvcRunMode and RvcCleanMode. rvc-app's modes come from
//! examples/rvc-app/rvc-common/include/rvc-mode-delegates.h; its mode-change
//! rules from rvc-common/src/rvc-device.cpp (`HandleRvcRunChangeToMode`,
//! `HandleRvcCleanChangeToMode`). Line numbers cited below are chip master
//! 5cd2917a; v1.4.2.0's rvc-mode-delegates.h is byte-identical and its two
//! change handlers differ only in whitespace, and these tests use neither
//! the app pipe nor a test-event trigger, so they are v1.4.2.0-safe.
//!
//! The tests run single-threaded (`--test-threads=1`, xtask `run_tests`) in
//! name order, against one rvc-app booted with a fresh KVS.

use integration_tests::dut::DutConfig;
use integration_tests::sweep::{
    attribute_ids, attribute_tlv, invoke_for_response, read_cluster_attributes,
};
use matter_clusters::error::ClusterError;
use matter_clusters::gen::{rvc_clean_mode, rvc_run_mode};
use matter_controller::{CommandPath, MatterController, Node};

/// rvc-app's RVC endpoint (`RVC_ENDPOINT` in examples/rvc-app/linux/main.cpp:25).
const EP: u16 = 1;

/// The DUT config, controller and node id, or `None` (skip) unless the DUT is
/// rvc-app.
async fn connect_rvc() -> Option<(DutConfig, MatterController, u64)> {
    let Some(cfg) = DutConfig::from_env() else {
        eprintln!("skipped: no DUT (set MATTER_INTEGRATION_DUT via `just integration-rvc`)");
        return None;
    };
    if !cfg.is_app("rvc") {
        eprintln!("skipped: RVC test needs the rvc-app DUT (`just integration-rvc`)");
        return None;
    }
    let (controller, node_id) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT");
    Some((cfg, controller, node_id))
}

/// Both mode clusters: every attribute decodes, ChangeToMode(CurrentMode)
/// answers Success with no StatusText, and the served attributes and
/// supported modes are exactly rvc-app's.
#[tokio::test]
async fn rvc_mode_clusters_decode_and_change_to_current_mode() {
    let Some((_, controller, node_id)) = connect_rvc().await else {
        return;
    };
    let node = controller.node(node_id);
    integration_tests::sweep_mode_base!(&node, EP, rvc_run_mode);
    integration_tests::sweep_mode_base!(&node, EP, rvc_clean_mode);
    assert_run_modes(&node).await;
    assert_clean_modes(&node).await;
}

/// RvcRunMode: rvc-app.matter:1956-1966 serves exactly SupportedModes and
/// CurrentMode (no OnMode/StartUpMode), and rvc-mode-delegates.h:36-57 lists
/// three modes, one tag each.
async fn assert_run_modes(node: &Node) {
    use rvc_run_mode::attribute_id::{CURRENT_MODE, SUPPORTED_MODES};
    use rvc_run_mode::ModeTag as Run;
    let attrs = read_cluster_attributes(node, EP, rvc_run_mode::CLUSTER_ID)
        .await
        .unwrap();
    assert_eq!(attribute_ids(&attrs), [SUPPORTED_MODES, CURRENT_MODE]);
    let run = rvc_run_mode::decode_supported_modes(attribute_tlv(&attrs, SUPPORTED_MODES)).unwrap();
    let got: Vec<(u8, &str, Vec<Run>)> = run
        .iter()
        .map(|m| {
            (
                m.mode,
                m.label.as_str(),
                m.mode_tags.iter().map(|t| t.value).collect(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (0, "Idle", vec![Run::Idle]),
            (1, "Cleaning", vec![Run::Cleaning]),
            (2, "Mapping", vec![Run::Mapping]),
        ]
    );
}

/// RvcCleanMode: rvc-app.matter:1968-1978 serves exactly SupportedModes and
/// CurrentMode, and rvc-mode-delegates.h:85-132 lists six modes whose tags mix
/// RvcCleanMode's own (Vacuum, Mop, DeepClean, VacuumThenMop) with the common
/// ModeBase ones (Quick, Auto, Quiet), in rvc-app's order.
async fn assert_clean_modes(node: &Node) {
    use rvc_clean_mode::attribute_id::{CURRENT_MODE, SUPPORTED_MODES};
    use rvc_clean_mode::ModeTag as Clean;
    let attrs = read_cluster_attributes(node, EP, rvc_clean_mode::CLUSTER_ID)
        .await
        .unwrap();
    assert_eq!(attribute_ids(&attrs), [SUPPORTED_MODES, CURRENT_MODE]);
    let clean =
        rvc_clean_mode::decode_supported_modes(attribute_tlv(&attrs, SUPPORTED_MODES)).unwrap();
    let got: Vec<(u8, &str, Vec<Clean>)> = clean
        .iter()
        .map(|m| {
            (
                m.mode,
                m.label.as_str(),
                m.mode_tags.iter().map(|t| t.value).collect(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (0, "Quick", vec![Clean::Vacuum, Clean::Quick]),
            (1, "Auto", vec![Clean::Auto, Clean::Vacuum]),
            (
                2,
                "Deep Clean",
                vec![Clean::Mop, Clean::DeepClean, Clean::Vacuum]
            ),
            (3, "Quiet", vec![Clean::Quiet, Clean::Vacuum]),
            (4, "Max Vac", vec![Clean::Vacuum, Clean::DeepClean]),
            (
                5,
                "Vacuum Then Mop",
                vec![Clean::Vacuum, Clean::Mop, Clean::VacuumThenMop]
            ),
        ]
    );
}

/// `CurrentMode` of a mode cluster on [`EP`], read fresh.
async fn current_mode(
    node: &Node,
    cluster: u32,
    decode: fn(&[u8]) -> Result<u8, ClusterError>,
) -> u8 {
    // CurrentMode is attribute 0x0001 in every ModeBase derivative.
    let attrs = read_cluster_attributes(node, EP, cluster).await.unwrap();
    decode(attribute_tlv(
        &attrs,
        rvc_run_mode::attribute_id::CURRENT_MODE,
    ))
    .unwrap()
}

/// `RvcRunMode.ChangeToMode(mode)` and its decoded response (the invoke must
/// answer with ChangeToModeResponse, not a bare status).
async fn change_run_mode(node: &Node, mode: u8) -> rvc_run_mode::ChangeToModeResponse {
    let resp = invoke_for_response(
        node,
        CommandPath {
            endpoint: EP,
            cluster: rvc_run_mode::CLUSTER_ID,
            command: rvc_run_mode::command_id::CHANGE_TO_MODE,
        },
        rvc_run_mode::encode_change_to_mode(mode),
        rvc_run_mode::command_id::CHANGE_TO_MODE_RESPONSE,
    )
    .await
    .unwrap_or_else(|e| panic!("RvcRunMode.ChangeToMode({mode}): {e:#}"));
    rvc_run_mode::ChangeToModeResponse::decode(&resp).expect("ChangeToModeResponse decodes")
}

/// `RvcCleanMode.ChangeToMode(mode)` and its decoded response.
async fn change_clean_mode(node: &Node, mode: u8) -> rvc_clean_mode::ChangeToModeResponse {
    let resp = invoke_for_response(
        node,
        CommandPath {
            endpoint: EP,
            cluster: rvc_clean_mode::CLUSTER_ID,
            command: rvc_clean_mode::command_id::CHANGE_TO_MODE,
        },
        rvc_clean_mode::encode_change_to_mode(mode),
        rvc_clean_mode::command_id::CHANGE_TO_MODE_RESPONSE,
    )
    .await
    .unwrap_or_else(|e| panic!("RvcCleanMode.ChangeToMode({mode}): {e:#}"));
    rvc_clean_mode::ChangeToModeResponse::decode(&resp).expect("ChangeToModeResponse decodes")
}

/// A refused mode change carries rvc-app's StatusText, on both clusters.
///
/// rvc-app boots in run mode Idle and operational state Stopped
/// (rvc-device.h:52-56). From there Idle -> Mapping is accepted
/// (rvc-device.cpp:42-61, state becomes Running). While Running, any run mode
/// but Idle is refused with InvalidInMode and a StatusText
/// (rvc-device.cpp:63-69), and any clean-mode change is refused because the
/// run mode is not Idle (rvc-device.cpp:87-96). Mapping -> Idle is then
/// accepted (rvc-device.cpp:71-77).
///
/// Every new mode differs from CurrentMode: chip answers a same-mode change
/// with Success before consulting the delegate (ModeBaseCluster.cpp:412-417),
/// which would make the refusal vacuous. The run mode is returned to Idle
/// before any value is asserted, so a wrong value cannot strand the robot in
/// Mapping. Not restorable here: the operational state is left SeekingCharger
/// (rvc-device.cpp:72-73), which only an app-pipe message changes; B2 sends
/// none, and no B2 test reads RvcOperationalState.
#[tokio::test]
async fn refused_run_mode_change_decodes_its_status_text() {
    let Some((_, controller, node_id)) = connect_rvc().await else {
        return;
    };
    let node = controller.node(node_id);
    use rvc_clean_mode::ModeChangeStatus as CleanStatus;
    use rvc_run_mode::ModeChangeStatus as RunStatus;
    let run_cluster = rvc_run_mode::CLUSTER_ID;
    let clean_cluster = rvc_clean_mode::CLUSTER_ID;
    let decode_run = rvc_run_mode::decode_current_mode;
    let decode_clean = rvc_clean_mode::decode_current_mode;

    let run_before = current_mode(&node, run_cluster, decode_run).await;
    assert_eq!(run_before, 0, "rvc-app boots Idle; a stale DUT?");
    let clean_before = current_mode(&node, clean_cluster, decode_clean).await;
    // Auto (1), or Quick (0) if Auto is current: never the current mode.
    let clean_target = match clean_before {
        1 => 0,
        _ => 1,
    };

    let start = change_run_mode(&node, 2).await; // Idle -> Mapping
    let mapping = current_mode(&node, run_cluster, decode_run).await;
    let refused = change_run_mode(&node, 1).await; // Mapping -> Cleaning
    let still_mapping = current_mode(&node, run_cluster, decode_run).await;
    let clean_refused = change_clean_mode(&node, clean_target).await;
    let clean_after = current_mode(&node, clean_cluster, decode_clean).await;
    let back = change_run_mode(&node, 0).await; // Mapping -> Idle
    let run_after = current_mode(&node, run_cluster, decode_run).await;

    assert_eq!(
        (start.status, start.status_text),
        (RunStatus::Success, None)
    );
    assert_eq!(mapping, 2);
    assert_eq!(refused.status, RunStatus::InvalidInMode);
    assert_eq!(
        refused.status_text.as_deref(),
        Some("Change to the mapping or cleaning mode is only allowed from idle")
    );
    assert_eq!(still_mapping, 2, "a refused change leaves CurrentMode");
    assert_eq!(clean_refused.status, CleanStatus::InvalidInMode);
    assert_eq!(
        clean_refused.status_text.as_deref(),
        Some("Change of the cleaning mode is only allowed in Idle.")
    );
    assert_eq!(
        clean_after, clean_before,
        "a refused change leaves CurrentMode"
    );
    assert_eq!((back.status, back.status_text), (RunStatus::Success, None));
    assert_eq!(run_after, 0, "the robot is back in Idle");
}
