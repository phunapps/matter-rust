// Integration tests are a binary crate; crate-level docs are not required.
// Test-code carve-out for unwrap/expect: see CLAUDE.md.
#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown
)]

/// OTA provider end-to-end vs chip's ota-requestor-app: commission the
/// requestor, then `serve_ota` — announce ourselves as its OTA provider,
/// accept its inbound CASE session (the requestor resumes the announce
/// session), answer `QueryImage` with the generated `.ota` image, stream it
/// over BDX, and return once the requestor sends `NotifyUpdateApplied`.
///
/// The DUT is launched by `just integration-ota`, which also generates the
/// image via chip's `ota_image_tool.py` (vendor 0xFFF1 / product 0x8000 /
/// version 2) and hands its path over in `MATTER_INTEGRATION_OTA_IMAGE`.
#[tokio::test]
async fn serve_ota_to_requestor() {
    let cfg = integration_tests::dut_or_skip!();
    if !cfg.is_app("ota") {
        eprintln!("skipped: OTA test needs the ota-requestor-app DUT (`just integration-ota`)");
        return;
    }
    let image_path = std::env::var("MATTER_INTEGRATION_OTA_IMAGE")
        .expect("MATTER_INTEGRATION_OTA_IMAGE not set — run via `just integration-ota`");
    let image = std::fs::read(&image_path).expect("read generated .ota image");

    let (controller, node_id) = integration_tests::fixture::connect(&cfg)
        .await
        .expect("connect/commission DUT");
    eprintln!(
        "[ota] commissioned node {node_id}; announcing + serving {}-byte image",
        image.len()
    );

    // Offered SoftwareVersion 2 matches the `.ota` header (`-vn 2`) and
    // exceeds the requestor's running version (1), so it downloads + applies.
    // Budget: the requestor first retries QueryImage over the stale announce
    // session (~10s inherent chip detour), commissioning latency varies
    // run-to-run, and the 64 KiB BDX transfer itself is sub-second — 180s
    // absorbs the observed worst case with headroom.
    tokio::time::timeout(
        std::time::Duration::from_secs(180),
        controller.serve_ota(
            node_id, image, /* software_version */ 2, /* port */ 5580,
        ),
    )
    .await
    .expect("OTA flow did not complete within 180s")
    .expect("serve_ota");
    eprintln!("[ota] serve_ota completed — requestor downloaded + applied the image");
}
