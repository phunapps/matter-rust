//! DUT fixture: commission the all-clusters-app on the first call of a run,
//! reconnect on later calls. The app can only be commissioned once per run, so
//! tests share one commissioning via the node-id sidecar that
//! `xtask integration` clears at the start of every run.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use matter_controller::{
    AttestationTrust, Error, FabricConfig, FileStore, MatterController, MatterTime, Node,
};

use crate::dut::DutConfig;

/// Connect to the DUT: commission it on the first call of the run (persisting the
/// node id to the sidecar), or reconnect via the persisted store + sidecar on
/// subsequent calls. Returns the controller and the commissioned node id.
///
/// # Errors
///
/// Propagates attestation-trust loading, controller construction, and
/// commissioning failures.
pub async fn connect(cfg: &DutConfig) -> Result<(MatterController, u64)> {
    let trust = AttestationTrust::from_dirs(&cfg.paa_dir(), &cfg.cd_dir())
        .context("loading development attestation roots")?;
    // A fresh store needs a fabric (stable commissioner identity) created before
    // commissioning; a restored store already has one.
    let fresh = !cfg.store_path().exists();
    let store = Arc::new(FileStore::new(cfg.store_path()));
    let controller = MatterController::builder(store)
        .attestation_trust(trust)
        .build()
        .await
        .context("building controller")?;

    if fresh {
        // Backdate notBefore an hour for device clock skew; no expiry. (A zero
        // notBefore at the Matter 2000 epoch trips a cert edge devices reject.)
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1_700_000_000, |d| d.as_secs());
        controller
            .create_fabric(FabricConfig::new(
                1,
                1,
                1,
                (
                    MatterTime::from_unix_secs(now_unix.saturating_sub(3600)),
                    MatterTime::NO_EXPIRY,
                ),
            ))
            .await
            .context("creating fabric")?;
    }

    // Already commissioned this run? Reconnect via the persisted store + sidecar
    // (CASE re-establishes lazily on first use).
    if let Ok(raw) = std::fs::read_to_string(cfg.node_sidecar()) {
        if let Ok(node_id) = raw.trim().parse::<u64>() {
            return Ok((controller, node_id));
        }
    }

    let node_id = controller
        .commission(&cfg.setup_code, None)
        .await
        .context("commissioning DUT")?
        .node_id;
    std::fs::write(cfg.node_sidecar(), node_id.to_string()).context("writing node-id sidecar")?;
    Ok((controller, node_id))
}

/// How long [`settle_acks`] waits: past matter-rust's 200 ms MRP
/// standalone-ACK timeout (`MrpConfig::standalone_ack_deadline`), with margin.
pub const ACK_SETTLE: Duration = Duration::from_millis(300);

/// Wait until the standalone ACK for the last response received has gone out
/// (M9-A3 B7).
///
/// matter-rust ACKs a response on its 200 ms standalone-ACK timer, not when
/// the exchange closes (chip flushes the ACK at once), and drops the pending
/// ACK if the controller is dropped first. Until the ACK arrives the device
/// keeps the response in a buffer and retransmits it. chip master's tv-app
/// has only 15 packet buffers (chip c37efec9db: `#ifndef
/// CHIP_DEVICE_LAYER_TARGET_DARWIN` leaves the pool at its default on Linux,
/// where chip's `src/platform/BUILD.gn` defines that macro as 0),
/// so a burst of exchanges, or a controller dropped right after one, runs the
/// pool dry and the device drops a response (seen live against tv-app built at
/// master 5cd2917a). Calling this after each exchange keeps at most one
/// response unACKed. It waits on our own timer, not on the device, so there is
/// no condition to poll.
///
/// This is a workaround, not the fix: remove it once matter-transport flushes
/// the pending standalone ACK when an exchange closes.
pub async fn settle_acks() {
    tokio::time::sleep(ACK_SETTLE).await;
}

/// IM status `INVALID_IN_STATE` (0xCB).
const STATUS_INVALID_IN_STATE: u8 = 0xCB;

/// `Groups::AddGroup` on `endpoint`, failing the test with an explicit diagnosis
/// when the DUT answers `INVALID_IN_STATE`.
///
/// From Groups cluster revision 5 (Matter 1.5), a device that supports the
/// Groupcast cluster owns group membership there and stubs `AddGroup` to return
/// `INVALID_IN_STATE` (connectedhomeip #74101, merged 2026-09-12). matter-rust
/// targets Matter 1.4 and has no Groupcast support yet, so against such a DUT the
/// group tests cannot provision membership. The harness pins connectedhomeip to
/// a 1.4 release for that reason; this message is what a future ref bump (or an
/// unpinned local `CHIP_ROOT`) will hit, instead of a bare status code.
///
/// # Panics
///
/// On any `AddGroup` failure — this is a test fixture.
pub async fn add_group_or_explain(node: &Node, endpoint: u16, group_id: u16, name: &str) {
    match node.add_group(endpoint, group_id, name).await {
        Ok(()) => {}
        Err(Error::GroupCommandRejected(STATUS_INVALID_IN_STATE)) => panic!(
            "add_group: the DUT rejected AddGroup with INVALID_IN_STATE (0xCB). \
             Its Groups cluster is revision 5+ (Matter 1.5 soft-deprecation): group \
             membership moved to the Groupcast cluster, which matter-rust does not \
             support yet. Run the harness against a Matter 1.4 connectedhomeip \
             (the nightly pins CHIP_REF=v1.4.2.0) or implement Groupcast."
        ),
        Err(e) => panic!("add_group: {e:?}"),
    }
}
