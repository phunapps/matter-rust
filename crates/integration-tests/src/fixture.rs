//! DUT fixture: commission the all-clusters-app on the first call of a run,
//! reconnect on later calls. The app can only be commissioned once per run, so
//! tests share one commissioning via the node-id sidecar that
//! `xtask integration` clears at the start of every run.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use matter_controller::{AttestationTrust, FabricConfig, FileStore, MatterController, MatterTime};

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
