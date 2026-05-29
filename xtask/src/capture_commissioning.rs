//! `xtask capture-commissioning` — drive matter.js through a full
//! simulated commissioning and record every emitted Invoke +
//! `ReadAttribute` payload to
//! `test-vectors/commissioning/e2e/happy-path.json`.
//!
//! M6.4.6. Operator-touch step — re-run whenever matter.js's
//! `@matter/protocol` `CommissioningManager` / `CommissionerNode` API
//! shifts. The fixture this generates feeds the
//! `commissioning_byte_parity.rs` integration test in
//! `matter-commissioning`, which skips cleanly when the fixture is
//! missing/empty so CI stays green during operator wiring (T56).
//!
//! Mirrors the dispatch pattern used by every other `capture-*` arm in
//! `main.rs`: resolve the script directory under
//! `xtask/scripts/capture-commissioning/`, refuse to run without
//! `node_modules` (forces the operator to `npm install` once), spawn
//! `node index.js` with that directory as `cwd`, surface a non-zero
//! exit verbatim.

#![forbid(unsafe_code)]
// xtask is build tooling, not library code; the CLAUDE.md no-unwrap
// rule is for library code only. The existing capture-* modules apply
// the same allow.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

/// Entry point invoked from xtask main.
///
/// # Errors
///
/// Returns a descriptive string if the script directory or its
/// `node_modules` are missing, if `node` fails to spawn, or if the
/// matter.js capture script exits non-zero. The xtask `main` surfaces
/// the message via `eprintln!` and exits non-zero.
pub(crate) fn run() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-commissioning");

    if !script_dir.exists() {
        return Err(format!(
            "capture-commissioning script directory not found: {}",
            script_dir.display()
        ));
    }
    if !script_dir.join("node_modules").exists() {
        return Err(format!(
            "node_modules not found in {}; run `npm install` there first",
            script_dir.display()
        ));
    }

    let status = Command::new("node")
        .arg("index.js")
        .current_dir(&script_dir)
        .status()
        .map_err(|err| format!("failed to spawn node: {err}"))?;

    if !status.success() {
        return Err(format!("node index.js exited with status {status}"));
    }
    Ok(())
}

// Mirrors the resolver in `main.rs` so this module stays self-contained
// (the one in `main.rs` is a free function, not exported).
fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| "CARGO_MANIFEST_DIR not set; run via `cargo xtask`".to_string())?;
    PathBuf::from(manifest_dir)
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| "could not derive workspace root from CARGO_MANIFEST_DIR".to_string())
}
