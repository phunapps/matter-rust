//! Cluster code generation (Milestone 7.3).
//!
//! Turns the frozen `xtask/model/clusters.json` (produced by `dump-model`,
//! M7.2) into the uniform per-cluster Rust module shape (M7 spec §2).
//!
//! Pipeline: [`model::load`] (deserialize + validate) → [`rustgen`] (map
//! types, emit strings) → rustfmt. The generator is pure: same JSON in →
//! same Rust out, byte-for-byte.

pub mod model;
pub mod rustgen;

use std::io::Write as _;
use std::process::{Command, Stdio};

/// Run `src` through rustfmt, returning the formatted source.
///
/// # Errors
///
/// Returns a message if rustfmt cannot be spawned or rejects the input.
pub fn rustfmt_source(src: &str) -> Result<String, String> {
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn rustfmt: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("rustfmt stdin unavailable")?
        .write_all(src.as_bytes())
        .map_err(|e| format!("write to rustfmt: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("rustfmt: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "rustfmt rejected generated source: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("rustfmt utf8: {e}"))
}
