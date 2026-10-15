//! Cluster code generation (Milestone 7.3).
//!
//! Turns the frozen `xtask/model/clusters.json` (produced by `dump-model`)
//! into one Rust module per cluster.
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

/// The `.rs` files in `dir` that are not in `expected` (file names such as
/// `on_off.rs`), sorted: modules an earlier codegen wrote under a name it no
/// longer produces (a cluster renamed by a [`rustgen::types::snake`] rule
/// change). `mod.rs` declares only the current names, so a stale file is
/// never compiled, and nothing else would notice it.
///
/// # Errors
///
/// Returns a message if `dir` cannot be listed.
pub fn stale_modules(
    dir: &std::path::Path,
    expected: &std::collections::BTreeSet<String>,
) -> Result<Vec<std::path::PathBuf>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("list {}: {e}", dir.display()))?;
    let mut stale = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("list {}: {e}", dir.display()))?
            .path();
        if is_stale(&path, expected) {
            stale.push(path);
        }
    }
    stale.sort();
    Ok(stale)
}

/// Whether `path` is a `.rs` file whose name is not in `expected`.
///
/// A name that is not UTF-8 counts as stale: every name codegen writes is
/// UTF-8, so such a file can never be one of them, and a drift guard must
/// report it rather than skip it.
fn is_stale(path: &std::path::Path, expected: &std::collections::BTreeSet<String>) -> bool {
    let is_rs = path.extension().is_some_and(|x| x == "rs");
    let known = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| expected.contains(n));
    is_rs && !known
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // Test code: a failed temp-dir write should fail the test.
    use super::{is_stale, stale_modules};
    use std::collections::BTreeSet;

    #[test]
    fn a_module_codegen_no_longer_writes_is_stale() {
        let dir = std::env::temp_dir().join(format!("xtask-stale-{}", std::process::id()));
        // A run that panicked before its cleanup may have left files behind
        // under a pid this process now reuses; start from an empty directory.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for f in [
            "mod.rs",
            "on_off.rs",
            "wi_fi_network_diagnostics.rs",
            "notes.txt",
        ] {
            std::fs::write(dir.join(f), "").unwrap();
        }
        let expected: BTreeSet<String> = ["mod.rs", "on_off.rs"].map(String::from).into();
        let stale = stale_modules(&dir, &expected).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(stale, vec![dir.join("wi_fi_network_diagnostics.rs")]);
    }

    /// A non-UTF-8 name cannot be created on every file system (APFS refuses
    /// one), so this checks the predicate on a path built in memory.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_rs_name_is_stale() {
        use std::os::unix::ffi::OsStrExt;
        let expected: BTreeSet<String> = ["mod.rs"].map(String::from).into();
        let name = std::ffi::OsStr::from_bytes(b"gen/\xffbad.rs");
        assert!(is_stale(std::path::Path::new(name), &expected));
        let other = std::ffi::OsStr::from_bytes(b"gen/\xffnotes.txt");
        assert!(!is_stale(std::path::Path::new(other), &expected));
        assert!(!is_stale(std::path::Path::new("gen/mod.rs"), &expected));
    }
}
