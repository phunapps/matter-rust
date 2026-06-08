//! Golden test for the cluster code generator.
//!
//! Regenerates the synthetic fixture cluster and compares against the
//! committed `crates/matter-clusters/src/golden.rs`. That file is compiled by
//! `matter-clusters` (behind `#[cfg(test)] mod golden;`), so this test proves
//! the generator emits **valid, compiling** Rust — not just matching text.
//!
//! Refresh the committed output after an intentional generator change:
//!   `CODEGEN_GOLDEN_REGENERATE=1 cargo test -p xtask --test codegen_golden`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Generate the fixture cluster source and run it through rustfmt, returning
/// the formatted source.
fn generate_formatted() -> String {
    let root = repo_root();
    let fixture = root.join("xtask/tests/fixtures/golden_cluster.json");
    let model = xtask::codegen::model::load(&fixture).expect("fixture loads");
    let raw = xtask::codegen::rustgen::emit::generate_cluster(&model.clusters[0]);
    rustfmt(&raw)
}

fn rustfmt(src: &str) -> String {
    use std::io::Write as _;
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn rustfmt");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(src.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("rustfmt output");
    assert!(
        out.status.success(),
        "rustfmt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn golden_cluster_matches_committed() {
    let generated = generate_formatted();
    let golden_path = repo_root().join("crates/matter-clusters/src/golden.rs");

    if std::env::var_os("CODEGEN_GOLDEN_REGENERATE").is_some() {
        std::fs::write(&golden_path, &generated).expect("write golden");
        eprintln!("regenerated {}", golden_path.display());
        return;
    }

    let committed = std::fs::read_to_string(&golden_path).unwrap_or_default();
    assert_eq!(
        generated, committed,
        "generated cluster source drifted from committed golden.rs — if intentional, \
         run `CODEGEN_GOLDEN_REGENERATE=1 cargo test -p xtask --test codegen_golden` and \
         re-verify `cargo test -p matter-clusters`"
    );
}
