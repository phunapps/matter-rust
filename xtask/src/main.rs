//! `xtask` — workspace automation entry point.
//!
//! Invoked as `cargo xtask <command>` (via the alias in `.cargo/config.toml`).
//! Real subcommands are added milestone by milestone:
//!
//! - `capture-tlv`  — drive `matter.js` to capture TLV vectors (Milestone 0).
//! - `codegen`      — generate cluster definitions from the Matter spec
//!   (Milestone 7).
//! - `release`      — workspace release helper (post-Milestone 1).

use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let cmd = args.next();
    match cmd.as_deref() {
        None | Some("help" | "--help" | "-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("capture-tlv") => match run_capture_tlv() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-tlv: {err}");
                ExitCode::from(1)
            }
        },
        Some(other) => {
            eprintln!("xtask: unknown subcommand `{other}`");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!(
        "xtask — matter-rust workspace automation\n\
         \n\
         USAGE:\n  \
             cargo xtask <subcommand>\n\
         \n\
         SUBCOMMANDS:\n  \
             help          Show this message.\n  \
             capture-tlv   Capture TLV test vectors from matter.js.\n"
    );
}

fn run_capture_tlv() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-tlv");

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

// `cargo xtask` sets CARGO_MANIFEST_DIR to `xtask/`; the workspace root is its
// parent. We resolve it dynamically rather than embedding it, so the binary
// keeps working if someone moves the workspace.
fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| "CARGO_MANIFEST_DIR not set; run via `cargo xtask`".to_string())?;
    PathBuf::from(manifest_dir)
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| "could not derive workspace root from CARGO_MANIFEST_DIR".to_string())
}
