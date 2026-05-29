//! `xtask` — workspace automation entry point.
//!
//! Invoked as `cargo xtask <command>` (via the alias in `.cargo/config.toml`).
//! Real subcommands are added milestone by milestone:
//!
//! - `check`         — run every gate CI runs, locally.
//! - `capture-tlv`   — drive `matter.js` to capture TLV vectors (Milestone 0).
//! - `capture-cert`  — drive `matter.js` to capture certificate vectors (Milestone 2).
//! - `capture-pase`  — drive matter.js to capture PASE handshakes with
//!   fixed scalars (Milestone 3).
//! - `capture-case`  — drive matter.js to capture CASE handshakes with
//!   fixed scalars (Milestone 4).
//! - `capture-framing` — drive matter.js to capture Matter secured-message
//!   framings with fixed AES-CCM keys + counters (Milestone 5).
//! - `capture-protocol-header` — drive matter.js to capture Matter
//!   application protocol header fixtures (Milestone 5.2).
//! - `capture-setup` — drive matter.js to capture Matter setup-payload
//!   fixtures (Milestone 6.1).
//! - `capture-attestation` — drive matter.js to capture P-256
//!   sign/verify `AttestationResponse` fixtures (Milestone 6.2.3).
//! - `capture-cd`    — generate a synthetic CSA-test CD signing root +
//!   matching Certification Declaration fixtures (Milestone 6.4.3).
//! - `capture-commissioning` — drive matter.js through a full
//!   commissioning and capture per-stage Invoke / `ReadAttribute`
//!   payloads for byte-parity (Milestone 6.4.6).
//! - `codegen`       — generate cluster definitions from the Matter spec
//!   (Milestone 7).
//! - `release`       — workspace release helper (post-Milestone 1).

mod capture_cd;
mod capture_commissioning;

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
        Some("check") => match run_check() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask check: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-tlv") => match run_capture_tlv() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-tlv: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-cert") => match run_capture_cert() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-cert: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-pase") => match run_capture_pase() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-pase: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-case") => match run_capture_case() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-case: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-framing") => match run_capture_framing() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-framing: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-protocol-header") => match run_capture_protocol_header() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-protocol-header: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-setup") => match run_capture_setup() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-setup: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-attestation") => match run_capture_attestation() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-attestation: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-noc") => match run_capture_noc() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-noc: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-cd") => match capture_cd::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-cd: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-commissioning") => match capture_commissioning::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-commissioning: {err}");
                ExitCode::FAILURE
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
             help           Show this message.\n  \
             check          Run every gate CI runs, locally.\n  \
             capture-tlv    Capture TLV test vectors from matter.js.\n  \
             capture-cert   Capture Matter test certificates from matter.js.\n  \
             capture-pase   Capture full PASE handshakes from matter.js with fixed scalars.\n  \
             capture-case   Capture full CASE handshakes from matter.js with fixed scalars.\n  \
             capture-framing Capture Matter secured-message framings from matter.js.\n  \
             capture-protocol-header Capture Matter application protocol header fixtures from matter.js.\n  \
             capture-setup            Capture Matter setup-payload fixtures from matter.js.\n  \
             capture-attestation      Capture Matter AttestationResponse fixtures from matter.js.\n  \
             capture-noc              Capture Matter NOC + OpCreds command fixtures from matter.js.\n  \
             capture-cd               Generate a synthetic CSA-test CD signing root + CD fixtures.\n  \
             capture-commissioning    Capture a full matter.js commissioning trace for byte-parity (M6.4.6).\n"
    );
}

/// Run every CI gate locally so a developer can validate the same things
/// CI will validate before pushing. Mirrors `.github/workflows/ci.yml`:
/// rustfmt, clippy, test, rustdoc, cargo audit, cargo deny.
///
/// `cargo audit` and `cargo deny` are optional locally — if they're not
/// installed we print an install hint and skip them, rather than failing
/// the whole command. Everything else is mandatory.
fn run_check() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let mut failures: Vec<&'static str> = Vec::new();

    println!("xtask check: rustfmt --check");
    if !run_cargo(&workspace_root, &["fmt", "--all", "--", "--check"]) {
        failures.push("rustfmt");
    }

    println!("\nxtask check: clippy -D warnings");
    if !run_cargo(
        &workspace_root,
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    ) {
        failures.push("clippy");
    }

    println!("\nxtask check: cargo test");
    if !run_cargo(&workspace_root, &["test", "--workspace", "--all-features"]) {
        failures.push("test");
    }

    println!("\nxtask check: cargo doc -D warnings");
    if !run_cargo_with_env(
        &workspace_root,
        &["doc", "--workspace", "--all-features", "--no-deps"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    ) {
        failures.push("doc");
    }

    println!("\nxtask check: feature-matrix build smoke");
    let matter_transport_invocations: [&[&str]; 3] = [
        &["build", "-p", "matter-transport", "--no-default-features"],
        &[
            "build",
            "-p",
            "matter-transport",
            "--no-default-features",
            "--features",
            "tokio",
        ],
        &[
            "build",
            "-p",
            "matter-transport",
            "--no-default-features",
            "--features",
            "mdns-sd",
        ],
    ];
    for args in matter_transport_invocations {
        if !run_cargo(&workspace_root, args) {
            failures.push("feature-matrix");
            break;
        }
    }

    println!("\nxtask check: cargo audit");
    if tool_installed("cargo-audit") {
        if !run_cargo(&workspace_root, &["audit"]) {
            failures.push("audit");
        }
    } else {
        println!(
            "  skipped — `cargo-audit` not installed.\n  \
             install with: cargo install cargo-audit --locked"
        );
    }

    println!("\nxtask check: cargo deny check");
    if tool_installed("cargo-deny") {
        if !run_cargo(&workspace_root, &["deny", "--all-features", "check"]) {
            failures.push("deny");
        }
    } else {
        println!(
            "  skipped — `cargo-deny` not installed.\n  \
             install with: cargo install cargo-deny --locked"
        );
    }

    println!();
    if failures.is_empty() {
        println!("xtask check: all gates green ✓");
        Ok(())
    } else {
        Err(format!("gates failed: {}", failures.join(", ")))
    }
}

fn run_cargo(cwd: &PathBuf, args: &[&str]) -> bool {
    run_cargo_with_env(cwd, args, &[])
}

fn run_cargo_with_env(cwd: &PathBuf, args: &[&str], env: &[(&str, &str)]) -> bool {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.args(args).current_dir(cwd);
    for (k, v) in env {
        command.env(k, v);
    }
    match command.status() {
        Ok(status) => status.success(),
        Err(err) => {
            eprintln!("  failed to spawn cargo: {err}");
            false
        }
    }
}

/// Check whether a cargo subcommand binary is installed.
///
/// `cargo <tool>` looks up `cargo-<tool>` on $PATH; we mirror that by
/// trying `cargo-<tool> --version`. This is cheap (~ms) and avoids
/// running the actual subcommand only to fail.
fn tool_installed(binary_name: &str) -> bool {
    Command::new(binary_name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn run_capture_tlv() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-tlv");

    if !script_dir.exists() {
        return Err(format!(
            "capture-tlv script directory not found: {}",
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

fn run_capture_cert() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-cert");

    if !script_dir.exists() {
        return Err(format!(
            "capture-cert script directory not found: {}",
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

fn run_capture_pase() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-pase");

    if !script_dir.exists() {
        return Err(format!(
            "capture-pase script directory not found: {}",
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

fn run_capture_case() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-case");

    if !script_dir.exists() {
        return Err(format!(
            "capture-case script directory not found: {}",
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

fn run_capture_framing() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-framing");

    if !script_dir.exists() {
        return Err(format!(
            "capture-framing script directory not found: {}",
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

fn run_capture_protocol_header() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-protocol-header");

    if !script_dir.exists() {
        return Err(format!(
            "capture-protocol-header script directory not found: {}",
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

fn run_capture_setup() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-setup");

    if !script_dir.exists() {
        return Err(format!(
            "capture-setup script directory not found: {}",
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

fn run_capture_attestation() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-attestation");

    if !script_dir.exists() {
        return Err(format!(
            "capture-attestation script directory not found: {}",
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

fn run_capture_noc() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-noc");

    if !script_dir.exists() {
        return Err(format!(
            "capture-noc script directory not found: {}",
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
