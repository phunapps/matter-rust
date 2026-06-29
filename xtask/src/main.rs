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
//! - `capture-im`     — drive matter.js IM TLV schemas to capture
//!   invoke/read/write fixtures (Milestone 7.1).
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
//! - `dump-model` — walk the pinned `@matter/model` standard data model and
//!   emit `xtask/model/clusters.json`, the frozen codegen input (Milestone 7).
//! - `capture-clusters` — encode curated cluster attribute/command TLV with
//!   matter.js 0.16.11 into `test-vectors/clusters/` (Milestone 7.4a).
//! - `trace-diff`    — structurally compare two decrypted commissioning
//!   dialogues (ours vs matter.js) for M6 cross-verification.
//! - `codegen`       — generate cluster definitions from the Matter spec
//!   (Milestone 7).
//! - `release`       — workspace release helper (post-Milestone 1).

mod capture_cd;
mod capture_commissioning;
mod integration;
mod trace_diff;

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use xtask::codegen;

#[allow(clippy::too_many_lines)]
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
        Some("capture-im") => match run_capture_im() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-im: {err}");
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
        Some("integration") => match integration::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask integration: {err}");
                ExitCode::FAILURE
            }
        },
        Some("dump-model") => match run_dump_model() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask dump-model: {err}");
                ExitCode::FAILURE
            }
        },
        Some("capture-clusters") => match run_capture_clusters() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask capture-clusters: {err}");
                ExitCode::FAILURE
            }
        },
        Some("codegen") => {
            let check = args.next().as_deref() == Some("--check");
            match run_codegen(check) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("xtask codegen: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("trace-diff") => {
            let (Some(a), Some(b)) = (args.next(), args.next()) else {
                eprintln!("usage: cargo xtask trace-diff <ours.jsonl> <theirs.jsonl>");
                return ExitCode::FAILURE;
            };
            match trace_diff::run(&PathBuf::from(a), &PathBuf::from(b)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("trace-diff: {e}");
                    ExitCode::FAILURE
                }
            }
        }
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
             capture-im      Capture IM invoke/read/write byte-parity fixtures from matter.js.\n  \
             capture-protocol-header Capture Matter application protocol header fixtures from matter.js.\n  \
             capture-setup            Capture Matter setup-payload fixtures from matter.js.\n  \
             capture-attestation      Capture Matter AttestationResponse fixtures from matter.js.\n  \
             capture-noc              Capture Matter NOC + OpCreds command fixtures from matter.js.\n  \
             capture-cd               Generate a synthetic CSA-test CD signing root + CD fixtures.\n  \
             capture-commissioning    Capture a full matter.js commissioning trace for byte-parity (M6.4.6).\n  \
             integration              Build/launch all-clusters-app DUT and run the integration sweep.\n  \
             dump-model               Dump the @matter/model data model to xtask/model/clusters.json (M7.2).\n  \
             capture-clusters         Capture cluster attribute/command byte-parity vectors from matter.js (M7.4a).\n  \
             codegen [--check]        Generate matter-clusters from clusters.json (M7); --check fails on drift.\n  \
             trace-diff               Compare two decrypted commissioning traces for M6 cross-verification.\n"
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

fn run_capture_im() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-im");

    if !script_dir.exists() {
        return Err(format!(
            "capture-im script directory not found: {}",
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

fn run_capture_clusters() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/capture-clusters");

    if !script_dir.exists() {
        return Err(format!(
            "capture-clusters script directory not found: {}",
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

fn run_dump_model() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    let script_dir = workspace_root.join("xtask/scripts/dump-model");

    if !script_dir.exists() {
        return Err(format!(
            "dump-model script directory not found: {}",
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

/// Generate `matter-clusters` cluster modules from `xtask/model/clusters.json`.
///
/// With `check`, regenerates and compares against the committed files,
/// returning an error on drift (no writes). Otherwise writes the modules to
/// `crates/matter-clusters/src/gen/`. The real generated output is committed
/// in M7.4 (gated by byte-parity); in M7.3 this command is functional but its
/// output is not committed.
fn run_codegen(check: bool) -> Result<(), String> {
    let root = workspace_root()?;
    let model_path = root.join("xtask/model/clusters.json");
    let model = codegen::model::load(&model_path)?;
    let out_dir = root.join("crates/matter-clusters/src/gen");

    for cluster in &model.clusters {
        let module = codegen::rustgen::emit::generate_cluster(cluster);
        let formatted = codegen::rustfmt_source(&module)?;
        let file = out_dir.join(format!(
            "{}.rs",
            codegen::rustgen::types::snake(&cluster.name)
        ));
        write_or_check(&file, &formatted, check)?;
    }

    // Shared globals module.
    let globals = codegen::rustfmt_source(&codegen::rustgen::emit::generate_globals())?;
    write_or_check(&out_dir.join("globals.rs"), &globals, check)?;

    // Module index: `pub mod <snake>;` for each cluster + globals.
    let mut index = String::from(
        "//! @generated by `cargo xtask codegen` — do not edit.\n\npub mod globals;\n",
    );
    let names: Vec<String> = model
        .clusters
        .iter()
        .map(|c| codegen::rustgen::types::snake(&c.name))
        .collect();
    for n in &names {
        index.push_str("pub mod ");
        index.push_str(n);
        index.push_str(";\n");
    }
    // rustfmt the index too (it reorders `mod` declarations), so `codegen
    // --check` matches a `cargo fmt`-normalized tree.
    let index = codegen::rustfmt_source(&index)?;
    write_or_check(&out_dir.join("mod.rs"), &index, check)?;

    if !check {
        println!(
            "codegen: wrote {} cluster modules + globals + mod.rs",
            model.clusters.len()
        );
    }
    Ok(())
}

/// Write `formatted` to `file`, or (when `check`) error if it differs from the
/// committed contents.
fn write_or_check(file: &std::path::Path, formatted: &str, check: bool) -> Result<(), String> {
    if check {
        let existing = std::fs::read_to_string(file).unwrap_or_default();
        if existing != formatted {
            return Err(format!("codegen drift in {}", file.display()));
        }
    } else {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        std::fs::write(file, formatted).map_err(|e| format!("write {}: {e}", file.display()))?;
    }
    Ok(())
}
