//! `xtask integration` — build/launch/teardown the all-clusters-app DUT, then
//! run the integration test suite.
//!
//! Usage: `cargo xtask integration` (or `just integration`).
//!
//! Steps:
//! 1. Locate (and optionally build) connectedhomeip's `all-clusters-app`.
//! 2. Kill any stale DUT process that might be holding a UDP port.
//! 3. Launch the app with a fresh temp KVS dir, redirecting output to a log
//!    file under `target/integration-dut/`.
//! 4. Wait up to 30 s for the app to log `"Server Listening"`.
//! 5. Run `cargo test -p integration-tests` with the necessary env vars set.
//! 6. Kill the app on every exit path via a Drop-based guard.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// A connectedhomeip example app the harness can drive as a DUT.
struct AppSpec {
    /// Canonical app name (also exported as `MATTER_INTEGRATION_DUT_APP`).
    name: &'static str,
    /// `build_examples.py` target suffix: `<host-target>-<suffix>`.
    target_suffix: &'static str,
    /// Binary name under `out/<host-target>-<suffix>/`.
    binary: &'static str,
    /// If set, this fixed setup QR is used; if `None`, the device's QR is parsed
    /// from the app log (keeps the proven all-clusters path on its known QR).
    fixed_qr: Option<&'static str>,
    /// If set, `cargo test` is restricted to this single `--test <name>` binary
    /// (so a minimal DUT doesn't run the all-clusters cluster tests).
    test_filter: Option<&'static str>,
    /// Extra CLI args passed to the DUT after `--KVS <path>` (default `&[]`).
    /// e.g. lit-icd-app's short ICD timers so a Check-In is prompt.
    extra_args: &'static [&'static str],
    /// If set, generate a `.ota` image before the tests and export its path as
    /// `MATTER_INTEGRATION_OTA_IMAGE` (the OTA requestor test consumes it).
    needs_ota_image: bool,
    /// On Linux, build/run the app's `-platform-mdns` target variant (chip
    /// advertises + resolves via avahi instead of its minimal-mDNS). Needed
    /// when the app must RESOLVE the controller's mdns-sd advertisement: on a
    /// headless runner there is no mediating responder, and chip's minmdns
    /// resolver does not see mdns-sd records (macOS's system mDNSResponder
    /// mediates, so the plain target works there). No effect on macOS.
    linux_platform_mdns: bool,
}

/// Resolve the DUT app spec from the optional `xtask integration <app>` argument.
fn app_spec(app: Option<&str>) -> Result<AppSpec, String> {
    Ok(match app.unwrap_or("all-clusters") {
        "all-clusters" => AppSpec {
            name: "all-clusters",
            target_suffix: "all-clusters",
            binary: "chip-all-clusters-app",
            fixed_qr: Some("MT:-24J042C00KA0648G00"),
            test_filter: None,
            extra_args: &[],
            needs_ota_image: false,
            linux_platform_mdns: false,
        },
        "lock" => AppSpec {
            name: "lock",
            target_suffix: "lock",
            binary: "chip-lock-app",
            fixed_qr: None,
            test_filter: Some("clusters_door_lock"),
            extra_args: &[],
            needs_ota_image: false,
            linux_platform_mdns: false,
        },
        "evse" => AppSpec {
            name: "evse",
            target_suffix: "evse",
            binary: "chip-evse-app",
            fixed_qr: None,
            test_filter: Some("clusters_electrical"),
            extra_args: &[],
            needs_ota_image: false,
            linux_platform_mdns: false,
        },
        "icd" => AppSpec {
            name: "icd",
            target_suffix: "lit-icd",
            binary: "lit-icd-app",
            fixed_qr: None,
            test_filter: Some("icd_checkin"),
            // Short ICD timers so the device goes idle ~1s after we go quiet and
            // checks in on a 15s cycle (defaults are 10s active / 3600s idle).
            // chip requires activeModeDuration(ms) <= idleModeDuration(s).
            extra_args: &[
                "--icdActiveModeDurationMs",
                "1000",
                "--icdIdleModeDuration",
                "15",
            ],
            needs_ota_image: false,
            // The ICD flow's Check-In requires the DEVICE to resolve the
            // controller's operational advertisement — the direction that
            // needs avahi mediation on a headless Linux runner.
            linux_platform_mdns: true,
        },
        "ota" => AppSpec {
            name: "ota",
            target_suffix: "ota-requestor",
            binary: "chip-ota-requestor-app",
            fixed_qr: None,
            test_filter: Some("ota_flow"),
            // Without --autoApplyImage the app stops after the BDX download
            // (StateTransition -> idle) and never sends ApplyUpdateRequest /
            // NotifyUpdateApplied, so the provider-side flow can't complete.
            extra_args: &["--autoApplyImage"],
            needs_ota_image: true,
            linux_platform_mdns: false,
        },
        other => {
            return Err(format!(
                "unknown integration app '{other}' \
                 (expected: all-clusters, lock, evse, icd, ota)"
            ))
        }
    })
}

/// Run the integration orchestration end-to-end for the selected DUT app.
pub(crate) fn run(app: Option<&str>) -> Result<(), String> {
    let spec = app_spec(app)?;
    let chip_root = chip_root()?;
    let binary = locate_or_build_binary(&chip_root, &spec)?;

    kill_stale_duts();

    let dut_dir = prepare_dut_dir()?;
    let kvs_path = dut_dir.join("kvs.json");
    let log_path = dut_dir.join("app.log");

    // Fresh state each run: the app must boot UNcommissioned (so the fixture can
    // commission it), and every controller store + node-id sidecar from a prior
    // run must be cleared (else a controller would try to reconnect — or re-create
    // a fabric — against a freshly-booted app that no longer has that node).
    // `controller-b-store.bin` is the second-controller store the multi_admin
    // test creates; it must be cleared too or its stale fabric breaks the re-run.
    for stale in [
        "kvs.json",
        "controller-store.bin",
        "controller-store.tmp",
        "node-id.txt",
        "controller-b-store.bin",
        "controller-b-store.tmp",
        "test.ota",
        "ota-payload.bin",
    ] {
        let _ = fs::remove_file(dut_dir.join(stale));
    }

    eprintln!("integration: app  → {}", spec.name);
    eprintln!("integration: launching {}", binary.display());
    eprintln!("integration: KVS  → {}", kvs_path.display());
    eprintln!("integration: log  → {}", log_path.display());

    let child = spawn_dut(&binary, &kvs_path, spec.extra_args, &log_path)?;

    // The Drop guard ensures the child is killed no matter how run() exits.
    let mut guard = DutGuard(child);

    wait_for_ready(&log_path)?;
    eprintln!("integration: DUT ready — Server Listening detected");

    // The all-clusters app keeps its known QR; other apps advertise a different
    // payload, so parse the device's real QR from its startup log.
    let setup_qr = match spec.fixed_qr {
        Some(qr) => qr.to_string(),
        None => parse_setup_qr(&log_path)?,
    };

    let multicast_if = resolve_multicast_if();

    // OTA requestor needs a real `.ota` image to download; generate it now and
    // hand its path to the test via env.
    let ota_image = if spec.needs_ota_image {
        let img = generate_ota_image(&chip_root, &dut_dir)?;
        eprintln!("integration: OTA image → {}", img.display());
        Some(img)
    } else {
        None
    };

    let status = run_tests(
        &chip_root,
        &dut_dir,
        multicast_if,
        &spec,
        &setup_qr,
        ota_image.as_deref(),
    )?;

    // Explicit teardown before we inspect the exit status, so the process is
    // gone even on a test failure.
    guard.kill_and_wait();

    if status.success() {
        eprintln!("integration: all tests passed ✓");
        Ok(())
    } else {
        Err(format!("integration tests exited with status {status}"))
    }
}

// ---------------------------------------------------------------------------
// Locate / build the DUT binary
// ---------------------------------------------------------------------------

/// Resolve `CHIP_ROOT` and verify the directory exists.
fn chip_root() -> Result<PathBuf, String> {
    let root: PathBuf = std::env::var("CHIP_ROOT")
        .unwrap_or_else(|_| "/Users/hemanshubhojak/code/connectedhomeip".into())
        .into();
    if !root.exists() {
        return Err(format!(
            "CHIP_ROOT directory does not exist: {}\n\
             Set the CHIP_ROOT environment variable to the connectedhomeip checkout.",
            root.display()
        ));
    }
    Ok(root)
}

/// Return the host-specific build target string (e.g. `darwin-arm64`).
fn host_target() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin-arm64"
    } else {
        "linux-x64"
    }
}

/// Return the expected path to the selected app's binary. If it is missing,
/// build it first.
fn locate_or_build_binary(chip_root: &Path, spec: &AppSpec) -> Result<PathBuf, String> {
    let target = host_target();
    let suffix = if spec.linux_platform_mdns && cfg!(target_os = "linux") {
        format!("{}-platform-mdns", spec.target_suffix)
    } else {
        spec.target_suffix.to_string()
    };
    let binary = chip_root
        .join("out")
        .join(format!("{target}-{suffix}"))
        .join(spec.binary);

    if binary.exists() {
        eprintln!(
            "integration: found pre-built binary at {}",
            binary.display()
        );
        return Ok(binary);
    }

    eprintln!("integration: binary not found — building {target}-{suffix} (this takes a while)");

    let script = format!(
        "source scripts/activate.sh && \
         ./scripts/build/build_examples.py \
             --target {target}-{suffix} build"
    );

    let status = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .current_dir(chip_root)
        .status()
        .map_err(|e| format!("failed to spawn build shell: {e}"))?;

    if !status.success() {
        return Err(format!(
            "connectedhomeip build failed (exit {status})\n\
             Build command: bash -c \"{script}\"\n\
             in directory: {}",
            chip_root.display()
        ));
    }

    if !binary.exists() {
        return Err(format!(
            "build appeared to succeed but binary still missing: {}",
            binary.display()
        ));
    }

    Ok(binary)
}

// ---------------------------------------------------------------------------
// Stale-process cleanup
// ---------------------------------------------------------------------------

/// Best-effort kill of any running chip-*-app processes (e.g. a DUT left over
/// from a previous crashed run). pkill returns non-zero when nothing matched,
/// so we silently ignore the exit status.
fn kill_stale_duts() {
    let _ = Command::new("pkill")
        .args(["-f", "chip-.*-app"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // Give the OS a moment to reclaim the UDP port.
    thread::sleep(Duration::from_millis(300));
}

// ---------------------------------------------------------------------------
// Temp KVS / log directory
// ---------------------------------------------------------------------------

/// Create (and return) `<workspace>/target/integration-dut/`.
fn prepare_dut_dir() -> Result<PathBuf, String> {
    // Derive the workspace root from CARGO_MANIFEST_DIR (set when run via
    // `cargo xtask`); the dir is `xtask/`, its parent is the workspace root.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| "CARGO_MANIFEST_DIR not set; run via `cargo xtask integration`".to_string())?;
    let workspace_root = PathBuf::from(&manifest_dir)
        .parent()
        .ok_or_else(|| "could not derive workspace root from CARGO_MANIFEST_DIR".to_string())?
        .to_path_buf();

    let dut_dir = workspace_root.join("target").join("integration-dut");
    fs::create_dir_all(&dut_dir)
        .map_err(|e| format!("create DUT dir {}: {e}", dut_dir.display()))?;
    Ok(dut_dir)
}

// ---------------------------------------------------------------------------
// Spawn DUT
// ---------------------------------------------------------------------------

/// Spawn the all-clusters-app with the given KVS path.  stdout+stderr are
/// redirected to `log_path` so the main terminal stays readable.
fn spawn_dut(
    binary: &Path,
    kvs_path: &Path,
    extra_args: &[&str],
    log_path: &Path,
) -> Result<Child, String> {
    let log_file = fs::File::create(log_path)
        .map_err(|e| format!("create log file {}: {e}", log_path.display()))?;
    // Two separate file handles for stdout and stderr.
    let log_file2 = log_file
        .try_clone()
        .map_err(|e| format!("clone log file handle for stderr: {e}"))?;

    let child = Command::new(binary)
        .arg("--KVS")
        .arg(kvs_path)
        .args(extra_args)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file2))
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", binary.display()))?;

    Ok(child)
}

/// Generate a throwaway `.ota` image under `dut_dir` with chip's image tool and
/// return its path. The requestor validates only the `OTAImageHeader` (vendor
/// 0xFFF1 / product 0x8000 / version 2, above the requestor's built-in
/// software version 1), not the payload, so a fixed zero payload is fine.
fn generate_ota_image(chip_root: &Path, dut_dir: &Path) -> Result<PathBuf, String> {
    let payload = dut_dir.join("ota-payload.bin");
    fs::write(&payload, vec![0u8; 64 * 1024])
        .map_err(|e| format!("write ota payload {}: {e}", payload.display()))?;
    let image = dut_dir.join("test.ota");
    let tool = chip_root.join("src/app/ota_image_tool.py");

    let status = Command::new("python3")
        .arg(&tool)
        .args([
            "create", "-v", "0xFFF1", "-p", "0x8000", "-vn", "2", "-vs", "2.0", "-da", "sha256",
        ])
        .arg(&payload)
        .arg(&image)
        .status()
        .map_err(|e| format!("spawn ota_image_tool.py: {e}"))?;
    if !status.success() {
        return Err(format!(
            "ota_image_tool.py create failed (exit {status}); tool: {}",
            tool.display()
        ));
    }
    Ok(image)
}

// ---------------------------------------------------------------------------
// Teardown guard
// ---------------------------------------------------------------------------

/// Holds a running DUT child process and kills it when dropped.
struct DutGuard(Child);

impl DutGuard {
    /// Kill the child and wait for it to exit.  Called explicitly before we
    /// inspect the test exit status so the port is free for re-use.
    fn kill_and_wait(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for DutGuard {
    fn drop(&mut self) {
        // Idempotent: kill() on an already-dead process is harmless.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ---------------------------------------------------------------------------
// Readiness probe
// ---------------------------------------------------------------------------

/// Poll `log_path` until `"Server Listening"` appears or 30 seconds elapse.
/// On timeout, returns an error that includes the last few lines of the log.
fn wait_for_ready(log_path: &Path) -> Result<(), String> {
    const TIMEOUT: Duration = Duration::from_secs(30);
    const POLL_INTERVAL: Duration = Duration::from_millis(200);
    const NEEDLE: &str = "Server Listening";

    let start = Instant::now();
    loop {
        if let Ok(mut f) = fs::File::open(log_path) {
            let mut contents = String::new();
            // read_to_string is best-effort; ignore transient errors while the
            // app is still writing.
            let _ = f.read_to_string(&mut contents);
            if contents.contains(NEEDLE) {
                return Ok(());
            }
        }

        if start.elapsed() >= TIMEOUT {
            // Include the tail of the log in the error for easier diagnosis.
            let tail = read_tail(log_path, 20);
            return Err(format!(
                "timed out waiting for DUT to print \"{NEEDLE}\" after {}s.\n\
                 Last lines of {}:\n{}",
                TIMEOUT.as_secs(),
                log_path.display(),
                tail
            ));
        }

        thread::sleep(POLL_INTERVAL);
    }
}

/// Read up to `n` lines from the end of a file (best-effort; returns empty
/// string on any I/O error so the caller can still format a useful message).
fn read_tail(path: &Path, n: usize) -> String {
    let Ok(contents) = fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

// ---------------------------------------------------------------------------
// Interface index resolution
// ---------------------------------------------------------------------------

/// Resolve the `MATTER_MULTICAST_IF` value:
///
/// - If the env var is already set by the caller, reuse it (pass-through).
/// - Otherwise try to look up `en0`'s index via `python3` (no new deps
///   needed — Python ships with macOS).
/// - If that fails, return `None`; tests that need multicast will skip.
fn resolve_multicast_if() -> Option<u32> {
    // If the caller pre-set the variable, honor it.
    if let Ok(val) = std::env::var("MATTER_MULTICAST_IF") {
        if let Ok(idx) = val.trim().parse::<u32>() {
            return Some(idx);
        }
    }

    // Shell out to Python3 (macOS / Linux standard library). Try the
    // platform-typical primary interfaces in order: en0 (macOS), then
    // eth0 / ens5 (Linux runners). Exits non-zero (StopIteration) when none
    // exist, which maps to `None` below.
    let out = Command::new("python3")
        .args([
            "-c",
            "import socket; m = {n: i for i, n in socket.if_nameindex()}; \
             print(next(m[n] for n in ('en0', 'eth0', 'ens5') if n in m))",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !out.status.success() {
        return None;
    }

    let s = String::from_utf8(out.stdout).ok()?;
    s.trim().parse::<u32>().ok()
}

// ---------------------------------------------------------------------------
// Run the tests
// ---------------------------------------------------------------------------

/// Parse the device's setup QR (`MT:...`) from a line like
/// `CHIP:SVR: SetupQRCode: [MT:....]` in the app log.
fn parse_setup_qr(log_path: &Path) -> Result<String, String> {
    let log = fs::read_to_string(log_path)
        .map_err(|e| format!("reading app log for SetupQRCode: {e}"))?;
    for line in log.lines() {
        if let Some(idx) = line.find("SetupQRCode: [") {
            let rest = &line[idx + "SetupQRCode: [".len()..];
            if let Some(end) = rest.find(']') {
                let qr = rest[..end].trim().to_string();
                if qr.starts_with("MT:") {
                    eprintln!("integration: parsed SetupQRCode {qr}");
                    return Ok(qr);
                }
            }
        }
    }
    Err("SetupQRCode: [MT:...] not found in app log".to_string())
}

/// Run `cargo test -p integration-tests` with the necessary env vars.
fn run_tests(
    chip_root: &Path,
    dut_dir: &Path,
    multicast_if: Option<u32>,
    spec: &AppSpec,
    setup_qr: &str,
    ota_image: Option<&Path>,
) -> Result<ExitStatus, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    let mut cmd = Command::new(cargo);
    cmd.args(["test", "-p", "integration-tests"]);
    // Minimal DUTs run only their own test binary (so they don't execute the
    // all-clusters cluster tests against an app that lacks those clusters).
    if let Some(test) = spec.test_filter {
        cmd.args(["--test", test]);
    }
    cmd.args(["--", "--nocapture", "--test-threads=1"]);

    cmd.env("MATTER_INTEGRATION_DUT", setup_qr);
    cmd.env("MATTER_INTEGRATION_DUT_APP", spec.name);
    cmd.env("CHIP_ROOT", chip_root);
    // Absolute DUT-state dir so the fixture's store/sidecar paths don't depend on
    // cargo's per-package test cwd.
    cmd.env("MATTER_INTEGRATION_DUT_DIR", dut_dir);

    if let Some(img) = ota_image {
        cmd.env("MATTER_INTEGRATION_OTA_IMAGE", img);
        eprintln!(
            "integration: MATTER_INTEGRATION_OTA_IMAGE={}",
            img.display()
        );
    }

    if let Some(idx) = multicast_if {
        cmd.env("MATTER_MULTICAST_IF", idx.to_string());
        eprintln!("integration: MATTER_MULTICAST_IF={idx}");
    } else {
        eprintln!("integration: MATTER_MULTICAST_IF not resolved — multicast tests will skip");
    }

    // Inherit stdio so test output appears directly in the terminal.
    let status = cmd
        .status()
        .map_err(|e| format!("failed to spawn cargo test: {e}"))?;
    Ok(status)
}
