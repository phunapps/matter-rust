//! `commission_ip` — operator binary that commissions an IP-reachable Matter
//! device end to end using the M6.6 [`commission`] orchestrator.
//!
//! Full walkthrough: `docs/runbooks/m6.6-first-commission.md`.
//!
//! Built behind the `driver` feature:
//! ```text
//! cargo run --example commission_ip --features driver -- --help
//! ```
//! For per-step tracing spans, also enable `tracing`:
//! ```text
//! cargo run --example commission_ip --features driver,tracing -- --manual <code> -vv
//! ```

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use clap::Parser;

use matter_cert::MatterTime;
use matter_commissioning::attestation::{CdSigningRoots, Paa, PaaTrustStore};
use matter_commissioning::driver::{commission, DriverConfig};
use matter_commissioning::noc::{FabricRecord, NocRng, SystemNocRng};
use matter_commissioning::setup::{parse_manual_code, parse_qr, SetupPayload};
use matter_commissioning::state_machine::{CommissionedFabric, CommissionerConfig};
use matter_crypto::{derive_compressed_fabric_id, RingSigner, Signer};
use matter_transport::{MdnsSdDiscovery, TokioUdpTransport};

// Fixed identity for this single commissioning run. A real controller (M8)
// persists these; the example mints a fresh fabric per run.
const FABRIC_ID: u64 = 1;
const RCAC_ID: u64 = 1;
const COMMISSIONER_NODE_ID: u64 = 0x1234_5678_9ABC_DEF0;
const ASSIGNED_NODE_ID: u64 = 0x0000_0000_0000_0002;
const ADMIN_VENDOR_ID: u16 = 0xFFF1; // CSA test VID
const IPK_EPOCH_KEY: [u8; 16] = [0x42; 16];

/// Commission an IP-reachable Matter device that is in commissioning mode.
#[derive(Debug, Parser)]
#[command(name = "commission_ip", about, long_about = None)]
struct Cli {
    /// Setup payload from a QR code (e.g. "MT:..."). Mutually exclusive with --manual.
    #[arg(long, conflicts_with = "manual")]
    qr: Option<String>,

    /// Setup payload from an 11- or 21-digit manual pairing code.
    #[arg(long)]
    manual: Option<String>,

    /// Dial this address directly (e.g. "`[fd11::2]:5540`"), skipping the mDNS browse.
    #[arg(long)]
    addr: Option<String>,

    /// Directory of PRODUCTION PAA root certs (loads every *.der file).
    /// When set, the bundled CSA test PAA roots are not used.
    #[arg(long)]
    paa_dir: Option<PathBuf>,

    /// PRODUCTION CD signing cert (PEM). When set, the bundled CSA test CD roots
    /// are not used.
    #[arg(long)]
    cd_root: Option<PathBuf>,

    /// Write the resulting fabric summary to this path as JSON.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Increase log verbosity (-v = info spans, -vv = debug).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// The attestation trust anchors the commissioner validates against.
struct TrustRoots {
    paa: PaaTrustStore,
    cd: CdSigningRoots,
    /// True when ANY bundled CSA *test* root is in use (drives the banner).
    using_test_roots: bool,
}

/// Build PAA + CD trust roots from the CLI. Defaults to the bundled CSA *test*
/// roots; `--paa-dir` / `--cd-root` independently swap in production roots.
fn build_trust_roots(cli: &Cli) -> anyhow::Result<TrustRoots> {
    let mut using_test_roots = false;

    let paa = if let Some(dir) = &cli.paa_dir {
        load_production_paa(dir)
            .with_context(|| format!("loading PAA roots from {}", dir.display()))?
    } else {
        using_test_roots = true;
        PaaTrustStore::with_csa_test_roots()
    };

    let cd = if let Some(path) = &cli.cd_root {
        let pem = fs::read(path)
            .with_context(|| format!("reading CD root {}", path.display()))?;
        CdSigningRoots::from_pem(&[pem.as_slice()]).context("parsing --cd-root PEM")?
    } else {
        using_test_roots = true;
        CdSigningRoots::with_csa_test_roots()
    };

    Ok(TrustRoots { paa, cd, using_test_roots })
}

/// Load every `*.der` file in `dir` into a PAA trust store. The connectedhomeip
/// snapshot (`credentials/production/paa-root-certs/`) ships paired `.der`+`.pem`
/// for each PAA, so loading DER-only avoids double-counting and PEM parsing.
fn load_production_paa(dir: &std::path::Path) -> anyhow::Result<PaaTrustStore> {
    let mut store = PaaTrustStore::empty();
    let mut count = 0_usize;
    for entry in fs::read_dir(dir).with_context(|| format!("reading dir {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("der") {
            continue;
        }
        let der = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let paa = Paa::from_der(&der)
            .with_context(|| format!("parsing PAA {}", path.display()))?;
        store.add(paa);
        count += 1;
    }
    if count == 0 {
        bail!("no *.der PAA certs found in {}", dir.display());
    }
    Ok(store)
}

/// Resolve the setup payload from exactly one of `--qr` / `--manual`.
fn parse_setup_payload(cli: &Cli) -> anyhow::Result<SetupPayload> {
    match (&cli.qr, &cli.manual) {
        (Some(qr), None) => parse_qr(qr).context("parsing --qr setup payload"),
        (None, Some(manual)) => {
            parse_manual_code(manual).context("parsing --manual pairing code")
        }
        (None, None) => bail!("one of --qr or --manual is required"),
        // clap's `conflicts_with` prevents both, but guard anyway.
        (Some(_), Some(_)) => bail!("--qr and --manual are mutually exclusive"),
    }
}

/// Current wall-clock time as `MatterTime`. A binary may read the system clock.
fn current_matter_time() -> anyhow::Result<MatterTime> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    Ok(MatterTime::from_unix_secs(secs))
}

/// Print a human-readable summary of the commissioned fabric.
fn print_summary(fabric: &CommissionedFabric) -> anyhow::Result<()> {
    let compressed = derive_compressed_fabric_id(
        fabric.fabric.root_public_key.as_bytes(),
        fabric.fabric.fabric_id,
    )
    .context("deriving compressed fabric id")?;
    println!("✅ commissioned");
    println!("   fabric_id            = {}", fabric.fabric.fabric_id);
    println!("   compressed_fabric_id = {}", hex::encode(compressed));
    println!("   peer_node_id         = {:#018x}", fabric.peer_node_id);
    println!("   peer_public_key      = {}", hex::encode(fabric.peer_root_public_key));
    println!("   terminated_at        = {:?}", fabric.terminated_at);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let payload = parse_setup_payload(&cli)?;
    println!(
        "setup payload: vid={:?} pid={:?} discriminator={} passcode=<redacted>",
        payload.vendor_id,
        payload.product_id,
        payload.discriminator.as_u16(),
    );
    let roots = build_trust_roots(&cli)?;
    if roots.using_test_roots {
        eprintln!(
            "\u{26A0}  TEST ATTESTATION ROOTS IN USE — this run trusts CSA *test* PAA/CD roots.\n   NOT valid for production trust decisions. Pass --paa-dir and --cd-root for real devices."
        );
    }

    // Self-generate an ephemeral fabric RCAC for this run.
    // FLAG: per-run identity only — M8 owns a stable persistent commissioner identity.
    let (root_signer, _pkcs8) = RingSigner::generate().context("generating fabric root key")?;
    let root_signer: Arc<dyn Signer> = Arc::new(root_signer);
    let now = current_matter_time()?;
    let fabric = FabricRecord::new_root_only(
        FABRIC_ID,
        root_signer,
        now,
        MatterTime::NO_EXPIRY,
        RCAC_ID,
        &SystemNocRng,
    )
    .context("building fabric RCAC")?;

    let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
    let commissioner = CommissionerConfig {
        // commission() overwrites this with the live PASE-derived attestation key.
        pase_attestation_challenge: [0u8; 16],
        fabric: &fabric,
        setup_payload: &payload,
        paa_trust_store: &roots.paa,
        cd_signing_roots: &roots.cd,
        commissioner_node_id: COMMISSIONER_NODE_ID,
        assigned_node_id: ASSIGNED_NODE_ID,
        ipk_epoch_key: IPK_EPOCH_KEY,
        case_admin_subject: COMMISSIONER_NODE_ID,
        admin_vendor_id: ADMIN_VENDOR_ID,
        now,
        rng,
        wifi_credentials: None, // ECM/Ethernet path; see runbook.
    };

    // Optional direct-dial address (skips the mDNS commissionable browse).
    let commissionable_addr = match &cli.addr {
        Some(s) => Some(s.parse::<SocketAddr>().context("parsing --addr")?),
        None => None,
    };

    let config = DriverConfig {
        commissioner,
        commissionable_addr,
        passcode: payload.passcode.as_u32(),
    };

    // Real IO: dual-stack [::]:0 UDP socket + mDNS discovery.
    let transport = TokioUdpTransport::bind(0).await.context("binding UDP socket")?;
    let mut discovery = MdnsSdDiscovery::new().context("starting mDNS discovery")?;

    println!("commissioning… (this performs PASE → attestation → NOC → CASE)");
    let fabric = commission(&transport, &mut discovery, config)
        .await
        .context("commission() failed")?;

    print_summary(&fabric)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // clap's own consistency checker: catches conflicting/duplicate args.
        Cli::command().debug_assert();
    }

    #[test]
    fn qr_and_manual_conflict() {
        let err = Cli::try_parse_from(["commission_ip", "--qr", "MT:X", "--manual", "123"]);
        assert!(err.is_err(), "--qr and --manual must be mutually exclusive");
    }
}
