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
use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::Parser;

use matter_commissioning::attestation::{CdSigningRoots, Paa, PaaTrustStore};
use matter_commissioning::setup::{parse_manual_code, parse_qr, SetupPayload};

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
// Fields `paa` and `cd` are consumed by the commission() call added in Task 4.
#[allow(dead_code)]
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

fn main() -> anyhow::Result<()> {
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
