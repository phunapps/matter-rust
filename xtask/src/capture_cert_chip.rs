//! `xtask capture-cert-chip` — generate Matter operational certificate
//! fixtures from `project-chip/connectedhomeip`'s `chip-cert` tool, as the
//! second (CSA-canonical C++) reference alongside the matter.js set in
//! `test-vectors/certs/`.
//!
//! matter.js is an excellent reference but has diverged from the C++
//! implementation before; `matter-cert`'s byte-parity gate should hold
//! against BOTH (TODO-1.0 "Cross-verification against
//! project-chip/connectedhomeip").
//!
//! ## Output layout
//!
//! ```text
//! test-vectors/certs/connectedhomeip/
//!   manifest.toml      same schema as ../manifest.toml
//!   rcac.bin           RCAC as raw CHIP TLV (chip-cert convert-cert -c)
//!   rcac.tbs.bin       TBSCertificate DER slice of chip-cert's X.509 output
//!   icac.bin / icac.tbs.bin
//!   noc.bin  / noc.tbs.bin
//!   README.md
//! ```
//!
//! The `.tbs.bin` files are the exact bytes chip-cert's CA signed (the
//! TBSCertificate element of its X.509 DER), so
//! `MatterCertificate::to_x509_tbs_der()` matching them byte-for-byte is the
//! same strict gate the matter.js `asUnsignedDer()` fixtures provide.
//!
//! ## Prerequisite
//!
//! A built `chip-cert` binary. Default location:
//! `~/code/connectedhomeip/out/darwin-arm64-chip-cert/chip-cert`
//! (build with `./scripts/build/build_examples.py --target
//! <host>-chip-cert build` inside an activated connectedhomeip checkout);
//! override with `MATTER_CHIP_CERT=/path/to/chip-cert`.
//!
//! Keys are generated fresh on every capture (same policy as the matter.js
//! set): the parity tests exercise whatever bytes are committed, not a fixed
//! expected sequence.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Validity for every generated certificate: 2023-01-01 + 20 years. Fixed so
/// recaptures differ only in key material.
const VALID_FROM: &str = "2023-01-01";
const LIFETIME_DAYS: &str = "7305";

/// Subject ids for the 3-tier chain (arbitrary but stable values; the NOC's
/// node id sits in the operational range and the fabric id is non-zero as
/// chip-cert requires).
const RCAC_ID: &str = "CACACACA00000001";
const ICAC_ID: &str = "CACACACA00000002";
const NOC_NODE_ID: &str = "DEDEDEDE00010001";
const FABRIC_ID: &str = "000000000000001D";

/// Entry point for `cargo xtask capture-cert-chip`.
pub(crate) fn run() -> Result<(), String> {
    let chip_cert = locate_chip_cert()?;
    let root = workspace_root()?;
    let out_dir = root.join("test-vectors/certs/connectedhomeip");
    let work = out_dir.join(".capture-work");
    // chip-cert refuses to overwrite existing outputs — clear previous
    // fixtures (a capture replaces the whole set) and any stale work dir.
    if work.exists() {
        std::fs::remove_dir_all(&work).map_err(|e| format!("clear {}: {e}", work.display()))?;
    }
    for id in ["rcac", "icac", "noc"] {
        for suffix in [".bin", ".tbs.bin"] {
            let stale = out_dir.join(format!("{id}{suffix}"));
            if stale.exists() {
                std::fs::remove_file(&stale)
                    .map_err(|e| format!("clear {}: {e}", stale.display()))?;
            }
        }
    }
    std::fs::create_dir_all(&work).map_err(|e| format!("create {}: {e}", work.display()))?;

    // 1. Generate the 3-tier chain as X.509 PEM (chip-cert signs the X.509
    //    TBS, so the PEM is the source of truth for both formats).
    let rcac_pem = work.join("rcac.pem");
    let rcac_key = work.join("rcac-key.pem");
    run_chip_cert(
        &chip_cert,
        &[
            "gen-cert",
            "-t",
            "r",
            "-i",
            RCAC_ID,
            "-o",
            path_str(&rcac_pem)?,
            "-O",
            path_str(&rcac_key)?,
            "-F",
            "x509-pem",
            "-V",
            VALID_FROM,
            "-l",
            LIFETIME_DAYS,
        ],
    )?;

    let icac_pem = work.join("icac.pem");
    let icac_key = work.join("icac-key.pem");
    run_chip_cert(
        &chip_cert,
        &[
            "gen-cert",
            "-t",
            "c",
            "-i",
            ICAC_ID,
            "-f",
            FABRIC_ID,
            "-C",
            path_str(&rcac_pem)?,
            "-K",
            path_str(&rcac_key)?,
            "-o",
            path_str(&icac_pem)?,
            "-O",
            path_str(&icac_key)?,
            "-F",
            "x509-pem",
            "-V",
            VALID_FROM,
            "-l",
            LIFETIME_DAYS,
        ],
    )?;

    let noc_pem = work.join("noc.pem");
    let noc_key = work.join("noc-key.pem");
    run_chip_cert(
        &chip_cert,
        &[
            "gen-cert",
            "-t",
            "n",
            "-i",
            NOC_NODE_ID,
            "-f",
            FABRIC_ID,
            "-C",
            path_str(&icac_pem)?,
            "-K",
            path_str(&icac_key)?,
            "-o",
            path_str(&noc_pem)?,
            "-O",
            path_str(&noc_key)?,
            "-F",
            "x509-pem",
            "-V",
            VALID_FROM,
            "-l",
            LIFETIME_DAYS,
        ],
    )?;

    // 2. Convert each to raw CHIP TLV (`<id>.bin`) and extract the X.509
    //    TBSCertificate slice (`<id>.tbs.bin`).
    for (id, pem) in [("rcac", &rcac_pem), ("icac", &icac_pem), ("noc", &noc_pem)] {
        let chip_bin = out_dir.join(format!("{id}.bin"));
        run_chip_cert(
            &chip_cert,
            &["convert-cert", "-c", path_str(pem)?, path_str(&chip_bin)?],
        )?;

        let der = work.join(format!("{id}.der"));
        run_chip_cert(
            &chip_cert,
            &["convert-cert", "-d", path_str(pem)?, path_str(&der)?],
        )?;
        let der_bytes = std::fs::read(&der).map_err(|e| format!("read {}: {e}", der.display()))?;
        let tbs = extract_tbs(&der_bytes).map_err(|e| format!("extract TBS from {id}.der: {e}"))?;
        let tbs_path = out_dir.join(format!("{id}.tbs.bin"));
        std::fs::write(&tbs_path, tbs).map_err(|e| format!("write {}: {e}", tbs_path.display()))?;
    }

    // 3. Validate the chain with chip-cert itself, so a broken capture never
    //    lands as a fixture.
    run_chip_cert(
        &chip_cert,
        &[
            "validate-cert",
            "-c",
            path_str(&icac_pem)?,
            "-t",
            path_str(&rcac_pem)?,
            path_str(&noc_pem)?,
        ],
    )?;

    // 4. Manifest (same schema as ../manifest.toml) + README.
    std::fs::write(out_dir.join("manifest.toml"), manifest_toml())
        .map_err(|e| format!("write manifest.toml: {e}"))?;
    std::fs::write(out_dir.join("README.md"), readme_md())
        .map_err(|e| format!("write README.md: {e}"))?;

    // 5. Drop the working PEMs/keys — only TLV + TBS fixtures are committed
    //    (same policy as the matter.js set: no private keys in the repo).
    std::fs::remove_dir_all(&work).map_err(|e| format!("cleanup {}: {e}", work.display()))?;

    println!(
        "capture-cert-chip: wrote rcac/icac/noc .bin + .tbs.bin to {}",
        out_dir.display()
    );
    Ok(())
}

fn manifest_toml() -> String {
    format!(
        r#"# Generated by `cargo xtask capture-cert-chip` — see README.md.

[[certificate]]
id = "rcac"
description = "Root CA certificate (self-signed), chip-cert gen-cert -t r"
source = "connectedhomeip chip-cert (subject id {RCAC_ID})"
file = "rcac.bin"
kind = "rcac"
tbs_file = "rcac.tbs.bin"
is_self_signed = true

[[certificate]]
id = "icac"
description = "Intermediate CA certificate (signed by RCAC), chip-cert gen-cert -t c"
source = "connectedhomeip chip-cert (subject id {ICAC_ID}, fabric {FABRIC_ID})"
file = "icac.bin"
kind = "icac"
tbs_file = "icac.tbs.bin"
signed_by_id = "rcac"

[[certificate]]
id = "noc"
description = "Node Operational Certificate (signed by ICAC), chip-cert gen-cert -t n"
source = "connectedhomeip chip-cert (node id {NOC_NODE_ID}, fabric {FABRIC_ID})"
file = "noc.bin"
kind = "noc"
tbs_file = "noc.tbs.bin"
signed_by_id = "icac"
"#
    )
}

fn readme_md() -> String {
    "# connectedhomeip certificate test vectors\n\
     \n\
     Second reference set for `matter-cert`'s byte-parity gate, generated by\n\
     the CSA C++ implementation's `chip-cert` tool (the matter.js set lives\n\
     one directory up). Regenerate with `cargo xtask capture-cert-chip`\n\
     (requires a built chip-cert; see the rustdoc in\n\
     `xtask/src/capture_cert_chip.rs`).\n\
     \n\
     `<id>.bin` is the raw CHIP TLV certificate; `<id>.tbs.bin` is the\n\
     TBSCertificate slice of chip-cert's X.509 DER output — the exact bytes\n\
     the CA signed, which `MatterCertificate::to_x509_tbs_der()` must\n\
     reproduce byte-for-byte.\n\
     \n\
     Keys are generated fresh per capture and are NOT committed; the tests\n\
     exercise whatever bytes are committed here.\n"
        .to_string()
}

/// Extract the `TBSCertificate` element (header + content) from a DER
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
/// signature }`.
fn extract_tbs(der: &[u8]) -> Result<Vec<u8>, String> {
    let (outer_content, _) = der_element(der)?;
    let (_, tbs_total_len) = der_element(outer_content)?;
    Ok(outer_content
        .get(..tbs_total_len)
        .ok_or("TBS length exceeds outer content")?
        .to_vec())
}

/// Parse one DER element at the start of `buf`; return its content slice and
/// the total length of the element (header + content).
fn der_element(buf: &[u8]) -> Result<(&[u8], usize), String> {
    if buf.len() < 2 {
        return Err("DER element shorter than 2 bytes".into());
    }
    let first_len_byte = buf[1];
    let (content_len, header_len) = if first_len_byte & 0x80 == 0 {
        (usize::from(first_len_byte), 2)
    } else {
        let n = usize::from(first_len_byte & 0x7F);
        if n == 0 || n > 4 {
            return Err(format!("unsupported DER length-of-length {n}"));
        }
        let bytes = buf.get(2..2 + n).ok_or("truncated DER long-form length")?;
        let mut len = 0usize;
        for &b in bytes {
            len = (len << 8) | usize::from(b);
        }
        (len, 2 + n)
    };
    let content = buf
        .get(header_len..header_len + content_len)
        .ok_or("DER content exceeds buffer")?;
    Ok((content, header_len + content_len))
}

fn run_chip_cert(chip_cert: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new(chip_cert)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {}: {e}", chip_cert.display()))?;
    if !output.status.success() {
        return Err(format!(
            "chip-cert {} failed ({}):\n{}",
            args.first().unwrap_or(&""),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// Locate the chip-cert binary: `MATTER_CHIP_CERT` env override, else the
/// conventional connectedhomeip checkout location.
fn locate_chip_cert() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("MATTER_CHIP_CERT") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!("MATTER_CHIP_CERT={} is not a file", p.display()));
    }
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    let conventional =
        PathBuf::from(home).join("code/connectedhomeip/out/darwin-arm64-chip-cert/chip-cert");
    if conventional.is_file() {
        return Ok(conventional);
    }
    Err(format!(
        "chip-cert not found at {} — build it with \
         `./scripts/build/build_examples.py --target darwin-arm64-chip-cert build` \
         in an activated connectedhomeip checkout, or set MATTER_CHIP_CERT",
        conventional.display()
    ))
}

fn path_str(p: &Path) -> Result<&str, String> {
    p.to_str()
        .ok_or_else(|| format!("non-UTF-8 path: {}", p.display()))
}

// Reuse main.rs's workspace-root convention (CARGO_MANIFEST_DIR = xtask/).
fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| "CARGO_MANIFEST_DIR not set; run via `cargo xtask`".to_string())?;
    PathBuf::from(manifest_dir)
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| "could not derive workspace root from CARGO_MANIFEST_DIR".to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    /// `extract_tbs` slices the first child of the outer SEQUENCE, header
    /// included, for both short- and long-form lengths.
    #[test]
    fn extract_tbs_slices_first_child() {
        // Outer SEQUENCE { inner SEQUENCE {0x01 0x02}, NULL }.
        let der = [0x30, 0x06, 0x30, 0x02, 0x01, 0x02, 0x05, 0x00];
        assert_eq!(extract_tbs(&der).unwrap(), vec![0x30, 0x02, 0x01, 0x02]);

        // Long-form outer length (0x81).
        let mut long = vec![0x30, 0x81, 0x06];
        long.extend_from_slice(&[0x30, 0x02, 0x01, 0x02, 0x05, 0x00]);
        assert_eq!(extract_tbs(&long).unwrap(), vec![0x30, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn extract_tbs_rejects_truncated_input() {
        assert!(extract_tbs(&[0x30]).is_err());
        // Outer claims 6 bytes of content but only 2 follow.
        assert!(extract_tbs(&[0x30, 0x06, 0x30, 0x02]).is_err());
    }
}
