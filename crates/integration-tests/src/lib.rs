//! Local/nightly integration harness driving connectedhomeip's all-clusters-app.
//! Tests early-return ("skipped") unless `MATTER_INTEGRATION_DUT` is set (by
//! `xtask integration`), so the normal `cargo test` / gate compiles + skips them.
use std::path::PathBuf;

/// Device-under-test configuration and helpers.
pub mod dut {
    use super::PathBuf;

    /// Configuration for a live device-under-test, sourced from env by
    /// `xtask integration`. `None` => no DUT available => tests skip.
    #[derive(Clone, Debug)]
    pub struct DutConfig {
        /// QR/manual setup code to commission the DUT.
        pub setup_code: String,
        /// connectedhomeip checkout root (for dev-cert attestation dirs).
        pub chip_root: PathBuf,
        /// Multicast egress interface index for group-cast (`MATTER_MULTICAST_IF`).
        pub multicast_if: Option<u32>,
    }

    impl DutConfig {
        /// Read DUT config from env; `None` if `MATTER_INTEGRATION_DUT` is unset.
        #[must_use]
        pub fn from_env() -> Option<DutConfig> {
            let setup_code = std::env::var("MATTER_INTEGRATION_DUT").ok()?;
            let chip_root = std::env::var("CHIP_ROOT")
                .unwrap_or_else(|_| "/Users/hemanshubhojak/code/connectedhomeip".into())
                .into();
            let multicast_if = std::env::var("MATTER_MULTICAST_IF")
                .ok()
                .and_then(|s| s.parse().ok());
            Some(DutConfig {
                setup_code,
                chip_root,
                multicast_if,
            })
        }

        /// Development PAA root certs dir.
        #[must_use]
        pub fn paa_dir(&self) -> PathBuf {
            self.chip_root
                .join("credentials/development/paa-root-certs")
        }

        /// Development CD signing certs dir.
        #[must_use]
        pub fn cd_dir(&self) -> PathBuf {
            self.chip_root.join("credentials/development/cd-certs")
        }
    }
}

/// Skip-guard: returns from a `#[tokio::test]` early (logging) when no DUT.
#[macro_export]
macro_rules! dut_or_skip {
    () => {{
        match $crate::dut::DutConfig::from_env() {
            Some(c) => c,
            None => {
                eprintln!("skipped: no DUT (set MATTER_INTEGRATION_DUT via `just integration`)");
                return;
            }
        }
    }};
}
