//! The async `commission()` orchestrator (M6.6.4): drive the sans-IO
//! `Commissioner` cursor over the M6.6.2/M6.6.3 driver, end to end.

use std::net::SocketAddr;

use matter_transport::{Discovery, ServiceKind, SessionManager};

use crate::driver::datagram::AsyncDatagram;
use crate::driver::error::DriverError;
use crate::CommissionedFabric;
use crate::CommissionerConfig;

/// How many times to poll discovery before giving up, and the gap between
/// polls (~5 s total) — bounded so the driver doesn't hang forever.
///
/// Mirrors the constants in `case.rs` (`RESOLVE_POLL_ATTEMPTS` /
/// `RESOLVE_POLL_INTERVAL`).
const RESOLVE_POLL_ATTEMPTS: usize = 50;
const RESOLVE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Inputs for one commissioning run. Borrows the commissioner config pieces
/// (fabric, trust stores, setup payload) for the run's duration.
pub struct DriverConfig<'a> {
    /// The sans-IO commissioner configuration (fabric, trust stores, node ids,
    /// wifi creds, rng, etc.). Built by the caller (M6.6.5 example / M8).
    pub commissioner: CommissionerConfig<'a>,
    /// Already-resolved commissionable device address (loopback/tests supply
    /// this directly; M6.6.5 fills it from `resolve_commissionable`). When
    /// `None`, `commission()` discovers it via mDNS using the setup payload's
    /// discriminator.
    pub commissionable_addr: Option<SocketAddr>,
    /// Device passcode (from the setup payload).
    pub passcode: u32,
}

/// Browse `_matterc._udp` commissionable records and return the socket address
/// of the first device whose `D` TXT record matches `discriminator`.
///
/// The long (12-bit) discriminator is advertised as a decimal string in the
/// `D` TXT key (Matter Core Spec §5.4.7.4). This function queries for
/// commissionable services and returns the first that advertises the matching
/// discriminator, with a bounded poll loop identical in structure to
/// `resolve_operational` in `case.rs`.
///
/// FLAGGED: takes the first advertised address from `addresses[0]`. Link-local
/// `fe80::` addresses need an interface scope-id that [`matter_transport::MatterService`]
/// does not carry — dialing those is deferred to M6.6.5.
///
/// # Errors
///
/// - [`DriverError::Transport`] if the discovery query fails.
/// - [`DriverError::Discovery`] if no matching record with an address appears
///   within the poll budget.
pub async fn resolve_commissionable<D: Discovery>(
    discovery: &mut D,
    discriminator: u16,
) -> Result<SocketAddr, DriverError> {
    let handle = discovery
        .query(ServiceKind::Commissionable)
        .map_err(DriverError::Transport)?;

    for _ in 0..RESOLVE_POLL_ATTEMPTS {
        for svc in discovery.poll_results(handle) {
            if let Some(d_str) = svc.txt_records.get("D") {
                if d_str.parse::<u16>().ok() == Some(discriminator) {
                    if let Some(addr) = svc.addresses.first() {
                        discovery.stop_query(handle);
                        return Ok(SocketAddr::new(*addr, svc.port));
                    }
                }
            }
        }
        tokio::time::sleep(RESOLVE_POLL_INTERVAL).await;
    }
    discovery.stop_query(handle);
    Err(DriverError::Discovery(format!(
        "commissionable device with discriminator {discriminator} not found via mDNS"
    )))
}

/// Commission a device end to end, returning the resulting [`CommissionedFabric`].
///
/// # Errors
///
/// Any [`DriverError`] from discovery, PASE, the command loop, CASE, or a
/// commissioning-state-machine `Abort`.
pub async fn commission<T, D>(
    _transport: &T,
    _discovery: &mut D,
    _config: DriverConfig<'_>,
) -> Result<CommissionedFabric, DriverError>
where
    T: AsyncDatagram,
    D: matter_transport::Discovery,
{
    // Filled in across Tasks 2-6.
    let _ = SessionManager::new();
    Err(DriverError::Discovery(
        "commission() not yet implemented".into(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use matter_transport::{MatterService, QueryHandle};

    struct FakeDiscovery {
        service: MatterService,
    }

    impl Discovery for FakeDiscovery {
        fn publish(&mut self, _s: &MatterService) -> matter_transport::Result<()> {
            Ok(())
        }
        fn unpublish(&mut self, _n: &str, _k: ServiceKind) -> matter_transport::Result<()> {
            Ok(())
        }
        fn query(&mut self, _k: ServiceKind) -> matter_transport::Result<QueryHandle> {
            Ok(QueryHandle(1))
        }
        fn stop_query(&mut self, _h: QueryHandle) {}
        fn poll_results(&mut self, _h: QueryHandle) -> Vec<MatterService> {
            vec![self.service.clone()]
        }
    }

    #[tokio::test]
    async fn resolve_commissionable_matches_discriminator() {
        const DISCRIMINATOR: u16 = 0xF00;
        let mut txt = HashMap::new();
        txt.insert("D".to_string(), DISCRIMINATOR.to_string());
        let mut disc = FakeDiscovery {
            service: MatterService {
                instance_name: "AABBCCDDEEFF1122".to_string(),
                kind: ServiceKind::Commissionable,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))],
                port: 5540,
                txt_records: txt,
            },
        };
        let addr = resolve_commissionable(&mut disc, DISCRIMINATOR)
            .await
            .unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)), 5540)
        );
    }
}
