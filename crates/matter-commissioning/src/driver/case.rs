//! CASE bridge (M6.6.3b): operational discovery + (later) drive the sans-IO
//! `CaseInitiator` over the unsecured datagram path.
//!
//! CASE Sigma1/2/3 are exchanged UNSECURED (session-id 0, `SecureChannel`
//! protocol) — the operational secured session only exists once the handshake
//! derives keys.

use std::net::SocketAddr;

use matter_transport::{Discovery, ServiceKind};

use crate::driver::error::DriverError;

/// Build the operational mDNS instance name `<compressed-fabric-id>-<node-id>`,
/// each as fixed-width uppercase hex (16 + 1 + 16 chars), per the Matter
/// operational-discovery instance-name convention.
///
/// FLAGGED: confirm exact casing/width/separator against matter.js byte parity
/// before the first real-device CASE (M6.6.5); this matches the connectedhomeip
/// convention and the in-tree examples.
#[must_use]
pub fn operational_instance_name(compressed_fabric_id: [u8; 8], node_id: u64) -> String {
    let cfid = u64::from_be_bytes(compressed_fabric_id);
    format!("{cfid:016X}-{node_id:016X}")
}

/// How many times to poll discovery before giving up, and the gap between
/// polls (~5 s total) — bounded so the driver doesn't hang forever.
const RESOLVE_POLL_ATTEMPTS: usize = 50;
const RESOLVE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Browse `_matter._tcp` operational records and return the socket address of
/// the node whose instance name matches `(compressed_fabric_id, node_id)`.
///
/// FLAGGED: takes the first advertised address. Link-local `fe80::` operational
/// addresses need an interface scope id that [`MatterService`](matter_transport::MatterService)
/// does not carry — dialing those is deferred to M6.6.5.
///
/// # Errors
///
/// - [`DriverError::Transport`] if the discovery query fails.
/// - [`DriverError::Discovery`] if no matching record with an address appears
///   within the poll budget.
pub async fn resolve_operational<D: Discovery>(
    discovery: &mut D,
    compressed_fabric_id: [u8; 8],
    node_id: u64,
) -> Result<SocketAddr, DriverError> {
    let target = operational_instance_name(compressed_fabric_id, node_id);
    let handle = discovery
        .query(ServiceKind::Operational)
        .map_err(DriverError::Transport)?;

    for _ in 0..RESOLVE_POLL_ATTEMPTS {
        for svc in discovery.poll_results(handle) {
            if svc.instance_name.eq_ignore_ascii_case(&target) {
                if let Some(addr) = svc.addresses.first() {
                    discovery.stop_query(handle);
                    return Ok(SocketAddr::new(*addr, svc.port));
                }
            }
        }
        tokio::time::sleep(RESOLVE_POLL_INTERVAL).await;
    }
    discovery.stop_query(handle);
    Err(DriverError::Discovery(format!(
        "operational node {target} not found via mDNS"
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    #[test]
    fn operational_instance_name_formats_16_16_uppercase_hex() {
        let cfid = [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30];
        let node_id: u64 = 0x0000_0000_0000_0001;
        assert_eq!(operational_instance_name(cfid, node_id), "87E1B004E235A130-0000000000000001");
    }

    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use matter_transport::{MatterService, QueryHandle};

    struct FakeDiscovery {
        service: MatterService,
    }

    impl Discovery for FakeDiscovery {
        fn publish(&mut self, _s: &MatterService) -> matter_transport::Result<()> { Ok(()) }
        fn unpublish(&mut self, _n: &str, _k: ServiceKind) -> matter_transport::Result<()> { Ok(()) }
        fn query(&mut self, _k: ServiceKind) -> matter_transport::Result<QueryHandle> { Ok(QueryHandle(1)) }
        fn stop_query(&mut self, _h: QueryHandle) {}
        fn poll_results(&mut self, _h: QueryHandle) -> Vec<MatterService> { vec![self.service.clone()] }
    }

    #[tokio::test]
    async fn resolve_operational_returns_matching_addr() {
        let cfid = [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30];
        let node_id: u64 = 1;
        let name = operational_instance_name(cfid, node_id);
        let mut disc = FakeDiscovery {
            service: MatterService {
                instance_name: name,
                kind: ServiceKind::Operational,
                addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))],
                port: 5540,
                txt_records: HashMap::new(),
            },
        };
        let addr = resolve_operational(&mut disc, cfid, node_id).await.unwrap();
        assert_eq!(addr, std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 5540));
    }
}
