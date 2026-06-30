//! The OTA **provider server** (M9-F3): a dedicated task that advertises our
//! operational service, accepts an inbound CASE session as the responder, and
//! dispatches one server-side `InvokeRequest`. Productionizes the responder
//! accept-flow proven in the actor's loopback tests; hosts it in
//! `matter-controller` so it can reuse the persisted operational identity
//! (`crate::credentials::operational_credentials`) and the existing session /
//! transport / discovery machinery without a new crate boundary.

use std::net::IpAddr;

use matter_transport::{MatterService, ServiceKind};

/// Build the operational `_matter._tcp` mDNS record to advertise so a requestor
/// can resolve us. Instance name is `<compressed-fabric-id>-<node-id>` in
/// uppercase hex (Matter Core §4.3.1), matching what the controller's initiator
/// resolves against via `operational_instance_name`.
#[must_use]
pub fn build_operational_service(
    compressed_fabric_id: [u8; 8],
    node_id: u64,
    addresses: Vec<IpAddr>,
    port: u16,
) -> MatterService {
    let instance_name =
        matter_commissioning::driver::operational_instance_name(compressed_fabric_id, node_id);
    // Operational TXT params (SII/SAI/SAT) are optional hints; F3 advertises
    // none (the requestor resolves us by SRV + A/AAAA). F4/hardening can add
    // session-interval hints if a requestor needs them.
    MatterService::new(
        instance_name,
        ServiceKind::Operational,
        addresses,
        port,
        std::collections::HashMap::new(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md carve-out.
    use super::*;
    use matter_transport::ServiceKind;
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn operational_service_has_expected_name_kind_and_port() {
        let compressed = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let node_id = 0x0000_0000_0000_0001;
        let addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let svc = build_operational_service(compressed, node_id, vec![addr], 5540);

        assert_eq!(svc.kind, ServiceKind::Operational);
        assert_eq!(svc.port, 5540);
        // <16-hex compressed>-<16-hex node>, uppercase.
        assert_eq!(svc.instance_name, "DEADBEEFCAFEBABE-0000000000000001");
        assert_eq!(svc.addresses, vec![addr]);
    }
}
