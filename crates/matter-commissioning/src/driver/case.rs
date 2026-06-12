//! CASE bridge (M6.6.3b): operational discovery + drive the sans-IO
//! `CaseInitiator` over the unsecured datagram path.
//!
//! CASE Sigma1/2/3 are exchanged UNSECURED (session-id 0, `SecureChannel`
//! protocol) — the operational secured session only exists once the handshake
//! derives keys.

use std::net::SocketAddr;

use matter_cert::{MatterTime, TrustedRoots};
use matter_crypto::{CaseCredentials, CaseInitiator};
use matter_transport::{Discovery, ServiceKind, SessionId, SessionManager, SessionRole};

use crate::driver::datagram::AsyncDatagram;
use crate::driver::error::DriverError;
use crate::driver::unsecured::{parse_status_report, require_handshake_opcode, UnsecuredExchange};

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
/// polls (~30 s total) — bounded so the driver doesn't hang forever. The
/// operational record only appears after `AddNOC`, so mDNS propagation can
/// take several seconds on a real LAN (observed during M6.6.5 validation);
/// chip's session-establishment discovery budget is of the same order.
const RESOLVE_POLL_ATTEMPTS: usize = 300;
const RESOLVE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Pick the most routable address from an mDNS record: IPv4 first, then any
/// non-link-local IPv6, then whatever is left. A `fe80::` IPv6 needs an
/// interface scope id that [`MatterService`](matter_transport::MatterService)
/// does not carry, so a dial-out socket cannot route to it — devices often
/// list it FIRST, ahead of perfectly routable addresses (M6.6.5: closes the
/// previously FLAGGED `.first()` pick). Shared with `resolve_commissionable`.
pub(crate) fn preferred_address(addresses: &[std::net::IpAddr]) -> Option<std::net::IpAddr> {
    let is_v6_link_local = |a: &std::net::IpAddr| match a {
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        std::net::IpAddr::V4(_) => false,
    };
    addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addresses.iter().find(|a| !is_v6_link_local(a)))
        .or_else(|| addresses.first())
        .copied()
}

/// Browse `_matter._tcp` operational records and return the socket address of
/// the node whose instance name matches `(compressed_fabric_id, node_id)`.
///
/// The advertised address list is filtered for routability
/// (IPv4 → non-link-local IPv6 → fallback) — see `preferred_address`.
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
                if let Some(addr) = preferred_address(&svc.addresses) {
                    discovery.stop_query(handle);
                    return Ok(SocketAddr::new(addr, svc.port));
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

// SecureChannel opcodes for the CASE handshake (Matter Core Spec §4.14.1).
const OP_SIGMA1: u8 = 0x30;
const OP_SIGMA2: u8 = 0x31;
const OP_SIGMA3: u8 = 0x32;

const CASE_EXCHANGE_ID: u16 = 1;

/// Drive a fresh CASE (SIGMA-I) handshake against an already-resolved
/// operational `peer` and register the resulting operational session, returning
/// its local [`SessionId`]. `credentials` is this controller's operational
/// identity; `peer_node_id`/`peer_fabric_id` identify the device. Resumption is
/// not used (a fresh handshake every time); that is M8.
///
/// `now` is the wall-clock instant against which the device's operational
/// certificate chain is checked for temporal validity during Sigma2. The caller
/// (controller layer) supplies the real time; this crate never reads the system
/// clock.
///
/// # Errors
///
/// - [`DriverError::Crypto`] if a SIGMA step fails (peer chain/signature
///   invalid, key mismatch, etc.).
/// - [`DriverError::Io`] / [`DriverError::Transport`] / [`DriverError::Timeout`]
///   on datagram, framing, or reply-timeout failure.
// 8 params: the CASE setup (transport, sessions, peer, credentials, roots,
// node/fabric ids) plus the injected validation clock; bundling them would
// obscure the call site.
#[allow(clippy::too_many_arguments)]
pub async fn run_case<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    peer: SocketAddr,
    credentials: CaseCredentials,
    trusted_roots: TrustedRoots,
    peer_node_id: u64,
    peer_fabric_id: u64,
    now: MatterTime,
) -> Result<SessionId, DriverError> {
    let local = sessions.allocate_session_id();
    let mut initiator = CaseInitiator::new(
        credentials,
        trusted_roots,
        peer_node_id,
        peer_fabric_id,
        local.0,
        now,
    )?;
    // CSPRNG-seeded counter + ephemeral source node id (spec §4.5.1.1,
    // §4.13.2.1) — same unsecured-header requirements as PASE apply to SIGMA.
    let mut exch = UnsecuredExchange::new_ephemeral(CASE_EXCHANGE_ID)?;

    let sigma1 = initiator.start()?;
    let sigma2 = exch
        .send_and_recv(transport, peer, OP_SIGMA1, &sigma1, None)
        .await?;
    if let Err(e) = require_handshake_opcode(&sigma2, OP_SIGMA2) {
        // Best-effort ack so a rejecting device stops retransmitting its
        // (reliable) StatusReport before we abort.
        let _ = exch
            .send_standalone_ack(transport, peer, sigma2.message_counter)
            .await;
        return Err(e);
    }
    #[cfg(feature = "tracing")]
    tracing::debug!(
        sigma2 = %crate::hexdump::hex(&sigma2.payload),
        "received Sigma2"
    );
    initiator.handle_sigma2(&sigma2.payload)?;

    // Sigma3 is sent reliably and the device closes the handshake with a
    // SecureChannel StatusReport (success or failure) — consumed and acked
    // here, exactly as in `run_pase` (see that bridge for rationale).
    let sigma3 = initiator.next_message()?;
    let report = exch
        .send_and_recv(
            transport,
            peer,
            OP_SIGMA3,
            &sigma3,
            Some(sigma2.message_counter),
        )
        .await?;
    let status = parse_status_report(&report)?;
    exch.send_standalone_ack(transport, peer, report.message_counter)
        .await?;
    if !status.is_session_establishment_success() {
        return Err(DriverError::SessionEstablishmentFailed {
            general_code: status.general_code,
            protocol_code: status.protocol_code,
        });
    }

    let output = initiator.finish()?;
    let sid = sessions.register_case(&output, SessionRole::Initiator);
    Ok(sid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    #[test]
    fn operational_instance_name_formats_16_16_uppercase_hex() {
        let cfid = [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30];
        let node_id: u64 = 0x0000_0000_0000_0001;
        assert_eq!(
            operational_instance_name(cfid, node_id),
            "87E1B004E235A130-0000000000000001"
        );
    }

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
        assert_eq!(
            addr,
            std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 5540)
        );
    }

    #[tokio::test]
    async fn resolve_operational_prefers_routable_addresses() {
        // mDNS records list link-local IPv6 first on many devices, but a
        // `fe80::` address without a scope id is unroutable from a dial-out
        // socket. Prefer IPv4, then non-link-local IPv6, and fall back to
        // whatever is left (M6.6.5: closes the FLAGGED `.first()` pick).
        use std::net::Ipv6Addr;
        let cfid = [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30];
        let node_id: u64 = 1;
        let name = operational_instance_name(cfid, node_id);
        let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1d42));
        let ula = IpAddr::V6(Ipv6Addr::new(0xfdfc, 0x20da, 0x4273, 0x126f, 0, 0, 0, 1));
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 248));

        // Link-local listed first, IPv4 buried last — IPv4 must win.
        let mut disc = FakeDiscovery {
            service: MatterService {
                instance_name: name.clone(),
                kind: ServiceKind::Operational,
                addresses: vec![link_local, ula, v4],
                port: 5540,
                txt_records: HashMap::new(),
            },
        };
        let addr = resolve_operational(&mut disc, cfid, node_id).await.unwrap();
        assert_eq!(addr, std::net::SocketAddr::new(v4, 5540));

        // No IPv4: the non-link-local IPv6 must win over fe80.
        let mut disc = FakeDiscovery {
            service: MatterService {
                instance_name: name,
                kind: ServiceKind::Operational,
                addresses: vec![link_local, ula],
                port: 5540,
                txt_records: HashMap::new(),
            },
        };
        let addr = resolve_operational(&mut disc, cfid, node_id).await.unwrap();
        assert_eq!(addr, std::net::SocketAddr::new(ula, 5540));
    }

    // -----------------------------------------------------------------------
    // run_case loopback test (M6.6.3b Task 5)
    // -----------------------------------------------------------------------

    use matter_cert::test_support::{build_unsigned, with_signature, TestCertFields};
    use matter_cert::{
        BasicConstraints, DistinguishedName, DnAttribute, Extensions, KeyIdentifier, KeyUsage,
        MatterCertificate, MatterTime, PublicKey, Signature, TrustAnchor, TrustedRoots,
    };
    use matter_crypto::{CaseCredentials, CaseResponder, CaseSigner, RingSigner, Sigma1Outcome};
    use matter_transport::{SessionKeys, SessionManager};

    use crate::driver::datagram::InMemoryDatagram;
    use crate::driver::unsecured::{decode_unsecured, encode_unsecured};

    const T_FABRIC_ID: u64 = 0x4242_4242_4242_4242;
    const T_INITIATOR_NODE: u64 = 0xDEAD_BEEF_CAFE_F00D;
    const T_RESPONDER_NODE: u64 = 0xBABE_FEED_1234_5678;
    const T_IPK: [u8; 16] = [0x77; 16];
    const T_RCAC_SKI: [u8; 20] = [0x01; 20];
    const T_NOC_SKI: [u8; 20] = [0x02; 20];

    /// Build a self-signed RCAC and return it with its signer and raw public
    /// key. The caller builds `TrustedRoots` from the returned `&rcac` so
    /// that two independent roots sets (controller + device) can be derived
    /// without requiring `TrustedRoots: Clone` — though it happens to be
    /// `Clone`, both patterns work.
    fn build_test_rcac() -> (MatterCertificate, RingSigner, [u8; 65]) {
        let (rcac_signer, _pkcs8) = RingSigner::generate().unwrap();
        let rcac_pub = *rcac_signer.public_key().as_bytes();
        let rcac_dn = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);
        let extensions = Extensions {
            basic_constraints: Some(BasicConstraints {
                is_ca: true,
                path_len_constraint: Some(1),
            }),
            key_usage: Some(KeyUsage::KEY_CERT_SIGN),
            extended_key_usage: None,
            subject_key_identifier: Some(KeyIdentifier(T_RCAC_SKI)),
            authority_key_identifier: Some(KeyIdentifier(T_RCAC_SKI)),
        };
        let fields = TestCertFields {
            serial: vec![0x01],
            issuer: rcac_dn.clone(),
            not_before: MatterTime::from_unix_secs(1_700_000_000),
            not_after: MatterTime::from_unix_secs(2_500_000_000),
            subject: rcac_dn,
            public_key: PublicKey::new(rcac_pub).unwrap(),
            extensions,
            signature: Signature::new([0u8; 64]),
        };
        let unsigned = build_unsigned(fields);
        let tbs = unsigned.to_x509_tbs_der().unwrap();
        let sig = rcac_signer.sign_p256_sha256(&tbs).unwrap();
        let rcac = with_signature(&unsigned, Signature::new(sig));
        (rcac, rcac_signer, rcac_pub)
    }

    fn roots_for(rcac: &MatterCertificate) -> TrustedRoots {
        let mut roots = TrustedRoots::new();
        roots.add(TrustAnchor::from_root_cert(rcac));
        roots
    }

    fn build_test_noc(rcac_signer: &RingSigner, node_id: u64) -> (MatterCertificate, RingSigner) {
        let (noc_signer, _) = RingSigner::generate().unwrap();
        let noc_pub = *noc_signer.public_key().as_bytes();
        let subject_dn = DistinguishedName::new(vec![
            DnAttribute::FabricId(T_FABRIC_ID),
            DnAttribute::NodeId(node_id),
        ]);
        let issuer_dn = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);
        let extensions = Extensions {
            basic_constraints: Some(BasicConstraints {
                is_ca: false,
                path_len_constraint: None,
            }),
            key_usage: Some(KeyUsage::DIGITAL_SIGNATURE),
            extended_key_usage: None,
            subject_key_identifier: Some(KeyIdentifier(T_NOC_SKI)),
            authority_key_identifier: Some(KeyIdentifier(T_RCAC_SKI)),
        };
        let fields = TestCertFields {
            serial: vec![0x02],
            issuer: issuer_dn,
            not_before: MatterTime::from_unix_secs(1_700_000_000),
            not_after: MatterTime::from_unix_secs(2_500_000_000),
            subject: subject_dn,
            public_key: PublicKey::new(noc_pub).unwrap(),
            extensions,
            signature: Signature::new([0u8; 64]),
        };
        let unsigned = build_unsigned(fields);
        let tbs = unsigned.to_x509_tbs_der().unwrap();
        let sig = rcac_signer.sign_p256_sha256(&tbs).unwrap();
        let noc = with_signature(&unsigned, Signature::new(sig));
        (noc, noc_signer)
    }

    fn creds(
        noc: MatterCertificate,
        signer: RingSigner,
        node_id: u64,
        rcac_pub: [u8; 65],
    ) -> CaseCredentials {
        CaseCredentials {
            noc,
            icac: None,
            signer: Box::new(signer),
            fabric_id: T_FABRIC_ID,
            node_id,
            ipk: T_IPK,
            rcac_public_key: rcac_pub,
        }
    }

    #[tokio::test]
    async fn run_case_surfaces_sigma1_status_report_rejection() {
        // A device that cannot match Sigma1's destination id (e.g. IPK or
        // fabric mismatch) answers with a StatusReport (NoSharedTrustRoots,
        // protocol code 0x0001) instead of Sigma2. run_case must surface the
        // device's codes, not feed the report into the Sigma2 parser
        // (observed: Tapo P110M, M6.6.5 — misparsed as "invalid parameter").
        let (rcac, rcac_signer, rcac_pub) = build_test_rcac();
        let (init_noc, init_signer) = build_test_noc(&rcac_signer, T_INITIATOR_NODE);
        let init_creds = creds(init_noc, init_signer, T_INITIATOR_NODE, rcac_pub);
        let ctrl_roots = roots_for(&rcac);

        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut sessions = SessionManager::new();

        let device = async {
            let (p, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&p).unwrap();
            // StatusReport: FAILURE / SecureChannel NoSharedTrustRoots.
            let mut body = Vec::new();
            body.extend_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&0x0001u16.to_le_bytes());
            let report = encode_unsecured(
                200,
                m.exchange_id,
                0x40,
                matter_transport::ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(m.message_counter),
                None,
                &body,
            );
            dev_io.send_to(&report, ctrl_addr).await.unwrap();
        };

        let controller = run_case(
            &ctrl_io,
            &mut sessions,
            dev_addr,
            init_creds,
            ctrl_roots,
            T_RESPONDER_NODE,
            T_FABRIC_ID,
            MatterTime::from_unix_secs(2_000_000_000),
        );

        let (ctrl_result, ()) = tokio::join!(controller, device);
        let err = ctrl_result.unwrap_err();
        assert!(
            matches!(
                err,
                DriverError::SessionEstablishmentFailed {
                    general_code: 1,
                    protocol_code: 0x0001,
                }
            ),
            "expected SessionEstablishmentFailed, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn run_case_establishes_matching_session() {
        let (rcac, rcac_signer, rcac_pub) = build_test_rcac();
        let (init_noc, init_signer) = build_test_noc(&rcac_signer, T_INITIATOR_NODE);
        let (resp_noc, resp_signer) = build_test_noc(&rcac_signer, T_RESPONDER_NODE);
        let init_creds = creds(init_noc, init_signer, T_INITIATOR_NODE, rcac_pub);
        let resp_creds = creds(resp_noc, resp_signer, T_RESPONDER_NODE, rcac_pub);
        let resp_roots = roots_for(&rcac);
        let ctrl_roots = roots_for(&rcac);

        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut sessions = SessionManager::new();

        let device = async {
            let mut responder = CaseResponder::new(
                resp_creds,
                resp_roots,
                0x00D2,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .unwrap();
            let (p, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&p).unwrap();
            assert!(matches!(
                responder.handle_sigma1(&m.payload).unwrap(),
                Sigma1Outcome::NewSession
            ));
            let sigma2 = responder.next_message().unwrap();
            let wire = encode_unsecured(
                200,
                m.exchange_id,
                0x31,
                matter_transport::ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(m.message_counter),
                None,
                &sigma2,
            );
            dev_io.send_to(&wire, ctrl_addr).await.unwrap();
            let (p, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&p).unwrap();
            responder.handle_sigma3(&m.payload).unwrap();

            // Close the handshake with a success StatusReport (real-device
            // behaviour) and expect the controller's standalone ack.
            let mut body = Vec::new();
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            let report = encode_unsecured(
                201,
                m.exchange_id,
                0x40,
                matter_transport::ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(m.message_counter),
                None,
                &body,
            );
            dev_io.send_to(&report, ctrl_addr).await.unwrap();
            let ack = tokio::time::timeout(std::time::Duration::from_secs(2), dev_io.recv_from())
                .await
                .expect("controller must ack the StatusReport")
                .unwrap();
            let ack = decode_unsecured(&ack.0).unwrap();
            assert_eq!(ack.opcode, 0x10);
            assert_eq!(ack.ack_counter, Some(201));

            responder.finish().unwrap()
        };

        let controller = run_case(
            &ctrl_io,
            &mut sessions,
            dev_addr,
            init_creds,
            ctrl_roots,
            T_RESPONDER_NODE,
            T_FABRIC_ID,
            MatterTime::from_unix_secs(2_000_000_000),
        );

        let (ctrl_result, dev_out) = tokio::join!(controller, device);
        let sid = ctrl_result.unwrap();
        let registered = sessions.get(sid).unwrap();
        assert_eq!(registered.keys, SessionKeys::from_case_output(&dev_out));
        assert_eq!(registered.peer_id, matter_transport::SessionId(0x00D2));
    }
}
