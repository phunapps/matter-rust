//! CASE bridge (M6.6.3b): operational discovery + drive the sans-IO
//! `CaseInitiator` over the unsecured datagram path.
//!
//! CASE Sigma1/2/3 are exchanged UNSECURED (session-id 0, `SecureChannel`
//! protocol) — the operational secured session only exists once the handshake
//! derives keys.

use std::net::SocketAddr;

use matter_cert::TrustedRoots;
use matter_crypto::{CaseCredentials, CaseInitiator};
use matter_transport::{Discovery, ServiceKind, SessionId, SessionManager, SessionRole};

use crate::driver::error::DriverError;
use crate::driver::datagram::AsyncDatagram;
use crate::driver::unsecured::UnsecuredExchange;

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

// SecureChannel opcodes for the CASE handshake (Matter Core Spec §4.14.1).
const OP_SIGMA1: u8 = 0x30;
const OP_SIGMA3: u8 = 0x32;

const CASE_INITIAL_COUNTER: u32 = 1;
const CASE_EXCHANGE_ID: u16 = 1;

/// Drive a fresh CASE (SIGMA-I) handshake against an already-resolved
/// operational `peer` and register the resulting operational session, returning
/// its local [`SessionId`]. `credentials` is this controller's operational
/// identity; `peer_node_id`/`peer_fabric_id` identify the device. Resumption is
/// not used (a fresh handshake every time); that is M8.
///
/// # Errors
///
/// - [`DriverError::Crypto`] if a SIGMA step fails (peer chain/signature
///   invalid, key mismatch, etc.).
/// - [`DriverError::Io`] / [`DriverError::Transport`] / [`DriverError::Timeout`]
///   on datagram, framing, or reply-timeout failure.
pub async fn run_case<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    peer: SocketAddr,
    credentials: CaseCredentials,
    trusted_roots: TrustedRoots,
    peer_node_id: u64,
    peer_fabric_id: u64,
) -> Result<SessionId, DriverError> {
    let local = sessions.allocate_session_id();
    let mut initiator =
        CaseInitiator::new(credentials, trusted_roots, peer_node_id, peer_fabric_id, local.0)?;
    let mut exch = UnsecuredExchange::new(CASE_INITIAL_COUNTER, CASE_EXCHANGE_ID);

    let sigma1 = initiator.start()?;
    let sigma2 = exch
        .send_and_recv(transport, peer, OP_SIGMA1, &sigma1, None)
        .await?;
    initiator.handle_sigma2(&sigma2.payload)?;

    let sigma3 = initiator.next_message()?;
    exch.send(transport, peer, OP_SIGMA3, &sigma3, Some(sigma2.message_counter))
        .await?;

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
            let mut responder = CaseResponder::new(resp_creds, resp_roots, 0x00D2).unwrap();
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
                &sigma2,
            );
            dev_io.send_to(&wire, ctrl_addr).await.unwrap();
            let (p, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&p).unwrap();
            responder.handle_sigma3(&m.payload).unwrap();
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
        );

        let (ctrl_result, dev_out) = tokio::join!(controller, device);
        let sid = ctrl_result.unwrap();
        let registered = sessions.get(sid).unwrap();
        assert_eq!(registered.keys, SessionKeys::from_case_output(&dev_out));
        assert_eq!(registered.peer_id, matter_transport::SessionId(0x00D2));
    }
}
