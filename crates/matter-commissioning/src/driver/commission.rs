//! The async `commission()` orchestrator (M6.6.4): drive the sans-IO
//! `Commissioner` cursor over the M6.6.2/M6.6.3 driver, end to end.

use std::net::SocketAddr;

use matter_transport::{Discovery, ProtocolId, ServiceKind, SessionId, SessionManager};

use crate::driver::datagram::AsyncDatagram;
use crate::driver::error::DriverError;
use crate::driver::exchange::secured_round_trip;
use crate::im::{CommandPath, ImStatus};
use crate::CommissionedFabric;
use crate::CommissionerConfig;

/// Outcome of a single `dispatch_invoke` round-trip.
///
/// Either the device replied with a response-command payload (`Command`), or
/// it returned a bare IM status with no payload (`Status`).
// wired into the poll loop in Task 6
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InvokeOutcome {
    /// Device returned a response command; `Vec<u8>` is the re-anonymised
    /// `CommandFields` TLV blob (anonymous-tagged struct, ready for the state
    /// machine's `on_response`).
    Command(Vec<u8>),
    /// Device returned a bare IM status (no response-command payload).
    Status(ImStatus),
}

/// Send a single `InvokeRequest` over an already-established secured session
/// and await the `InvokeResponse`.
///
/// Builds the `InvokeRequestMessage` from `path` and `fields_tlv`, sends it
/// via [`secured_round_trip`], then parses the `InvokeResponseMessage` and
/// returns the outcome.
///
/// # Errors
///
/// - [`DriverError::Transport`] / [`DriverError::Io`] / [`DriverError::Timeout`]
///   propagated from [`secured_round_trip`].
/// - [`DriverError::Im`] if the response cannot be parsed as a valid
///   `InvokeResponseMessage`.
// wired into the poll loop in Task 6
#[allow(dead_code)]
pub(crate) async fn dispatch_invoke<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    session_id: SessionId,
    peer: SocketAddr,
    path: CommandPath,
    fields_tlv: &[u8],
) -> Result<InvokeOutcome, DriverError> {
    const OP_INVOKE_REQUEST: u8 = 0x08;
    let msg = crate::im::build_invoke_request(path, fields_tlv);
    let resp = secured_round_trip(
        transport,
        sessions,
        session_id,
        peer,
        OP_INVOKE_REQUEST,
        ProtocolId::INTERACTION_MODEL,
        &msg,
    )
    .await?;
    match crate::im::parse_invoke_response(&resp.payload)? {
        crate::im::InvokeResponse::Command { fields_tlv, .. } => {
            Ok(InvokeOutcome::Command(fields_tlv))
        }
        crate::im::InvokeResponse::Status(s) => Ok(InvokeOutcome::Status(s)),
    }
}

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
    use std::time::Instant;

    use matter_codec::{Tag, TlvWriter};
    use matter_crypto::pase::PaseSessionKeys;
    use matter_transport::{
        DecodeInboundOutput, MatterService, MrpFlags, PeerHint, ProtocolId, QueryHandle,
        SessionRole,
    };

    use crate::driver::datagram::InMemoryDatagram;

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

    /// Build two `SessionManager`s sharing one PASE key set, cross-registered
    /// as Initiator (controller) / Responder (device). Mirrors the harness in
    /// `exchange.rs::tests::paired_pase_sessions`.
    fn paired_pase_sessions() -> (SessionManager, SessionManager) {
        let keys = PaseSessionKeys {
            ke: [0u8; 16],
            i2r_key: [1u8; 16],
            r2i_key: [2u8; 16],
            attestation_key: [3u8; 16],
        };
        let mut ctrl = SessionManager::new();
        let mut dev = SessionManager::new();
        ctrl.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
        dev.register_pase(keys, SessionRole::Responder, 1, PeerHint::default());
        (ctrl, dev)
    }

    /// Build a minimal valid `InvokeResponseMessage` that carries a single
    /// `CommandDataIB` with the given `path` and `fields_tlv`, ready to be
    /// parsed by `crate::im::parse_invoke_response`.
    ///
    /// Hand-rolls the TLV because the `im` module only exports a request
    /// builder, not a response builder. Structure mirrors the
    /// `parses_command_response_payload` test in `im/invoke.rs`.
    fn build_canned_invoke_response(path: crate::im::CommandPath, fields_tlv: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseMessage
        w.put_bool(Tag::Context(0), false).unwrap(); // SuppressResponse
        w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
        {
            w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
            w.start_structure(Tag::Context(0)).unwrap(); // Command = CommandDataIB
                                                         // CommandPathIB list
            w.start_list(Tag::Context(0)).unwrap();
            w.put_uint(Tag::Context(0), u64::from(path.endpoint))
                .unwrap();
            w.put_uint(Tag::Context(1), u64::from(path.cluster))
                .unwrap();
            w.put_uint(Tag::Context(2), u64::from(path.command))
                .unwrap();
            w.end_container().unwrap(); // CommandPathIB
                                        // CommandFields: embed fields_tlv as context-1 struct.
                                        // `put_preencoded` re-tags the anonymous-struct byte to context-1.
            w.put_preencoded(Tag::Context(1), fields_tlv).unwrap();
            w.end_container().unwrap(); // CommandDataIB
            w.end_container().unwrap(); // InvokeResponseIB
        }
        w.end_container().unwrap(); // InvokeResponses
        w.put_uint(Tag::Context(0xFF), u64::from(crate::im::IM_REVISION))
            .unwrap();
        w.end_container().unwrap(); // InvokeResponseMessage
        buf
    }

    /// `dispatch_invoke` sends an `InvokeRequest` via `secured_round_trip`,
    /// and the device side replies with a canned `InvokeResponse`. The test
    /// asserts the returned `InvokeOutcome::Command(fields_tlv)` matches the
    /// bytes we put into the canned response.
    #[tokio::test]
    async fn dispatch_invoke_returns_command_fields() {
        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        // The command fields we expect the device to echo back.
        // An anonymous empty struct: 0x15 0x18 (start-structure anonymous + end-container).
        let canned_fields: Vec<u8> = vec![0x15, 0x18];

        let path = CommandPath {
            endpoint: 0,
            cluster: 0x0030, // General Commissioning
            command: 0x00,   // ArmFailSafe
        };

        // Build the canned InvokeResponse the device will send back.
        let canned_response = build_canned_invoke_response(path, &canned_fields);

        // Controller side: call dispatch_invoke and collect the outcome.
        let controller =
            dispatch_invoke(&ctrl_io, &mut ctrl, session, dev_addr, path, &canned_fields);

        // Device side: receive the InvokeRequest and reply with the canned InvokeResponse.
        let device = async {
            loop {
                let (pkt, _) = dev_io.recv_from().await.unwrap();
                if let DecodeInboundOutput::AppMessage { exchange_id, .. } =
                    dev.decode_inbound(&pkt, Instant::now()).unwrap()
                {
                    // Reply on the SAME exchange_id (opcode 0x09 = InvokeResponse).
                    let out = dev
                        .encode_outbound(
                            session,
                            Some(exchange_id),
                            0x09,
                            ProtocolId::INTERACTION_MODEL,
                            &canned_response,
                            MrpFlags { reliable: true },
                            Instant::now(),
                        )
                        .unwrap();
                    dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
                    break;
                }
            }
        };

        let (outcome, ()) = tokio::join!(controller, device);
        // The parse_invoke_response re-anonymises the CommandFields: an empty
        // anonymous struct re-encodes as [0x15, 0x18].
        assert_eq!(outcome.unwrap(), InvokeOutcome::Command(canned_fields));
    }
}
