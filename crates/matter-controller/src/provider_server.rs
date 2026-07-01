//! The OTA **provider server** (M9-F3): a dedicated task that advertises our
//! operational service, accepts an inbound CASE session as the responder, and
//! dispatches one server-side `InvokeRequest`. Productionizes the responder
//! accept-flow proven in the actor's loopback tests; hosts it in
//! `matter-controller` so it can reuse the persisted operational identity
//! (`crate::credentials::operational_credentials`) and the existing session /
//! transport / discovery machinery without a new crate boundary.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use matter_cert::{MatterTime, TrustedRoots};
use matter_commissioning::driver::{decode_unsecured, encode_unsecured, AsyncDatagram};
use matter_crypto::{CaseCredentials, CaseResponder, Sigma1Outcome};
use matter_interaction::{
    build_invoke_response_command, build_invoke_response_status, parse_invoke_request, CommandPath,
    ImStatus, ParsedInvokeRequest,
};
use matter_transport::{
    DecodeInboundOutput, MatterService, MrpFlags, ProtocolId, ServiceKind, SessionId,
    SessionManager, SessionRole,
};

use crate::error::Error;

// SecureChannel handshake opcodes (Matter Core §4.10 / §4.13).
const OP_SIGMA1: u8 = 0x30;
const OP_SIGMA2: u8 = 0x31;
const OP_SIGMA3: u8 = 0x32;
const OP_STATUS_REPORT: u8 = 0x40;
// Interaction Model opcodes.
const OP_INVOKE_REQUEST: u8 = 0x08;
const OP_INVOKE_RESPONSE: u8 = 0x09;

// OtaSoftwareUpdateProvider (0x0029) command ids (Matter Core §11.20).
const OTA_PROVIDER_CLUSTER: u32 = 0x0029;
const CMD_QUERY_IMAGE: u32 = 0x00;
const CMD_QUERY_IMAGE_RESPONSE: u32 = 0x01;
const CMD_APPLY_UPDATE_REQUEST: u32 = 0x02;
const CMD_APPLY_UPDATE_RESPONSE: u32 = 0x03;
const CMD_NOTIFY_UPDATE_APPLIED: u32 = 0x04;

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

/// A single-session OTA provider server: accepts one inbound CASE session as the
/// responder, then dispatches server-side `InvokeRequest`s. Generic over the
/// datagram transport so it runs over `TokioUdpTransport` in production and
/// `InMemoryDatagram` in tests.
///
/// This productionizes the responder accept-flow proven in the actor's loopback
/// tests (`run_loopback_device`): Sigma1→Sigma2→Sigma3→`SessionManager` register,
/// then secured IM dispatch on the established session.
pub struct ProviderServer<D> {
    io: D,
    credentials: Option<CaseCredentials>,
    roots: TrustedRoots,
    responder_session_id: u16,
    now: MatterTime,
    handshake_counter: u32,
}

impl<D: AsyncDatagram> ProviderServer<D> {
    /// Build a provider server bound to `io`, authenticating as `credentials`
    /// (our operational identity) and validating the peer's certificate chain
    /// against `roots` at `now`. `responder_session_id` is the non-zero secured
    /// session id we advertise in Sigma2.
    #[must_use]
    pub fn new(
        io: D,
        credentials: CaseCredentials,
        roots: TrustedRoots,
        responder_session_id: u16,
        now: MatterTime,
    ) -> Self {
        Self {
            io,
            credentials: Some(credentials),
            roots,
            responder_session_id,
            now,
            handshake_counter: 1,
        }
    }

    fn next_handshake_counter(&mut self) -> u32 {
        let c = self.handshake_counter;
        self.handshake_counter = self.handshake_counter.wrapping_add(1);
        c
    }

    async fn recv(&self) -> Result<(Vec<u8>, SocketAddr), Error> {
        self.io
            .recv_from()
            .await
            .map_err(|e| Error::Operational(format!("provider recv: {e}")))
    }

    async fn send(&self, bytes: &[u8], peer: SocketAddr) -> Result<(), Error> {
        self.io
            .send_to(bytes, peer)
            .await
            .map_err(|e| Error::Operational(format!("provider send: {e}")))
    }

    /// Accept ONE inbound CASE session as the responder, returning an
    /// established [`SessionManager`] + the secured `SessionId` + the peer's
    /// address. Mirrors the proven `run_loopback_device` accept-flow.
    async fn accept_case(&mut self) -> Result<(SessionManager, SessionId, SocketAddr), Error> {
        let credentials = self
            .credentials
            .take()
            .ok_or_else(|| Error::Operational("provider server already consumed".into()))?;
        let mut responder = CaseResponder::new(
            credentials,
            self.roots.clone(),
            self.responder_session_id,
            self.now,
        )
        .map_err(|e| Error::Operational(format!("CASE responder init: {e}")))?;

        // Sigma1 → Sigma2.
        let (s1, peer) = self.recv().await?;
        let m1 = decode_unsecured(&s1).map_err(|e| Error::Operational(format!("sigma1: {e}")))?;
        if m1.opcode != OP_SIGMA1 {
            return Err(Error::Operational(format!(
                "expected Sigma1 (0x30), got {:#04x}",
                m1.opcode
            )));
        }
        match responder
            .handle_sigma1(&m1.payload)
            .map_err(|e| Error::Operational(format!("handle_sigma1: {e}")))?
        {
            Sigma1Outcome::NewSession => {}
            Sigma1Outcome::ResumptionRequested { .. } => {
                return Err(Error::Operational(
                    "provider server only supports new CASE sessions (resumption unsupported)"
                        .into(),
                ))
            }
        }
        let sigma2 = responder
            .next_message()
            .map_err(|e| Error::Operational(format!("sigma2: {e}")))?;
        let c = self.next_handshake_counter();
        let wire = encode_unsecured(
            c,
            m1.exchange_id,
            OP_SIGMA2,
            ProtocolId::SECURE_CHANNEL,
            false,
            true,
            Some(m1.message_counter),
            None,
            &sigma2,
        );
        self.send(&wire, peer).await?;

        // Sigma3 → success StatusReport.
        let (s3, _) = self.recv().await?;
        let m3 = decode_unsecured(&s3).map_err(|e| Error::Operational(format!("sigma3: {e}")))?;
        if m3.opcode != OP_SIGMA3 {
            return Err(Error::Operational(format!(
                "expected Sigma3 (0x32), got {:#04x}",
                m3.opcode
            )));
        }
        responder
            .handle_sigma3(&m3.payload)
            .map_err(|e| Error::Operational(format!("handle_sigma3: {e}")))?;
        let mut body = Vec::with_capacity(8);
        body.extend_from_slice(&0u16.to_le_bytes()); // GeneralCode: success
        body.extend_from_slice(&0u32.to_le_bytes()); // ProtocolId: SecureChannel
        body.extend_from_slice(&0u16.to_le_bytes()); // ProtocolCode: 0
        let c = self.next_handshake_counter();
        let report = encode_unsecured(
            c,
            m3.exchange_id,
            OP_STATUS_REPORT,
            ProtocolId::SECURE_CHANNEL,
            false,
            true,
            Some(m3.message_counter),
            None,
            &body,
        );
        self.send(&report, peer).await?;

        // Absorb the initiator's standalone ack of our StatusReport.
        let _ack = self.recv().await?;

        let output = responder
            .finish()
            .map_err(|e| Error::Operational(format!("CASE finish: {e}")))?;
        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);
        Ok((sessions, sid, peer))
    }

    /// Accept ONE inbound CASE session, then dispatch up to `max_invokes`
    /// server-side `InvokeRequest`s through `handler`, replying to each on its
    /// exchange. Returns the number of invokes dispatched.
    ///
    /// `handler` maps a parsed `InvokeRequest` to the encoded `InvokeResponse`
    /// message bytes (e.g. via `matter_interaction::build_invoke_response_*`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Operational`] on a transport, CASE-handshake, or framing
    /// failure (including a non-`NewSession` Sigma1 or an unexpected opcode), or
    /// [`Error::Transport`] / [`Error::InteractionModel`] from the session / IM
    /// layers.
    pub async fn accept_and_dispatch_once<H>(
        mut self,
        mut handler: H,
        max_invokes: usize,
    ) -> Result<usize, Error>
    where
        H: FnMut(&ParsedInvokeRequest) -> Vec<u8>,
    {
        let (mut sessions, sid, peer) = self.accept_case().await?;

        let mut dispatched = 0usize;
        while dispatched < max_invokes {
            let (wire, _) = self.recv().await?;
            if let DecodeInboundOutput::AppMessage {
                exchange_id,
                opcode,
                payload,
                ..
            } = sessions.decode_inbound(&wire, Instant::now())?
            {
                if opcode != OP_INVOKE_REQUEST {
                    // Ignore non-invoke app messages in F3 (e.g. reads).
                    continue;
                }
                let parsed = parse_invoke_request(&payload)?;
                let response = handler(&parsed);
                let out = sessions.encode_outbound(
                    sid,
                    Some(exchange_id),
                    OP_INVOKE_RESPONSE,
                    ProtocolId::INTERACTION_MODEL,
                    &response,
                    MrpFlags { reliable: false },
                    Instant::now(),
                )?;
                self.send(&out.wire_bytes, peer).await?;
                dispatched += 1;
            }
        }
        Ok(dispatched)
    }

    /// Accept ONE CASE session, then serve `image` to the requestor over the
    /// full OTA flow: `QueryImage` → `QueryImageResponse`, a BDX transfer, then
    /// `ApplyUpdateRequest` → `ApplyUpdateResponse` and `NotifyUpdateApplied` →
    /// Success. Returns once `NotifyUpdateApplied` is handled.
    ///
    /// `offer` shapes the `QueryImageResponse` (its `ImageURI`/`UpdateToken`);
    /// `max_block_size` caps each BDX block. All replies are unreliable
    /// (piggyback ack) — happy-path, localhost-validated. Messages route by
    /// [`ProtocolId`]: Interaction-Model invokes go to the `matter-ota` handlers,
    /// `ProtocolId::BDX` messages drive a [`matter_bdx::BlockSender`].
    ///
    /// # Errors
    ///
    /// [`Error::Operational`] on a CASE/transport/codec failure, a BDX abort, an
    /// unexpected OTA command, or if the flow ends without `NotifyUpdateApplied`;
    /// [`Error::Transport`] / [`Error::InteractionModel`] from the session / IM
    /// layers.
    #[allow(clippy::too_many_lines)] // Linear OTA protocol-dispatch loop; splitting hurts clarity.
    pub async fn serve_ota_once(
        mut self,
        offer: matter_ota::ImageOffer,
        image: Vec<u8>,
        max_block_size: u16,
    ) -> Result<(), Error> {
        use matter_bdx::{BdxMessage, BlockSender, MessageType, SenderOutcome};

        let (mut sessions, sid, peer) = self.accept_case().await?;
        let mut bdx: Option<BlockSender> = None;
        let mut applied = false;

        // Generous step bound: one per OTA command + one per block + slack.
        let max_steps = image.len() / usize::from(max_block_size.max(1)) + 64;
        let mut steps = 0usize;

        while !applied && steps < max_steps {
            steps += 1;
            let (wire, _) = self.recv().await?;
            let DecodeInboundOutput::AppMessage {
                exchange_id,
                protocol_id,
                opcode,
                payload,
                ..
            } = sessions.decode_inbound(&wire, Instant::now())?
            else {
                continue;
            };

            if protocol_id == ProtocolId::INTERACTION_MODEL && opcode == OP_INVOKE_REQUEST {
                let parsed = parse_invoke_request(&payload)?;
                let cmd = parsed
                    .commands
                    .first()
                    .ok_or_else(|| Error::Operational("OTA invoke had no command".into()))?;
                let response = if cmd.path.command == CMD_QUERY_IMAGE {
                    bdx = Some(BlockSender::new(image.clone(), max_block_size));
                    let fields = matter_ota::handle_query_image(&cmd.fields_tlv, Some(&offer))
                        .map_err(|e| Error::Operational(format!("QueryImage: {e}")))?;
                    build_invoke_response_command(
                        CommandPath {
                            endpoint: 0,
                            cluster: OTA_PROVIDER_CLUSTER,
                            command: CMD_QUERY_IMAGE_RESPONSE,
                        },
                        &fields,
                    )
                } else if cmd.path.command == CMD_APPLY_UPDATE_REQUEST {
                    let fields = matter_ota::handle_apply_update_request(&cmd.fields_tlv)
                        .map_err(|e| Error::Operational(format!("ApplyUpdateRequest: {e}")))?;
                    build_invoke_response_command(
                        CommandPath {
                            endpoint: 0,
                            cluster: OTA_PROVIDER_CLUSTER,
                            command: CMD_APPLY_UPDATE_RESPONSE,
                        },
                        &fields,
                    )
                } else if cmd.path.command == CMD_NOTIFY_UPDATE_APPLIED {
                    matter_ota::parse_notify_update_applied(&cmd.fields_tlv)
                        .map_err(|e| Error::Operational(format!("NotifyUpdateApplied: {e}")))?;
                    applied = true;
                    build_invoke_response_status(
                        CommandPath {
                            endpoint: 0,
                            cluster: OTA_PROVIDER_CLUSTER,
                            command: CMD_NOTIFY_UPDATE_APPLIED,
                        },
                        ImStatus::Success,
                    )
                } else {
                    return Err(Error::Operational(format!(
                        "unexpected OTA command {:#04x}",
                        cmd.path.command
                    )));
                };
                let out = sessions.encode_outbound(
                    sid,
                    Some(exchange_id),
                    OP_INVOKE_RESPONSE,
                    ProtocolId::INTERACTION_MODEL,
                    &response,
                    MrpFlags { reliable: false },
                    Instant::now(),
                )?;
                self.send(&out.wire_bytes, peer).await?;
            } else if protocol_id == ProtocolId::BDX {
                let mt = MessageType::from_u8(opcode).ok_or_else(|| {
                    Error::Operational(format!("unknown BDX opcode {opcode:#04x}"))
                })?;
                let msg = BdxMessage::decode(mt, &payload)
                    .map_err(|e| Error::Operational(format!("BDX decode: {e}")))?;
                let sender = bdx
                    .as_mut()
                    .ok_or_else(|| Error::Operational("BDX message before QueryImage".into()))?;
                let outcome = match msg {
                    BdxMessage::ReceiveInit(init) => sender.accept_receive_init(&init),
                    BdxMessage::BlockQuery(q) => sender.handle_block_query(&q),
                    BdxMessage::BlockAckEof(a) => sender.handle_block_ack_eof(&a),
                    _ => return Err(Error::Operational("unexpected inbound BDX message".into())),
                };
                match outcome {
                    SenderOutcome::Send(out) => {
                        let w = sessions.encode_outbound(
                            sid,
                            Some(exchange_id),
                            out.message_type.to_u8(),
                            ProtocolId::BDX,
                            &out.payload,
                            MrpFlags { reliable: false },
                            Instant::now(),
                        )?;
                        self.send(&w.wire_bytes, peer).await?;
                    }
                    SenderOutcome::Done => {}
                    SenderOutcome::Abort(code) => {
                        return Err(Error::Operational(format!(
                            "BDX transfer aborted: status {:#06x}",
                            code.to_u16()
                        )))
                    }
                }
            }
        }

        if applied {
            Ok(())
        } else {
            Err(Error::Operational(
                "OTA flow ended without NotifyUpdateApplied".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)] // Test code: CLAUDE.md carve-out.
    use super::*;
    use std::net::Ipv6Addr;

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
