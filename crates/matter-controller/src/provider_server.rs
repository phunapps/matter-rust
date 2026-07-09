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
use matter_commissioning::driver::{decode_unsecured, encode_unsecured_reply, AsyncDatagram};
use matter_crypto::{CaseCredentials, CaseResponder, ResumptionRecord, Sigma1Outcome};
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
const OP_SIGMA2_RESUME: u8 = 0x33;
const OP_STATUS_REPORT: u8 = 0x40;
const OP_MRP_STANDALONE_ACK: u8 = 0x10;
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

/// A multi-session OTA provider server: accepts inbound CASE sessions as the
/// responder (one per pooled credential), then dispatches server-side
/// `InvokeRequest`s. Generic over the datagram transport so it runs over
/// `TokioUdpTransport` in production and `InMemoryDatagram` in tests.
///
/// This productionizes the responder accept-flow proven in the actor's loopback
/// tests (`run_loopback_device`): Sigma1→Sigma2→Sigma3→`SessionManager` register,
/// then secured IM dispatch on the established session.
///
/// The credential pool is consumed one entry per `accept_case` call. When the
/// pool is exhausted, `accept_case` (and any caller such as `serve_ota_once`)
/// returns [`Error::Operational`] with the message
/// `"provider server: credential pool exhausted"`. The pool is sized by the
/// caller — `serve_ota` mints four entries (first session + post-reboot session
/// + retry slack) from the persisted fabric.
pub struct ProviderServer<D> {
    io: D,
    /// Pool of operational identities, one consumed per CASE accept (the
    /// responder state machine takes ownership of its credentials).
    /// `serve_ota` mints these from the persisted fabric — see the spec's
    /// sizing rationale (first session + post-reboot session + retry slack).
    credentials: Vec<CaseCredentials>,
    roots: TrustedRoots,
    /// Base secured session id; accept N advertises `base.wrapping_add(N)` so
    /// consecutive sessions never share a local id.
    base_session_id: u16,
    /// Number of accepts performed so far (also indexes the session id).
    accepts: u16,
    now: MatterTime,
    handshake_counter: u32,
    /// Known CASE resumption records. When an inbound Sigma1 carries
    /// resumption fields whose id matches one of these, the session is
    /// resumed (`Sigma2_Resume`) instead of a full handshake — chip's OTA
    /// requestor always requests resumption of the session the controller
    /// just used to announce, so `serve_ota` seeds this with the announce
    /// connect's persisted record. No match falls back to
    /// `reject_resumption` + full handshake.
    resumption_records: Vec<ResumptionRecord>,
    /// Invoked with the fresh [`ResumptionRecord`] each accept produces
    /// (rotated on the resumed path, brand-new on the full path), so the
    /// caller can persist it IMMEDIATELY — a caller-side timeout that drops
    /// the serve future must not lose the rotation. Best-effort: the sink
    /// must not block (spawn if it needs async work).
    record_sink: Option<Box<dyn Fn(ResumptionRecord) + Send + Sync>>,
}

impl<D: AsyncDatagram> ProviderServer<D> {
    /// Build a provider server bound to `io`, authenticating from the
    /// `credentials` pool (our operational identities). `roots` and `now` are
    /// used to validate the peer's certificate chain on each accept.
    ///
    /// `base_session_id` is the first secured session id advertised in Sigma2;
    /// the Nth accept uses `base_session_id.wrapping_add(N)` so consecutive
    /// sessions never reuse the same local id.
    ///
    /// The pool is consumed one entry per accept. When it is empty, the next
    /// call to [`Self::serve_ota_once`] (or any method that calls `accept_case`)
    /// returns an [`Error::Operational`] containing
    /// `"provider server: credential pool exhausted"`.
    #[must_use]
    pub fn new(
        io: D,
        credentials: Vec<CaseCredentials>,
        roots: TrustedRoots,
        base_session_id: u16,
        now: MatterTime,
    ) -> Self {
        Self {
            io,
            credentials,
            roots,
            base_session_id,
            accepts: 0,
            now,
            handshake_counter: 1,
            resumption_records: Vec::new(),
            record_sink: None,
        }
    }

    /// Register a callback that is invoked once per completed accept with the
    /// fresh [`ResumptionRecord`] the handshake produced (rotated on the resumed
    /// path, brand-new on the full path). The caller can use this to persist the
    /// record immediately — a future that is cancelled after `accept_case`
    /// completes but before the caller stores the record would otherwise lose the
    /// rotation. The sink is called synchronously and **must not block**; spawn
    /// an async task if async work is needed.
    #[must_use]
    pub fn with_record_sink(mut self, sink: Box<dyn Fn(ResumptionRecord) + Send + Sync>) -> Self {
        self.record_sink = Some(sink);
        self
    }

    /// Seed the server with known CASE resumption records (see the field
    /// docs). An inbound resumption-requesting Sigma1 matching one of these
    /// by id is accepted via `Sigma2_Resume`; anything else falls back to a
    /// full handshake.
    #[must_use]
    pub fn with_resumption_records(mut self, records: Vec<ResumptionRecord>) -> Self {
        self.resumption_records = records;
        self
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

    /// Receive the next datagram while driving the session's MRP timers, so
    /// scheduled standalone acks (and retransmits) fire even while we sit in
    /// `recv`. Load-bearing for the OTA flow: the requestor's `BlockAckEOF`
    /// is MRP-reliable and we reply with nothing — without the pumped
    /// standalone ack, chip retransmits it, marks the session defunct, and
    /// abandons the update before `ApplyUpdateRequest` (observed live).
    async fn recv_secured(
        &self,
        sessions: &mut SessionManager,
        peer: SocketAddr,
    ) -> Result<(Vec<u8>, SocketAddr), Error> {
        use matter_transport::MrpEvent;
        loop {
            let Some(deadline) = sessions.poll_timeout() else {
                return self.recv().await;
            };
            let wait = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(wait, self.recv()).await {
                Ok(result) => return result,
                Err(_deadline_hit) => {
                    for event in sessions.handle_timeout(Instant::now()) {
                        match event {
                            MrpEvent::Retransmit { packet, .. }
                            | MrpEvent::SendStandaloneAck { packet, .. } => {
                                self.send(&packet, peer).await?;
                            }
                            // Single-session server: nothing to resolve on
                            // expiry; `MrpEvent` is non_exhaustive.
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    /// Accept ONE inbound CASE session as the responder, returning an
    /// established [`SessionManager`] + the secured `SessionId` + the peer's
    /// address. Mirrors the proven `run_loopback_device` accept-flow on the full
    /// path; a Sigma1 carrying resumption fields that match a seeded record (see
    /// [`Self::with_resumption_records`]) takes the `Sigma2_Resume` fast path
    /// instead.
    ///
    /// The fresh [`ResumptionRecord`] the handshake produces is handled
    /// internally: it is re-seeded into `self.resumption_records` (so the NEXT
    /// accept can match it) and passed to the `record_sink` (if set) before this
    /// method returns.
    ///
    /// If `first_frame` is `Some`, that datagram is used as the Sigma1 instead
    /// of calling `recv` — useful for callers that have already peeked the first
    /// packet (e.g., a multi-session loop that demuxes by session id).
    async fn accept_case(
        &mut self,
        first_frame: Option<(Vec<u8>, SocketAddr)>,
    ) -> Result<(SessionManager, SessionId, SocketAddr), Error> {
        let credentials = if self.credentials.is_empty() {
            return Err(Error::Operational(
                "provider server: credential pool exhausted".into(),
            ));
        } else {
            self.credentials.remove(0)
        };
        let responder_session_id = self.base_session_id.wrapping_add(self.accepts);
        self.accepts = self.accepts.wrapping_add(1);
        let mut responder = CaseResponder::new(
            credentials,
            self.roots.clone(),
            responder_session_id,
            self.now,
        )
        .map_err(|e| Error::Operational(format!("CASE responder init: {e}")))?;

        // Sigma1 → decide between the resumed and full paths.
        let (s1, peer) = match first_frame {
            Some(f) => f,
            None => self.recv().await?,
        };
        let m1 = decode_unsecured(&s1).map_err(|e| Error::Operational(format!("sigma1: {e}")))?;
        if m1.opcode != OP_SIGMA1 {
            return Err(Error::Operational(format!(
                "expected Sigma1 (0x30), got {:#04x}",
                m1.opcode
            )));
        }
        let outcome = responder
            .handle_sigma1(&m1.payload)
            .map_err(|e| Error::Operational(format!("handle_sigma1: {e}")))?;

        let resumed = match outcome {
            Sigma1Outcome::NewSession => false,
            Sigma1Outcome::ResumptionRequested { id } => {
                if let Some(pos) = self.resumption_records.iter().position(|r| r.id == id) {
                    let record = self.resumption_records.swap_remove(pos);
                    responder
                        .accept_resumption(record)
                        .map_err(|e| Error::Operational(format!("accept_resumption: {e}")))?;
                    true
                } else {
                    // Unknown id — decline and fall back to a full handshake.
                    responder
                        .reject_resumption()
                        .map_err(|e| Error::Operational(format!("reject_resumption: {e}")))?;
                    false
                }
            }
        };

        if resumed {
            self.complete_resumed(&mut responder, &m1, peer).await?;
        } else {
            self.complete_full(&mut responder, &m1, peer).await?;
        }

        let output = responder
            .finish()
            .map_err(|e| Error::Operational(format!("CASE finish: {e}")))?;
        if let Some(record) = output.resumption_record.clone() {
            // Re-seed so the NEXT accept (the post-reboot requestor resumes
            // with the id rotated during THIS handshake) can match it.
            self.resumption_records.push(record.clone());
            if let Some(sink) = &self.record_sink {
                sink(record);
            }
        }
        let mut sessions = SessionManager::new();
        let sid = sessions.register_case(&output, SessionRole::Responder);
        Ok((sessions, sid, peer))
    }

    /// Resumed path: send `Sigma2_Resume` on Sigma1's exchange, then await the
    /// initiator's success `StatusReport` and standalone-ack it (the report is
    /// MRP-reliable; without our ack chip retransmits it and eventually tears
    /// the exchange down). Tolerates interleaved Sigma1 retransmits (re-sends
    /// `Sigma2_Resume`) and stray standalone acks.
    async fn complete_resumed(
        &mut self,
        responder: &mut CaseResponder,
        m1: &matter_commissioning::driver::UnsecuredMessage,
        peer: SocketAddr,
    ) -> Result<(), Error> {
        let sigma2_resume = responder
            .next_message()
            .map_err(|e| Error::Operational(format!("sigma2_resume: {e}")))?;
        let c = self.next_handshake_counter();
        let wire = encode_unsecured_reply(
            c,
            m1.exchange_id,
            OP_SIGMA2_RESUME,
            ProtocolId::SECURE_CHANNEL,
            true,
            Some(m1.message_counter),
            m1.source_node_id,
            &sigma2_resume,
        );
        self.send(&wire, peer).await?;

        // Await the initiator's SigmaFinished success StatusReport, within a
        // bounded frame budget.
        for _ in 0..8 {
            let (bytes, _) = self.recv().await?;
            let m = decode_unsecured(&bytes)
                .map_err(|e| Error::Operational(format!("post-resume frame: {e}")))?;
            match m.opcode {
                OP_STATUS_REPORT => {
                    // StatusReport body: GeneralCode(u16 LE) || ProtocolId(u32) || ProtocolCode(u16).
                    let general_code = m
                        .payload
                        .get(0..2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .ok_or_else(|| {
                            Error::Operational("truncated resumption StatusReport".into())
                        })?;
                    if general_code != 0 {
                        return Err(Error::Operational(format!(
                            "initiator rejected resumption: StatusReport general code {general_code}"
                        )));
                    }
                    // Ack the reliable report so the initiator's MRP settles.
                    let c = self.next_handshake_counter();
                    let ack = encode_unsecured_reply(
                        c,
                        m.exchange_id,
                        OP_MRP_STANDALONE_ACK,
                        ProtocolId::SECURE_CHANNEL,
                        false,
                        Some(m.message_counter),
                        m.source_node_id.or(m1.source_node_id),
                        &[],
                    );
                    self.send(&ack, peer).await?;
                    return Ok(());
                }
                // Sigma1 retransmit: our Sigma2_Resume (or its ack) was lost —
                // re-send it on the same exchange.
                OP_SIGMA1 => {
                    let c = self.next_handshake_counter();
                    let wire = encode_unsecured_reply(
                        c,
                        m.exchange_id,
                        OP_SIGMA2_RESUME,
                        ProtocolId::SECURE_CHANNEL,
                        true,
                        Some(m.message_counter),
                        m.source_node_id.or(m1.source_node_id),
                        &sigma2_resume,
                    );
                    self.send(&wire, peer).await?;
                }
                // A standalone ack of our Sigma2_Resume — fine, keep waiting.
                OP_MRP_STANDALONE_ACK => {}
                other => {
                    return Err(Error::Operational(format!(
                        "expected resumption StatusReport (0x40), got {other:#04x}"
                    )))
                }
            }
        }
        Err(Error::Operational(
            "no StatusReport after Sigma2_Resume within frame budget".into(),
        ))
    }

    /// Full-handshake path (Sigma2 → Sigma3 → our success `StatusReport`), used
    /// for a plain Sigma1 and as the fallback after `reject_resumption`.
    async fn complete_full(
        &mut self,
        responder: &mut CaseResponder,
        m1: &matter_commissioning::driver::UnsecuredMessage,
        peer: SocketAddr,
    ) -> Result<(), Error> {
        let sigma2 = responder
            .next_message()
            .map_err(|e| Error::Operational(format!("sigma2: {e}")))?;
        let c = self.next_handshake_counter();
        let wire = encode_unsecured_reply(
            c,
            m1.exchange_id,
            OP_SIGMA2,
            ProtocolId::SECURE_CHANNEL,
            true,
            Some(m1.message_counter),
            m1.source_node_id,
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
        let report = encode_unsecured_reply(
            c,
            m3.exchange_id,
            OP_STATUS_REPORT,
            ProtocolId::SECURE_CHANNEL,
            true,
            Some(m3.message_counter),
            m3.source_node_id.or(m1.source_node_id),
            &body,
        );
        self.send(&report, peer).await?;

        // Absorb the initiator's standalone ack of our StatusReport.
        let _ack = self.recv().await?;
        Ok(())
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
        let (mut sessions, sid, peer) = self.accept_case(None).await?;

        let mut dispatched = 0usize;
        while dispatched < max_invokes {
            let (wire, _) = self.recv_secured(&mut sessions, peer).await?;
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
    /// `ApplyUpdateRequest` → `ApplyUpdateResponse` (Proceed). Completes once
    /// the apply is delivered — after a short same-session grace window for an
    /// in-process requestor's `NotifyUpdateApplied` (answered with Success). A
    /// real requestor reboots into the new image and sends
    /// `NotifyUpdateApplied` over a FRESH session on its next boot, which this
    /// single-session server intentionally does not serve.
    ///
    /// The fresh [`ResumptionRecord`] the accept handshake produced is re-seeded
    /// and forwarded to the `record_sink` (if set via
    /// [`Self::with_record_sink`]) before the OTA dispatch loop begins — the
    /// caller need not wait for the full OTA flow to persist the rotation.
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
    /// unexpected OTA command, or if the flow ends without reaching
    /// `ApplyUpdateRequest`; [`Error::Transport`] / [`Error::InteractionModel`]
    /// from the session / IM layers.
    #[allow(clippy::too_many_lines)] // Linear OTA protocol-dispatch loop; splitting hurts clarity.
    pub async fn serve_ota_once(
        mut self,
        offer: matter_ota::ImageOffer,
        image: Vec<u8>,
        max_block_size: u16,
    ) -> Result<(), Error> {
        use matter_bdx::{BdxMessage, BlockSender, MessageType, SenderOutcome};

        let (mut sessions, sid, peer) = self.accept_case(None).await?;
        let mut bdx: Option<BlockSender> = None;
        let mut applied = false;
        let mut apply_confirmed = false;

        // Same-session NotifyUpdateApplied grace window. A REAL requestor
        // (chip's app and real devices alike) sends NotifyUpdateApplied only
        // AFTER rebooting into the new image — over a fresh CASE session this
        // single-session server does not serve — so once ApplyUpdateResponse
        // (Proceed) is delivered the provider's job is done. We linger briefly
        // for an in-process requestor's same-session Notify (the loopback
        // floor), then complete successfully.
        let notify_grace = std::time::Duration::from_secs(3);

        // Generous step bound: one per OTA command + one per block + slack.
        let max_steps = image.len() / usize::from(max_block_size.max(1)) + 64;
        let mut steps = 0usize;

        while !applied && steps < max_steps {
            steps += 1;
            let (wire, _) = if apply_confirmed {
                match tokio::time::timeout(notify_grace, self.recv_secured(&mut sessions, peer))
                    .await
                {
                    Ok(result) => result?,
                    // Grace expired with the apply delivered: the requestor is
                    // rebooting into the image — done.
                    Err(_) => break,
                }
            } else {
                self.recv_secured(&mut sessions, peer).await?
            };
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
                    apply_confirmed = true;
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

        if applied || apply_confirmed {
            Ok(())
        } else {
            Err(Error::Operational(
                "OTA flow ended without ApplyUpdateRequest or NotifyUpdateApplied".into(),
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

    /// An empty credential pool must fail fast (before any IO) with the
    /// canonical error message. This exercises the pool-exhaustion guard in
    /// `accept_case` without requiring a real CASE peer.
    #[tokio::test]
    async fn empty_credential_pool_errors_before_any_io() {
        let (io, _peer) = matter_commissioning::driver::InMemoryDatagram::pair();
        let server = ProviderServer::new(
            io,
            Vec::new(),
            TrustedRoots::new(),
            0x10,
            MatterTime::from_unix_secs(2_000_000_000),
        );
        let offer = matter_ota::ImageOffer {
            software_version: 2,
            software_version_string: "2.0".into(),
            image_uri: "bdx://0/fw.ota".into(),
            update_token: vec![0xAB; 16],
        };
        let err = server
            .serve_ota_once(offer, vec![0u8; 16], 960)
            .await
            .expect_err("empty pool must fail fast");
        assert!(
            err.to_string().contains("credential pool exhausted"),
            "unexpected error: {err}"
        );
    }
}
