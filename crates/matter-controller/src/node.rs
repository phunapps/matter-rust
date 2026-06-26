//! A cheap handle addressing one device node. Holds no session state.

use tokio::sync::oneshot;

use matter_codec::{Tag, TlvReader, TlvWriter, Value};
use matter_interaction::{
    build_invoke_request, build_invoke_request_timed, build_list_write_chunks,
    build_read_request_full, build_read_request_paths, build_write_request,
    build_write_request_timed, parse_invoke_response, parse_write_response, AttributePath,
    AttributeWriteRequest, CommandPath, EventFilter, EventPath, EventReport, ImStatus,
    InvokeResponse, ReadPath, ReportAccumulator, ReportData,
};

use crate::actor::Command;
use crate::error::Error;

pub(crate) const OP_READ_REQUEST: u8 = 0x02;
const OP_WRITE_REQUEST: u8 = 0x06;
const OP_INVOKE_REQUEST: u8 = 0x08;

/// Budget for a single `WriteRequestMessage` when writing the ACL list.
/// Stays well under `MAX_PAYLOAD_LEN` (1024 post-encryption); reserves
/// headroom for the secured-message header, MRP acks, and AES tag.
const WRITE_CHUNK_BUDGET: usize = 800;

/// Default timed-interaction timeout (milliseconds) used by
/// [`Node::write_timed`] / [`Node::invoke_timed`] when the caller passes `None`.
///
/// This is the window the **device** holds open for the follow-up Write/Invoke
/// after our `TimedRequest`. We send the action immediately, so this only needs
/// to cover the round-trip plus MRP retransmits; a chip-aligned 10s is generous.
pub const TIMED_DEFAULT_MS: u16 = 10_000;

/// Outcome of [`Node::invoke`].
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum InvokeResult {
    /// The device returned a response command with (anonymous-tagged) fields.
    Data {
        /// The response command path.
        path: CommandPath,
        /// The decoded response fields.
        fields: Value,
    },
    /// The device returned a bare status (e.g. `Success`).
    Status(ImStatus),
}

/// Encode a `Value` into a standalone anonymous-tagged TLV blob.
///
/// Exposed as `pub(crate)` so tests in sibling modules can encode ACL entry
/// values for chunk-count calculations without reaching through the public API.
///
/// # Errors
///
/// Returns [`Error::Codec`] if the TLV writer fails.
pub(crate) fn value_to_tlv(value: &Value) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.write_value(Tag::Anonymous, value)?;
    Ok(buf)
}

/// Decode an anonymous-tagged TLV blob back into a `Value`.
///
/// # Errors
///
/// Returns [`Error::Codec`] if the TLV reader fails.
fn tlv_to_value(bytes: &[u8]) -> Result<Value, Error> {
    let mut r = TlvReader::new(bytes);
    let (_tag, value) = r.read_value()?;
    Ok(value)
}

/// Handle to one commissioned device. Obtain via
/// [`MatterController::node`](crate::controller::MatterController::node).
#[derive(Clone)]
pub struct Node {
    pub(crate) tx: tokio::sync::mpsc::Sender<Command>,
    pub(crate) node_id: u64,
}

impl Node {
    /// The device's operational node ID.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Send a raw secured Interaction-Model payload and await the response
    /// payload. Establishes/caches the CASE session transparently.
    ///
    /// A generic primitive retained for tests that exercise connect/cache/demux
    /// without IM payloads; the production verbs (`read`/`write`/`invoke`/
    /// `subscribe`) use the specialized actor commands.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`] if the owning task has stopped, or any
    /// connect / transport / driver error.
    #[cfg(test)]
    pub(crate) async fn round_trip(
        &self,
        opcode: u8,
        protocol_id: matter_transport::ProtocolId,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::RoundTrip {
                node_id: self.node_id,
                opcode,
                protocol_id,
                payload,
                reply,
            })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        rx.await.map_err(|_| Error::ControllerStopped)?
    }

    /// Send a chunked read request and collect every `ReportData` chunk payload
    /// in order. A non-chunked read yields a single-element `Vec`.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`] if the owning task has stopped, or any
    /// connect / transport / driver error.
    pub(crate) async fn round_trip_chunked(
        &self,
        payload: Vec<u8>,
    ) -> Result<Vec<ReportData>, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Read {
                node_id: self.node_id,
                payload,
                reply,
            })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        rx.await.map_err(|_| Error::ControllerStopped)?
    }

    /// Run a timed interaction: send a `TimedRequest`, await
    /// `StatusResponse(SUCCESS)`, then send `action_payload` (opcode
    /// `action_opcode`) on the same exchange and return its response bytes.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`] if the owning task stopped, or any
    /// connect / transport / driver error.
    pub(crate) async fn round_trip_timed(
        &self,
        timeout_ms: u16,
        action_opcode: u8,
        action_payload: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::TimedRoundTrip {
                node_id: self.node_id,
                timeout_ms,
                action_opcode,
                action_payload,
                reply,
            })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        rx.await.map_err(|_| Error::ControllerStopped)?
    }

    /// Send a multi-chunk write: each element of `chunks` is one
    /// `WriteRequestMessage` (built by
    /// [`build_list_write_chunks`](matter_interaction::build_list_write_chunks),
    /// which sets `MoreChunkedMessages` on all but the last). All chunks are sent
    /// reliably on ONE exchange; the device replies with a single
    /// `WriteResponseMessage` after the final chunk, whose bytes are returned.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`] if the owning task stopped, or any
    /// connect / transport / driver error.
    pub(crate) async fn chunked_write(&self, chunks: Vec<Vec<u8>>) -> Result<Vec<u8>, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::ChunkedWrite {
                node_id: self.node_id,
                chunks,
                reply,
            })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        rx.await.map_err(|_| Error::ControllerStopped)?
    }

    /// The controller's commissioner node id (the sole fabric's
    /// `commissioner.node_id`). Used by the ACL lockout guard to avoid writing
    /// an ACL that would lock the commissioner out of the device.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`] if the owning task stopped, or
    /// [`Error::NotCommissioned`] if no sole fabric exists.
    pub(crate) async fn commissioner_node_id(&self) -> Result<u64, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::CommissionerNodeId { reply })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        rx.await.map_err(|_| Error::ControllerStopped)?
    }

    /// Read attributes (concrete or wildcard paths). Returns the device's
    /// `(path, value)` reports keyed by the concrete paths it reports. Values
    /// are raw [`Value`]; decode them with `matter-clusters` codecs.
    ///
    /// A wildcard read (e.g. [`ReadPath::all`]) whose response spans multiple
    /// `ReportData` chunks is reassembled transparently — every chunk is
    /// solicited and merged through [`ReportAccumulator`], so the result is the
    /// device's complete attribute set, not just the first chunk.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`], any connect/transport error, or
    /// [`Error::InteractionModel`] if a response chunk cannot be parsed.
    pub async fn read(&self, paths: &[ReadPath]) -> Result<Vec<(AttributePath, Value)>, Error> {
        let req = build_read_request_paths(paths);
        // Chunks arrive already parsed (the actor's receive path parses each
        // `ReportData` exactly once); merge them without re-walking the TLV.
        let chunks = self.round_trip_chunked(req).await?;
        let mut acc = ReportAccumulator::new();
        for chunk in chunks {
            acc.push(chunk)?;
        }
        Ok(acc.finish())
    }

    /// Read events for the given (concrete or wildcard) event paths, optionally
    /// filtered to events with number `>= event_min` (via [`EventFilter`]).
    /// Returns every reported [`EventReport`] in wire order, reassembled across
    /// chunks. Decode the event payloads with `matter-clusters` codecs.
    ///
    /// Events are discrete records (not list attributes), so — unlike
    /// [`read`](Self::read) — there is no merge step: each chunk's events are
    /// concatenated in arrival order.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`], any connect/transport error, or
    /// [`Error::InteractionModel`] if a response chunk cannot be parsed.
    pub async fn read_events(
        &self,
        paths: &[EventPath],
        filters: &[EventFilter],
    ) -> Result<Vec<EventReport>, Error> {
        let req = build_read_request_full(&[], paths, filters);
        let chunks = self.round_trip_chunked(req).await?;
        let mut events = Vec::new();
        for chunk in chunks {
            events.extend(chunk.events);
        }
        Ok(events)
    }

    /// Run a write/invoke `Action` through the actor: the actor consults the
    /// learned timed-cache (skips the plain attempt for known-timed paths) and
    /// transparently retries timed on a `NEEDS_TIMED_INTERACTION` rejection.
    /// Returns the final response bytes.
    async fn action(
        &self,
        opcode: u8,
        plain_payload: Vec<u8>,
        timed_payload: Vec<u8>,
        keys: Vec<(u32, u32)>,
    ) -> Result<Vec<u8>, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Action {
                node_id: self.node_id,
                opcode,
                plain_payload,
                timed_payload,
                keys,
                timeout_ms: TIMED_DEFAULT_MS,
                reply,
            })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        rx.await.map_err(|_| Error::ControllerStopped)?
    }

    /// Write attributes. Each `Value` is TLV-encoded into the write payload.
    /// Returns the per-path statuses the device reported.
    ///
    /// Timed writes are handled transparently: if the device rejects the write
    /// with `NEEDS_TIMED_INTERACTION`, the controller retries it as a timed
    /// interaction and remembers the path so later writes skip the wasted attempt.
    /// Use [`write_timed`](Self::write_timed) to force the timed path explicitly.
    ///
    /// # Errors
    ///
    /// As [`Self::read`], plus [`Error::Codec`] if a value fails to encode.
    pub async fn write(
        &self,
        writes: &[(AttributePath, Value)],
    ) -> Result<Vec<(AttributePath, ImStatus)>, Error> {
        let mut reqs = Vec::with_capacity(writes.len());
        for (path, value) in writes {
            reqs.push(AttributeWriteRequest {
                path: *path,
                value_tlv: value_to_tlv(value)?,
            });
        }
        let keys = writes
            .iter()
            .map(|(p, _)| (p.cluster, p.attribute))
            .collect();
        let resp = self
            .action(
                OP_WRITE_REQUEST,
                build_write_request(&reqs),
                build_write_request_timed(&reqs),
                keys,
            )
            .await?;
        Ok(parse_write_response(&resp)?)
    }

    /// Like [`write`](Self::write) but always performs a **timed** interaction:
    /// a `TimedRequest` precedes the write (required by some attributes, e.g.
    /// certain `DoorLock` settings). `timeout_ms` defaults to [`TIMED_DEFAULT_MS`].
    ///
    /// Plain [`write`](Self::write) already auto-upgrades to timed on a
    /// `NEEDS_TIMED_INTERACTION` rejection; use this when you want to force the
    /// timed path explicitly (e.g. to avoid the first wasted round-trip, or for
    /// testing).
    ///
    /// # Errors
    ///
    /// As [`Self::write`].
    pub async fn write_timed(
        &self,
        writes: &[(AttributePath, Value)],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<(AttributePath, ImStatus)>, Error> {
        let mut reqs = Vec::with_capacity(writes.len());
        for (path, value) in writes {
            reqs.push(AttributeWriteRequest {
                path: *path,
                value_tlv: value_to_tlv(value)?,
            });
        }
        let payload = build_write_request_timed(&reqs);
        let resp = self
            .round_trip_timed(
                timeout_ms.unwrap_or(TIMED_DEFAULT_MS),
                OP_WRITE_REQUEST,
                payload,
            )
            .await?;
        Ok(parse_write_response(&resp)?)
    }

    /// Invoke a command with raw `Value` fields (TLV-encoded into the payload).
    ///
    /// # Errors
    ///
    /// As [`Self::read`], plus [`Error::Codec`] if the fields fail to encode
    /// or the response fields cannot be decoded.
    pub async fn invoke(&self, path: CommandPath, fields: Value) -> Result<InvokeResult, Error> {
        let fields_tlv = value_to_tlv(&fields)?;
        let resp = self
            .action(
                OP_INVOKE_REQUEST,
                build_invoke_request(path, &fields_tlv),
                build_invoke_request_timed(path, &fields_tlv),
                vec![(path.cluster, path.command)],
            )
            .await?;
        match parse_invoke_response(&resp)? {
            InvokeResponse::Status(s) => Ok(InvokeResult::Status(s)),
            InvokeResponse::Command { path, fields_tlv } => Ok(InvokeResult::Data {
                path,
                fields: tlv_to_value(&fields_tlv)?,
            }),
        }
    }

    /// Like [`invoke`](Self::invoke) but always performs a **timed** interaction
    /// (a `TimedRequest` precedes the command — required by some commands, e.g.
    /// `DoorLock` lock/unlock). `timeout_ms` defaults to [`TIMED_DEFAULT_MS`].
    ///
    /// Plain [`invoke`](Self::invoke) already auto-upgrades to timed on a
    /// `NEEDS_TIMED_INTERACTION` rejection; use this to force the timed path.
    ///
    /// # Errors
    ///
    /// As [`Self::invoke`].
    pub async fn invoke_timed(
        &self,
        path: CommandPath,
        fields: Value,
        timeout_ms: Option<u16>,
    ) -> Result<InvokeResult, Error> {
        let fields_tlv = value_to_tlv(&fields)?;
        let payload = build_invoke_request_timed(path, &fields_tlv);
        let resp = self
            .round_trip_timed(
                timeout_ms.unwrap_or(TIMED_DEFAULT_MS),
                OP_INVOKE_REQUEST,
                payload,
            )
            .await?;
        match parse_invoke_response(&resp)? {
            InvokeResponse::Status(s) => Ok(InvokeResult::Status(s)),
            InvokeResponse::Command { path, fields_tlv } => Ok(InvokeResult::Data {
                path,
                fields: tlv_to_value(&fields_tlv)?,
            }),
        }
    }

    /// Read `AdministratorCommissioning` `WindowStatus`, `AdminFabricIndex`, and
    /// `AdminVendorId` from endpoint 0. Returns a snapshot of the current
    /// commissioning-window state.
    ///
    /// # Errors
    ///
    /// An interaction error if the read fails.
    pub async fn commissioning_window_status(&self) -> Result<crate::admin::WindowStatus, Error> {
        use crate::admin::{
            ADMIN_COMMISSIONING_CLUSTER, ATTR_ADMIN_FABRIC_INDEX, ATTR_ADMIN_VENDOR_ID,
            ATTR_WINDOW_STATUS,
        };
        let paths = [
            ReadPath::concrete(0, ADMIN_COMMISSIONING_CLUSTER, ATTR_WINDOW_STATUS),
            ReadPath::concrete(0, ADMIN_COMMISSIONING_CLUSTER, ATTR_ADMIN_FABRIC_INDEX),
            ReadPath::concrete(0, ADMIN_COMMISSIONING_CLUSTER, ATTR_ADMIN_VENDOR_ID),
        ];
        let reports = self.read(&paths).await?;
        Ok(crate::admin::parse_window_status(&reports))
    }

    /// Read the device's `Fabrics` list (every fabric it is commissioned onto).
    ///
    /// # Errors
    ///
    /// An interaction error if the read fails.
    pub async fn list_fabrics(&self) -> Result<Vec<crate::opcreds::FabricDescriptor>, Error> {
        let paths = [ReadPath::concrete(
            0,
            crate::opcreds::OPERATIONAL_CREDENTIALS_CLUSTER,
            crate::opcreds::ATTR_FABRICS,
        )];
        let reports = self.read(&paths).await?;
        Ok(crate::opcreds::parse_fabrics(&reports))
    }

    /// Write the device's `AccessControl.Acl` list to exactly `entries`.
    ///
    /// Refuses (before sending) any list that would strip our own administrative
    /// access ([`Error::AclWouldLockOut`]). Small lists go in one
    /// `WriteRequestMessage` (byte-identical to a normal write); larger lists are
    /// chunked (`ReplaceAll`+`AppendItem`) without ever sending an empty `ReplaceAll`.
    ///
    /// ACL writes are NOT timed (the spec does not require `TimedRequest` for
    /// `AccessControl.Acl`); however, if the device unexpectedly rejects the write
    /// with `NEEDS_TIMED_INTERACTION` the controller's timed-auto-upgrade will
    /// transparently retry on the single-chunk path (the same bytes are safe to
    /// re-send because the whole list is idempotent). The multi-chunk path fails
    /// cleanly on a `0xc6` rejection (the `ChunkedWrite` pending does not carry
    /// a `timed_payload`).
    ///
    /// # Errors
    ///
    /// [`Error::AclWouldLockOut`] if `entries` contains no Administer/CASE entry
    /// covering our commissioner node id; no bytes are sent to the device in that
    /// case. Otherwise returns an interaction error or a per-path device status.
    pub async fn write_acl(
        &self,
        entries: &[crate::acl::AclEntry],
    ) -> Result<Vec<(AttributePath, ImStatus)>, Error> {
        self.write_acl_with_budget(entries, WRITE_CHUNK_BUDGET)
            .await
    }

    /// Inner implementation of [`write_acl`](Node::write_acl) with an injectable
    /// per-chunk byte budget.
    ///
    /// The lockout guard runs before any bytes are sent to the device, regardless
    /// of the budget. `budget` controls the `build_list_write_chunks` split point;
    /// the production verb always passes [`WRITE_CHUNK_BUDGET`] (800 bytes).
    ///
    /// Exposed as `pub(crate)` so tests can force a small budget (e.g. 40 bytes)
    /// to exercise the multi-chunk dispatch branch through `write_acl` itself
    /// rather than calling `chunked_write` directly.
    ///
    /// # Errors
    ///
    /// [`Error::AclWouldLockOut`] if `entries` contains no Administer/CASE entry
    /// covering our commissioner node id; no bytes are sent to the device in that
    /// case. Otherwise returns an interaction error or a per-path device status.
    pub(crate) async fn write_acl_with_budget(
        &self,
        entries: &[crate::acl::AclEntry],
        budget: usize,
    ) -> Result<Vec<(AttributePath, ImStatus)>, Error> {
        // Lockout guard MUST run before any network I/O.
        let our = self.commissioner_node_id().await?;
        if !crate::acl::acl_retains_admin(entries, our) {
            return Err(Error::AclWouldLockOut);
        }
        let path = AttributePath {
            endpoint: 0,
            cluster: crate::acl::ACCESS_CONTROL_CLUSTER,
            attribute: crate::acl::ATTR_ACL,
        };
        let element_tlvs: Vec<Vec<u8>> = entries
            .iter()
            .map(|e| value_to_tlv(&crate::acl::acl_entry_value(e)))
            .collect::<Result<_, _>>()?;
        let chunks = build_list_write_chunks(path, &element_tlvs, budget, false);
        let resp = if chunks.len() == 1 {
            // Single message: reuse the plain Action path (byte-identical to a
            // normal write, 0xc6 auto-upgrade intact). Pass `chunks[0]` as both
            // plain and timed payload so the retry — if the device demands timed —
            // re-sends identical bytes (safe for a full-list replace).
            self.action(
                OP_WRITE_REQUEST,
                chunks[0].clone(),
                chunks[0].clone(),
                vec![(path.cluster, path.attribute)],
            )
            .await?
        } else {
            self.chunked_write(chunks).await?
        };
        Ok(parse_write_response(&resp)?)
    }

    /// Read the device's `AccessControl.Acl` list (the ACL entries on this fabric).
    ///
    /// # Errors
    ///
    /// An interaction error if the read fails.
    pub async fn read_acl(&self) -> Result<Vec<crate::acl::AclEntry>, Error> {
        let paths = [ReadPath::concrete(
            0,
            crate::acl::ACCESS_CONTROL_CLUSTER,
            crate::acl::ATTR_ACL,
        )];
        let reports = self.read(&paths).await?;
        Ok(crate::acl::parse_acl(&reports))
    }

    /// Open an enhanced commissioning window using **caller-supplied** secrets
    /// (test/power-user seam). Most callers want
    /// `Node::open_commissioning_window` (Task 3), which generates the secrets.
    ///
    /// Computes the PAKE passcode verifier from `passcode`/`salt`/`iterations`,
    /// invokes `OpenCommissioningWindow` (a **timed** invoke — `AdminComm` requires
    /// it), and returns the onboarding payload.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommissioningWindowRejected`] if the device rejects the
    /// command, or a crypto/interaction error.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_commissioning_window_with(
        &self,
        timeout_s: u16,
        passcode: u32,
        salt: &[u8],
        discriminator: u16,
        iterations: u32,
        vendor_id: Option<u16>,
        product_id: Option<u16>,
    ) -> Result<crate::admin::CommissioningWindow, Error> {
        let verifier = matter_crypto::pake_passcode_verifier(passcode, salt, iterations)
            .map_err(|e| Error::Operational(format!("verifier: {e}")))?;
        let fields =
            crate::admin::open_window_fields(timeout_s, &verifier, discriminator, iterations, salt);
        let path = CommandPath {
            endpoint: 0,
            cluster: crate::admin::ADMIN_COMMISSIONING_CLUSTER,
            command: crate::admin::CMD_OPEN_COMMISSIONING_WINDOW,
        };
        self.admin_timed_command(path, fields).await?;
        let (manual_code, qr_code) =
            crate::admin::onboarding_payload(passcode, discriminator, vendor_id, product_id)?;
        Ok(crate::admin::CommissioningWindow {
            passcode,
            discriminator,
            iterations,
            salt: salt.to_vec(),
            manual_code,
            qr_code,
        })
    }

    /// Open an enhanced commissioning window so a second admin can commission
    /// this device onto its own fabric. Generates a fresh passcode/salt/
    /// discriminator, computes the PAKE verifier, and returns the onboarding
    /// payload (manual pairing code, plus QR when `opts.vendor_id`/`product_id`
    /// are set). The `AdminComm` command is sent as a timed invoke.
    ///
    /// # Errors
    /// Returns [`Error::CommissioningWindowRejected`] if the device rejects it,
    /// or a crypto/RNG/interaction error.
    pub async fn open_commissioning_window(
        &self,
        opts: crate::admin::OpenWindowOpts,
    ) -> Result<crate::admin::CommissioningWindow, Error> {
        let (passcode, salt, discriminator) = crate::admin::random_window_secrets()?;
        self.open_commissioning_window_with(
            opts.timeout_s,
            passcode,
            &salt,
            discriminator,
            opts.iterations,
            opts.vendor_id,
            opts.product_id,
        )
        .await
    }

    /// Open a *basic* commissioning window (reuses the device's original
    /// passcode — no new onboarding payload). Timed invoke.
    ///
    /// # Errors
    /// [`Error::CommissioningWindowRejected`] on device rejection, else an
    /// interaction error.
    pub async fn open_basic_commissioning_window(&self, timeout_s: u16) -> Result<(), Error> {
        let fields = matter_codec::Value::Structure(vec![(
            matter_codec::Tag::Context(0),
            matter_codec::Value::Uint(u64::from(timeout_s)),
        )]);
        let path = CommandPath {
            endpoint: 0,
            cluster: crate::admin::ADMIN_COMMISSIONING_CLUSTER,
            command: crate::admin::CMD_OPEN_BASIC_COMMISSIONING_WINDOW,
        };
        self.admin_timed_command(path, fields).await
    }

    /// Revoke any open commissioning window. Timed invoke. Returns `Ok(())`
    /// even if no window was open (the device reports `WindowNotOpen`, which is
    /// surfaced as [`Error::CommissioningWindowRejected`] only on a hard IM
    /// failure).
    ///
    /// # Errors
    /// [`Error::CommissioningWindowRejected`] on device rejection.
    pub async fn revoke_commissioning(&self) -> Result<(), Error> {
        let fields = matter_codec::Value::Structure(vec![]);
        let path = CommandPath {
            endpoint: 0,
            cluster: crate::admin::ADMIN_COMMISSIONING_CLUSTER,
            command: crate::admin::CMD_REVOKE_COMMISSIONING,
        };
        self.admin_timed_command(path, fields).await
    }

    /// Shared helper: timed-invoke an `AdminComm` command expecting a bare
    /// success status. Maps `Success` to `Ok(())`, `Failure(code)` to
    /// [`Error::CommissioningWindowRejected`], any other `Status(_)` variant
    /// (catch-all for `#[non_exhaustive]` future codes) to an operational
    /// error, and any response command to an operational error.
    async fn admin_timed_command(
        &self,
        path: CommandPath,
        fields: matter_codec::Value,
    ) -> Result<(), Error> {
        match self.invoke_timed(path, fields, None).await? {
            InvokeResult::Status(ImStatus::Success) => Ok(()),
            InvokeResult::Status(ImStatus::Failure(code)) => {
                Err(Error::CommissioningWindowRejected(code))
            }
            InvokeResult::Status(_) => Err(Error::Operational(
                "unrecognised IM status for admin command".into(),
            )),
            InvokeResult::Data { .. } => {
                Err(Error::Operational("unexpected response command".into()))
            }
        }
    }

    /// Remove a fabric from the device by its `fabric_index`.
    ///
    /// Reads `CurrentFabricIndex` first and refuses to remove our OWN fabric
    /// (that would sever this CASE session and orphan persisted state) with
    /// [`Error::WouldRemoveSelf`]. There is intentionally no `force` override.
    ///
    /// # Errors
    /// [`Error::WouldRemoveSelf`] if `fabric_index` is our own;
    /// [`Error::Operational`] if the device does not return a readable
    /// `CurrentFabricIndex` — the call fails without invoking `RemoveFabric` in
    /// that case (fail-closed on a destructive operation);
    /// [`Error::OperationalCredentialsRejected`] if the device rejects it (e.g.
    /// 7 `InvalidFabricIndex`); else an interaction error.
    pub async fn remove_fabric(&self, fabric_index: u8) -> Result<(), Error> {
        // Self-protection: CurrentFabricIndex over our session is OUR fabric's
        // index here. Must check BEFORE invoking — this is a destructive op.
        let cur = self
            .read(&[ReadPath::concrete(
                0,
                crate::opcreds::OPERATIONAL_CREDENTIALS_CLUSTER,
                crate::opcreds::ATTR_CURRENT_FABRIC_INDEX,
            )])
            .await?;
        // Fail CLOSED: if we cannot read CurrentFabricIndex we refuse to
        // proceed. The equality guard `== Some(fabric_index)` would silently
        // fall through when `parse_current_fabric_index` returns `None`,
        // allowing RemoveFabric on an unverified index.
        let cur_idx = crate::opcreds::parse_current_fabric_index(&cur).ok_or_else(|| {
            Error::Operational(
                "could not read CurrentFabricIndex; refusing remove_fabric for safety".into(),
            )
        })?;
        if cur_idx == fabric_index {
            return Err(Error::WouldRemoveSelf);
        }
        let fields = Value::Structure(vec![(
            matter_codec::Tag::Context(0),
            Value::Uint(u64::from(fabric_index)),
        )]);
        let path = CommandPath {
            endpoint: 0,
            cluster: crate::opcreds::OPERATIONAL_CREDENTIALS_CLUSTER,
            command: crate::opcreds::CMD_REMOVE_FABRIC,
        };
        match self.invoke(path, fields).await? {
            InvokeResult::Data { fields, .. } => {
                let status = crate::opcreds::parse_noc_response(&fields);
                crate::opcreds::noc_status_to_result(&status)
            }
            InvokeResult::Status(ImStatus::Success) => Ok(()),
            InvokeResult::Status(ImStatus::Failure(code)) => {
                Err(Error::OperationalCredentialsRejected(code))
            }
            InvokeResult::Status(_) => Err(Error::Operational(
                "unexpected status for RemoveFabric".into(),
            )),
        }
    }

    /// Update the label of OUR fabric on the device (`UpdateFabricLabel` acts on
    /// the accessing fabric; there is no index argument).
    ///
    /// # Errors
    /// [`Error::OperationalCredentialsRejected`] if the device rejects it
    /// (e.g. 9 `LabelConflict`); else an interaction error.
    pub async fn update_fabric_label(&self, label: &str) -> Result<(), Error> {
        let fields = Value::Structure(vec![(
            matter_codec::Tag::Context(0),
            Value::Utf8(label.to_string()),
        )]);
        let path = CommandPath {
            endpoint: 0,
            cluster: crate::opcreds::OPERATIONAL_CREDENTIALS_CLUSTER,
            command: crate::opcreds::CMD_UPDATE_FABRIC_LABEL,
        };
        match self.invoke(path, fields).await? {
            InvokeResult::Data { fields, .. } => {
                let status = crate::opcreds::parse_noc_response(&fields);
                crate::opcreds::noc_status_to_result(&status)
            }
            InvokeResult::Status(ImStatus::Success) => Ok(()),
            InvokeResult::Status(ImStatus::Failure(code)) => {
                Err(Error::OperationalCredentialsRejected(code))
            }
            InvokeResult::Status(_) => Err(Error::Operational(
                "unexpected status for UpdateFabricLabel".into(),
            )),
        }
    }

    /// Add the device endpoint to a group (`Groups.AddGroup`). The endpoint then
    /// joins the group's multicast address and accepts group commands.
    ///
    /// # Errors
    ///
    /// [`Error::GroupCommandRejected`] on a non-success status; else interaction error.
    pub async fn add_group(&self, endpoint: u16, group_id: u16, name: &str) -> Result<(), Error> {
        self.group_command(
            endpoint,
            crate::group::CMD_ADD_GROUP,
            crate::group::add_group_fields(group_id, name),
        )
        .await
    }

    /// Remove the device endpoint from a group (`Groups.RemoveGroup`).
    ///
    /// # Errors
    ///
    /// [`Error::GroupCommandRejected`] on a non-success status; else interaction error.
    pub async fn remove_group(&self, endpoint: u16, group_id: u16) -> Result<(), Error> {
        self.group_command(
            endpoint,
            crate::group::CMD_REMOVE_GROUP,
            crate::group::remove_group_fields(group_id),
        )
        .await
    }

    /// Shared: invoke a `Groups` command and map its response-status to `()`/error.
    ///
    /// `AddGroup`/`RemoveGroup` both return a response command whose `status` field
    /// (context tag 0) is 0 on success or a non-zero `GroupClusterStatus` code on
    /// failure. A bare `Success` IM status is also accepted (some devices skip the
    /// response command on success); bare `Failure` codes become
    /// [`Error::GroupCommandRejected`].
    async fn group_command(&self, endpoint: u16, command: u32, fields: Value) -> Result<(), Error> {
        let path = CommandPath {
            endpoint,
            cluster: crate::group::GROUPS_CLUSTER,
            command,
        };
        match self.invoke(path, fields).await? {
            InvokeResult::Data { fields, .. } => {
                let status = crate::group::parse_group_status(&fields);
                if status == 0 {
                    Ok(())
                } else {
                    Err(Error::GroupCommandRejected(status))
                }
            }
            InvokeResult::Status(ImStatus::Success) => Ok(()),
            InvokeResult::Status(ImStatus::Failure(code)) => Err(Error::GroupCommandRejected(code)),
            InvokeResult::Status(_) => Err(Error::Operational(
                "unexpected status for Groups command".into(),
            )),
        }
    }

    /// Provision a group key set on the device via `KeySetWrite`
    /// (`GroupKeyManagement` cluster, endpoint 0). The epoch key is the
    /// group's symmetric key material. Returns `Ok(())` on a bare
    /// `Success` status from the device.
    ///
    /// `KeySetWrite` is NOT a timed command — the plain `invoke` path is used.
    ///
    /// # Errors
    ///
    /// [`Error::GroupCommandRejected`] if the device returns a non-success IM
    /// status (e.g. `ResourceExhausted`). An interaction or transport error is
    /// surfaced as its corresponding [`Error`] variant.
    pub async fn write_group_key_set(&self, set: &crate::group::GroupKeySet) -> Result<(), Error> {
        let path = CommandPath {
            endpoint: 0,
            cluster: crate::group::GROUP_KEY_MANAGEMENT_CLUSTER,
            command: crate::group::CMD_KEY_SET_WRITE,
        };
        match self
            .invoke(path, crate::group::key_set_write_fields(set))
            .await?
        {
            InvokeResult::Status(ImStatus::Success) => Ok(()),
            InvokeResult::Status(ImStatus::Failure(code)) => Err(Error::GroupCommandRejected(code)),
            InvokeResult::Status(_) => Err(Error::Operational(
                "unexpected status for KeySetWrite".into(),
            )),
            InvokeResult::Data { .. } => Err(Error::Operational(
                "unexpected response command for KeySetWrite".into(),
            )),
        }
    }

    /// Write the device's `GroupKeyMap` list (binds group ids to key sets).
    ///
    /// Small lists go in one `WriteRequestMessage` (byte-identical to a normal
    /// write); larger lists are chunked (`ReplaceAll`+`AppendItem`) without ever
    /// sending an empty `ReplaceAll`. There is no lockout guard — `GroupKeyMap`
    /// has no self-lock concern unlike `AccessControl.Acl`.
    ///
    /// `GroupKeyMap` writes are NOT timed (the spec does not require
    /// `TimedRequest`); however, if the device unexpectedly rejects the write with
    /// `NEEDS_TIMED_INTERACTION` the controller's timed-auto-upgrade will
    /// transparently retry on the single-chunk path.
    ///
    /// # Errors
    ///
    /// Returns an interaction error or a per-path device status from the device.
    pub async fn write_group_key_map(
        &self,
        entries: &[crate::group::GroupKeyMapEntry],
    ) -> Result<Vec<(AttributePath, ImStatus)>, Error> {
        let path = AttributePath {
            endpoint: 0,
            cluster: crate::group::GROUP_KEY_MANAGEMENT_CLUSTER,
            attribute: crate::group::ATTR_GROUP_KEY_MAP,
        };
        let element_tlvs: Vec<Vec<u8>> = entries
            .iter()
            .map(|e| value_to_tlv(&crate::group::group_key_map_entry_value(*e)))
            .collect::<Result<_, _>>()?;
        let chunks = build_list_write_chunks(path, &element_tlvs, WRITE_CHUNK_BUDGET, false);
        let resp = if chunks.len() == 1 {
            // Single message: reuse the plain Action path (byte-identical to a
            // normal write, 0xc6 auto-upgrade intact). Pass `chunks[0]` as both
            // plain and timed payload so the retry — if the device demands timed —
            // re-sends identical bytes (safe for a full-list replace).
            self.action(
                OP_WRITE_REQUEST,
                chunks[0].clone(),
                chunks[0].clone(),
                vec![(path.cluster, path.attribute)],
            )
            .await?
        } else {
            self.chunked_write(chunks).await?
        };
        Ok(parse_write_response(&resp)?)
    }

    /// Subscribe to attribute reports for `attrs` and/or event reports for
    /// `events` (concrete or wildcard paths) on a **single** subscription. The
    /// device sends the priming values/events, then steady-state changes within
    /// `[min_interval, max_interval]` seconds. Await
    /// [`SubscriptionEvent`](crate::subscription::SubscriptionEvent)s — both
    /// `Report` (attributes) and `Event` (events) — via
    /// [`Subscription::next`](crate::subscription::Subscription::next).
    ///
    /// Pass an empty slice for either to subscribe to only the other. The
    /// subscription auto-resubscribes transparently on staleness/session loss,
    /// re-requesting the same attribute and event paths.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`] if the owning task stopped, or any
    /// connect / transport / interaction-model error while establishing the
    /// subscription.
    pub async fn subscribe(
        &self,
        attrs: &[ReadPath],
        events: &[EventPath],
        min_interval: u16,
        max_interval: u16,
    ) -> Result<crate::subscription::Subscription, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Subscribe {
                node_id: self.node_id,
                paths: attrs.to_vec(),
                event_paths: events.to_vec(),
                event_filters: Vec::new(),
                min_interval,
                max_interval,
                reply,
            })
            .await
            .map_err(|_| Error::ControllerStopped)?;
        let (receivers, key) = rx.await.map_err(|_| Error::ControllerStopped)??;
        Ok(crate::subscription::Subscription {
            rx: receivers.report_rx,
            ctrl_rx: receivers.ctrl_rx,
            tx: self.tx.clone(),
            key,
            cancelled: false,
        })
    }
}
