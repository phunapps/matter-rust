//! A cheap handle addressing one device node. Holds no session state.

use tokio::sync::oneshot;

use matter_codec::{Tag, TlvReader, TlvWriter, Value};
use matter_interaction::{
    build_invoke_request, build_invoke_request_timed, build_read_request_full,
    build_read_request_paths, build_write_request, build_write_request_timed,
    parse_invoke_response, parse_write_response, AttributePath, AttributeWriteRequest, CommandPath,
    EventFilter, EventPath, EventReport, ImStatus, InvokeResponse, ReadPath, ReportAccumulator,
    ReportData,
};

use crate::actor::Command;
use crate::error::Error;

pub(crate) const OP_READ_REQUEST: u8 = 0x02;
const OP_WRITE_REQUEST: u8 = 0x06;
const OP_INVOKE_REQUEST: u8 = 0x08;

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
/// # Errors
///
/// Returns [`Error::Codec`] if the TLV writer fails.
fn value_to_tlv(value: &Value) -> Result<Vec<u8>, Error> {
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
