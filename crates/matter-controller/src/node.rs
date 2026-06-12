//! A cheap handle addressing one device node. Holds no session state.

use tokio::sync::oneshot;

use matter_codec::{Tag, TlvReader, TlvWriter, Value};
use matter_interaction::{
    build_invoke_request, build_read_request_paths, build_write_request, parse_invoke_response,
    parse_write_response, AttributePath, AttributeWriteRequest, CommandPath, ImStatus,
    InvokeResponse, ReadPath, ReportAccumulator, ReportData,
};

use crate::actor::Command;
use crate::error::Error;

pub(crate) const OP_READ_REQUEST: u8 = 0x02;
const OP_WRITE_REQUEST: u8 = 0x06;
const OP_INVOKE_REQUEST: u8 = 0x08;

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
    /// Crate-internal: M8.4 layers typed read/write/invoke on top.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`] if the owning task has stopped, or any
    /// connect / transport / driver error.
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
            acc.push(chunk);
        }
        Ok(acc.finish())
    }

    /// Write attributes. Each `Value` is TLV-encoded into the write payload.
    /// Returns the per-path statuses the device reported.
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
        let req = build_write_request(&reqs);
        let resp = self
            .round_trip(
                OP_WRITE_REQUEST,
                matter_transport::ProtocolId::INTERACTION_MODEL,
                req,
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
        let req = build_invoke_request(path, &fields_tlv);
        let resp = self
            .round_trip(
                OP_INVOKE_REQUEST,
                matter_transport::ProtocolId::INTERACTION_MODEL,
                req,
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

    /// Subscribe to attribute reports for `paths` (concrete or wildcard). The
    /// device reports the priming values, then changes within
    /// `[min_interval, max_interval]` seconds. Await reports via
    /// [`Subscription::next`](crate::subscription::Subscription::next).
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`] if the owning task stopped, or any
    /// connect / transport / interaction-model error while establishing the
    /// subscription.
    pub async fn subscribe(
        &self,
        paths: &[ReadPath],
        min_interval: u16,
        max_interval: u16,
    ) -> Result<crate::subscription::Subscription, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Subscribe {
                node_id: self.node_id,
                paths: paths.to_vec(),
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
