//! A cheap handle addressing one device node. Holds no session state.

use tokio::sync::oneshot;

use matter_codec::{Tag, TlvReader, TlvWriter, Value};
use matter_interaction::{
    build_invoke_request, build_read_request_paths, build_write_request, parse_invoke_response,
    parse_report_data, parse_write_response, AttributePath, AttributeWriteRequest, CommandPath,
    ImStatus, InvokeResponse, ReadPath,
};

use crate::actor::Command;
use crate::error::Error;

const OP_READ_REQUEST: u8 = 0x02;
const OP_WRITE_REQUEST: u8 = 0x06;
const OP_INVOKE_REQUEST: u8 = 0x08;

/// Outcome of [`Node::invoke`].
#[derive(Clone, Debug, PartialEq)]
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

    /// Read attributes (concrete or wildcard paths). Returns the device's
    /// `(path, value)` reports keyed by the concrete paths it reports. Values
    /// are raw [`Value`]; decode them with `matter-clusters` codecs.
    ///
    /// # Errors
    ///
    /// [`Error::ControllerStopped`], any connect/transport error, or
    /// [`Error::InteractionModel`] if the response cannot be parsed.
    pub async fn read(&self, paths: &[ReadPath]) -> Result<Vec<(AttributePath, Value)>, Error> {
        let req = build_read_request_paths(paths);
        let resp = self
            .round_trip(
                OP_READ_REQUEST,
                matter_transport::ProtocolId::INTERACTION_MODEL,
                req,
            )
            .await?;
        Ok(parse_report_data(&resp)?.attributes)
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
}
