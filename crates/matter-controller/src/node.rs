//! A cheap handle addressing one device node. Holds no session state.

use tokio::sync::oneshot;

use crate::actor::Command;
use crate::error::Error;

/// Handle to one commissioned device. Obtain via
/// [`MatterController::node`](crate::controller::MatterController::node).
#[derive(Clone)]
pub struct Node {
    // `tx` is used by `round_trip` (Task 4 callers) and `session_count` (test).
    // Allow until M8.4 public callers land.
    #[allow(dead_code)]
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
    // Called by M8.4 typed verb wrappers and the Task 5 loopback test.
    #[allow(dead_code)]
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
}
