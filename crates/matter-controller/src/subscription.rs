//! A live attribute subscription: reports arrive via [`Subscription::next`].

use matter_codec::Value;
use matter_interaction::AttributePath;
use tokio::sync::mpsc;

use crate::actor::Command;
use crate::error::Error;

/// One reported attribute change from a subscription.
#[derive(Clone, Debug, PartialEq)]
pub struct AttributeReport {
    /// The concrete attribute path the device reported.
    pub path: AttributePath,
    /// The new value.
    pub value: Value,
}

/// An event from a live [`Subscription`].
#[derive(Debug)]
pub enum SubscriptionEvent {
    /// A reported attribute value (a priming value or a steady-state change).
    Report(AttributeReport),
    /// The subscription was (re-)established by the device; carries the
    /// device-assigned subscription id. Fired after each successful
    /// `SubscribeResponse`, including after an auto-resubscribe (SH.2b). Priming
    /// [`Self::Report`]s, if any, precede it (they arrive before the
    /// `SubscribeResponse` on the wire).
    Established {
        /// The device-assigned subscription id.
        subscription_id: u32,
    },
    /// The subscription went stale (liveness timeout or session loss) and is
    /// being transparently re-established; `cause` is why. Reports resume after
    /// the next [`Self::Established`]. Emitted by the SH.2b resubscribe engine.
    Resubscribing {
        /// Why the subscription is being re-established.
        cause: Error,
    },
}

/// A live attribute subscription. Await events with [`Self::next`]; dropping
/// the handle cancels the subscription (best-effort).
///
/// Events are buffered in an unbounded channel so a full re-prime (after an
/// auto-resubscribe) is never truncated. Call [`Self::next`] promptly: a handle
/// that is kept alive but never drained accumulates events in memory (bounded in
/// practice by the device's reporting cadence).
pub struct Subscription {
    pub(crate) rx: mpsc::UnboundedReceiver<SubscriptionEvent>,
    pub(crate) tx: mpsc::Sender<Command>,
    pub(crate) key: crate::actor::SubId,
    pub(crate) cancelled: bool,
}

impl Subscription {
    /// Await the next subscription event, or `None` once the subscription has
    /// ended (cancelled, or the controller task stopped).
    pub async fn next(&mut self) -> Option<SubscriptionEvent> {
        self.rx.recv().await
    }

    /// Cancel the subscription explicitly and stop receiving reports.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ControllerStopped`] if the owning task has already
    /// stopped (the subscription is effectively cancelled either way).
    pub async fn cancel(mut self) -> Result<(), Error> {
        self.cancelled = true;
        self.tx
            .send(Command::CancelSubscription { key: self.key })
            .await
            .map_err(|_| Error::ControllerStopped)
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if !self.cancelled {
            // Best-effort cancel on drop; ignore a full/closed channel.
            let _ = self
                .tx
                .try_send(Command::CancelSubscription { key: self.key });
        }
    }
}
