//! A live attribute subscription: reports arrive via [`Subscription::next`].

use matter_codec::Value;
use matter_interaction::AttributePath;
use matter_transport::SessionId;
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

/// A live attribute subscription. Await reports with [`Self::next`]; dropping
/// the handle cancels the subscription (best-effort).
pub struct Subscription {
    pub(crate) rx: mpsc::Receiver<AttributeReport>,
    pub(crate) tx: mpsc::Sender<Command>,
    pub(crate) key: (SessionId, u32),
    pub(crate) cancelled: bool,
}

impl Subscription {
    /// Await the next attribute report, or `None` once the subscription has
    /// ended (cancelled, or the controller task stopped).
    pub async fn next(&mut self) -> Option<AttributeReport> {
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
