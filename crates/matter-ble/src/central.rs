//! BLE central role for Matter commissioning (feature `central`).
//!
//! Scans for a commissionable device by discriminator, connects, opens the
//! Matter BTP GATT service (C1 write / C2 indication), performs the BTP
//! handshake, and drives the resulting `BtpSession` from an async pump task,
//! exposing a `BtpChannel` that sends and receives whole Matter messages.
//!
//! **macOS Bluetooth permission (TCC):** `BleCentral::new` instantiates a
//! `CoreBluetooth` `CBCentralManager`, which triggers the one-time Bluetooth
//! permission prompt attributed to the terminal application. Construct it only
//! from a user-initiated commissioning flow — never at library init — and see
//! `docs/runbooks/ble-commissioning.md`.
//!
//! btleplug specifics relied on here are pinned against 0.12.0 (spec §D8):
//! service-data advertisements arrive on the `events()` stream (never the stale
//! `PeripheralProperties`), `notifications()` is a capacity-16 broadcast that
//! drops on lag (so the pump drains it continuously, started before the
//! handshake write), and `mtu()` is unreadable on macOS (so the handshake
//! requests MTU 0 and adopts the peripheral's advertised fragment size).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use btleplug::api::{
    Central, CentralEvent, CentralState, Characteristic, Manager as _, Peripheral as _, ScanFilter,
    WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};
use futures::{Stream, StreamExt};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::advert::CommissionableAdvert;
use crate::handshake::{HandshakeRequest, HandshakeResponse, WINDOW_SIZE};
use crate::session::{BtpSession, Role};
use crate::BtpError;

/// Matter BTP GATT service UUID (`0000fff6-0000-1000-8000-00805f9b34fb`).
pub const MATTER_SERVICE_UUID: Uuid = Uuid::from_u128(0x0000_fff6_0000_1000_8000_0080_5f9b_34fb);
/// C1 characteristic — central writes BTP fragments here
/// (`18ee2ef5-263d-4559-959f-4f9c429f9d11`).
pub const C1_UUID: Uuid = Uuid::from_u128(0x18ee_2ef5_263d_4559_959f_4f9c_429f_9d11);
/// C2 characteristic — the device indicates BTP fragments here
/// (`18ee2ef5-263d-4559-959f-4f9c429f9d12`).
pub const C2_UUID: Uuid = Uuid::from_u128(0x18ee_2ef5_263d_4559_959f_4f9c_429f_9d12);

/// How long to wait for a GATT connection before giving up (plain `connect`
/// never times out on `CoreBluetooth`).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long to wait for the BTP handshake response indication
/// (chip `BTP_CONN_RSP_TIMEOUT_MS`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Errors from the BLE central and its BTP pump.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CentralError {
    /// No Bluetooth adapter, or the adapter is not powered on. The message
    /// points at the runbook; on macOS this is also how a denied Bluetooth
    /// permission surfaces (the adapter never reaches `PoweredOn`).
    #[error("bluetooth adapter unavailable ({0}); see docs/runbooks/ble-commissioning.md")]
    AdapterUnavailable(String),
    /// A scan operation failed.
    #[error("BLE scan failed: {0}")]
    Scan(String),
    /// No commissionable device matching the discriminator appeared before the
    /// scan timeout.
    #[error("no matching commissionable device found before timeout")]
    ScanTimeout,
    /// Connecting to the peripheral failed.
    #[error("BLE connect failed: {0}")]
    Connect(String),
    /// A required GATT characteristic (C1 or C2) was not found on the device.
    #[error("Matter BTP characteristic not found: {0}")]
    GattNotFound(&'static str),
    /// The BTP handshake failed (bad response, or the codec rejected it).
    #[error("BTP handshake failed: {0}")]
    Handshake(#[from] BtpError),
    /// No handshake response arrived before the timeout.
    #[error("BTP handshake response timed out")]
    HandshakeTimeout,
    /// The BLE link dropped.
    #[error("BLE peripheral disconnected")]
    Disconnected,
    /// A GATT write or subscription failed.
    #[error("BLE GATT operation failed: {0}")]
    Gatt(String),
}

/// A commissionable device located by [`BleCentral::find_device`].
#[derive(Debug, Clone)]
pub struct FoundDevice {
    /// btleplug identifier for the peripheral (a `CoreBluetooth` UUID on macOS —
    /// never a hardware MAC).
    pub peripheral_id: PeripheralId,
    /// The parsed advertisement that matched.
    pub advert: CommissionableAdvert,
}

/// Does `advert` match the requested `discriminator`?
///
/// With `short == false` the full 12-bit discriminator must match exactly. With
/// `short == true` only the upper 4 bits are compared (the short discriminator
/// carried by manual pairing codes): the request supplies those 4 bits in its
/// low nibble.
#[must_use]
pub fn advert_matches(advert: &CommissionableAdvert, discriminator: u16, short: bool) -> bool {
    if short {
        (advert.discriminator >> 8) == (discriminator & 0x0f)
    } else {
        advert.discriminator == discriminator
    }
}

/// A BLE central bound to a specific adapter.
///
/// Construction is the macOS TCC trigger — see the module docs.
pub struct BleCentral {
    adapter: Adapter,
}

impl BleCentral {
    /// Acquire the first Bluetooth adapter and verify it is powered on.
    ///
    /// **This instantiates `CoreBluetooth` and may raise the macOS Bluetooth
    /// permission prompt.** Call only from a user-initiated commissioning flow.
    ///
    /// # Errors
    /// [`CentralError::AdapterUnavailable`] when no adapter exists or it is not
    /// `PoweredOn` (including a denied macOS Bluetooth permission).
    pub async fn new() -> Result<Self, CentralError> {
        let manager = Manager::new()
            .await
            .map_err(|e| CentralError::AdapterUnavailable(e.to_string()))?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| CentralError::AdapterUnavailable(e.to_string()))?;
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or_else(|| CentralError::AdapterUnavailable("no adapters".to_string()))?;
        match adapter.adapter_state().await {
            Ok(CentralState::PoweredOn) => Ok(Self { adapter }),
            Ok(other) => Err(CentralError::AdapterUnavailable(format!("state {other:?}"))),
            Err(e) => Err(CentralError::AdapterUnavailable(e.to_string())),
        }
    }

    /// Scan for a commissionable Matter device whose advertisement matches
    /// `discriminator`, giving up after `timeout`.
    ///
    /// Service-data advertisements are consumed from the adapter event stream
    /// (never the stale per-peripheral properties). `short` selects short- vs
    /// long-discriminator matching (see [`advert_matches`]).
    ///
    /// # Errors
    /// [`CentralError::Scan`] on a scan failure, [`CentralError::ScanTimeout`]
    /// when nothing matches in time.
    pub async fn find_device(
        &self,
        discriminator: u16,
        short: bool,
        timeout: Duration,
    ) -> Result<FoundDevice, CentralError> {
        let mut events = self
            .adapter
            .events()
            .await
            .map_err(|e| CentralError::Scan(e.to_string()))?;
        self.adapter
            .start_scan(ScanFilter {
                services: vec![MATTER_SERVICE_UUID],
            })
            .await
            .map_err(|e| CentralError::Scan(e.to_string()))?;

        let found = tokio::time::timeout(timeout, async {
            while let Some(event) = events.next().await {
                if let CentralEvent::ServiceDataAdvertisement { id, service_data } = event {
                    if let Some(dev) = match_service_data(&id, &service_data, discriminator, short)
                    {
                        return Some(dev);
                    }
                }
            }
            None
        })
        .await;

        // Best-effort stop; ignore errors (we are done scanning either way).
        let _ = self.adapter.stop_scan().await;

        match found {
            Ok(Some(dev)) => Ok(dev),
            Ok(None) | Err(_) => Err(CentralError::ScanTimeout),
        }
    }

    /// Connect to `device`, open the Matter BTP GATT service, run the BTP
    /// handshake, and return a live [`BtpChannel`].
    ///
    /// The C2 notification stream is drained by a spawned pump task started
    /// before the handshake write, so the handshake response cannot be lost to
    /// btleplug's bounded notification buffer.
    ///
    /// # Errors
    /// [`CentralError`] variants for connect, GATT discovery, subscription, or
    /// handshake failures.
    pub async fn open_btp(&self, device: &FoundDevice) -> Result<BtpChannel, CentralError> {
        let peripheral = self
            .adapter
            .peripheral(&device.peripheral_id)
            .await
            .map_err(|e| CentralError::Connect(e.to_string()))?;
        peripheral
            .connect_with_timeout(CONNECT_TIMEOUT)
            .await
            .map_err(|e| CentralError::Connect(e.to_string()))?;
        peripheral
            .discover_services()
            .await
            .map_err(|e| CentralError::Connect(e.to_string()))?;

        let c1 = find_char(&peripheral, C1_UUID).ok_or(CentralError::GattNotFound("C1"))?;
        let c2 = find_char(&peripheral, C2_UUID).ok_or(CentralError::GattNotFound("C2"))?;

        // Subscribe and open the notification stream BEFORE the handshake write.
        peripheral
            .subscribe(&c2)
            .await
            .map_err(|e| CentralError::Gatt(e.to_string()))?;
        let mut indications = peripheral
            .notifications()
            .await
            .map_err(|e| CentralError::Gatt(e.to_string()))?;

        // Handshake: request MTU 0 (unknown on macOS) + our receive window; the
        // device's response fixes the negotiated fragment size and window.
        let request = HandshakeRequest {
            mtu: 0,
            window: WINDOW_SIZE,
        };
        peripheral
            .write(&c1, &request.encode(), WriteType::WithResponse)
            .await
            .map_err(|e| CentralError::Gatt(e.to_string()))?;

        let resp_bytes = tokio::time::timeout(HANDSHAKE_TIMEOUT, next_c2(&mut indications))
            .await
            .map_err(|_| CentralError::HandshakeTimeout)?
            .ok_or(CentralError::Disconnected)?;
        let response = HandshakeResponse::parse(&resp_bytes)?;

        let now = Instant::now();
        let session = BtpSession::new(Role::Central, response.segment_size, response.window, now);

        Ok(spawn_pump(peripheral, c1, indications, session))
    }
}

/// Parse a service-data map for the Matter service UUID and match its
/// discriminator; returns a [`FoundDevice`] on a hit. Pure over its inputs.
fn match_service_data(
    id: &PeripheralId,
    service_data: &HashMap<Uuid, Vec<u8>>,
    discriminator: u16,
    short: bool,
) -> Option<FoundDevice> {
    let raw = service_data.get(&MATTER_SERVICE_UUID)?;
    let advert = CommissionableAdvert::parse(raw).ok()?;
    if advert_matches(&advert, discriminator, short) {
        Some(FoundDevice {
            peripheral_id: id.clone(),
            advert,
        })
    } else {
        None
    }
}

/// Find a characteristic by UUID among the peripheral's discovered set.
fn find_char(peripheral: &Peripheral, uuid: Uuid) -> Option<Characteristic> {
    peripheral
        .characteristics()
        .into_iter()
        .find(|c| c.uuid == uuid)
}

/// Await the next C2 indication payload from the notification stream, skipping
/// notifications for other characteristics. `None` when the stream ends.
async fn next_c2<S>(indications: &mut S) -> Option<Vec<u8>>
where
    S: Stream<Item = btleplug::api::ValueNotification> + Unpin,
{
    while let Some(note) = indications.next().await {
        if note.uuid == C2_UUID {
            return Some(note.value);
        }
    }
    None
}

/// A command sent to the pump task.
enum PumpCommand {
    /// Queue a whole Matter message for segmentation; the pump acks once it is
    /// accepted by the BTP session.
    Send(Vec<u8>, oneshot::Sender<Result<(), CentralError>>),
    /// Close the channel and stop the pump.
    Close,
}

/// A live BTP session over BLE: send and receive whole Matter messages.
///
/// `recv` is single-consumer. Dropping the channel (or calling [`Self::close`])
/// stops the pump; the peripheral stays connected until it is dropped.
pub struct BtpChannel {
    commands: mpsc::Sender<PumpCommand>,
    inbound: mpsc::Receiver<Result<Vec<u8>, CentralError>>,
    pump: Option<JoinHandle<()>>,
}

impl BtpChannel {
    /// Send one whole Matter message. It is segmented into BTP fragments by the
    /// pump.
    ///
    /// # Errors
    /// [`CentralError::Disconnected`] if the pump has stopped; the underlying
    /// [`CentralError`] if the session rejected the message.
    pub async fn send(&self, message: &[u8]) -> Result<(), CentralError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.commands
            .send(PumpCommand::Send(message.to_vec(), ack_tx))
            .await
            .map_err(|_| CentralError::Disconnected)?;
        ack_rx.await.map_err(|_| CentralError::Disconnected)?
    }

    /// Await the next whole Matter message reassembled from the device.
    ///
    /// # Errors
    /// [`CentralError::Disconnected`] when the link drops or the pump stops.
    pub async fn recv(&mut self) -> Result<Vec<u8>, CentralError> {
        match self.inbound.recv().await {
            Some(result) => result,
            None => Err(CentralError::Disconnected),
        }
    }

    /// Stop the pump. Idempotent; the peripheral is left connected.
    pub async fn close(mut self) {
        let _ = self.commands.send(PumpCommand::Close).await;
        if let Some(handle) = self.pump.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for BtpChannel {
    fn drop(&mut self) {
        if let Some(handle) = self.pump.take() {
            handle.abort();
        }
    }
}

/// Spawn the pump task that owns the [`BtpSession`] and bridges it to the GATT
/// characteristics. Returns the [`BtpChannel`] wired to it.
fn spawn_pump(
    peripheral: Peripheral,
    c1: Characteristic,
    indications: impl Stream<Item = btleplug::api::ValueNotification> + Unpin + Send + 'static,
    session: BtpSession,
) -> BtpChannel {
    let (cmd_tx, cmd_rx) = mpsc::channel::<PumpCommand>(8);
    let (sdu_tx, sdu_rx) = mpsc::channel::<Result<Vec<u8>, CentralError>>(8);
    let pump = tokio::spawn(pump_loop(
        peripheral,
        c1,
        Box::pin(indications),
        session,
        cmd_rx,
        sdu_tx,
    ));
    BtpChannel {
        commands: cmd_tx,
        inbound: sdu_rx,
        pump: Some(pump),
    }
}

/// Write one fragment to C1 and release the one-op-in-flight slot.
///
/// Every C1 write — data fragment OR standalone ack — latches the session's
/// GATT-in-flight flag; `gatt_write_completed` MUST be called after the write
/// resolves or the session can never send again (a real deadlock caught by the
/// PASE-over-BTP floor test).
async fn write_fragment(
    peripheral: &Peripheral,
    c1: &Characteristic,
    session: &mut BtpSession,
    fragment: &[u8],
) -> Result<(), CentralError> {
    peripheral
        .write(c1, fragment, WriteType::WithResponse)
        .await
        .map_err(|e| CentralError::Gatt(e.to_string()))?;
    session.gatt_write_completed(Instant::now());
    Ok(())
}

/// Flush every fragment the session currently permits, then emit any
/// immediately-due standalone ack. Returns the next timer deadline, if any.
async fn drive_outbound(
    peripheral: &Peripheral,
    c1: &Characteristic,
    session: &mut BtpSession,
) -> Result<Option<Instant>, CentralError> {
    while let Some(fragment) = session.next_gatt_write(Instant::now()) {
        write_fragment(peripheral, c1, session, &fragment).await?;
    }
    while let Some(due) = session.poll_timeout() {
        if due > Instant::now() {
            return Ok(Some(due));
        }
        match session.handle_timeout(Instant::now())? {
            Some(ack) => write_fragment(peripheral, c1, session, &ack).await?,
            // Emission is deferred (blocked on window/GATT slot): wait for the
            // next IO event rather than spinning.
            None => break,
        }
    }
    Ok(session.poll_timeout())
}

/// The pump: owns the [`BtpSession`], services outbound fragments/acks, feeds
/// inbound C2 indications, and surfaces completed messages.
async fn pump_loop(
    peripheral: Peripheral,
    c1: Characteristic,
    mut indications: std::pin::Pin<Box<dyn Stream<Item = btleplug::api::ValueNotification> + Send>>,
    mut session: BtpSession,
    mut commands: mpsc::Receiver<PumpCommand>,
    sdu_tx: mpsc::Sender<Result<Vec<u8>, CentralError>>,
) {
    loop {
        let deadline = match drive_outbound(&peripheral, &c1, &mut session).await {
            Ok(deadline) => deadline,
            Err(e) => {
                let _ = sdu_tx.send(Err(e)).await;
                return;
            }
        };

        let timer = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            command = commands.recv() => match command {
                Some(PumpCommand::Send(message, ack)) => {
                    let _ = ack.send(session.queue_message(&message).map_err(CentralError::from));
                }
                Some(PumpCommand::Close) | None => return,
            },
            note = indications.next() => match note {
                Some(note) if note.uuid == C2_UUID => {
                    match session.on_indication(&note.value, Instant::now()) {
                        Ok(Some(sdu)) => {
                            if sdu_tx.send(Ok(sdu)).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            let _ = sdu_tx.send(Err(CentralError::from(e))).await;
                            return;
                        }
                    }
                }
                Some(_) => {}
                None => {
                    let _ = sdu_tx.send(Err(CentralError::Disconnected)).await;
                    return;
                }
            },
            () = timer => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
    use super::*;
    use crate::advert::CommissionableAdvert;

    fn advert(discriminator: u16) -> CommissionableAdvert {
        CommissionableAdvert {
            discriminator,
            adv_version: 0,
            vendor_id: 0xFFF1,
            product_id: 0x8000,
            has_additional_data: false,
            extended_announcement: false,
        }
    }

    #[test]
    fn long_discriminator_matches_exactly() {
        // Vector test-vectors/btp/advert.json "pi_default_disc": disc 0xF00.
        assert!(advert_matches(&advert(0xF00), 0xF00, false));
        assert!(!advert_matches(&advert(0xF00), 0xF01, false));
        assert!(!advert_matches(&advert(0xABC), 0xF00, false));
    }

    #[test]
    fn short_discriminator_matches_upper_nibble() {
        // Long 0xF00 has upper nibble 0xF; a short request of 0xF matches.
        assert!(advert_matches(&advert(0xF00), 0x0F, true));
        assert!(advert_matches(&advert(0xABC), 0x0A, true));
        assert!(!advert_matches(&advert(0xABC), 0x0B, true));
    }

    #[test]
    fn service_uuid_stringifies_to_spec_value() {
        assert_eq!(
            MATTER_SERVICE_UUID.to_string(),
            "0000fff6-0000-1000-8000-00805f9b34fb"
        );
    }

    #[test]
    fn characteristic_uuids_stringify_to_spec_values() {
        assert_eq!(C1_UUID.to_string(), "18ee2ef5-263d-4559-959f-4f9c429f9d11");
        assert_eq!(C2_UUID.to_string(), "18ee2ef5-263d-4559-959f-4f9c429f9d12");
    }
}
