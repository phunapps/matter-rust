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
//! `PeripheralProperties`), a service-UUID `ScanFilter` is unusable because it
//! blinds the `BlueZ` backend (so scans are unfiltered — see
//! `BleCentral::find_device`), `notifications()` is a capacity-16 broadcast that
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

/// Diagnostic pump tracing, enabled by setting `MATTER_BLE_PUMP_TRACE=1`.
///
/// macOS has no `btmon`, and the pump runs in a spawned task that prints
/// nothing between "commissioning…" and the result — so a hang (the known
/// macOS `CoreBluetooth` BTP stall) is invisible. When enabled, the pump emits
/// a timestamped line at each `open_btp` boundary (peripheral, connect, service
/// discovery, notifications, C1 write, subscribe, handshake response) and each
/// C1-write / C2-indication in the pump. This is how the macOS hang was
/// root-caused: the trace stops at `discover_services START` (or, past a patched
/// btleplug, at `handshake C1 write START`) — see the investigation under
/// `docs/superpowers/audits/`. Confirmed cause: btleplug 0.12.0 drops errored
/// `CoreBluetooth` delegate events, and `CoreBluetooth` rejects the `CHIPoBLE`
/// GATT ops with `CBError.uuidNotAllowed`.
///
/// Off by default and side-effect-free (a single relaxed env read, cached), so
/// it cannot affect the proven Linux path.
fn pump_trace_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("MATTER_BLE_PUMP_TRACE")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    })
}

/// Emit one diagnostic pump-trace line to stderr when `MATTER_BLE_PUMP_TRACE`
/// is set (see [`pump_trace_enabled`]).
fn pt(msg: &str) {
    if pump_trace_enabled() {
        eprintln!("[btp-pump] {msg}");
    }
}

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
/// Per-attempt timeout for GATT service discovery. On `CoreBluetooth`,
/// `discover_services()` can never return on its own: `btleplug` 0.12.0 only
/// completes the discovery future once every characteristic's *descriptor*
/// discovery reports success, but it silently drops the completion event when a
/// descriptor probe returns an error (`central_delegate.rs`, the
/// `didDiscoverDescriptorsForCharacteristic` handler gates on `error.is_none()`).
/// `CHIPoBLE`'s C1/C2 return `CBError.uuidNotAllowed` for that probe, so the
/// future stalls forever. A per-attempt bound converts the stall into a clean,
/// fast failure instead of hanging past every commissioning deadline. See the
/// macOS BLE investigation under docs/superpowers/audits/.
const SERVICE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(12);
/// How many times to (re-)issue service discovery before giving up. A retry
/// cannot recover the `btleplug` event-drop above (re-discovery hits the same
/// descriptor error), but it is cheap insurance against a genuinely transient
/// stall on other peripherals.
const SERVICE_DISCOVERY_ATTEMPTS: u32 = 2;
/// Timeout for a single C1 GATT write (`WithResponse`). Same `btleplug` 0.12.0
/// failure mode as discovery: the `didWriteValueForCharacteristic` handler only
/// emits its completion event on `error.is_none()`, so a write that
/// `CoreBluetooth` rejects (`CHIPoBLE` writes currently draw
/// `CBError.uuidNotAllowed` on macOS)
/// leaves `write().await` pending forever. Bound it so the failure surfaces.
const C1_WRITE_TIMEOUT: Duration = Duration::from_secs(12);
/// Bound for the best-effort pre-connect disconnect. On a not-connected
/// peripheral `CoreBluetooth`'s `disconnect()` never returns, so this is short:
/// if there is nothing to tear down we move on to `connect()` promptly.
const PRE_CONNECT_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// The scan is deliberately **unfiltered**, with [`MATTER_SERVICE_UUID`]
    /// matched in `match_service_data` instead of being handed to btleplug as a
    /// [`ScanFilter`]. Passing that filter is not portable: `CoreBluetooth`
    /// honours it, but on `BlueZ` it suppresses the backend entirely — no
    /// service-data events and an empty `peripherals()` — so every scan found
    /// nothing on Linux while macOS worked. Filtering here costs only the
    /// discarded non-Matter adverts and behaves identically on both backends.
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
        // Unfiltered on purpose — a service-UUID ScanFilter blinds BlueZ. See
        // the doc comment above.
        self.adapter
            .start_scan(ScanFilter::default())
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
    /// **Ordering is protocol-critical: the C1 handshake request must be
    /// written before subscribing to C2.** chip's peripheral stashes its
    /// capabilities response and only indicates it upon receiving the
    /// subscription (`BLEEndPoint::HandleSubscribeReceived`), which additionally
    /// requires the endpoint to already be in `kState_Connecting` with a
    /// non-empty send queue — the state the capabilities request establishes.
    /// Subscribing first therefore makes the peripheral reject the subscribe as
    /// `CHIP_ERROR_INCORRECT_STATE` and leaves the queued response with no
    /// trigger: the device goes silent and the handshake times out. Real
    /// hardware is the only thing that catches this; a loopback peer that
    /// answers a request immediately accepts either order.
    ///
    /// The local notification stream is still opened *before* the write (it
    /// writes no CCCD and the peripheral cannot observe it), so the response
    /// cannot be lost to btleplug's bounded notification buffer.
    ///
    /// # Errors
    /// [`CentralError`] variants for connect, GATT discovery, subscription, or
    /// handshake failures.
    pub async fn open_btp(&self, device: &FoundDevice) -> Result<BtpChannel, CentralError> {
        pt("open_btp: peripheral()");
        let peripheral = self
            .adapter
            .peripheral(&device.peripheral_id)
            .await
            .map_err(|e| CentralError::Connect(e.to_string()))?;
        // Clear any stale system-level connection to this peripheral before
        // connecting. On macOS `CoreBluetooth` a connection left over from a
        // prior (crashed/killed) attempt survives at the daemon and keeps the
        // peripheral from re-advertising, so a best-effort disconnect first
        // forces a clean link. Bounded by a short timeout: on a not-connected
        // peripheral `disconnect()` itself never returns (it awaits a
        // `didDisconnect` that never fires), so we must not block on it.
        let _ = tokio::time::timeout(PRE_CONNECT_DISCONNECT_TIMEOUT, peripheral.disconnect()).await;
        pt("open_btp: connect START");
        peripheral
            .connect_with_timeout(CONNECT_TIMEOUT)
            .await
            .map_err(|e| CentralError::Connect(e.to_string()))?;
        pt("open_btp: connect DONE; discover_services START");
        discover_services_with_retry(&peripheral).await?;
        pt("open_btp: discover_services DONE");

        let c1 = find_char(&peripheral, C1_UUID).ok_or(CentralError::GattNotFound("C1"))?;
        let c2 = find_char(&peripheral, C2_UUID).ok_or(CentralError::GattNotFound("C2"))?;

        // Open the local notification stream before anything can be indicated,
        // so the response cannot be lost to btleplug's bounded buffer. This is
        // local only — it writes no CCCD and is invisible to the peripheral.
        let mut indications = peripheral
            .notifications()
            .await
            .map_err(|e| CentralError::Gatt(e.to_string()))?;
        pt("open_btp: notifications opened");

        // Handshake: request MTU 0 (unknown on macOS) + our receive window; the
        // device's response fixes the negotiated fragment size and window.
        let request = HandshakeRequest {
            mtu: 0,
            window: WINDOW_SIZE,
        };
        pt("open_btp: handshake C1 write START");
        tokio::time::timeout(
            C1_WRITE_TIMEOUT,
            peripheral.write(&c1, &request.encode(), WriteType::WithResponse),
        )
        .await
        .map_err(|_| CentralError::Gatt("C1 handshake write timed out".into()))?
        .map_err(|e| CentralError::Gatt(e.to_string()))?;
        pt("open_btp: handshake C1 write DONE");

        // Subscribe AFTER the request: the CCCD write is what makes the
        // peripheral emit the response (see this method's doc comment).
        peripheral
            .subscribe(&c2)
            .await
            .map_err(|e| CentralError::Gatt(e.to_string()))?;
        pt("open_btp: subscribed C2; awaiting handshake response");

        let resp_bytes = tokio::time::timeout(HANDSHAKE_TIMEOUT, next_c2(&mut indications))
            .await
            .map_err(|_| CentralError::HandshakeTimeout)?
            .ok_or(CentralError::Disconnected)?;
        pt("open_btp: handshake response received");
        let response = HandshakeResponse::parse(&resp_bytes)?;

        let now = Instant::now();
        let session = BtpSession::new(Role::Central, response.segment_size, response.window, now);

        // Adapter event stream, used by the pump to observe DeviceDisconnected
        // for this peripheral (the notification stream alone does not reliably
        // close on link loss — spec §D8).
        let events = self
            .adapter
            .events()
            .await
            .map_err(|e| CentralError::Gatt(e.to_string()))?;

        Ok(spawn_pump(
            peripheral,
            c1,
            c2,
            device.peripheral_id.clone(),
            indications,
            events,
            session,
        ))
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
///
/// Exposed `#[doc(hidden)]` so out-of-crate adapters (e.g. matter-controller's
/// `BtpDatagram`) can unit-test against a [`BtpChannel::from_channels`] seam
/// without a live peripheral. Not part of the stable public API.
#[doc(hidden)]
pub enum PumpCommand {
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

    /// Build a `BtpChannel` directly from raw channel halves, with **no pump
    /// task** (`pump: None`).
    ///
    /// This is a `#[doc(hidden)]` test seam: it lets code in other crates
    /// unit-test adapters layered over a `BtpChannel` (matter-controller's
    /// `BtpDatagram`) by driving the command and inbound sides by hand — no
    /// live BLE peripheral, no `BleCentral`/`Manager`/`Adapter`. Not part of
    /// the stable public API.
    ///
    /// The caller owns the peer halves: the receiver of `commands` observes
    /// each [`PumpCommand`] produced by [`Self::send`] (and must reply on the
    /// embedded ack channel for `send` to resolve), and the sender of `inbound`
    /// feeds [`Self::recv`].
    #[doc(hidden)]
    #[must_use]
    pub fn from_channels(
        commands: mpsc::Sender<PumpCommand>,
        inbound: mpsc::Receiver<Result<Vec<u8>, CentralError>>,
    ) -> Self {
        Self {
            commands,
            inbound,
            pump: None,
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
#[allow(clippy::too_many_arguments)] // Pump wiring: all inputs are load-bearing.
fn spawn_pump(
    peripheral: Peripheral,
    c1: Characteristic,
    c2: Characteristic,
    peripheral_id: PeripheralId,
    indications: impl Stream<Item = btleplug::api::ValueNotification> + Unpin + Send + 'static,
    events: impl Stream<Item = CentralEvent> + Unpin + Send + 'static,
    session: BtpSession,
) -> BtpChannel {
    let (cmd_tx, cmd_rx) = mpsc::channel::<PumpCommand>(8);
    let (sdu_tx, sdu_rx) = mpsc::channel::<Result<Vec<u8>, CentralError>>(8);
    let pump = tokio::spawn(pump_loop(
        peripheral,
        c1,
        c2,
        peripheral_id,
        Box::pin(indications),
        Box::pin(events),
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

/// Discover the peripheral's GATT services, bounding the macOS
/// `CoreBluetooth` hang where `discover_services()` never returns.
///
/// Root cause (verified against a real ESP32-C6 on macOS 26): `btleplug` 0.12.0
/// only fulfills the discovery future after every characteristic's *descriptor*
/// discovery reports back, but its delegate drops that event when the probe
/// errors. `CHIPoBLE`'s C1/C2 answer descriptor discovery with
/// `CBError.uuidNotAllowed`, so the future never completes. A per-attempt bound
/// plus a small retry budget ([`SERVICE_DISCOVERY_ATTEMPTS`]) turns the infinite
/// hang into a fast, diagnosable failure. Full macOS BLE commissioning is still
/// blocked upstream (the same `uuidNotAllowed` also rejects the C1 write); this
/// only ensures we fail cleanly rather than hang.
async fn discover_services_with_retry(peripheral: &Peripheral) -> Result<(), CentralError> {
    let mut last: Option<String> = None;
    for attempt in 1..=SERVICE_DISCOVERY_ATTEMPTS {
        pt(&format!("discover_services attempt {attempt}"));
        match tokio::time::timeout(SERVICE_DISCOVERY_TIMEOUT, peripheral.discover_services()).await
        {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => last = Some(e.to_string()),
            Err(_) => last = Some("timed out (no reply from CoreBluetooth)".into()),
        }
        // Let a still-in-progress service modification settle before re-issuing;
        // the next `discover_services` replaces the stale in-flight discovery.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Err(CentralError::Connect(format!(
        "GATT service discovery did not complete after {SERVICE_DISCOVERY_ATTEMPTS} attempts: {}",
        last.unwrap_or_else(|| "unknown".into())
    )))
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
    // The tell-tale for the macOS half-duplex-deadlock hypothesis: a `START`
    // with no matching `DONE` means the pump is blocked in this `WithResponse`
    // write `await` (which runs outside the `select!`), so it has stopped
    // reading C2 indications. See [`pump_trace_enabled`].
    pt(&format!("C1 write START ({} bytes)", fragment.len()));
    peripheral
        .write(c1, fragment, WriteType::WithResponse)
        .await
        .map_err(|e| CentralError::Gatt(e.to_string()))?;
    pt("C1 write DONE");
    session.gatt_write_completed(Instant::now());
    Ok(())
}

/// What the pump should wait on after draining outbound work.
enum Wake {
    /// A future timer deadline (deferred send-ack, or the 15 s ack-timeout).
    At(Instant),
    /// A due action is blocked on a closed window / in-flight GATT slot. Park on
    /// IO but re-check after a bounded delay so the blocked ack is retried and
    /// the 15 s ack-timeout still fires — without hot-spinning on a past-due
    /// deadline (`sleep_until(past)` returns instantly).
    Retry,
    /// Nothing is pending; block on IO only.
    Idle,
}

/// Bounded fallback re-check delay for a blocked send-ack (see [`Wake::Retry`]).
/// Normal operation unblocks far sooner via an inbound indication crediting the
/// window; this only bounds the pathological silent-window case.
const BLOCKED_ACK_RETRY: Duration = Duration::from_millis(250);

/// Flush every fragment the session currently permits, then emit any
/// immediately-due standalone ack. Returns what the pump should wait on next.
async fn drive_outbound(
    peripheral: &Peripheral,
    c1: &Characteristic,
    session: &mut BtpSession,
) -> Result<Wake, CentralError> {
    while let Some(fragment) = session.next_gatt_write(Instant::now()) {
        write_fragment(peripheral, c1, session, &fragment).await?;
    }
    loop {
        match session.poll_timeout() {
            None => return Ok(Wake::Idle),
            Some(due) if due > Instant::now() => return Ok(Wake::At(due)),
            Some(_) => match session.handle_timeout(Instant::now())? {
                Some(ack) => write_fragment(peripheral, c1, session, &ack).await?,
                // Emission is deferred (blocked on window / GATT slot): do not
                // spin on the past-due deadline — bounded-retry and park on IO.
                None => return Ok(Wake::Retry),
            },
        }
    }
}

/// The pump: owns the [`BtpSession`], services outbound fragments/acks, feeds
/// inbound C2 indications, surfaces completed messages, and closes on a
/// `DeviceDisconnected` event for this peripheral.
#[allow(clippy::too_many_arguments)] // Pump wiring: all inputs are load-bearing.
async fn pump_loop(
    peripheral: Peripheral,
    c1: Characteristic,
    c2: Characteristic,
    peripheral_id: PeripheralId,
    mut indications: std::pin::Pin<Box<dyn Stream<Item = btleplug::api::ValueNotification> + Send>>,
    mut events: std::pin::Pin<Box<dyn Stream<Item = CentralEvent> + Send>>,
    mut session: BtpSession,
    mut commands: mpsc::Receiver<PumpCommand>,
    sdu_tx: mpsc::Sender<Result<Vec<u8>, CentralError>>,
) {
    loop {
        let wake = match drive_outbound(&peripheral, &c1, &mut session).await {
            Ok(wake) => wake,
            Err(e) => {
                let _ = sdu_tx.send(Err(e)).await;
                return;
            }
        };

        let timer = async {
            match wake {
                Wake::At(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                Wake::Retry => tokio::time::sleep(BLOCKED_ACK_RETRY).await,
                Wake::Idle => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            command = commands.recv() => match command {
                Some(PumpCommand::Send(message, ack)) => {
                    let _ = ack.send(session.queue_message(&message).map_err(CentralError::from));
                }
                Some(PumpCommand::Close) | None => {
                    // Graceful close: drop the C2 subscription and the link
                    // (best-effort — the caller is done regardless).
                    let _ = peripheral.unsubscribe(&c2).await;
                    let _ = peripheral.disconnect().await;
                    return;
                }
            },
            note = indications.next() => match note {
                Some(note) if note.uuid == C2_UUID => {
                    pt(&format!("C2 indication ({} bytes)", note.value.len()));
                    match session.on_indication(&note.value, Instant::now()) {
                        Ok(Some(sdu)) => {
                            pt(&format!("SDU surfaced ({} bytes)", sdu.len()));
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
            event = events.next() => match event {
                Some(CentralEvent::DeviceDisconnected(id)) if id == peripheral_id => {
                    let _ = sdu_tx.send(Err(CentralError::Disconnected)).await;
                    return;
                }
                // Other events (and other peripherals) are irrelevant here; a
                // closed event stream is not itself fatal (the notification
                // stream / ack-timeout still detect a dead link).
                Some(_) | None => {}
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
