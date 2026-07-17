//! The async `commission()` orchestrator (M6.6.4): drive the sans-IO
//! `Commissioner` cursor over the M6.6.2/M6.6.3 driver, end to end.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use matter_cert::{MatterTime, TrustedRoots};
use matter_crypto::{derive_compressed_fabric_id, CaseCredentials};
use matter_transport::{Discovery, MrpEvent, ProtocolId, ServiceKind, SessionId, SessionManager};

use crate::driver::case::{resolve_operational_with_attempts, run_case};
use crate::driver::datagram::AsyncDatagram;
use crate::driver::error::DriverError;
use crate::driver::exchange::secured_round_trip;
use crate::driver::TransportReliability;
use crate::im::{CommandPath, ImStatus};
use crate::CommissionedFabric;
use crate::CommissionerConfig;

/// Sentinel peer for message-stream transports (BTP) where the
/// [`AsyncDatagram`] `SocketAddr` is routing-irrelevant — a BTP `AsyncDatagram`
/// is wired to exactly one GATT peer at construction and ignores the send
/// destination. This value is **never dereferenced as a real address**; it only
/// satisfies the `SocketAddr` parameter of the shared driver helpers on the
/// BLE path (design D1). IPv6 localhost:5540 (the Matter UDP port) is a
/// deliberately obvious, non-routing placeholder.
pub const STREAM_PEER: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5540, 0, 0));

/// Response deadline for a secured commissioning dispatch on the BLE path when
/// the invoke is **not** `NetworkCommissioning::ConnectNetwork`. With MRP off
/// over BTP (design D3), nothing at the exchange layer ever times out, so this
/// wrapper is the only guard against an unbounded hang if the device stops
/// responding. 30 s matches the unsecured PASE path's response window and
/// chip's BTP-ack-derived exchange response timeout.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(30);

/// Response deadline for `NetworkCommissioning::ConnectNetwork` on the BLE path.
/// Longer than [`RESPONSE_DEADLINE`] because the device performs the (slow)
/// Wi-Fi association + DHCP inline before replying (design D3).
const CONNECT_NETWORK_RESPONSE_DEADLINE: Duration = Duration::from_secs(60);

/// Placeholder exchange id reported when a BLE-path response deadline fires.
/// Unlike an MRP retransmit-budget [`DriverError::Timeout`] (which knows the
/// exchange that expired), a response-deadline timeout cancels the in-flight
/// dispatch future, so the concrete exchange id is not recoverable; the
/// rollback path does not consult it.
const RESPONSE_DEADLINE_EXCHANGE_SENTINEL: u16 = 0;

/// Attribute IDs used by the commissioning read path.
///
/// These are the concrete attribute IDs extracted from the cluster specs and
/// from the attribute list emitted by `Stage::ReadCommissioningInfo` and
/// `Stage::ReadNetworkCommissioningInfo`.
mod attr_id {
    /// `GeneralCommissioning::BasicCommissioningInfo` — attribute **0x0001**
    /// (spec §11.10.6; confirmed against a real device's report — 0x0004 is
    /// `SupportsConcurrentConnection`, a bool).
    ///
    /// The struct carrying `failsafe_expiry_length_seconds`.
    /// Matches the list in commissioner.rs `Stage::ReadCommissioningInfo`.
    pub(super) const BASIC_COMMISSIONING_INFO: u32 = 0x0001;

    /// `NetworkCommissioning::FeatureMap` — attribute 0xFFFC.
    ///
    /// Universal Matter meta-attribute (Spec §7.13). Matches
    /// `crate::clusters::network_commissioning::attribute_id::FEATURE_MAP`.
    pub(super) const FEATURE_MAP: u32 =
        crate::clusters::network_commissioning::attribute_id::FEATURE_MAP;

    /// `NetworkCommissioning::ConnectMaxTimeSeconds` — attribute 0x0009
    /// (spec §11.9.5.4). Read alongside `FeatureMap` to size the
    /// failsafe extension before `ConnectNetwork` (D7).
    pub(super) const CONNECT_MAX_TIME_SECONDS: u32 =
        crate::clusters::network_commissioning::attribute_id::CONNECT_MAX_TIME_SECONDS;
}

/// Outcome of a single `dispatch_invoke` round-trip.
///
/// Either the device replied with a response-command payload (`Command`), or
/// it returned a bare IM status with no payload (`Status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InvokeOutcome {
    /// Device returned a response command; `Vec<u8>` is the re-anonymised
    /// `CommandFields` TLV blob (anonymous-tagged struct, ready for the state
    /// machine's `on_response`).
    Command(Vec<u8>),
    /// Device returned a bare IM status (no response-command payload).
    Status(ImStatus),
}

/// Send a single `InvokeRequest` over an already-established secured session
/// and await the `InvokeResponse`.
///
/// Builds the `InvokeRequestMessage` from `path` and `fields_tlv`, sends it
/// via [`secured_round_trip`], then parses the `InvokeResponseMessage` and
/// returns the outcome.
///
/// # Errors
///
/// - [`DriverError::Transport`] / [`DriverError::Io`] / [`DriverError::Timeout`]
///   propagated from [`secured_round_trip`].
/// - [`DriverError::Im`] if the response cannot be parsed as a valid
///   `InvokeResponseMessage`.
pub(crate) async fn dispatch_invoke<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    session_id: SessionId,
    peer: SocketAddr,
    path: CommandPath,
    fields_tlv: &[u8],
) -> Result<InvokeOutcome, DriverError> {
    const OP_INVOKE_REQUEST: u8 = 0x08;
    let msg = crate::im::build_invoke_request(path, fields_tlv);
    let resp = secured_round_trip(
        transport,
        sessions,
        session_id,
        peer,
        OP_INVOKE_REQUEST,
        ProtocolId::INTERACTION_MODEL,
        &msg,
    )
    .await?;
    match crate::im::parse_invoke_response(&resp.payload)? {
        crate::im::InvokeResponse::Command { fields_tlv, .. } => {
            Ok(InvokeOutcome::Command(fields_tlv))
        }
        crate::im::InvokeResponse::Status(s) => Ok(InvokeOutcome::Status(s)),
    }
}

/// Extract the `on_response` payload bytes for a given [`Expectation`] from a
/// parsed [`crate::im::ReportData`].
///
/// This is the trickiest glue in the read path: a single `ReportDataMessage`
/// may carry multiple `(AttributePath, Value)` entries, but the sans-IO state
/// machine's `on_response` expects a *single* per-`Expectation` byte slice in
/// a specific format. This helper scans the report for the relevant attribute
/// and re-encodes just that value into the format `on_response` decodes.
///
/// # Payload formats (what `on_response` parses)
///
/// | `Expectation`              | Cluster  | Attr ID | Re-encoded format                        |
/// |----------------------------|----------|---------|------------------------------------------|
/// | `NetworkCommissioningInfo` | `0x0031` | `0xFFFC`| Anonymous-tagged unsigned integer TLV.   |
/// |                            |          |         | `decode_feature_map` expects this exact  |
/// |                            |          |         | shape: a bare `Element::Scalar { value:  |
/// |                            |          |         | Value::Uint, .. }`.                      |
/// | `CommissioningInfo`        | `0x0030` | `0x0001`| Anonymous-tagged struct TLV. The struct  |
/// |                            |          |         | carries ctx-tag-0 = failsafe seconds     |
/// |                            |          |         | (u16/u32) and optionally ctx-tag-1 =     |
/// |                            |          |         | max-cumulative seconds. An empty struct  |
/// |                            |          |         | `[0x15, 0x18]` is also accepted by       |
/// |                            |          |         | `decode_basic_commissioning_info` (which |
/// |                            |          |         | is best-effort: it returns `None` on any |
/// |                            |          |         | parse failure).                          |
///
/// # Errors
///
/// - [`DriverError::Im`] wrapping [`crate::im::ImError::MissingField`] if the
///   expected attribute is absent from the report.
/// - [`DriverError::Im`] wrapping [`crate::im::ImError::UnexpectedValue`] if
///   `expect` is not a read-expectation (i.e. not `CommissioningInfo` or
///   `NetworkCommissioningInfo`). The poll loop will never call this with
///   a non-read expectation, but the helper is defensive.
pub(crate) fn extract_read_payload(
    expect: crate::Expectation,
    report: &crate::im::ReportData,
) -> Result<Vec<u8>, DriverError> {
    use crate::im::ImError;
    use crate::Expectation;
    use matter_codec::{Tag, TlvWriter, Value};

    match expect {
        Expectation::NetworkCommissioningInfo => {
            // Scan for FeatureMap (cluster 0x0031, attribute 0xFFFC).
            let feat_val = report
                .attributes()
                .find(|(p, _)| {
                    p.cluster == crate::clusters::network_commissioning::CLUSTER_ID
                        && p.attribute == attr_id::FEATURE_MAP
                })
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    DriverError::Im(ImError::MissingField(
                        "FeatureMap attribute absent from NetworkCommissioning ReportData",
                    ))
                })?;
            // Re-encode as anonymous-tagged unsigned int (what decode_feature_map parses).
            let raw = match feat_val {
                Value::Uint(n) => *n,
                _ => {
                    return Err(DriverError::Im(ImError::UnexpectedValue(
                        "FeatureMap value is not a Uint",
                    )))
                }
            };
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            // Vec-backed TlvWriter is infallible; map the error anyway to satisfy
            // the Result return type (the error branch is unreachable in practice).
            w.put_uint(Tag::Anonymous, raw)
                .map_err(|e| DriverError::Im(ImError::Codec(e)))?;
            Ok(buf)
        }
        Expectation::CommissioningInfo => {
            // Scan for BasicCommissioningInfo (cluster 0x0030, attribute 0x0001).
            let struct_val = report
                .attributes()
                .find(|(p, _)| {
                    p.cluster == crate::clusters::general_commissioning::CLUSTER_ID
                        && p.attribute == attr_id::BASIC_COMMISSIONING_INFO
                })
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    DriverError::Im(ImError::MissingField(
                        "BasicCommissioningInfo attribute absent from GeneralCommissioning ReportData",
                    ))
                })?;
            // Re-encode as anonymous-tagged struct TLV (what decode_basic_commissioning_info parses).
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            w.write_value(Tag::Anonymous, struct_val)
                .map_err(|e| DriverError::Im(ImError::Codec(e)))?;
            Ok(buf)
        }
        _ => Err(DriverError::Im(ImError::UnexpectedValue(
            "extract_read_payload called with a non-read Expectation",
        ))),
    }
}

/// Extract `ConnectMaxTimeSeconds` (`NetworkCommissioning` cluster
/// `0x0031`, attribute `0x0009`) from a `ReportData`, if present.
///
/// Returns `None` when the attribute is absent or is not an unsigned
/// value — the state machine then keeps its generous default. Mirrors the
/// `FeatureMap` branch of [`extract_read_payload`]: the report's parsed
/// `Value` is re-encoded as a bare anonymous uint TLV and routed through
/// [`crate::clusters::network_commissioning::decode_connect_max_time_seconds`]
/// so a single decoder governs the wire → `u16` mapping.
fn extract_connect_max_time_seconds(report: &crate::im::ReportData) -> Option<u16> {
    use crate::clusters::network_commissioning as nc;
    use matter_codec::{Tag, TlvWriter, Value};
    let raw = report
        .attributes()
        .find(|(p, _)| {
            p.cluster == nc::CLUSTER_ID && p.attribute == attr_id::CONNECT_MAX_TIME_SECONDS
        })
        .and_then(|(_, v)| match v {
            Value::Uint(n) => Some(*n),
            _ => None,
        })?;
    let mut buf = Vec::new();
    // Vec-backed TlvWriter is infallible; a write error would just drop
    // the optional hint (default kept), so map it to `None`.
    TlvWriter::new(&mut buf)
        .put_uint(Tag::Anonymous, raw)
        .ok()?;
    nc::decode_connect_max_time_seconds(&buf).ok()
}

/// Drive any *imminent* pending MRP deadlines (within ~500 ms — in practice
/// the 200 ms standalone-ack timer buffered for the most recent secured
/// response, see `secured_round_trip`'s pending-ack note) and send the
/// resulting packets, so no ack is left owed to the device before a
/// non-secured exchange (CASE) starts.
///
/// # Errors
///
/// - [`DriverError::Io`] if a flushed packet fails to send.
async fn flush_pending_acks<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    peer: SocketAddr,
) -> Result<(), DriverError> {
    use std::time::{Duration, Instant};
    const FLUSH_HORIZON: Duration = Duration::from_millis(500);
    while let Some(deadline) = sessions.poll_timeout() {
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait > FLUSH_HORIZON {
            // Far-future deadline (e.g. an idle retransmit timer) — not the
            // ack we are after; leave it to the normal exchange loops.
            break;
        }
        tokio::time::sleep(wait).await;
        for event in sessions.handle_timeout(Instant::now()) {
            match event {
                MrpEvent::Retransmit { packet, .. }
                | MrpEvent::SendStandaloneAck { packet, .. } => {
                    transport.send_to(&packet, peer).await?;
                }
                // MrpEvent::Expired and — `MrpEvent` being `#[non_exhaustive]`
                // — any future variant are not relevant to this ack-collection
                // loop.
                _ => {}
            }
        }
    }
    Ok(())
}

/// Send a single `ReadRequest` over an already-established secured session
/// and await the `ReportData`.
///
/// Builds the `ReadRequestMessage` from `paths`, sends it via
/// [`secured_round_trip`], then parses the `ReportDataMessage` and returns
/// the result.
///
/// # Errors
///
/// - [`DriverError::Transport`] / [`DriverError::Io`] / [`DriverError::Timeout`]
///   propagated from [`secured_round_trip`].
/// - [`DriverError::Im`] if the response cannot be parsed as a valid
///   `ReportDataMessage`.
pub(crate) async fn dispatch_read<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    session_id: SessionId,
    peer: SocketAddr,
    paths: &[crate::im::AttributePath],
) -> Result<crate::im::ReportData, DriverError> {
    const OP_READ_REQUEST: u8 = 0x02;
    let msg = crate::im::build_read_request(paths);
    let resp = secured_round_trip(
        transport,
        sessions,
        session_id,
        peer,
        OP_READ_REQUEST,
        ProtocolId::INTERACTION_MODEL,
        &msg,
    )
    .await?;
    #[cfg(feature = "tracing")]
    tracing::debug!(
        report_data_tlv = %crate::hexdump::hex(&resp.payload),
        "ReportData received"
    );
    let report = crate::im::parse_report_data(&resp.payload)?;
    Ok(report)
}

/// How many times to poll discovery before giving up, and the gap between
/// polls (~5 s total) — bounded so the driver doesn't hang forever.
///
/// Mirrors the constants in `case.rs` (`RESOLVE_POLL_ATTEMPTS` /
/// `RESOLVE_POLL_INTERVAL`).
const RESOLVE_POLL_ATTEMPTS: usize = 50;
const RESOLVE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Inputs for one commissioning run. Borrows the commissioner config pieces
/// (fabric, trust stores, setup payload) for the run's duration.
pub struct DriverConfig<'a> {
    /// The sans-IO commissioner configuration (fabric, trust stores, node ids,
    /// wifi creds, rng, etc.). Built by the caller (M6.6.5 example / M8).
    pub commissioner: CommissionerConfig<'a>,
    /// Already-resolved commissionable device address (loopback/tests supply
    /// this directly; M6.6.5 fills it from `resolve_commissionable`). When
    /// `None`, `commission()` discovers it via mDNS using the setup payload's
    /// discriminator.
    pub commissionable_addr: Option<SocketAddr>,
    /// Device passcode (from the setup payload).
    pub passcode: u32,
    /// The controller's **persistent** commissioner operational identity on
    /// this fabric: its NOC (signed by the fabric RCAC, subject node id ==
    /// `commissioner.commissioner_node_id`) and its operational private key
    /// as PKCS#8 DER. Used to authenticate the post-commissioning CASE.
    ///
    /// Replaces the per-call throwaway mint (former M6.6.4 simplification):
    /// the caller now owns one stable identity for commission-time and
    /// operational sessions alike (matter-controller persists it in M8.1).
    pub commissioner_noc: &'a matter_cert::MatterCertificate,
    /// PKCS#8 DER of the commissioner operational private key (pairs with
    /// `commissioner_noc`'s subject public key).
    pub commissioner_signer_pkcs8: &'a [u8],
}

/// Browse `_matterc._udp` commissionable records and return the socket address
/// of the device matching `discriminator`.
///
/// The device advertises its **long** (12-bit) discriminator as a decimal string
/// in the `D` TXT key (Matter Core Spec §5.4.7.4). `discriminator` may be either:
///
/// - a **long** discriminator (from a QR code), matched exactly; or
/// - a **short** (4-bit) discriminator from a manual pairing code, which Matter
///   packs into the upper 4 bits and zero-extends — i.e. `short << 8`. A manual
///   code does not carry the lower 8 bits, so it cannot match the advertised `D`
///   exactly; per the Matter discovery model (and connectedhomeip's
///   `kShortDiscriminator` filter) it is matched against the **upper 4 bits** of
///   the advertised long discriminator (`advertised >> 8 == short`).
///
/// To handle both without a separate flag, each poll round prefers an **exact**
/// long match and only falls back to the short (upper-4-bit) match — a value
/// that came from a manual code never matches a device's full `D` exactly, so it
/// deterministically takes the short path, while a QR's long discriminator
/// exact-matches its device. Short discriminators are only 4 bits, so the
/// fallback is inherently ambiguous if multiple devices are commissionable with
/// the same upper nibble (the same limitation chip carries).
///
/// FLAGGED: takes the first advertised address from `addresses[0]`. Link-local
/// `fe80::` addresses need an interface scope-id that [`matter_transport::MatterService`]
/// does not carry.
///
/// # Errors
///
/// - [`DriverError::Transport`] if the discovery query fails.
/// - [`DriverError::Discovery`] if no matching record with an address appears
///   within the poll budget.
pub async fn resolve_commissionable<D: Discovery>(
    discovery: &mut D,
    discriminator: u16,
) -> Result<SocketAddr, DriverError> {
    let short = ((discriminator >> 8) & 0x0F) as u8;
    let handle = discovery
        .query(ServiceKind::Commissionable)
        .map_err(DriverError::Transport)?;

    // A device advertises `CM=1`/`2` while a commissioning window is open and
    // `CM=0` once it closes. Skip closed windows so a stale advertisement is not
    // matched (which would then fail PASE). Absent `CM` is treated as open.
    let window_open =
        |svc: &matter_transport::MatterService| svc.txt_str("CM").is_none_or(|v| v != "0");

    for _ in 0..RESOLVE_POLL_ATTEMPTS {
        let results = discovery.poll_results(handle);

        // Prefer an exact long-discriminator match (QR codes).
        for svc in results.iter().filter(|s| window_open(s)) {
            if svc.txt_str("D").and_then(|d| d.parse::<u16>().ok()) == Some(discriminator) {
                if let Some(addr) = crate::driver::case::preferred_address(&svc.addresses) {
                    discovery.stop_query(handle);
                    return Ok(SocketAddr::new(addr, svc.port));
                }
            }
        }

        // Fall back to the upper-4-bit short discriminator (manual codes).
        for svc in results.iter().filter(|s| window_open(s)) {
            let advertised = svc.txt_str("D").and_then(|d| d.parse::<u16>().ok());
            if let Some(adv) = advertised {
                if ((adv >> 8) & 0x0F) as u8 == short {
                    if let Some(addr) = crate::driver::case::preferred_address(&svc.addresses) {
                        discovery.stop_query(handle);
                        return Ok(SocketAddr::new(addr, svc.port));
                    }
                }
            }
        }

        tokio::time::sleep(RESOLVE_POLL_INTERVAL).await;
    }
    discovery.stop_query(handle);
    Err(DriverError::Discovery(format!(
        "commissionable device with discriminator {discriminator} (short {short:#x}) not found via mDNS"
    )))
}

/// Best-effort disarm of the device's failsafe by sending `ArmFailSafe(expiry=0)`
/// over the PASE session. Called by the `Action::Abort` branch of the poll loop
/// (Task 6) when `send_disarm_failsafe` is `true`.
///
/// Errors from [`dispatch_invoke`] are intentionally swallowed: this is a
/// best-effort cleanup step. If the device is unreachable or the session has
/// already expired the rollback is silently skipped — the device's built-in
/// failsafe timer will expire on its own.
///
/// # Errors
///
/// This function is infallible; it always returns `()`.
pub(crate) async fn rollback<T: AsyncDatagram>(
    transport: &T,
    sessions: &mut SessionManager,
    pase_session_id: SessionId,
    peer: SocketAddr,
) {
    let path = CommandPath {
        endpoint: 0,
        cluster: crate::clusters::general_commissioning::CLUSTER_ID,
        command: crate::clusters::general_commissioning::command_id::ARM_FAIL_SAFE,
    };
    let fields = crate::clusters::general_commissioning::encode_arm_fail_safe(0, 0);
    let _ = dispatch_invoke(transport, sessions, pase_session_id, peer, path, &fields).await;
}

/// Resolve the device's operational address via mDNS and complete a CASE
/// handshake, returning the new [`SessionId`] **and the resolved operational
/// [`SocketAddr`]** so the caller can direct post-CASE secured traffic at the
/// operational address (over the operational transport) rather than the
/// commissionable one.
///
/// Steps:
/// 1. Derive the 8-byte compressed fabric id from `root_public_key` +
///    `fabric_id` via [`derive_compressed_fabric_id`].
/// 2. Call [`resolve_operational_with_attempts`] to discover the device's
///    operational address within `resolve_attempts` poll rounds (the IP path
///    passes the ~30 s budget, the BLE path the ~60 s budget).
/// 3. Call [`run_case`] to complete the SIGMA-I handshake and register the
///    resulting session.
///
/// The mapping of a `DriverError` result to
/// `on_response(Expectation::CaseFailed, &[])` is the **caller's** job
/// (Task 6's poll loop) — this function simply returns the `Result` so the
/// caller can choose how to handle it.
///
/// # Errors
///
/// - [`DriverError::Crypto`] if [`derive_compressed_fabric_id`] fails
///   (extremely unlikely — ring HKDF over fixed-length inputs).
/// - [`DriverError::Discovery`] if no matching operational mDNS record appears
///   within the poll budget.
/// - [`DriverError::Transport`] / [`DriverError::Io`] / [`DriverError::Timeout`]
///   / [`DriverError::Crypto`] propagated from [`run_case`].
#[allow(clippy::too_many_arguments)] // 9 params reflect the CASE setup split; the caller (commission()) bundles them from a config struct.
pub(crate) async fn establish_case_session<T: AsyncDatagram, D: Discovery>(
    transport: &T,
    sessions: &mut SessionManager,
    discovery: &mut D,
    root_public_key: &[u8; 65],
    fabric_id: u64,
    credentials: CaseCredentials,
    trusted_roots: TrustedRoots,
    peer_node_id: u64,
    now: MatterTime,
    resolve_attempts: u32,
) -> Result<(SessionId, SocketAddr), DriverError> {
    let compressed =
        derive_compressed_fabric_id(root_public_key, fabric_id).map_err(DriverError::Crypto)?;
    let peer_addr =
        resolve_operational_with_attempts(discovery, compressed, peer_node_id, resolve_attempts)
            .await?;
    let peer_fabric_id = credentials.fabric_id;
    let sid = run_case(
        transport,
        sessions,
        peer_addr,
        credentials,
        trusted_roots,
        peer_node_id,
        peer_fabric_id,
        now,
    )
    .await?;
    Ok((sid, peer_addr))
}

/// Inputs for one BLE-transport commissioning run.
///
/// Mirrors [`DriverConfig`]'s parameter set exactly, minus
/// [`DriverConfig::commissionable_addr`]: on the BLE path the BTP
/// `AsyncDatagram` is already connected to the target peripheral (there is no
/// commissionable mDNS resolve step — discovery and BTP connect happen in the
/// controller layer before `commission_ble` is called), so a commissionable
/// address is never needed. Reuses the same `CommissionerConfig` and persistent
/// commissioner-identity types as `commission()`.
pub struct BleDriverConfig<'a> {
    /// The sans-IO commissioner configuration (fabric, trust stores, node ids,
    /// network creds, rng, etc.). Its `network` **must** be
    /// `NetworkCredentials::WiFi` for a Wi-Fi device: a BLE-only device with no
    /// network credentials to install is unprovisionable (design D7). Mirrors
    /// [`DriverConfig::commissioner`].
    pub commissioner: CommissionerConfig<'a>,
    /// Device passcode (from the setup payload). Mirrors [`DriverConfig::passcode`].
    pub passcode: u32,
    /// The controller's **persistent** commissioner operational identity NOC,
    /// signed by the fabric RCAC. Mirrors [`DriverConfig::commissioner_noc`].
    pub commissioner_noc: &'a matter_cert::MatterCertificate,
    /// PKCS#8 DER of the commissioner operational private key (pairs with
    /// `commissioner_noc`). Mirrors [`DriverConfig::commissioner_signer_pkcs8`].
    pub commissioner_signer_pkcs8: &'a [u8],
}

/// Commission a device end to end, returning the resulting [`CommissionedFabric`].
///
/// Drives the full commissioning protocol from start to finish:
///
/// 1. **Discovery.** Resolves the commissionable device address via mDNS if
///    `config.commissionable_addr` is `None`, or uses the pre-resolved address
///    directly for testing.
/// 2. **PASE.** Runs the SPAKE2+ handshake using `config.passcode`, producing
///    a secured PASE session.
/// 3. **Command loop.** Polls the [`crate::Commissioner`] cursor until it emits
///    `Action::Done` or `Action::Abort`, dispatching each action over the
///    correct session (PASE or CASE) — see `run_poll_loop`.
///
/// This is a thin wrapper around the shared `run_commission` body with the
/// **same transport used for both** the PASE/pre-operational phase and the
/// operational CASE phase, [`TransportReliability::Mrp`] (UDP/MRP throughout),
/// and the IP operational-resolve budget. The BLE sibling is [`commission_ble`].
///
/// ## Behavior note (intended change vs. earlier revisions)
///
/// Post-CASE secured traffic now targets the **resolved operational address**
/// (returned by `establish_case_session`) instead of the commissionable
/// address. Same device, same socket on the IP path — strictly more correct;
/// it also makes the two-transport BLE split possible.
///
/// # Errors
///
/// - [`DriverError::Discovery`] if the commissionable device cannot be found via
///   mDNS within the poll budget.
/// - [`DriverError::Crypto`] / [`DriverError::Io`] / [`DriverError::Transport`]
///   / [`DriverError::Timeout`] from the PASE/CASE handshake or any secured
///   round-trip.
/// - [`DriverError::Im`] if an Interaction Model response cannot be parsed.
/// - [`DriverError::Commissioning`] if the state machine returns an error from
///   `poll()` or `on_response()`.
/// - [`DriverError::Aborted`] if the state machine emits `Action::Abort` (device
///   returned a non-OK commissioning result, attestation failure, etc.).
/// - [`DriverError::Handshake`] if `Action::EvictCase` is unexpectedly emitted.
pub async fn commission<T, D>(
    transport: &T,
    discovery: &mut D,
    config: DriverConfig<'_>,
) -> Result<CommissionedFabric, DriverError>
where
    T: AsyncDatagram,
    D: matter_transport::Discovery,
{
    // Bind the Copy identity fields before the partial move of
    // `config.commissioner` below (both are references — Copy — so reading them
    // alongside the move of a *different* field is fine).
    let commissioner_noc = config.commissioner_noc;
    let commissioner_pkcs8 = config.commissioner_signer_pkcs8;

    // 1. Resolve the commissionable address (or use the pre-resolved one).
    let peer = if let Some(addr) = config.commissionable_addr {
        addr
    } else {
        let disc = config.commissioner.setup_payload.discriminator.as_u16();
        resolve_commissionable(discovery, disc).await?
    };

    // Same transport carries both phases; MRP throughout; IP resolve budget.
    run_commission(
        transport,
        peer,
        transport,
        discovery,
        config.commissioner,
        config.passcode,
        commissioner_noc,
        commissioner_pkcs8,
        TransportReliability::Mrp,
        crate::driver::case::RESOLVE_POLL_ATTEMPTS,
    )
    .await
}

/// Commission a device over BLE/BTP: PASE and every pre-operational stage run
/// over `btp` (an already-connected BTP [`AsyncDatagram`]); the operational
/// CASE handshake and all post-CASE secured traffic run over `udp` at the
/// device's mDNS-resolved operational address. `discovery` is used **only** for
/// the operational resolve — the commissionable device was already discovered
/// and BTP-connected by the controller layer (design D2).
///
/// Differs from [`commission`] in exactly three ways, all threaded through the
/// shared `run_commission` body:
///
/// 1. **Two transports.** `btp` for PASE + pre-operational IM, `udp` for CASE
///    onward. The sentinel [`STREAM_PEER`] is the BTP send destination (a BTP
///    `AsyncDatagram` ignores it).
/// 2. **Reliability off.** [`TransportReliability::TransportProvides`]: BTP
///    self-reliabilizes, so the PASE handshake and the secured PASE session
///    suppress MRP (no R-flag, retransmits, or standalone acks; Matter spec
///    §4.12). With MRP off nothing at the exchange layer times out, so
///    pre-operational secured dispatches are wrapped in a response deadline
///    (30 s, or 60 s for `ConnectNetwork`) inside `run_poll_loop`. The
///    operational CASE session runs over `udp` with MRP as usual.
/// 3. **Longer operational resolve.** [`crate::driver::BLE_RESOLVE_POLL_ATTEMPTS`]
///    (~60 s) because a just-provisioned device must still join Wi-Fi and
///    announce its operational record.
///
/// # Errors
///
/// Same error set as [`commission`], plus a [`DriverError::Timeout`] if a
/// pre-operational secured dispatch exceeds its BLE-path response deadline.
pub async fn commission_ble<B, U, D>(
    btp: &B,
    udp: &U,
    discovery: &mut D,
    config: BleDriverConfig<'_>,
) -> Result<CommissionedFabric, DriverError>
where
    B: AsyncDatagram,
    U: AsyncDatagram,
    D: matter_transport::Discovery,
{
    run_commission(
        btp,
        STREAM_PEER,
        udp,
        discovery,
        config.commissioner,
        config.passcode,
        config.commissioner_noc,
        config.commissioner_signer_pkcs8,
        TransportReliability::TransportProvides,
        crate::driver::case::BLE_RESOLVE_POLL_ATTEMPTS,
    )
    .await
}

/// Shared body of [`commission`] and [`commission_ble`]: run PASE over the
/// `pase_transport` (at `pase_peer`, with the given `reliability`), then drive
/// the commissioning poll loop with CASE and post-CASE traffic over
/// `op_transport`, funnelling every exit through one best-effort failsafe-disarm
/// point.
///
/// The two entry points differ only in what they pass here:
/// - `commission`: `(transport, peer, transport, Mrp, RESOLVE_POLL_ATTEMPTS)`.
/// - `commission_ble`: `(btp, STREAM_PEER, udp, TransportProvides, BLE_RESOLVE_POLL_ATTEMPTS)`.
///
/// ## Failsafe disarm on failure
///
/// Once PASE is up the device has (or is about to have) its failsafe armed; any
/// FAILED exit best-effort DISARMs it (over the `pase_transport`/`pase_peer` —
/// the PASE session is the only one guaranteed to exist) so a half-finished run
/// does not leave the device stuck until its own timer expires. `Action::Abort`
/// carries `send_disarm_failsafe`; an abort that knows the failsafe was never
/// armed skips the disarm. RESIDUAL GAP (documented, low severity): this only
/// disarms on explicit error *return* paths — a dropped (cancelled) future runs
/// no disarm.
///
/// # Errors
///
/// See [`commission`] / [`commission_ble`].
#[allow(clippy::too_many_arguments)] // The two transports + reliability + resolve budget are the axes that distinguish the IP and BLE paths; bundling them into a struct would just move the arity.
async fn run_commission<P, O, D>(
    pase_transport: &P,
    pase_peer: SocketAddr,
    op_transport: &O,
    discovery: &mut D,
    commissioner_cfg: CommissionerConfig<'_>,
    passcode: u32,
    commissioner_noc: &matter_cert::MatterCertificate,
    commissioner_pkcs8: &[u8],
    reliability: TransportReliability,
    resolve_attempts: u32,
) -> Result<CommissionedFabric, DriverError>
where
    P: AsyncDatagram,
    O: AsyncDatagram,
    D: matter_transport::Discovery,
{
    use matter_crypto::RingSigner;

    let commissioner_noc = commissioner_noc.clone();

    // 1. Run PASE over the PASE transport with the requested reliability.
    //    (`run_pase_with(.., Mrp)` == `run_pase`, so the IP path is byte-for-byte
    //    unchanged; the BLE path passes `TransportProvides`.)
    let mut sessions = SessionManager::new();
    let pase_sid = crate::driver::pase::run_pase_with(
        pase_transport,
        &mut sessions,
        pase_peer,
        passcode,
        reliability,
    )
    .await?;

    // 2. Source the attestation challenge from the LIVE PASE-derived session.
    //
    //    The attestation challenge the device signs AttestationResponse /
    //    CSRResponse over is the SPAKE2+-derived `attestation_key`, NOT a static
    //    config input. Both sides derive it from the same PASE handshake, so the
    //    device's signature and the Commissioner's verification only agree if the
    //    Commissioner uses THIS live value. Overwrite `pase_attestation_challenge`
    //    with the session's `attestation_key`; any value the caller put there is
    //    intentionally discarded.
    let pase_attestation_challenge = sessions
        .get(pase_sid)
        .ok_or(DriverError::Handshake(
            "PASE session missing after run_pase",
        ))?
        .keys
        .attestation_key;
    let mut commissioner_cfg = commissioner_cfg;
    commissioner_cfg.pase_attestation_challenge = pase_attestation_challenge;

    // 3. Load the caller's PERSISTENT commissioner operational identity so we
    //    have CASE credentials ready when Action::EstablishCase arrives. The
    //    NOC is signed by the fabric RCAC (the same RCAC the device receives
    //    via AddTrustedRootCertificate), so the device validates it during CASE.
    let fabric = commissioner_cfg.fabric;
    let commissioner_node_id = commissioner_cfg.commissioner_node_id;
    let ipk_epoch_key = commissioner_cfg.ipk_epoch_key;
    // Validation clock for the device's operational cert chain during CASE.
    // Captured before `commissioner_cfg` is moved into the state machine.
    let validation_time = commissioner_cfg.now;
    let commissioner_signer_value =
        RingSigner::from_pkcs8(commissioner_pkcs8).map_err(DriverError::Crypto)?;
    // Wrap in Option so we can move it into CaseCredentials exactly once
    // (EstablishCase fires at most once per run).
    let mut commissioner_signer: Option<RingSigner> = Some(commissioner_signer_value);

    // The CASE session slot carries both the local session id and the resolved
    // operational address so post-CASE dispatches target the operational node.
    let mut case_slot: Option<(SessionId, SocketAddr)> = None;

    // 4. Build the state machine cursor.
    let mut sm = crate::Commissioner::new(commissioner_cfg)?;

    // 5. Poll loop (single-return so every exit funnels through the disarm below).
    let outcome = run_poll_loop(
        &mut sm,
        pase_transport,
        op_transport,
        discovery,
        &mut sessions,
        pase_sid,
        pase_peer,
        &mut case_slot,
        &mut commissioner_signer,
        &commissioner_noc,
        commissioner_node_id,
        &ipk_epoch_key,
        fabric,
        validation_time,
        reliability,
        resolve_attempts,
    )
    .await;

    match outcome {
        Ok(fabric) => Ok(fabric),
        Err(exit) => {
            // Best-effort disarm over the PASE transport/peer before surfacing
            // the error. `disarm_on_exit` honors an abort that asked to skip it.
            if disarm_on_exit(&exit) {
                // Bound the rollback dispatch with the SAME response deadline the
                // poll loop uses. Under `Mrp` (IP path) `with_response_deadline`
                // is a transparent pass-through — MRP's own timers bound the
                // wait, so IP-path behavior is byte-for-byte unchanged. Under
                // `TransportProvides` (BLE) MRP is off, so an unbounded rollback
                // over a stalled BTP session would hang forever (D11.3); the
                // 30 s deadline (rollback is an `ArmFailSafe` invoke, never a
                // ConnectNetwork) caps it. A rollback timeout is swallowed by the
                // outer `let _` exactly like any other best-effort rollback
                // failure — the ORIGINAL `exit` error is what we return, so a
                // rollback timeout must never mask it.
                let _ = with_response_deadline(reliability, false, async {
                    rollback(pase_transport, &mut sessions, pase_sid, pase_peer).await;
                    Ok(())
                })
                .await;
            }
            Err(exit.into_driver_error())
        }
    }
}

/// Apply a BLE-path response deadline to a secured dispatch future.
///
/// Under [`TransportReliability::Mrp`] (the IP path) this is a transparent
/// `fut.await` — MRP's own retransmit/expiry timers bound the wait, so the
/// behavior of `commission()` is unchanged. Under
/// [`TransportReliability::TransportProvides`] (BLE) MRP is off and nothing at
/// the exchange layer times out, so the future is wrapped in a
/// [`tokio::time::timeout`]: [`CONNECT_NETWORK_RESPONSE_DEADLINE`] (60 s) when
/// `is_connect_network`, else [`RESPONSE_DEADLINE`] (30 s). A fired deadline
/// maps to [`DriverError::Timeout`] and routes through the normal rollback path.
///
/// # Errors
///
/// - Any error the wrapped `fut` produces.
/// - [`DriverError::Timeout`] if the deadline fires (BLE path only).
async fn with_response_deadline<T>(
    reliability: TransportReliability,
    is_connect_network: bool,
    fut: impl std::future::Future<Output = Result<T, DriverError>>,
) -> Result<T, DriverError> {
    match reliability {
        TransportReliability::Mrp => fut.await,
        TransportReliability::TransportProvides => {
            let deadline = if is_connect_network {
                CONNECT_NETWORK_RESPONSE_DEADLINE
            } else {
                RESPONSE_DEADLINE
            };
            match tokio::time::timeout(deadline, fut).await {
                Ok(result) => result,
                Err(_elapsed) => Err(DriverError::Timeout {
                    exchange_id: RESPONSE_DEADLINE_EXCHANGE_SENTINEL,
                }),
            }
        }
    }
}

/// Whether a failed [`run_poll_loop`] exit should trigger a best-effort failsafe
/// disarm before the error is surfaced.
///
/// `true` for any [`LoopExit::Failed`] (the device may have an armed failsafe),
/// and for an [`LoopExit::Aborted`] whose `disarm` flag is set; `false` only for
/// an abort the state machine marked as not needing a disarm (failsafe never
/// armed / already rolled back).
fn disarm_on_exit(exit: &LoopExit) -> bool {
    match exit {
        LoopExit::Failed(_) => true,
        LoopExit::Aborted { disarm, .. } => *disarm,
    }
}

/// How the commissioning poll loop ([`run_poll_loop`]) terminated abnormally.
///
/// `Ok` from the loop is the success case ([`Action::Done`]); these are the two
/// failure shapes, kept distinct so the caller knows whether the state machine
/// asked to suppress the failsafe disarm.
enum LoopExit {
    /// The state machine emitted [`crate::Action::Abort`]. `disarm` mirrors its
    /// `send_disarm_failsafe` flag; `reason` is the human-readable summary.
    Aborted {
        /// Whether the caller should best-effort disarm the failsafe.
        disarm: bool,
        /// Human-readable abort reason from the state machine.
        reason: String,
    },
    /// Any other error (`?`-propagated). The caller disarms best-effort then
    /// surfaces this error.
    Failed(DriverError),
}

impl LoopExit {
    /// Convert this loop exit into the public [`DriverError`] surfaced by
    /// [`commission`].
    fn into_driver_error(self) -> DriverError {
        match self {
            LoopExit::Aborted { reason, .. } => DriverError::Aborted(reason),
            LoopExit::Failed(e) => e,
        }
    }
}

impl From<DriverError> for LoopExit {
    fn from(e: DriverError) -> Self {
        LoopExit::Failed(e)
    }
}

impl From<crate::CommissioningError> for LoopExit {
    fn from(e: crate::CommissioningError) -> Self {
        LoopExit::Failed(DriverError::from(e))
    }
}

/// The commissioning command loop, factored out of [`run_commission`] so every
/// exit path returns through one place (letting the caller best-effort disarm
/// the device failsafe on failure — see the call site).
///
/// Two transports are threaded so a BLE run can split the phases:
/// `SessionContext::Pase` dispatches go over `pase_transport` at `pase_peer`;
/// `Action::EstablishCase` and every post-CASE `SessionContext::Case` dispatch
/// go over `op_transport` at the mDNS-resolved operational address (stored in
/// `case_slot` alongside the session id). On the IP path `commission()` passes
/// the same transport for both and `pase_peer` for both, so behavior is
/// identical except that post-CASE traffic now targets the resolved operational
/// address rather than the commissionable one (a no-op on a single socket).
///
/// `reliability` selects the response-deadline policy for PASE-session
/// dispatches via [`with_response_deadline`] (transparent under `Mrp`, wrapped
/// under `TransportProvides`); `resolve_attempts` is the operational-resolve
/// budget passed to `establish_case_session`. CASE-session dispatches always run
/// over `op_transport` with MRP, so they are never deadline-wrapped.
///
/// Returns the [`CommissionedFabric`] on `Action::Done`, or a [`LoopExit`]
/// describing the failure otherwise.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_poll_loop<P, O, D>(
    sm: &mut crate::Commissioner,
    pase_transport: &P,
    op_transport: &O,
    discovery: &mut D,
    sessions: &mut SessionManager,
    pase_sid: SessionId,
    pase_peer: SocketAddr,
    case_slot: &mut Option<(SessionId, SocketAddr)>,
    commissioner_signer: &mut Option<matter_crypto::RingSigner>,
    commissioner_noc: &matter_cert::MatterCertificate,
    commissioner_node_id: u64,
    ipk_epoch_key: &[u8; 16],
    fabric: &crate::FabricRecord,
    validation_time: MatterTime,
    reliability: TransportReliability,
    resolve_attempts: u32,
) -> Result<CommissionedFabric, LoopExit>
where
    P: AsyncDatagram,
    O: AsyncDatagram,
    D: matter_transport::Discovery,
{
    use crate::{Action, SessionContext};
    use matter_cert::{TrustAnchor, TrustedRoots};

    loop {
        let action = sm.poll().map_err(DriverError::from)?;
        match action {
            Action::Invoke {
                session,
                endpoint,
                cluster,
                command,
                payload,
                expect,
            } => {
                let path = crate::im::CommandPath {
                    endpoint,
                    cluster,
                    command,
                };
                // NetworkCommissioning::ConnectNetwork gets the longer BLE-path
                // response deadline (device does slow Wi-Fi assoc + DHCP inline).
                let is_connect_network = cluster
                    == crate::clusters::network_commissioning::CLUSTER_ID
                    && command
                        == crate::clusters::network_commissioning::command_id::CONNECT_NETWORK;
                let outcome = match session {
                    // PASE-session dispatch → PASE transport; under
                    // `TransportProvides` it is bounded by a response deadline.
                    SessionContext::Pase => {
                        with_response_deadline(
                            reliability,
                            is_connect_network,
                            dispatch_invoke(
                                pase_transport,
                                sessions,
                                pase_sid,
                                pase_peer,
                                path,
                                &payload,
                            ),
                        )
                        .await?
                    }
                    // CASE-session dispatch → operational transport at the
                    // resolved address; always MRP, so MRP bounds the wait.
                    SessionContext::Case => {
                        let (sid, addr) = case_slot.ok_or(DriverError::Handshake(
                            "CASE session required but not yet established",
                        ))?;
                        dispatch_invoke(op_transport, sessions, sid, addr, path, &payload).await?
                    }
                };
                // Map InvokeOutcome → the byte slice on_response expects:
                //   Command(fields) → the response-command TLV bytes verbatim.
                //   Status(Success) → [0x00] (single byte; state machine checks first byte).
                //   Status(Failure(code)) → [code].
                let response_payload: Vec<u8> = match outcome {
                    InvokeOutcome::Command(fields) => fields,
                    InvokeOutcome::Status(crate::im::ImStatus::Success) => vec![0x00],
                    InvokeOutcome::Status(crate::im::ImStatus::Failure(code)) => vec![code],
                    // ImStatus is #[non_exhaustive] across the crate boundary since the
                    // M7.1 lift: map any future variant to generic FAILURE, never success.
                    InvokeOutcome::Status(_) => vec![0x01],
                };
                sm.on_response(expect, &response_payload)?;
            }

            Action::ReadAttribute {
                session,
                endpoint,
                cluster,
                attributes,
                expect,
            } => {
                // Build one AttributePath per attribute id in the slice.
                let paths: Vec<crate::im::AttributePath> = attributes
                    .iter()
                    .map(|&attr| crate::im::AttributePath {
                        endpoint,
                        cluster,
                        attribute: attr,
                    })
                    .collect();
                let report = match session {
                    // Reads occur during the PASE (pre-operational) phase; under
                    // `TransportProvides` they are deadline-bounded (never a
                    // ConnectNetwork, so the standard deadline).
                    SessionContext::Pase => {
                        with_response_deadline(
                            reliability,
                            false,
                            dispatch_read(pase_transport, sessions, pase_sid, pase_peer, &paths),
                        )
                        .await?
                    }
                    SessionContext::Case => {
                        let (sid, addr) = case_slot.ok_or(DriverError::Handshake(
                            "CASE session required but not yet established for ReadAttribute",
                        ))?;
                        dispatch_read(op_transport, sessions, sid, addr, &paths).await?
                    }
                };
                let read_payload = extract_read_payload(expect, &report)?;
                sm.on_response(expect, &read_payload)?;
                // D7: the NetworkCommissioning read also carries
                // `ConnectMaxTimeSeconds` (attr 0x0009). It rides in the
                // same `ReportData` but does not route the state machine,
                // so it is applied out-of-band here (after the FeatureMap
                // response) to size the FailsafeBeforeNetworkEnable
                // extension. Absent / non-uint → left at the default.
                if expect == crate::Expectation::NetworkCommissioningInfo {
                    if let Some(secs) = extract_connect_max_time_seconds(&report) {
                        sm.set_connect_max_time_seconds(secs);
                    }
                }
            }

            Action::EstablishCase {
                fabric_id,
                peer_node_id,
            } => {
                // Flush the standalone ack still owed for the last secured
                // (PASE-session) response before switching to the unsecured
                // CASE exchange — otherwise the device retransmits that
                // response into the Sigma handshake (exchange.rs documents
                // the deferred ack; observed on a real device: Tapo P110M,
                // M6.6.5 validation). Over the PASE transport/peer. Under
                // `TransportProvides` no MRP timers exist, so this is a no-op.
                flush_pending_acks(pase_transport, sessions, pase_peer).await?;
                // Build CASE credentials for the commissioner's own identity.
                // commissioner_signer is moved out of the Option here — it can
                // only be taken once; a second EstablishCase would return an
                // error.
                let signer = commissioner_signer.take().ok_or(DriverError::Handshake(
                    "EstablishCase emitted more than once per commission() run",
                ))?;
                // `CaseCredentials.ipk` is the *operational* IPK (what the
                // Sigma1 destination id is HMAC'd with) — derived from the
                // SAME epoch key AddNOC sent, salted with the compressed
                // fabric id (spec §4.15.2). Passing the raw epoch key makes
                // real devices reject Sigma1 with NoSharedTrustRoots
                // (observed: Tapo P110M, M6.6.5 validation).
                let compressed_fabric_id = matter_crypto::derive_compressed_fabric_id(
                    fabric.root_public_key.as_bytes(),
                    fabric_id,
                )
                .map_err(DriverError::Crypto)?;
                let operational_ipk = matter_crypto::operational::derive_operational_ipk(
                    ipk_epoch_key,
                    &compressed_fabric_id,
                )
                .map_err(DriverError::Crypto)?;
                let credentials = CaseCredentials {
                    noc: commissioner_noc.clone(),
                    icac: fabric.icac_cert.clone(),
                    signer: Box::new(signer),
                    fabric_id,
                    node_id: commissioner_node_id,
                    ipk: operational_ipk,
                    rcac_public_key: *fabric.root_public_key.as_bytes(),
                };
                // Build TrustedRoots from this fabric's RCAC.
                let mut trusted_roots = TrustedRoots::new();
                trusted_roots.add(TrustAnchor::from_root_cert(&fabric.root_cert));

                // CASE runs over the OPERATIONAL transport; the resolved address
                // is captured into `case_slot` so post-CASE dispatches target it.
                match establish_case_session(
                    op_transport,
                    sessions,
                    discovery,
                    fabric.root_public_key.as_bytes(),
                    fabric_id,
                    credentials,
                    trusted_roots,
                    peer_node_id,
                    validation_time,
                    resolve_attempts,
                )
                .await
                {
                    Ok((sid, addr)) => {
                        *case_slot = Some((sid, addr));
                        sm.on_case_established()?;
                    }
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(error = %e, "CASE establishment failed");
                        #[cfg(not(feature = "tracing"))]
                        let _ = &e;
                        sm.on_response(crate::Expectation::CaseFailed, &[])?;
                    }
                }
            }

            Action::Done(commissioned_fabric) => {
                return Ok(commissioned_fabric);
            }

            Action::Abort {
                send_disarm_failsafe,
                reason,
            } => {
                // The caller best-effort disarms after we return — pass the
                // state machine's `send_disarm_failsafe` flag through so an
                // abort that knows the failsafe was never armed skips it.
                return Err(LoopExit::Aborted {
                    disarm: send_disarm_failsafe,
                    reason,
                });
            }

            Action::EvictCase { .. } => {
                return Err(LoopExit::Failed(DriverError::Handshake(
                    "unexpected Action::EvictCase in M6 commission() loop (multi-fabric not implemented)",
                )));
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::items_after_statements, // nested struct/impl in test body
    clippy::too_many_lines          // CASE integration tests are inherently verbose
)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use matter_codec::{Tag, TlvWriter};
    use matter_crypto::pase::PaseSessionKeys;
    use matter_transport::{
        DecodeInboundOutput, MatterService, MrpFlags, PeerHint, ProtocolId, QueryHandle,
        SessionRole,
    };

    use crate::driver::datagram::InMemoryDatagram;

    // -----------------------------------------------------------------------
    // Device-side helpers — test-only, NOT part of the controller public API.
    //
    // A Matter controller never parses InvokeRequests (the device does) or
    // decodes ArmFailSafe request fields (the device does). These helpers live
    // here so the in-process loopback device simulator in the Task 5 tests can
    // assert/reply without leaking device-codec into production.
    // -----------------------------------------------------------------------

    /// Decoded single-command `InvokeRequestMessage`.
    /// Used by the device-side task in the `rollback` test to assert path+fields.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct InvokeRequest {
        path: crate::im::CommandPath,
        fields_tlv: Vec<u8>,
    }

    /// Parse a single-command `InvokeRequestMessage` (device-side, test-only).
    fn parse_invoke_request(bytes: &[u8]) -> Result<InvokeRequest, crate::im::ImError> {
        use crate::im::{
            error::ImError, expect_message_struct, read_container_members, read_container_value,
            skip_container, CommandPath,
        };
        use matter_codec::{ContainerKind, Element, Tag, TlvReader, Value};

        let mut r = TlvReader::new(bytes);
        expect_message_struct(&mut r)?;

        // Scan for Context(2) = InvokeRequests array.
        loop {
            match r.next()? {
                None | Some(Element::ContainerEnd) => {
                    return Err(ImError::MissingField("InvokeRequests"))
                }
                Some(Element::ContainerStart {
                    tag: Tag::Context(2),
                    kind: ContainerKind::Array,
                }) => break,
                Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
                Some(_) => {}
            }
        }

        // Expect the first CommandDataIB (anonymous struct).
        match r.next()? {
            Some(Element::ContainerStart {
                kind: ContainerKind::Structure,
                ..
            }) => {}
            _ => return Err(ImError::MissingField("CommandDataIB")),
        }

        // Parse CommandDataIB body: scan for CommandPathIB (ctx 0) and CommandFields (ctx 1).
        let mut path: Option<CommandPath> = None;
        let mut fields_tlv: Vec<u8> = Vec::new();
        loop {
            match r.next()? {
                None => return Err(ImError::MissingField("CommandDataIB.body")),
                Some(Element::ContainerEnd) => break,
                Some(Element::ContainerStart {
                    tag: Tag::Context(0),
                    kind: ContainerKind::List,
                }) => {
                    let members = read_container_members(&mut r)?;
                    let mut endpoint = None;
                    let mut cluster = None;
                    let mut command = None;
                    for (tag, v) in &members {
                        match (tag, v) {
                            (Tag::Context(0), Value::Uint(n)) => {
                                endpoint = Some(u16::try_from(*n).map_err(|_| {
                                    ImError::UnexpectedValue("CommandPath.endpoint exceeds u16")
                                })?);
                            }
                            (Tag::Context(1), Value::Uint(n)) => {
                                cluster = Some(u32::try_from(*n).map_err(|_| {
                                    ImError::UnexpectedValue("CommandPath.cluster exceeds u32")
                                })?);
                            }
                            (Tag::Context(2), Value::Uint(n)) => {
                                command = Some(u32::try_from(*n).map_err(|_| {
                                    ImError::UnexpectedValue("CommandPath.command exceeds u32")
                                })?);
                            }
                            _ => {}
                        }
                    }
                    path = Some(CommandPath {
                        endpoint: endpoint.ok_or(ImError::MissingField("CommandPath.endpoint"))?,
                        cluster: cluster.ok_or(ImError::MissingField("CommandPath.cluster"))?,
                        command: command.ok_or(ImError::MissingField("CommandPath.command"))?,
                    });
                }
                Some(Element::ContainerStart {
                    tag: Tag::Context(1),
                    kind,
                }) => {
                    let v = read_container_value(&mut r, kind)?;
                    // Re-encode as anonymous-tagged struct so callers get a self-contained TLV blob.
                    let mut buf = Vec::new();
                    let mut w = matter_codec::TlvWriter::new(&mut buf);
                    w.write_value(Tag::Anonymous, &v).unwrap();
                    fields_tlv = buf;
                }
                Some(Element::ContainerStart { .. }) => skip_container(&mut r)?,
                Some(_) => {}
            }
        }

        // If no CommandFields were present, canonicalize to an anonymous empty struct.
        if fields_tlv.is_empty() {
            let mut buf = Vec::new();
            let mut w = matter_codec::TlvWriter::new(&mut buf);
            w.write_value(Tag::Anonymous, &Value::Structure(Vec::new()))
                .unwrap();
            fields_tlv = buf;
        }

        Ok(InvokeRequest {
            path: path.ok_or(ImError::MissingField("CommandDataIB.CommandPath"))?,
            fields_tlv,
        })
    }

    /// Decoded `ArmFailSafe` request fields (device-side, test-only).
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ArmFailSafeFields {
        expiry_length_seconds: u16,
        breadcrumb: u64,
    }

    /// Decode `ArmFailSafe` request fields from a TLV anonymous struct (device-side, test-only).
    fn decode_arm_fail_safe_fields(tlv: &[u8]) -> ArmFailSafeFields {
        use matter_codec::{ContainerKind, Element, Tag, TlvReader, Value};
        let mut r = TlvReader::new(tlv);
        if !matches!(
            r.next().ok().flatten(),
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure,
            })
        ) {
            return ArmFailSafeFields {
                expiry_length_seconds: 0,
                breadcrumb: 0,
            };
        }
        let mut expiry: u16 = 0;
        let mut breadcrumb: u64 = 0;
        loop {
            match r.next().ok().flatten() {
                None | Some(Element::ContainerEnd) => break,
                Some(Element::Scalar {
                    tag: Tag::Context(0),
                    value: Value::Uint(v),
                }) => {
                    expiry = u16::try_from(v).unwrap_or(0);
                }
                Some(Element::Scalar {
                    tag: Tag::Context(1),
                    value: Value::Uint(v),
                }) => {
                    breadcrumb = v;
                }
                Some(_) => {}
            }
        }
        ArmFailSafeFields {
            expiry_length_seconds: expiry,
            breadcrumb,
        }
    }

    /// Encode an `ArmFailSafeResponse` with the given error code (device-side, test-only).
    fn encode_arm_fail_safe_response(error_code: u8) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_uint(Tag::Context(0), u64::from(error_code)).unwrap();
        w.end_container().unwrap();
        buf
    }

    struct FakeDiscovery {
        service: MatterService,
    }

    impl Discovery for FakeDiscovery {
        fn publish(&mut self, _s: &MatterService) -> matter_transport::Result<()> {
            Ok(())
        }
        fn unpublish(&mut self, _n: &str, _k: ServiceKind) -> matter_transport::Result<()> {
            Ok(())
        }
        fn query(&mut self, _k: ServiceKind) -> matter_transport::Result<QueryHandle> {
            Ok(QueryHandle(1))
        }
        fn stop_query(&mut self, _h: QueryHandle) {}
        fn poll_results(&mut self, _h: QueryHandle) -> Vec<MatterService> {
            vec![self.service.clone()]
        }
    }

    #[tokio::test]
    async fn resolve_commissionable_matches_discriminator() {
        const DISCRIMINATOR: u16 = 0xF00;
        let mut txt = HashMap::new();
        txt.insert("D".to_string(), DISCRIMINATOR.to_string().into_bytes());
        let mut disc = FakeDiscovery {
            service: MatterService::new(
                "AABBCCDDEEFF1122".to_string(),
                ServiceKind::Commissionable,
                vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))],
                5540,
                txt,
            ),
        };
        let addr = resolve_commissionable(&mut disc, DISCRIMINATOR)
            .await
            .unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)), 5540)
        );
    }

    #[tokio::test]
    async fn resolve_commissionable_matches_short_discriminator_from_manual_code() {
        // A device advertises its full long discriminator (0x4B4 = 1204 — the
        // real Tapo P110M value), but a manual pairing code only carries the
        // short discriminator 0x4, packed as `short << 8` = 0x400 = 1024. The
        // exact long match fails; the upper-4-bit short match (0x4B4 >> 8 == 0x4)
        // succeeds — the connectedhomeip `kShortDiscriminator` behaviour.
        const DEVICE_LONG: u16 = 0x4B4;
        const MANUAL_SHORT_PACKED: u16 = 0x0400;
        let mut txt = HashMap::new();
        txt.insert("D".to_string(), DEVICE_LONG.to_string().into_bytes());
        let mut disc = FakeDiscovery {
            service: MatterService::new(
                "3C64CF0B1D42".to_string(),
                ServiceKind::Commissionable,
                vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 248))],
                5540,
                txt,
            ),
        };
        let addr = resolve_commissionable(&mut disc, MANUAL_SHORT_PACKED)
            .await
            .unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 248)), 5540)
        );
    }

    /// Build two `SessionManager`s sharing one PASE key set, cross-registered
    /// as Initiator (controller) / Responder (device). Mirrors the harness in
    /// `exchange.rs::tests::paired_pase_sessions`.
    fn paired_pase_sessions() -> (SessionManager, SessionManager) {
        let keys = PaseSessionKeys {
            ke: [0u8; 16],
            i2r_key: [1u8; 16],
            r2i_key: [2u8; 16],
            attestation_key: [3u8; 16],
        };
        let mut ctrl = SessionManager::new();
        let mut dev = SessionManager::new();
        ctrl.register_pase(keys.clone(), SessionRole::Initiator, 1, PeerHint::default());
        dev.register_pase(keys, SessionRole::Responder, 1, PeerHint::default());
        (ctrl, dev)
    }

    /// Build a minimal valid `InvokeResponseMessage` that carries a single
    /// `CommandDataIB` with the given `path` and `fields_tlv`, ready to be
    /// parsed by `crate::im::parse_invoke_response`.
    ///
    /// Hand-rolls the TLV because the `im` module only exports a request
    /// builder, not a response builder. Structure mirrors the
    /// `parses_command_response_payload` test in `im/invoke.rs`.
    fn build_canned_invoke_response(path: crate::im::CommandPath, fields_tlv: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseMessage
        w.put_bool(Tag::Context(0), false).unwrap(); // SuppressResponse
        w.start_array(Tag::Context(1)).unwrap(); // InvokeResponses
        {
            w.start_structure(Tag::Anonymous).unwrap(); // InvokeResponseIB
            w.start_structure(Tag::Context(0)).unwrap(); // Command = CommandDataIB
                                                         // CommandPathIB list
            w.start_list(Tag::Context(0)).unwrap();
            w.put_uint(Tag::Context(0), u64::from(path.endpoint))
                .unwrap();
            w.put_uint(Tag::Context(1), u64::from(path.cluster))
                .unwrap();
            w.put_uint(Tag::Context(2), u64::from(path.command))
                .unwrap();
            w.end_container().unwrap(); // CommandPathIB
                                        // CommandFields: embed fields_tlv as context-1 struct.
                                        // `put_preencoded` re-tags the anonymous-struct byte to context-1.
            w.put_preencoded(Tag::Context(1), fields_tlv).unwrap();
            w.end_container().unwrap(); // CommandDataIB
            w.end_container().unwrap(); // InvokeResponseIB
        }
        w.end_container().unwrap(); // InvokeResponses
        w.put_uint(Tag::Context(0xFF), u64::from(crate::im::IM_REVISION))
            .unwrap();
        w.end_container().unwrap(); // InvokeResponseMessage
        buf
    }

    /// `dispatch_invoke` sends an `InvokeRequest` via `secured_round_trip`,
    /// and the device side replies with a canned `InvokeResponse`. The test
    /// asserts the returned `InvokeOutcome::Command(fields_tlv)` matches the
    /// bytes we put into the canned response.
    #[tokio::test]
    async fn dispatch_invoke_returns_command_fields() {
        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        // The command fields we expect the device to echo back.
        // An anonymous empty struct: 0x15 0x18 (start-structure anonymous + end-container).
        let canned_fields: Vec<u8> = vec![0x15, 0x18];

        let path = CommandPath {
            endpoint: 0,
            cluster: 0x0030, // General Commissioning
            command: 0x00,   // ArmFailSafe
        };

        // Build the canned InvokeResponse the device will send back.
        let canned_response = build_canned_invoke_response(path, &canned_fields);

        // Controller side: call dispatch_invoke and collect the outcome.
        let controller =
            dispatch_invoke(&ctrl_io, &mut ctrl, session, dev_addr, path, &canned_fields);

        // Device side: receive the InvokeRequest and reply with the canned InvokeResponse.
        let device = async {
            loop {
                let (pkt, _) = dev_io.recv_from().await.unwrap();
                if let DecodeInboundOutput::AppMessage { exchange_id, .. } =
                    dev.decode_inbound(&pkt, Instant::now()).unwrap()
                {
                    // Reply on the SAME exchange_id (opcode 0x09 = InvokeResponse).
                    let out = dev
                        .encode_outbound(
                            session,
                            Some(exchange_id),
                            0x09,
                            ProtocolId::INTERACTION_MODEL,
                            &canned_response,
                            MrpFlags { reliable: true },
                            Instant::now(),
                        )
                        .unwrap();
                    dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
                    break;
                }
            }
        };

        let (outcome, ()) = tokio::join!(controller, device);
        // The parse_invoke_response re-anonymises the CommandFields: an empty
        // anonymous struct re-encodes as [0x15, 0x18].
        assert_eq!(outcome.unwrap(), InvokeOutcome::Command(canned_fields));
    }

    /// Build a minimal `ReportDataMessage` carrying the supplied `(path, value)` pairs.
    ///
    /// Hand-rolls the TLV because the `im` module only exports a request builder,
    /// not a response builder. The layout matches what `parse_report_data` expects:
    ///
    /// ```text
    /// ReportDataMessage (anon struct)
    ///   AttributeReports [1] (array)
    ///     AttributeReportIB (anon struct)
    ///       AttributeData [1] (struct)
    ///         AttributePathIB [1] (list)
    ///           endpoint [2], cluster [3], attribute [4]
    ///         Data [2] = <value>
    ///   InteractionModelRevision [0xFF]
    /// ```
    fn build_canned_report_data(
        entries: &[(crate::im::AttributePath, matter_codec::Value)],
    ) -> Vec<u8> {
        use matter_codec::{Tag, TlvWriter};
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap(); // ReportDataMessage
        w.start_array(Tag::Context(1)).unwrap(); // AttributeReports
        for (path, value) in entries {
            w.start_structure(Tag::Anonymous).unwrap(); // AttributeReportIB
            w.start_structure(Tag::Context(1)).unwrap(); // AttributeData
                                                         // AttributePathIB list at [1]
            w.start_list(Tag::Context(1)).unwrap();
            w.put_uint(Tag::Context(2), u64::from(path.endpoint))
                .unwrap();
            w.put_uint(Tag::Context(3), u64::from(path.cluster))
                .unwrap();
            w.put_uint(Tag::Context(4), u64::from(path.attribute))
                .unwrap();
            w.end_container().unwrap(); // AttributePathIB
                                        // Data at [2] — write the value as context-tag-2
            w.write_value(Tag::Context(2), value).unwrap();
            w.end_container().unwrap(); // AttributeData
            w.end_container().unwrap(); // AttributeReportIB
        }
        w.end_container().unwrap(); // AttributeReports
        w.put_uint(Tag::Context(0xFF), u64::from(crate::im::IM_REVISION))
            .unwrap();
        w.end_container().unwrap(); // ReportDataMessage
        buf
    }

    // -----------------------------------------------------------------------
    // extract_read_payload unit tests (Step 1 — failing first, then pass)
    // -----------------------------------------------------------------------

    /// A `ReportData` carrying a bare `FeatureMap` u32 is mapped to the bare
    /// anonymous-tagged uint TLV that `decode_feature_map` expects.
    #[test]
    fn extract_read_payload_network_commissioning_info_bare_uint() {
        use crate::im::{AttributePath, AttributeReportItem, ReportOp};
        use crate::Expectation;
        use matter_codec::Value;

        // FeatureMap = 0x01 (WIFI bit set)
        let feat_val: u64 = 0x01;
        let report = crate::im::ReportData::new(
            vec![AttributeReportItem::new(
                AttributePath {
                    endpoint: 0,
                    cluster: crate::clusters::network_commissioning::CLUSTER_ID, // 0x0031
                    attribute: crate::clusters::network_commissioning::attribute_id::FEATURE_MAP, // 0xFFFC
                },
                ReportOp::Replace,
                Value::Uint(feat_val),
                None,
            )],
            None,
            false,
            false,
        );

        let payload = extract_read_payload(Expectation::NetworkCommissioningInfo, &report).unwrap();

        // decode_feature_map expects: anonymous uint TLV.
        // For value 0x01 (fits in u8): [0x04, 0x01]
        let mut expected = Vec::new();
        let mut w = matter_codec::TlvWriter::new(&mut expected);
        w.put_uint(matter_codec::Tag::Anonymous, feat_val).unwrap();
        assert_eq!(
            payload, expected,
            "NetworkCommissioningInfo payload mismatch: got {payload:02x?}, expected {expected:02x?}",
        );

        // Also verify the produced bytes round-trip through decode_feature_map.
        let features = crate::clusters::network_commissioning::decode_feature_map(&payload)
            .expect("decode_feature_map should accept the re-encoded payload");
        assert!(
            features.contains(
                crate::clusters::network_commissioning::NetworkCommissioningFeature::WIFI
            ),
            "WIFI bit must be set after round-trip",
        );
    }

    /// Replay of a real device's `GeneralCommissioning` report (Tapo P110M,
    /// M6.6.5 validation): all four requested attributes come back, and
    /// `BasicCommissioningInfo` is attribute **0x0001** (spec §11.10.6) — NOT
    /// 0x0004, which is `SupportsConcurrentConnection`, a bool. The extractor
    /// must pick the struct at 0x0001.
    #[test]
    fn extract_read_payload_picks_basic_commissioning_info_at_0x0001() {
        use crate::im::{AttributePath, AttributeReportItem, ReportOp};
        use crate::Expectation;
        use matter_codec::{Tag, Value};

        let gc = crate::clusters::general_commissioning::CLUSTER_ID;
        let item = |attribute: u32, value: Value| {
            AttributeReportItem::new(
                AttributePath {
                    endpoint: 0,
                    cluster: gc,
                    attribute,
                },
                ReportOp::Replace,
                value,
                None,
            )
        };
        // Order and values as the Tapo returned them.
        let report = crate::im::ReportData::new(
            vec![
                item(0x0004, Value::Bool(true)), // SupportsConcurrentConnection
                item(0x0002, Value::Uint(0)),    // RegulatoryConfig
                item(
                    0x0001, // BasicCommissioningInfo
                    Value::Structure(vec![
                        (Tag::Context(0), Value::Uint(60)),
                        (Tag::Context(1), Value::Uint(900)),
                    ]),
                ),
                item(0x0000, Value::Uint(0)), // Breadcrumb
            ],
            None,
            false,
            false,
        );

        let payload = extract_read_payload(Expectation::CommissioningInfo, &report).unwrap();
        // Must be the anonymous-tagged STRUCT (0x15 … 0x18), not the bool.
        assert_eq!(
            payload.first(),
            Some(&0x15u8),
            "extractor must return the BasicCommissioningInfo struct, \
             not another attribute's value"
        );
        assert_eq!(payload.last(), Some(&0x18u8));
    }

    /// A `ReportData` carrying a `BasicCommissioningInfo` struct is re-encoded as
    /// an anonymous-tagged struct that `decode_basic_commissioning_info` accepts.
    #[test]
    fn extract_read_payload_commissioning_info_struct() {
        use crate::im::{AttributePath, AttributeReportItem, ReportOp};
        use crate::Expectation;
        use matter_codec::{Tag, Value};

        // BasicCommissioningInfo struct: { ctx(0): 120u16, ctx(1): 900u16 }
        let struct_value = Value::Structure(vec![
            (Tag::Context(0), Value::Uint(120)),
            (Tag::Context(1), Value::Uint(900)),
        ]);
        let report = crate::im::ReportData::new(
            vec![AttributeReportItem::new(
                AttributePath {
                    endpoint: 0,
                    cluster: crate::clusters::general_commissioning::CLUSTER_ID, // 0x0030
                    attribute: attr_id::BASIC_COMMISSIONING_INFO,                // 0x0001
                },
                ReportOp::Replace,
                struct_value.clone(),
                None,
            )],
            None,
            false,
            false,
        );

        let payload = extract_read_payload(Expectation::CommissioningInfo, &report).unwrap();

        // decode_basic_commissioning_info expects an anonymous-tagged struct.
        // The payload must start with 0x15 (anon-struct-start) and end with 0x18.
        assert_eq!(
            payload.first(),
            Some(&0x15u8),
            "should start with anon-struct byte"
        );
        assert_eq!(
            payload.last(),
            Some(&0x18u8),
            "should end with end-container"
        );

        // Round-trip: decode_basic_commissioning_info must extract failsafe = 120.
        let info =
            crate::clusters::general_commissioning::decode_basic_commissioning_info(&payload)
                .expect("decode_basic_commissioning_info should accept the re-encoded payload");
        assert_eq!(info.failsafe_expiry_length_seconds, 120);
        assert_eq!(info.max_cumulative_failsafe_seconds, 900);
    }

    /// Missing `FeatureMap` attribute → `DriverError::Im` (`MissingField`).
    #[test]
    fn extract_read_payload_missing_feature_map_returns_error() {
        use crate::Expectation;

        let report = crate::im::ReportData::new(Vec::new(), None, false, false);
        let err = extract_read_payload(Expectation::NetworkCommissioningInfo, &report)
            .expect_err("missing attribute should fail");
        assert!(
            matches!(err, DriverError::Im(_)),
            "expected DriverError::Im, got {err:?}",
        );
    }

    /// Non-read `Expectation` → `DriverError::Im` (`UnexpectedValue`).
    #[test]
    fn extract_read_payload_non_read_expectation_returns_error() {
        use crate::Expectation;

        let report = crate::im::ReportData::new(Vec::new(), None, false, false);
        let err = extract_read_payload(Expectation::ArmFailsafeResponse, &report)
            .expect_err("non-read expectation should fail");
        assert!(
            matches!(err, DriverError::Im(_)),
            "expected DriverError::Im, got {err:?}",
        );
    }

    // -----------------------------------------------------------------------
    // dispatch_read integration tests (Step 2)
    // -----------------------------------------------------------------------

    /// `dispatch_read` sends a `ReadRequest`, the device replies with a canned
    /// `ReportData`, and the function returns the parsed report. Then
    /// `extract_read_payload` produces the right bytes per `Expectation`.
    #[tokio::test]
    async fn dispatch_read_and_extract_network_commissioning_info() {
        use crate::im::AttributePath;
        use crate::Expectation;
        use matter_codec::Value;

        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        let feat_val: u64 = 0x01; // WIFI bit set

        // Build the canned ReportData the device will send back.
        let entries = vec![(
            AttributePath {
                endpoint: 0,
                cluster: crate::clusters::network_commissioning::CLUSTER_ID,
                attribute: crate::clusters::network_commissioning::attribute_id::FEATURE_MAP,
            },
            Value::Uint(feat_val),
        )];
        let canned_report = build_canned_report_data(&entries);

        let paths = vec![AttributePath {
            endpoint: 0,
            cluster: crate::clusters::network_commissioning::CLUSTER_ID,
            attribute: crate::clusters::network_commissioning::attribute_id::FEATURE_MAP,
        }];

        // Controller side: send ReadRequest and collect the ReportData.
        let controller = dispatch_read(&ctrl_io, &mut ctrl, session, dev_addr, &paths);

        // Device side: receive the ReadRequest and reply with the canned ReportData.
        let device = async {
            loop {
                let (pkt, _) = dev_io.recv_from().await.unwrap();
                if let DecodeInboundOutput::AppMessage { exchange_id, .. } =
                    dev.decode_inbound(&pkt, Instant::now()).unwrap()
                {
                    // Reply on the SAME exchange_id (opcode 0x05 = ReportData).
                    let out = dev
                        .encode_outbound(
                            session,
                            Some(exchange_id),
                            0x05,
                            ProtocolId::INTERACTION_MODEL,
                            &canned_report,
                            MrpFlags { reliable: true },
                            Instant::now(),
                        )
                        .unwrap();
                    dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
                    break;
                }
            }
        };

        let (report_result, ()) = tokio::join!(controller, device);
        let report = report_result.unwrap();

        // Verify the report parsed correctly.
        let attrs: Vec<_> = report.attributes().collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(
            attrs[0].0.cluster,
            crate::clusters::network_commissioning::CLUSTER_ID
        );
        assert_eq!(*attrs[0].1, Value::Uint(feat_val));

        // Verify extract_read_payload produces bytes that decode_feature_map accepts.
        let payload = extract_read_payload(Expectation::NetworkCommissioningInfo, &report).unwrap();
        let features = crate::clusters::network_commissioning::decode_feature_map(&payload)
            .expect("decode_feature_map should accept the extracted payload");
        assert!(features
            .contains(crate::clusters::network_commissioning::NetworkCommissioningFeature::WIFI),);
    }

    // -----------------------------------------------------------------------
    // Task 5 failing tests — rollback + establish_case_session
    // -----------------------------------------------------------------------

    /// `rollback` sends `ArmFailSafe(expiry_length=0, breadcrumb=0)` over the
    /// PASE session and swallows any error. The device side asserts it received
    /// cluster 0x0030 / command 0x00 and that the decoded `expiry_length_seconds`
    /// field is 0.
    /// The disarm decision (Finding #3): a `?`-propagated mid-flight failure
    /// must trigger a best-effort failsafe disarm, an abort that asks to disarm
    /// must disarm, and an abort that says the failsafe was never armed must
    /// NOT disarm. Combined with `rollback_sends_arm_fail_safe_zero_over_pase`
    /// (which proves the disarm wire form is `ArmFailSafe` with expiry 0), this
    /// covers the failure-path disarm without driving a full RNG-backed PASE.
    #[test]
    fn disarm_on_exit_decision() {
        assert!(
            disarm_on_exit(&LoopExit::Failed(DriverError::Handshake(
                "mid-flight failure"
            ))),
            "a propagated failure must disarm the failsafe best-effort"
        );
        assert!(
            disarm_on_exit(&LoopExit::Aborted {
                disarm: true,
                reason: "device rejected".to_string(),
            }),
            "an abort that requests disarm must disarm"
        );
        assert!(
            !disarm_on_exit(&LoopExit::Aborted {
                disarm: false,
                reason: "failsafe never armed".to_string(),
            }),
            "an abort that says not to disarm must be honored"
        );
    }

    /// `into_driver_error` maps each `LoopExit` to the right public error.
    #[test]
    fn loop_exit_maps_to_driver_error() {
        let aborted = LoopExit::Aborted {
            disarm: true,
            reason: "boom".to_string(),
        };
        match aborted.into_driver_error() {
            DriverError::Aborted(r) => assert_eq!(r, "boom"),
            other => panic!("expected Aborted, got {other:?}"),
        }
        match LoopExit::Failed(DriverError::Handshake("h")).into_driver_error() {
            DriverError::Handshake("h") => {}
            other => panic!("expected Handshake, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // with_response_deadline — the BLE-path hang guard (D3/D11.1)
    // -----------------------------------------------------------------------

    /// Under `Mrp` the wrapper is transparent: a ready future's value passes
    /// straight through with no deadline (MRP's own timers bound the wait). A
    /// *pending* future under `Mrp` would hang forever, which is exactly the
    /// unchanged `commission()` behavior — so we only assert the pass-through.
    #[tokio::test]
    async fn with_response_deadline_mrp_is_transparent() {
        let out = with_response_deadline(
            TransportReliability::Mrp,
            false,
            std::future::ready(Ok::<u8, DriverError>(7)),
        )
        .await
        .unwrap();
        assert_eq!(out, 7);
    }

    /// Under `TransportProvides` a ready future still passes through (no timeout
    /// fires when the reply is already available).
    #[tokio::test]
    async fn with_response_deadline_transport_provides_passes_ready_value() {
        let out = with_response_deadline(
            TransportReliability::TransportProvides,
            false,
            std::future::ready(Ok::<u8, DriverError>(9)),
        )
        .await
        .unwrap();
        assert_eq!(out, 9);
    }

    /// Under `TransportProvides`, a non-`ConnectNetwork` dispatch that never
    /// replies fails with `DriverError::Timeout` at exactly the 30 s deadline
    /// (measured on the paused virtual clock — no real sleep).
    #[tokio::test(start_paused = true)]
    async fn with_response_deadline_transport_provides_times_out_at_30s() {
        let start = tokio::time::Instant::now();
        let err = with_response_deadline(
            TransportReliability::TransportProvides,
            false,
            std::future::pending::<Result<(), DriverError>>(),
        )
        .await
        .expect_err("a never-replying dispatch must hit the response deadline");
        assert!(matches!(err, DriverError::Timeout { .. }), "got {err:?}");
        assert_eq!(
            start.elapsed(),
            RESPONSE_DEADLINE,
            "non-ConnectNetwork deadline must be 30 s"
        );
    }

    /// A `ConnectNetwork` dispatch gets the longer 60 s deadline (slow Wi-Fi
    /// assoc + DHCP inline).
    #[tokio::test(start_paused = true)]
    async fn with_response_deadline_connect_network_times_out_at_60s() {
        let start = tokio::time::Instant::now();
        let err = with_response_deadline(
            TransportReliability::TransportProvides,
            true,
            std::future::pending::<Result<(), DriverError>>(),
        )
        .await
        .expect_err("a never-replying ConnectNetwork must hit the longer deadline");
        assert!(matches!(err, DriverError::Timeout { .. }), "got {err:?}");
        assert_eq!(
            start.elapsed(),
            CONNECT_NETWORK_RESPONSE_DEADLINE,
            "ConnectNetwork deadline must be 60 s"
        );
    }

    #[tokio::test]
    async fn rollback_sends_arm_fail_safe_zero_over_pase() {
        use crate::im::CommandPath;
        use matter_transport::{DecodeInboundOutput, MrpFlags, ProtocolId};

        let (mut ctrl, mut dev) = paired_pase_sessions();
        let pase_session = SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        // Drive rollback (controller side) and a minimal device receiver concurrently.
        let controller = rollback(&ctrl_io, &mut ctrl, pase_session, dev_addr);

        let device = async {
            // Receive the InvokeRequest that rollback sends.
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let msg = dev.decode_inbound(&pkt, Instant::now()).unwrap();
            let (exchange_id, payload) = match msg {
                DecodeInboundOutput::AppMessage {
                    exchange_id,
                    payload,
                    ..
                } => (exchange_id, payload),
                other => panic!("expected AppMessage, got {other:?}"),
            };

            // Decode the InvokeRequest and assert path + expiry=0.
            let invoke = parse_invoke_request(&payload).unwrap();
            assert_eq!(
                invoke.path,
                CommandPath {
                    endpoint: 0,
                    cluster: crate::clusters::general_commissioning::CLUSTER_ID,
                    command: crate::clusters::general_commissioning::command_id::ARM_FAIL_SAFE,
                }
            );
            // The fields TLV is an anonymous struct: { ctx(0): 0u16, ctx(1): 0u64 }.
            let arm = decode_arm_fail_safe_fields(&invoke.fields_tlv);
            assert_eq!(arm.expiry_length_seconds, 0, "expiry must be 0 for disarm");
            assert_eq!(arm.breadcrumb, 0);

            // Send a canned OK response so rollback's dispatch_invoke can complete.
            let ok_fields = encode_arm_fail_safe_response(0);
            let resp = build_canned_invoke_response(invoke.path, &ok_fields);
            let out = dev
                .encode_outbound(
                    pase_session,
                    Some(exchange_id),
                    0x09,
                    ProtocolId::INTERACTION_MODEL,
                    &resp,
                    MrpFlags { reliable: true },
                    Instant::now(),
                )
                .unwrap();
            dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
        };

        tokio::join!(controller, device);
    }

    /// `establish_case_session` drives `resolve_operational` + `run_case` and
    /// returns a [`SessionId`]. Mirrors the `run_case_establishes_matching_session`
    /// test in `case.rs` but calls through the higher-level helper.
    #[tokio::test]
    async fn establish_case_session_returns_session_id() {
        use std::collections::HashMap;

        use matter_cert::test_support::{build_unsigned, with_signature, TestCertFields};
        use matter_cert::{
            BasicConstraints, DistinguishedName, DnAttribute, Extensions, KeyIdentifier, KeyUsage,
            MatterCertificate, MatterTime, PublicKey, Signature, TrustAnchor, TrustedRoots,
        };
        use matter_crypto::{
            CaseCredentials, CaseResponder, CaseSigner, RingSigner, Sigma1Outcome,
        };
        use matter_transport::{
            MatterService, QueryHandle, ServiceKind, SessionKeys, SessionManager,
        };

        use crate::driver::case::operational_instance_name;
        use crate::driver::datagram::InMemoryDatagram;
        use crate::driver::unsecured::{decode_unsecured, encode_unsecured};

        // --- credential constants (mirror case.rs T_* constants) ---
        const T_FABRIC_ID: u64 = 0x4242_4242_4242_4242;
        const T_INITIATOR_NODE: u64 = 0xDEAD_BEEF_CAFE_F00D;
        const T_RESPONDER_NODE: u64 = 0xBABE_FEED_1234_5678;
        const T_IPK: [u8; 16] = [0x77; 16];
        const T_RCAC_SKI: [u8; 20] = [0x01; 20];
        const T_NOC_SKI: [u8; 20] = [0x02; 20];

        fn build_test_rcac() -> (MatterCertificate, RingSigner, [u8; 65]) {
            let (rcac_signer, _) = RingSigner::generate().unwrap();
            let rcac_pub = *rcac_signer.public_key().as_bytes();
            let rcac_dn = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);
            let ext = Extensions::builder()
                .basic_constraints(Some(BasicConstraints::new(true, Some(1))))
                .key_usage(Some(KeyUsage::KEY_CERT_SIGN))
                .subject_key_identifier(Some(KeyIdentifier(T_RCAC_SKI)))
                .authority_key_identifier(Some(KeyIdentifier(T_RCAC_SKI)))
                .build();
            let fields = TestCertFields {
                serial: vec![0x01],
                issuer: rcac_dn.clone(),
                not_before: MatterTime::from_unix_secs(1_700_000_000),
                not_after: MatterTime::from_unix_secs(2_500_000_000),
                subject: rcac_dn,
                public_key: PublicKey::new(rcac_pub).unwrap(),
                extensions: ext,
                signature: Signature::new([0u8; 64]),
            };
            let unsigned = build_unsigned(fields);
            let tbs = unsigned.to_x509_tbs_der().unwrap();
            let sig = rcac_signer.sign_p256_sha256(&tbs).unwrap();
            (
                with_signature(&unsigned, Signature::new(sig)),
                rcac_signer,
                rcac_pub,
            )
        }

        fn build_test_noc(
            rcac_signer: &RingSigner,
            node_id: u64,
        ) -> (MatterCertificate, RingSigner) {
            let (noc_signer, _) = RingSigner::generate().unwrap();
            let noc_pub = *noc_signer.public_key().as_bytes();
            let subj = DistinguishedName::new(vec![
                DnAttribute::FabricId(T_FABRIC_ID),
                DnAttribute::NodeId(node_id),
            ]);
            let issuer = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);
            let ext = Extensions::builder()
                .basic_constraints(Some(BasicConstraints::new(false, None)))
                .key_usage(Some(KeyUsage::DIGITAL_SIGNATURE))
                .subject_key_identifier(Some(KeyIdentifier(T_NOC_SKI)))
                .authority_key_identifier(Some(KeyIdentifier(T_RCAC_SKI)))
                .build();
            let fields = TestCertFields {
                serial: vec![0x02],
                issuer,
                not_before: MatterTime::from_unix_secs(1_700_000_000),
                not_after: MatterTime::from_unix_secs(2_500_000_000),
                subject: subj,
                public_key: PublicKey::new(noc_pub).unwrap(),
                extensions: ext,
                signature: Signature::new([0u8; 64]),
            };
            let unsigned = build_unsigned(fields);
            let tbs = unsigned.to_x509_tbs_der().unwrap();
            let sig = rcac_signer.sign_p256_sha256(&tbs).unwrap();
            (with_signature(&unsigned, Signature::new(sig)), noc_signer)
        }

        fn make_creds(
            noc: MatterCertificate,
            signer: RingSigner,
            node_id: u64,
            rcac_pub: [u8; 65],
        ) -> CaseCredentials {
            CaseCredentials {
                noc,
                icac: None,
                signer: Box::new(signer),
                fabric_id: T_FABRIC_ID,
                node_id,
                ipk: T_IPK,
                rcac_public_key: rcac_pub,
            }
        }

        // Build credentials.
        let (rcac, rcac_signer, rcac_pub) = build_test_rcac();
        let (init_noc, init_signer) = build_test_noc(&rcac_signer, T_INITIATOR_NODE);
        let (resp_noc, resp_signer) = build_test_noc(&rcac_signer, T_RESPONDER_NODE);
        let init_creds = make_creds(init_noc, init_signer, T_INITIATOR_NODE, rcac_pub);
        let resp_creds = make_creds(resp_noc, resp_signer, T_RESPONDER_NODE, rcac_pub);
        let ctrl_roots = {
            let mut r = TrustedRoots::new();
            r.add(TrustAnchor::from_root_cert(&rcac));
            r
        };
        let resp_roots = {
            let mut r = TrustedRoots::new();
            r.add(TrustAnchor::from_root_cert(&rcac));
            r
        };

        // Transport pair.
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();
        let mut sessions = SessionManager::new();

        // FakeDiscovery: always returns dev_addr for the operational query.
        let compressed =
            matter_crypto::derive_compressed_fabric_id(&rcac_pub, T_FABRIC_ID).unwrap();
        let instance = operational_instance_name(compressed, T_RESPONDER_NODE);

        struct FakeOpDiscovery {
            service: MatterService,
        }
        impl matter_transport::Discovery for FakeOpDiscovery {
            fn publish(&mut self, _s: &MatterService) -> matter_transport::Result<()> {
                Ok(())
            }
            fn unpublish(&mut self, _n: &str, _k: ServiceKind) -> matter_transport::Result<()> {
                Ok(())
            }
            fn query(&mut self, _k: ServiceKind) -> matter_transport::Result<QueryHandle> {
                Ok(QueryHandle(1))
            }
            fn stop_query(&mut self, _h: QueryHandle) {}
            fn poll_results(&mut self, _h: QueryHandle) -> Vec<MatterService> {
                vec![self.service.clone()]
            }
        }

        let mut discovery = FakeOpDiscovery {
            service: MatterService::new(
                instance,
                ServiceKind::Operational,
                vec![dev_addr.ip()],
                dev_addr.port(),
                HashMap::new(),
            ),
        };

        // Device side: CaseResponder.
        const OP_SIGMA2: u8 = 0x31;
        let device = async {
            let mut responder = CaseResponder::new(
                resp_creds,
                resp_roots,
                0x00D2,
                MatterTime::from_unix_secs(2_000_000_000),
            )
            .unwrap();
            let (p, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&p).unwrap();
            assert!(matches!(
                responder.handle_sigma1(&m.payload).unwrap(),
                Sigma1Outcome::NewSession
            ));
            let sigma2 = responder.next_message().unwrap();
            let wire = encode_unsecured(
                200,
                m.exchange_id,
                OP_SIGMA2,
                matter_transport::ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(m.message_counter),
                None,
                &sigma2,
            );
            dev_io.send_to(&wire, ctrl_addr).await.unwrap();
            let (p, _) = dev_io.recv_from().await.unwrap();
            let m = decode_unsecured(&p).unwrap();
            responder.handle_sigma3(&m.payload).unwrap();

            // Close with a success StatusReport and expect the standalone ack
            // (real-device behaviour).
            let mut body = Vec::new();
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            let report = encode_unsecured(
                201,
                m.exchange_id,
                0x40,
                matter_transport::ProtocolId::SECURE_CHANNEL,
                false,
                true,
                Some(m.message_counter),
                None,
                &body,
            );
            dev_io.send_to(&report, ctrl_addr).await.unwrap();
            let ack = tokio::time::timeout(std::time::Duration::from_secs(2), dev_io.recv_from())
                .await
                .expect("controller must ack the StatusReport")
                .unwrap();
            let ack = decode_unsecured(&ack.0).unwrap();
            assert_eq!(ack.opcode, 0x10);

            responder.finish().unwrap()
        };

        // Controller side: establish_case_session. Now returns (SessionId,
        // resolved operational SocketAddr) and takes an explicit resolve budget.
        let controller = establish_case_session(
            &ctrl_io,
            &mut sessions,
            &mut discovery,
            &rcac_pub,
            T_FABRIC_ID,
            init_creds,
            ctrl_roots,
            T_RESPONDER_NODE,
            MatterTime::from_unix_secs(2_000_000_000),
            crate::driver::case::RESOLVE_POLL_ATTEMPTS,
        );

        let (ctrl_result, dev_out) = tokio::join!(controller, device);
        let (sid, resolved_addr) = ctrl_result.unwrap();
        assert_eq!(
            resolved_addr, dev_addr,
            "establish_case_session must return the mDNS-resolved operational address"
        );
        let registered = sessions.get(sid).unwrap();
        assert_eq!(registered.keys, SessionKeys::from_case_output(&dev_out));
    }

    /// After a secured round-trip, the piggyback ack for the received
    /// response is left buffered (see `secured_round_trip`). `flush_pending_acks`
    /// must emit it so the device stops retransmitting before the unsecured
    /// CASE exchange starts (observed straggler: Tapo P110M, M6.6.5).
    #[tokio::test]
    async fn flush_pending_acks_delivers_buffered_standalone_ack() {
        use std::time::Instant;

        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        let controller = async {
            let resp = secured_round_trip(
                &ctrl_io,
                &mut ctrl,
                session,
                dev_addr,
                0x08,
                ProtocolId::INTERACTION_MODEL,
                b"req",
            )
            .await
            .unwrap();
            assert_eq!(resp.payload, b"resp");
            // The ack for the device's reliable response is now pending.
            flush_pending_acks(&ctrl_io, &mut ctrl, dev_addr)
                .await
                .unwrap();
        };

        let device = async {
            let (pkt, _) = dev_io.recv_from().await.unwrap();
            let DecodeInboundOutput::AppMessage { exchange_id, .. } =
                dev.decode_inbound(&pkt, Instant::now()).unwrap()
            else {
                panic!("expected request");
            };
            let out = dev
                .encode_outbound(
                    session,
                    Some(exchange_id),
                    0x09,
                    ProtocolId::INTERACTION_MODEL,
                    b"resp",
                    MrpFlags { reliable: true },
                    Instant::now(),
                )
                .unwrap();
            dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
            // The flushed standalone ack must arrive and decode as AckOnly.
            let (ack_pkt, _) =
                tokio::time::timeout(std::time::Duration::from_secs(2), dev_io.recv_from())
                    .await
                    .expect("flush must deliver the standalone ack")
                    .unwrap();
            assert!(
                matches!(
                    dev.decode_inbound(&ack_pkt, Instant::now()).unwrap(),
                    DecodeInboundOutput::AckOnly { .. }
                ),
                "flushed packet must be a standalone ack"
            );
        };

        let ((), ()) = tokio::join!(controller, device);
    }

    /// `dispatch_read` for `CommissioningInfo`: canned `ReportData` carries a
    /// `BasicCommissioningInfo` struct; `extract_read_payload` produces bytes
    /// that `decode_basic_commissioning_info` decodes correctly.
    #[tokio::test]
    async fn dispatch_read_and_extract_commissioning_info() {
        use crate::im::AttributePath;
        use crate::Expectation;
        use matter_codec::{Tag, Value};

        let (mut ctrl, mut dev) = paired_pase_sessions();
        let session = SessionId(1);
        let (ctrl_io, dev_io) = InMemoryDatagram::pair();
        let dev_addr = dev_io.local_addr();
        let ctrl_addr = ctrl_io.local_addr();

        // BasicCommissioningInfo: failsafe=120s, max_cumulative=900s
        let struct_value = Value::Structure(vec![
            (Tag::Context(0), Value::Uint(120)),
            (Tag::Context(1), Value::Uint(900)),
        ]);

        let entries = vec![(
            AttributePath {
                endpoint: 0,
                cluster: crate::clusters::general_commissioning::CLUSTER_ID,
                attribute: attr_id::BASIC_COMMISSIONING_INFO,
            },
            struct_value,
        )];
        let canned_report = build_canned_report_data(&entries);

        let paths = vec![AttributePath {
            endpoint: 0,
            cluster: crate::clusters::general_commissioning::CLUSTER_ID,
            attribute: attr_id::BASIC_COMMISSIONING_INFO,
        }];

        let controller = dispatch_read(&ctrl_io, &mut ctrl, session, dev_addr, &paths);

        let device = async {
            loop {
                let (pkt, _) = dev_io.recv_from().await.unwrap();
                if let DecodeInboundOutput::AppMessage { exchange_id, .. } =
                    dev.decode_inbound(&pkt, Instant::now()).unwrap()
                {
                    let out = dev
                        .encode_outbound(
                            session,
                            Some(exchange_id),
                            0x05,
                            ProtocolId::INTERACTION_MODEL,
                            &canned_report,
                            MrpFlags { reliable: true },
                            Instant::now(),
                        )
                        .unwrap();
                    dev_io.send_to(&out.wire_bytes, ctrl_addr).await.unwrap();
                    break;
                }
            }
        };

        let (report_result, ()) = tokio::join!(controller, device);
        let report = report_result.unwrap();

        assert_eq!(report.attributes().count(), 1);

        let payload = extract_read_payload(Expectation::CommissioningInfo, &report).unwrap();
        let info =
            crate::clusters::general_commissioning::decode_basic_commissioning_info(&payload)
                .expect("decode_basic_commissioning_info should accept the extracted payload");
        assert_eq!(info.failsafe_expiry_length_seconds, 120);
        assert_eq!(info.max_cumulative_failsafe_seconds, 900);
    }
}
