//! M9-C1 Task 9 gate: the REAL `commission_ble()` driver commissions a
//! self-contained dual-transport `MockDevice` end to end, hardware-free.
//!
//! Unlike [`commission_loopback`], the controller here runs PASE + every
//! pre-operational stage over one [`InMemoryDatagram`] pair (the "BTP" pair,
//! under `TransportReliability::TransportProvides`) and the operational CASE
//! handshake + post-CASE traffic over a SECOND pair (the "UDP" pair, under
//! MRP). The device half is `support::run_mock_device_dual`, which answers PASE
//! on the BTP pair and CASE on the UDP pair.
//!
//! This is a *plain-datagram* floor for the routing + reliability logic — the
//! BTP-framing floor (real `BtpSession` seg/reassembly) is Task 10. It asserts:
//! - commissioning completes with the right fabric;
//! - every unsecured frame the controller sends on the BTP pair has the R-bit
//!   **clear** and no standalone ack ever appears there (MRP off);
//! - the CASE Sigma frames appear only on the UDP pair with the R-bit **set**
//!   (MRP on), and PASE frames appear only on the BTP pair — proving the
//!   two-transport routing split.
//! - a device that stalls after PASE makes `commission_ble` fail with the
//!   response-deadline `Timeout` at 30 s under paused virtual time.

// Drives the `driver`-gated `commission_ble` orchestrator and the `support`
// module. Without the feature the file is empty (CI runs `--all-features`;
// plain `cargo test` then skips it cleanly).
#![cfg(feature = "driver")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::doc_markdown, clippy::similar_names)]

mod support;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use matter_cert::{MatterTime, TrustAnchor, TrustedRoots};
use matter_commissioning::attestation::CdSigningRoots;
use matter_commissioning::driver::{
    commission_ble, operational_instance_name, AsyncDatagram, BleDriverConfig, DriverError,
    InMemoryDatagram,
};
use matter_commissioning::noc::{issue_noc, FabricRecord, NocRng, SystemNocRng, VerifiedCsr};
use matter_commissioning::setup::{
    CommissioningFlow, DiscoveryCapabilities, Discriminator, Passcode, SetupPayload,
};
use matter_commissioning::state_machine::{
    CommissionerConfig, NetworkCredentials, Stage, WiFiCredentials,
};
use matter_crypto::{derive_compressed_fabric_id, CaseCredentials, RingSigner, Signer};
use matter_transport::{Discovery, ExchangeFlags, MatterService, QueryHandle, ServiceKind};

use support::{
    build_mock_device_pki, run_mock_device_dual, run_mock_device_dual_silent_after,
    MockDeviceCaseSetup, PID, VID,
};

// ── Fixed run parameters (mirror commission_loopback) ──────────────────────────

const PASSCODE: u32 = 20_202_021;
const DISCRIMINATOR: u16 = 0x0F00;
const FABRIC_ID: u64 = 0x0000_0000_0000_0001;
const COMMISSIONER_NODE_ID: u64 = 0x0000_0000_0000_0001;
const ASSIGNED_NODE_ID: u64 = 0x0000_0000_0000_0002;
const PASE_RESPONDER_SESSION_ID: u16 = 0x00BB;
const CASE_RESPONDER_SESSION_ID: u16 = 0x00D2;

fn now() -> MatterTime {
    MatterTime::from_unix_secs(1_800_000_000)
}

// ── Recording transport wrapper ────────────────────────────────────────────────

/// An [`AsyncDatagram`] that records every outbound frame (controller → device)
/// into a shared buffer, then forwards to the wrapped [`InMemoryDatagram`].
/// Inbound `recv_from` passes straight through. The `std::sync::Mutex` guard is
/// dropped before the forwarding await, so the returned futures stay `Send`.
struct RecordingDatagram {
    inner: InMemoryDatagram,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl RecordingDatagram {
    fn new(inner: InMemoryDatagram, sent: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
        Self { inner, sent }
    }
}

impl AsyncDatagram for RecordingDatagram {
    async fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<()> {
        self.sent.lock().unwrap().push(buf.to_vec());
        self.inner.send_to(buf, peer).await
    }
    async fn recv_from(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        self.inner.recv_from().await
    }
}

// ── FakeDiscovery (operational browse only) ────────────────────────────────────

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

// ── Device CASE setup (mint device NOC under the fabric RCAC) ───────────────────

fn build_device_case_setup(fabric: &FabricRecord, ipk_epoch_key: [u8; 16]) -> MockDeviceCaseSetup {
    let (device_op_signer, _pkcs8) = RingSigner::generate().expect("device op key");
    let device_op_pub = device_op_signer.public_key().clone();
    let verified_csr = VerifiedCsr {
        public_key: device_op_pub,
    };
    let device_noc = issue_noc(
        fabric,
        &verified_csr,
        ASSIGNED_NODE_ID,
        &[],
        (now(), MatterTime::NO_EXPIRY),
        &SystemNocRng,
    )
    .expect("device NOC issuance under fabric RCAC");

    let compressed_fabric_id = matter_crypto::derive_compressed_fabric_id(
        fabric.root_public_key.as_bytes(),
        fabric.fabric_id,
    )
    .expect("compressed fabric id");
    let operational_ipk =
        matter_crypto::derive_operational_ipk(&ipk_epoch_key, &compressed_fabric_id)
            .expect("operational IPK derivation");

    let credentials = CaseCredentials {
        noc: device_noc,
        icac: fabric.icac_cert.clone(),
        signer: Box::new(device_op_signer),
        fabric_id: fabric.fabric_id,
        node_id: ASSIGNED_NODE_ID,
        ipk: operational_ipk,
        rcac_public_key: *fabric.root_public_key.as_bytes(),
    };

    let mut trusted_roots = TrustedRoots::new();
    trusted_roots.add(TrustAnchor::from_root_cert(&fabric.root_cert));

    MockDeviceCaseSetup {
        credentials,
        trusted_roots,
        responder_session_id: CASE_RESPONDER_SESSION_ID,
        now: now(),
    }
}

// ── Shared config builder ──────────────────────────────────────────────────────

/// Everything the controller side needs, owned by the caller for the run's
/// duration. `fabric` and `commissioner_noc`/`pkcs8` outlive the borrows in the
/// `CommissionerConfig` / `BleDriverConfig`.
struct ControllerFixture {
    fabric: FabricRecord,
    setup: SetupPayload,
    mock_pki: support::MockDevicePki,
    cd_signing_roots: CdSigningRoots,
    rng: Arc<dyn NocRng>,
    commissioner_noc: matter_cert::MatterCertificate,
    commissioner_pkcs8: Vec<u8>,
    op_instance_name: String,
    ipk_epoch_key: [u8; 16],
}

fn build_controller_fixture() -> ControllerFixture {
    let mock_pki = build_mock_device_pki(now());

    let (root_signer, _pkcs8) = RingSigner::generate().expect("fabric root key");
    let root_signer: Arc<dyn Signer> = Arc::new(root_signer);
    let fabric = FabricRecord::new_root_only(
        FABRIC_ID,
        root_signer,
        now(),
        MatterTime::NO_EXPIRY,
        1,
        &SystemNocRng,
    )
    .expect("fabric RCAC");

    let setup = SetupPayload {
        version: 0,
        vendor_id: Some(VID),
        product_id: Some(PID),
        commissioning_flow: CommissioningFlow::Standard,
        discovery_capabilities: DiscoveryCapabilities::ON_NETWORK,
        discriminator: Discriminator::new(DISCRIMINATOR).unwrap(),
        passcode: Passcode::new(PASSCODE).unwrap(),
    };

    let (commissioner_signer, commissioner_pkcs8) =
        RingSigner::generate().expect("commissioner keypair");
    let commissioner_noc = issue_noc(
        &fabric,
        &VerifiedCsr {
            public_key: matter_crypto::CaseSigner::public_key(&commissioner_signer).clone(),
        },
        COMMISSIONER_NODE_ID,
        &[],
        (now(), MatterTime::NO_EXPIRY),
        &SystemNocRng,
    )
    .expect("commissioner NOC");

    let compressed =
        derive_compressed_fabric_id(fabric.root_public_key.as_bytes(), FABRIC_ID).unwrap();
    let op_instance_name = operational_instance_name(compressed, ASSIGNED_NODE_ID);

    ControllerFixture {
        fabric,
        setup,
        mock_pki,
        cd_signing_roots: CdSigningRoots::with_csa_test_roots(),
        rng: Arc::new(SystemNocRng),
        commissioner_noc,
        commissioner_pkcs8,
        op_instance_name,
        ipk_epoch_key: [0x42_u8; 16],
    }
}

impl ControllerFixture {
    /// Build the `CommissionerConfig` (borrowing this fixture) with Wi-Fi
    /// credentials set — a BLE-commissioned Wi-Fi device must be provisioned.
    fn commissioner_config(&self) -> CommissionerConfig<'_> {
        CommissionerConfig {
            pase_attestation_challenge: [0u8; 16],
            fabric: &self.fabric,
            setup_payload: &self.setup,
            paa_trust_store: &self.mock_pki.paa_trust_store,
            cd_signing_roots: &self.cd_signing_roots,
            commissioner_node_id: COMMISSIONER_NODE_ID,
            assigned_node_id: ASSIGNED_NODE_ID,
            ipk_epoch_key: self.ipk_epoch_key,
            case_admin_subject: COMMISSIONER_NODE_ID,
            admin_vendor_id: VID,
            now: now(),
            rng: self.rng.clone(),
            network: NetworkCredentials::WiFi(WiFiCredentials {
                ssid: b"test-ssid".to_vec(),
                credentials: b"test-passphrase".to_vec(),
            }),
        }
    }
}

// ── Frame inspection helpers ────────────────────────────────────────────────────

/// The 2-byte little-endian session id at header offset 1 (0 = unsecured).
fn frame_session_id(frame: &[u8]) -> u16 {
    u16::from_le_bytes([frame[1], frame[2]])
}

/// For an unsecured frame (session id 0), the `(opcode, reliable-bit-set)` read
/// from its cleartext protocol header.
fn unsecured_opcode_and_reliable(frame: &[u8]) -> (u8, bool) {
    let (_hdr, rest) = matter_transport::decode_header(frame).expect("message header");
    let (ph, _payload) = matter_transport::decode_protocol_header(rest).expect("protocol header");
    (
        ph.opcode,
        ph.exchange_flags.contains(ExchangeFlags::RELIABLE),
    )
}

// ── Headline gate: dual-transport commission ────────────────────────────────────

#[tokio::test]
#[allow(clippy::too_many_lines)] // Dual-transport setup + frame-routing assertions are inherently long.
async fn commission_ble_reaches_done_over_two_transports() {
    let fx = build_controller_fixture();

    // Two transport pairs: BTP (PASE + pre-op) and UDP (CASE + operational).
    let (ctrl_btp, dev_btp) = InMemoryDatagram::pair();
    let (ctrl_udp, dev_udp) = InMemoryDatagram::pair();
    let ctrl_btp_addr = ctrl_btp.local_addr();
    let ctrl_udp_addr = ctrl_udp.local_addr();
    let dev_udp_addr = dev_udp.local_addr();

    let btp_sent = Arc::new(Mutex::new(Vec::new()));
    let udp_sent = Arc::new(Mutex::new(Vec::new()));
    let btp = RecordingDatagram::new(ctrl_btp, btp_sent.clone());
    let udp = RecordingDatagram::new(ctrl_udp, udp_sent.clone());

    // Operational discovery returns the device's UDP endpoint (address ignored
    // by InMemoryDatagram, but the instance name must match).
    let mut fake_disc = FakeDiscovery {
        service: MatterService::new(
            fx.op_instance_name.clone(),
            ServiceKind::Operational,
            vec![dev_udp_addr.ip()],
            dev_udp_addr.port(),
            std::collections::HashMap::new(),
        ),
    };

    let config = BleDriverConfig {
        commissioner: fx.commissioner_config(),
        passcode: PASSCODE,
        commissioner_noc: &fx.commissioner_noc,
        commissioner_signer_pkcs8: &fx.commissioner_pkcs8,
    };

    let case_setup = build_device_case_setup(&fx.fabric, fx.ipk_epoch_key);

    // Device: PASE on the BTP pair, CASE on the UDP pair.
    let device = run_mock_device_dual(
        &dev_btp,
        &dev_udp,
        ctrl_btp_addr,
        ctrl_udp_addr,
        &fx.mock_pki,
        PASSCODE,
        matter_crypto::pase::PasePbkdfParams {
            iterations: 1000,
            salt: vec![0x55; 16],
        },
        PASE_RESPONDER_SESSION_ID,
        case_setup,
    );

    let (commission_result, device_result) =
        tokio::join!(commission_ble(&btp, &udp, &mut fake_disc, config), device);

    device_result.expect("mock dual device completed without error");
    let commissioned = commission_result.expect("commission_ble reached Done");
    assert_eq!(commissioned.terminated_at, Stage::Cleanup);
    assert_eq!(commissioned.peer_node_id, ASSIGNED_NODE_ID);
    assert_eq!(commissioned.fabric.fabric_id, FABRIC_ID);

    // ── Routing + reliability assertions ─────────────────────────────────────
    let btp_frames = btp_sent.lock().unwrap().clone();
    let udp_frames = udp_sent.lock().unwrap().clone();

    // BTP pair: unsecured frames are the PASE handshake requests. Every one has
    // the R-bit CLEAR, none is a standalone ack, and no CASE Sigma leaks here.
    let mut btp_unsecured_opcodes = Vec::new();
    let mut btp_has_secured = false;
    for f in &btp_frames {
        if frame_session_id(f) == 0 {
            let (opcode, reliable) = unsecured_opcode_and_reliable(f);
            assert!(
                !reliable,
                "BTP unsecured frame opcode {opcode:#04x} set the R-bit — MRP must be off over BTP"
            );
            assert_ne!(
                opcode, 0x10,
                "controller must send no standalone ack on the BTP (TransportProvides) pair"
            );
            assert!(
                !(0x30..=0x32).contains(&opcode),
                "CASE Sigma opcode {opcode:#04x} must not appear on the BTP pair"
            );
            btp_unsecured_opcodes.push(opcode);
        } else {
            btp_has_secured = true;
        }
    }
    // The PASE requests the controller sends: PBKDFParamRequest, Pake1, Pake3.
    for op in [0x20u8, 0x22, 0x24] {
        assert!(
            btp_unsecured_opcodes.contains(&op),
            "PASE opcode {op:#04x} missing from BTP frames {btp_unsecured_opcodes:02x?}"
        );
    }
    assert!(
        btp_has_secured,
        "the pre-operational secured IM stages must run on the BTP pair"
    );

    // UDP pair: CASE Sigma1/Sigma3 with the R-bit SET (MRP on), a standalone
    // ack for the closing StatusReport, no PASE opcode leaks, and the
    // operational secured IM (CommissioningComplete) present.
    let mut udp_unsecured_opcodes = Vec::new();
    let mut udp_has_secured = false;
    let mut sigma1_reliable = false;
    for f in &udp_frames {
        if frame_session_id(f) == 0 {
            let (opcode, reliable) = unsecured_opcode_and_reliable(f);
            assert!(
                !(0x20..=0x24).contains(&opcode),
                "PASE opcode {opcode:#04x} must not appear on the UDP pair"
            );
            if opcode == 0x30 {
                sigma1_reliable = reliable;
            }
            udp_unsecured_opcodes.push(opcode);
        } else {
            udp_has_secured = true;
        }
    }
    assert!(
        udp_unsecured_opcodes.contains(&0x30) && udp_unsecured_opcodes.contains(&0x32),
        "CASE Sigma1/Sigma3 must appear on the UDP pair, got {udp_unsecured_opcodes:02x?}"
    );
    assert!(
        sigma1_reliable,
        "CASE Sigma1 on the UDP pair must set the R-bit (MRP on)"
    );
    assert!(
        udp_unsecured_opcodes.contains(&0x10),
        "controller must send a standalone ack for the CASE StatusReport on the UDP pair"
    );
    assert!(
        udp_has_secured,
        "the operational secured IM (CommissioningComplete) must run on the UDP pair"
    );
}

// ── D11.3: rollback over a dead BTP session must never mask the original error ──
//
// The focused paused-time unit tests on `with_response_deadline` in
// `driver/commission.rs` cover the loop dispatch deadline in isolation. This
// full-flow test covers the *failure-exit rollback*: after the poll loop times
// out on a stalled `TransportProvides` (BLE) session, the best-effort
// `ArmFailSafe(0)` rollback is dispatched over that same still-dead BTP session.
// Before the fix it had no deadline, so `commission_ble` hung forever and never
// surfaced the original `Timeout`. The fix wraps that rollback in the same 30 s
// response deadline; a rollback timeout is swallowed so the ORIGINAL error wins.

/// The device answers PASE + the first pre-operational IM round-trip over BTP,
/// then goes silent. The controller's next PASE-session dispatch hits its 30 s
/// response deadline (`LoopExit::Failed(Timeout)`), then the failure-exit
/// rollback `ArmFailSafe(0)` over the same dead BTP session also gets no reply.
///
/// Asserts, under paused virtual time:
/// - `commission_ble` returns `Err(DriverError::Timeout { .. })` — the ORIGINAL
///   loop-deadline error, NOT a rollback error and NOT a hang;
/// - it returns within a bounded amount of virtual time (both the 30 s loop
///   deadline and the 30 s rollback deadline elapse ≈ 60 s of virtual time),
///   proving the rollback is now deadline-bounded rather than unbounded.
#[tokio::test(start_paused = true)]
async fn commission_ble_rollback_over_dead_btp_returns_original_timeout() {
    let fx = build_controller_fixture();

    // Two transport pairs, exactly as the headline gate — but the device never
    // reaches the CASE phase, so the UDP pair stays idle.
    let (ctrl_btp, dev_btp) = InMemoryDatagram::pair();
    let (ctrl_udp, dev_udp) = InMemoryDatagram::pair();
    let ctrl_btp_addr = ctrl_btp.local_addr();
    let ctrl_udp_addr = ctrl_udp.local_addr();
    let dev_udp_addr = dev_udp.local_addr();

    // No recording needed here; drive the raw endpoints.
    let btp = ctrl_btp;
    let udp = ctrl_udp;

    // Operational discovery is never consulted (the run fails before CASE), but
    // build a well-formed stub for signature parity with the happy path.
    let mut fake_disc = FakeDiscovery {
        service: MatterService::new(
            fx.op_instance_name.clone(),
            ServiceKind::Operational,
            vec![dev_udp_addr.ip()],
            dev_udp_addr.port(),
            std::collections::HashMap::new(),
        ),
    };

    let config = BleDriverConfig {
        commissioner: fx.commissioner_config(),
        passcode: PASSCODE,
        commissioner_noc: &fx.commissioner_noc,
        commissioner_signer_pkcs8: &fx.commissioner_pkcs8,
    };

    // Device answers PASE + 1 pre-op IM stage, then goes silent (holds both
    // endpoints open, never replies again).
    let device = run_mock_device_dual_silent_after(
        &dev_btp,
        &dev_udp,
        ctrl_btp_addr,
        ctrl_udp_addr,
        &fx.mock_pki,
        PASSCODE,
        matter_crypto::pase::PasePbkdfParams {
            iterations: 1000,
            salt: vec![0x55; 16],
        },
        PASE_RESPONDER_SESSION_ID,
        1,
    );

    let start = tokio::time::Instant::now();

    // `select!` (not `join!`): the silent device parks forever, so we take
    // `commission_ble`'s result the moment it returns and drop the device future
    // (releasing its borrowed endpoints).
    let result = tokio::select! {
        r = commission_ble(&btp, &udp, &mut fake_disc, config) => r,
        _ = device => unreachable!("silent device future never resolves"),
    };

    let elapsed = start.elapsed();

    // 1. The ORIGINAL loop-deadline Timeout is returned — not masked by the
    //    rollback (which also timed out), and not a hang.
    match result {
        Err(DriverError::Timeout { .. }) => {}
        other => panic!("expected the original DriverError::Timeout, got {other:?}"),
    }

    // 2. Bounded virtual time: both 30 s deadlines (loop + rollback) elapsed, so
    //    ~60 s of virtual time passed. The rollback being deadline-bounded is the
    //    whole point — an unbounded rollback would hang here forever. Assert the
    //    lower bound (both deadlines fired) and a generous upper bound (no extra
    //    stalls / not hung).
    assert!(
        elapsed >= std::time::Duration::from_secs(60),
        "expected both 30 s deadlines to elapse (~60 s virtual), got {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(120),
        "commission_ble took too long ({elapsed:?}) — rollback deadline not bounding the stall"
    );
}
