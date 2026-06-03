//! M6.6.4 headline gate: the REAL `commission()` Commissioner commissions a
//! self-contained `MockDevice` end to end, hardware-free.
//!
//! This is the milestone green check. The controller half is the production
//! [`matter_commissioning::driver::commission`] driver; the device half is the
//! `support::run_mock_device` twin (Tasks 7b–11). Both run under one
//! `tokio::join!` over a single [`InMemoryDatagram`] pair. No part of
//! `commission()` is mocked or stubbed — only the network transport and mDNS
//! discovery are in-process.
//!
//! ## Mutually-consistent assembly (where loopbacks live or die)
//!
//! - **VID/PID:** mock DAC + CD fixture + SetupPayload all use 0xFFF1 / 0x8001
//!   (`support::VID` / `support::PID`). The controller's `paa_trust_store` is the
//!   mock PKI's store; `cd_signing_roots` is `CdSigningRoots::with_csa_test_roots()`.
//! - **Passcode / PASE:** the SetupPayload passcode, `DriverConfig.passcode`, and
//!   the mock's `pase_pin` are the SAME value. The PBKDF params (`PasePbkdfParams`)
//!   are supplied by the device verifier and negotiated to the controller's
//!   prover via PBKDFParamResponse (see `pase.rs::run_pase`), so any valid params
//!   are fine as long as both halves use the same ones.
//! - **Attestation challenge:** sourced from the LIVE PASE session on both sides
//!   (Step 0 fix to `commission()` + `run_mock_device`'s `pase_keys.attestation_key`).
//!   The controller's `pase_attestation_challenge` config field is overwritten by
//!   `commission()`, so we set it to `[0u8; 16]` here to prove that.
//! - **Fabric / CASE / NOC:** ONE fabric RCAC (`FabricRecord::new_root_only`).
//!   The controller commissions under it (and mints its own operational NOC under
//!   the RCAC inside `commission()`). The DEVICE's CASE NOC is minted HERE under
//!   the SAME RCAC for `ASSIGNED_NODE_ID`, with `trusted_roots` = that RCAC. CASE
//!   then validates both NOCs against the shared root.
//! - **Node ids:** `COMMISSIONER_NODE_ID` (controller) != `ASSIGNED_NODE_ID`
//!   (device); the device CASE NOC's node id == `ASSIGNED_NODE_ID` == the
//!   `EstablishCase{peer_node_id}` the Commissioner emits.
//! - **Discovery:** the `commissionable_addr` is supplied directly (no mDNS for
//!   discovery). `commission()` still browses `_matter._tcp` operational records
//!   during `EstablishCase`; `FakeDiscovery` returns `dev_addr` for the matching
//!   operational instance name (compressed-fabric-id + assigned node id).

// Test-code carve-out: see CLAUDE.md.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Domain acronyms (VID, PID, PASE, CASE, NOC, RCAC, PBKDF, mDNS) are prose, not
// code items; and `commission`/`commissioner`/`commissioned` are intentionally
// related names that mirror the API surface under test.
#![allow(clippy::doc_markdown, clippy::similar_names)]

mod support;

use std::sync::Arc;

use matter_cert::{MatterTime, TrustAnchor, TrustedRoots};
use matter_commissioning::attestation::CdSigningRoots;
use matter_commissioning::driver::{
    commission, operational_instance_name, DriverConfig, InMemoryDatagram,
};
use matter_commissioning::noc::{issue_noc, FabricRecord, NocRng, SystemNocRng, VerifiedCsr};
use matter_commissioning::setup::{
    CommissioningFlow, DiscoveryCapabilities, Discriminator, Passcode, SetupPayload,
};
use matter_commissioning::state_machine::{CommissionerConfig, Stage};
use matter_crypto::{derive_compressed_fabric_id, CaseCredentials, RingSigner, Signer};
use matter_transport::{Discovery, MatterService, QueryHandle, ServiceKind};

use support::{build_mock_device_pki, run_mock_device, MockDeviceCaseSetup, PID, VID};

// ── Fixed run parameters ──────────────────────────────────────────────────────

/// Device passcode. The SetupPayload, the driver config, and the mock verifier
/// PIN are all this value (Matter Core Spec §5.1.7 — a SPAKE2+ passcode).
const PASSCODE: u32 = 20_202_021;

/// 12-bit commissionable discriminator. Only used to build the SetupPayload; the
/// commissionable address is supplied directly so mDNS discovery is bypassed.
const DISCRIMINATOR: u16 = 0x0F00;

/// Fabric id the controller commissions under. Both the controller's and the
/// device's operational NOCs carry this fabric id.
const FABRIC_ID: u64 = 0x0000_0000_0000_0001;

/// The controller's own operational node id on this fabric.
const COMMISSIONER_NODE_ID: u64 = 0x0000_0000_0000_0001;

/// The node id assigned to the device. The device CASE NOC's node id MUST equal
/// this, and it is the `peer_node_id` the Commissioner emits in `EstablishCase`.
const ASSIGNED_NODE_ID: u64 = 0x0000_0000_0000_0002;

/// Responder PASE session id the DEVICE advertises in PBKDFParamResponse. The
/// controller learns it via the handshake and addresses its secured PASE replies
/// to it. Mirrors the `0x00BB` the `pase.rs` loopback uses.
const PASE_RESPONDER_SESSION_ID: u16 = 0x00BB;

/// Responder CASE session id the DEVICE advertises in Sigma2. Mirrors the
/// `0x00D2` the `case.rs` `run_case` loopback uses.
const CASE_RESPONDER_SESSION_ID: u16 = 0x00D2;

/// Wall-clock anchor for the run (Unix 1_800_000_000 ≈ 2027-01-15). Matches the
/// `now()` used by the mock PKI builder so the DAC/PAI/PAA validity windows
/// bracket it.
fn now() -> MatterTime {
    MatterTime::from_unix_secs(1_800_000_000)
}

// ── FakeDiscovery (operational browse only) ────────────────────────────────────

/// Minimal [`Discovery`] that returns one canned operational record for every
/// query. `commission()` only browses discovery for the operational record
/// during `EstablishCase` (the commissionable address is supplied directly), and
/// `resolve_operational` filters by `instance_name`, so the canned record's
/// instance name is the operational instance name for our fabric + assigned node.
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

/// Mint the device's operational CASE NOC under the fabric RCAC and assemble the
/// `MockDeviceCaseSetup` the responder needs.
///
/// The device generates a fresh operational keypair; we issue its NOC under the
/// same `fabric` the controller commissions under (RCAC -> NOC, no ICAC), for
/// `ASSIGNED_NODE_ID`. The responder validates the controller's NOC against the
/// fabric RCAC and vice versa.
fn build_device_case_setup(fabric: &FabricRecord) -> MockDeviceCaseSetup {
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

    let credentials = CaseCredentials {
        noc: device_noc,
        icac: fabric.icac_cert.clone(),
        signer: Box::new(device_op_signer),
        fabric_id: fabric.fabric_id,
        node_id: ASSIGNED_NODE_ID,
        ipk: fabric.identity_protection_key,
        rcac_public_key: *fabric.root_public_key.as_bytes(),
    };

    let mut trusted_roots = TrustedRoots::new();
    trusted_roots.add(TrustAnchor::from_root_cert(&fabric.root_cert));

    MockDeviceCaseSetup {
        credentials,
        trusted_roots,
        responder_session_id: CASE_RESPONDER_SESSION_ID,
    }
}

#[tokio::test]
async fn commission_reaches_done_against_mock_device() {
    // ── 1. Mock-device PKI: PAA/PAI/DAC chain + the PAA trust store the
    //       controller validates the device attestation against. ──────────────
    let mock_pki = build_mock_device_pki(now());

    // ── 2. One fabric RCAC the controller commissions under. ──────────────────
    let (root_signer, _pkcs8) = RingSigner::generate().expect("fabric root key");
    let root_signer: Arc<dyn Signer> = Arc::new(root_signer);
    let fabric = FabricRecord::new_root_only(
        FABRIC_ID,
        root_signer,
        now(),
        MatterTime::NO_EXPIRY,
        1, // rcac_id
        &SystemNocRng,
    )
    .expect("fabric RCAC");

    // ── 3. Setup payload (VID/PID/passcode/discriminator) matching the mock. ──
    let setup = SetupPayload {
        version: 0,
        vendor_id: Some(VID),
        product_id: Some(PID),
        commissioning_flow: CommissioningFlow::Standard,
        discovery_capabilities: DiscoveryCapabilities::ON_NETWORK,
        discriminator: Discriminator::new(DISCRIMINATOR).unwrap(),
        passcode: Passcode::new(PASSCODE).unwrap(),
    };

    let cd_signing_roots = CdSigningRoots::with_csa_test_roots();
    let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);

    // ── 4. Transport pair + discovery returning the operational record. ───────
    let (ctrl_io, dev_io) = InMemoryDatagram::pair();
    let dev_addr = dev_io.local_addr();
    let ctrl_addr = ctrl_io.local_addr();

    // The operational instance name the controller's resolve_operational expects:
    // compressed-fabric-id(root_public_key, fabric_id) + assigned node id.
    let compressed = derive_compressed_fabric_id(fabric.root_public_key.as_bytes(), FABRIC_ID)
        .expect("compressed fabric id");
    let op_instance_name = operational_instance_name(compressed, ASSIGNED_NODE_ID);
    let mut fake_disc = FakeDiscovery {
        service: MatterService {
            instance_name: op_instance_name,
            kind: ServiceKind::Operational,
            addresses: vec![dev_addr.ip()],
            port: dev_addr.port(),
            txt_records: std::collections::HashMap::new(),
        },
    };

    // ── 5. CommissionerConfig + DriverConfig (the controller under test). ─────
    //
    // pase_attestation_challenge is intentionally [0u8; 16]: commission() (Step 0
    // fix) overrides it with the live PASE-derived attestation_key, so the value
    // here is irrelevant — proving the fix sources the challenge from the session.
    let commissioner = CommissionerConfig {
        pase_attestation_challenge: [0u8; 16],
        fabric: &fabric,
        setup_payload: &setup,
        paa_trust_store: &mock_pki.paa_trust_store,
        cd_signing_roots: &cd_signing_roots,
        commissioner_node_id: COMMISSIONER_NODE_ID,
        assigned_node_id: ASSIGNED_NODE_ID,
        ipk_epoch_key: [0x42_u8; 16],
        case_admin_subject: COMMISSIONER_NODE_ID,
        admin_vendor_id: VID,
        now: now(),
        rng,
        wifi_credentials: None, // Ethernet path
    };
    let config = DriverConfig {
        commissioner,
        commissionable_addr: Some(dev_addr),
        passcode: PASSCODE,
    };

    // ── 6. Device CASE setup (NOC under the SAME fabric RCAC). ────────────────
    let case_setup = build_device_case_setup(&fabric);

    // ── 7. Run BOTH halves concurrently: the real commission() driver against
    //       the mock device. ────────────────────────────────────────────────
    let device = run_mock_device(
        &dev_io,
        ctrl_addr, // replies go back to the controller's loopback endpoint
        &mock_pki,
        PASSCODE,
        matter_crypto::pase::PasePbkdfParams {
            iterations: 1000,
            salt: vec![0x55; 16],
        },
        PASE_RESPONDER_SESSION_ID,
        case_setup,
    );

    let (commission_result, device_result) =
        tokio::join!(commission(&ctrl_io, &mut fake_disc, config), device);

    // ── 8. Assert the green check. ────────────────────────────────────────────
    device_result.expect("mock device side completed without error");
    let commissioned = commission_result.expect("commission() reached Done");

    assert_eq!(
        commissioned.terminated_at,
        Stage::Cleanup,
        "commissioning must terminate at the Cleanup stage"
    );
    assert_eq!(
        commissioned.peer_node_id, ASSIGNED_NODE_ID,
        "commissioned peer node id must equal the assigned node id"
    );
    assert_eq!(
        commissioned.fabric.fabric_id, FABRIC_ID,
        "commissioned fabric id must match the fabric we commissioned under"
    );
}
