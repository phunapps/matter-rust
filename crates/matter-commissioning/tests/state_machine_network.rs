//! Unit tests for the M6.5.2 `NetworkCommissioning` sub-cursor.
//!
//! Covers the `Stage::ReadNetworkCommissioningInfo` dispatch arm and
//! the `Expectation::NetworkCommissioningInfo` response handler's
//! Wi-Fi / Ethernet / Thread / malformed branching logic.
//!
//! Requires the `test-helpers` cargo feature (see `Cargo.toml`
//! `[[test]]` section). The feature gates
//! `Commissioner::new_at_read_network_commissioning_info`, which jumps
//! the cursor past M6.4 attestation + NOC crypto that cannot be driven
//! with synthetic data. This is intentional test isolation: the real
//! crypto path is exercised in the in-source glass-box tests in
//! `src/state_machine/commissioner.rs::tests`.

// Test-code carve-out: see CLAUDE.md.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, OnceLock};

use matter_cert::time::MatterTime;
use matter_commissioning::attestation::CdSigningRoots;
use matter_commissioning::noc::{FabricRecord, NocRng, SystemNocRng};
use matter_commissioning::setup::{
    CommissioningFlow, DiscoveryCapabilities, Discriminator, Passcode, SetupPayload,
};
use matter_commissioning::{
    Commissioner, CommissionerConfig, CommissioningError, Expectation, NetworkKind, PaaTrustStore,
    Stage, WiFiCredentials,
};
use matter_crypto::{RingSigner, Signer};

// ---------------------------------------------------------------------------
// Static fixtures (OnceLock pattern from sample_valid_config in commissioner.rs)
// ---------------------------------------------------------------------------

fn static_fabric() -> &'static FabricRecord {
    static FABRIC: OnceLock<FabricRecord> = OnceLock::new();
    FABRIC.get_or_init(|| {
        let (signer, _pkcs8) = RingSigner::generate().expect("ring keypair");
        let signer: Arc<dyn Signer> = Arc::new(signer);
        FabricRecord::new_root_only(
            0x0000_0000_0000_0001,
            signer,
            MatterTime::from_unix_secs(1_704_067_200),
            MatterTime::from_unix_secs(1_735_689_600),
            42,
            &SystemNocRng,
        )
        .expect("valid root fabric")
    })
}

fn static_setup() -> &'static SetupPayload {
    static SETUP: OnceLock<SetupPayload> = OnceLock::new();
    SETUP.get_or_init(|| SetupPayload {
        version: 0,
        vendor_id: Some(0xFFF1),
        product_id: Some(0x8000),
        commissioning_flow: CommissioningFlow::Standard,
        discovery_capabilities: DiscoveryCapabilities::ON_NETWORK,
        discriminator: Discriminator::new(0x0F00).expect("valid discriminator"),
        passcode: Passcode::new(20_202_021).expect("valid passcode"),
    })
}

fn static_paa() -> &'static PaaTrustStore {
    static PAA: OnceLock<PaaTrustStore> = OnceLock::new();
    PAA.get_or_init(PaaTrustStore::with_csa_test_roots)
}

fn static_cd() -> &'static CdSigningRoots {
    static CD: OnceLock<CdSigningRoots> = OnceLock::new();
    CD.get_or_init(CdSigningRoots::with_csa_test_roots)
}

/// Returns a fully-populated `CommissionerConfig<'static>` with Wi-Fi
/// credentials set (ssid=`b"matter"`, credentials=`b"hunter22"`).
fn make_wifi_config() -> CommissionerConfig<'static> {
    let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
    CommissionerConfig {
        pase_attestation_challenge: [0u8; 16],
        fabric: static_fabric(),
        setup_payload: static_setup(),
        paa_trust_store: static_paa(),
        cd_signing_roots: static_cd(),
        commissioner_node_id: 0x1,
        assigned_node_id: 0x2,
        ipk_epoch_key: [0x42_u8; 16],
        case_admin_subject: 0x1,
        admin_vendor_id: 0xFFF1,
        now: MatterTime::from_unix_secs(1_704_067_200),
        rng,
        wifi_credentials: Some(WiFiCredentials {
            ssid: b"matter".to_vec(),
            credentials: b"hunter22".to_vec(),
        }),
    }
}

/// Returns a config without Wi-Fi credentials (for Ethernet-only tests).
fn make_ethernet_config() -> CommissionerConfig<'static> {
    let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
    CommissionerConfig {
        pase_attestation_challenge: [0u8; 16],
        fabric: static_fabric(),
        setup_payload: static_setup(),
        paa_trust_store: static_paa(),
        cd_signing_roots: static_cd(),
        commissioner_node_id: 0x1,
        assigned_node_id: 0x2,
        ipk_epoch_key: [0x42_u8; 16],
        case_admin_subject: 0x1,
        admin_vendor_id: 0xFFF1,
        now: MatterTime::from_unix_secs(1_704_067_200),
        rng,
        wifi_credentials: None,
    }
}

// ---------------------------------------------------------------------------
// FeatureMap TLV encoder
// ---------------------------------------------------------------------------

/// Encode a bare `u32` FeatureMap value as the minimal-width TLV scalar
/// that `decode_feature_map` expects.
///
/// Matter attribute read responses return a bare TLV scalar (not wrapped
/// in a struct). The two encoding widths used in tests:
/// - `bits ≤ 0xFF`: 1-byte unsigned (TLV type byte `0x04`) followed by the
///   value byte.
/// - `bits ≤ 0xFFFF`: 2-byte unsigned (type `0x05`) followed by LE bytes.
fn feature_map_tlv(bits: u32) -> Vec<u8> {
    if bits <= 0xFF {
        vec![0x04, bits as u8]
    } else {
        vec![
            0x05,
            (bits & 0xFF) as u8,
            ((bits >> 8) & 0xFF) as u8,
        ]
    }
}

// ---------------------------------------------------------------------------
// Cursor helper
// ---------------------------------------------------------------------------

/// Create a `Commissioner` positioned at `Stage::ReadNetworkCommissioningInfo`
/// using `Commissioner::new_at_read_network_commissioning_info` (gated by the
/// `test-helpers` cargo feature).
///
/// This skips M6.4 attestation + NOC crypto; the full crypto path is covered
/// by the in-source glass-box tests in `commissioner.rs::tests`.
fn drive_to_read_network_info(config: CommissionerConfig<'static>) -> Commissioner {
    Commissioner::new_at_read_network_commissioning_info(config)
        .expect("valid config must produce a Commissioner")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn wifi_only_feature_map_advances_to_wifi_setup() {
    let mut sm = drive_to_read_network_info(make_wifi_config());
    let action = sm.poll().expect("emit ReadAttribute");
    // Verify the emitted action has the right expectation.
    match action {
        matter_commissioning::Action::ReadAttribute { expect, .. } => {
            assert_eq!(expect, Expectation::NetworkCommissioningInfo);
        }
        other => panic!("expected ReadAttribute, got {other:?}"),
    }
    sm.on_response(Expectation::NetworkCommissioningInfo, &feature_map_tlv(0b001))
        .expect("WiFi-only FeatureMap accepted");
    assert_eq!(sm.stage(), Stage::WiFiNetworkSetup);
}

#[test]
fn ethernet_only_feature_map_skips_to_evict_case() {
    let mut sm = drive_to_read_network_info(make_ethernet_config());
    let _ = sm.poll().expect("emit ReadAttribute");
    sm.on_response(Expectation::NetworkCommissioningInfo, &feature_map_tlv(0b100))
        .expect("Ethernet-only FeatureMap accepted");
    assert_eq!(sm.stage(), Stage::EvictPreviousCaseSessions);
}

#[test]
fn thread_only_feature_map_fails_fast() {
    let mut sm = drive_to_read_network_info(make_wifi_config());
    let _ = sm.poll().expect("emit ReadAttribute");
    let Err(err) = sm.on_response(
        Expectation::NetworkCommissioningInfo,
        &feature_map_tlv(0b010),
    ) else {
        panic!("Thread-only FeatureMap should fail");
    };
    assert!(
        matches!(
            err,
            CommissioningError::NetworkFeatureUnsupported {
                needed: NetworkKind::Thread,
            },
        ),
        "got {err:?}",
    );
}

#[test]
fn wifi_credentials_none_with_wifi_device_fails_with_typed_error() {
    // Ethernet config (no wifi_credentials) fed a Wi-Fi FeatureMap.
    let mut sm = drive_to_read_network_info(make_ethernet_config());
    let _ = sm.poll().expect("emit ReadAttribute");
    let Err(err) = sm.on_response(
        Expectation::NetworkCommissioningInfo,
        &feature_map_tlv(0b001),
    ) else {
        panic!("WiFi FeatureMap with no creds should fail");
    };
    assert!(
        matches!(err, CommissioningError::WifiCredentialsRequired),
        "got {err:?}",
    );
}

#[test]
fn empty_feature_map_is_malformed() {
    let mut sm = drive_to_read_network_info(make_wifi_config());
    let _ = sm.poll().expect("emit ReadAttribute");
    let Err(err) = sm.on_response(
        Expectation::NetworkCommissioningInfo,
        &feature_map_tlv(0),
    ) else {
        panic!("Empty FeatureMap should fail");
    };
    assert!(
        matches!(
            err,
            CommissioningError::MalformedResponse(Stage::ReadNetworkCommissioningInfo),
        ),
        "got {err:?}",
    );
}
