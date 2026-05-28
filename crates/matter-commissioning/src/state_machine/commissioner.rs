//! `Commissioner` — the state-machine cursor.

#![forbid(unsafe_code)]

use std::sync::Arc;

use matter_cert::time::MatterTime;

use crate::attestation::PaaTrustStore;
use crate::noc::{FabricRecord, NocRng};
use crate::setup::SetupPayload;
use crate::state_machine::action::{Action, Expectation};
use crate::state_machine::error::CommissioningError;
use crate::state_machine::stage::Stage;

/// Configuration passed to [`Commissioner::new`].
///
/// All fields are by-reference where possible so the state machine
/// can share long-lived caller-owned resources (the fabric record, the
/// trust store, the setup payload) without copying.
#[non_exhaustive]
pub struct CommissionerConfig<'a> {
    /// 16-byte attestation challenge derived from the active PASE
    /// session. Matter Core Spec §3.6.4: bytes `[32..48]` of the
    /// 48-byte PASE session key blob (exposed as
    /// `PaseSessionKeys::attestation_key`).
    pub pase_attestation_challenge: [u8; 16],
    /// The commissioner's fabric record (RCAC keypair + signer + IPK).
    /// Constructed via [`FabricRecord::new_root_only`] from M6.3.
    pub fabric: &'a FabricRecord,
    /// The setup payload parsed from QR or manual code (M6.1). Used
    /// to cross-check VID/PID against the DAC's subject during
    /// attestation verification.
    pub setup_payload: &'a SetupPayload,
    /// Trusted PAA roots for attestation chain validation (M6.2).
    pub paa_trust_store: &'a PaaTrustStore,
    /// The commissioner's own operational node ID on this fabric.
    /// Must be non-zero.
    pub commissioner_node_id: u64,
    /// The operational node ID being assigned to the device on this
    /// fabric. Must be non-zero and distinct from
    /// `commissioner_node_id`.
    pub assigned_node_id: u64,
    /// 16-byte Identity Protection Key (IPK) epoch key for `AddNOC`.
    /// Matter Core Spec §4.15.2. Must not be all-zero (rejected by
    /// the device-side `AddNOC` handler).
    pub ipk_epoch_key: [u8; 16],
    /// CASE admin subject for `AddNOC` (typically the commissioner's
    /// own operational node ID).
    pub case_admin_subject: u64,
    /// Admin vendor ID for `AddNOC`.
    pub admin_vendor_id: u16,
    /// Wall-clock time at construction. Used for NOC + RCAC validity
    /// windows and for chain verification's `not_before` / `not_after`
    /// checks.
    pub now: MatterTime,
    /// RNG for nonces (`CSRNonce`, `AttestationNonce`) and NOC serials.
    pub rng: Arc<dyn NocRng>,
}

/// The commissioning state machine cursor.
///
/// One `Commissioner` per in-flight commissioning. `Send` but `!Sync`.
/// See module docs in [`crate::state_machine`] for the driver-loop
/// example.
// `commissioner_node_id` mirrors Matter Core Spec terminology
// (commissioner node ID vs. assigned node ID). Renaming to satisfy
// the lint would obscure the spec mapping.
#[allow(clippy::struct_field_names)]
pub struct Commissioner {
    stage: Stage,

    // Configuration captured at construction time. Storage slots for
    // M6.4.2+ (`pai_der`, `dac_der`, `attestation_response`, CSR /
    // NOC artefacts, the CASE-awaiting flag, etc.) are added in
    // later tasks as the corresponding stages land — keeping the
    // struct minimal here avoids per-task churn on the field list.
    #[allow(dead_code)] // Used by attestation/CSR verification in M6.4.2+.
    pase_attestation_challenge: [u8; 16],
    #[allow(dead_code)] // Used by NOC issuance + chain validation in M6.4.4.
    fabric: FabricRecord,
    #[allow(dead_code)] // Used by chain validation in M6.4.2.
    paa_trust_store: PaaTrustStore,
    #[allow(dead_code)] // Used by VID/PID cross-check in M6.4.2.
    setup_payload: SetupPayload,
    #[allow(dead_code)] // Used by NOC subject in M6.4.4.
    commissioner_node_id: u64,
    #[allow(dead_code)] // Used by NOC subject in M6.4.4.
    assigned_node_id: u64,
    #[allow(dead_code)] // Used by AddNOC payload in M6.4.4.
    ipk_epoch_key: [u8; 16],
    #[allow(dead_code)] // Used by AddNOC payload in M6.4.4.
    case_admin_subject: u64,
    #[allow(dead_code)] // Used by AddNOC payload in M6.4.4.
    admin_vendor_id: u16,
    #[allow(dead_code)] // Used by cert validity windows in M6.4.2 + M6.4.4.
    now: MatterTime,
    #[allow(dead_code)] // Used for nonce generation in M6.4.2 + M6.4.4.
    rng: Arc<dyn NocRng>,

    /// The Expectation the state machine last emitted with `poll()`.
    /// `None` while not waiting for a response (terminal stages, or
    /// pre-poll).
    awaiting: Option<Expectation>,

    /// Cached pending Action so repeated `poll()` calls between
    /// `on_response`s are idempotent. Cleared when the cursor advances.
    pending_action: Option<Action>,
}

impl Commissioner {
    /// Construct a new commissioner from a validated config.
    ///
    /// # Errors
    ///
    /// Returns [`CommissioningError::InvalidConfig`] if any field fails
    /// basic validation: zero `commissioner_node_id`, zero
    /// `assigned_node_id`, `commissioner_node_id == assigned_node_id`,
    /// or all-zero `ipk_epoch_key`.
    pub fn new(cfg: CommissionerConfig<'_>) -> Result<Self, CommissioningError> {
        if cfg.commissioner_node_id == 0 {
            return Err(CommissioningError::InvalidConfig(
                "commissioner_node_id must be non-zero",
            ));
        }
        if cfg.assigned_node_id == 0 {
            return Err(CommissioningError::InvalidConfig(
                "assigned_node_id must be non-zero",
            ));
        }
        if cfg.assigned_node_id == cfg.commissioner_node_id {
            return Err(CommissioningError::InvalidConfig(
                "assigned_node_id must differ from commissioner_node_id",
            ));
        }
        if cfg.ipk_epoch_key == [0u8; 16] {
            return Err(CommissioningError::InvalidConfig(
                "ipk_epoch_key must not be all-zero",
            ));
        }
        Ok(Self {
            stage: Stage::SecurePairing,
            pase_attestation_challenge: cfg.pase_attestation_challenge,
            fabric: cfg.fabric.clone(),
            paa_trust_store: cfg.paa_trust_store.clone(),
            setup_payload: cfg.setup_payload.clone(),
            commissioner_node_id: cfg.commissioner_node_id,
            assigned_node_id: cfg.assigned_node_id,
            ipk_epoch_key: cfg.ipk_epoch_key,
            case_admin_subject: cfg.case_admin_subject,
            admin_vendor_id: cfg.admin_vendor_id,
            now: cfg.now,
            rng: cfg.rng,
            awaiting: None,
            pending_action: None,
        })
    }

    /// Current cursor position. Useful for logging + tests.
    #[must_use]
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// Drive the state machine forward.
    ///
    /// Returns the next [`Action`] the caller must perform. Idempotent:
    /// calling `poll` twice without an intervening `on_response` returns
    /// the same `Action`.
    ///
    /// # Errors
    ///
    /// Returns the typed error that caused a transition into
    /// [`Stage::Failed`] — when this happens, the cursor advances to
    /// `Failed` and the next `poll()` call emits an
    /// [`Action::Abort`] with a rendered summary of the failure.
    pub fn poll(&mut self) -> Result<Action, CommissioningError> {
        if let Some(act) = self.pending_action.clone() {
            return Ok(act);
        }
        let action = self.dispatch_stage()?;
        self.pending_action = Some(action.clone());
        Ok(action)
    }

    /// Compute the next [`Action`] for the current [`Stage`].
    ///
    /// Called by [`Self::poll`] only when there is no cached
    /// `pending_action`. Walks `Stage::SecurePairing` forward to the
    /// first wire stage by self-recursion; stages past
    /// `Stage::ConfigRegulatory` short-circuit to `Stage::Failed` until
    /// M6.4.2+ tasks land.
    fn dispatch_stage(&mut self) -> Result<Action, CommissioningError> {
        use crate::clusters::general_commissioning as gc;
        use crate::state_machine::action::SessionContext;
        match self.stage {
            Stage::SecurePairing => {
                // Entry → first wire stage. Advance and re-dispatch.
                self.stage = Stage::ReadCommissioningInfo;
                self.dispatch_stage()
            }
            Stage::ReadCommissioningInfo => {
                self.awaiting = Some(Expectation::CommissioningInfo);
                Ok(Action::ReadAttribute {
                    session: SessionContext::Pase,
                    endpoint: 0,
                    cluster: gc::CLUSTER_ID,
                    attributes: &[
                        // Spec §11.10.7: BasicCommissioningInfo (failsafe_expiry_length_seconds, …)
                        0x0000, // RegulatoryConfig
                        0x0001, // LocationCapability
                        0x0002, // SupportsConcurrentConnection
                        0x0004,
                    ],
                    expect: Expectation::CommissioningInfo,
                })
            }
            Stage::ArmFailsafe => {
                // Failsafe expiry length is set conservatively to 60s.
                // M6.4.1 hard-codes; future tasks may read the value
                // from `ReadCommissioningInfo`'s response.
                let payload = gc::encode_arm_fail_safe(60, 0);
                self.awaiting = Some(Expectation::ArmFailsafeResponse);
                Ok(Action::Invoke {
                    session: SessionContext::Pase,
                    endpoint: 0,
                    cluster: gc::CLUSTER_ID,
                    command: gc::command_id::ARM_FAIL_SAFE,
                    payload,
                    expect: Expectation::ArmFailsafeResponse,
                })
            }
            Stage::ConfigRegulatory => {
                let payload = gc::encode_set_regulatory_config(
                    gc::RegulatoryLocation::IndoorOutdoor,
                    "XX",
                    0,
                );
                self.awaiting = Some(Expectation::SetRegulatoryConfigResponse);
                Ok(Action::Invoke {
                    session: SessionContext::Pase,
                    endpoint: 0,
                    cluster: gc::CLUSTER_ID,
                    command: gc::command_id::SET_REGULATORY_CONFIG,
                    payload,
                    expect: Expectation::SetRegulatoryConfigResponse,
                })
            }
            Stage::Failed => {
                // Subsequent poll() after a failure surfaces the Abort.
                // The state machine stays in Failed.
                self.awaiting = None;
                Ok(Action::Abort {
                    send_disarm_failsafe: true,
                    reason: CommissioningError::CdVerificationUnavailable.to_string(),
                })
            }
            // Stages past ConfigRegulatory land in M6.4.2+ sub-phases.
            // For M6.4.1, short-circuit to Failed so the state machine
            // emits a self-consistent (if intentionally incomplete)
            // Abort sequence.
            _ => {
                self.stage = Stage::Failed;
                self.awaiting = None;
                self.pending_action = None;
                Err(CommissioningError::CdVerificationUnavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Test-code carve-out: see CLAUDE.md.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::noc::{FabricRecord, NocRng, SystemNocRng};
    use crate::setup::{
        CommissioningFlow, DiscoveryCapabilities, Discriminator, Passcode, SetupPayload,
    };
    use crate::state_machine::{Action, Expectation};
    use crate::PaaTrustStore;
    use matter_cert::time::MatterTime;
    use matter_crypto::{RingSigner, Signer};
    use std::sync::Arc;

    fn make_setup_payload() -> SetupPayload {
        SetupPayload {
            version: 0,
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            commissioning_flow: CommissioningFlow::Standard,
            discovery_capabilities: DiscoveryCapabilities::ON_NETWORK,
            discriminator: Discriminator::new(0x0F00).expect("valid discriminator"),
            passcode: Passcode::new(20_202_021).expect("valid passcode"),
        }
    }

    fn make_fabric_record() -> FabricRecord {
        let (signer, _pkcs8) = RingSigner::generate().unwrap();
        let signer: Arc<dyn Signer> = Arc::new(signer);
        FabricRecord::new_root_only(
            /* fabric_id */ 0x0000_0000_0000_0001,
            signer,
            /* not_before */ MatterTime::from_unix_secs(1_704_067_200),
            /* not_after */ MatterTime::from_unix_secs(1_735_689_600),
            /* rcac_id */ 42,
            &SystemNocRng,
        )
        .unwrap()
    }

    fn base_config<'a>(
        fabric: &'a FabricRecord,
        setup: &'a SetupPayload,
        paa: &'a PaaTrustStore,
        rng: Arc<dyn NocRng>,
    ) -> CommissionerConfig<'a> {
        CommissionerConfig {
            pase_attestation_challenge: [0u8; 16],
            fabric,
            setup_payload: setup,
            paa_trust_store: paa,
            commissioner_node_id: 0x1,
            assigned_node_id: 0x2,
            ipk_epoch_key: [0x42_u8; 16],
            case_admin_subject: 0x1,
            admin_vendor_id: 0xFFF1,
            now: MatterTime::from_unix_secs(1_704_067_200),
            rng,
        }
    }

    #[test]
    fn new_rejects_zero_commissioner_node_id() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
        let mut cfg = base_config(&fabric, &setup, &paa, rng);
        cfg.commissioner_node_id = 0;
        // Cannot use `expect_err`: `Commissioner` does not impl Debug
        // because `FabricRecord` (a stored field) is not Debug.
        let Err(err) = Commissioner::new(cfg) else {
            panic!("zero commissioner_node_id should fail");
        };
        assert!(
            matches!(err, CommissioningError::InvalidConfig(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn new_rejects_zero_assigned_node_id() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
        let mut cfg = base_config(&fabric, &setup, &paa, rng);
        cfg.assigned_node_id = 0;
        let Err(err) = Commissioner::new(cfg) else {
            panic!("zero assigned_node_id should fail");
        };
        assert!(
            matches!(err, CommissioningError::InvalidConfig(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn new_rejects_equal_commissioner_and_assigned_ids() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
        let mut cfg = base_config(&fabric, &setup, &paa, rng);
        cfg.commissioner_node_id = 0x42;
        cfg.assigned_node_id = 0x42;
        let Err(err) = Commissioner::new(cfg) else {
            panic!("equal IDs should fail");
        };
        assert!(
            matches!(err, CommissioningError::InvalidConfig(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn new_rejects_zero_ipk_epoch_key() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
        let mut cfg = base_config(&fabric, &setup, &paa, rng);
        cfg.ipk_epoch_key = [0u8; 16];
        let Err(err) = Commissioner::new(cfg) else {
            panic!("zero IPK should fail");
        };
        assert!(
            matches!(err, CommissioningError::InvalidConfig(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn new_returns_secure_pairing_stage() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
        let cfg = base_config(&fabric, &setup, &paa, rng);
        let sm = Commissioner::new(cfg).expect("valid config should construct");
        assert_eq!(sm.stage(), Stage::SecurePairing);
    }

    #[test]
    fn poll_from_secure_pairing_emits_read_commissioning_info() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
        let cfg = base_config(&fabric, &setup, &paa, rng);
        let mut sm = Commissioner::new(cfg).expect("valid config");
        let act = sm.poll().expect("poll succeeds");
        match act {
            Action::ReadAttribute {
                session,
                endpoint,
                cluster,
                attributes,
                expect,
            } => {
                assert_eq!(session, crate::state_machine::SessionContext::Pase);
                assert_eq!(endpoint, 0);
                assert_eq!(cluster, 0x0030);
                assert_eq!(expect, Expectation::CommissioningInfo);
                assert!(!attributes.is_empty());
            }
            other => panic!("expected ReadAttribute, got {other:?}"),
        }
        assert_eq!(sm.stage(), Stage::ReadCommissioningInfo);
    }

    #[test]
    fn poll_is_idempotent_between_responses() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
        let cfg = base_config(&fabric, &setup, &paa, rng);
        let mut sm = Commissioner::new(cfg).expect("valid config");
        let act1 = sm.poll().expect("first poll");
        let act2 = sm.poll().expect("second poll");
        match (act1, act2) {
            (
                Action::ReadAttribute {
                    cluster: c1,
                    expect: e1,
                    ..
                },
                Action::ReadAttribute {
                    cluster: c2,
                    expect: e2,
                    ..
                },
            ) => {
                assert_eq!(c1, c2);
                assert_eq!(e1, e2);
            }
            other => panic!("idempotent poll returned different variants: {other:?}"),
        }
    }
}
