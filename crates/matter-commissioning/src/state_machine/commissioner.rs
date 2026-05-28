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

    /// Rendered summary of why the state machine entered `Failed`,
    /// stashed by `on_response`'s error path and read by the
    /// `Stage::Failed` arm of `dispatch_stage` so `Action::Abort.reason`
    /// surfaces the real failure (not a hard-coded placeholder).
    last_failure: Option<String>,
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
            last_failure: None,
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
                let reason = self
                    .last_failure
                    .clone()
                    .unwrap_or_else(|| CommissioningError::CdVerificationUnavailable.to_string());
                Ok(Action::Abort {
                    send_disarm_failsafe: true,
                    reason,
                })
            }
            // Stages past ConfigRegulatory land in M6.4.2+ sub-phases.
            // For M6.4.1, short-circuit to Failed so the state machine
            // emits a self-consistent (if intentionally incomplete)
            // Abort sequence.
            _ => {
                self.last_failure = Some(CommissioningError::CdVerificationUnavailable.to_string());
                self.stage = Stage::Failed;
                self.awaiting = None;
                self.pending_action = None;
                Err(CommissioningError::CdVerificationUnavailable)
            }
        }
    }

    /// Feed a response payload back into the state machine.
    ///
    /// `expect` MUST match the [`Expectation`] from the last `poll()`'s
    /// emitted `Action`.
    ///
    /// # Errors
    ///
    /// - [`CommissioningError::OutOfOrderResponse`] if the state machine
    ///   isn't currently waiting for a response.
    /// - [`CommissioningError::UnexpectedResponseKind`] if `expect`
    ///   doesn't match the last `Action`'s `Expectation`. The cursor
    ///   does not advance.
    /// - [`CommissioningError::MalformedResponse`] if `payload` fails
    ///   to decode at the cluster-command level.
    /// - [`CommissioningError::DeviceImStatus`] if the device returned a
    ///   non-OK Interaction Model status.
    ///
    /// Any error other than `OutOfOrderResponse` and
    /// `UnexpectedResponseKind` transitions the cursor to
    /// [`Stage::Failed`]; the next `poll()` call emits
    /// [`Action::Abort`] with a rendered summary.
    pub fn on_response(
        &mut self,
        expect: Expectation,
        payload: &[u8],
    ) -> Result<(), CommissioningError> {
        let Some(awaiting) = self.awaiting else {
            return Err(CommissioningError::OutOfOrderResponse(self.stage));
        };
        if awaiting != expect {
            return Err(CommissioningError::UnexpectedResponseKind {
                expected: awaiting,
                got: expect,
            });
        }
        match self.handle_response(expect, payload) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.last_failure = Some(err.to_string());
                self.stage = Stage::Failed;
                self.awaiting = None;
                self.pending_action = None;
                Err(err)
            }
        }
    }

    fn handle_response(
        &mut self,
        expect: Expectation,
        payload: &[u8],
    ) -> Result<(), CommissioningError> {
        use crate::clusters::general_commissioning as gc;
        match expect {
            Expectation::CommissioningInfo => {
                // M6.4.1: accept any well-formed TLV. Future sub-phases
                // may parse BasicCommissioningInfo to extract
                // failsafe_expiry_length_seconds + regulatory caps.
                Self::assert_tlv_well_formed(self.stage, payload)?;
                self.advance(Stage::ArmFailsafe);
                Ok(())
            }
            Expectation::ArmFailsafeResponse => {
                let resp = gc::decode_arm_fail_safe_response(payload)?;
                if resp.error_code != 0 {
                    return Err(CommissioningError::DeviceImStatus {
                        stage: Stage::ArmFailsafe,
                        im_status: u16::from(resp.error_code),
                    });
                }
                self.advance(Stage::ConfigRegulatory);
                Ok(())
            }
            Expectation::SetRegulatoryConfigResponse => {
                let resp = gc::decode_set_regulatory_config_response(payload)?;
                if resp.error_code != 0 {
                    return Err(CommissioningError::DeviceImStatus {
                        stage: Stage::ConfigRegulatory,
                        im_status: u16::from(resp.error_code),
                    });
                }
                self.advance(Stage::SendPaiCertRequest);
                Ok(())
            }
            // Other Expectations land in M6.4.2+ sub-phases.
            _ => Err(CommissioningError::OutOfOrderResponse(self.stage)),
        }
    }

    fn advance(&mut self, next: Stage) {
        self.stage = next;
        self.awaiting = None;
        self.pending_action = None;
    }

    fn assert_tlv_well_formed(stage: Stage, payload: &[u8]) -> Result<(), CommissioningError> {
        use matter_codec::{ContainerKind, Element, Tag, TlvReader};
        let mut reader = TlvReader::new(payload);
        match reader
            .next()
            .map_err(|_| CommissioningError::MalformedResponse(stage))?
        {
            Some(Element::ContainerStart {
                tag: Tag::Anonymous,
                kind: ContainerKind::Structure,
            }) => {}
            _ => return Err(CommissioningError::MalformedResponse(stage)),
        }
        // Walk to ContainerEnd; ignore contents for M6.4.1.
        loop {
            match reader
                .next()
                .map_err(|_| CommissioningError::MalformedResponse(stage))?
            {
                None => return Err(CommissioningError::MalformedResponse(stage)),
                Some(Element::ContainerEnd) => return Ok(()),
                Some(_) => {}
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

    #[test]
    fn full_happy_path_through_config_regulatory_emits_abort_at_pai_request() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn crate::noc::NocRng> = Arc::new(SystemNocRng);
        let cfg = base_config(&fabric, &setup, &paa, rng);
        let mut sm = Commissioner::new(cfg).expect("valid config");

        // SecurePairing → ReadCommissioningInfo
        let _ = sm.poll().expect("poll #1");
        let canned_info = encode_read_commissioning_info_response();
        sm.on_response(Expectation::CommissioningInfo, &canned_info)
            .expect("commissioning info accepted");
        assert_eq!(sm.stage(), Stage::ArmFailsafe);

        // ArmFailsafe
        let _ = sm.poll().expect("poll #2");
        sm.on_response(
            Expectation::ArmFailsafeResponse,
            &[0x15, 0x24, 0x00, 0x00, 0x18],
        )
        .expect("arm failsafe ok");
        assert_eq!(sm.stage(), Stage::ConfigRegulatory);

        // ConfigRegulatory
        let _ = sm.poll().expect("poll #3");
        sm.on_response(
            Expectation::SetRegulatoryConfigResponse,
            &[0x15, 0x24, 0x00, 0x00, 0x18],
        )
        .expect("config regulatory ok");
        assert_eq!(sm.stage(), Stage::SendPaiCertRequest);

        // Next poll() short-circuits to Failed with CdVerificationUnavailable.
        let err = sm
            .poll()
            .expect_err("M6.4.1 short-circuits past ConfigRegulatory");
        assert!(matches!(err, CommissioningError::CdVerificationUnavailable));
        assert_eq!(sm.stage(), Stage::Failed);

        // Subsequent poll emits Action::Abort with the rendered reason.
        match sm.poll().expect("abort emission") {
            Action::Abort {
                send_disarm_failsafe,
                reason,
            } => {
                assert!(send_disarm_failsafe);
                assert!(reason.contains("M6.4.3"), "reason was {reason}");
            }
            other => panic!("expected Abort, got {other:?}"),
        }
    }

    #[test]
    fn arm_failsafe_busy_response_aborts_with_device_im_status() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn crate::noc::NocRng> = Arc::new(SystemNocRng);
        let cfg = base_config(&fabric, &setup, &paa, rng);
        let mut sm = Commissioner::new(cfg).expect("valid config");
        let _ = sm.poll().expect("poll info");
        sm.on_response(
            Expectation::CommissioningInfo,
            &encode_read_commissioning_info_response(),
        )
        .expect("commissioning info ok");
        let _ = sm.poll().expect("poll arm failsafe");
        // Device returns BusyWithOtherAdmin: error_code = 4 (spec §11.10.5.1).
        let err = sm
            .on_response(
                Expectation::ArmFailsafeResponse,
                &[0x15, 0x24, 0x00, 0x04, 0x18],
            )
            .expect_err("busy should fail");
        assert!(matches!(
            err,
            CommissioningError::DeviceImStatus {
                stage: Stage::ArmFailsafe,
                im_status: 4,
            }
        ));
        assert_eq!(sm.stage(), Stage::Failed);
        match sm.poll().expect("abort emission") {
            Action::Abort {
                send_disarm_failsafe,
                reason,
            } => {
                assert!(send_disarm_failsafe);
                assert!(reason.contains("ArmFailsafe"), "reason was {reason}");
                assert!(reason.contains("0x4"), "reason was {reason}");
            }
            other => panic!("expected Abort, got {other:?}"),
        }
    }

    #[test]
    fn out_of_order_response_returns_error_without_advancing() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn crate::noc::NocRng> = Arc::new(SystemNocRng);
        let cfg = base_config(&fabric, &setup, &paa, rng);
        let mut sm = Commissioner::new(cfg).expect("valid config");
        // No poll called — state machine isn't waiting on anything.
        let err = sm
            .on_response(Expectation::ArmFailsafeResponse, &[])
            .expect_err("should reject out-of-order");
        assert!(matches!(err, CommissioningError::OutOfOrderResponse(_)));
        assert_eq!(sm.stage(), Stage::SecurePairing);
    }

    #[test]
    fn wrong_expectation_returns_unexpected_response_kind() {
        let fabric = make_fabric_record();
        let setup = make_setup_payload();
        let paa = PaaTrustStore::with_csa_test_roots();
        let rng: Arc<dyn crate::noc::NocRng> = Arc::new(SystemNocRng);
        let cfg = base_config(&fabric, &setup, &paa, rng);
        let mut sm = Commissioner::new(cfg).expect("valid config");
        let _ = sm.poll().expect("poll");
        let err = sm
            .on_response(Expectation::ArmFailsafeResponse, &[])
            .expect_err("wrong kind should fail");
        assert!(matches!(
            err,
            CommissioningError::UnexpectedResponseKind {
                expected: Expectation::CommissioningInfo,
                got: Expectation::ArmFailsafeResponse,
            }
        ));
        // Wrong-kind does NOT advance the cursor.
        assert_eq!(sm.stage(), Stage::ReadCommissioningInfo);
    }

    fn encode_read_commissioning_info_response() -> Vec<u8> {
        // Minimal well-formed anonymous struct. M6.4.1 doesn't parse
        // individual attributes yet.
        vec![0x15, 0x18]
    }
}
