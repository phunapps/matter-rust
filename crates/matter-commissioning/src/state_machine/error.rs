//! `CommissioningError` — error variants surfaced by the state machine.

#![forbid(unsafe_code)]

use crate::attestation::AttestationError;
use crate::noc::NocError;
use crate::state_machine::action::Expectation;
use crate::state_machine::stage::Stage;

/// Errors emitted by the commissioning state machine.
///
/// All variants are `#[non_exhaustive]` — future sub-phases or future
/// milestones (M6.5 network commissioning, etc.) can add variants
/// without breaking SemVer.
///
/// `CommissioningError` is intentionally **not** `Clone`. The summary
/// emitted in [`super::Action::Abort`] is a pre-rendered `String`, so
/// callers never need to clone the full error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommissioningError {
    /// `CommissionerConfig` failed validation in `Commissioner::new`.
    /// Carries a `&'static str` describing which field is bad — no
    /// alloc on the error path.
    #[error("invalid commissioner config: {0}")]
    InvalidConfig(&'static str),

    /// Caller invoked `on_response` with an `Expectation` that does
    /// not match the last `poll()`'s emitted `Expectation`.
    #[error("unexpected response kind: expected {expected:?}, got {got:?}")]
    UnexpectedResponseKind {
        /// The Expectation the state machine emitted with the last
        /// Action.
        expected: Expectation,
        /// The Expectation the caller passed in.
        got: Expectation,
    },

    /// Caller invoked `on_response` or `on_case_established` in a
    /// stage where the state machine is not waiting for input (e.g.
    /// `Stage::Cleanup` or `Stage::SecurePairing`).
    #[error("response delivered out of order at stage {0:?}")]
    OutOfOrderResponse(Stage),

    /// Device returned a non-OK Interaction Model status for a cluster
    /// command at `stage`. The 16-bit `im_status` is the canonical
    /// Matter status code from the response envelope.
    #[error("device rejected stage {stage:?}: IM status {im_status:#x}")]
    DeviceImStatus {
        /// Where the rejection happened.
        stage: Stage,
        /// IM status code (Matter Core Spec §8.10).
        im_status: u16,
    },

    /// Response TLV failed to decode at the cluster command level.
    #[error("malformed response at stage {0:?}")]
    MalformedResponse(Stage),

    /// Attestation verification failed (chain / signature / CD).
    #[error("attestation verification failed: {0}")]
    Attestation(#[from] AttestationError),

    /// CD verification module is required but absent. Emitted only by
    /// M6.4.2 builds (after the attestation flow lands but before M6.4.3
    /// wires CD verification in). Removed once M6.4.3 lands.
    #[error("certification declaration verification unavailable — M6.4.3 required")]
    CdVerificationUnavailable,

    /// CSR verification or NOC issuance failed.
    #[error("NOC issuance failed: {0}")]
    Noc(#[from] NocError),

    /// CASE establishment failed (caller called
    /// `on_response(Expectation::CaseFailed, &[])`).
    #[error("CASE session establishment failed")]
    CaseEstablishmentFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::action::Expectation;
    use crate::state_machine::stage::Stage;

    #[test]
    fn invalid_config_carries_message() {
        let e = CommissioningError::InvalidConfig("missing IPK epoch key");
        let msg = e.to_string();
        assert!(msg.contains("missing IPK"), "{msg}");
    }

    #[test]
    fn unexpected_response_kind_shows_both_sides() {
        let e = CommissioningError::UnexpectedResponseKind {
            expected: Expectation::ArmFailsafeResponse,
            got: Expectation::AttestationResponse,
        };
        let msg = e.to_string();
        assert!(msg.contains("ArmFailsafeResponse"), "{msg}");
        assert!(msg.contains("AttestationResponse"), "{msg}");
    }

    #[test]
    fn out_of_order_response_names_the_stage() {
        let e = CommissioningError::OutOfOrderResponse(Stage::ArmFailsafe);
        let msg = e.to_string();
        assert!(msg.contains("ArmFailsafe"), "{msg}");
    }

    #[test]
    fn device_im_status_includes_stage_and_status_code() {
        let e = CommissioningError::DeviceImStatus {
            stage: Stage::ArmFailsafe,
            im_status: 0x0098,
        };
        let msg = e.to_string();
        assert!(msg.contains("ArmFailsafe"), "{msg}");
        assert!(msg.contains("0x98"), "{msg}");
    }

    #[test]
    fn cd_verification_unavailable_message_mentions_m6_4_3() {
        let msg = CommissioningError::CdVerificationUnavailable.to_string();
        assert!(msg.contains("M6.4.3"), "{msg}");
    }
}
