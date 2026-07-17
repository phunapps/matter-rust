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
/// without breaking `SemVer`.
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

    /// CSR verification or NOC issuance failed.
    #[error("NOC issuance failed: {0}")]
    Noc(#[from] NocError),

    /// CASE establishment failed (caller called
    /// `on_response(Expectation::CaseFailed, &[])`).
    #[error("CASE session establishment failed")]
    CaseEstablishmentFailed,

    /// `NetworkCommissioning::FeatureMap` declared a network type the
    /// commissioner does not support in v1.0. Currently this means a
    /// device that only supports Thread, or a device that returned a
    /// `FeatureMap` with no recognised bits set.
    #[error("device requires {needed:?} network type; not supported in v1.0")]
    NetworkFeatureUnsupported {
        /// Which network type the device requires.
        needed: NetworkKind,
    },

    /// Device rejected `AddOrUpdateWiFiNetwork` or `ConnectNetwork`
    /// with a non-OK `NetworkCommissioningStatusEnum` value
    /// (spec §11.9.5.1).
    #[error(
        "network commissioning rejected at stage {stage:?}: \
             networking_status {networking_status:#x}, \
             debug_text={debug_text:?}, hint={remediation_hint:?}"
    )]
    NetworkRejected {
        /// Which stage the device rejected.
        stage: Stage,
        /// Raw `NetworkCommissioningStatusEnum` value from the
        /// response.
        networking_status: u8,
        /// Optional human-readable debug text echoed by the device.
        debug_text: Option<String>,
        /// Mapped remediation category for downstream UI rendering.
        remediation_hint: RemediationHint,
    },

    /// `network` was not `NetworkCredentials::WiFi` but the device's
    /// `FeatureMap` declared Wi-Fi at a stage that requires the SSID/PSK.
    /// Distinct from `InvalidConfig` because it surfaces at a later
    /// stage once the device's network shape is known.
    #[error("device is Wi-Fi but no wifi credentials supplied")]
    WifiCredentialsRequired,
}

/// Which Matter network-commissioning type a device declared in its
/// `NetworkCommissioning::FeatureMap`.
///
/// `#[non_exhaustive]` — future Matter-spec network interfaces
/// (e.g. Thread Border Router relay) can be added without a breaking
/// change.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum NetworkKind {
    /// Wi-Fi network interface (`FeatureMap` bit 0).
    WiFi,
    /// Thread network interface (`FeatureMap` bit 1).
    Thread,
    /// Ethernet network interface (`FeatureMap` bit 2).
    Ethernet,
}

/// Hint describing what a downstream UI could suggest to remediate a
/// `CommissioningError::NetworkRejected` (lands in M6.5.2).
///
/// Maps from a Matter `NetworkCommissioningStatusEnum` value (spec
/// §11.9.5.1) into a category callers can render meaningfully without
/// parsing the raw status code. The mapping table lives in
/// `crate::clusters::network_commissioning::remediation_for`.
///
/// # Stability
///
/// `#[non_exhaustive]` from inception. New variants may be added in any
/// release. Existing variants will never be renamed or reordered.
/// Changes to the `status_code` → variant mapping are documented in the
/// CHANGELOG as semi-public behavioural changes.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RemediationHint {
    /// Password/passphrase likely wrong. From `AuthFailure` (7).
    CheckPassphrase,
    /// SSID not found. From `NetworkNotFound` (5), `NetworkIDNotFound` (3).
    CheckSsid,
    /// Country code / regulatory location mismatch. From
    /// `RegulatoryError` (6).
    CheckRegulatoryRegion,
    /// Wi-Fi security cipher unsupported (e.g. WEP-only device). From
    /// `UnsupportedSecurity` (8).
    UpgradeSecurityMode,
    /// Device reached its `MaxNetworks` limit. From `BoundsExceeded` (2).
    DeviceNetworkSlotsFull,
    /// IP-stack-layer failure on the device side. From `IPV6Failed` (10),
    /// `IPBindFailed` (11).
    DeviceIpStackFailure,
    /// No specific guidance available. From `OtherConnectionFailure` (9),
    /// `UnknownError` (12), or any status code not yet mapped.
    None,
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
    fn remediation_hint_is_copy_eq_hash() {
        fn assert_copy<T: Copy + Eq + std::hash::Hash>() {}
        assert_copy::<RemediationHint>();
        assert_eq!(RemediationHint::None, RemediationHint::None);
        assert_ne!(RemediationHint::None, RemediationHint::CheckPassphrase);
    }
}
