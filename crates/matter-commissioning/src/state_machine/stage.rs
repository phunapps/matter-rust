//! `Stage` — every cursor position the state machine can occupy.
//!
//! Stages match `project-chip/connectedhomeip`'s `CommissioningStage`
//! enum (translated to Rust style and trimmed to the M6.4 subset).
//! Stages we defer past M6.4 are noted inline as `// deferred: kFoo`
//! so future expansion is mechanical.

#![forbid(unsafe_code)]

/// Cursor position inside the commissioning sequence.
///
/// Variants are ordered top-to-bottom in transition order. The transition
/// function lives in [`next_stage`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stage {
    /// Entry state — caller has just constructed the [`super::Commissioner`]
    /// with a valid PASE session. No action emitted; advances on first
    /// `poll()` to [`Self::ReadCommissioningInfo`].
    SecurePairing,
    /// Read `BasicCommissioningInfo`, `RegulatoryConfig`, etc. from the
    /// `GeneralCommissioning` cluster (id `0x0030`) so the commissioner
    /// knows `failsafe_expiry_length_seconds` before arming the failsafe.
    ReadCommissioningInfo,
    /// `GeneralCommissioning::ArmFailSafe` (command id `0x00`).
    ArmFailsafe,
    /// `GeneralCommissioning::SetRegulatoryConfig` (command id `0x02`).
    ConfigRegulatory,
    /// `OperationalCredentials::CertificateChainRequest` with `type=PAI`
    /// (cluster `0x003E`, command `0x02`, type enum `0x01`).
    SendPaiCertRequest,
    /// `OperationalCredentials::CertificateChainRequest` with `type=DAC`
    /// (type enum `0x02`).
    SendDacCertRequest,
    /// `OperationalCredentials::AttestationRequest` (command `0x00`).
    SendAttestationRequest,
    /// Off-wire: chain + signature + CD verification.
    AttestationVerification,
    /// `OperationalCredentials::CSRRequest` (command `0x04`).
    SendOpCertSigningRequest,
    /// Off-wire: PKCS#10 self-signature + DAC attestation + nonce echo.
    ValidateCsr,
    /// Off-wire: build + sign the NOC under the commissioner's RCAC.
    GenerateNocChain,
    /// `OperationalCredentials::AddTrustedRootCertificate` (command `0x0B`).
    SendTrustedRootCert,
    /// `OperationalCredentials::AddNOC` (command `0x06`).
    SendNoc,
    /// Network commissioning — M6.4 ships as a structural no-op. M6.5
    /// expands into the full Wi-Fi/Thread subgraph (`kScanNetworks`,
    /// `kWiFiNetworkSetup`, `kFailsafeBeforeWiFiEnable`,
    /// `kWiFiNetworkEnable`, etc.).
    NetworkCommissioning,
    /// Evict any prior CASE session for this fabric/peer pair. M6.4
    /// only supports new-fabric commissioning — no eviction needed —
    /// so the stage advances immediately. Slot reserved for M8
    /// multi-fabric work.
    EvictPreviousCaseSessions,
    /// Caller establishes a CASE session via mDNS find-operational +
    /// SIGMA handshake (M6.6 mechanics). State machine emits
    /// `Action::EstablishCase` and waits for `on_case_established()`.
    FindOperationalForComplete,
    /// `GeneralCommissioning::CommissioningComplete` (command `0x04`),
    /// sent over the freshly-established CASE session.
    SendComplete,
    /// Terminal success. Emits `Action::Done(CommissionedFabric)`.
    Cleanup,
    /// Terminal failure. Emits `Action::Abort`.
    Failed,
    // deferred: kReadCommissioningInfo2 (post-NOC capability re-read)
    // deferred: kConfigureUTCTime, kConfigureTimeZone, kConfigureDSTOffset, kConfigureDefaultNTP
    // deferred: kAttestationRevocationCheck
    // deferred: kJCMTrustVerification
    // deferred: kICDGetRegistrationInfo, kICDRegistration
    // deferred: kConfigureTCAcknowledgments
    // deferred: kPrimaryOperationalNetworkFailed, kRemoveWiFiNetworkConfig, kRemoveThreadNetworkConfig
}

/// Happy-path successor of `current`. Returns `None` for terminal
/// stages (`Cleanup`, `Failed`).
///
/// Used by [`super::Commissioner`] to advance the cursor after a stage
/// completes successfully. Errors at any stage transition the cursor
/// directly to [`Stage::Failed`] rather than calling this function.
// Used by Commissioner::advance from M6.4.1 T6 onward.
#[allow(dead_code)]
#[allow(unreachable_pub)]
#[must_use]
pub fn next_stage(current: Stage) -> Option<Stage> {
    Some(match current {
        Stage::SecurePairing => Stage::ReadCommissioningInfo,
        Stage::ReadCommissioningInfo => Stage::ArmFailsafe,
        Stage::ArmFailsafe => Stage::ConfigRegulatory,
        Stage::ConfigRegulatory => Stage::SendPaiCertRequest,
        Stage::SendPaiCertRequest => Stage::SendDacCertRequest,
        Stage::SendDacCertRequest => Stage::SendAttestationRequest,
        Stage::SendAttestationRequest => Stage::AttestationVerification,
        Stage::AttestationVerification => Stage::SendOpCertSigningRequest,
        Stage::SendOpCertSigningRequest => Stage::ValidateCsr,
        Stage::ValidateCsr => Stage::GenerateNocChain,
        Stage::GenerateNocChain => Stage::SendTrustedRootCert,
        Stage::SendTrustedRootCert => Stage::SendNoc,
        Stage::SendNoc => Stage::NetworkCommissioning,
        Stage::NetworkCommissioning => Stage::EvictPreviousCaseSessions,
        Stage::EvictPreviousCaseSessions => Stage::FindOperationalForComplete,
        Stage::FindOperationalForComplete => Stage::SendComplete,
        Stage::SendComplete => Stage::Cleanup,
        Stage::Cleanup | Stage::Failed => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_advances_through_all_stages() {
        // Test-code carve-out: see CLAUDE.md.
        #![allow(clippy::unwrap_used)]
        let expected = [
            Stage::SecurePairing,
            Stage::ReadCommissioningInfo,
            Stage::ArmFailsafe,
            Stage::ConfigRegulatory,
            Stage::SendPaiCertRequest,
            Stage::SendDacCertRequest,
            Stage::SendAttestationRequest,
            Stage::AttestationVerification,
            Stage::SendOpCertSigningRequest,
            Stage::ValidateCsr,
            Stage::GenerateNocChain,
            Stage::SendTrustedRootCert,
            Stage::SendNoc,
            Stage::NetworkCommissioning,
            Stage::EvictPreviousCaseSessions,
            Stage::FindOperationalForComplete,
            Stage::SendComplete,
            Stage::Cleanup,
        ];
        for pair in expected.windows(2) {
            assert_eq!(
                next_stage(pair[0]),
                Some(pair[1]),
                "next_stage({:?}) should be Some({:?})",
                pair[0],
                pair[1],
            );
        }
        assert_eq!(next_stage(Stage::Cleanup), None, "Cleanup is terminal");
        assert_eq!(next_stage(Stage::Failed), None, "Failed is terminal");
    }
}
