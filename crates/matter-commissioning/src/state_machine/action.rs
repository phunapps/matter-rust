//! `Action` / `Expectation` / `SessionContext` / `CommissionedFabric` —
//! the outbound vocabulary the [`super::Commissioner`] uses to ask the
//! caller for work.

#![forbid(unsafe_code)]

use crate::noc::FabricRecord;
use crate::state_machine::stage::Stage;

/// Whether an `Action::Invoke` or `Action::ReadAttribute` should be
/// routed over the PASE session (pre-commissioning) or the CASE session
/// (post-AddNOC, after [`Action::EstablishCase`] is fulfilled).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SessionContext {
    /// Pre-commissioning session keyed off the device's passcode.
    Pase,
    /// Post-AddNOC operational session keyed off the new fabric.
    Case,
}

/// The next piece of work the caller must perform.
///
/// Returned by [`super::Commissioner::poll`]. The state machine is
/// idempotent: calling `poll` twice without an intervening `on_response`
/// returns the same `Action`.
// `Done(CommissionedFabric)` is intentionally large (~130 B) but is emitted
// exactly once per successful commission — boxing it would force an alloc on
// the happy path with no real benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Action {
    /// Invoke a cluster command. The caller frames `payload` into an
    /// Invoke envelope and routes via `matter-transport` over the
    /// indicated session. The decoded response payload is fed back via
    /// [`super::Commissioner::on_response`] with the matching `expect`.
    Invoke {
        /// Which session to route the Invoke over.
        session: SessionContext,
        /// Matter endpoint (always `0` for commissioning).
        endpoint: u16,
        /// Cluster ID (`0x0030` `GeneralCommissioning` or `0x003E`
        /// `OperationalCredentials` for all M6.4 stages).
        cluster: u32,
        /// Cluster command ID.
        command: u32,
        /// TLV-encoded command payload.
        payload: Vec<u8>,
        /// The response type the state machine expects next.
        expect: Expectation,
    },

    /// Read attributes from a cluster. Used only by
    /// [`Stage::ReadCommissioningInfo`].
    ReadAttribute {
        /// Which session to route the Read over.
        session: SessionContext,
        /// Matter endpoint (always `0` for commissioning).
        endpoint: u16,
        /// Cluster ID.
        cluster: u32,
        /// Attribute IDs to read.
        attributes: &'static [u32],
        /// The response type the state machine expects next.
        expect: Expectation,
    },

    /// Evict any prior CASE session for this fabric/peer pair.
    ///
    /// **Reserved for M8 multi-fabric work; never emitted by M6.4's
    /// state machine.** Kept in the enum so M8 can wire eviction in
    /// without a `SemVer` bump.
    EvictCase {
        /// Fabric ID to evict on.
        fabric_id: u64,
        /// Peer operational node ID to evict for.
        peer_node_id: u64,
    },

    /// Discover the device on its operational network and establish a
    /// CASE session. Caller calls `Commissioner::on_case_established`
    /// (added in M6.4.5) on success or
    /// `on_response(Expectation::CaseFailed, &[])` on failure.
    EstablishCase {
        /// Fabric ID to establish CASE on.
        fabric_id: u64,
        /// Peer operational node ID to establish with.
        peer_node_id: u64,
    },

    /// Commissioning succeeded. Caller may persist the
    /// [`CommissionedFabric`] long-term.
    Done(CommissionedFabric),

    /// Commissioning failed. If `send_disarm_failsafe` is true, the
    /// caller should send `ArmFailSafe(expiry_length_seconds=0)` to the
    /// device over PASE to roll the device back to its
    /// pre-commissioning state.
    ///
    /// `reason` is a rendered, log-friendly summary of the
    /// `CommissioningError` that caused the abort. The caller will have
    /// also received that error directly via
    /// [`super::Commissioner::on_response`]'s `Err` return — `reason`
    /// here is supplementary, intended for logs.
    Abort {
        /// Whether the caller should send `DisarmFailsafe` before
        /// dropping the PASE session.
        send_disarm_failsafe: bool,
        /// Pre-rendered description of the failure cause.
        reason: String,
    },
}

/// The response type the state machine expects after an
/// [`Action::Invoke`] or [`Action::ReadAttribute`].
///
/// Passed back into [`super::Commissioner::on_response`] alongside the
/// raw TLV payload so the state machine can validate that the response
/// matches the request without parsing the entire TLV first.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Expectation {
    /// Response to `Action::ReadAttribute` for `BasicCommissioningInfo` +
    /// `RegulatoryConfig` + `CapabilityMinima`.
    CommissioningInfo,
    /// `GeneralCommissioning::ArmFailSafeResponse` (cluster `0x0030`,
    /// response `0x01`).
    ArmFailsafeResponse,
    /// `GeneralCommissioning::SetRegulatoryConfigResponse` (response `0x03`).
    SetRegulatoryConfigResponse,
    /// `OperationalCredentials::CertificateChainResponse` for the PAI.
    PaiCertChainResponse,
    /// `OperationalCredentials::CertificateChainResponse` for the DAC.
    DacCertChainResponse,
    /// `OperationalCredentials::AttestationResponse` (response `0x01`).
    AttestationResponse,
    /// `OperationalCredentials::CSRResponse` (response `0x05`).
    CsrResponse,
    /// Status-only ack for `OperationalCredentials::AddTrustedRootCertificate`.
    AddTrustedRootResponse,
    /// `OperationalCredentials::NOCResponse` (response `0x08`).
    NocResponse,
    /// `GeneralCommissioning::CommissioningCompleteResponse` (response `0x05`).
    CommissioningCompleteResponse,
    /// Response to `Action::ReadAttribute` for
    /// `NetworkCommissioning::FeatureMap` (attribute `0xFFFC`). Caller
    /// delivers the bare u32 attribute value's TLV bytes, not the
    /// Interaction Model `AttributeReportIB` envelope.
    NetworkCommissioningInfo,
    /// `NetworkCommissioning::NetworkConfigResponse` (cluster `0x0031`
    /// response `0x05`) — emitted by `AddOrUpdateWiFiNetwork`.
    NetworkConfigResponse,
    /// `NetworkCommissioning::ConnectNetworkResponse` (response `0x07`).
    ConnectNetworkResponse,
    /// Caller-side signal that CASE establishment failed. Fed into
    /// `on_response(Expectation::CaseFailed, &[])` after
    /// [`Action::EstablishCase`].
    CaseFailed,
}

/// Output of a successful commissioning run. Returned in
/// [`Action::Done`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CommissionedFabric {
    /// The fabric record the device is now a member of (RCAC + IPK +
    /// fabric ID).
    pub fabric: FabricRecord,
    /// Operational node ID the device was assigned on this fabric.
    pub peer_node_id: u64,
    /// Raw SEC1 uncompressed P-256 (65 bytes) — the device's NOC public
    /// key, extracted from the issued NOC.
    pub peer_root_public_key: [u8; 65],
    /// Stage where the run terminated. Always [`Stage::Cleanup`] on
    /// success; useful for logging.
    pub terminated_at: Stage,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoke_action_round_trips_through_clone() {
        let a = Action::Invoke {
            session: SessionContext::Pase,
            endpoint: 0,
            cluster: 0x0030,
            command: 0x00,
            payload: vec![0x15, 0x18],
            expect: Expectation::ArmFailsafeResponse,
        };
        let b = a.clone();
        match (a, b) {
            (
                Action::Invoke {
                    endpoint: e1,
                    cluster: c1,
                    command: cmd1,
                    ..
                },
                Action::Invoke {
                    endpoint: e2,
                    cluster: c2,
                    command: cmd2,
                    ..
                },
            ) => {
                assert_eq!(e1, e2);
                assert_eq!(c1, c2);
                assert_eq!(cmd1, cmd2);
            }
            _ => panic!("clone produced wrong variant"),
        }
    }

    #[test]
    fn expectation_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<Expectation>();
    }

    #[test]
    fn session_context_distinguishes_pase_and_case() {
        assert_ne!(SessionContext::Pase, SessionContext::Case);
    }

    #[test]
    fn abort_reason_carries_string() {
        let a = Action::Abort {
            send_disarm_failsafe: true,
            reason: "synthetic failure".to_string(),
        };
        match a {
            Action::Abort {
                reason,
                send_disarm_failsafe,
            } => {
                assert!(send_disarm_failsafe);
                assert_eq!(reason, "synthetic failure");
            }
            _ => panic!("expected Abort"),
        }
    }
}
