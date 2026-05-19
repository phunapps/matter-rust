//! Matter CASE (Certificate Authenticated Session Establishment) via SIGMA-I.
//!
//! Implementation lands across phases:
//! - M4.1 (current): math + Sigma1/2/3 state machines + new-session wire messages.
//! - M4.2: session resumption (`Sigma2_Resume`, `Sigma3_Resume`).
//! - M4.3: matter.js byte-parity verification + readiness markers.
//!
//! See Matter Core Specification §4.13 and
//! `docs/superpowers/specs/2026-05-19-matter-crypto-case-design.md`.

pub(crate) mod initiator;
pub(crate) mod messages;
pub(crate) mod responder;
pub(crate) mod sigma;
pub(crate) mod signer;

use crate::case::signer::CaseSigner;
use matter_cert::{MatterCertificate, MatterTime};

/// Identifies one of the 5 CASE message types. Used by
/// [`crate::Error::UnexpectedMessage`] and `expected_inbound()` accessors
/// on the state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaseMessageKind {
    /// The first CASE message sent by the initiator (new-session path).
    Sigma1,
    /// The responder's reply to `Sigma1` (new-session path).
    Sigma2,
    /// The initiator's final message completing the handshake (new-session path).
    Sigma3,
    /// Resumption response (M4.2).
    Sigma2Resume,
    /// Resumption finish (M4.2).
    Sigma3Resume,
}

/// Operational identity for a CASE session.
///
/// Packages the things that identify a participant on a fabric:
/// NOC, optional ICAC, signer for the NOC's private key, the
/// claimed `FabricId` + `NodeId`, the fabric-scoped IPK, and
/// the RCAC's public key (needed for `DestinationId` computation).
/// Consumed by both `CaseInitiator::new` and `CaseResponder::new`.
#[derive(Debug)]
pub struct CaseCredentials {
    /// Node Operational Certificate. Issued by this fabric's CA chain.
    pub noc: MatterCertificate,
    /// Optional Intermediate CA Certificate, if NOC was issued by an
    /// intermediate rather than directly by the RCAC.
    pub icac: Option<MatterCertificate>,
    /// Signer for the NOC's private key.
    pub signer: Box<dyn CaseSigner>,
    /// Fabric ID this identity is associated with. Cross-checked against
    /// the `FabricId` attribute in the NOC's subject DN.
    pub fabric_id: u64,
    /// Node ID this identity is associated with. Cross-checked against
    /// the `NodeId` attribute in the NOC's subject DN.
    pub node_id: u64,
    /// 16-byte fabric-scoped Identity Protection Key (IPK).
    ///
    /// Used as the HKDF salt in CASE key derivations (`DestinationId`, S2RK,
    /// S3SK, and attestation-challenge). Provides cross-fabric domain
    /// separation: two fabrics sharing a NOC but using different IPKs cannot
    /// impersonate each other. The IPK is derived during commissioning (M6
    /// fabric storage persists it alongside the NOC).
    ///
    /// Pinned from matter.js: `operationalIdentityProtectionKey` (16 bytes).
    pub ipk: [u8; 16],
    /// 65-byte SEC1-uncompressed public key of this fabric's Root CA (RCAC).
    ///
    /// Required for `DestinationId` computation (Matter Core Spec §4.13.2.4).
    /// The `DestinationId` salt is
    /// `HMAC-SHA256(IPK, initiatorRandom || rcacPublicKey || fabricId_le8 || nodeId_le8)`.
    ///
    /// Pinned from matter.js: `fabric.rootPublicKey` used in
    /// `Fabric.#generateSalt(nodeId, random)`.
    pub rcac_public_key: [u8; 65],
}

/// Output of a successful CASE handshake.
#[derive(Debug, Clone)]
pub struct CaseSessionOutput {
    /// Pure key material for the symmetric cipher (consumed by M5 transport).
    pub keys: CaseSessionKeys,
    /// Peer's identity discovered during the handshake.
    pub peer: PeerInfo,
    /// Our side's identity (mirror; included for symmetry).
    pub local: LocalInfo,
    /// Resumption record for next-time fast-path. `None` if the peer
    /// did not include resumption-supporting `responder_session_params`.
    pub resumption_record: Option<ResumptionRecord>,
}

/// Symmetric session keys derived by a completed CASE handshake.
///
/// Consumed by M5 transport's AES-CCM cipher wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseSessionKeys {
    /// Key for encrypting initiator → responder traffic.
    pub i2r_key: [u8; 16],
    /// Key for encrypting responder → initiator traffic.
    pub r2i_key: [u8; 16],
    /// Challenge used for the attestation step on the operational session.
    pub attestation_challenge: [u8; 16],
}

/// Identity of the peer we just shook hands with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// Peer's Node ID (extracted from peer's NOC subject DN).
    pub node_id: u64,
    /// Peer's Fabric ID (extracted from peer's NOC subject DN).
    pub fabric_id: u64,
    /// Peer's NOC verbatim. Available for cert-pinning callers (ACL
    /// evaluation, fast-path re-binding, etc.).
    pub noc: MatterCertificate,
    /// Peer's session ID for messages sent BACK to it.
    pub session_id: u16,
}

/// Our own identity on the session (mirror of `PeerInfo`, useful for symmetry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInfo {
    /// Our Node ID.
    pub node_id: u64,
    /// Our Fabric ID.
    pub fabric_id: u64,
    /// Our session ID for messages sent TO us.
    pub session_id: u16,
}

/// 16-byte resumption identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResumptionId(pub [u8; 16]);

/// State persisted by the caller after a successful CASE handshake,
/// allowing a future session to skip the full 3-message handshake via
/// `Sigma2_Resume`. Resumption flow lands in M4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumptionRecord {
    /// Identifier the peer sends back in Sigma1 to attempt resumption.
    pub id: ResumptionId,
    /// 16-byte shared secret derived from the original session. Caller
    /// treats this as opaque.
    pub shared_secret: [u8; 16],
    /// Peer's identity at the time the record was created.
    pub peer: PeerInfo,
    /// Optional expiry timestamp. Callers should reject resumption
    /// attempts after this point.
    pub expires_at: Option<MatterTime>,
}

/// Outcome of processing a Sigma1 message.
///
/// On `ResumptionRequested`, the caller looks up the corresponding
/// `ResumptionRecord` in their session store and calls either
/// `accept_resumption(record)` or `reject_resumption()` on the
/// `CaseResponder`. (Resumption flow lands in M4.2.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sigma1Outcome {
    /// Initiator wants a fresh CASE session.
    NewSession,
    /// Initiator wants to resume a previous session by ID.
    ResumptionRequested {
        /// The resumption ID the initiator presented.
        id: ResumptionId,
    },
}
