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
///
/// # Secret hygiene
///
/// Carries the fabric-scoped IPK (a 16-byte secret). The [`Debug`] impl
/// redacts the IPK, and a manual [`Drop`] zeroizes the IPK bytes when the
/// credentials are dropped. We cannot derive [`zeroize::ZeroizeOnDrop`] on the
/// whole struct because several fields (`noc`, `icac`, the boxed `signer`) are
/// not `Zeroize`; the NOC private key inside `signer` is owned and wiped by the
/// signer implementation itself.
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

impl core::fmt::Debug for CaseCredentials {
    /// Redacts the secret `ipk`; prints the remaining (non-secret) fields.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CaseCredentials")
            .field("noc", &self.noc)
            .field("icac", &self.icac)
            .field("signer", &self.signer)
            .field("fabric_id", &self.fabric_id)
            .field("node_id", &self.node_id)
            .field("ipk", &"<redacted>")
            .field("rcac_public_key", &self.rcac_public_key)
            .finish()
    }
}

impl Drop for CaseCredentials {
    /// Wipe the secret IPK from memory on drop. The other fields are either
    /// non-secret or own their own secret material (the boxed signer wipes its
    /// private key in its own `Drop`).
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.ipk.zeroize();
    }
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
///
/// # Secret hygiene
///
/// This type carries live symmetric key material. It implements
/// [`zeroize::ZeroizeOnDrop`] so the key bytes are wiped from memory when the
/// value is dropped, and its [`Debug`] impl redacts every field (printing
/// `CaseSessionKeys { .. }`) so key bytes never reach logs. Equality is
/// intentionally *not* derived: comparing session keys with the variable-time
/// `==` would be a timing side-channel, and no caller needs it (tests compare
/// individual byte-array fields directly).
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct CaseSessionKeys {
    /// Key for encrypting initiator → responder traffic.
    pub i2r_key: [u8; 16],
    /// Key for encrypting responder → initiator traffic.
    pub r2i_key: [u8; 16],
    /// Challenge used for the attestation step on the operational session.
    pub attestation_challenge: [u8; 16],
}

impl core::fmt::Debug for CaseSessionKeys {
    /// Redacts all key material; never prints key bytes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CaseSessionKeys").finish_non_exhaustive()
    }
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
///
/// # Secret hygiene
///
/// Carries the resumption `shared_secret`. Implements
/// [`zeroize::ZeroizeOnDrop`] (only the secret is wiped — the non-secret
/// metadata fields `id`, `peer`, and `expires_at` are `#[zeroize(skip)]`),
/// redacts the secret in its [`Debug`] impl, and does not derive variable-time
/// equality.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct ResumptionRecord {
    /// Identifier the peer sends back in Sigma1 to attempt resumption.
    ///
    /// Skipped from zeroization: a public, non-secret session identifier (it is
    /// sent on the wire in Sigma1). Only `shared_secret` is sensitive.
    #[zeroize(skip)]
    pub id: ResumptionId,
    /// 16-byte shared secret derived from the original session. Caller
    /// treats this as opaque.
    pub shared_secret: [u8; 16],
    /// Peer's identity at the time the record was created.
    ///
    /// Skipped from zeroization: non-secret identity/cert metadata, and
    /// `PeerInfo` is not `Zeroize`.
    #[zeroize(skip)]
    pub peer: PeerInfo,
    /// Optional expiry timestamp. Callers should reject resumption
    /// attempts after this point.
    ///
    /// Skipped from zeroization: non-secret timestamp metadata.
    #[zeroize(skip)]
    pub expires_at: Option<MatterTime>,
}

impl core::fmt::Debug for ResumptionRecord {
    /// Redacts `shared_secret`; the non-secret fields are printed verbatim.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResumptionRecord")
            .field("id", &self.id)
            .field("shared_secret", &"<redacted>")
            .field("peer", &self.peer)
            .field("expires_at", &self.expires_at)
            .finish()
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod secret_hygiene_tests {
    use super::*;
    use matter_cert::test_support::{build_unsigned, TestCertFields};
    use matter_cert::{
        DistinguishedName, DnAttribute, Extensions, MatterTime, PublicKey, Signature,
    };

    /// Compile-time proof that `T: ZeroizeOnDrop`. Instantiating it for each
    /// secret-bearing type fails to compile if the trait is ever removed,
    /// which is the strongest guarantee we can give without observing the
    /// (already-freed) memory at runtime.
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn secret_key_types_are_zeroize_on_drop() {
        assert_zeroize_on_drop::<CaseSessionKeys>();
        assert_zeroize_on_drop::<ResumptionRecord>();
        assert_zeroize_on_drop::<crate::pase::PaseSessionKeys>();
    }

    /// A minimal `MatterCertificate` for building a `PeerInfo`.
    fn dummy_cert() -> MatterCertificate {
        let subject = DistinguishedName::new(vec![
            DnAttribute::FabricId(0x5678),
            DnAttribute::NodeId(0x1234),
        ]);
        let issuer = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);
        build_unsigned(TestCertFields {
            serial: vec![1],
            issuer,
            not_before: MatterTime::from_unix_secs(0),
            not_after: MatterTime::NO_EXPIRY,
            subject,
            public_key: PublicKey::new([0x04u8; 65]).unwrap(),
            extensions: Extensions::default(),
            signature: Signature::new([0u8; 64]),
        })
    }

    #[test]
    fn case_session_keys_debug_redacts_key_bytes() {
        let keys = CaseSessionKeys {
            i2r_key: [0xAA; 16],
            r2i_key: [0xBB; 16],
            attestation_challenge: [0xCC; 16],
        };
        let s = format!("{keys:?}");
        // The redacting Debug must not leak any key byte pattern.
        assert!(!s.contains("aa"), "i2r_key bytes leaked: {s}");
        assert!(!s.contains("bb"), "r2i_key bytes leaked: {s}");
        assert!(!s.contains("cc"), "attestation bytes leaked: {s}");
        assert!(s.contains("CaseSessionKeys"));
    }

    #[test]
    fn resumption_record_debug_redacts_shared_secret() {
        let record = ResumptionRecord {
            id: ResumptionId([0x11; 16]),
            shared_secret: [0xDD; 16],
            peer: PeerInfo {
                node_id: 0x1234,
                fabric_id: 0x5678,
                noc: dummy_cert(),
                session_id: 1,
            },
            expires_at: None,
        };
        let s = format!("{record:?}");
        assert!(!s.contains("dd"), "shared_secret leaked: {s}");
        assert!(s.contains("<redacted>"));
        assert!(s.contains("ResumptionRecord"));
    }

    #[test]
    fn case_credentials_debug_redacts_ipk() {
        use crate::case::signer::RingSigner;
        let (signer, _) = RingSigner::generate().unwrap();
        let creds = CaseCredentials {
            noc: dummy_cert(),
            icac: None,
            signer: Box::new(signer),
            fabric_id: 0x5678,
            node_id: 0x1234,
            ipk: [0xEE; 16],
            rcac_public_key: [0x04; 65],
        };
        let s = format!("{creds:?}");
        assert!(!s.contains("ee"), "ipk bytes leaked: {s}");
        assert!(s.contains("<redacted>"));
        assert!(s.contains("CaseCredentials"));
    }
}
