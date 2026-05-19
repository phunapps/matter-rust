//! Initiator-side CASE state machine.
//!
//! Drives the 3-message Sigma1 / Sigma2 / Sigma3 handshake from the
//! initiator's perspective. Sans-IO: the caller is responsible for
//! transmitting and receiving bytes; this module only handles the
//! cryptographic state transitions.
//!
//! # Protocol flow (new-session path — Matter Core Spec §4.13.2.4)
//!
//! ```text
//! Initiator (us)                    Responder
//! ─────────────────────────────────────────────────────────
//! new() / new_using_rng()
//! start()
//!   → Sigma1  ──────────────────────────────────────────>
//!              <──────────────────────────────── Sigma2
//! handle_sigma2()
//! next_message()
//!   → Sigma3  ──────────────────────────────────────────>
//!              <──────────────────────────────── StatusReport: Success
//! finish() → CaseSessionOutput
//! ```
//!
//! Resumption (`Sigma1` with resumption fields → `Sigma2Resume` / `Sigma3Resume`)
//! lands in M4.2; this module implements only the new-session path.
//!
//! # KDF inputs (pinned from matter.js `CaseClient.ts` + `NodeSession.ts`)
//!
//! ## `DestinationId` (§4.13.2.4 step 1)
//!
//! ```text
//! salt = initiatorRandom(32) || rcacPublicKey(65) || fabricId_le8 || nodeId_le8
//! DestinationId = HMAC-SHA256(IPK, salt)
//! ```
//! Pinned from `Fabric.ts#generateSalt` + `signHmac(IPK, salt)`.
//!
//! ## S2K — Sigma2 TBE decryption key
//!
//! ```text
//! sigma2Salt = IPK(16) || responderRandom(32) || responderEphPub(65) || SHA-256(s1_bytes)
//! S2K = HKDF(secret=sharedSecret, salt=sigma2Salt, info="Sigma2", len=16)
//! ```
//! Pinned from `CaseClient.ts` lines 193–199.
//!
//! ## S3K — Sigma3 TBE encryption key
//!
//! ```text
//! sigma3Salt = IPK(16) || SHA-256(s1_bytes || s2_bytes)
//! S3K = HKDF(secret=sharedSecret, salt=sigma3Salt, info="Sigma3", len=16)
//! ```
//! Pinned from `CaseClient.ts` lines 244–248.
//!
//! ## Session keys
//!
//! ```text
//! sessionSalt = IPK(16) || SHA-256(s1_bytes || s2_bytes || s3_bytes)
//! keys(48) = HKDF(secret=sharedSecret, salt=sessionSalt, info="SessionKeys", len=48)
//! i2r_key = keys[0..16]   (initiator to responder encrypt key)
//! r2i_key = keys[16..32]  (responder to initiator decrypt key)
//! attestation_challenge = keys[32..48]
//! ```
//! Pinned from `NodeSession.ts` lines 61–82 (`isInitiator=true` branch).
//!
//! ## `TBEData2` layout (plaintext after S2K decrypt)
//!
//! ```text
//! TlvEncryptedDataSigma2 = {
//!     1: responderNoc (bytes),
//!     2: responderIcac (bytes, optional),
//!     3: signature (64 bytes),
//!     4: resumptionId (16 bytes),
//! }
//! ```
//!
//! ## `TBSData2` (signed payload verified from peer's NOC key)
//!
//! ```text
//! TlvSignedData = {
//!     1: responderNoc (bytes),
//!     2: responderIcac (bytes, optional),
//!     3: responderPublicKey (65 bytes) = responderEphPub,
//!     4: initiatorPublicKey (65 bytes) = initiatorEphPub,
//! }
//! ```
//! Pinned from `CaseMessages.ts` (`TlvSignedData`).
//!
//! ## `TBEData3` layout (plaintext before S3K encrypt)
//!
//! ```text
//! TlvEncryptedDataSigma3 = {
//!     1: responderNoc (bytes) = our NOC,
//!     2: responderIcac (bytes, optional) = our ICAC,
//!     3: signature (64 bytes),
//! }
//! ```
//!
//! ## `TBSData3` (what we sign with our NOC key)
//!
//! ```text
//! TlvSignedData = {
//!     1: responderNoc (bytes) = our NOC,
//!     2: responderIcac (bytes, optional) = our ICAC,
//!     3: responderPublicKey (65 bytes) = our ephemeral pub,
//!     4: initiatorPublicKey (65 bytes) = peer's ephemeral pub,
//! }
//! ```
//! Note: in Sigma3 the initiator plays the role of "responder" in `TlvSignedData`
//! because the field names in matter.js's `TlvSignedData` were defined from the
//! SIGMA-I Sigma2 perspective; `TlvSignedData` is re-used symmetrically in Sigma3.
//! Pinned from `CaseClient.ts` lines 249–254.

use p256::SecretKey;
use ring::rand::{SecureRandom, SystemRandom};

use matter_cert::{CertificateChain, MatterCertificate, MatterTime, Signature, TrustedRoots};
use matter_codec::{Tag, TlvWriter};

use crate::case::messages::{Sigma1, Sigma2, Sigma3};
use crate::case::sigma::{
    aead_decrypt, aead_encrypt, ecdh_shared_secret, generate_ephemeral_keypair, hkdf_derive,
    transcript_hash, AEAD_KEY_LEN, HKDF_INFO_SIGMA2, HKDF_INFO_SIGMA3, NONCE_TBE_DATA2,
    NONCE_TBE_DATA3,
};
use crate::case::{
    CaseCredentials, CaseMessageKind, CaseSessionKeys, CaseSessionOutput, LocalInfo, PeerInfo,
};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// HKDF info for session key derivation.
// Pinned from matter.js NodeSession.ts line 41:
//   const SESSION_KEYS_INFO = Bytes.fromString("SessionKeys")
// ---------------------------------------------------------------------------
const HKDF_INFO_SESSION_KEYS: &[u8] = b"SessionKeys";

// ---------------------------------------------------------------------------
// State enum
// ---------------------------------------------------------------------------

/// Internal states of the initiator-side CASE handshake.
///
/// Named for the *next expected* action at each point.
/// `Poisoned` is a sentinel used during `std::mem::replace` transitions;
/// it is never observable to callers (all methods replace it immediately
/// with either the next real state or an error return).
#[derive(Debug)]
enum State {
    /// Initial state: `start()` has not been called yet.
    ///
    /// The ephemeral keypair and initiator random are pre-sampled here so
    /// that `start()` cannot fail due to randomness.
    AwaitingStart {
        credentials: CaseCredentials,
        trusted_roots: TrustedRoots,
        peer_node_id: u64,
        peer_fabric_id: u64,
        eph_secret: SecretKey,
        eph_pub: [u8; 65],
        initiator_random: [u8; 32],
        initiator_session_id: u16,
    },

    /// `start()` emitted Sigma1; waiting for the responder's Sigma2.
    AwaitingSigma2 {
        credentials: CaseCredentials,
        trusted_roots: TrustedRoots,
        peer_node_id: u64,
        peer_fabric_id: u64,
        eph_secret: SecretKey,
        eph_pub: [u8; 65],
        /// Stored for M4.2 resumption (`Sigma1_Resume` MIC uses the initiator random).
        /// Not read in the new-session path implemented here.
        #[allow(dead_code)]
        initiator_random: [u8; 32],
        initiator_session_id: u16,
        sigma1_bytes: Vec<u8>,
    },

    /// `handle_sigma2()` has processed Sigma2 and produced Sigma3 + session
    /// keys; `next_message()` will hand off the Sigma3 bytes and move to
    /// `Complete`.
    ReadyToSendSigma3 {
        sigma3_bytes: Vec<u8>,
        session_keys: CaseSessionKeys,
        peer: PeerInfo,
        local: LocalInfo,
    },

    /// `next_message()` has emitted Sigma3; `finish()` may be called.
    Complete {
        session_keys: CaseSessionKeys,
        peer: PeerInfo,
        local: LocalInfo,
    },

    /// Sentinel during `std::mem::replace` transitions.
    Poisoned,
}

// ---------------------------------------------------------------------------
// CaseInitiator
// ---------------------------------------------------------------------------

/// Initiator-side CASE state machine (new-session path).
///
/// Drives the Sigma1 / Sigma2 / Sigma3 handshake from the initiator's
/// (commissioner's) perspective. Sans-IO: the caller feeds raw bytes in via
/// [`handle_sigma2`][Self::handle_sigma2] and reads raw bytes out via
/// [`start`][Self::start] and [`next_message`][Self::next_message].
///
/// # Construction
///
/// - [`CaseInitiator::new`] — production constructor; uses the OS CSPRNG.
/// - `new_using_rng` (crate-internal) — deterministic constructor for tests;
///   accepts an injectable `ring::rand::SecureRandom`.
///
/// # Driving the handshake
///
/// 1. Call [`start`][Self::start] → get Sigma1 bytes; send them.
/// 2. Receive Sigma2 bytes from the peer.
/// 3. Call [`handle_sigma2`][Self::handle_sigma2] with those bytes.
/// 4. Call [`next_message`][Self::next_message] → get Sigma3 bytes; send them.
/// 5. After the peer confirms with a `StatusReport: Success`, call
///    [`finish`][Self::finish] to retrieve [`CaseSessionOutput`].
///
/// Use [`expected_inbound`][Self::expected_inbound] at any point to query
/// which message the machine is currently waiting to receive.
pub struct CaseInitiator {
    state: State,
}

impl CaseInitiator {
    // ─── Public constructors ──────────────────────────────────────────────

    /// Construct an initiator using the OS CSPRNG.
    ///
    /// Pre-samples the ephemeral keypair and 32-byte initiator random so that
    /// [`start`][Self::start] cannot fail due to randomness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EphemeralKeyGenerationFailed`] if the OS RNG fails
    /// (extremely unlikely in practice).
    pub fn new(
        credentials: CaseCredentials,
        trusted_roots: TrustedRoots,
        peer_node_id: u64,
        peer_fabric_id: u64,
    ) -> Result<Self> {
        let rng = SystemRandom::new();
        Self::new_using_rng(
            credentials,
            trusted_roots,
            peer_node_id,
            peer_fabric_id,
            &rng,
        )
    }

    /// Deterministic constructor for testing — accepts an injectable RNG.
    ///
    /// Production code should always use [`new`][Self::new].
    ///
    /// # Errors
    ///
    /// Returns [`Error::EphemeralKeyGenerationFailed`] if the RNG fails.
    pub(crate) fn new_using_rng(
        credentials: CaseCredentials,
        trusted_roots: TrustedRoots,
        peer_node_id: u64,
        peer_fabric_id: u64,
        rng: &dyn SecureRandom,
    ) -> Result<Self> {
        let (eph_secret, eph_pub) = generate_ephemeral_keypair(rng)?;
        let mut initiator_random = [0u8; 32];
        rng.fill(&mut initiator_random)
            .map_err(|_| Error::EphemeralKeyGenerationFailed)?;
        Ok(Self {
            state: State::AwaitingStart {
                credentials,
                trusted_roots,
                peer_node_id,
                peer_fabric_id,
                eph_secret,
                eph_pub,
                initiator_random,
                initiator_session_id: 0, // M6 commissioning assigns a real value.
            },
        })
    }

    // ─── State inspection ─────────────────────────────────────────────────

    /// Returns the CASE message kind the machine is currently waiting to
    /// receive, or `None` if the machine is in an outbound-only state,
    /// has completed, or has been poisoned.
    pub fn expected_inbound(&self) -> Option<CaseMessageKind> {
        match &self.state {
            State::AwaitingSigma2 { .. } => Some(CaseMessageKind::Sigma2),
            _ => None,
        }
    }

    // ─── Handshake methods ────────────────────────────────────────────────

    /// Produce the Sigma1 message bytes and advance to `AwaitingSigma2`.
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedCaseMessage`] if called from the wrong state.
    /// - [`Error::Codec`] on TLV encoding failure.
    pub fn start(&mut self) -> Result<Vec<u8>> {
        let prev = std::mem::replace(&mut self.state, State::Poisoned);
        match prev {
            State::AwaitingStart {
                credentials,
                trusted_roots,
                peer_node_id,
                peer_fabric_id,
                eph_secret,
                eph_pub,
                initiator_random,
                initiator_session_id,
            } => {
                let dest_id = compute_dest_id(
                    &credentials.ipk,
                    &credentials.rcac_public_key,
                    credentials.fabric_id,
                    peer_node_id,
                    &initiator_random,
                );

                let sigma1 = Sigma1 {
                    initiator_random,
                    initiator_session_id,
                    dest_id,
                    initiator_eph_pub: eph_pub,
                    initiator_session_params: None,
                    resumption_id: None,
                    initiator_resume_mic: None,
                };
                let sigma1_bytes = sigma1.encode()?;

                self.state = State::AwaitingSigma2 {
                    credentials,
                    trusted_roots,
                    peer_node_id,
                    peer_fabric_id,
                    eph_secret,
                    eph_pub,
                    initiator_random,
                    initiator_session_id,
                    sigma1_bytes: sigma1_bytes.clone(),
                };
                Ok(sigma1_bytes)
            }
            other => {
                self.state = other;
                Err(Error::UnexpectedCaseMessage {
                    expected: CaseMessageKind::Sigma1,
                    got: CaseMessageKind::Sigma2,
                })
            }
        }
    }

    /// Process the inbound Sigma2 message, verify the peer's credentials,
    /// and produce Sigma3.
    ///
    /// After this call succeeds, call [`next_message`][Self::next_message] to
    /// retrieve the Sigma3 bytes that must be sent to the responder.
    ///
    /// # Sigma2 processing steps
    ///
    /// 1. Parse Sigma2 TLV.
    /// 2. ECDH shared secret from our ephemeral secret + peer's ephemeral
    ///    public key.
    /// 3. Derive S2K via HKDF (see module doc for salt composition).
    /// 4. AES-128-CCM decrypt the encrypted blob using S2K and the
    ///    `NCASE_Sigma2N` nonce.
    /// 5. Parse `TBEData2` = `{ responderNoc, responderIcac?, signature,
    ///    resumptionId }`.
    /// 6. Validate the peer's NOC chain against `trusted_roots`.
    /// 7. Check that the NOC's `NodeId` and `FabricId` match expectations.
    /// 8. Verify the peer's ECDSA signature over `TBSData2`.
    /// 9. Build `TBSData3`, sign with our NOC's private key.
    /// 10. Encode `TBEData3`, encrypt with S3K and `NCASE_Sigma3N` nonce.
    /// 11. Derive the final session keys.
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedCaseMessage`] if called from the wrong state.
    /// - [`Error::Codec`] on TLV decode / encode failure.
    /// - [`Error::InvalidParameter`] if the peer's ephemeral public key is
    ///   not a valid P-256 point.
    /// - [`Error::EncryptedBlobDecryptionFailed`] if the encrypted blob
    ///   fails AEAD verification.
    /// - [`Error::InvalidPeerNocChain`] if chain validation fails.
    /// - [`Error::FabricIdMismatch`] / [`Error::PeerNodeIdMismatch`] if the
    ///   peer's identity doesn't match expectations.
    /// - [`Error::PeerSignatureInvalid`] if the peer's ECDSA signature fails.
    /// - [`Error::SigningFailed`] if our own signing operation fails.
    /// - [`Error::EphemeralKeyGenerationFailed`] on HKDF failure.
    pub fn handle_sigma2(&mut self, bytes: &[u8]) -> Result<()> {
        let prev = std::mem::replace(&mut self.state, State::Poisoned);
        match prev {
            State::AwaitingSigma2 {
                credentials,
                trusted_roots,
                peer_node_id,
                peer_fabric_id,
                eph_secret,
                eph_pub,
                initiator_random: _,
                initiator_session_id,
                sigma1_bytes,
            } => {
                let (sigma3_bytes, session_keys, peer, local) = process_sigma2(
                    bytes,
                    &credentials,
                    &trusted_roots,
                    peer_node_id,
                    peer_fabric_id,
                    &eph_secret,
                    &eph_pub,
                    initiator_session_id,
                    &sigma1_bytes,
                )?;
                self.state = State::ReadyToSendSigma3 {
                    sigma3_bytes,
                    session_keys,
                    peer,
                    local,
                };
                Ok(())
            }
            other => {
                self.state = other;
                Err(Error::UnexpectedCaseMessage {
                    expected: CaseMessageKind::Sigma2,
                    got: CaseMessageKind::Sigma3,
                })
            }
        }
    }

    /// Retrieve the next outbound message (Sigma3) and advance to `Complete`.
    ///
    /// Must be called after a successful [`handle_sigma2`][Self::handle_sigma2].
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedCaseMessage`] if called from the wrong state.
    pub fn next_message(&mut self) -> Result<Vec<u8>> {
        let prev = std::mem::replace(&mut self.state, State::Poisoned);
        match prev {
            State::ReadyToSendSigma3 {
                sigma3_bytes,
                session_keys,
                peer,
                local,
            } => {
                self.state = State::Complete {
                    session_keys,
                    peer,
                    local,
                };
                Ok(sigma3_bytes)
            }
            other => {
                self.state = other;
                Err(Error::UnexpectedCaseMessage {
                    expected: CaseMessageKind::Sigma3,
                    got: CaseMessageKind::Sigma1,
                })
            }
        }
    }

    /// Finalise the session and retrieve the derived [`CaseSessionOutput`].
    ///
    /// May only be called after [`next_message`][Self::next_message] has
    /// emitted Sigma3 (i.e., the state machine is in the `Complete` state).
    ///
    /// # Errors
    ///
    /// - [`Error::HandshakeIncomplete`] if called before all handshake phases
    ///   have completed.
    pub fn finish(self) -> Result<CaseSessionOutput> {
        match self.state {
            State::Complete {
                session_keys,
                peer,
                local,
            } => Ok(CaseSessionOutput {
                keys: session_keys,
                peer,
                local,
                resumption_record: None, // M4.2 populates this.
            }),
            _ => Err(Error::HandshakeIncomplete),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: Sigma2 processing inner logic
// ---------------------------------------------------------------------------

/// Execute the full Sigma2 verification + Sigma3 construction logic.
///
/// Extracted from `CaseInitiator::handle_sigma2` to keep that method's
/// line count within the `clippy::too_many_lines` limit.
///
/// Returns `(sigma3_bytes, session_keys, peer, local)` on success.
///
/// # Errors
///
/// See `CaseInitiator::handle_sigma2` for the full error taxonomy.
// The 10-step SIGMA-I protocol is intentionally kept as one function for
// auditability: a reviewer must be able to trace every step in sequence
// without jumping across files. The 100-line limit is relaxed here.
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn process_sigma2(
    sigma2_bytes: &[u8],
    credentials: &CaseCredentials,
    trusted_roots: &TrustedRoots,
    peer_node_id: u64,
    peer_fabric_id: u64,
    eph_secret: &SecretKey,
    eph_pub: &[u8; 65],
    initiator_session_id: u16,
    sigma1_bytes: &[u8],
) -> Result<(Vec<u8>, CaseSessionKeys, PeerInfo, LocalInfo)> {
    let sigma2 = Sigma2::decode(sigma2_bytes)?;

    // Step 1: ECDH shared secret from our eph secret + peer's eph pub.
    let shared_secret = ecdh_shared_secret(eph_secret, &sigma2.responder_eph_pub)?;

    // Step 2: Derive S2K.
    // sigma2Salt = IPK(16) || responderRandom(32) || responderEphPub(65) || SHA-256(sigma1)
    let h_sigma1 = transcript_hash(&[sigma1_bytes]);
    let mut sigma2_salt: Vec<u8> = Vec::with_capacity(16 + 32 + 65 + 32);
    sigma2_salt.extend_from_slice(&credentials.ipk);
    sigma2_salt.extend_from_slice(&sigma2.responder_random);
    sigma2_salt.extend_from_slice(&sigma2.responder_eph_pub);
    sigma2_salt.extend_from_slice(&h_sigma1);
    let mut s2k = [0u8; AEAD_KEY_LEN];
    hkdf_derive(&shared_secret, &sigma2_salt, HKDF_INFO_SIGMA2, &mut s2k)?;

    // Step 3: AES-128-CCM decrypt.
    let sigma2_decrypted = aead_decrypt(&s2k, NONCE_TBE_DATA2, b"", &sigma2.encrypted)?;

    // Step 4: Parse TBEData2.
    let peer_tbe = decode_tbedata2(&sigma2_decrypted)?;

    // Step 5: Validate peer NOC chain against trusted roots.
    // Fixed-time stub (Unix 2023-11-15); Task 8 integration test uses real clock.
    let now = MatterTime::from_unix_secs(1_700_000_000);
    let chain_certs: Vec<MatterCertificate> = match &peer_tbe.peer_icac {
        Some(icac) => vec![peer_tbe.peer_noc.clone(), icac.clone()],
        None => vec![peer_tbe.peer_noc.clone()],
    };
    CertificateChain::new(&chain_certs)
        .validate(trusted_roots, now)
        .map_err(Error::InvalidPeerNocChain)?;

    // Step 6: Check peer NodeId + FabricId match expectations.
    let peer_dn = peer_tbe.peer_noc.subject();
    let verified_node_id = peer_dn
        .node_id()
        .ok_or(Error::PeerNodeIdMismatch(0, peer_node_id))?;
    let verified_fabric_id = peer_dn.fabric_id().ok_or(Error::FabricIdMismatch {
        peer: 0,
        local: peer_fabric_id,
    })?;
    if verified_node_id != peer_node_id {
        return Err(Error::PeerNodeIdMismatch(verified_node_id, peer_node_id));
    }
    if verified_fabric_id != peer_fabric_id {
        return Err(Error::FabricIdMismatch {
            peer: verified_fabric_id,
            local: peer_fabric_id,
        });
    }

    // Step 7: Verify peer's ECDSA signature over TBSData2.
    // TBSData2 = TlvSignedData { responderNoc, responderIcac?, responderEphPub, initiatorEphPub }
    let peer_noc_tlv = peer_tbe
        .peer_noc
        .to_tlv()
        .map_err(Error::InvalidPeerNocChain)?;
    let peer_icac_tlv: Option<Vec<u8>> = match &peer_tbe.peer_icac {
        Some(icac) => Some(icac.to_tlv().map_err(Error::InvalidPeerNocChain)?),
        None => None,
    };
    let peer_signed_data = encode_tbs_data(
        &peer_noc_tlv,
        peer_icac_tlv.as_deref(),
        &sigma2.responder_eph_pub,
        eph_pub,
    )?;
    let peer_sig =
        Signature::from_slice(&peer_tbe.peer_signature).map_err(|_| Error::PeerSignatureInvalid)?;
    peer_tbe
        .peer_noc
        .public_key()
        .verify(&peer_signed_data, &peer_sig)
        .map_err(|_| Error::PeerSignatureInvalid)?;

    // Step 8: Build TBSData3 and sign with our NOC key.
    // The initiator plays the "responder" role in TlvSignedData because the
    // field names were defined from Sigma2's perspective. (CaseClient.ts lines 249–254)
    let our_noc_tlv = credentials
        .noc
        .to_tlv()
        .map_err(|_| Error::SigningFailed(crate::case::signer::SignerError::Internal))?;
    let our_icac_tlv: Option<Vec<u8>> = match &credentials.icac {
        Some(icac) => Some(
            icac.to_tlv()
                .map_err(|_| Error::SigningFailed(crate::case::signer::SignerError::Internal))?,
        ),
        None => None,
    };
    let our_signed_data = encode_tbs_data(
        &our_noc_tlv,
        our_icac_tlv.as_deref(),
        eph_pub,                   // our eph pub = "responderPublicKey"
        &sigma2.responder_eph_pub, // peer's eph pub = "initiatorPublicKey"
    )?;
    let our_signature = credentials
        .signer
        .sign_p256_sha256(&our_signed_data)
        .map_err(Error::SigningFailed)?;

    // Step 9: Encode TBEData3 and encrypt with S3K.
    // sigma3Salt = IPK(16) || SHA-256(sigma1 || sigma2)
    let h_s1_s2 = transcript_hash(&[sigma1_bytes, sigma2_bytes]);
    let mut sigma3_salt: Vec<u8> = Vec::with_capacity(16 + 32);
    sigma3_salt.extend_from_slice(&credentials.ipk);
    sigma3_salt.extend_from_slice(&h_s1_s2);
    let mut s3k = [0u8; AEAD_KEY_LEN];
    hkdf_derive(&shared_secret, &sigma3_salt, HKDF_INFO_SIGMA3, &mut s3k)?;

    let sigma3_plaintext = encode_tbedata3(&our_noc_tlv, our_icac_tlv.as_deref(), &our_signature)?;
    let encrypted3 = aead_encrypt(&s3k, NONCE_TBE_DATA3, b"", &sigma3_plaintext)?;
    let sigma3_bytes = Sigma3 {
        encrypted: encrypted3,
    }
    .encode()?;

    // Step 10: Derive final session keys.
    // sessionSalt = IPK(16) || SHA-256(sigma1 || sigma2 || sigma3)
    let h_all = transcript_hash(&[sigma1_bytes, sigma2_bytes, &sigma3_bytes]);
    let mut session_salt: Vec<u8> = Vec::with_capacity(16 + 32);
    session_salt.extend_from_slice(&credentials.ipk);
    session_salt.extend_from_slice(&h_all);
    let mut keys_blob = [0u8; 48];
    hkdf_derive(
        &shared_secret,
        &session_salt,
        HKDF_INFO_SESSION_KEYS,
        &mut keys_blob,
    )?;

    // Initiator key assignment (NodeSession.ts lines 75–77, isInitiator=true):
    //   encryptKey (i2r) = keys[0..16]
    //   decryptKey (r2i) = keys[16..32]
    //   attestationChallenge  = keys[32..48]
    let mut i2r_key = [0u8; 16];
    let mut r2i_key = [0u8; 16];
    let mut attestation_challenge = [0u8; 16];
    i2r_key.copy_from_slice(&keys_blob[0..16]);
    r2i_key.copy_from_slice(&keys_blob[16..32]);
    attestation_challenge.copy_from_slice(&keys_blob[32..48]);

    let session_keys = CaseSessionKeys {
        i2r_key,
        r2i_key,
        attestation_challenge,
    };

    let peer = PeerInfo {
        node_id: verified_node_id,
        fabric_id: verified_fabric_id,
        noc: peer_tbe.peer_noc,
        session_id: sigma2.responder_session_id,
    };
    let local = LocalInfo {
        node_id: credentials.node_id,
        fabric_id: credentials.fabric_id,
        session_id: initiator_session_id,
    };

    Ok((sigma3_bytes, session_keys, peer, local))
}

// ---------------------------------------------------------------------------
// Helper: DestinationId
// ---------------------------------------------------------------------------

/// Compute the `DestinationId` for Sigma1.
///
/// Matter Core Spec §4.13.2.4 and matter.js `Fabric.#generateSalt`:
/// ```text
/// salt = initiatorRandom(32) || rcacPublicKey(65) || fabricId_le8 || nodeId_le8
/// DestinationId = HMAC-SHA256(key = IPK, message = salt)
/// ```
///
/// Note the order of inputs matches matter.js exactly:
/// random → rootPublicKey → fabricId → nodeId.
fn compute_dest_id(
    ipk: &[u8; 16],
    rcac_public_key: &[u8; 65],
    fabric_id: u64,
    node_id: u64,
    initiator_random: &[u8; 32],
) -> [u8; 32] {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, ipk);
    // Capacity: 32 (random) + 65 (rootPubKey) + 8 (fabricId) + 8 (nodeId) = 113 bytes.
    let mut salt: Vec<u8> = Vec::with_capacity(113);
    salt.extend_from_slice(initiator_random);
    salt.extend_from_slice(rcac_public_key);
    salt.extend_from_slice(&fabric_id.to_le_bytes());
    salt.extend_from_slice(&node_id.to_le_bytes());
    let tag = hmac::sign(&key, &salt);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

// ---------------------------------------------------------------------------
// Helper: TBSData encode (shared by Sigma2 verify + Sigma3 sign)
// ---------------------------------------------------------------------------

/// Encode a `TlvSignedData` structure for ECDSA signing/verification.
///
/// matter.js `TlvSignedData` (CaseMessages.ts):
/// ```ts
/// TlvSignedData = TlvObject({
///     1: responderNoc (bytes),
///     2: responderIcac (bytes, optional),
///     3: responderPublicKey (65 bytes),
///     4: initiatorPublicKey (65 bytes),
/// })
/// ```
///
/// # Errors
///
/// Propagates [`Error::Codec`] on TLV write failure.
fn encode_tbs_data(
    responder_noc_tlv: &[u8],
    responder_icac_tlv: Option<&[u8]>,
    responder_public_key: &[u8; 65],
    initiator_public_key: &[u8; 65],
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)?;
    w.put_bytes(Tag::Context(1), responder_noc_tlv)?;
    if let Some(icac) = responder_icac_tlv {
        w.put_bytes(Tag::Context(2), icac)?;
    }
    w.put_bytes(Tag::Context(3), responder_public_key)?;
    w.put_bytes(Tag::Context(4), initiator_public_key)?;
    w.end_container()?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Helper: TBEData2 decode
// ---------------------------------------------------------------------------

/// Parsed plaintext of the `encrypted` field in Sigma2.
///
/// Maps to `TlvEncryptedDataSigma2` in matter.js CaseMessages.ts:
/// ```ts
/// {
///     1: responderNoc (bytes),
///     2: responderIcac (bytes, optional),
///     3: signature (64 bytes),
///     4: resumptionId (16 bytes),
/// }
/// ```
struct TbeData2 {
    peer_noc: MatterCertificate,
    peer_icac: Option<MatterCertificate>,
    /// Raw 64-byte r||s ECDSA signature.
    peer_signature: Vec<u8>,
    /// 16-byte resumption ID. Not used in M4.1 (resumption is M4.2).
    #[allow(dead_code)]
    resumption_id: [u8; 16],
}

/// Decode the `TBEData2` plaintext.
///
/// # Errors
///
/// - [`Error::InvalidParameter`] if a required field is absent,
///   the structure is malformed, or a byte-string has the wrong length.
/// - [`Error::Codec`] on TLV decode failure.
/// - [`Error::InvalidPeerNocChain`] if the NOC or ICAC TLV cannot be
///   parsed as a `MatterCertificate`.
fn decode_tbedata2(plaintext: &[u8]) -> Result<TbeData2> {
    use matter_codec::{ContainerKind, Element, Tag as MTag, TlvReader, Value};

    let mut reader = TlvReader::new(plaintext);
    // Outer anonymous structure.
    match reader.next()? {
        Some(Element::ContainerStart {
            tag: MTag::Anonymous,
            kind: ContainerKind::Structure,
        }) => {}
        _ => return Err(Error::InvalidParameter),
    }

    let mut noc_bytes: Option<Vec<u8>> = None;
    let mut icac_bytes: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    let mut resumption_id: Option<[u8; 16]> = None;

    loop {
        match reader.next()? {
            Some(Element::ContainerEnd) => break,

            // Tag 1: responderNoc
            Some(Element::Scalar {
                tag: MTag::Context(1),
                value: Value::Bytes(b),
            }) => {
                noc_bytes = Some(b);
            }

            // Tag 2: responderIcac (optional)
            Some(Element::Scalar {
                tag: MTag::Context(2),
                value: Value::Bytes(b),
            }) => {
                icac_bytes = Some(b);
            }

            // Tag 3: signature (64 bytes)
            Some(Element::Scalar {
                tag: MTag::Context(3),
                value: Value::Bytes(b),
            }) => {
                signature = Some(b);
            }

            // Tag 4: resumptionId (16 bytes)
            Some(Element::Scalar {
                tag: MTag::Context(4),
                value: Value::Bytes(b),
            }) => {
                let arr: [u8; 16] = b.try_into().map_err(|_| Error::InvalidParameter)?;
                resumption_id = Some(arr);
            }

            None | Some(_) => return Err(Error::InvalidParameter),
        }
    }

    let noc_b = noc_bytes.ok_or(Error::InvalidParameter)?;
    let sig = signature.ok_or(Error::InvalidParameter)?;
    let rid = resumption_id.ok_or(Error::InvalidParameter)?;

    let peer_noc = MatterCertificate::from_tlv(&noc_b).map_err(Error::InvalidPeerNocChain)?;
    let peer_icac = match icac_bytes {
        Some(b) => Some(MatterCertificate::from_tlv(&b).map_err(Error::InvalidPeerNocChain)?),
        None => None,
    };

    Ok(TbeData2 {
        peer_noc,
        peer_icac,
        peer_signature: sig,
        resumption_id: rid,
    })
}

// ---------------------------------------------------------------------------
// Helper: TBEData3 encode
// ---------------------------------------------------------------------------

/// Encode the `TBEData3` plaintext (initiator's NOC chain + signature).
///
/// Maps to `TlvEncryptedDataSigma3` in matter.js CaseMessages.ts:
/// ```ts
/// {
///     1: responderNoc (bytes),   -- our NOC TLV
///     2: responderIcac (bytes, optional), -- our ICAC TLV (optional)
///     3: signature (64 bytes),
/// }
/// ```
///
/// # Errors
///
/// Propagates [`Error::Codec`] on TLV write failure.
fn encode_tbedata3(
    our_noc_tlv: &[u8],
    our_icac_tlv: Option<&[u8]>,
    signature: &[u8; 64],
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut w = TlvWriter::new(&mut buf);
    w.start_structure(Tag::Anonymous)?;
    w.put_bytes(Tag::Context(1), our_noc_tlv)?;
    if let Some(icac) = our_icac_tlv {
        w.put_bytes(Tag::Context(2), icac)?;
    }
    w.put_bytes(Tag::Context(3), signature)?;
    w.end_container()?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use crate::case::signer::{CaseSigner, RingSigner};
    use matter_cert::test_support::{build_unsigned, TestCertFields};
    use matter_cert::{
        BasicConstraints, DistinguishedName, DnAttribute, Extensions, MatterTime, TrustAnchor,
        TrustedRoots,
    };

    // ─── Test helpers ─────────────────────────────────────────────────────

    /// Build a minimal `MatterCertificate` suitable for unit tests.
    ///
    /// The cert is not validly signed; its purpose is to let state-machine
    /// tests exercise paths that don't reach chain validation.
    fn make_test_cert(node_id: u64, fabric_id: u64) -> MatterCertificate {
        let (signer, _) = RingSigner::generate().unwrap();
        let pk_bytes = *signer.public_key().as_bytes();
        let pub_key = matter_cert::PublicKey::new(pk_bytes).unwrap();
        let subject = DistinguishedName::new(vec![
            DnAttribute::FabricId(fabric_id),
            DnAttribute::NodeId(node_id),
        ]);
        let issuer = DistinguishedName::new(vec![DnAttribute::RcacId(1)]);
        let extensions = Extensions {
            basic_constraints: Some(BasicConstraints {
                is_ca: false,
                path_len_constraint: None,
            }),
            ..Default::default()
        };
        build_unsigned(TestCertFields {
            serial: vec![1],
            issuer,
            not_before: MatterTime::from_unix_secs(0),
            not_after: MatterTime::NO_EXPIRY,
            subject,
            public_key: pub_key,
            extensions,
            signature: matter_cert::Signature::new([0u8; 64]),
        })
    }

    /// Build a `CaseCredentials` with a fresh `RingSigner` keypair.
    fn make_test_credentials(
        node_id: u64,
        fabric_id: u64,
        ipk: [u8; 16],
        rcac_public_key: [u8; 65],
    ) -> CaseCredentials {
        let (signer, _) = RingSigner::generate().unwrap();
        let noc = make_test_cert(node_id, fabric_id);
        CaseCredentials {
            noc,
            icac: None,
            signer: Box::new(signer),
            fabric_id,
            node_id,
            ipk,
            rcac_public_key,
        }
    }

    /// Build an empty `TrustedRoots` set (used for tests that don't reach
    /// chain validation).
    fn empty_roots() -> TrustedRoots {
        TrustedRoots::new()
    }

    /// A valid-looking RCAC public key (SEC1 uncompressed, prefix 0x04).
    fn dummy_rcac_pub() -> [u8; 65] {
        let mut k = [0u8; 65];
        k[0] = 0x04;
        k
    }

    // ─── Construction ─────────────────────────────────────────────────────

    /// `new()` must accept valid credentials.
    #[test]
    fn new_succeeds_with_valid_credentials() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let _initiator = CaseInitiator::new(creds, empty_roots(), 0x1234, 0x5678).unwrap();
    }

    // ─── start() ──────────────────────────────────────────────────────────

    /// `start()` must return a non-empty byte slice that starts with the
    /// anonymous TLV structure byte (0x15).
    #[test]
    fn start_returns_sigma1_bytes() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let mut initiator = CaseInitiator::new(creds, empty_roots(), 0x1234, 0x5678).unwrap();
        let bytes = initiator.start().unwrap();
        assert!(!bytes.is_empty(), "Sigma1 bytes must be non-empty");
        assert_eq!(bytes[0], 0x15, "anonymous structure must start with 0x15");
    }

    /// After `start()`, `expected_inbound()` must report `Sigma2`.
    #[test]
    fn expected_inbound_after_start_is_sigma2() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let mut initiator = CaseInitiator::new(creds, empty_roots(), 0x1234, 0x5678).unwrap();
        let _ = initiator.start().unwrap();
        assert_eq!(initiator.expected_inbound(), Some(CaseMessageKind::Sigma2));
    }

    /// `start()` must encode a Sigma1 that round-trips through the decoder.
    #[test]
    fn start_produces_valid_sigma1() {
        use crate::case::messages::Sigma1;
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let mut initiator = CaseInitiator::new(creds, empty_roots(), 0x1234, 0x5678).unwrap();
        let bytes = initiator.start().unwrap();
        // Must decode without error.
        let decoded = Sigma1::decode(&bytes).unwrap();
        // dest_id is 32 bytes.
        assert_eq!(decoded.dest_id.len(), 32);
        // initiator_eph_pub starts with 0x04 (SEC1 uncompressed).
        assert_eq!(
            decoded.initiator_eph_pub[0], 0x04,
            "ephemeral pub key must be SEC1 uncompressed"
        );
    }

    // ─── terminal-state guards ────────────────────────────────────────────

    /// `finish()` before the handshake is complete returns `HandshakeIncomplete`.
    #[test]
    fn finish_before_complete_returns_handshake_incomplete() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let initiator = CaseInitiator::new(creds, empty_roots(), 0x1234, 0x5678).unwrap();
        assert!(matches!(
            initiator.finish(),
            Err(Error::HandshakeIncomplete)
        ));
    }

    /// `finish()` called immediately after `start()` returns `HandshakeIncomplete`.
    #[test]
    fn finish_after_start_returns_handshake_incomplete() {
        let creds2 = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let fresh = CaseInitiator::new(creds2, empty_roots(), 0x1234, 0x5678).unwrap();
        // The initiator is in AwaitingStart — finish() must fail.
        assert!(matches!(fresh.finish(), Err(Error::HandshakeIncomplete)));
    }

    // ─── out-of-order rejection ────────────────────────────────────────────

    /// Calling `handle_sigma2` before `start` (still in `AwaitingStart`)
    /// must return `UnexpectedCaseMessage`.
    #[test]
    fn handle_sigma2_before_start_is_rejected() {
        use crate::case::messages::Sigma2;
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let mut initiator = CaseInitiator::new(creds, empty_roots(), 0x1234, 0x5678).unwrap();
        let dummy_sigma2 = Sigma2 {
            responder_random: [0u8; 32],
            responder_session_id: 1,
            responder_eph_pub: [0x04; 65],
            encrypted: vec![0xAA; 80],
            responder_session_params: None,
        };
        let bytes = dummy_sigma2.encode().unwrap();
        assert!(matches!(
            initiator.handle_sigma2(&bytes),
            Err(Error::UnexpectedCaseMessage { .. })
        ));
    }

    /// Calling `next_message` before `handle_sigma2` must return
    /// `UnexpectedCaseMessage`.
    #[test]
    fn next_message_before_handle_sigma2_is_rejected() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let mut initiator = CaseInitiator::new(creds, empty_roots(), 0x1234, 0x5678).unwrap();
        let _ = initiator.start().unwrap();
        // Still in AwaitingSigma2; next_message is not valid here.
        assert!(matches!(
            initiator.next_message(),
            Err(Error::UnexpectedCaseMessage { .. })
        ));
    }

    /// Calling `start()` twice returns `UnexpectedCaseMessage` on the second call.
    #[test]
    fn double_start_is_rejected() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let mut initiator = CaseInitiator::new(creds, empty_roots(), 0x1234, 0x5678).unwrap();
        let _ = initiator.start().unwrap();
        assert!(matches!(
            initiator.start(),
            Err(Error::UnexpectedCaseMessage { .. })
        ));
    }

    // ─── expected_inbound() states ────────────────────────────────────────

    /// Before `start()`, `expected_inbound()` returns `None`.
    #[test]
    fn expected_inbound_before_start_is_none() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let initiator = CaseInitiator::new(creds, empty_roots(), 0x1234, 0x5678).unwrap();
        assert_eq!(initiator.expected_inbound(), None);
    }

    // ─── TrustedRoots with an anchor ──────────────────────────────────────

    /// `TrustedRoots::add` works and produces a non-empty set.
    #[test]
    fn trusted_roots_with_anchor_is_non_empty() {
        let rcac = make_test_cert(0, 0x5678);
        let anchor = TrustAnchor::from_root_cert(&rcac);
        let mut roots = TrustedRoots::new();
        roots.add(anchor);
        assert!(!roots.is_empty());
        assert_eq!(roots.len(), 1);
    }
}
