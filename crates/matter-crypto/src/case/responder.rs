//! Responder-side CASE state machine.
//!
//! Drives the 3-message Sigma1 / Sigma2 / Sigma3 handshake from the
//! responder's perspective. Sans-IO: the caller is responsible for
//! transmitting and receiving bytes; this module only handles the
//! cryptographic state transitions.
//!
//! # Protocol flow (new-session path — Matter Core Spec §4.13.2.4)
//!
//! ```text
//! Initiator                         Responder (us)
//! ─────────────────────────────────────────────────────────
//!   Sigma1  ──────────────────────────────────────────>
//!                                    new() / new_using_rng()
//!                                    handle_sigma1()
//!              <──────────────────── next_message() → Sigma2
//!   Sigma3  ──────────────────────────────────────────>
//!                                    handle_sigma3()
//!              <──────────────────── StatusReport: Success
//!                                    finish() → CaseSessionOutput
//! ```
//!
//! Resumption (`Sigma1` with resumption fields → `Sigma2Resume` / `Sigma3Resume`)
//! lands in M4.2; this module implements only the new-session path.
//!
//! # KDF inputs (pinned from matter.js `CaseServer.ts` + `NodeSession.ts`)
//!
//! ## `DestinationId` verification (§4.13.2.4 step 1)
//!
//! The responder re-computes `DestinationId` and compares it against the
//! `dest_id` field in Sigma1 to determine whether this Sigma1 is addressed to
//! this fabric/node identity:
//!
//! ```text
//! salt = initiatorRandom(32) || rcacPublicKey(65) || fabricId_le8 || nodeId_le8
//! DestinationId = HMAC-SHA256(IPK, salt)
//! ```
//!
//! ## S2K — Sigma2 TBE encryption key
//!
//! ```text
//! sigma2Salt = IPK(16) || responderRandom(32) || responderEphPub(65) || SHA-256(sigma1_bytes)
//! S2K = HKDF(secret=sharedSecret, salt=sigma2Salt, info="Sigma2", len=16)
//! ```
//!
//! ## S3K — Sigma3 TBE decryption key
//!
//! ```text
//! sigma3Salt = IPK(16) || SHA-256(sigma1_bytes || sigma2_bytes)
//! S3K = HKDF(secret=sharedSecret, salt=sigma3Salt, info="Sigma3", len=16)
//! ```
//!
//! ## Session keys (responder assignment)
//!
//! ```text
//! sessionSalt = IPK(16) || SHA-256(sigma1_bytes || sigma2_bytes || sigma3_bytes)
//! keys(48) = HKDF(secret=sharedSecret, salt=sessionSalt, info="SessionKeys", len=48)
//! ```
//!
//! Responder key assignment differs from initiator (`NodeSession.ts`, `isInitiator=false`):
//! ```text
//! decryptKey (i2r) = keys[0..16]   -- responder decrypts what initiator encrypted
//! encryptKey (r2i) = keys[16..32]  -- responder encrypts to initiator
//! attestationChallenge = keys[32..48]
//! ```
//!
//! ## `TBSData2` (what we sign with our NOC key in Sigma2)
//!
//! ```text
//! TlvSignedData = {
//!     1: responderNoc (bytes) = our NOC,
//!     2: responderIcac (bytes, optional) = our ICAC,
//!     3: responderPublicKey (65 bytes) = our ephemeral pub,
//!     4: initiatorPublicKey (65 bytes) = initiator's ephemeral pub,
//! }
//! ```
//!
//! ## `TBSData3` (what we verify with initiator's NOC key from Sigma3)
//!
//! ```text
//! TlvSignedData = {
//!     1: responderNoc (bytes) = initiator's NOC,  ← note: field names from Sigma2 perspective
//!     2: responderIcac (bytes, optional) = initiator's ICAC,
//!     3: responderPublicKey (65 bytes) = initiator's ephemeral pub,
//!     4: initiatorPublicKey (65 bytes) = our ephemeral pub,
//! }
//! ```
//!
//! Pinned from `CaseServer.ts`; matter.js re-uses `TlvSignedData` symmetrically
//! in Sigma3 with the initiator in the "responder" position.

use p256::SecretKey;
use ring::rand::{SecureRandom, SystemRandom};

use matter_cert::{CertificateChain, MatterCertificate, MatterTime, Signature, TrustedRoots};

use crate::case::messages::{Sigma1, Sigma2, Sigma3};
use crate::case::sigma::{
    aead_decrypt, aead_encrypt, compute_dest_id, decode_tbedata3, ecdh_shared_secret,
    encode_tbedata2, encode_tbs_data, generate_ephemeral_keypair, hkdf_derive, transcript_hash,
    AEAD_KEY_LEN, HKDF_INFO_SIGMA2, HKDF_INFO_SIGMA3, NONCE_TBE_DATA2, NONCE_TBE_DATA3,
};
use crate::case::{
    CaseCredentials, CaseMessageKind, CaseSessionKeys, CaseSessionOutput, LocalInfo, PeerInfo,
    ResumptionRecord, Sigma1Outcome,
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

/// Internal states of the responder-side CASE handshake.
///
/// Named for the *next expected* action at each point.
/// `Poisoned` is a sentinel used during `std::mem::replace` transitions;
/// it is never observable to callers (all methods replace it immediately
/// with either the next real state or an error return).
#[derive(Debug)]
enum State {
    /// Initial state: `handle_sigma1()` has not been called yet.
    ///
    /// The ephemeral keypair and responder random are pre-sampled here so
    /// that `handle_sigma1()` cannot fail due to randomness.
    AwaitingSigma1 {
        credentials: CaseCredentials,
        trusted_roots: TrustedRoots,
        eph_secret: SecretKey,
        eph_pub: [u8; 65],
        responder_random: [u8; 32],
    },

    /// `handle_sigma1()` succeeded; the Sigma2 bytes are pre-built.
    /// `next_message()` retrieves them and advances to `AwaitingSigma3`.
    ReadyToSendSigma2 {
        credentials: CaseCredentials,
        trusted_roots: TrustedRoots,
        sigma2_bytes: Vec<u8>,
        sigma1_bytes: Vec<u8>,
        shared_secret: [u8; 32],
        initiator_random: [u8; 32],
        responder_random: [u8; 32],
        initiator_eph_pub: [u8; 65],
        eph_pub: [u8; 65],
        initiator_session_id: u16,
        responder_session_id: u16,
    },

    /// `next_message()` has emitted Sigma2; waiting for the initiator's Sigma3.
    AwaitingSigma3 {
        credentials: CaseCredentials,
        trusted_roots: TrustedRoots,
        sigma1_bytes: Vec<u8>,
        sigma2_bytes: Vec<u8>,
        shared_secret: [u8; 32],
        /// Stored for M4.2 resumption (`Sigma1_Resume` MIC needs this).
        /// Not read in the new-session path implemented here.
        #[allow(dead_code)]
        initiator_random: [u8; 32],
        /// Stored for M4.2 resumption (`Sigma2_Resume` MIC needs this).
        /// Not read in the new-session path implemented here.
        #[allow(dead_code)]
        responder_random: [u8; 32],
        initiator_eph_pub: [u8; 65],
        eph_pub: [u8; 65],
        initiator_session_id: u16,
        responder_session_id: u16,
    },

    /// `handle_sigma3()` succeeded; `finish()` may be called.
    Complete {
        session_keys: CaseSessionKeys,
        peer: PeerInfo,
        local: LocalInfo,
    },

    /// Sentinel during `std::mem::replace` transitions.
    Poisoned,
}

// ---------------------------------------------------------------------------
// CaseResponder
// ---------------------------------------------------------------------------

/// Responder-side CASE state machine (new-session path).
///
/// Handles the Sigma1 / Sigma2 / Sigma3 handshake from the responder's
/// (device's) perspective. Sans-IO: the caller feeds raw bytes in via
/// [`handle_sigma1`][Self::handle_sigma1] and
/// [`handle_sigma3`][Self::handle_sigma3], and reads raw bytes out via
/// [`next_message`][Self::next_message].
///
/// # Construction
///
/// - [`CaseResponder::new`] — production constructor; uses the OS CSPRNG.
/// - `new_using_rng` (crate-internal) — deterministic constructor for tests;
///   accepts an injectable `ring::rand::SecureRandom`.
///
/// # Driving the handshake
///
/// 1. Receive Sigma1 bytes from the peer.
/// 2. Call [`handle_sigma1`][Self::handle_sigma1] with those bytes.
///    - Returns [`Sigma1Outcome::NewSession`] for a fresh session (M4.1).
///    - Returns `Err` if the `dest_id` doesn't match our fabric identity.
/// 3. Call [`next_message`][Self::next_message] → get Sigma2 bytes; send them.
/// 4. Receive Sigma3 bytes from the peer.
/// 5. Call [`handle_sigma3`][Self::handle_sigma3] with those bytes.
/// 6. Send a `StatusReport: Success` to the initiator.
/// 7. Call [`finish`][Self::finish] to retrieve [`CaseSessionOutput`].
///
/// Use [`expected_inbound`][Self::expected_inbound] at any point to query
/// which message the machine is currently waiting to receive.
pub struct CaseResponder {
    state: State,
}

impl CaseResponder {
    // ─── Public constructors ──────────────────────────────────────────────

    /// Construct a responder using the OS CSPRNG.
    ///
    /// Pre-samples the ephemeral keypair and 32-byte responder random so that
    /// [`handle_sigma1`][Self::handle_sigma1] cannot fail due to randomness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EphemeralKeyGenerationFailed`] if the OS RNG fails
    /// (extremely unlikely in practice).
    pub fn new(credentials: CaseCredentials, trusted_roots: TrustedRoots) -> Result<Self> {
        let rng = SystemRandom::new();
        Self::new_using_rng(credentials, trusted_roots, &rng)
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
        rng: &dyn SecureRandom,
    ) -> Result<Self> {
        let (eph_secret, eph_pub) = generate_ephemeral_keypair(rng)?;
        let mut responder_random = [0u8; 32];
        rng.fill(&mut responder_random)
            .map_err(|_| Error::EphemeralKeyGenerationFailed)?;
        Ok(Self {
            state: State::AwaitingSigma1 {
                credentials,
                trusted_roots,
                eph_secret,
                eph_pub,
                responder_random,
            },
        })
    }

    // ─── State inspection ─────────────────────────────────────────────────

    /// Returns the CASE message kind the machine is currently waiting to
    /// receive, or `None` if the machine is in an outbound-only state,
    /// has completed, or has been poisoned.
    pub fn expected_inbound(&self) -> Option<CaseMessageKind> {
        match &self.state {
            State::AwaitingSigma1 { .. } => Some(CaseMessageKind::Sigma1),
            State::AwaitingSigma3 { .. } => Some(CaseMessageKind::Sigma3),
            _ => None,
        }
    }

    // ─── Handshake methods ────────────────────────────────────────────────

    /// Process the inbound Sigma1 message.
    ///
    /// Verifies that the `dest_id` in Sigma1 matches the responder's fabric
    /// identity. If it does, computes the ECDH shared secret, builds and
    /// encrypts `TBEData2`, signs `TBSData2` with our NOC key, encodes the Sigma2
    /// message, and advances to `ReadyToSendSigma2`.
    ///
    /// # M4.1 stub behaviour for resumption
    ///
    /// If Sigma1 carries a `resumption_id`, this method returns
    /// [`Error::UnexpectedCaseMessage`]. Full resumption support lands in M4.2.
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedCaseMessage`] if called from the wrong state, or
    ///   if Sigma1 contains a `resumption_id` (M4.1 stub).
    /// - [`Error::InvalidParameter`] if the `dest_id` in Sigma1 does not match
    ///   our fabric identity, or TLV decode fails.
    /// - [`Error::EphemeralKeyGenerationFailed`] if ECDH or HKDF fails.
    /// - [`Error::SigningFailed`] if our NOC signing step fails.
    /// - [`Error::Codec`] on TLV encoding failure.
    pub fn handle_sigma1(&mut self, bytes: &[u8]) -> Result<Sigma1Outcome> {
        let prev = std::mem::replace(&mut self.state, State::Poisoned);
        match prev {
            State::AwaitingSigma1 {
                credentials,
                trusted_roots,
                eph_secret,
                eph_pub,
                responder_random,
            } => {
                // Decode Sigma1.
                let sigma1 = match Sigma1::decode(bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        // Restore state so the machine isn't poisoned.
                        self.state = State::AwaitingSigma1 {
                            credentials,
                            trusted_roots,
                            eph_secret,
                            eph_pub,
                            responder_random,
                        };
                        return Err(e);
                    }
                };

                // M4.1 stub: reject resumption requests.
                if sigma1.resumption_id.is_some() {
                    self.state = State::AwaitingSigma1 {
                        credentials,
                        trusted_roots,
                        eph_secret,
                        eph_pub,
                        responder_random,
                    };
                    return Err(Error::UnexpectedCaseMessage {
                        expected: CaseMessageKind::Sigma1,
                        got: CaseMessageKind::Sigma2Resume,
                    });
                }

                // Verify dest_id matches our fabric identity.
                let expected_dest_id = compute_dest_id(
                    &credentials.ipk,
                    &credentials.rcac_public_key,
                    credentials.fabric_id,
                    credentials.node_id,
                    &sigma1.initiator_random,
                );
                if expected_dest_id != sigma1.dest_id {
                    self.state = State::AwaitingSigma1 {
                        credentials,
                        trusted_roots,
                        eph_secret,
                        eph_pub,
                        responder_random,
                    };
                    return Err(Error::InvalidParameter);
                }

                // Build Sigma2.
                let (sigma2_bytes, shared_secret) = match build_sigma2(
                    bytes,
                    &sigma1,
                    &credentials,
                    &eph_secret,
                    &eph_pub,
                    &responder_random,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        self.state = State::AwaitingSigma1 {
                            credentials,
                            trusted_roots,
                            eph_secret,
                            eph_pub,
                            responder_random,
                        };
                        return Err(e);
                    }
                };

                let initiator_eph_pub = sigma1.initiator_eph_pub;
                let initiator_random = sigma1.initiator_random;
                let initiator_session_id = sigma1.initiator_session_id;
                let sigma1_bytes = bytes.to_vec();

                self.state = State::ReadyToSendSigma2 {
                    credentials,
                    trusted_roots,
                    sigma2_bytes,
                    sigma1_bytes,
                    shared_secret,
                    initiator_random,
                    responder_random,
                    initiator_eph_pub,
                    eph_pub,
                    initiator_session_id,
                    responder_session_id: 0, // M6 commissioning assigns a real value.
                };

                Ok(Sigma1Outcome::NewSession)
            }
            other => {
                self.state = other;
                Err(Error::UnexpectedCaseMessage {
                    expected: CaseMessageKind::Sigma1,
                    got: CaseMessageKind::Sigma3,
                })
            }
        }
    }

    /// M4.1 stub: resumption acceptance is not yet implemented.
    ///
    /// M4.2 will implement the `Sigma2_Resume` path properly.
    ///
    /// # Errors
    ///
    /// Always returns [`Error::UnexpectedCaseMessage`].
    pub fn accept_resumption(&mut self, _record: ResumptionRecord) -> Result<()> {
        Err(Error::UnexpectedCaseMessage {
            expected: CaseMessageKind::Sigma2,
            got: CaseMessageKind::Sigma2Resume,
        })
    }

    /// M4.1 stub: resumption rejection (no-op for the new-session path).
    ///
    /// M4.2 will route the state machine to the new-session preparation when
    /// the caller calls this after a `ResumptionRequested` outcome.
    ///
    /// # Errors
    ///
    /// Never errors in M4.1.
    pub fn reject_resumption(&mut self) -> Result<()> {
        Ok(())
    }

    /// Retrieve the Sigma2 message bytes and advance to `AwaitingSigma3`.
    ///
    /// Must be called after a successful [`handle_sigma1`][Self::handle_sigma1].
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedCaseMessage`] if called from the wrong state.
    pub fn next_message(&mut self) -> Result<Vec<u8>> {
        let prev = std::mem::replace(&mut self.state, State::Poisoned);
        match prev {
            State::ReadyToSendSigma2 {
                credentials,
                trusted_roots,
                sigma2_bytes,
                sigma1_bytes,
                shared_secret,
                initiator_random,
                responder_random,
                initiator_eph_pub,
                eph_pub,
                initiator_session_id,
                responder_session_id,
            } => {
                self.state = State::AwaitingSigma3 {
                    credentials,
                    trusted_roots,
                    sigma1_bytes,
                    sigma2_bytes: sigma2_bytes.clone(),
                    shared_secret,
                    initiator_random,
                    responder_random,
                    initiator_eph_pub,
                    eph_pub,
                    initiator_session_id,
                    responder_session_id,
                };
                Ok(sigma2_bytes)
            }
            other => {
                self.state = other;
                Err(Error::UnexpectedCaseMessage {
                    expected: CaseMessageKind::Sigma2,
                    got: CaseMessageKind::Sigma1,
                })
            }
        }
    }

    /// Process the inbound Sigma3 message, verify the initiator's credentials,
    /// and derive the final session keys.
    ///
    /// # Sigma3 processing steps
    ///
    /// 1. Derive S3K via HKDF (same salt construction as initiator, mirrored).
    /// 2. AES-128-CCM decrypt the encrypted blob using S3K and the
    ///    `NCASE_Sigma3N` nonce.
    /// 3. Parse `TBEData3` = `{ initiatorNoc, initiatorIcac?, signature }`.
    /// 4. Validate the initiator's NOC chain against `trusted_roots`.
    /// 5. Extract initiator `NodeId` + `FabricId` from NOC subject.
    /// 6. Verify `FabricId` matches our credentials.
    /// 7. Verify the initiator's ECDSA signature over `TBSData3`.
    /// 8. Derive final session keys; assign i2r/r2i with responder convention.
    ///
    /// # Key assignment convention (responder, `isInitiator=false` in matter.js)
    ///
    /// ```text
    /// decryptKey  = keys[0..16]   (responder decrypts initiator traffic = i2r)
    /// encryptKey  = keys[16..32]  (responder encrypts to initiator = r2i)
    /// attestationChallenge = keys[32..48]
    /// ```
    ///
    /// Pinned from `NodeSession.ts`, `isInitiator=false` branch.
    ///
    /// # Errors
    ///
    /// - [`Error::UnexpectedCaseMessage`] if called from the wrong state.
    /// - [`Error::EphemeralKeyGenerationFailed`] if HKDF fails.
    /// - [`Error::EncryptedBlobDecryptionFailed`] if the encrypted blob
    ///   fails AEAD verification.
    /// - [`Error::Codec`] / [`Error::InvalidParameter`] on TLV decode failure.
    /// - [`Error::InvalidPeerNocChain`] if chain validation fails.
    /// - [`Error::FabricIdMismatch`] if the initiator's NOC carries a
    ///   different `FabricId` than our credentials.
    /// - [`Error::PeerSignatureInvalid`] if the initiator's ECDSA signature
    ///   fails.
    pub fn handle_sigma3(&mut self, bytes: &[u8]) -> Result<()> {
        let prev = std::mem::replace(&mut self.state, State::Poisoned);
        match prev {
            State::AwaitingSigma3 {
                credentials,
                trusted_roots,
                sigma1_bytes,
                sigma2_bytes,
                shared_secret,
                initiator_random: _,
                responder_random: _,
                initiator_eph_pub,
                eph_pub,
                initiator_session_id,
                responder_session_id,
            } => {
                let (session_keys, peer, local) = match process_sigma3(
                    bytes,
                    &credentials,
                    &trusted_roots,
                    &shared_secret,
                    &sigma1_bytes,
                    &sigma2_bytes,
                    &initiator_eph_pub,
                    &eph_pub,
                    initiator_session_id,
                    responder_session_id,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        // Poison — the handshake cannot be retried on error.
                        return Err(e);
                    }
                };

                self.state = State::Complete {
                    session_keys,
                    peer,
                    local,
                };
                Ok(())
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
    /// May only be called after [`handle_sigma3`][Self::handle_sigma3] has
    /// completed (i.e., the state machine is in the `Complete` state).
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
// Helper: Sigma2 construction inner logic
// ---------------------------------------------------------------------------

/// Build the Sigma2 message and return `(sigma2_bytes, shared_secret)`.
///
/// Extracted from `CaseResponder::handle_sigma1` to keep the method body
/// within the `clippy::too_many_lines` limit.
///
/// Steps performed:
/// 1. ECDH shared secret from our eph secret + initiator's eph pub.
/// 2. Derive S2K.
/// 3. Build `TBSData2` and sign with our NOC key.
/// 4. Encode `TBEData2` and encrypt with S2K + `NCASE_Sigma2N` nonce.
/// 5. Encode the Sigma2 wire message.
///
/// # Errors
///
/// See `CaseResponder::handle_sigma1` error documentation.
#[allow(clippy::too_many_arguments)]
fn build_sigma2(
    sigma1_bytes: &[u8],
    sigma1: &Sigma1,
    credentials: &CaseCredentials,
    eph_secret: &SecretKey,
    eph_pub: &[u8; 65],
    responder_random: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32])> {
    // Step 1: ECDH shared secret from our eph secret + initiator's eph pub.
    let shared_secret = ecdh_shared_secret(eph_secret, &sigma1.initiator_eph_pub)?;

    // Step 2: Derive S2K.
    // sigma2Salt = IPK(16) || responderRandom(32) || responderEphPub(65) || SHA-256(sigma1)
    let h_sigma1 = transcript_hash(&[sigma1_bytes]);
    let mut sigma2_salt: Vec<u8> = Vec::with_capacity(16 + 32 + 65 + 32);
    sigma2_salt.extend_from_slice(&credentials.ipk);
    sigma2_salt.extend_from_slice(responder_random);
    sigma2_salt.extend_from_slice(eph_pub);
    sigma2_salt.extend_from_slice(&h_sigma1);
    let mut s2k = [0u8; AEAD_KEY_LEN];
    hkdf_derive(&shared_secret, &sigma2_salt, HKDF_INFO_SIGMA2, &mut s2k)?;

    // Step 3: Build TBSData2 and sign with our NOC key.
    // TBSData2 = TlvSignedData { ourNoc, ourIcac?, ourEphPub, initiatorEphPub }
    // Responder's NOC is "responderNoc"; initiator's eph pub is "initiatorPublicKey".
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
    let tbs_data2 = encode_tbs_data(
        &our_noc_tlv,
        our_icac_tlv.as_deref(),
        eph_pub,                   // our eph pub = "responderPublicKey"
        &sigma1.initiator_eph_pub, // initiator eph pub = "initiatorPublicKey"
    )?;
    let our_signature = credentials
        .signer
        .sign_p256_sha256(&tbs_data2)
        .map_err(Error::SigningFailed)?;

    // Step 4: Encode TBEData2, encrypt with S2K.
    // resumptionId is 16 zero bytes in M4.1.
    let resumption_id = [0u8; 16];
    let tbedata2_plaintext = encode_tbedata2(
        &our_noc_tlv,
        our_icac_tlv.as_deref(),
        &our_signature,
        &resumption_id,
    )?;
    let encrypted2 = aead_encrypt(&s2k, NONCE_TBE_DATA2, b"", &tbedata2_plaintext)?;

    // Step 5: Encode Sigma2 wire message.
    let sigma2 = Sigma2 {
        responder_random: *responder_random,
        responder_session_id: 0, // M6 commissioning assigns a real value.
        responder_eph_pub: *eph_pub,
        encrypted: encrypted2,
        responder_session_params: None,
    };
    let sigma2_bytes = sigma2.encode()?;

    Ok((sigma2_bytes, shared_secret))
}

// ---------------------------------------------------------------------------
// Helper: Sigma3 processing inner logic
// ---------------------------------------------------------------------------

/// Execute the full Sigma3 verification + session key derivation.
///
/// Extracted from `CaseResponder::handle_sigma3` to keep that method's
/// line count within the `clippy::too_many_lines` limit.
///
/// Returns `(session_keys, peer, local)` on success.
///
/// # Errors
///
/// See `CaseResponder::handle_sigma3` for the full error taxonomy.
// The 8-step SIGMA-R protocol is intentionally kept as one function for
// auditability: a reviewer must be able to trace every step in sequence
// without jumping across files. The 100-line limit is relaxed here.
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn process_sigma3(
    sigma3_bytes: &[u8],
    credentials: &CaseCredentials,
    trusted_roots: &TrustedRoots,
    shared_secret: &[u8; 32],
    sigma1_bytes: &[u8],
    sigma2_bytes: &[u8],
    initiator_eph_pub: &[u8; 65],
    eph_pub: &[u8; 65],
    initiator_session_id: u16,
    responder_session_id: u16,
) -> Result<(CaseSessionKeys, PeerInfo, LocalInfo)> {
    let sigma3 = Sigma3::decode(sigma3_bytes)?;

    // Step 1: Derive S3K.
    // sigma3Salt = IPK(16) || SHA-256(sigma1 || sigma2)
    let h_s1_s2 = transcript_hash(&[sigma1_bytes, sigma2_bytes]);
    let mut sigma3_salt: Vec<u8> = Vec::with_capacity(16 + 32);
    sigma3_salt.extend_from_slice(&credentials.ipk);
    sigma3_salt.extend_from_slice(&h_s1_s2);
    let mut s3k = [0u8; AEAD_KEY_LEN];
    hkdf_derive(shared_secret, &sigma3_salt, HKDF_INFO_SIGMA3, &mut s3k)?;

    // Step 2: AES-128-CCM decrypt.
    let sigma3_decrypted = aead_decrypt(&s3k, NONCE_TBE_DATA3, b"", &sigma3.encrypted)?;

    // Step 3: Parse TBEData3.
    let peer_tbe = decode_tbedata3(&sigma3_decrypted)?;

    // Step 4: Validate initiator NOC chain against trusted roots.
    // Fixed-time stub (Unix 2023-11-15); Task 8 integration test uses real clock.
    let now = MatterTime::from_unix_secs(1_700_000_000);
    let chain_certs: Vec<MatterCertificate> = match &peer_tbe.peer_icac {
        Some(icac) => vec![peer_tbe.peer_noc.clone(), icac.clone()],
        None => vec![peer_tbe.peer_noc.clone()],
    };
    CertificateChain::new(&chain_certs)
        .validate(trusted_roots, now)
        .map_err(Error::InvalidPeerNocChain)?;

    // Step 5: Extract initiator NodeId + FabricId from NOC subject.
    let peer_dn = peer_tbe.peer_noc.subject();
    let peer_node_id = peer_dn
        .node_id()
        .ok_or(Error::PeerNodeIdMismatch(0, credentials.node_id))?;
    let peer_fabric_id = peer_dn.fabric_id().ok_or(Error::FabricIdMismatch {
        peer: 0,
        local: credentials.fabric_id,
    })?;

    // Step 6: Verify FabricId matches our credentials.
    if peer_fabric_id != credentials.fabric_id {
        return Err(Error::FabricIdMismatch {
            peer: peer_fabric_id,
            local: credentials.fabric_id,
        });
    }

    // Step 7: Verify initiator's ECDSA signature over TBSData3.
    // In Sigma3, the initiator plays the "responder" role in TlvSignedData
    // (field names defined from Sigma2 perspective; re-used symmetrically).
    // Pinned from CaseServer.ts: initiatorEphPub → "responderPublicKey",
    //                             responderEphPub → "initiatorPublicKey".
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
        initiator_eph_pub, // initiator's eph pub = "responderPublicKey" in TBSData3
        eph_pub,           // our eph pub = "initiatorPublicKey" in TBSData3
    )?;
    let peer_sig =
        Signature::from_slice(&peer_tbe.peer_signature).map_err(|_| Error::PeerSignatureInvalid)?;
    peer_tbe
        .peer_noc
        .public_key()
        .verify(&peer_signed_data, &peer_sig)
        .map_err(|_| Error::PeerSignatureInvalid)?;

    // Step 8: Derive final session keys.
    // sessionSalt = IPK(16) || SHA-256(sigma1 || sigma2 || sigma3)
    let h_all = transcript_hash(&[sigma1_bytes, sigma2_bytes, sigma3_bytes]);
    let mut session_salt: Vec<u8> = Vec::with_capacity(16 + 32);
    session_salt.extend_from_slice(&credentials.ipk);
    session_salt.extend_from_slice(&h_all);
    let mut keys_blob = [0u8; 48];
    hkdf_derive(
        shared_secret,
        &session_salt,
        HKDF_INFO_SESSION_KEYS,
        &mut keys_blob,
    )?;

    // Responder key assignment (NodeSession.ts, isInitiator=false):
    //   decryptKey (i2r) = keys[0..16]   — responder decrypts what initiator encrypts
    //   encryptKey (r2i) = keys[16..32]  — responder encrypts to initiator
    //   attestationChallenge = keys[32..48]
    // The key bytes are identical to the initiator's derivation; only the
    // variable-name binding differs (swap which end "encrypts" and which "decrypts").
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
        node_id: peer_node_id,
        fabric_id: peer_fabric_id,
        noc: peer_tbe.peer_noc,
        session_id: initiator_session_id,
    };
    let local = LocalInfo {
        node_id: credentials.node_id,
        fabric_id: credentials.fabric_id,
        session_id: responder_session_id,
    };

    Ok((session_keys, peer, local))
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

    /// `new()` must accept valid credentials without panicking.
    #[test]
    fn new_succeeds_with_valid_credentials() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let _responder = CaseResponder::new(creds, empty_roots()).unwrap();
    }

    // ─── expected_inbound() states ────────────────────────────────────────

    /// Freshly constructed responder must be waiting for Sigma1.
    #[test]
    fn expected_inbound_initially_is_sigma1() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let responder = CaseResponder::new(creds, empty_roots()).unwrap();
        assert_eq!(responder.expected_inbound(), Some(CaseMessageKind::Sigma1));
    }

    /// After `handle_sigma1` and `next_message`, `expected_inbound` is `Sigma3`.
    #[test]
    fn expected_inbound_after_next_message_is_sigma3() {
        use crate::case::messages::Sigma1;
        let ipk = [0xAB; 16];
        let mut rcac_pub = [0u8; 65];
        rcac_pub[0] = 0x04;

        let creds = make_test_credentials(0x1234, 0x5678, ipk, rcac_pub);
        let mut responder = CaseResponder::new(creds, empty_roots()).unwrap();

        // Compute the correct dest_id for this responder.
        let initiator_random = [0x42u8; 32];
        let dest_id = compute_dest_id(&ipk, &rcac_pub, 0x5678, 0x1234, &initiator_random);

        // Build a Sigma1 that addresses this responder.
        let sigma1 = Sigma1 {
            initiator_random,
            initiator_session_id: 1,
            dest_id,
            initiator_eph_pub: {
                let rng = ring::rand::SystemRandom::new();
                let (_, pub_bytes) = generate_ephemeral_keypair(&rng).unwrap();
                pub_bytes
            },
            initiator_session_params: None,
            resumption_id: None,
            initiator_resume_mic: None,
        };
        let sigma1_bytes = sigma1.encode().unwrap();

        let outcome = responder.handle_sigma1(&sigma1_bytes).unwrap();
        assert_eq!(outcome, Sigma1Outcome::NewSession);

        let _ = responder.next_message().unwrap();
        assert_eq!(responder.expected_inbound(), Some(CaseMessageKind::Sigma3));
    }

    // ─── handle_sigma1: dest_id mismatch ──────────────────────────────────

    /// `handle_sigma1` with a wrong `dest_id` must return `InvalidParameter`.
    #[test]
    fn handle_sigma1_unknown_dest_id_returns_invalid_parameter() {
        use crate::case::messages::Sigma1;
        let ipk = [0xAB; 16];
        let rcac_pub = dummy_rcac_pub();
        let creds = make_test_credentials(0x1234, 0x5678, ipk, rcac_pub);
        let mut responder = CaseResponder::new(creds, empty_roots()).unwrap();

        // Build a Sigma1 with a garbage dest_id — it won't match our identity.
        let sigma1 = Sigma1 {
            initiator_random: [0x11; 32],
            initiator_session_id: 1,
            dest_id: [0xFF; 32], // clearly wrong
            initiator_eph_pub: {
                let rng = ring::rand::SystemRandom::new();
                let (_, pub_bytes) = generate_ephemeral_keypair(&rng).unwrap();
                pub_bytes
            },
            initiator_session_params: None,
            resumption_id: None,
            initiator_resume_mic: None,
        };
        let sigma1_bytes = sigma1.encode().unwrap();

        assert!(matches!(
            responder.handle_sigma1(&sigma1_bytes),
            Err(Error::InvalidParameter)
        ));
    }

    // ─── handle_sigma1: resumption M4.1 stub ──────────────────────────────

    /// `handle_sigma1` with a `resumption_id` must return `UnexpectedCaseMessage`
    /// (M4.1 stub behaviour; resumption is not yet supported).
    #[test]
    fn handle_sigma1_with_resumption_id_returns_unexpected_message() {
        use crate::case::messages::Sigma1;
        let ipk = [0xAB; 16];
        let rcac_pub = dummy_rcac_pub();
        let creds = make_test_credentials(0x1234, 0x5678, ipk, rcac_pub);
        let mut responder = CaseResponder::new(creds, empty_roots()).unwrap();

        // Build a Sigma1 with the correct dest_id but also a resumption_id.
        let initiator_random = [0x42u8; 32];
        let dest_id = compute_dest_id(&ipk, &rcac_pub, 0x5678, 0x1234, &initiator_random);

        let sigma1 = Sigma1 {
            initiator_random,
            initiator_session_id: 1,
            dest_id,
            initiator_eph_pub: {
                let rng = ring::rand::SystemRandom::new();
                let (_, pub_bytes) = generate_ephemeral_keypair(&rng).unwrap();
                pub_bytes
            },
            initiator_session_params: None,
            resumption_id: Some([0xCC; 16]), // trigger M4.1 stub
            initiator_resume_mic: None,
        };
        let sigma1_bytes = sigma1.encode().unwrap();

        assert!(matches!(
            responder.handle_sigma1(&sigma1_bytes),
            Err(Error::UnexpectedCaseMessage { .. })
        ));
    }

    // ─── Out-of-order rejection ────────────────────────────────────────────

    /// `next_message` before `handle_sigma1` must return `UnexpectedCaseMessage`.
    #[test]
    fn next_message_before_handle_sigma1_is_rejected() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let mut responder = CaseResponder::new(creds, empty_roots()).unwrap();
        assert!(matches!(
            responder.next_message(),
            Err(Error::UnexpectedCaseMessage { .. })
        ));
    }

    /// `handle_sigma3` before `handle_sigma1` must return `UnexpectedCaseMessage`.
    #[test]
    fn handle_sigma3_before_sigma1_is_rejected() {
        use crate::case::messages::Sigma3;
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let mut responder = CaseResponder::new(creds, empty_roots()).unwrap();

        let dummy_sigma3 = Sigma3 {
            encrypted: vec![0xAA; 80],
        };
        let bytes = dummy_sigma3.encode().unwrap();
        assert!(matches!(
            responder.handle_sigma3(&bytes),
            Err(Error::UnexpectedCaseMessage { .. })
        ));
    }

    // ─── finish() before Complete ──────────────────────────────────────────

    /// `finish()` before any handshake steps returns `HandshakeIncomplete`.
    #[test]
    fn finish_before_complete_returns_handshake_incomplete() {
        let creds = make_test_credentials(0x1234, 0x5678, [0xAB; 16], dummy_rcac_pub());
        let responder = CaseResponder::new(creds, empty_roots()).unwrap();
        assert!(matches!(
            responder.finish(),
            Err(Error::HandshakeIncomplete)
        ));
    }

    // ─── TrustedRoots helper verification ─────────────────────────────────

    /// Ensures the `TrustedRoots` type accepts roots correctly (used by both
    /// initiator and responder tests).
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
