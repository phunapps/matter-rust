# matter-crypto

Matter protocol session-establishment primitives — PASE (Password
Authenticated Session Establishment) via SPAKE2+ and CASE (Certificate
Authenticated Session Establishment) via SIGMA-I. Part of the
[matter-rust](https://github.com/phunapps/matter-rust) workspace.

## Scope

### PASE — spec §3.10

- Sans-IO state machines (`PaseProver`, `PaseVerifier`) — drive bytes
  through method-per-message-type APIs; caller owns the transport.
- SPAKE2+ math over P-256 with Matter's M and N constants.
- PBKDF2 setup-PIN derivation; HKDF session-key derivation.
- Constant-time confirmation tag comparison via `subtle`.
- Byte-for-byte verified against matter.js for three handshake
  scenarios (negotiation, known-params, max-iterations).

### CASE — spec §4.13

- Sans-IO `CaseInitiator` / `CaseResponder` state machines.
- SIGMA-I math: ephemeral P-256 ECDH, mutual ECDSA signatures,
  AES-CCM-128 encrypted blobs.
- NOC chain validation via `matter-cert::CertificateChain::validate`.
- Pluggable signing via the `CaseSigner` trait — wire your own
  HSM/TPM/secure-element by implementing one method.
- Session resumption: Sigma1 + Sigma2_Resume fast path. The caller
  drives record lookup via the `Sigma1Outcome` enum (sans-IO purity).
- Byte-for-byte verified against matter.js for the new-session scenario.
  Resumption byte-parity is deferred — see
  [`TODO-1.0.md`](../../TODO-1.0.md).

## Status

**Pre-release (`0.1.0-pre`).** PASE and CASE feature-complete.

This crate has not been externally crypto-reviewed yet. See
[`TODO-1.0.md`](../../TODO-1.0.md) for review tracking before any
crates.io release.

## Minimal example

```rust
use matter_crypto::{PasePbkdfParams, PaseProver, PaseVerifier};

let pin = 20202021_u32;
let params = PasePbkdfParams {
    iterations: 1_000,
    salt: vec![0x42u8; 16],
};

let mut prover = PaseProver::new_with_negotiation(pin)?;
let mut verifier = PaseVerifier::new_from_pin(pin, params)?;

// Drive the 5-message handshake — pseudo-code; caller pipes bytes
// between the two sides over the actual network in production.
let m = prover.start()?;
verifier.handle_pbkdf_request(&m)?;
let m = verifier.next_message()?;
prover.handle_pbkdf_response(&m)?;
let m = prover.next_message()?;
verifier.handle_pake1(&m)?;
let m = verifier.next_message()?;
prover.handle_pake2(&m)?;
let m = prover.next_message()?;
verifier.handle_pake3(&m)?;

let prover_keys = prover.finish()?;
let verifier_keys = verifier.finish()?;
assert_eq!(prover_keys.ke, verifier_keys.ke);
```

## Minimal example — CASE

```rust
use matter_crypto::{
    CaseCredentials, CaseInitiator, CaseResponder, RingSigner, Sigma1Outcome,
};
use matter_cert::TrustedRoots;

// --- Build credentials (caller supplies these) ---
// `noc` and `icac` are MatterCertificate values from matter-cert.
// `signer` holds the NOC private key.
let (signer, _pkcs8) = RingSigner::generate()?;
let rcac_pub: [u8; 65] = *signer.public_key().as_bytes(); // example; real app uses RCAC pub key
let initiator_creds = CaseCredentials {
    noc: my_noc,
    icac: None,
    signer: Box::new(signer),
    fabric_id: 0x1234_5678_9ABC_DEF0,
    node_id: 0xAAAA_BBBB_CCCC_DDDD,
    ipk: my_ipk,
    rcac_public_key: rcac_pub,
};

// --- Drive the 3-message Sigma1/2/3 handshake ---
// (caller pipes bytes across the network in a real deployment)
let mut initiator = CaseInitiator::new(
    initiator_creds, trusted_roots, responder_node_id, fabric_id, initiator_session_id,
)?;
let mut responder = CaseResponder::new(responder_creds, trusted_roots, responder_session_id)?;

let sigma1 = initiator.start()?;
let outcome = responder.handle_sigma1(&sigma1)?;
assert!(matches!(outcome, Sigma1Outcome::NewSession));

let sigma2 = responder.next_message()?;
initiator.handle_sigma2(&sigma2)?;

let sigma3 = initiator.next_message()?;
responder.handle_sigma3(&sigma3)?;

let init_out = initiator.finish()?;
let resp_out = responder.finish()?;
// Both sides derive the same session keys.
assert_eq!(init_out.keys.i2r_key, resp_out.keys.i2r_key);
```

## Cryptographic primitives

This crate never implements crypto primitives. Underlying math:
- [`ring`](https://github.com/briansmith/ring) — SHA-256, HMAC, HKDF,
  PBKDF2, ECDSA-verify.
- [`p256`](https://crates.io/crates/p256) — P-256 scalar/point
  arithmetic for SPAKE2+ (ring deliberately doesn't expose these).
- [`subtle`](https://crates.io/crates/subtle) — constant-time
  comparison for PASE confirmation tags.
- [`aes`](https://crates.io/crates/aes) +
  [`ccm`](https://crates.io/crates/ccm) — AES-CCM-128 for CASE
  encrypted blobs (ring 0.17 does not expose AES-CCM).

## Cross-verification

PASE messages produced by our `PaseProver` and `PaseVerifier` are
byte-identical to matter.js's output for the same inputs. CI runs
this verification on every PR against three captured handshake
scenarios.

CASE new-session messages (Sigma1/2/3) are byte-identical to matter.js's
output for the same inputs. Resumption byte-parity is deferred —
known divergences are documented in [`TODO-1.0.md`](../../TODO-1.0.md).

## License

Apache 2.0. See [LICENSE](../../LICENSE).
