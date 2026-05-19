# matter-crypto

Matter protocol session-establishment primitives — PASE (Password
Authenticated Session Establishment) via SPAKE2+ and CASE (Certificate
Authenticated Session Establishment) via SIGMA-I. Part of the
[matter-rust](https://github.com/phunapps/matter-rust) workspace.

## Scope

Implements Matter Core Specification §3.10 (PASE). CASE coming in M4.

- Sans-IO state machines (`PaseProver`, `PaseVerifier`) — drive bytes
  through method-per-message-type APIs; caller owns the transport.
- SPAKE2+ math over P-256 with Matter's M and N constants.
- PBKDF2 setup-PIN derivation; HKDF session-key derivation.
- Constant-time confirmation tag comparison via `subtle`.
- Byte-for-byte verified against matter.js for three handshake
  scenarios (negotiation, known-params, max-iterations).

## Status

**Pre-release (`0.1.0-pre`).** PASE feature-complete; CASE TBD in M4.

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

## Cryptographic primitives

This crate never implements crypto primitives. Underlying math:
- [`ring`](https://github.com/briansmith/ring) — SHA-256, HMAC, HKDF,
  PBKDF2, AES-CCM, ECDSA-verify.
- [`p256`](https://crates.io/crates/p256) — P-256 scalar/point
  arithmetic for SPAKE2+ (ring deliberately doesn't expose these).
- [`subtle`](https://crates.io/crates/subtle) — constant-time
  comparison for confirmation tags.

## Cross-verification

PASE messages produced by our `PaseProver` and `PaseVerifier` are
byte-identical to matter.js's output for the same inputs. CI runs
this verification on every PR against three captured handshake
scenarios.

## License

Apache 2.0. See [LICENSE](../../LICENSE).
