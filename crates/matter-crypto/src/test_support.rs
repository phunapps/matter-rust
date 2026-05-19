//! Test-only helpers for `matter-crypto`.
//!
//! Available only when the `test-support` Cargo feature is enabled.
//! Production callers must NOT enable this feature — these helpers
//! exist solely to drive the M3.3 matter.js byte-parity verification
//! tests, which need deterministic scalar values matching captured
//! matter.js handshakes.
//!
//! # Design note: why no `FixedBytesRng`
//!
//! `ring::rand::SecureRandom` is a sealed trait — external crates cannot
//! implement it. Rather than wrapping an RNG, these helpers call dedicated
//! `pub(crate)` constructors on `PaseProver`/`PaseVerifier` that accept
//! the pre-decoded scalar bytes directly. This is simpler and more explicit:
//! the caller supplies exactly the values the state machine needs, not a
//! byte stream that the constructor then re-parses.
//!
//! # Scalar validity
//!
//! Every scalar passed to these helpers must be a valid non-zero P-256 scalar
//! (big-endian, < curve order). Passing the zero scalar or a value ≥ the
//! curve order returns `Err(Error::InvalidScalar)`.

use crate::error::Result;
use crate::pase::{PasePbkdfParams, PaseProver, PaseVerifier};

// =============================================================================
// Public helpers
// =============================================================================

/// Construct a [`PaseProver`] (known-params path) with a fixed `x` scalar.
///
/// Skips PBKDF param negotiation. The prover's first outbound message (after
/// calling [`PaseProver::start`]) will be Pake1, not `PBKDFParamRequest`.
///
/// Used to match matter.js's captured handshake values in byte-parity tests.
/// Production code must NOT enable the `test-support` feature.
///
/// # Errors
///
/// - [`crate::Error::PbkdfIterationsTooLow`] if `params.iterations < 1000`.
/// - [`crate::Error::PbkdfSaltLengthInvalid`] if `params.salt.len()` ∉ \[16, 32\].
/// - [`crate::Error::InvalidScalar`] if `x_scalar` is zero or not a valid
///   P-256 scalar (i.e., ≥ curve order).
pub fn prover_with_scalar(
    pin: u32,
    params: PasePbkdfParams,
    x_scalar: [u8; 32],
) -> Result<PaseProver> {
    PaseProver::new_with_known_params_with_scalar(pin, params, x_scalar)
}

/// Construct a [`PaseProver`] (negotiation path) with a fixed `x` scalar
/// AND a fixed `initiator_random`.
///
/// The prover's first outbound message (after calling [`PaseProver::start`])
/// will be `PBKDFParamRequest`, carrying the fixed `initiator_random`.
///
/// Used to match matter.js's captured handshake values in byte-parity tests.
///
/// # Errors
///
/// - [`crate::Error::InvalidScalar`] if `x_scalar` is zero or not a valid
///   P-256 scalar (i.e., ≥ curve order).
pub fn prover_with_scalar_and_random(
    pin: u32,
    x_scalar: [u8; 32],
    initiator_random: [u8; 32],
) -> Result<PaseProver> {
    PaseProver::new_with_negotiation_with_scalar(pin, x_scalar, initiator_random)
}

/// Construct a [`PaseVerifier`] from pre-computed verification values, with
/// a fixed `y` scalar.
///
/// In production a device stores `w0` and `L` at provisioning time (not the
/// PIN). This constructor mirrors [`PaseVerifier::new`] but injects a fixed
/// `y` scalar for deterministic testing.
///
/// # Parameters
///
/// - `w0`: 32-byte big-endian P-256 scalar derived from the PIN.
/// - `l`: 65-byte uncompressed P-256 point `L = w1·P`.
/// - `params`: PBKDF2 parameters used when `w0`/`L` were derived.
/// - `y_scalar`: the fixed 32-byte scalar to use instead of a random one.
///
/// # Errors
///
/// - [`crate::Error::PbkdfIterationsTooLow`] if `params.iterations < 1000`.
/// - [`crate::Error::PbkdfSaltLengthInvalid`] if `params.salt.len()` ∉ \[16, 32\].
/// - [`crate::Error::InvalidScalar`] if `w0` or `y_scalar` is zero or not a
///   valid P-256 scalar.
pub fn verifier_with_scalar(
    w0: [u8; 32],
    l: [u8; 65],
    params: PasePbkdfParams,
    y_scalar: [u8; 32],
) -> Result<PaseVerifier> {
    PaseVerifier::new_with_scalar(w0, l, params, y_scalar)
}

/// Construct a [`PaseVerifier`] from a PIN with a fixed `y` scalar.
///
/// Derives `w0` and `L` from the PIN using PBKDF2, then constructs the
/// verifier with the given fixed scalar. Useful when the test PIN is known
/// but the raw `w0`/`L` bytes are not.
///
/// # Errors
///
/// - [`crate::Error::PbkdfIterationsTooLow`] / [`crate::Error::PbkdfSaltLengthInvalid`]
///   if `params` are out of spec.
/// - [`crate::Error::PinDerivationFailed`] if PBKDF2 fails.
/// - [`crate::Error::InvalidScalar`] if `y_scalar` is zero or not a valid
///   P-256 scalar.
pub fn verifier_with_scalar_from_pin(
    pin: u32,
    params: PasePbkdfParams,
    y_scalar: [u8; 32],
) -> Result<PaseVerifier> {
    PaseVerifier::new_from_pin_with_scalar(pin, params, y_scalar)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pase::PaseMessageKind;

    // ─── Helpers ──────────────────────────────────────────────────────────

    /// A valid P-256 scalar: the value 7 in big-endian (non-zero, < curve order).
    fn valid_scalar() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = 0x07;
        s
    }

    fn test_params() -> PasePbkdfParams {
        PasePbkdfParams {
            iterations: 1_000,
            salt: vec![0x42u8; 16],
        }
    }

    // ─── prover_with_scalar ───────────────────────────────────────────────

    #[test]
    fn prover_with_scalar_constructs_known_params() {
        // After construction with known-params, the prover is in
        // AwaitingStartKnownParams. `expected_inbound()` returns None
        // because the machine is waiting to emit (via start()), not to receive.
        let prover = prover_with_scalar(20_202_021, test_params(), valid_scalar()).unwrap();
        assert!(
            prover.expected_inbound().is_none(),
            "after construction, prover has not yet called start()"
        );
    }

    #[test]
    fn prover_with_scalar_rejects_zero_scalar() {
        let result = prover_with_scalar(20_202_021, test_params(), [0u8; 32]);
        assert!(result.is_err(), "zero scalar must be rejected");
    }

    // ─── prover_with_scalar_and_random ────────────────────────────────────

    #[test]
    fn prover_with_scalar_and_random_constructs_negotiation() {
        let prover = prover_with_scalar_and_random(
            20_202_021,
            valid_scalar(),
            [0xABu8; 32], // fixed initiator_random
        )
        .unwrap();
        // AwaitingStartNegotiation: expected_inbound() is None before start().
        assert!(
            prover.expected_inbound().is_none(),
            "after construction, negotiation prover has not yet called start()"
        );
    }

    #[test]
    fn prover_with_scalar_and_random_rejects_zero_scalar() {
        let result = prover_with_scalar_and_random(20_202_021, [0u8; 32], [0xABu8; 32]);
        assert!(result.is_err(), "zero scalar must be rejected");
    }

    // ─── verifier_with_scalar_from_pin ────────────────────────────────────

    #[test]
    fn verifier_with_scalar_from_pin_constructs() {
        // Exercises both pin derivation and scalar injection.
        let verifier =
            verifier_with_scalar_from_pin(20_202_021, test_params(), valid_scalar()).unwrap();
        // After construction the verifier is in AwaitingFirstMessage.
        assert_eq!(
            verifier.expected_inbound(),
            Some(PaseMessageKind::PbkdfParamRequest),
            "verifier should be awaiting the first inbound message"
        );
    }

    #[test]
    fn verifier_with_scalar_from_pin_rejects_zero_scalar() {
        let result = verifier_with_scalar_from_pin(20_202_021, test_params(), [0u8; 32]);
        assert!(result.is_err(), "zero scalar must be rejected");
    }

    // ─── verifier_with_scalar ─────────────────────────────────────────────

    #[test]
    fn verifier_with_scalar_rejects_zero_w0() {
        // All-zero w0 is not a valid P-256 scalar (zero = identity).
        let result = verifier_with_scalar(
            [0u8; 32],    // zero w0 — invalid
            [0x04u8; 65], // l doesn't matter; w0 validation fires first
            test_params(),
            valid_scalar(),
        );
        assert!(result.is_err(), "zero w0 must be rejected");
    }

    #[test]
    fn verifier_with_scalar_rejects_zero_y() {
        let result = verifier_with_scalar(
            valid_scalar(), // valid w0
            [0x04u8; 65],
            test_params(),
            [0u8; 32], // zero y — invalid
        );
        assert!(result.is_err(), "zero y scalar must be rejected");
    }
}
