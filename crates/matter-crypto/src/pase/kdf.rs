//! Key-derivation primitives for PASE.
//!
//! - [`validate_params`]: enforce Matter spec §3.10.3 bounds on
//!   iteration count and salt length.
//! - [`derive_w0_w1`]: PBKDF2-HMAC-SHA256 to derive 80 bytes from the
//!   setup PIN, split into 40-byte w0 and 40-byte w1, then reduced mod
//!   the P-256 curve order q.
//! - [`derive_l`]: `L = w1 · P`, where `P` is the P-256 generator.
//! - [`hkdf_expand`]: thin wrapper around ring's HKDF-Expand used by
//!   `spake2plus.rs` for confirmation keys and session keys.
//!
//! # matter.js cross-reference
//!
//! All design choices below were verified against
//! `@matter/general/src/crypto/Spake2p.ts` (`computeW0W1` / `computeW0L`):
//!
//! - PIN serialisation: **4 little-endian bytes** (`pinWriter.writeUInt32(pin)`).
//! - PBKDF2 output length: **80 bytes** (`CRYPTO_W_SIZE_BYTES * 2` where
//!   `CRYPTO_W_SIZE_BYTES = CRYPTO_GROUP_SIZE_BYTES + 8 = 32 + 8 = 40`).
//! - w0 / w1 split: bytes `[0..40]` and `[40..80]`.
//! - Reduction: `mod(bytesToNumberBE(slice), curve.n)` — big-endian
//!   interpretation, modular reduction mod the P-256 group order n.
//! - `L = Point.BASE.multiply(w1).toBytes(false)` — uncompressed SEC1.
//! - HKDF info strings (for Task 4 / `spake2plus.rs`):
//!   - `"ConfirmationKeys"` → 32-byte `KcAB`, split `KcA`/`KcB`.
//!   - `"SessionKeys"` → 48-byte keys, split into decrypt/encrypt/attestation
//!     (from `@matter/protocol/src/session/NodeSession.ts`).
//!
//! Matter Core Spec §3.10.2, §3.10.3, §A.4.

// All items in this module are consumed by `spake2plus.rs` (Task 4).
// Until that file is populated the compiler sees them as dead code;
// this allow will be removed once Task 4 lands.
#![allow(dead_code)]

use std::num::NonZeroU32;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, Scalar};
use ring::hkdf;
use ring::pbkdf2;

use crate::error::{Error, Result};

/// Length of the PBKDF output before reduction.
///
/// Matter Core Spec §3.10.2: `CRYPTO_W_SIZE_BYTES * 2 = 40 * 2 = 80`.
/// `CRYPTO_W_SIZE_BYTES = CRYPTO_GROUP_SIZE_BYTES + 8 = 32 + 8 = 40`.
const PBKDF_OUTPUT_LEN: usize = 80;

/// Each w0/w1 half is 40 bytes before mod-q reduction.
const W_HALF_LEN: usize = 40;

/// Minimum PBKDF2 iterations per Matter spec §3.10.3.
const PBKDF_MIN_ITERATIONS: u32 = 1_000;

/// Salt length bounds per Matter spec §3.10.3.
const PBKDF_SALT_MIN: usize = 16;
const PBKDF_SALT_MAX: usize = 32;

/// Validate PBKDF parameters per Matter spec §3.10.3.
///
/// Returns [`Error::PbkdfIterationsTooLow`] or [`Error::PbkdfSaltLengthInvalid`]
/// if the constraints are violated.
pub(crate) fn validate_params(iterations: u32, salt: &[u8]) -> Result<()> {
    if iterations < PBKDF_MIN_ITERATIONS {
        return Err(Error::PbkdfIterationsTooLow(iterations));
    }
    if salt.len() < PBKDF_SALT_MIN || salt.len() > PBKDF_SALT_MAX {
        return Err(Error::PbkdfSaltLengthInvalid(salt.len()));
    }
    Ok(())
}

/// Derive the SPAKE2+ verifier scalars from the setup PIN.
///
/// Per Matter spec §3.10.2 (cross-verified against matter.js `computeW0W1`):
///
/// ```text
/// w0 || w1 = PBKDF2-HMAC-SHA256(
///     password = PIN encoded as 4 little-endian bytes,
///     salt     = salt,
///     iter     = iterations,
///     out_len  = 80 bytes,
/// )
/// w0 := bytes[0..40] interpreted as big-endian integer, then mod q
/// w1 := bytes[40..80] interpreted as big-endian integer, then mod q
/// ```
///
/// Each returned scalar is reduced mod the P-256 curve order q.
pub(crate) fn derive_w0_w1(pin: u32, salt: &[u8], iterations: u32) -> Result<(Scalar, Scalar)> {
    validate_params(iterations, salt)?;

    // matter.js: `pinWriter.writeUInt32(pin)` with `Endian.Little`.
    let pin_bytes = pin.to_le_bytes();

    let mut out = [0u8; PBKDF_OUTPUT_LEN];
    // iterations was already validated >= 1000 above, so NonZeroU32::new is safe.
    let iter_nz = NonZeroU32::new(iterations).ok_or(Error::PinDerivationFailed)?;
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iter_nz,
        salt,
        &pin_bytes,
        &mut out,
    );

    let w0 = reduce_40_bytes_mod_q(&out[..W_HALF_LEN])?;
    let w1 = reduce_40_bytes_mod_q(&out[W_HALF_LEN..])?;
    Ok((w0, w1))
}

/// Reduce a 40-byte big-endian buffer to a P-256 scalar mod q.
///
/// Matter spec / matter.js use: `mod(bytesToNumberBE(slice_40), curve.n)`.
/// A 40-byte (320-bit) value is slightly larger than the 256-bit field, so
/// we need 320-bit big-integer arithmetic to do the reduction.
///
/// Strategy:
/// 1. Parse 40 bytes as a [`crypto_bigint::U320`] (big-endian).
/// 2. Pad the P-256 order `n` (32 bytes, 256 bits) to 40 bytes to match width.
/// 3. Compute `rem = input mod n` using crypto-bigint's constant-time division.
/// 4. Extract the low 32 bytes of the 40-byte result (upper 8 bytes are zero
///    because the remainder is < n < 2^256).
/// 5. Wrap in a `Scalar` via [`Reduce<U256>::reduce`], which handles the final
///    Barrett reduction for uniformity.
fn reduce_40_bytes_mod_q(input: &[u8]) -> Result<Scalar> {
    use p256::elliptic_curve::bigint::{Encoding, NonZero, U256};
    use p256::elliptic_curve::ops::Reduce;
    use p256::elliptic_curve::{bigint::ArrayEncoding, Curve};

    // Internal type alias: U320 is available via the crypto-bigint re-export
    // inside elliptic_curve::bigint (which p256 re-exports as
    // `p256::elliptic_curve::bigint`).
    // 40 bytes = 320 bits = 5 × 64-bit limbs.
    type U320 = p256::elliptic_curve::bigint::Uint<5>;

    if input.len() != W_HALF_LEN {
        return Err(Error::PinDerivationFailed);
    }

    // Step 1: parse 40 bytes as big-endian U320.
    let n320 = U320::from_be_slice(input);

    // Step 2: embed the P-256 order (32 bytes, 256 bits) into a U320 by
    // zero-padding the upper 8 bytes.
    // `NistP256::ORDER` is a U256; `Curve` trait brings it into scope.
    let order_u256: U256 = p256::NistP256::ORDER;
    let order_be = order_u256.to_be_byte_array(); // 32-byte generic array
    let mut order_buf = [0u8; 40];
    order_buf[8..].copy_from_slice(&order_be); // top 8 bytes remain 0
    let order_u320 = U320::from_be_slice(&order_buf);

    // Step 3: constant-time modular reduction.
    // NonZero::new returns CtOption; the P-256 order is never zero.
    let order_nz: NonZero<U320> = NonZero::new(order_u320)
        .into_option()
        .ok_or(Error::PinDerivationFailed)?;
    let rem_u320 = n320.rem(&order_nz);

    // Step 4: extract the low 32 bytes from the 40-byte remainder.
    // The result is < n < 2^256, so the upper 8 bytes are always zero.
    // `Encoding::to_be_bytes` is brought into scope above.
    let rem_be: [u8; 40] = rem_u320.to_be_bytes();
    // rem_be[0..8] is always zero; the scalar occupies rem_be[8..40].
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&rem_be[8..]);

    // Step 5: wrap via `Reduce<U256>` for a well-formed scalar.
    // `reduce()` performs Barrett reduction; since the value is already < n,
    // this is effectively a no-op that gives us a typed Scalar.
    let scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&scalar_bytes));
    Ok(scalar)
}

/// Compute `L = w1 · P`, where `P` is the P-256 generator.
///
/// `L` is the device's stored verifier point (SEC1 uncompressed, 65 bytes).
/// In production a device computes this once at provisioning and persists it;
/// the PIN is never stored after provisioning.
///
/// matter.js: `Point.BASE.multiply(w1).toBytes(false)`.
pub(crate) fn derive_l(w1: &Scalar) -> [u8; 65] {
    let l_point = ProjectivePoint::GENERATOR * w1;
    let encoded = l_point.to_affine().to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// Thin wrapper around ring's HKDF-Expand for use by `spake2plus.rs`.
///
/// `prk` is the pseudo-random key (typically derived from the SPAKE2+
/// transcript hash); `info` is the spec-defined info string (e.g.
/// `b"ConfirmationKeys"` or `b"SessionKeys"`); `out` is the destination
/// buffer whose length determines how many bytes are produced.
///
/// Uses HKDF-SHA256. The salt for `extract` is left empty because `prk` is
/// already a proper pseudo-random key in the SPAKE2+ context.
pub(crate) fn hkdf_expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    // ring's HKDF design: Salt::new().extract(ikm) produces a Prk.
    // We pass the prk bytes as the "ikm" with an empty salt so ring treats
    // them as the PRK directly (HKDF-Extract of prk with empty salt is a
    // no-op from a security perspective when prk is already well-distributed).
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk_obj = salt.extract(prk);
    // `ring::hkdf::Prk::expand` borrows the info slice for the lifetime of
    // the returned Okm, so we must keep it in a named binding.
    let info_arr = [info];
    let okm = prk_obj
        .expand(&info_arr, OutLen(out.len()))
        .map_err(|_| Error::PinDerivationFailed)?;
    okm.fill(out).map_err(|_| Error::PinDerivationFailed)?;
    Ok(())
}

/// `KeyType` adapter so we can pass a runtime-determined output length to
/// `ring::hkdf::Prk::expand`. ring requires a type-level bound but accepts
/// any type implementing `KeyType`.
struct OutLen(usize);

impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;

    // ─── validate_params ──────────────────────────────────────────────────────

    #[test]
    fn validate_rejects_iter_below_min() {
        assert!(matches!(
            validate_params(999, &[0u8; 16]),
            Err(Error::PbkdfIterationsTooLow(999))
        ));
    }

    #[test]
    fn validate_rejects_iter_zero() {
        assert!(matches!(
            validate_params(0, &[0u8; 16]),
            Err(Error::PbkdfIterationsTooLow(0))
        ));
    }

    #[test]
    fn validate_rejects_salt_too_short() {
        assert!(matches!(
            validate_params(1_000, &[0u8; 15]),
            Err(Error::PbkdfSaltLengthInvalid(15))
        ));
    }

    #[test]
    fn validate_rejects_salt_too_long() {
        assert!(matches!(
            validate_params(1_000, &[0u8; 33]),
            Err(Error::PbkdfSaltLengthInvalid(33))
        ));
    }

    #[test]
    fn validate_accepts_boundary_values() {
        // Exact minimum values must be accepted.
        validate_params(1_000, &[0u8; 16]).unwrap();
        // Larger values must be accepted.
        validate_params(10_000, &[0u8; 32]).unwrap();
    }

    // ─── derive_w0_w1 ────────────────────────────────────────────────────────

    #[test]
    // w0 / w0b / w1 / w1b are the SPAKE2+ PBKDF output binding names
    // from Matter Core Spec §3.10 (RFC 9383 §3.3). The `b` suffix denotes
    // the verifier-side mirror used in cross-check tests. Renaming would
    // impair verification against the spec.
    #[allow(clippy::similar_names)]
    fn derive_w0_w1_is_deterministic() {
        let salt = [0x42u8; 16];
        let (w0a, w1a) = derive_w0_w1(20_202_021, &salt, 1_000).unwrap();
        let (w0b, w1b) = derive_w0_w1(20_202_021, &salt, 1_000).unwrap();
        assert_eq!(w0a.to_bytes(), w0b.to_bytes());
        assert_eq!(w1a.to_bytes(), w1b.to_bytes());
    }

    #[test]
    // w0 / w0b are the SPAKE2+ PBKDF output binding names from Matter
    // Core Spec §3.10 (RFC 9383 §3.3); the `b` suffix denotes the
    // verifier-side mirror used in cross-check tests.
    #[allow(clippy::similar_names)]
    fn derive_w0_w1_changes_with_pin() {
        let salt = [0x42u8; 16];
        let (w0a, _) = derive_w0_w1(20_202_021, &salt, 1_000).unwrap();
        let (w0b, _) = derive_w0_w1(20_202_022, &salt, 1_000).unwrap();
        assert_ne!(w0a.to_bytes(), w0b.to_bytes());
    }

    #[test]
    // w0 / w0b are the SPAKE2+ PBKDF output binding names from Matter
    // Core Spec §3.10 (RFC 9383 §3.3); the `b` suffix denotes the
    // verifier-side mirror used in cross-check tests.
    #[allow(clippy::similar_names)]
    fn derive_w0_w1_changes_with_salt() {
        let (w0a, _) = derive_w0_w1(20_202_021, &[0x42u8; 16], 1_000).unwrap();
        let (w0b, _) = derive_w0_w1(20_202_021, &[0x43u8; 16], 1_000).unwrap();
        assert_ne!(w0a.to_bytes(), w0b.to_bytes());
    }

    #[test]
    // w0 / w0b are the SPAKE2+ PBKDF output binding names from Matter
    // Core Spec §3.10 (RFC 9383 §3.3); the `b` suffix denotes the
    // verifier-side mirror used in cross-check tests.
    #[allow(clippy::similar_names)]
    fn derive_w0_w1_changes_with_iterations() {
        let salt = [0x42u8; 16];
        let (w0a, _) = derive_w0_w1(20_202_021, &salt, 1_000).unwrap();
        let (w0b, _) = derive_w0_w1(20_202_021, &salt, 2_000).unwrap();
        assert_ne!(w0a.to_bytes(), w0b.to_bytes());
    }

    #[test]
    fn derive_w0_w1_rejects_bad_params() {
        // iterations too low
        assert!(derive_w0_w1(20_202_021, &[0u8; 16], 999).is_err());
        // salt too short
        assert!(derive_w0_w1(20_202_021, &[0u8; 15], 1_000).is_err());
    }

    // ─── derive_l ────────────────────────────────────────────────────────────

    #[test]
    fn derive_l_produces_uncompressed_p256_point() {
        let salt = [0x42u8; 16];
        let (_, w1) = derive_w0_w1(20_202_021, &salt, 1_000).unwrap();
        let l = derive_l(&w1);
        // SEC1 uncompressed points always start with 0x04.
        assert_eq!(l[0], 0x04, "SEC1 uncompressed prefix");
        assert_eq!(l.len(), 65);
    }

    #[test]
    fn derive_l_is_deterministic() {
        let salt = [0x42u8; 16];
        let (_, w1) = derive_w0_w1(20_202_021, &salt, 1_000).unwrap();
        let l1 = derive_l(&w1);
        let l2 = derive_l(&w1);
        assert_eq!(l1, l2);
    }

    #[test]
    // w1 / w1b are the SPAKE2+ PBKDF output binding names from Matter
    // Core Spec §3.10 (RFC 9383 §3.3); the `b` suffix denotes the
    // verifier-side mirror used in cross-check tests.
    #[allow(clippy::similar_names)]
    fn derive_l_changes_with_w1() {
        let (_, w1a) = derive_w0_w1(20_202_021, &[0x42u8; 16], 1_000).unwrap();
        let (_, w1b) = derive_w0_w1(20_202_022, &[0x42u8; 16], 1_000).unwrap();
        let la = derive_l(&w1a);
        let lb = derive_l(&w1b);
        assert_ne!(la, lb);
    }

    // ─── hkdf_expand ─────────────────────────────────────────────────────────

    #[test]
    fn hkdf_expand_is_deterministic() {
        let prk = [0x11u8; 32];
        let info = b"ConfirmationKeys";
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        hkdf_expand(&prk, info, &mut out_a).unwrap();
        hkdf_expand(&prk, info, &mut out_b).unwrap();
        assert_eq!(out_a, out_b);
    }

    #[test]
    fn hkdf_expand_differs_with_info() {
        let prk = [0x11u8; 32];
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        hkdf_expand(&prk, b"ConfirmationKeys", &mut out_a).unwrap();
        hkdf_expand(&prk, b"SessionKeys", &mut out_b).unwrap();
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn hkdf_expand_differs_with_prk() {
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        hkdf_expand(&[0x11u8; 32], b"ConfirmationKeys", &mut out_a).unwrap();
        hkdf_expand(&[0x22u8; 32], b"ConfirmationKeys", &mut out_b).unwrap();
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn hkdf_expand_variable_output_length() {
        let prk = [0x11u8; 32];
        let mut out_16 = [0u8; 16];
        let mut out_48 = [0u8; 48];
        hkdf_expand(&prk, b"SessionKeys", &mut out_16).unwrap();
        hkdf_expand(&prk, b"SessionKeys", &mut out_48).unwrap();
        // The first 16 bytes of a 48-byte expand must equal a standalone 16-byte expand.
        assert_eq!(&out_48[..16], &out_16[..]);
    }
}
