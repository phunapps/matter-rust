//! Test-only helpers for `matter-crypto`.
//!
//! Available only when the `test-support` Cargo feature is enabled.
//!
//! M3.1: empty (no helpers needed yet — the math is tested via spec
//! vectors in `kdf.rs` and `spake2plus.rs` directly). M3.2 adds
//! scalar-injecting constructors for `PaseProver` / `PaseVerifier`
//! (used by matter.js byte-parity tests in M3.3).
