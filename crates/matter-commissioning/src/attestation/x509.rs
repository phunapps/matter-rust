//! X.509 DER cert wrappers for the Matter attestation chain
//! (`Dac`, `Pai`, `Paa`).
//!
//! Each wrapper owns its DER bytes plus the few fields the verifier
//! needs (subject VID/PID per role, SPKI). Parsing happens once at
//! construction so the accessors are infallible and cheap.

// Implementation lands in Tasks 6–8.

/// Placeholder. Real implementation lands in T6.
pub struct Dac;

/// Placeholder. Real implementation lands in T7.
pub struct Pai;

/// Placeholder. Real implementation lands in T8.
pub struct Paa;
