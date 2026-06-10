//! Versioned TLV serialization of [`ControllerState`]. Implemented in M8.1 Tasks 5–6.

use crate::error::Error;
use crate::state::ControllerState;

/// Serialize controller state into an opaque TLV blob.
///
/// # Errors
///
/// Returns [`Error::Snapshot`] (stub — not yet implemented).
pub fn serialize(_state: &ControllerState) -> Result<Vec<u8>, Error> {
    Err(Error::Snapshot("serialize not yet implemented".into()))
}

/// Deserialize a snapshot blob into [`ControllerState`].
///
/// # Errors
///
/// Returns [`Error::Snapshot`] (stub — not yet implemented).
pub fn deserialize(_bytes: &[u8]) -> Result<ControllerState, Error> {
    Err(Error::Snapshot("deserialize not yet implemented".into()))
}
