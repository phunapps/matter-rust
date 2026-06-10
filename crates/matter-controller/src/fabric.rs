//! Fabric management (create, persist, restore). Implemented in M8.1 Task 7.

use crate::error::Error;
use crate::state::FabricEntry;
use matter_cert::MatterTime;

/// Inputs for creating a new fabric.
#[derive(Debug, Clone)]
pub struct FabricConfig {
    /// Matter fabric identifier (spec §6.2.1).
    pub fabric_id: u64,
    /// RCAC subject DN's `rcac-id` value.
    pub rcac_id: u64,
    /// The stable node ID the controller takes on this fabric.
    pub commissioner_node_id: u64,
    /// `(not_before, not_after)` validity for the RCAC and commissioner NOC.
    pub validity: (MatterTime, MatterTime),
}

/// Create a fabric. Implemented in M8.1 Task 7.
///
/// # Errors
///
/// Returns [`Error::Snapshot`] (stub — not yet implemented).
pub fn create_fabric(
    _cfg: &FabricConfig,
    _rng: &dyn matter_commissioning::NocRng,
) -> Result<FabricEntry, Error> {
    Err(Error::Snapshot("create_fabric not yet implemented".into()))
}
