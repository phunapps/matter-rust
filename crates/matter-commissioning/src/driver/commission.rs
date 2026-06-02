//! The async `commission()` orchestrator (M6.6.4): drive the sans-IO
//! `Commissioner` cursor over the M6.6.2/M6.6.3 driver, end to end.

use std::net::SocketAddr;

use matter_transport::SessionManager;

use crate::driver::datagram::AsyncDatagram;
use crate::driver::error::DriverError;
use crate::CommissionedFabric;
use crate::CommissionerConfig;

/// Inputs for one commissioning run. Borrows the commissioner config pieces
/// (fabric, trust stores, setup payload) for the run's duration.
pub struct DriverConfig<'a> {
    /// The sans-IO commissioner configuration (fabric, trust stores, node ids,
    /// wifi creds, rng, etc.). Built by the caller (M6.6.5 example / M8).
    pub commissioner: CommissionerConfig<'a>,
    /// Already-resolved commissionable device address (loopback/tests supply
    /// this directly; M6.6.5 fills it from `resolve_commissionable`). When
    /// `None`, `commission()` discovers it via mDNS using the setup payload's
    /// discriminator.
    pub commissionable_addr: Option<SocketAddr>,
    /// Device passcode (from the setup payload).
    pub passcode: u32,
}

/// Commission a device end to end, returning the resulting [`CommissionedFabric`].
///
/// # Errors
///
/// Any [`DriverError`] from discovery, PASE, the command loop, CASE, or a
/// commissioning-state-machine `Abort`.
pub async fn commission<T, D>(
    _transport: &T,
    _discovery: &mut D,
    _config: DriverConfig<'_>,
) -> Result<CommissionedFabric, DriverError>
where
    T: AsyncDatagram,
    D: matter_transport::Discovery,
{
    // Filled in across Tasks 2-6.
    let _ = SessionManager::new();
    Err(DriverError::Discovery(
        "commission() not yet implemented".into(),
    ))
}
