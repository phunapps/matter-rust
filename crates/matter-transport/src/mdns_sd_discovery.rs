//! Default mdns-sd-based discovery adapter for Matter. Task 5 of the
//! M5.3 plan fills this in.

#![allow(missing_docs, dead_code, unused_imports, clippy::missing_errors_doc)]

use crate::discovery::{Discovery, MatterService, QueryHandle, ServiceKind};
use crate::error::Result;

pub struct MdnsSdDiscovery {
    _todo: (),
}

impl MdnsSdDiscovery {
    /// Spawn a fresh internal `ServiceDaemon`. Task 5 fills in.
    pub fn new() -> Result<Self> {
        unimplemented!("filled in by Task 5")
    }

    /// Reuse an externally-managed `ServiceDaemon`. Task 5 fills in.
    pub fn with_daemon(_daemon: mdns_sd::ServiceDaemon) -> Self {
        unimplemented!("filled in by Task 5")
    }
}

impl Discovery for MdnsSdDiscovery {
    fn publish(&mut self, _service: &MatterService) -> Result<()> {
        unimplemented!("filled in by Task 5")
    }
    fn unpublish(&mut self, _instance_name: &str, _kind: ServiceKind) -> Result<()> {
        unimplemented!("filled in by Task 5")
    }
    fn query(&mut self, _kind: ServiceKind) -> Result<QueryHandle> {
        unimplemented!("filled in by Task 5")
    }
    fn stop_query(&mut self, _handle: QueryHandle) {
        unimplemented!("filled in by Task 5")
    }
    fn poll_results(&mut self, _handle: QueryHandle) -> Vec<MatterService> {
        unimplemented!("filled in by Task 5")
    }
}
