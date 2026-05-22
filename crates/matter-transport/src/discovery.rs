//! Sans-IO `Discovery` trait + service-record types. Task 3 of the M5.3
//! plan fills this in.

#![allow(missing_docs, dead_code, unused_imports, clippy::missing_errors_doc)]

use std::collections::HashMap;
use std::net::IpAddr;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceKind {
    Commissionable,
    Commissioner,
    Operational,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatterService {
    pub instance_name: String,
    pub kind: ServiceKind,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
    pub txt_records: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryHandle(pub u64);

pub trait Discovery {
    fn publish(&mut self, service: &MatterService) -> Result<()>;
    fn unpublish(&mut self, instance_name: &str, kind: ServiceKind) -> Result<()>;
    fn query(&mut self, kind: ServiceKind) -> Result<QueryHandle>;
    fn stop_query(&mut self, handle: QueryHandle);
    fn poll_results(&mut self, handle: QueryHandle) -> Vec<MatterService>;
}
