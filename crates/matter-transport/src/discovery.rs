//! Sans-IO `Discovery` trait + Matter service-record types.
//!
//! The trait is what embedded callers implement to plug their own mDNS
//! stack into the rest of `matter-transport`. The default mdns-sd
//! adapter implements it over `mdns_sd::ServiceDaemon` when the
//! `mdns-sd` Cargo feature is enabled.
#![cfg_attr(
    feature = "mdns-sd",
    doc = "See [`crate::mdns_sd_discovery::MdnsSdDiscovery`] for that adapter."
)]

use std::collections::HashMap;
use std::net::IpAddr;

use crate::error::Result;

/// What kind of Matter service to publish or query.
///
/// Matter Core Spec §5.4 + §4.3.1 define three DNS-SD service types
/// the controller side interacts with.
///
/// `#[non_exhaustive]`: the spec may define further service types (and we may
/// surface group/border-router records later); marking this avoids a semver
/// break. Downstream `match`es must include a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServiceKind {
    /// `_matterc._udp` — devices in commissioning mode.
    Commissionable,
    /// `_matterd._udp` — commissioner (fabric admin) advertising itself
    /// while a commissioning window is open. Matter spec §5.4.2 requires
    /// commissioners to publish this for the duration of the window.
    Commissioner,
    /// `_matter._tcp` — operational nodes on an existing fabric.
    /// Despite the `_tcp` label (a DNS-SD convention quirk), operational
    /// Matter traffic is still UDP.
    Operational,
}

impl ServiceKind {
    /// DNS-SD service type string (with trailing dot, ready to pass to
    /// most mDNS libraries).
    #[must_use]
    pub const fn service_type(self) -> &'static str {
        match self {
            Self::Commissionable => "_matterc._udp.local.",
            Self::Commissioner => "_matterd._udp.local.",
            Self::Operational => "_matter._tcp.local.",
        }
    }
}

/// One Matter mDNS record — what we publish, what we discover.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MatterService {
    /// DNS instance name (left-most label, e.g. `"DEADBEEFCAFEBABE-0000000000000001"`).
    pub instance_name: String,
    /// Service kind.
    pub kind: ServiceKind,
    /// Resolved IP addresses (may include both IPv4 and IPv6).
    pub addresses: Vec<IpAddr>,
    /// UDP/TCP port.
    pub port: u16,
    /// TXT records (vendor/product IDs, discriminator, etc.).
    pub txt_records: HashMap<String, String>,
}

impl MatterService {
    /// Construct a [`MatterService`] from its mDNS record fields.
    ///
    /// Provided because the struct is `#[non_exhaustive]`: callers in other
    /// crates cannot use a struct literal, so this constructor is the stable
    /// way to build one. Future spec-driven fields will gain defaults here
    /// without breaking existing callers.
    #[must_use]
    pub fn new(
        instance_name: String,
        kind: ServiceKind,
        addresses: Vec<IpAddr>,
        port: u16,
        txt_records: HashMap<String, String>,
    ) -> Self {
        Self {
            instance_name,
            kind,
            addresses,
            port,
            txt_records,
        }
    }
}

/// Opaque handle for an in-progress query. Returned by
/// [`Discovery::query`]; passed back to [`Discovery::poll_results`] and
/// [`Discovery::stop_query`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryHandle(pub u64);

/// What an mDNS adapter must do to publish and query Matter services.
///
/// The default daemon adapter is available when the `mdns-sd` feature
/// is enabled.
#[cfg_attr(
    feature = "mdns-sd",
    doc = "It is implemented by [`crate::mdns_sd_discovery::MdnsSdDiscovery`]."
)]
pub trait Discovery {
    /// Publish a Matter service. Idempotent — re-publishing the same
    /// `(instance_name, kind)` replaces the prior advertisement.
    ///
    /// # Errors
    #[cfg_attr(
        feature = "mdns-sd",
        doc = "- [`Error::Mdns`](crate::error::Error::Mdns) on daemon failure."
    )]
    #[cfg_attr(
        not(feature = "mdns-sd"),
        doc = "- `Error::Mdns` on daemon failure (only present with the `mdns-sd` feature)."
    )]
    fn publish(&mut self, service: &MatterService) -> Result<()>;

    /// Withdraw a previously-published service.
    ///
    /// # Errors
    #[cfg_attr(
        feature = "mdns-sd",
        doc = "- [`Error::Mdns`](crate::error::Error::Mdns) on daemon failure."
    )]
    #[cfg_attr(
        not(feature = "mdns-sd"),
        doc = "- `Error::Mdns` on daemon failure (only present with the `mdns-sd` feature)."
    )]
    fn unpublish(&mut self, instance_name: &str, kind: ServiceKind) -> Result<()>;

    /// Begin a query for services of `kind`. Returns a handle the
    /// caller passes to [`Self::poll_results`] to drain matches as they
    /// arrive.
    ///
    /// # Errors
    #[cfg_attr(
        feature = "mdns-sd",
        doc = "- [`Error::Mdns`](crate::error::Error::Mdns) on daemon failure."
    )]
    #[cfg_attr(
        not(feature = "mdns-sd"),
        doc = "- `Error::Mdns` on daemon failure (only present with the `mdns-sd` feature)."
    )]
    fn query(&mut self, kind: ServiceKind) -> Result<QueryHandle>;

    /// Stop an in-progress query. Idempotent — calling on a stopped or
    /// unknown handle is a no-op.
    fn stop_query(&mut self, handle: QueryHandle);

    /// Drain any services discovered for `handle` since the last call.
    /// Non-blocking. Returns an empty vec if no new services have
    /// arrived. Repeat calls accumulate freshly-resolved services.
    fn poll_results(&mut self, handle: QueryHandle) -> Vec<MatterService>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv6Addr;

    #[test]
    fn service_kind_service_type_strings_exact() {
        assert_eq!(
            ServiceKind::Commissionable.service_type(),
            "_matterc._udp.local.",
        );
        assert_eq!(
            ServiceKind::Commissioner.service_type(),
            "_matterd._udp.local.",
        );
        assert_eq!(
            ServiceKind::Operational.service_type(),
            "_matter._tcp.local.",
        );
    }

    #[test]
    fn service_kind_hash_consistency() {
        let mut set = HashSet::new();
        set.insert(ServiceKind::Commissionable);
        assert!(set.contains(&ServiceKind::Commissionable));
        assert!(!set.contains(&ServiceKind::Operational));
    }

    #[test]
    fn matter_service_roundtrip_equality() {
        let mut txt = HashMap::new();
        txt.insert("VP".to_string(), "65521+32768".to_string());
        txt.insert("D".to_string(), "3840".to_string());
        let svc = MatterService {
            instance_name: "DEADBEEFCAFEBABE-0000000000000001".to_string(),
            kind: ServiceKind::Commissionable,
            addresses: vec![std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)],
            port: 5540,
            txt_records: txt,
        };
        assert_eq!(svc.clone(), svc);
    }

    #[test]
    fn query_handle_eq_hash_consistency() {
        let a = QueryHandle(1);
        let b = QueryHandle(1);
        let c = QueryHandle(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }
}
