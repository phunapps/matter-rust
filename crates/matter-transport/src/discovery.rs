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
    ///
    /// Values are kept as raw bytes rather than `String`: DNS-SD TXT values
    /// are arbitrary octet strings, and while the Matter-defined keys
    /// (`D`, `CM`, `VP`, `PI`, …) carry ASCII, a lossy UTF-8 decode would
    /// silently corrupt any binary-valued or vendor-specific key. Callers
    /// that expect an ASCII/UTF-8 value decode the bytes themselves (see
    /// [`Self::txt_str`]).
    pub txt_records: HashMap<String, Vec<u8>>,
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
        txt_records: HashMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            instance_name,
            kind,
            addresses,
            port,
            txt_records,
        }
    }

    /// Look up a TXT key and return its value decoded as UTF-8, or `None`
    /// if the key is absent OR the value is not valid UTF-8.
    ///
    /// All Matter-defined TXT keys (discriminator `D`, commissioning mode
    /// `CM`, vendor/product `VP`, pairing instruction `PI`, …) carry ASCII
    /// values, so this is the right accessor for them. Binary or
    /// vendor-specific values that aren't valid UTF-8 are available raw via
    /// [`Self::txt_records`].
    #[must_use]
    pub fn txt_str(&self, key: &str) -> Option<&str> {
        self.txt_records
            .get(key)
            .and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Parse the peer's advertised MRP retransmit parameters — mDNS TXT keys
    /// `SII` (Session Idle Interval), `SAI` (Session Active Interval), and
    /// `SAT` (Session Active Threshold), each a decimal-ASCII millisecond count
    /// (Matter Core Spec §4.3.1.8) — into an [`MrpConfig`](crate::MrpConfig).
    ///
    /// A device advertises these to tell the initiator how patiently to
    /// retransmit to it; a sleepy device advertises large `SII`. Any key that
    /// is absent, non-ASCII, or not a valid integer falls back to the Matter
    /// spec default inside [`MrpConfig::for_peer`](crate::MrpConfig::for_peer),
    /// which also clamps out-of-range values.
    #[must_use]
    pub fn peer_mrp_config(&self) -> crate::mrp::MrpConfig {
        let ms = |key: &str| {
            self.txt_str(key)
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(std::time::Duration::from_millis)
        };
        crate::mrp::MrpConfig::for_peer(ms("SII"), ms("SAI"), ms("SAT"))
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
    fn peer_mrp_config_parses_txt_and_falls_back() {
        use std::time::Duration;
        // A device advertising SII/SAI/SAT (decimal ms) → parsed into MrpConfig.
        let mut txt = HashMap::new();
        txt.insert("SII".to_string(), b"5000".to_vec());
        txt.insert("SAI".to_string(), b"800".to_vec());
        txt.insert("SAT".to_string(), b"6000".to_vec());
        let svc = MatterService::new("N".to_string(), ServiceKind::Operational, vec![], 5540, txt);
        let c = svc.peer_mrp_config();
        assert_eq!(c.initial_idle, Duration::from_secs(5));
        assert_eq!(c.initial_active, Duration::from_millis(800));
        assert_eq!(c.idle_threshold, Duration::from_secs(6));

        // No MRP keys → spec defaults (500/300/4000).
        let bare = MatterService::new(
            "N".to_string(),
            ServiceKind::Operational,
            vec![],
            5540,
            HashMap::new(),
        );
        let d = bare.peer_mrp_config();
        assert_eq!(d.initial_idle, Duration::from_millis(500));
        assert_eq!(d.initial_active, Duration::from_millis(300));
        assert_eq!(d.idle_threshold, Duration::from_secs(4));
    }

    #[test]
    fn matter_service_roundtrip_equality() {
        let mut txt = HashMap::new();
        txt.insert("VP".to_string(), b"65521+32768".to_vec());
        txt.insert("D".to_string(), b"3840".to_vec());
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
    fn txt_values_preserve_binary_bytes_and_parse_ascii() {
        // A binary (non-UTF-8) TXT value must survive verbatim, while an
        // ASCII key like the discriminator still parses cleanly.
        let mut txt = HashMap::new();
        let binary = vec![0x00u8, 0xFF, 0xFE, 0x80, 0x01];
        assert!(
            std::str::from_utf8(&binary).is_err(),
            "test fixture must be non-UTF-8 to be meaningful"
        );
        txt.insert("BIN".to_string(), binary.clone());
        txt.insert("D".to_string(), b"3840".to_vec());

        let svc = MatterService::new(
            "INSTANCE".to_string(),
            ServiceKind::Commissionable,
            vec![std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)],
            5540,
            txt,
        );

        // Binary value round-trips with no corruption.
        assert_eq!(svc.txt_records.get("BIN"), Some(&binary));
        // The non-UTF-8 value yields None from the str accessor (not garbage).
        assert_eq!(svc.txt_str("BIN"), None);
        // ASCII discriminator parses normally.
        assert_eq!(svc.txt_str("D"), Some("3840"));
        assert_eq!(
            svc.txt_str("D").and_then(|d| d.parse::<u16>().ok()),
            Some(3840)
        );
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
