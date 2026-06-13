//! Default mdns-sd-based discovery adapter for Matter.
//!
//! Wraps [`mdns_sd::ServiceDaemon`] (which spawns its own background
//! thread on creation) and translates between its [`ServiceEvent`]
//! stream and our [`MatterService`] shape.
//!
//! [`ServiceEvent`]: mdns_sd::ServiceEvent

use std::collections::HashMap;
use std::net::IpAddr;

use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo, TxtProperty};

use crate::discovery::{Discovery, MatterService, QueryHandle, ServiceKind};
use crate::error::{Error, Result};

impl From<mdns_sd::Error> for Error {
    fn from(e: mdns_sd::Error) -> Self {
        Self::Mdns(e.to_string())
    }
}

/// Internal per-query state.
struct QueryState {
    service_type: &'static str,
    receiver: Receiver<ServiceEvent>,
}

/// Default mDNS discovery adapter for Matter, backed by `mdns-sd`.
///
/// Construct via [`Self::new`] (the 90% path — owns its own daemon)
/// or [`Self::with_daemon`] (advanced: share a daemon across multiple
/// controllers, or inject a pre-configured daemon in tests).
pub struct MdnsSdDiscovery {
    daemon: ServiceDaemon,
    owns_daemon: bool,
    queries: HashMap<QueryHandle, QueryState>,
    next_handle: u64,
}

impl MdnsSdDiscovery {
    /// Spawn a fresh internal [`ServiceDaemon`]. Simplest path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Mdns`] if daemon creation fails (typically when
    /// the host has no mDNS support or port 5353 is unavailable).
    pub fn new() -> Result<Self> {
        let daemon = ServiceDaemon::new()?;
        Ok(Self {
            daemon,
            owns_daemon: true,
            queries: HashMap::new(),
            next_handle: 1,
        })
    }

    /// Reuse an externally-managed [`ServiceDaemon`]. Use this to share
    /// one daemon across multiple Matter controllers, or to inject a
    /// pre-configured daemon in tests.
    #[must_use]
    pub fn with_daemon(daemon: ServiceDaemon) -> Self {
        Self {
            daemon,
            owns_daemon: false,
            queries: HashMap::new(),
            next_handle: 1,
        }
    }

    fn allocate_handle(&mut self) -> QueryHandle {
        let h = QueryHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        if self.next_handle == 0 {
            self.next_handle = 1;
        }
        h
    }

    /// DNS-SD instance fullname for a `(instance_name, kind)` pair.
    fn fullname(instance_name: &str, kind: ServiceKind) -> String {
        format!("{}.{}", instance_name, kind.service_type())
    }
}

impl Drop for MdnsSdDiscovery {
    fn drop(&mut self) {
        if self.owns_daemon {
            let _ = self.daemon.shutdown();
        }
    }
}

impl Discovery for MdnsSdDiscovery {
    fn publish(&mut self, service: &MatterService) -> Result<()> {
        // ServiceInfo::new requires host_name. Synthesize from
        // instance_name (mdns-sd appends .local. automatically).
        let host = format!("{}.local.", service.instance_name);
        let addrs: Vec<IpAddr> = service.addresses.clone();
        // TXT values are raw bytes; build `TxtProperty` entries that carry
        // them verbatim (mdns-sd's `From<(K, V: AsRef<[u8]>)>`) rather than
        // the `HashMap<String, String>` path, which would force a UTF-8
        // value and drop binary-valued keys.
        let props: Vec<TxtProperty> = service
            .txt_records
            .iter()
            .map(|(k, v)| TxtProperty::from((k.clone(), v.clone())))
            .collect();
        let info = ServiceInfo::new(
            service.kind.service_type(),
            &service.instance_name,
            &host,
            &addrs[..],
            service.port,
            props,
        )?;
        self.daemon.register(info)?;
        Ok(())
    }

    fn unpublish(&mut self, instance_name: &str, kind: ServiceKind) -> Result<()> {
        let fullname = Self::fullname(instance_name, kind);
        // unregister returns a Receiver we drop — the daemon completes
        // the unregister asynchronously.
        let _ = self.daemon.unregister(&fullname)?;
        Ok(())
    }

    fn query(&mut self, kind: ServiceKind) -> Result<QueryHandle> {
        let receiver = self.daemon.browse(kind.service_type())?;
        let handle = self.allocate_handle();
        self.queries.insert(
            handle,
            QueryState {
                service_type: kind.service_type(),
                receiver,
            },
        );
        Ok(handle)
    }

    fn stop_query(&mut self, handle: QueryHandle) {
        if let Some(state) = self.queries.remove(&handle) {
            let _ = self.daemon.stop_browse(state.service_type);
        }
        // Unknown handle: no-op.
    }

    fn poll_results(&mut self, handle: QueryHandle) -> Vec<MatterService> {
        let Some(state) = self.queries.get(&handle) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        // Drain pending events without blocking.
        while let Ok(event) = state.receiver.try_recv() {
            if let ServiceEvent::ServiceResolved(info) = event {
                if let Some(svc) = service_info_to_matter(&info) {
                    out.push(svc);
                }
            }
            // Other events (ServiceFound, ServiceRemoved,
            // SearchStarted, SearchStopped, etc.) are intentionally
            // discarded — poll_results only emits usable
            // (address-resolved) services.
        }
        out
    }
}

/// Translate an mdns-sd `ResolvedService` into our `MatterService`.
/// Returns `None` (skipping the record) if:
/// - the service has no resolved addresses (the spec guarantees
///   `ServiceResolved` only fires once at least one address is known, but
///   we double-check defensively);
/// - the service type is not one we recognise;
/// - the `fullname` has no dot, so the leading instance label cannot be
///   split off. A well-formed DNS-SD fullname is
///   `<instance>.<service-type>.local.`, so a dotless name is malformed —
///   we skip it rather than fabricate a service with an empty
///   `instance_name` (which would later fail to commission/resolve).
///
/// `ResolvedService` replaced `ServiceInfo` here in mdns-sd 0.20: the
/// resolver now emits a plain data struct rather than the
/// builder-style cert. Field access shifts from `info.get_*()` to
/// public fields (`info.fullname`, `info.port`, `info.addresses`,
/// `info.ty_domain`, `info.txt_properties`). The `addresses` field
/// also changed to `HashSet<ScopedIp>`; we flatten each entry into
/// `IpAddr` via `ScopedIp::to_ip_addr` since matter-transport doesn't
/// (yet) thread interface scope through.
fn service_info_to_matter(info: &ResolvedService) -> Option<MatterService> {
    let addresses: Vec<IpAddr> = info
        .addresses
        .iter()
        .map(mdns_sd::ScopedIp::to_ip_addr)
        .collect();
    if addresses.is_empty() {
        return None;
    }
    let kind = kind_from_service_type(&info.ty_domain)?;
    // Skip malformed records whose fullname has no instance label (see the
    // helper). Surfacing as `None` is the adapter's "skip this record" path.
    let instance_name = instance_name_from_fullname(&info.fullname)?;
    let txt = txt_properties_to_records(&info.txt_properties);
    Some(MatterService {
        instance_name,
        kind,
        addresses,
        port: info.port,
        txt_records: txt,
    })
}

/// Split the leading DNS-SD instance label off a service fullname.
///
/// A well-formed fullname is `<instance>.<service-type>.local.`, so the
/// instance label is everything before the first dot. Returns `None` when
/// the fullname has no dot (cannot be split) or the leading label is empty
/// — both malformed — so the caller skips the record rather than
/// fabricating a service with an empty `instance_name`.
fn instance_name_from_fullname(fullname: &str) -> Option<String> {
    match fullname.split_once('.') {
        Some((instance, _rest)) if !instance.is_empty() => Some(instance.to_string()),
        _ => None,
    }
}

/// Translate mdns-sd `TxtProperties` into our raw-byte TXT map.
///
/// DNS-SD TXT values are arbitrary octet strings (RFC 6763 §6.5); we keep
/// them as `Vec<u8>` rather than lossily UTF-8-decoding, so a binary-valued
/// or vendor-specific Matter key is preserved byte-for-byte. A value-less
/// boolean key maps to an empty value.
fn txt_properties_to_records(props: &mdns_sd::TxtProperties) -> HashMap<String, Vec<u8>> {
    let mut txt = HashMap::new();
    for prop in props.iter() {
        txt.insert(
            prop.key().to_string(),
            prop.val().map(<[u8]>::to_vec).unwrap_or_default(),
        );
    }
    txt
}

fn kind_from_service_type(service_type: &str) -> Option<ServiceKind> {
    match service_type {
        "_matterc._udp.local." => Some(ServiceKind::Commissionable),
        "_matterd._udp.local." => Some(ServiceKind::Commissioner),
        "_matter._tcp.local." => Some(ServiceKind::Operational),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Test-code carve-out: see CLAUDE.md.
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv6Addr;
    use std::time::{Duration, Instant};

    fn sample_service(instance: &str, kind: ServiceKind) -> MatterService {
        let mut txt = HashMap::new();
        txt.insert("D".to_string(), b"3840".to_vec());
        MatterService {
            instance_name: instance.to_string(),
            kind,
            addresses: vec![std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)],
            port: 5540,
            txt_records: txt,
        }
    }

    #[test]
    fn dotless_fullname_is_skipped() {
        // A fullname with no dot cannot be split into instance + service —
        // it must be skipped (None), not yield an empty instance_name.
        assert_eq!(instance_name_from_fullname("nodothere"), None);
        // An empty leading label is also malformed.
        assert_eq!(instance_name_from_fullname("._matterc._udp.local."), None);
        // A well-formed fullname yields just the instance label.
        assert_eq!(
            instance_name_from_fullname("INSTANCE._matterc._udp.local."),
            Some("INSTANCE".to_string()),
        );
    }

    #[test]
    fn binary_txt_value_preserved_and_ascii_parses() {
        use mdns_sd::IntoTxtProperties;
        // A binary TXT value must survive the parse verbatim; an ASCII
        // discriminator key must still parse.
        let binary = vec![0x00u8, 0xFF, 0x80, 0x01];
        assert!(std::str::from_utf8(&binary).is_err());
        let props: mdns_sd::TxtProperties = vec![
            mdns_sd::TxtProperty::from(("BIN".to_string(), binary.clone())),
            mdns_sd::TxtProperty::from(("D".to_string(), b"3840".to_vec())),
        ]
        .into_txt_properties();

        let records = txt_properties_to_records(&props);
        assert_eq!(records.get("BIN"), Some(&binary), "binary value verbatim");

        // Wrap in a service to exercise the ASCII accessor.
        let svc = MatterService::new(
            "INSTANCE".to_string(),
            ServiceKind::Commissionable,
            vec![std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)],
            5540,
            records,
        );
        assert_eq!(svc.txt_str("BIN"), None, "non-UTF-8 value is not a str");
        assert_eq!(
            svc.txt_str("D").and_then(|d| d.parse::<u16>().ok()),
            Some(3840),
        );
    }

    #[test]
    fn new_spawns_daemon_without_error() {
        let _ = MdnsSdDiscovery::new().unwrap();
    }

    #[test]
    fn publish_unpublish_roundtrip() {
        let mut d = MdnsSdDiscovery::new().unwrap();
        let svc = sample_service("matter-rust-test-publish", ServiceKind::Commissionable);
        d.publish(&svc).unwrap();
        d.unpublish("matter-rust-test-publish", ServiceKind::Commissionable)
            .unwrap();
    }

    #[test]
    fn with_daemon_uses_provided_daemon() {
        let daemon = mdns_sd::ServiceDaemon::new().unwrap();
        let mut d = MdnsSdDiscovery::with_daemon(daemon);
        let svc = sample_service("matter-rust-test-with-daemon", ServiceKind::Commissionable);
        d.publish(&svc).unwrap();
        d.unpublish("matter-rust-test-with-daemon", ServiceKind::Commissionable)
            .unwrap();
    }

    #[test]
    fn query_returns_fresh_handles() {
        let mut d = MdnsSdDiscovery::new().unwrap();
        let h1 = d.query(ServiceKind::Commissionable).unwrap();
        let h2 = d.query(ServiceKind::Operational).unwrap();
        assert_ne!(h1, h2);
        d.stop_query(h1);
        d.stop_query(h2);
    }

    #[test]
    fn stop_query_idempotent() {
        let mut d = MdnsSdDiscovery::new().unwrap();
        let h = d.query(ServiceKind::Commissionable).unwrap();
        d.stop_query(h);
        d.stop_query(h); // second call is a no-op, must not panic
                         // poll_results on a stopped handle returns empty.
        let results = d.poll_results(h);
        assert!(results.is_empty());
    }

    #[test]
    fn service_kind_to_dns_sd_string_exact() {
        // Defensive: the adapter relies on these strings; if Task 3's
        // service_type changes, this test catches it.
        assert_eq!(
            ServiceKind::Commissionable.service_type(),
            "_matterc._udp.local."
        );
        assert_eq!(
            ServiceKind::Commissioner.service_type(),
            "_matterd._udp.local."
        );
        assert_eq!(
            ServiceKind::Operational.service_type(),
            "_matter._tcp.local."
        );
    }

    #[test]
    #[ignore = "requires host mDNS multicast support; CI containers (GitHub \
                Actions ubuntu-latest, macos-latest) don't deliver loopback \
                mDNS announces between two ServiceDaemon instances even with \
                enable_interface(LoopbackV{4,6}). Run locally with `cargo test \
                --features tokio,mdns-sd -- --ignored self_publish_self_discover`. \
                Tracked in TODO-1.0.md as 'mDNS loopback interop in CI'."]
    fn self_publish_self_discover() {
        // Daemon A publishes; adapter B (with its own daemon) queries
        // and observes the service within 5 seconds via poll_results.
        //
        // The sample_service uses `::1` (IPv6 loopback) — mdns-sd 0.13
        // disables loopback interfaces by default and filters
        // addresses to those that match an enabled interface's subnet.
        // We therefore explicitly enable the loopback interfaces on
        // both daemons (publisher and querier) before use. This keeps
        // the test hermetic — no dependency on a real network
        // interface — at the cost of needing the lower-level
        // `with_daemon` constructor here.
        //
        // (Plan default was 2s; bumped to 5s — mdns-sd's register
        // path performs a probing/announce delay before answers
        // appear on a querier, so 2s is racy locally and on CI.)
        let pub_daemon = mdns_sd::ServiceDaemon::new().unwrap();
        pub_daemon
            .enable_interface(mdns_sd::IfKind::LoopbackV4)
            .unwrap();
        pub_daemon
            .enable_interface(mdns_sd::IfKind::LoopbackV6)
            .unwrap();
        let q_daemon = mdns_sd::ServiceDaemon::new().unwrap();
        q_daemon
            .enable_interface(mdns_sd::IfKind::LoopbackV4)
            .unwrap();
        q_daemon
            .enable_interface(mdns_sd::IfKind::LoopbackV6)
            .unwrap();
        let mut publisher = MdnsSdDiscovery::with_daemon(pub_daemon);
        let mut querier = MdnsSdDiscovery::with_daemon(q_daemon);

        let svc = sample_service("matter-rust-test-discover", ServiceKind::Commissionable);
        publisher.publish(&svc).unwrap();
        let handle = querier.query(ServiceKind::Commissionable).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut found = false;
        while Instant::now() < deadline {
            let results = querier.poll_results(handle);
            if results
                .iter()
                .any(|s| s.instance_name == "matter-rust-test-discover")
            {
                found = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        querier.stop_query(handle);
        publisher
            .unpublish("matter-rust-test-discover", ServiceKind::Commissionable)
            .unwrap();

        assert!(found, "did not discover self-published service within 5s");
    }
}
