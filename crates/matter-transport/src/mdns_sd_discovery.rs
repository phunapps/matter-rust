//! Default mdns-sd-based discovery adapter for Matter.
//!
//! Wraps [`mdns_sd::ServiceDaemon`] (which spawns its own background
//! thread on creation) and translates between its [`ServiceEvent`]
//! stream and our [`MatterService`] shape.
//!
//! # One browse per service type, shared by every handle
//!
//! `mdns-sd` keeps **one querier per service type**: its
//! `service_queriers` map is keyed by `ty_domain`, so a second
//! `browse("_matter._tcp.local.")` *replaces* the sender of the first and the
//! first `Receiver` never sees another event; and `stop_browse` removes that
//! shared querier — and drops the daemon's cached records for the type —
//! whoever asks for it.
//!
//! [`QueryHandle`]s are therefore **not** independent browses. This adapter
//! models what the daemon actually provides: it opens at most one browse per
//! service type, reference-counts the handles attached to it, fans every
//! surfaced record out to *all* of them, and calls `stop_browse` only when the
//! last handle for that type is released. Without that, two concurrent
//! `query(ServiceKind::Operational)` callers silently sabotage each other —
//! the second one's `browse` orphans the first's receiver, and its
//! `stop_query` tears down the browse the first is still waiting on, so the
//! first never resolves again for the life of the process (issue #113).
//!
//! # Diagnostics
//!
//! Discovery is the one part of the stack whose failures are invisible from the
//! outside: a record that never arrives, and a record that arrives but is
//! discarded during translation, look identical to a caller (a resolve that
//! simply never completes). This adapter therefore traces every browse it
//! starts, every record it surfaces, and — individually, with the offending
//! value — every record it drops, under the `matter_transport::mdns` target:
//!
//! - `debug`: browse started, record surfaced, record dropped (no addresses,
//!   unrecognised service type).
//! - `warn`: record dropped because it is malformed (fullname with no instance
//!   label) — that is a peer bug, not a normal condition.
//! - `trace`: every non-`ServiceResolved` browse event, by variant. A
//!   `ServiceFound` with no matching `ServiceResolved` means the resolver never
//!   completed SRV/address resolution for that instance, which is otherwise
//!   undiagnosable.
//!
//! Nothing is logged unless the caller installs a `tracing` subscriber; with
//! none installed each site is a cheap dispatcher check.
//!
//! ```text
//! RUST_LOG=matter_transport::mdns=trace,matter_controller::actor=debug
//! ```
//!
//! [`ServiceEvent`]: mdns_sd::ServiceEvent

use std::collections::HashMap;
use std::net::IpAddr;

use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo, TxtProperty};

use crate::discovery::{Discovery, MatterService, QueryHandle, ServiceKind};
use crate::error::{Error, Result};

/// `tracing` target for this adapter's diagnostics, so discovery can be turned
/// up on its own (`RUST_LOG=matter_transport::mdns=trace`) without enabling
/// every other target in the process.
const LOG_TARGET: &str = "matter_transport::mdns";

impl From<mdns_sd::Error> for Error {
    fn from(e: mdns_sd::Error) -> Self {
        Self::Mdns(e.to_string())
    }
}

/// The single browse we run for one DNS-SD service type, plus the handles
/// sharing it.
///
/// `mdns-sd` gives us exactly one querier (and one `Receiver`) per service
/// type — see the module docs — so this is the unit of ownership, not the
/// [`QueryHandle`]. `pending` doubles as the refcount: the browse lives while
/// it is non-empty.
struct BrowseState {
    /// The one `Receiver` mdns-sd handed back for this type. Drained by
    /// whichever handle polls; the records go to every handle in `pending`.
    receiver: Receiver<ServiceEvent>,
    /// Handles attached to this browse, each with the records surfaced since
    /// that handle last called [`Discovery::poll_results`].
    ///
    /// A buffer grows until its handle polls or is stopped — the same
    /// accumulation the per-handle `Receiver` used to provide, so a caller
    /// that polls in a loop (every caller in this workspace) sees no
    /// difference.
    pending: HashMap<QueryHandle, Vec<MatterService>>,
}

/// Default mDNS discovery adapter for Matter, backed by `mdns-sd`.
///
/// Construct via [`Self::new`] (the 90% path — owns its own daemon)
/// or [`Self::with_daemon`] (advanced: inject a pre-configured daemon).
///
/// Handles of the same [`ServiceKind`] share one browse and each receive
/// every record it surfaces; see the module docs for why that is forced on us
/// by mdns-sd's per-type querier.
pub struct MdnsSdDiscovery {
    daemon: ServiceDaemon,
    owns_daemon: bool,
    /// One entry per *service type* with at least one live handle.
    browses: HashMap<&'static str, BrowseState>,
    /// Which browse each live handle belongs to. Absent ⇒ stopped/unknown.
    handle_types: HashMap<QueryHandle, &'static str>,
    next_handle: u64,
    /// Test-only observation of the daemon calls this adapter makes, so a test
    /// can assert "browsed once per type" and "stopped only on the last
    /// release" without a public API or a live network.
    #[cfg(test)]
    browse_calls: HashMap<&'static str, u32>,
    #[cfg(test)]
    stop_browse_calls: HashMap<&'static str, u32>,
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
        Ok(Self::from_daemon(daemon, true))
    }

    /// Reuse an externally-managed [`ServiceDaemon`] — e.g. one configured
    /// with specific interfaces enabled.
    ///
    /// # Sharing one daemon across adapters is unsafe for browsing
    ///
    /// The refcounting described in the module docs is **per
    /// `MdnsSdDiscovery` instance**, while mdns-sd's querier is per *daemon*
    /// and keyed by service type. Two `MdnsSdDiscovery` values built over the
    /// same daemon that browse the same [`ServiceKind`] therefore still
    /// clobber each other exactly as two raw `browse` calls would: the second
    /// instance's `browse` orphans the first's receiver, and its `stop_query`
    /// tears down the browse the first still depends on.
    ///
    /// So: share a daemon freely for *publishing*, but give each component
    /// that browses its own adapter over its own daemon — or, better, share
    /// the one `MdnsSdDiscovery` instance itself (its handles are designed to
    /// coexist). Sharing a daemon between one browsing adapter and any number
    /// of publish-only adapters is also fine.
    #[must_use]
    pub fn with_daemon(daemon: ServiceDaemon) -> Self {
        Self::from_daemon(daemon, false)
    }

    fn from_daemon(daemon: ServiceDaemon, owns_daemon: bool) -> Self {
        Self {
            daemon,
            owns_daemon,
            browses: HashMap::new(),
            handle_types: HashMap::new(),
            next_handle: 1,
            #[cfg(test)]
            browse_calls: HashMap::new(),
            #[cfg(test)]
            stop_browse_calls: HashMap::new(),
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

    /// Test seam: hand a browse event to the `kind` browse exactly as a
    /// [`Discovery::poll_results`] drain would.
    ///
    /// The browse `Receiver` is a re-exported `flume::Receiver` whose `Sender`
    /// lives inside the daemon, so a test cannot put an event on the real
    /// channel, and CI hosts do not deliver loopback mDNS (see the `#[ignore]`
    /// on `self_publish_self_discover`). This bypasses **only** the delivery
    /// of the event: translation, fan-out to every attached handle, buffering
    /// and per-handle consumption all run the production code.
    ///
    /// No-op when no browse is open for `kind` — which is itself the assertion
    /// some tests make.
    #[cfg(test)]
    fn deliver_for_test(&mut self, kind: ServiceKind, event: ServiceEvent) {
        if let Some(browse) = self.browses.get_mut(kind.service_type()) {
            fan_out_event(&mut browse.pending, event);
        }
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

    /// Attach a handle to this service type's browse, opening the browse only
    /// if this is the first handle for the type.
    ///
    /// A second `daemon.browse` of a type we are already browsing would
    /// *replace* the daemon's querier for it and orphan the receiver every
    /// existing handle of that type reads from (module docs, issue #113), so
    /// the reuse here is a correctness requirement, not an optimisation.
    fn query(&mut self, kind: ServiceKind) -> Result<QueryHandle> {
        let service_type = kind.service_type();
        // Open the browse BEFORE allocating a handle so a daemon failure
        // leaves no state behind.
        let receiver = if self.browses.contains_key(service_type) {
            None
        } else {
            let receiver = self.daemon.browse(service_type)?;
            #[cfg(test)]
            self.browse_calls
                .entry(service_type)
                .and_modify(|n| *n += 1)
                .or_insert(1);
            tracing::debug!(
                target: LOG_TARGET,
                service_type,
                "mDNS browse started",
            );
            Some(receiver)
        };
        if let Some(receiver) = receiver {
            self.browses.insert(
                service_type,
                BrowseState {
                    receiver,
                    pending: HashMap::new(),
                },
            );
        }
        let handle = self.allocate_handle();
        let Some(browse) = self.browses.get_mut(service_type) else {
            // Unreachable: the entry was either already present or inserted
            // just above. Reported as an error rather than asserted, because a
            // handle with no browse behind it could only ever return nothing.
            return Err(Error::Mdns(format!(
                "internal: no browse state for {service_type} after opening it"
            )));
        };
        browse.pending.insert(handle, Vec::new());
        let handles = browse.pending.len();
        self.handle_types.insert(handle, service_type);
        tracing::debug!(
            target: LOG_TARGET,
            service_type,
            handle = handle.0,
            handles,
            "mDNS browse handle attached",
        );
        Ok(handle)
    }

    /// Release one handle. The underlying browse is stopped only when its
    /// **last** handle goes away.
    ///
    /// Note that `mdns_sd::ServiceDaemon::stop_browse` also drops the daemon's
    /// cached records for the service type, so releasing the last handle
    /// discards what the browse had learned; the next `query` for that type
    /// starts from an empty cache and must wait for fresh announcements.
    /// That is why stopping is deferred to the last release, and why a caller
    /// that reconnects repeatedly is better off holding one handle open.
    fn stop_query(&mut self, handle: QueryHandle) {
        // Unknown or already-stopped handle: no-op.
        let Some(service_type) = self.handle_types.remove(&handle) else {
            return;
        };
        let remaining = match self.browses.get_mut(service_type) {
            Some(browse) => {
                browse.pending.remove(&handle);
                browse.pending.len()
            }
            None => 0,
        };
        tracing::debug!(
            target: LOG_TARGET,
            service_type,
            handle = handle.0,
            remaining,
            "mDNS browse handle released",
        );
        if remaining == 0 {
            self.browses.remove(service_type);
            let _ = self.daemon.stop_browse(service_type);
            #[cfg(test)]
            self.stop_browse_calls
                .entry(service_type)
                .and_modify(|n| *n += 1)
                .or_insert(1);
            tracing::debug!(
                target: LOG_TARGET,
                service_type,
                "mDNS browse stopped (last handle released; mdns-sd also drops its cached records for this type)",
            );
        }
    }

    /// Drain the shared browse once and return **this** handle's share.
    ///
    /// Every record drained here is appended to the buffer of *every* handle
    /// attached to the same service type, then this handle's buffer is taken
    /// and returned. So the documented contract still holds — a record is
    /// returned to a given handle exactly once — while a second handle on the
    /// same type no longer steals records the first is waiting for.
    fn poll_results(&mut self, handle: QueryHandle) -> Vec<MatterService> {
        let Some(service_type) = self.handle_types.get(&handle).copied() else {
            return Vec::new();
        };
        let Some(browse) = self.browses.get_mut(service_type) else {
            return Vec::new();
        };
        // Destructure so the receiver and the per-handle buffers are borrowed
        // as the disjoint fields they are.
        let BrowseState { receiver, pending } = browse;
        // Drain pending events without blocking, fanning each out to every
        // handle attached to this browse — including handles that are not the
        // one polling, which is the whole point (issue #113).
        while let Ok(event) = receiver.try_recv() {
            fan_out_event(pending, event);
        }
        match pending.get_mut(&handle) {
            Some(buffer) => std::mem::take(buffer),
            // Unreachable: `handle_types` and `pending` are inserted and
            // removed together. Empty is the safe answer either way.
            None => Vec::new(),
        }
    }
}

/// Translate one browse event and append the resulting record to the buffer of
/// **every** handle attached to that browse.
///
/// Split out of [`Discovery::poll_results`] so the fan-out has one
/// implementation, shared with the test seam that delivers synthetic events
/// (mdns-sd's browse `Sender` lives inside the daemon, so an event cannot
/// otherwise be injected without a live multicast network).
fn fan_out_event(pending: &mut HashMap<QueryHandle, Vec<MatterService>>, event: ServiceEvent) {
    match event {
        ServiceEvent::ServiceResolved(info) => {
            // `service_info_to_matter` logs its own drop reason, so a
            // `None` here is already accounted for in the trace.
            if let Some(svc) = service_info_to_matter(&info) {
                tracing::debug!(
                    target: LOG_TARGET,
                    instance = %svc.instance_name,
                    kind = ?svc.kind,
                    addresses = ?svc.addresses,
                    port = svc.port,
                    handles = pending.len(),
                    "mDNS record surfaced",
                );
                for buffer in pending.values_mut() {
                    buffer.push(svc.clone());
                }
            }
        }
        // Other events (ServiceFound, ServiceRemoved, SearchStarted,
        // SearchStopped, etc.) are intentionally discarded — poll_results only
        // emits usable (address-resolved) services. Traced rather than dropped
        // silently: a `ServiceFound` never followed by a `ServiceResolved` for
        // the same instance is the signature of the resolver failing to
        // complete SRV/address resolution, and is otherwise invisible.
        other => trace_unused_event(&other),
    }
}

/// Trace a browse event `poll_results` does not turn into a [`MatterService`],
/// naming the variant and (where the variant carries one) the instance it
/// concerns.
///
/// `ServiceEvent` is `#[non_exhaustive]`, so the catch-all arm is required and
/// keeps a future variant visible as its `Debug` form rather than silent.
fn trace_unused_event(event: &ServiceEvent) {
    match event {
        ServiceEvent::SearchStarted(ty) => {
            tracing::trace!(target: LOG_TARGET, service_type = %ty, "mDNS event: SearchStarted");
        }
        ServiceEvent::ServiceFound(ty, fullname) => {
            tracing::trace!(
                target: LOG_TARGET,
                service_type = %ty,
                fullname = %fullname,
                "mDNS event: ServiceFound (awaiting ServiceResolved)",
            );
        }
        ServiceEvent::ServiceRemoved(ty, fullname) => {
            tracing::trace!(
                target: LOG_TARGET,
                service_type = %ty,
                fullname = %fullname,
                "mDNS event: ServiceRemoved",
            );
        }
        ServiceEvent::SearchStopped(ty) => {
            tracing::trace!(target: LOG_TARGET, service_type = %ty, "mDNS event: SearchStopped");
        }
        other => {
            tracing::trace!(target: LOG_TARGET, event = ?other, "mDNS event: unhandled variant");
        }
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
/// Every one of those drops is logged (see the module's Diagnostics section)
/// with the value that caused it, because a dropped record is indistinguishable
/// from an absent one at the caller.
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
        tracing::debug!(
            target: LOG_TARGET,
            fullname = %info.fullname,
            "mDNS record dropped: resolved with no addresses",
        );
        return None;
    }
    let Some(kind) = kind_from_service_type(&info.ty_domain) else {
        // The compare is exact, so ANY unexpected `ty_domain` — including a
        // record surfaced under a Matter subtype such as
        // `_I<compressed-fabric>._sub._matter._tcp.local.` — dies here. Logging
        // the actual value is what makes that distinguishable from "no record
        // arrived at all".
        tracing::debug!(
            target: LOG_TARGET,
            fullname = %info.fullname,
            ty_domain = %info.ty_domain,
            "mDNS record dropped: service type is not a recognised Matter type",
        );
        return None;
    };
    // Skip malformed records whose fullname has no instance label (see the
    // helper). Surfacing as `None` is the adapter's "skip this record" path.
    let Some(instance_name) = instance_name_from_fullname(&info.fullname) else {
        tracing::warn!(
            target: LOG_TARGET,
            fullname = %info.fullname,
            ty_domain = %info.ty_domain,
            "mDNS record dropped: malformed fullname (no leading instance label)",
        );
        return None;
    };
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

    // ---------------------------------------------------------------------
    // Shared-browse fan-out and refcounting (issue #113).
    //
    // mdns-sd keeps ONE querier per service type; these tests pin that this
    // adapter models that rather than pretending each handle owns a browse.
    // Events are delivered through `deliver_for_test` (see its docs) because
    // the browse `Sender` is inside the daemon and CI hosts don't deliver
    // loopback mDNS; everything downstream of delivery is production code.
    // ---------------------------------------------------------------------

    /// A `ServiceResolved` event for `instance`, shaped exactly like the one
    /// mdns-sd emits for a Matter record of `kind`.
    fn resolved_event(instance: &str, kind: ServiceKind) -> ServiceEvent {
        let info = ServiceInfo::new(
            kind.service_type(),
            instance,
            &format!("{instance}.local."),
            &[std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)][..],
            5540,
            Vec::<TxtProperty>::new(),
        )
        .unwrap();
        ServiceEvent::ServiceResolved(Box::new(info.as_resolved_service()))
    }

    /// Whether a poll result carries `instance`. Used instead of comparing
    /// whole vectors: a developer machine may have real Matter records on the
    /// network, and they land in these browses too.
    fn contains(results: &[MatterService], instance: &str) -> bool {
        results.iter().any(|s| s.instance_name == instance)
    }

    #[test]
    fn two_handles_of_one_type_share_one_browse_and_both_see_each_record() {
        // THE #113 FAILURE: the second `query` used to open a second
        // `daemon.browse` of the same type, which replaces the daemon's
        // querier and orphans the first handle's receiver — so the first
        // handle never saw another record.
        let mut d = MdnsSdDiscovery::new().unwrap();
        let a = d.query(ServiceKind::Operational).unwrap();
        let b = d.query(ServiceKind::Operational).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            d.browse_calls.get(ServiceKind::Operational.service_type()),
            Some(&1),
            "the second handle must reuse the first handle's browse",
        );

        d.deliver_for_test(
            ServiceKind::Operational,
            resolved_event("113-shared", ServiceKind::Operational),
        );

        let first = d.poll_results(a);
        let second = d.poll_results(b);
        assert!(contains(&first, "113-shared"), "handle A must see it");
        assert!(
            contains(&second, "113-shared"),
            "handle B must see it too — one handle polling must not consume \
             another handle's copy",
        );

        // Per-handle consumption still holds: a record is handed to a given
        // handle exactly once.
        assert!(!contains(&d.poll_results(a), "113-shared"));
        assert!(!contains(&d.poll_results(b), "113-shared"));

        d.stop_query(a);
        d.stop_query(b);
    }

    #[test]
    fn stopping_one_handle_leaves_the_other_handles_browse_alive() {
        // THE OTHER HALF OF #113: `stop_browse` is per service type, so the
        // short-lived resolve's `stop_query` used to tear down the browse the
        // long-lived handle was still waiting on (and wipe mdns-sd's cache
        // for the type), permanently for the process.
        let ty = ServiceKind::Operational.service_type();
        let mut d = MdnsSdDiscovery::new().unwrap();
        let long_lived = d.query(ServiceKind::Operational).unwrap();
        let short_lived = d.query(ServiceKind::Operational).unwrap();

        d.stop_query(short_lived);
        assert_eq!(
            d.stop_browse_calls.get(ty),
            None,
            "a browse with a handle still attached must not be stopped",
        );

        d.deliver_for_test(
            ServiceKind::Operational,
            resolved_event("113-survivor", ServiceKind::Operational),
        );
        assert!(
            contains(&d.poll_results(long_lived), "113-survivor"),
            "the surviving handle must still receive records",
        );
        // The released handle is inert, not merely quiet.
        assert!(d.poll_results(short_lived).is_empty());

        d.stop_query(long_lived);
        assert_eq!(
            d.stop_browse_calls.get(ty),
            Some(&1),
            "only the LAST release stops the browse",
        );
    }

    #[test]
    fn browse_reopens_after_the_last_handle_is_released() {
        // Refcount must drop to zero and be usable again — a stopped type is
        // not permanently poisoned.
        let ty = ServiceKind::Operational.service_type();
        let mut d = MdnsSdDiscovery::new().unwrap();
        let first = d.query(ServiceKind::Operational).unwrap();
        d.stop_query(first);
        assert_eq!(d.stop_browse_calls.get(ty), Some(&1));

        // A delivery with no browse open goes nowhere (nothing to fan out to).
        d.deliver_for_test(
            ServiceKind::Operational,
            resolved_event("113-orphan", ServiceKind::Operational),
        );

        let second = d.query(ServiceKind::Operational).unwrap();
        assert_eq!(
            d.browse_calls.get(ty),
            Some(&2),
            "a type with no handles must be browsed afresh",
        );
        assert!(!contains(&d.poll_results(second), "113-orphan"));
        d.deliver_for_test(
            ServiceKind::Operational,
            resolved_event("113-reopened", ServiceKind::Operational),
        );
        assert!(contains(&d.poll_results(second), "113-reopened"));
        d.stop_query(second);
    }

    #[test]
    fn handles_of_different_types_are_independent() {
        // Fan-out is per service type: an operational record must not leak
        // into a commissionable browse, and stopping one type must not touch
        // the other's browse.
        let mut d = MdnsSdDiscovery::new().unwrap();
        let operational = d.query(ServiceKind::Operational).unwrap();
        let commissionable = d.query(ServiceKind::Commissionable).unwrap();

        d.deliver_for_test(
            ServiceKind::Operational,
            resolved_event("113-op-only", ServiceKind::Operational),
        );
        assert!(!contains(&d.poll_results(commissionable), "113-op-only"));
        assert!(contains(&d.poll_results(operational), "113-op-only"));

        d.stop_query(commissionable);
        assert_eq!(
            d.stop_browse_calls
                .get(ServiceKind::Operational.service_type()),
            None,
            "stopping one type must not stop another",
        );
        d.deliver_for_test(
            ServiceKind::Operational,
            resolved_event("113-still-live", ServiceKind::Operational),
        );
        assert!(contains(&d.poll_results(operational), "113-still-live"));
        d.stop_query(operational);
    }

    #[test]
    fn actor_usage_pattern_survives_a_nested_resolve() {
        // The exact shape of the reported failure, at the adapter level: the
        // controller actor holds ONE long-lived operational browse for its
        // parked resolves, while another operational resolve (the connect
        // fallback, or a commissioning driver sharing the same `Discovery`)
        // runs its own query/poll/stop cycle underneath. Before the fix the
        // nested resolve orphaned the actor's receiver and then stopped the
        // shared browse, and every later parked resolve failed with
        // "not found via mDNS" for the rest of the process.
        let mut d = MdnsSdDiscovery::new().unwrap();
        let actor_browse = d.query(ServiceKind::Operational).unwrap();

        // ... a nested resolve runs to completion, exactly as
        // `resolve_operational` does: query, poll, stop_query.
        let nested = d.query(ServiceKind::Operational).unwrap();
        d.deliver_for_test(
            ServiceKind::Operational,
            resolved_event("113-nested-target", ServiceKind::Operational),
        );
        assert!(contains(&d.poll_results(nested), "113-nested-target"));
        d.stop_query(nested);

        // ... and afterwards the actor's browse is still live and still
        // delivering, which is what #113 lost.
        d.deliver_for_test(
            ServiceKind::Operational,
            resolved_event("113-after-nested", ServiceKind::Operational),
        );
        let late = d.poll_results(actor_browse);
        assert!(
            contains(&late, "113-after-nested"),
            "the long-lived browse must survive a nested resolve",
        );
        // It also still holds the record the nested resolve consumed for
        // itself — the fan-out gave both handles a copy.
        assert!(contains(&late, "113-nested-target"));
        d.stop_query(actor_browse);
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
