# Changelog

All notable changes to crates in the `matter-rust` workspace.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## About 0.1.0 — the first published release

**Every crate here is published to crates.io at `0.1.0`, and that is the first
release of each.** Nothing was published before it.

The per-crate headings below record *internal* development history from before
first publication — milestone by milestone, including version numbers
(`0.1.0-pre`, `0.1.1`, …) that only ever existed in this repository. Everything
listed under a crate, under any heading, is contained in that crate's `0.1.0`.
They are kept because the reasoning is worth reading, not because those versions
were ever installable.

From `0.1.0` onward the headings mean what they say, and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) applies. Note that
while a crate is `0.x`, a **breaking change bumps the minor version** — these
APIs have had no outside users yet and are expected to move.

## Unreleased

### Added — operational discovery browses the compressed-fabric subtype ([#113])

Operational resolves now browse the fabric's DNS-SD **compressed-fabric
subtype**, `_I<compressed-fabric-id>._sub._matter._tcp.local.` (the id as
fixed-width uppercase hex), instead of relying solely on the base
`_matter._tcp` browse. Matter Core Spec §4.3.1 defines that subtype for exactly
this purpose: it narrows discovery to the nodes of *our own* fabric.

**Why.** Following up on [#113], the reporter instrumented his own network: the
base-type browse finds 18 operational instances, and `mdns-sd` resolves roughly
one per query cycle with an exponential backoff, so his three nodes were
*found* at 317 ms and still had no address, port or TXT record when our 30 s
budget expired — invisible to us, and the resolve failed with
`not found via mDNS`. Running the compressed-fabric subtype browse in the same
environment resolved all three nodes at **~266 ms**, with addresses and TXT
properties. We reproduced the narrowing on our own rig (a 16-instance browse
collapses to the single node on our fabric, resolved immediately).

**The subtype browse runs alone first.** This matters more than it looks, and
the first version of this change got it wrong — see *A correction* below.

**This is not yet confirmed to fix the reporter's failure** — his environment
confirms only that the subtype resolves where the base type stalls, and the fix
is pending his verification against this branch.

#### A correction: the base-type browse must NOT run concurrently

The first attempt at this fix opened the subtype browse **and** the base
`_matter._tcp` browse at the same time and matched on whichever delivered first,
reasoning that an extra browse could only add records and never remove them.

**The reporter tested that build, and it did not help.** His debug log — from
our own instrumentation — shows why: both browses open, every single surfaced
record carries `browse="_matter._tcp.local." subtype_browse=false`, the subtype
browse surfaces **nothing at all** in 30 s (with zero records dropped, so they
never arrived rather than being filtered out), and all three resolves expire.
Meanwhile a manual run against the subtype **alone**, on a fresh daemon,
resolved all three nodes in ~266 ms.

**The mechanism.** The underlying defect is that `mdns-sd` completes
per-instance SRV/address resolution slowly — roughly one instance per query
cycle on his network ([keepsimple1/mdns-sd#493]) — from a queue shared by every
open browse. The subtype helps *only* because it limits how many instances enter
that queue: 3 instead of 18. Opening the base-type browse re-discovers all 18
and puts his three nodes back at the end of the same slow queue. A subtype
browse cannot deliver a resolved record for an instance the resolver has not
resolved yet, so the concurrent fallback reintroduced exactly the bug the
subtype was meant to sidestep. (It looked fine on our rig — but our network
resolves everything promptly, so our rig could not tell the two designs apart.
That is how it got through.)

**The corrected design.** The subtype browse is the *sole* browse at resolve
start. The base-type browse is opened only as a **delayed fallback**, after
`SUBTYPE_ONLY_WINDOW` = **2 s** with no match, for the case it exists to
serve: a responder that genuinely publishes no subtype PTR. Two seconds is long
enough that a healthy subtype responder always answers first (~266 ms on the
reporter's network, ~250 ms on ours — roughly 8x headroom, and enough to absorb
a query that has to be retransmitted once), and short enough to be noise against
the ~30 s resolve budget, leaving ~28 s for a subtype-less responder, which is
discovered on the base browse from that browse's first query cycle. Once open,
both browses are polled and whichever delivers the record first still settles
the resolve. If the subtype browse cannot be opened at all, the base type is
opened immediately — there is nothing to wait for.

The delayed open is driven from each site's **existing poll loop**, not a new
timer or task: `matter-commissioning`'s resolve counts poll iterations, and the
controller actor holds a deadline that its 250 ms resolve-poll arm checks, so the
fallback opens within one tick of becoming due and the actor gains no new timer
source. When it does open, it is logged at debug with the reason
(`no subtype match after 2s; opening the base-type _matter._tcp browse as a
fallback`), so a log says plainly whether the fallback was needed.

- **`matter-transport`**
  - New `Discovery::query_operational_fabric(compressed_fabric_id)` with a
    **default implementation that delegates to
    `query(ServiceKind::Operational)`** — additive and non-breaking, so an
    out-of-tree `Discovery` keeps compiling and keeps today's behaviour.
  - New `operational_fabric_subtype(compressed_fabric_id) -> String` builds the
    browse string (`_IF52AC107C954E38E._sub._matter._tcp.local.`), matching the
    hex convention of `matter_commissioning::driver::operational_instance_name`.
  - `MdnsSdDiscovery` overrides it to browse the subtype. Browses are now keyed
    by service-type *string* rather than `ServiceKind`, so a subtype browse is a
    distinct key from its base type: the two coexist under the refcounting added
    in `ca6e093d`, with independent fan-out, replay and `stop_browse`.
  - Records surfaced through a subtype arrive with the subtype as their
    `ty_domain`; it is stripped during translation, so they surface as ordinary
    `ServiceKind::Operational` records instead of being dropped as an
    unrecognised type.

- **`matter-commissioning` / `matter-controller`** — both operational resolve
  paths (`resolve_operational*` and the controller actor's parked resolve) open
  the subtype browse **alone**, and open the base type only as the delayed
  fallback described above. The base type is deliberately kept, because a
  subtype browse *narrows*: a responder that publishes no subtype PTR must not
  become invisible — regressing from "slow" to "finds nothing" would be worse
  than the bug. But it must not run *concurrently*, or the narrowing it exists
  to preserve is undone. Failing to open one browse is not fatal as long as the
  other opens; equal handles (what the trait default hands back) are polled once.

- **Diagnostics** — the trace added in `9b001743` now says which browse did the
  work: `matter_transport::mdns` logs `browse` and `subtype_browse` on every
  surfaced record, and `matter_controller::actor` logs `browse = subtype|base`
  on each drain and on the record that settles a resolve. Same filter as before:

  ```text
  RUST_LOG=matter_transport::mdns=trace,matter_controller::actor=debug
  ```

  The `browse` / `subtype_browse` fields are deliberately kept, so the next
  field report says which browse actually won.

[keepsimple1/mdns-sd#493]: https://github.com/keepsimple1/mdns-sd/issues/493

## 0.7.1

A discovery-reliability release, prompted by [#113]. It fixes a real aliasing
bug in our `mdns-sd` adapter and makes the discovery path diagnosable, which it
previously was not — a failed operational resolve produced one opaque line
thirty seconds later, with no way to tell whether a record had ever been seen.

Crate versions: **`matter-transport` 0.3.2**, **`matter-commissioning` 0.5.2**,
**`matter-controller` 0.7.1**. Every other crate is unchanged from `0.7.0` and
is not republished.

### Fixed — concurrent mDNS queries aliased each other's browse ([#113])

**What this is, precisely:** a **verified aliasing bug in our `mdns-sd`
adapter**, found while investigating [#113] and fixed below. Its behaviour is
consistent with what the issue reports. But **the reporter's failure has not
been reproduced here**, so it is *not* confirmed to be the same fault, and this
release does not claim to close #113. If you hit the reported symptom on a
version with this fix, please say so on the issue — with the trace filter at the
end of this section, the next report can be diagnosed instead of guessed at.

**Reported symptom ([#113]):** after the first reconnect attempt, every later
attempt to reach an already-commissioned device fails with

```text
device discovery failed: operational node <fabric>-<node> not found via mDNS
```

for the rest of the process — while `avahi-browse` shows the `_matter._tcp`
records the whole time. Initial commissioning works; only subsequent operational
resolves are affected, and only a restart clears it.

**The bug we found:** `MdnsSdDiscovery` handed out a `QueryHandle` per `query()`
call and kept a `Receiver` per handle, as though each handle were an independent
browse. `mdns-sd` does not work that way: its queriers are keyed by service
type, so a second `browse("_matter._tcp.local.")` *replaces* the first handle's
sender — that handle never receives another event — and `stop_browse` removes
the shared querier (and drops the daemon's cached records) for the whole type,
whichever handle asked.

The controller opens its shared operational browse when a resolve is parked and
drops it again as soon as none is (`release_resolve_query_if_idle`), so the
exposure is not continuous: it is the window in which a resolve is outstanding,
at most the ~30 s resolve budget. Within that window, a second operational
resolve on the same `Discovery` (the connect fallback, or a commissioning driver
sharing the object) orphaned the parked resolve's receiver and then tore the
browse down. That is a narrow window, which is worth weighing when judging how
likely this is to be *the* cause of #113 rather than *a* real bug found on the
way.

**Fix:** the adapter now models what the daemon actually provides — **one browse
per service type, reference-counted across handles**. `query()` reuses the
existing browse for a type instead of re-`browse`-ing it; each drained record is
fanned out to *every* handle attached to that type (so one handle polling can no
longer consume another's copy, while each handle still receives a given record
exactly once); and `stop_query()` calls `stop_browse` only when the type's last
handle is released. No API change — `Discovery`, `QueryHandle` and `with_daemon`
are untouched.

Reusing a browse means the new handle never gets the cache replay a real
`browse` performs, and `mdns-sd` re-emits a record only when it *changes* — so
on its own, the reuse would starve a handle that attaches after a stable service
has already resolved (it would poll its entire budget and see nothing that
`avahi-browse` shows). The adapter therefore keeps its own record of the last
service surfaced per instance name and seeds each newly attached handle from it.
That restores replay from the adapter's own memory, keeps "each handle receives
a given record exactly once", and is bounded by the number of distinct instances
on the link rather than by how long the browse has been open.

Three consequences are now documented rather than surprising: releasing the last
handle for a type discards mdns-sd's cached records for it (`stop_browse` clears
the cache), so the next query starts cold; the refcount is **per
`MdnsSdDiscovery` instance**, so two adapters sharing one `ServiceDaemon` and
browsing the same service type still clobber each other — share the adapter, not
just the daemon (see `MdnsSdDiscovery::with_daemon`); and a leaked `QueryHandle`
now holds the shared browse open as well as buffering records, so pair every
`query` with a `stop_query` on all paths — the realistic leak is a dropped or
cancelled future that never reaches its `stop_query`. Both points are now on the
`Discovery::query` / `Discovery::stop_query` rustdoc.

### Diagnostics for operational-discovery failures ([#113])

Issue [#113] reports reconnects to already-commissioned devices failing with

```text
device discovery failed: operational node <fabric>-<node> not found via mDNS
```

while `avahi-discover` shows the `_matter._tcp` records. It has not been
reproduced here, and the discovery path offered nothing to reason with: an mDNS
record could be discarded at four separate points without leaving any trace, and
the caller saw a single opaque line 30 seconds later. **The instrumentation
below adds no fix and changes no discovery behaviour** — no retries, no timing
changes, no new matching rules; it landed first, to make the path observable.
(Reading `mdns-sd`'s querier bookkeeping then turned up a real aliasing bug of
our own — fixed above — but, not having reproduced the report, we cannot say it
was *the* cause.)

- **`matter-transport` now depends on `tracing`** and the `mdns-sd` adapter
  instruments every decision it makes, under the `matter_transport::mdns`
  target: the browse it starts, every record it surfaces (instance, addresses,
  port), and — individually, with the offending value — every record it drops:
  resolved with no addresses, unrecognised `ty_domain` (the compare is exact, so
  the actual value is logged), and, at `warn`, a malformed fullname. Every
  browse event that is *not* `ServiceResolved` is traced by variant at `trace`,
  so a `ServiceFound` that never becomes a `ServiceResolved` — mdns-sd failing
  to complete SRV/address resolution — is now visible instead of silent.
  Nothing is emitted unless the application installs a subscriber.
- **`matter-controller` traces the parked-resolve path** (`matter_controller::actor`):
  which instance name each connect is waiting for, what the shared browse
  actually drained each pass, records ignored for having no routable address,
  and each resolve that matches or expires — so a target-vs-seen mismatch is
  directly readable.
- **The failure message now says what discovery did see.** Both producers of the
  error (the controller's parked resolve and `matter-commissioning`'s inline
  resolver) now append a bounded summary — either
  `(saw 0 operational mDNS records — either no _matter._tcp response reached this
  host, or responses arrived and were discarded before being counted;
  RUST_LOG=matter_transport::mdns=debug distinguishes the two)` or
  `(saw 3 operational mDNS record(s), none matching: <up to five names>)`. A
  non-empty count says the browse works and this node was not in it (device
  offline, different fabric, stale node id). A zero is deliberately the weaker
  claim: records dropped during translation — an unrecognised `ty_domain`, no
  routable address — are never counted, so zero does not by itself convict the
  network, and the two producers do not even count the same population (the
  controller counts records that survived address selection; the commissioning
  resolver counts every record it polled). The `not found via mDNS` substring is
  unchanged.

Suggested filter when reporting a discovery problem:

```text
RUST_LOG=matter_transport::mdns=trace,matter_controller::actor=debug
```

[#113]: https://github.com/phunapps/matter-rust/issues/113

## 0.7.0

A robustness-and-honesty release. The code change is one fix in the controller's
event loop; the bulk of the work is making the crates' *documentation* true,
prompted by issue [#111] — where an adopter hit a wall because our own README
told him to.

**Documentation is now compile-checked.** Every crate README is wired in as a
doctest (`#[cfg(doctest)] #[doc = include_str!("../README.md")]`), so an example
that stops compiling fails the build. Turning that on surfaced eleven kinds of
API drift, including three examples that could never have compiled at all —
a `CertificateChain::new` call that fails to borrow-check, a `CommissionerConfig`
missing a required field added in an earlier release, and a driver loop matching
every variant of a `#[non_exhaustive]` enum. A follow-up pass rewrote the
crate-level rustdoc (the docs.rs landing pages) and the READMEs, which were
written as internal milestone logs and in several places claimed the crates
could do *less* than they can: `matter-interaction` advertised no subscriptions,
no events, no timed actions and no chunked writes, all four of which ship.
24 false claims corrected across 8 crates.

**The controller's event loop can no longer spin on a failing transport.** It
previously discarded every `recv_from` error and immediately re-polled, so a
transport returning a permanent error pegged a core. Errors are now classified:
terminal kinds shut the actor down cleanly, everything else is transient and
backed off. See the `matter-controller` and `matter-commissioning` sections for
the behaviour contract this places on `AsyncDatagram` implementors.

**`p256` moved from 0.13 to 0.14**, under SPAKE2+ and CASE. No wire bytes, no
derived keys and no signatures change, and every test vector passes unmodified.

Crate versions: **`matter-controller` 0.7.0** (the loop behaviour change),
and patch releases for the rest — **`matter-codec`**, **`matter-cert`**,
**`matter-crypto`**, **`matter-transport`** 0.3.1, **`matter-bdx`** 0.3.1,
**`matter-interaction`**, **`matter-clusters`** 0.4.1, **`matter-commissioning`**,
**`matter-ota`** 0.5.1, **`matter-ble`** 0.3.3.

### Fixed

- **`matter-controller`: the actor loop no longer discards transport receive
  errors, which could make it busy-loop at 100% CPU.** The `select!`'s inbound
  arm was `if let Ok((packet, from)) = recv { … }` — an `Err` fell through
  silently and the loop re-polled at once. Against a transport whose `recv_from`
  fails *permanently*, the arm is therefore ready forever and the loop spins:
  measured at ~447 000 error returns in 6 seconds (~75 000 per second) against
  an `InMemoryDatagram` whose paired endpoint had been dropped (it returns
  `BrokenPipe` for good in that state).

  Blast radius before the fix was the in-process test harness only — the real
  `TokioUdpTransport` has no permanent-error mode — so this is a robustness fix,
  not a reported outage. But the loop should not be one bad transport away from
  pegging a core.

  Errors are now **classified**, because neither "ignore all" (the bug) nor
  "treat all as fatal" is correct. The forcing argument is that `io::ErrorKind`
  is `#[non_exhaustive]` and recoverable receive errors exist (`EINTR`, spurious
  wakeups, and — on a *connected* UDP socket — `ECONNREFUSED` synthesised from a
  peer's ICMP port-unreachable): an error we did not anticipate must cost a
  bounded backoff, never a dead controller. (`ECONNREFUSED` is the textbook
  example, but it cannot reach this workspace's own transport, which binds
  `[::]:port` and never calls `connect()`. It applies to out-of-tree
  `AsyncDatagram` implementations that are connected.)

  - **Terminal** — `BrokenPipe`, `NotConnected`. The socket will never deliver
    again. The actor logs at `warn` and shuts down through exactly the path a
    dropped command channel takes (`shutdown_discovery`), so the shared mDNS
    browse is released rather than left running. The list is deliberately short:
    an unanticipated kind is treated as transient, since backing off on an error
    we did not foresee is far better than killing a live controller over it.
  - **Transient** — everything else. Logged at `debug` and the loop continues.
    To stop "transient" from re-introducing the spin, 8 consecutive errors with
    no successful receive in between start a doubling backoff (1 ms, capped at
    200 ms) that suppresses the receive arm. The cap sits below the ~300 ms floor
    of an MRP retransmit interval, so a wedged transport cannot swallow a whole
    retransmit window for datagrams that *do* arrive, and it bounds such a
    transport to ~5 wakeups/second. The backoff is expressed as a deadline the
    loop parks on — one more component of `next_timer_deadline`, retired at the
    top of each iteration once elapsed — not a `sleep` inside the arm, so
    commands, MRP and subscription liveness keep running at full speed
    throughout.

    A run of transient errors **decays**: two errors more than 400 ms apart are
    not a run, so the counter (and the escalation below) resets. Without that,
    the counter fell only on a *successful* receive, and a controller whose only
    peer is offline — one error per MRP retransmit, no intervening `Ok` — would
    creep to the 200 ms ceiling and stay pinned there for the process's life,
    delaying the first datagram from a returning device. The decay window is
    deliberately longer than the ceiling, so a genuinely wedged transport is not
    handed its free retries back by the backoff's own pacing.

    A transport that fails *every* receive with a transient kind is also
    escalated to `warn`, **edge-triggered**: once when the run leaves the
    free-retry budget, once more when the backoff saturates, and once when a
    receive finally succeeds. Such a transport leaves the controller alive but
    deaf — every read/write/subscribe fails with a timeout — which at `debug`
    was invisible to anyone running at the default `info`. Edge-triggering keeps
    a wedged transport from becoming a log flood in its own right.

  **No signature change** — `AsyncDatagram` is source- and ABI-compatible, and
  no published API gained or lost an item.

  **But the `AsyncDatagram` behaviour contract did change**, and out-of-tree
  implementors must read this: returning `BrokenPipe` or `NotConnected` from
  `recv_from` **once** now permanently stops the controller's actor, after which
  every call fails with `ControllerStopped` and only a rebuilt
  `MatterController` recovers. A transport wrapping a reconnecting relay, an IPC
  hop, or a socket being re-bound must therefore not report a momentary gap as
  `BrokenPipe` — natural though that reading is — but keep awaiting, or use a
  transient kind (`WouldBlock`, `ConnectionReset`, `TimedOut`, `Interrupted`).
  The contract is now documented on `AsyncDatagram::recv_from` itself.

  Users of the in-process `InMemoryDatagram` harness should likewise note that
  dropping one endpoint now stops the controller's actor instead of being
  silently ignored; the in-crate test devices keep their endpoint open, which is
  what a real UDP socket does when the device at the other end goes quiet.

### Changed

- **`matter-controller`: `LIVENESS_TICK` renamed to `RESOLVE_POLL_INTERVAL`**
  (private const; no API impact). It has not been a liveness tick since the
  actor's park became deadline-driven — it is exclusively the mDNS
  resolve-polling interval, which is what its own rustdoc already said.

- **`matter-controller`: `park_resolve` re-arms the resolve-poll anchor itself**
  when it is the first entry to park. The invariant "the anchor is fresh
  whenever `pending_resolves` becomes non-empty" previously held only because
  the sole caller happened to call `drive_pending_resolves()` two lines later.
  Behaviour is unchanged (breaking the coupling cost one self-healing guard
  pass); the invariant is now local to the function that establishes it.

### Testing

- **`matter-controller`: real coverage for the absolute resolve-poll anchor.**
  The anchor is stored as an absolute instant precisely so that a `select!` arm
  firing faster than `RESOLVE_POLL_INTERVAL` cannot push it forward forever and
  starve mDNS discovery. Until now that property was only exercised *by
  accident*, via the receive-error spin above — so fixing the spin would have
  silently deleted its only coverage. The new
  `parked_resolve_expires_while_the_inbound_arm_is_hot` keeps the inbound arm
  genuinely hot on purpose (a paced sender, ~1000 datagrams/second, with an
  assertion that the flood really happened) while a resolve is parked, and
  asserts the parked resolve still expires at its deadline. Verified to fail
  against a relative `now + RESOLVE_POLL_INTERVAL` anchor and pass against the
  absolute one.

- **`matter-controller`: direct coverage for the receive-error classification** —
  a terminal error stops the loop while its command channel is still open; a
  permanently-*transient* transport leaves the loop responsive and is polled ~18
  times per 500 ms instead of tens of thousands; plus unit tests pinning the
  terminal/transient split, the backoff ramp's saturation at the arithmetic
  edge, the decay of a run after a quiet gap (including that the decay window
  outlasts the saturated backoff's own pacing), and the edge-triggering of the
  `warn` escalation.

- **`matter-controller`: correction to the record on the test-harness change.**
  The commit that introduced `keep_endpoint_open` described nine in-crate tests
  as "spinning a core each". Nine tests do fail without the harness change —
  that part is confirmed, and the change is required — but most of them never
  spun: several call sites drive `Actor` methods directly and never run the
  actor loop at all, so the broken transport was never polled there. Only
  `actor_stays_live_while_resolve_pends` was measured burning CPU: 2.21 s of
  user time over 2.22 s of wall clock before the fix, 0.31 s after it.

### Documentation / CI

- **Crate-level rustdoc rewritten to describe what each crate does, not how it
  was built.** The `//!` block at the top of `lib.rs` *is* the docs.rs landing
  page, and in eight crates it was still an internal milestone development log:
  phase bullets, `(current)` markers, and roadmap language. `matter-commissioning`
  was the worst — a 0.5.0 crate that has commissioned real hardware over Wi-Fi,
  Thread, and BLE opened with a changelog ending in "M6.6 (next-next): Tokio
  driver + first real-device commission". A reader arriving from crates.io could
  not tell which parts of the crate existed.

  Rewritten for `matter-commissioning`, `matter-cert`, `matter-clusters`,
  `matter-transport`, `matter-crypto`, `matter-codec`, `matter-bdx`, and
  `matter-interaction`, along with the commissioning `state_machine`, `driver`,
  and `clusters` module docs and the crypto `pase` / `case` module docs. Content
  was re-derived from each crate's own source, which surfaced four stale claims
  now corrected: `matter-interaction` advertised "no chunked writes" though
  `build_list_write_chunks` ships, and did not mention its server-side invoke
  surface; `matter-clusters` listed 43 of its 47 generated clusters and said a
  wildcard read API would "arrive in later milestones" when `matter-controller`
  already has one; `matter-cert` documented no issuance despite shipping
  `Builder` and the role-aware RCAC/ICAC/NOC constructors; and
  `Action::ReadAttribute` claimed to be emitted only by
  `Stage::ReadCommissioningInfo` when `Stage::ReadNetworkCommissioningInfo`
  emits it too. **No API change** — documentation only.

- **Crate READMEs swept for false capability claims.** The rustdoc rewrite above
  left several READMEs — the first thing crates.io renders — staler than the
  `lib.rs` beside them, and some understated the crate to a reader's face.
  `matter-interaction` was the worst: its "deliberate subset" paragraph denied
  batch invoke, wildcard paths, subscriptions, events, timed actions, and
  chunked writes, all six of which ship. `matter-cert` said "not yet on
  crates.io" at a version two minors behind and disclaimed issuance it has;
  `matter-crypto` called CASE resumption byte-parity "deferred" though
  `test-vectors/case/` carries the accepted and declined fixtures, and omitted
  the `operational`, `checkin`, and `aead` modules entirely; `matter-transport`
  was organised around internal phase numbering, claimed `mdns-sd` 0.13 (it is
  0.20), and never mentioned group framing; `matter-clusters` claimed every
  generated codec had a byte-parity oracle when coverage is deliberately tiered;
  `matter-codec` pointed at four sibling crates as "(future)" when all four are
  published; `matter-bdx` listed codecs for three messages it does not
  implement; and `matter-ble` called the macOS BLE failure "root cause unknown"
  after it was root-caused on hardware. Stale version banners and dependency
  lines were corrected against each `Cargo.toml`, and internal milestone
  numbering removed. **No API change** — documentation only.

- **Every README's Rust examples are now compiled by `just doctest`** (i.e. by
  `cargo test --workspace --all-features --doc`, which the gate and CI run).
  Each crate carries the standard idiom in its `lib.rs`:

  ```rust
  #[cfg(doctest)]
  #[doc = include_str!("../README.md")]
  struct ReadmeDoctests;
  ```

  `#[cfg(doctest)]` means the item exists only while rustdoc collects doctests,
  so the README is compile-checked without being duplicated into the rendered
  docs. The workspace-root README is attached to the unpublished
  `integration-tests` crate instead of a published one, because an
  `include_str!` reaching outside a crate directory breaks `cargo package`
  verification. **No API change** — this is documentation and CI hygiene.

  Motivation: [#111]. The reporter lost significant time to a quickstart in the
  `matter-controller` README that showed `MatterTime::from_unix_secs(0)` as a
  certificate `not_before`; commissioning then failed with an opaque
  `IM status 0x85`. The same README carried a `FabricConfig { .. }` struct
  literal that could not compile outside the crate at all (`FabricConfig` is
  `#[non_exhaustive]`). No README in this workspace had ever been compiled, so
  nothing caught either. Making the examples compile makes that class of bug a
  build failure.

  API drift the compiler surfaced and this change corrects:

  - Root README: `Node::subscribe` was shown with three arguments; it takes
    four (attribute paths, **event paths**, min interval, max interval).
    `AttestationTrust::csa_test_roots()` no longer exists — it is
    `example_device_roots()`.
  - `matter-crypto`: `PaseProver::new_with_negotiation` gained an
    `initiator_session_id`; `PaseVerifier::new_from_pin` gained a
    `responder_session_id`; `CaseInitiator::new` and `CaseResponder::new` both
    gained a `now: MatterTime`; `RingSigner::public_key` is reached through the
    `CaseSigner`/`Signer` trait.
  - `matter-commissioning`: `CommissionerConfig` gained the required `network`
    field (`NetworkCredentials`), and `Action` is `#[non_exhaustive]`, so the
    documented driver loop needs a catch-all match arm. That arm **returns
    `CommissioningError::InvalidConfig`; it does not panic.** `Action` is
    `#[non_exhaustive]` precisely so a future minor release can add a variant,
    and this loop is the driver skeleton integrators copy — a downstream driver
    meeting an unknown action must stay in control and disarm the failsafe on
    the device, not `unreachable!()` mid-commissioning with the failsafe armed.
  - `matter-cert`: the chain example bound `CertificateChain::new(&[noc, icac])`
    to a temporary that is dropped while still borrowed — it never compiled as
    written.

  Fences that perform I/O (networking, commissioning, file stores) are marked
  `no_run`: compiled, never executed. No fence is `ignore`.

  A review pass over the same READMEs corrected what the compiler cannot see:

  - **Stale version claims.** Every crate README's status line or dependency
    snippet now matches its `Cargo.toml`: `matter-crypto` 0.3, `matter-interaction`
    0.4, `matter-commissioning` 0.5, `matter-controller` 0.6, `matter-transport`
    0.3, `matter-bdx` 0.3, `matter-ota` 0.5, and `matter-ble` 0.3 — the last
    mattering most, since the snippet pinned `0.1`, predating the 0.3.1 D-Bus
    file-descriptor-leak fix.
  - **Trust roots.** The `matter-controller` quickstart — the page crates.io
    renders, and the document behind [#111] — now shows `AttestationTrust::from_dirs`
    with the caveat inline in the fence rather than `example_device_roots()` with
    the caveat in distant prose. The root README no longer claims the example
    roots verify *no* real device: they verify chip's example devices, including
    the esp-matter ESP32-C6 this project validates against nightly.
  - **Readability.** `FabricConfig::new(1, 1, 1, validity)` — three
    indistinguishable `u64`s — is now written with `/* fabric_id */`-style
    argument labels, and the `CommissionerConfig` fences show the `&` each
    borrowed field requires instead of hiding it in a `# fn run(…)` line a
    GitHub reader never sees.
  - `matter-bdx`, `matter-ble` and `matter-ota` gained an explicit
    `readme = "README.md"` manifest key. Cargo auto-detection already found the
    file, but `#[cfg(doctest)]` is stripped before `include_str!` expands, so a
    packaging change that dropped the README from the tarball would have
    published cleanly and broken only downstream `cargo test --doc`.

  [#111]: https://github.com/phunapps/matter-rust/issues/111

- **`matter-commissioning`'s README now describes the shipped crate instead of
  the milestone that was in progress when it was written.** The crates.io
  landing page still announced "Milestone 6.4 … complete" and "Next: M6.5
  (Wi-Fi network commissioning) and M6.6 (Tokio driver + first real-device
  commission)" — work that shipped long ago, along with all of M7–M9. Headings
  and prose were milestone-relative throughout ("Chain validation … is M6.2.2",
  "M6.4.4 will land the CSR / NOC issuance stages"), which is unreadable for
  anyone who has not read this repository's roadmap.

  The status block is replaced by a capability list (setup payloads,
  attestation, NOC issuance, the sans-IO state machine, the optional `driver`
  feature) plus a stability note and a pointer to `matter-controller` for
  callers who want a whole controller. Every internal milestone number is gone;
  where one was load-bearing it is restated as a capability. The previously
  undocumented `driver` feature now has its own section, explicit that
  `commission_ble` contains no Bluetooth stack. **Documentation only** — no API
  change, and the ten Rust fences are unchanged apart from four comments and one
  `unreachable!` message that named milestones.

### Changed

- **`p256` upgraded from 0.13 to 0.14** (`matter-crypto`, `matter-commissioning`).
  This moves the elliptic-curve library underneath SPAKE2+ (PASE) and
  CASE/SIGMA. It is a **library-API migration only** — the protocol logic is
  untouched. **No wire bytes, no derived keys, and no signatures change.** Every
  existing test vector passes unmodified: the Matter spec SPAKE2+ vectors, the
  matter.js byte-parity captures for PASE and CASE, and the chip-derived KATs.

  What actually changed at the call sites, and why each is a no-op:

  - `p256::EncodedPoint` → `p256::Sec1Point`, and the `FromEncodedPoint` /
    `ToEncodedPoint` traits → `FromSec1Point` / `ToSec1Point`. Renames only;
    0.14 keeps the old names as deprecated forwarders to the new ones.
  - `SecretKey::new(scalar.into())` → `SecretKey::from(scalar)`. In 0.13 the
    `From<NonZeroScalar>` impl *was* `SecretKey::new(scalar.into())`, so this is
    the same construction under the name that survived.
  - `Signature::normalize_s()` returned `Option<Signature>` in 0.13 (`Some` only
    when it flipped `s` to `n - s`) and returns `Signature` in 0.14, folding the
    already-low case in. `sig.normalize_s().unwrap_or(sig)` therefore becomes
    `sig.normalize_s()` with identical output — CASE signatures stay low-`s`, as
    matter.js produces them.
  - The SPAKE2+ `w0`/`w1` derivation reduces a 40-byte PBKDF2 output modulo the
    curve order `n`. `NistP256::ORDER` is now `Odd<U256>` rather than `U256` (same
    numeric value, dereferenced), `Uint::to_be_bytes` returns crypto-bigint 0.7's
    `EncodedUint` rather than a bare `[u8; 40]` (same big-endian bytes), and
    `Reduce::reduce` takes its argument by reference. The 320-bit intermediate is
    now spelled with crypto-bigint's own `U320` alias instead of a hand-written
    `Uint<5>` — literally the same type on 64-bit targets, and the width-correct
    one on 32-bit, where the hand-written `Uint<5>` would have been 160 bits and
    `from_be_slice`'s length assertion would have *panicked* on the 40-byte
    input (loudly, on the first PASE derivation — never a wrong-but-plausible
    scalar). This workspace builds for no 32-bit target today, so the swap is a
    no-op in practice. Big-endian interpretation, operand widths, and the final
    conditional subtraction are all unchanged; the derived `w0`/`L` bytes were
    re-checked against an independent `int.from_bytes(be, "big") % n` oracle in
    addition to the committed vectors.

  Randomness plumbing is unaffected. `p256` 0.14 pulls `rand_core` 0.10 (0.13
  pulled 0.6), but this workspace never uses `p256`'s RNG entry points — every
  scalar, nonce and keypair still comes from `ring::rand::SystemRandom` via the
  `NocRng` abstraction, and `rand_core` is not a direct dependency.

  **The ECDSA stack under CASE moved wholesale, not just `p256` itself**, and
  that is worth stating plainly because it is where the assurance has to come
  from: `rfc6979` 0.4 → 0.6 (the deterministic-nonce generator sitting directly
  under CASE signing), `sha2` 0.10 → 0.11 (the hash `Signer::sign` uses),
  `signature` 2 → 3, `sec1` 0.7 → 0.8, `pkcs8` 0.10 → 0.11, `hmac` 0.12 → 0.13,
  `hkdf` 0.12 → 0.13, `digest` 0.10 → 0.11, `crypto-bigint` 0.5 → 0.7, and
  `ff`/`group`/`primeorder` 0.13 → 0.14. Additionally
  `PublicKey::from_secret_scalar` — which produces every CASE ephemeral public
  key — changed internally from `generator() * scalar` to
  `ProjectivePoint::mul_by_generator(scalar)`. None of this is taken on trust:
  the matter.js byte-parity fixtures assert full hex equality of Sigma1
  (carrying the ephemeral public key in the clear), Sigma2 and Sigma3 (carrying
  the ECDSA signature inside TBEData under a deterministic key), so byte-equal
  messages imply a byte-equal `r‖s` and an unchanged nonce derivation.

- **Dependency-tree consequence:** the workspace now contains two RustCrypto
  generations side by side. `p256` 0.14 brings `der` 0.8, `const-oid` 0.10,
  `spki` 0.8, `crypto-common` 0.2 and `rand_core` 0.10, while `matter-cert`
  continues to use `der` 0.7 / `const-oid` 0.9 / `spki` 0.7. The two generations
  only ever meet at `&[u8]` boundaries — the sole adjacency is a `#[cfg(test)]`
  CSR path that hands a `Vec<u8>` to our own DER encoders — so this is a
  compile-time and binary-size cost, not a correctness one. `cargo deny` is
  content with the duplication. Unifying them is separate work, and it
  strengthens the case for the planned X.509 stack consolidation.

## 0.6.0

The first release driven by outside users. Every change here comes from issues
[#110], [#111] and [#112], filed by [@qwandor] within days of `0.5.0` — fabric
setup that was easy to get wrong in ways that failed far from the mistake, and
a cluster family the library had never generated. Nothing is breaking.

Crate versions in this release: **`matter-clusters` 0.4.0**,
**`matter-commissioning` 0.5.0** (dependency bump only),
**`matter-ota` 0.5.0** (dependency bump only), and **`matter-controller`
0.6.0**. Every other crate is unchanged from `0.5.0` and is not republished.

One behaviour change to be aware of before upgrading, detailed below:
`create_fabric` now **refuses** a `fabric_id` that already exists rather than
silently creating a duplicate. Code that called it unconditionally on every
startup — which the old quickstart in this repo demonstrated — must now gate on
`fabrics()` being empty.

[#110]: https://github.com/phunapps/matter-rust/issues/110
[#111]: https://github.com/phunapps/matter-rust/issues/111
[#112]: https://github.com/phunapps/matter-rust/issues/112
[@qwandor]: https://github.com/qwandor

Fixes from friction the first external adopter hit setting up a fabric, all on
`matter-controller`, plus the rest of the class each one belongs to. A validity
window that would produce a certificate a device installs but cannot use — a
`not_before` at the Matter epoch, one implausibly far in the future, an
already-expired `not_after`, an inverted or empty window — is now refused
locally, with an error that names the cause, instead of surfacing as an opaque
device-side failure later. Two known gaps remain, both documented on
`FabricConfig::validity`: a pre-2000 `not_after` clamps to `MatterTime(0)`,
which *is* `MatterTime::NO_EXPIRY`, so a units mistake there silently means
"never expires" and is indistinguishable from the intent; and on a host whose
clock is unset the two clock-relative checks cannot run at all (see below).

### `matter-controller`

#### Added

- **`MatterController::fabrics() -> Vec<FabricInfo>`** — a typed,
  snapshot-decoupled accessor mirroring `nodes()`. Returns each fabric's
  `fabric_id`, the controller's own `commissioner_node_id` on it, its
  commissioned node count, and whether it uses a 3-tier ICAC chain. Call it
  before `create_fabric` to check which fabrics already exist (#110). Note the
  distinction from `Node::list_fabrics`, which reads the *device's* fabric
  table over the wire; both rustdocs now cross-reference the other.
- **`Error::SystemClockUnset(u64)`** — a new variant (the `Error` enum is
  `#[non_exhaustive]`, so this is additive) returned when this host's wall
  clock reads before the Matter epoch.

#### Fixed

- **`create_fabric` now refuses to create a fabric whose `fabric_id` already
  exists**, returning `Error::FabricAlreadyExists` instead of silently
  pushing a duplicate `FabricEntry` (#110). The duplicate previously broke
  `sole_fabric()` addressing — every subsequent read/write/commission failed
  with an opaque "multiple fabrics" error — which is exactly what the
  reporter hit: `create_fabric` called unconditionally on every startup,
  including runs that loaded an existing fabric from the store. This is a
  **behaviour change**: a caller that (incorrectly) relied on repeat
  `create_fabric` calls being silently idempotent now gets an error back;
  gate the call on `fabrics()` being empty, or on a fresh store, as the
  crate's examples, README and rustdoc quickstart now show. The error also
  says how to recover (use the existing fabric, pick a different `fabric_id`,
  or start from a fresh store — there is no local fabric-removal API).
- **`create_fabric` validates `FabricConfig::validity` up front** and returns
  `Error::InvalidFabricValidity` instead of letting a bad window surface deep
  in commissioning as an opaque `IM status 0x85` on
  `AddTrustedRootCertificate` (#111). Rejected: a `not_before` at the Matter
  epoch (`MatterTime(0)` / `MatterTime::from_unix_secs(0)`) — the reporter's
  evidenced failure — and an inverted or empty window
  (`not_after <= not_before`). `MatterTime::NO_EXPIRY` for `not_after` remains
  valid regardless of `not_before`. `FabricConfig::validity` and
  `FabricConfig::new` now document what to pass, including the exact cause:
  chip's `ChipEpochToASN1Time`
  (`connectedhomeip/src/credentials/CHIPCert.cpp`) re-encodes epoch 0 as
  `99991231235959Z` for both `notBefore` and `notAfter`, so the X.509 TBS a
  device rebuilds from our TLV certificate differs from the one we signed and
  the *signature* check fails — chip's own comment says such certificates
  "are not usable with this code".
- **`create_fabric` also refuses a `not_before` more than 24 h ahead of this
  host's clock.** Same failure class as #111, worse consequence: the most
  common time-unit mistake — a *millisecond* timestamp passed to
  `MatterTime::from_unix_secs` — saturates to `MatterTime(u32::MAX)`
  (≈ 2136), and with `not_after = NO_EXPIRY` the ordering check exempts it.
  Such a root is not rejected by the device: `ValidateChipRCAC` deliberately
  skips RCAC validity times, so `AddTrustedRootCertificate` *succeeds*, the
  fabric half-commissions, and every CASE session afterwards fails with
  `kNotYetValid` with nothing naming the cause. The tolerance is one day —
  callers are told to backdate `not_before`, never to postdate it, so any
  forward gap is pure clock disagreement.
- **`create_fabric` also refuses an already-expired `not_after`.** The exact
  symmetric twin of the case above — the same `ValidateChipRCAC` exemption
  means an expired root installs just as happily, and every CASE session then
  fails with `kExpired` on the commissioner NOC instead of `kNotYetValid`. The
  route in is a `(not_before, not_after)` pair copied from an older document:
  the ordering check passes, `not_before` is in the past so the upper bound
  passes, and nothing else compared `not_after` to the present.
  `MatterTime::NO_EXPIRY` remains exempt (it is numerically `MatterTime(0)`,
  which would otherwise read as "expired in 2000").
- **An unset host clock is refused where it does damage.**
  `current_matter_time()` builds on `MatterTime::from_unix_secs`, which
  saturates any pre-2000 reading to `MatterTime(0)` — so a host with no RTC
  that had not yet reached an NTP server (a very plausible embedded
  deployment) minted **device NOCs** with `notBefore == 0` during
  commissioning, hitting the identical chip TBS-signature failure as #111 one
  stage later, at `AddNOC`. Commissioning and operational CASE now return the
  new `Error::SystemClockUnset`, naming the unset clock, instead of minting a
  certificate that cannot work. **`create_fabric` deliberately does not fail
  on this**: it mints from `FabricConfig::validity` alone and needs no clock,
  so an unusable clock only means its clock-relative checks are skipped (with
  a `tracing` warning) — an RTC-less board that creates its fabric during init
  with a known-good window and syncs NTP seconds later keeps working. The
  clock-independent checks still run there, so the epoch-zero `not_before`
  that such a host produces if it derives one from `SystemTime::now()` is
  still rejected — and the error names the unset clock as the likely source.

#### Documentation

- The crate rustdoc quickstart (the docs.rs landing page), the crate README
  quickstart, `docs/matter-js-migration-guide.md`, and the two multi-admin
  runbooks all demonstrated one or both of the fixed anti-patterns
  (unconditional `create_fabric`, `MatterTime::from_unix_secs(0)`). They now
  gate on `fabrics()` and derive `not_before` from the real clock, backdated
  an hour for device clock skew, rather than passing a magic constant. The
  migration guide's snippet additionally built `FabricConfig` with a struct
  literal (illegal outside the crate since it became `#[non_exhaustive]`) and
  omitted `.await`; both fixed.
- `FabricConfig::validity` now also warns that `from_unix_secs` clamps a
  pre-2000 time to `MatterTime(0)`, which *is* `MatterTime::NO_EXPIRY` — so a
  units mistake in `not_after` silently means "never expires".
- The per-crate `crates/matter-controller/CHANGELOG.md` (stale since M8.1, but
  shipped inside the published crate) now redirects to this file.

### `matter-clusters`

#### Added

- **The concentration measurement cluster family (Matter 1.2) — 10 new
  generated modules**, reported missing by `qwandor`, the project's first
  external adopter, in [#112]: `CarbonMonoxideConcentrationMeasurement`
  (0x040C), `CarbonDioxideConcentrationMeasurement` (0x040D),
  `NitrogenDioxideConcentrationMeasurement` (0x0413),
  `OzoneConcentrationMeasurement` (0x0415), `Pm25ConcentrationMeasurement`
  (0x042A), `FormaldehydeConcentrationMeasurement` (0x042B),
  `Pm1ConcentrationMeasurement` (0x042C), `Pm10ConcentrationMeasurement`
  (0x042D), `TotalVolatileOrganicCompoundsConcentrationMeasurement` (0x042E),
  and `RadonConcentrationMeasurement` (0x042F). The issue named two; all ten
  are here because they *derive from one base cluster* and therefore share a
  single shape — shipping a subset would only invite the follow-up issue. Every
  id and name was verified against the pinned `@matter/model` 0.17.1 dump, not
  from memory. They were never absent from the data model, only from the
  codegen allowlist, so this is a purely additive regeneration: no existing
  cluster's generated code changed, and `@matter/model` stays pinned at 0.17.1.
  All attributes are read-only, so the modules expose decoders (and the three
  `MeasurementUnitEnum` / `MeasurementMediumEnum` / `LevelValueEnum` enums, the
  feature bitflags, and the attribute-id constants) but no encoders.
- These clusters bring the **first float attributes** in the crate
  (`MeasuredValue`, `Min`/`Max`/`Peak`/`AverageMeasuredValue`, `Uncertainty`
  are all `single` → `f32`), which required teaching the generator to emit
  floats at all — see *xtask (codegen)* below. Tested with a per-cluster
  decode-smoke, a matter.js byte-parity vector for the FLOAT32 wire encoding
  (`test-vectors/clusters/carbon_dioxide_concentration_measurement/`), an
  explicit wire round-trip over the binary32 edges (signed zero, the smallest
  normal and the smallest subnormal, both infinities, NaN — all compared by
  bits, since `NaN != NaN` and `0.0 == -0.0` would let a value-equality test
  lie), and a `proptest` round-trip drawn uniformly from the whole binary32 bit
  space. Because these attributes are `single`, their decoders accept a FLOAT32
  element only; a FLOAT64 in the same attribute is a type error, and that is
  pinned by a test.

[#112]: https://github.com/phunapps/matter-rust/issues/112

### xtask (codegen)

#### Added

- **The cluster code generator can now emit float attributes and fields.**
  `single` and `double` already mapped to `f32`/`f64` on the *type* side, but
  the codec emitter had no `float` arm on either the read or the write
  dispatch, so a float element fell through to the unsigned-integer path —
  emitting `w.put_uint(tag, u64::from(<f32>))`, which does not compile. Both
  dispatches now emit width-matched TLV calls (`Value::Float`/`put_float` for
  `single`, `Value::Double`/`put_double` for `double`), including the nullable
  and list-element forms. No cluster in the model had a float attribute until
  now, so this path had never been exercised; it is the reusable part of the
  concentration-measurement work below.
- **Which wire widths a float decoder accepts now follows chip's `TLVReader`
  exactly** (`src/lib/core/TLVReader.cpp`). A `single` decoder takes a FLOAT32
  element and rejects a FLOAT64, matching the strict `Get(float&)`; a `double`
  decoder takes FLOAT64 *or* FLOAT32 (widened losslessly), matching the lenient
  `Get(double&)`. matter.js is lenient in both directions — `TlvFloat` and
  `TlvDouble` are one `TlvType.Float`, the width being an encode-time choice —
  so where the two references disagree we take the stricter, since device
  firmware is overwhelmingly built from chip. Note this is unlike the *integer*
  arms, which are width-flexible: `TlvReader` folds UINT8..UINT64 into a single
  `Value::Uint(u64)` (and INT8..INT64 into `Value::Int(i64)`), so one pattern
  matches any encoded width and the range check is `try_from`. The `double`
  leniency changes no generated code today — no cluster in the pinned model has
  a `double` attribute — and is recorded so the first one that does inherits
  the reference behaviour rather than a stricter guess.

#### Changed

- **An unsupported metatype is now a hard generator error rather than a silent
  fallthrough.** The `_ =>` arms in the scalar read/write emitters previously
  defaulted to an unsigned-integer codec for *any* unrecognised metatype,
  which either failed to compile or — worse — compiled and encoded the value
  wrongly. `cargo xtask codegen` now panics with the offending metatype and
  type name. No currently generated cluster reached the fallthrough, so the
  generated tree is unchanged by this.

## 0.5.0

The performance & memory remediation release: five phases from the 2026-08-09
whole-workspace audit, landed one phase at a time, each hardware-validated
against a real ESP32-C6 before the next began. **It is not only a performance
release** — phases 1 and 3 fixed correctness bugs that only a real chip stack
exposed (multi-chunk writes violating MRP's one-outstanding-message rule, a
sticky `MoreChunkedMessages` parse, persisted state that could roll backwards,
one unresolvable node freezing every other session). Nothing in it is
breaking; the recorded breaking items stay parked for a future deliberate
breaking release.

Crate versions in this release: **`matter-codec` 0.3.0**, **`matter-cert`
0.3.0**, **`matter-crypto` 0.3.0**, **`matter-transport` 0.3.0**,
**`matter-interaction` 0.4.0**, **`matter-clusters` 0.3.0** (dependency bump
only), **`matter-commissioning` 0.4.0**, **`matter-bdx` 0.3.0**, **`matter-ota`
0.4.0** (dependency bump only), **`matter-ble` 0.3.2** (internal only — no API
change), and **`matter-controller` 0.5.0**.

Three things to read before upgrading, all detailed in their crate sections
below: consumers who already build `matter-controller` with
`default-features = false` must add `features = ["ota"]` to keep the OTA
provider API; `FabricEntry::outbound_group_counter` changed *meaning* (same
type, same encoding — it is now a reserved ceiling, not the next counter to
send); and `matter-interaction` now hands back a command's `fields_tlv` as the
device's verbatim bytes.

Controller-liveness performance phase 1: nothing on the actor's `select!` loop
may block on I/O that is not the thing the loop is there to do. Four changes,
all internal to the controller's actor loop; the two API-surface notes they
carry are listed under `#### Changed` below.

Packet-crypto performance phase 2: no key schedule and no key derivation is
recomputed per packet when its inputs cannot have changed. **No wire bytes
move** — every known-answer vector (chip's privacy frame, the matter.js group
and session vectors) is unchanged and is what pins this. The only new public
API is `matter_crypto::aead::SessionAead` and the two additive group-framing
variants below; everything else is internal caching.

Algorithmic performance phase 3: no O(n²) loop and no per-event linear scan on
a hot path. **No wire bytes move** — the chunked-write byte-identity tests, the
CASE/matter.js vectors, and the chip check-in KAT pin every change. The only
new public API is the additive `Session::peer_addr` routing hint in
matter-transport; everything else is internal.

Chunked-write chip-parity fixes (found by phase 3's live hardware validation —
the multi-chunk write path's first-ever contact with a real chip stack): the
two entries under `matter-controller` → *Fixed* and `matter-interaction` →
*Fixed* below. One of them deliberately moves multi-chunk wire bytes; the
"no wire bytes move" claim above is about the phase-3 performance changes,
which these two fixes are not part of.

Codec zero-copy performance phase 4: swap the TLV reader's owned-tree walk
for a borrowed, zero-copy streaming walk (`ValueRef`/`ElementRef`/
`next_ref`), and adopt it through `matter-interaction`'s report/invoke parse
paths so a report no longer allocates one member `Vec` per parsed item just
to discard most of it. **No wire bytes move** — the golden TLV vectors, the
IM byte-parity tests, and the chunk byte-parity tests are all unchanged and
are what pins this; `matter-codec`'s next publish is an additive MINOR (new
public API only, nothing removed or retyped).

**Validation for this phase (Task 10) caught a real, reproducible decode-side
regression against the `pre-phase4` criterion baseline** — exactly the risk
the phase-4 spec itself flagged ("`next()` now routes through `next_ref` —
watch for regression here specifically"). At its peak
`decode/report_170attr_64B` went 25.67 µs → 64.64 µs (+152%), every other
decode bench moved +45% to +186%, and `matter-interaction`'s streaming report
parse regressed with it (`parse_report_data/170attr_64B` +78%). Each delta was
re-run 2-3 times (including at low system load, to rule out contention) and
held: the absolute point estimates moved by the same multiple as the
percentages. Root cause was two things, separated by ablation: the
tree-builder still drove `next()`, so every materialised element was built
into an owned `Element` and immediately destructured again; and marking the
relocated decode core `#[inline]` changed the inlining context of the private
per-element decode helpers, which LLVM then stopped inlining, so each element
paid a real call per decode step. **Both were fixed inside this phase** — the
tree-builder now consumes the borrowed walk directly and converts
`ValueRef` → `Value` at push time, and `#[inline]` is restored on the helpers.
Final numbers vs `pre-phase4`: `parse_report_data/170attr_64B` 19.36 µs →
17.35 µs (−10.6%, i.e. the streaming-parse win the phase was for now shows
through), four of the six decode benches at or below baseline, and
`decode/report_170attr_64B` within +4.5% — that residual is attributed to the
per-element span bookkeeping this phase added, on a shape that is ~1700
mostly-empty container elements; the remedy (cheaper span fields) is known and
deliberately deferred rather than made without a measurement to justify it.
Fuzz smoke (`fuzz_decode`, 200k runs) is clean — no crashes, and no
correctness issue was ever in play here.

The writer's header-batching work in this phase is a deliberate trade, and
worth stating plainly: realistic message shapes won
(`encode/report_170attr_64B` 5.51 µs → 4.59 µs, −17%; `encode/nested_30deep`
−11%) while tiny-element synthetic microbenches regressed 12-19%
(`encode/struct_500_uint`, `encode/array_2000_uint`,
`encode/array_1000x32B`). Matter traffic is report- and
command-shaped, not thousand-element flat arrays, so the batching stays —
documented here rather than left for someone to rediscover in a baseline diff.

Memory & platform performance phase 5: reduce copies and idle wakeups outside
the hot decode/encode path — one shared image allocation instead of one per
OTA send, one BlueZ D-Bus query instead of one per BLE advertisement, and an
actor loop that parks on a computed deadline instead of polling four times a
second. **No wire bytes move** — every byte-parity suite (the BDX loopback
reassembly tests, the CASE/PASE matter.js vectors, the IM message-level
byte-parity tests) is unchanged and is what pins this; the one exception is
CASE peer-chain validation, which changes *how* the peer's NOC/ICAC are held
in memory (move + `swap_remove` instead of clone) but not the bytes validated
or signed. New public API is additive only —
`matter_bdx::BlockSender::from_shared`, `matter-controller`'s default-on
`ota` feature, and `matter-ble`'s `MATTER_BLE_SCAN_TRACE` diagnostic — so the
next publish is a MINOR for `matter-bdx`, `matter-controller`, `matter-ble`,
`matter-crypto`, `matter-cert`, `matter-interaction`, and `matter-codec`.

This phase's first task also folded in the phase-4 hygiene batch left over
from that phase's validation pass: reader/writer test gaps around
`next`/`next_ref` parity and `skip_container` span/depth bookkeeping, two
doc clarifications (see `matter-codec` → *Changed* below), the
`matter-interaction` accumulator single-lookup refactor (see below), and a
`matter-clusters` proptest generator fix — its `node_label_roundtrip`
strategy generated raw `0x1F` (the IS1 localized-string separator), which
`matter-codec`'s decoder deliberately truncates at by design. That was a
generator defect, not a codec bug, and is fixed by excluding `0x1F` from the
generated character set.

Bench validation against the pre-phase5 baseline (Task 14): `report_parse`
and codec decode/encode are unmoved (encode/report slightly improved —
`encode/report_170attr` −0.7%/−2.5%), and CASE handshake benches are unmoved
once re-measured on a quiet machine — a first, contended run of
`case/full_handshake` showed a spurious +10.2% that vanished on rerun
(654 µs vs. a 637 µs baseline, +1.5%, within noise), judged by interval
width rather than the point estimate, per this project's established bench
discipline (see the phase-4 paragraph above for where that discipline was
first written down). The actor's idle timer-wake count over a 60 s window
with zero subscriptions went from 239 (the old fixed 250 ms tick) to 0.

### `matter-controller`

#### Added

- **New default-on `ota` feature** (`ota = ["dep:matter-ota", "dep:matter-bdx"]`,
  `default = ["ota"]`) gating `serve_ota` / `serve_ota_with_block_size` /
  `serve_ota_once` / `announce_ota_provider`. The default build surface is
  unchanged — this is purely additive for consumers who build with the crate
  defaults. It is **not** additive for anyone who already sets
  `default-features = false`: that combination used to still yield the full
  API (there was no `default` key to opt out of), and now silently sheds
  `serve_ota` / `serve_ota_with_block_size` / `serve_ota_once` /
  `announce_ota_provider` along with the `matter-ota` and `matter-bdx`
  dependencies. Such consumers must add `features = ["ota"]` to keep the OTA
  provider API. A new `controller-no-ota` CI job builds, tests, and doc-checks
  the crate with `--no-default-features` so the gated surface can't silently
  rot.

#### Fixed

- **A device whose operational mDNS record never appears no longer stalls every
  other session.** `spawn_connect` polled the resolver inline on the actor loop,
  so one unresolvable node froze all traffic — other sessions' verbs, MRP
  retransmits, subscription liveness — for the full ~30 s discovery budget. The
  connect now parks and is settled from the existing timer arm, one shared
  `_matter._tcp` browse and one drain per tick. Drained records are cached
  (bounded, TTL-aged) so a record that arrives before its resolve parks is not
  lost, and the browse is released when the controller shuts down.
- **Resubscribe entries whose consumer is gone are reaped instead of retried
  forever.** A `PendingResubscribe` whose subscription handle had been dropped
  could never be observed again, yet kept churning reconnects on backoff and
  leaking its entry. It is now dropped at both retry points, which are the
  places that reliably observe the closed channels.
- **A stale best-effort snapshot save can no longer clobber newer persisted
  state.** Detached best-effort saves could be descheduled behind a later
  durable save and then win the store's atomic rename, rolling persisted state
  backwards. Every save now carries its serialize-time sequence and shares a
  per-controller write gate; an out-of-order job is skipped.
- **Chunked writes now gate each chunk on its `WriteResponse`** instead of
  pipelining every chunk back-to-back on one exchange. MRP permits one
  outstanding reliable message per exchange, so the pipelined chunks rode on
  retransmit timing: against a real Thread device the write reported success
  while later chunks were still in flight, and the device's half-fed write
  transaction answered subsequent writes with `Busy` until it timed out.
  Each chunk's response is now parsed and its statuses accumulated (chip's
  `WriteClient` pumps every chunk regardless of element statuses, and so do
  we); a message-level `StatusResponse` rejection or a malformed response
  aborts with an error instead of feeding chunks into a closed transaction.

#### Performance

- **Group sends no longer fsync the whole snapshot per message.** The persisted
  outbound group counter now holds a reserved *ceiling* rather than the
  last-sent value, so 64 group sends cost one store write instead of 64. The
  replay-protection invariant is unchanged and enforced by test: a restart
  resumes at the ceiling — skipping at most a block of never-sent counters, and
  never reusing a counter that was sent. This is the design chip uses
  (`GroupPeerMessageCounter.cpp`), with a smaller block (64 vs chip's 1000).
- **Group key material is derived once per fabric, not once per message.**
  Every `invoke_group` re-ran four HKDFs — compressed fabric id, operational
  group key, group session id, and (inside the framing layer) the privacy key —
  although all four are a pure function of the fabric's epoch key. They are now
  cached per fabric and invalidated by comparing the epoch key on every send, so
  a rotated key set (`create_group` / `KeySetWrite`) still re-derives before
  anything goes out under it. Covered by a test that rotates the epoch key and
  asserts the next frame decrypts under the NEW key and not the cached one.
- **Steady-state reports route to their subscription in O(1).** `deliver_report`
  scanned every live subscription per report; a secondary index keyed by
  `(session, wire subscription id)` — maintained by the only two helpers allowed
  to mutate the subscription map — replaces the scan. A non-compliant device
  that reuses a subscription id on one session cannot poison the index: the
  first owner keeps the key (the old scan's graceful degradation, kept
  deliberately) and index keys are only ever removed by the entry they map to.
- **MRP retransmit routing no longer triple-scans per timer event.**
  `peer_for_session` walked subscriptions, pending ops, and the session cache
  on every retransmit/ack; the peer address is now stamped on the transport
  session at registration (see `matter-transport` below) and read O(1), with
  the old scan kept only as a fallback for unstamped sessions.
- **The OTA provider holds one `Arc<[u8]>` image and hands out cheap handles
  instead of cloning the whole image.** `serve_ota_once` previously cloned
  the full image `Vec<u8>` into every `BlockSender::new` call — once per
  `QueryImage`, and again on every cross-session BDX re-arm — so a large
  image was copied end-to-end on each new download attempt. It now wraps the
  image once (`Arc::from(image)`) and hands out `Arc::clone` handles via
  `matter_bdx::BlockSender::from_shared` (see `matter-bdx` below);
  `image.len()` and every other read-only use is unaffected via `Deref`.
- **The actor now parks on a computed timer deadline instead of waking
  4×/s.** The idle tick previously fired every 250 ms unconditionally; it
  now parks on the minimum of MRP retransmit/ack-flush, subscription
  liveness, scheduled resubscribes, and — only while an mDNS resolve is
  parked — a 250 ms resolve-polling anchor, falling back to a 1-hour
  backstop when nothing is outstanding. Measured idle timer wakeups over a
  60 s window with zero subscriptions: 239 → 0. The resolve-polling anchor
  is deliberately an **absolute** instant, re-armed each time it's
  consulted, rather than a relative `now + tick` recomputed every loop
  iteration — a relative tick is starvable, since any other `select!` arm
  firing faster than the tick pushes the deadline forward forever, which
  would silently stall mDNS discovery under a report flood. A hung test
  (spinning ~793k iterations without ever expiring its parked resolve)
  caught the relative version before it shipped.
- **`Node::write` and `Node::invoke_tlv` build the timed-variant payload
  lazily instead of always pre-encoding it.** Both actions used to TLV-encode
  a plain request *and* its timed variant up front and hand both to the
  actor, even though the timed one is only consumed on two rare paths (a
  learned-timed cache hit, or a `0x00D9` / `0xc6` `NEEDS_TIMED_INTERACTION`
  escalation). The timed payload is now a boxed `FnOnce() -> Vec<u8>` builder
  invoked only on those two paths; the common case (plain write/invoke
  accepted) no longer pays for a second encode it discards. Wire bytes on the
  timed-escalation path are unchanged — the builder calls the same
  `build_write_request_timed` / `build_invoke_request_timed` functions with
  the same inputs, just later.

#### Changed

- **`FabricEntry::outbound_group_counter` changed MEANING** (the type and the
  snapshot encoding are unchanged). It used to hold the next counter to send;
  it now holds the reserved *ceiling*, which may sit up to a block above the
  last counter actually sent. No migration is needed — the pre-change value is
  the smallest never-sent counter, which is exactly a valid ceiling — but code
  reading this field as "how many group messages were sent" will over-report.

### `matter-commissioning`

#### Changed

- `preferred_address` is now `pub` (was crate-internal), so the controller's
  timer-driven resolve picks the same address the inline resolver did.

### `matter-transport`

#### Added

- `encode_group_secured_with_privacy_key` / `decode_group_secured_with_privacy_key`
  — the group framing functions with the privacy key supplied by the caller
  instead of derived per packet. Additive: the existing
  `encode_group_secured` / `decode_group_secured` derive the key and delegate,
  so there is one encode path and one decode path, and their behaviour is
  byte-identical (the chip privacy vector and the matter.js plain-frame vector
  both still pass). Use them when you hold a long-lived group key set: derive
  once with `matter_crypto::derive_group_privacy_key` and cache it.

#### Performance

- **One AES-CCM key schedule per session instead of one per packet.** Each
  `Session` now caches the ciphers for its two directional keys, built on first
  use. Session keys never change once a session is registered (Matter re-keys by
  establishing a new session), so the cache needs no invalidation — and a debug
  build now asserts that, tripping if `keys` is ever mutated out of crate via
  `SessionManager::get_mut` while a cipher is cached.
- **Outbound secured frames are allocated at their final size**, so the header
  + ciphertext no longer forces a reallocation and copy on every send.

### `matter-crypto`

#### Added

- `aead::SessionAead` — an AES-CCM handle that owns its key schedule, so a
  caller holding a long-lived key (a session, a group key set) computes the
  schedule once and encrypts/decrypts many packets against it. The free
  `aead::encrypt` / `aead::decrypt` functions are unchanged; this is purely an
  additional way to reach the same cipher, and the same primitive
  implementation underneath.

#### Performance

- **CASE TBS signatures are verified over the peer's received NOC/ICAC bytes.**
  `TbeData2`/`TbeData3` now keep the raw certificate TLV exactly as it arrived,
  and Sigma2/Sigma3 signature verification feeds those bytes into the signed
  data instead of re-serializing the parsed certificates. This removes two
  encodes per handshake — and, more importantly, removes the assumption that
  our `to_tlv` re-encodes a peer's certificate byte-identically (chip and
  matter.js also sign over received bytes). Trust decisions are unchanged:
  chain validation still runs on the parsed certificates, and the verifying key
  is still taken from the chain-validated NOC.
- **Check-in decode drains its counter prefix in place** instead of copying the
  application payload into a second allocation.
- **SPAKE2+ constant points M and N are decoded once, not once per handshake
  call site.** `M_POINT` / `N_POINT` are now `LazyLock<ProjectivePoint>`
  statics computed on first access instead of re-running a SEC1 decode plus
  point decompression (a modular square root) at each of `compute_x` /
  `compute_y` / `compute_z_v_prover` / `compute_z_v_verifier`. A pin test
  asserts both statics equal a fresh `point_from_spec_bytes` decode; the
  transcript path still hashes the raw constant bytes, so nothing the
  handshake transcript depends on changes.
- **CASE transcript hashing feeds each message slice to one
  `ring::digest::Context` instead of concatenating into an intermediate
  buffer first.** Byte-identical because the transcript is pure
  concatenation with no length or version prefixes between messages —
  pinned by the existing `transcript_hash_single_message_matches_sha256`
  guard test, which compares the incremental result against `ring`'s
  one-shot `digest()` on the same bytes.
- **CASE peer-chain validation moves the peer's NOC/ICAC into the validation
  `Vec` instead of deep-cloning them, and takes the NOC back out with
  `swap_remove(0)`** (index 0 because the NOC is always pushed first) in
  both `process_sigma2` (initiator) and `process_sigma3` (responder). Trust
  decisions, chain order, and every failure path (`InvalidPeerNocChain`,
  `PeerNodeIdMismatch`, `FabricIdMismatch`, `PeerSignatureInvalid`) are
  unchanged — the bytes validated and later read are identical, just moved
  instead of copied. A second, smaller clone on the CASE session-resumption
  path was investigated and deliberately left in place: removing it would
  need a public, dummy-constructible `MatterCertificate` that `matter-cert`
  doesn't expose (no `Default`, no public fields, no cheap constructor
  reachable outside the crate), and adding one just to shave a cold-path
  clone wasn't judged worth the new public API surface on a
  certificate-parsing crate. Recorded as a candidate follow-up:
  `ResumptionRecord.peer: Arc<PeerInfo>` would make it an `Arc::clone` at the
  cost of a breaking field-type change, deferred to its own task.
- **CASE and PASE message encoders (`Sigma1`/`Sigma2`/`Sigma2Resume`/
  `Sigma3`, `PbkdfParamsInner`/`PbkdfParamRequest`/`PbkdfParamResponse`,
  `Pake1`/`Pake2`/`Pake3`) now start their output buffer at a computed
  capacity** instead of `Vec::new()`, sized from known field lengths (fixed
  constants plus `self.field.len()` where the payload is variable). No wire
  bytes change — capacity is purely a reservation hint, and the byte-parity
  / matter.js vector suites pin the encoded bytes.

### `matter-cert`

#### Performance

- **Trust-anchor verification computes the top certificate's TBS-DER once**,
  not once per candidate anchor. Behavioural note: a top certificate whose
  X.509 conversion fails now surfaces that conversion error from
  `CertificateChain::validate` instead of falling through to `UntrustedRoot`
  (no previously-valid chain changes outcome; the error is strictly more
  precise).
- **`MatterCertificate::to_tlv` starts its output buffer at
  `Vec::with_capacity(512)`** instead of growing from empty. No wire bytes
  change.

### `matter-codec`

#### Added

- `ValueRef`/`ElementRef`/`TlvReader::next_ref` — a zero-copy streaming walk
  over borrowed input; `TlvReader::next` is now implemented on top of
  `next_ref` rather than the other way around. See the phase-4 paragraph
  above for the decode-side regression this routing initially introduced and
  its same-phase fix.
- `ElementSpan`/`element_span`/`skip_container_span`/`span_bytes` — a
  two-form span contract (the full span including the tag/length header, and
  the body-only span) that discharges the exact-byte `RawElement` promise
  documented on `Value`, for callers that need to re-emit an element with its
  original width preserved.

#### Changed

- `skip_container` is now an allocation-free raw walk instead of building and
  discarding an owned `Value` tree. **Skipped (unobserved) string data is no
  longer UTF-8 validated** — a deliberate loosening (perf spec §4.1); this is
  intentional and future differential tests must not flag it as a
  divergence.
- The writer now batches element headers into a stack buffer and reserves
  capacity ahead of copying string payloads, instead of writing header bytes
  one field at a time.
- `#[inline]` added to a short list of cross-crate hot functions. This is not
  limited to trivially small ones: the decode core itself (`next_ref` and its
  `read_value_body_ref` helper) is inlined, which is what the regression fix
  described above turned on.
- Reader rustdoc now states explicitly that reader position and depth are
  unspecified after a **failed** `skip_container` / `skip_container_span` —
  callers should discard the reader rather than continue from it.
  `ElementSpan`'s contract doc gained a third bullet documenting the
  `ContainerEnd` span shape (1-byte full span, empty body). Doc-only; no
  behaviour changed.

### `matter-interaction`

#### Fixed

- **Multi-chunk `WriteRequest`s now carry `MoreChunkedMessages` explicitly on
  every chunk — including an explicit `false` on the final one.** chip's
  `WriteHandler` initialises the flag from the previous chunk's value before
  parsing, so an *absent* field on the final chunk inherits `true` and the
  device waits for more chunks until its transaction times out (observed live
  against an ESP32-C6; chip's own `WriteClient` always encodes the flag).
  This deliberately changes multi-chunk wire bytes (+2 bytes on the final
  chunk); the old bytes never worked against a chip stack. Single-message
  writes are unchanged and remain byte-identical to `build_write_request`.

#### Performance

- **`skip_container` streams past discarded sub-trees** instead of collecting
  them into an owned `Value` tree. Skipped (unobserved) payload is structurally
  validated but never retained — a peer can no longer force full
  materialisation of fields we throw away. Skipped containers are bounded by
  input size rather than the tree-builder element budget (which this path, as
  a pure streaming walk, never charged in its current form).
- **Chunked list writes are packed with incremental size accounting.**
  `build_list_write_chunks` re-encoded the whole candidate chunk for every
  element it considered (O(n²) in elements per chunk); it now derives the
  per-element cost once and packs in one pass, with one real encode per emitted
  chunk. Output bytes are identical for every input — the previous
  implementation is retained as a test oracle and a property test pins
  equivalence across random element sets. A new `write_chunks` micro-bench
  documents the win (100×64 B elements: −86% multi-chunk, −98% single-chunk).
- **The report accumulator's element-cap check folded into the map's vacant
  arms**, so pushing a new attribute key now costs one `HashMap` lookup
  instead of two — the old top-of-loop `contains_key` pre-check duplicated
  the lookup that `entry()` / `get_mut()` / `insert()` already perform. Same
  `AccumulatorOverflow` error, same fields, cap still enforced before insert;
  a new pin test (`element_ceiling_is_enforced_for_append_new_key`) covers
  the branch whose check moved.
- **IM request/response builders now start their output buffer at a computed
  capacity** instead of `Vec::new()` — `build_read_request_full`,
  `build_write_request_inner`, `build_invoke_request_inner` /
  `build_invoke_request_batch`, `build_invoke_response_command` /
  `build_invoke_response_status`, `build_subscribe_request`,
  `build_status_response`, `build_timed_request`. No wire bytes change; the
  IM byte-parity suites pin it.

#### Changed

- Attribute, command, and event report parsing is now a streaming walk over
  `matter-codec`'s zero-copy reader — no member `Vec` allocated per report
  item just to be read once and dropped. This path initially inherited the
  codec's decode-side regression along with the adoption; with that fixed in
  the same phase it is a net win — `parse_report_data/170attr_64B` 19.36 µs →
  17.35 µs (−10.6%) vs `pre-phase4`. See the phase-4 paragraph above.
- **Invoke `fields_tlv` is now the peer's original `CommandFields` bytes,
  verbatim, under a fresh anonymous tag** (span-copy + retag) rather than a
  decode-then-re-encode round trip. Preserved integer widths are the visible
  part; the blob is no longer normalised at all, which has three further
  consequences. (1) A localized-string suffix (element type `0x1F`, IS1) now
  survives in the blob instead of being dropped by the re-encode; decoded
  `Value`s are unchanged, because the downstream decoder still truncates at
  the IS1 separator. (2) Invalid UTF-8 inside `CommandFields` is no longer
  rejected at IM parse time — the copy never validates it, so it surfaces from
  the consumer's own decoder instead. This is the same class of deliberate
  loosening as this phase's skip change, and future differential tests must
  not flag it as a divergence. (3) An off-spec `Array` `CommandFields` whose
  children carry non-anonymous tags is now copied through as-is and fails in
  the consumer's decoder with `NonAnonymousArrayTag`, where the old
  decode-then-re-encode path silently normalised those tags away. Only the
  wire bytes matter-interaction itself produces here are affected, and only
  when re-emitting a peer's own fields.
- `read_container_value` is now kind-aware: arrays build `Vec<Value>`
  directly instead of routing through the generic struct/list path.
- The chunked-report accumulator now merges into a single map slot per
  attribute instead of separate value and data-version maps.

### `matter-bdx`

#### Added

- `BlockSender::from_shared(image: Arc<[u8]>, max_block_size: u16)` — an
  additive constructor that shares one image allocation across every
  `BlockSender` built from it, instead of each one owning its own copy.
  `BlockSender::new(image: Vec<u8>, max_block_size: u16)` is unchanged and
  now delegates (`Arc::from(image)`); every existing call site keeps
  compiling and behaving identically.

#### Performance

- **`handle_block_query` builds the block payload directly** —
  `counter.to_le_bytes()` followed by the image slice, into one pre-sized
  `Vec` — **instead of copying the slice into a `Vec` and then encoding a
  `DataBlock` from it.** The per-block double copy is gone. Wire bytes are
  byte-identical — the loopback roundtrip suite (multi-block, exact-multiple,
  single-block, provider-cap-wins) pins reassembly, and a new
  `from_shared_serves_without_copying_the_image` test additionally samples
  `Arc::strong_count` right after `from_shared` and again after the transfer's
  `BlockAckEOF`, pinning it at 2 (image + sender's clone) at both ends — no
  copy made.
- `TransferInit::encode` / `ReceiveAccept::encode` / `SendAccept::encode` now
  start their output buffer at a computed capacity instead of `Vec::new()`.
  No wire bytes change.

### `matter-ble`

#### Added

- `MATTER_BLE_SCAN_TRACE=1` (or `true`) emits one `[ble-scan]` line per real
  BlueZ name query, for diagnosing scan behaviour on real hardware. Off by
  default and side-effect-free when unset; a distinct env var and prefix
  from the existing pump-scoped `[btp-pump]` tracing.

#### Performance

- **Nameless peripherals no longer cost a BlueZ D-Bus properties round trip
  per advertisement.** `CommissionableScan` previously re-queried a
  peripheral's name on every single advertisement it observed; a device
  advertising 2-10×/s was re-queried indefinitely. Negative lookups (device
  has no name yet) are now cached with a 10 s TTL; positive lookups persist
  for the scan's lifetime, since a name legitimately can't un-arrive once
  seen. `FoundDevice::local_name` semantics are unchanged — a name can still
  arrive in a later scan response, which is exactly why the negative cache
  entry expires instead of sticking permanently.

## matter-ble 0.3.1

A single-crate hotfix release: only `matter-ble` is republished.

### `matter-ble`

#### Fixed

- **D-Bus connection leak on Linux — one leaked fd per `BleCentral::new()`,
  eventually a system-wide BLE outage.** btleplug's Linux backend opens a new
  D-Bus system-bus connection per `Manager::new()` (`bluez-async`
  `BluetoothSession`), whose connection-owning task is detached and can never
  be aborted — dropping the central does not close it. Constructing a central
  per scan/commission therefore climbed monotonically toward dbus-daemon's
  256-connections-per-user cap, after which **every** process's BLE on the
  host failed ("No buffer space available", `bluetoothctl` SIGABRT) until the
  consumer process was restarted. Observed live on a Pi hub after ~45 minutes
  of periodic scans. `BleCentral::new()` now lazily initializes one
  process-wide shared btleplug session (adapter + the scan refcount, which
  must span all centrals now that they share one radio) and every subsequent
  construction reuses it: the fd count stays flat no matter how consumers
  construct centrals. First-call semantics are unchanged (macOS TCC prompt
  still fires on first use; a failed first init is retried, not cached). The
  adapter identity is now cached for the process lifetime — hot-replacing the
  only Bluetooth adapter requires a process restart (same guidance
  `bluez-async` gives for a lost D-Bus connection).

## 0.4.1

A WeaveHome-dogfooding follow-up batch: a continuous BLE scan API (safe to run
alongside an in-flight commission), a scoped BLE connect retry, and two
commissioning hardening fixes. Crate versions in this release:
**`matter-ble` 0.3.0** (breaking — the `FoundDevice` change below),
**`matter-commissioning` 0.3.1** (bug fixes; patch-bumps-on-bug-fixes rule,
no exceptions), and **`matter-controller` 0.4.1** (additive API on top of
`0.4.0`). All other crates are unchanged and not republished.

### `matter-ble`

#### Added

- `BleCentral::scan_commissionables()` — a continuous, unfiltered scan
  returning a `CommissionableScan` stream that yields every observed
  commissionable advertisement (no discriminator filter, no dedup — the same
  device yields again on every advertising interval; consumers own
  windowing/dedup by `peripheral_id`). Safe to hold across a concurrent
  commission: the radio scan is now refcounted across every scan user on a
  `BleCentral` (`start_scan`/`stop_scan` fire only on the 0→1 / 1→0
  transition), so a live enumeration scan and an in-flight `find_device` no
  longer fight over the adapter. `find_device` is now a thin,
  discriminator-filtered wrapper over the same stream.
- `FoundDevice::local_name` — best-effort BLE local name from the peripheral's
  cached advertisement properties (populated on `find_device` and cached
  per-device inside `CommissionableScan`; may be `None` on first sighting
  since names often arrive in a later scan response than the first
  service-data advertisement).

#### Changed (breaking)

- `FoundDevice` is now `#[non_exhaustive]` (carries the new `local_name`
  field).
- `CentralError::ServiceDiscovery(String)` is a new variant, split out of what
  was previously reported as `Connect`: GATT service-discovery exhaustion
  (the documented macOS `uuidNotAllowed` stall) is not the transient failure
  `Connect` represents. `matter-controller`'s new BLE connect retry (below)
  keys on `Connect` specifically so it doesn't double a ~25 s known-hopeless
  discovery timeout. `CentralError` was already `#[non_exhaustive]`.

### `matter-commissioning`

#### Fixed

- `NetworkConfigResponse::debug_text` / `ConnectNetworkResponse::debug_text`
  are now capped at the spec's 512-octet bound at decode (floors to a UTF-8
  char boundary rather than panicking mid-char). Both are device-echoed free
  text and were previously unbounded.
- `CommissioningError::NetworkRejected`'s `Display` now renders `debug_text`
  capped at 64 characters with an ellipsis instead of the full (still
  512-byte-capped) string; the field itself is unchanged for deliberate
  consumers. Semi-public behavioral change — matches the `RemediationHint`
  stability precedent (rendered text is not covered by semver, the typed
  field is).

#### Pinned

- `CommissioningError::NetworkFeatureUnsupported`'s rendered wording
  (`"does not support {needed:?} network type"`) is now locked by a
  regression test: WeaveHome substring-matches it to route Wi-Fi-only devices
  off an automatic Thread path. Reword only in coordination with WeaveHome;
  new consumers should prefer the typed
  `matter_controller::Error::network_feature_unsupported()` below.

### `matter-controller`

#### Added

- `Error::network_feature_unsupported() -> Option<NetworkKind>` — typed
  access to a `NetworkFeatureUnsupported` commissioning failure (which
  network type the supplied credentials required), so callers can route on
  the error without substring-matching the rendered message. `NetworkKind` is
  now re-exported from `matter-commissioning`.
- New non-optional `tracing` dependency (`0.1`, `default-features = false`,
  `std` feature only) — logs the BLE connect retry below.

#### Changed

- `commission_ble` now retries a BLE **connect** failure once before
  surfacing it: transient local aborts (e.g. BlueZ
  `le-connection-abort-by-local`) routinely succeed on an immediate retry,
  and no BTP state exists yet so a full re-open is safe. Scoped to
  `CentralError::Connect` only — a `ServiceDiscovery` failure (the
  known-hopeless macOS stall) still surfaces immediately.
- README status line corrected to **0.4.0** (was stale at 0.3.0).

## 0.4.0

A 1.0-readiness pass over the public surface (from a freeze-readiness review),
plus a real-hardware interop fix from WeaveHome dogfooding. Published so WeaveHome
can dogfood the latest. Crate versions in this release: **`matter-controller`
0.4.0**, **`matter-interaction` 0.3.0** (the breaking `#[non_exhaustive]` change),
and **`matter-commissioning` 0.3.0** / **`matter-ota` 0.3.0** (dependency bump
only — they now require `matter-interaction` 0.3.0, no source change). The other
lower crates are unchanged at `0.2.0`.

### `matter-controller`

#### Fixed

- **Timed auto-upgrade now fires when a device reports the requirement
  per-command / per-attribute.** The transparent retry-as-timed only triggered
  on a message-level `StatusResponse(NEEDS_TIMED_INTERACTION, 0xc6)`. Shipping
  door locks (e.g. eufy E31) return `0xc6` as a `CommandStatusIB` inside an
  `InvokeResponse` (or an `AttributeStatusIB` inside a `WriteResponse`) instead,
  so timed-required commands (`DoorLock` lock/unlock, any T-quality command)
  failed against them. Detection now covers all three delivery forms. Behaviour
  fix (semver-patch); reported via WeaveHome dogfooding.

#### Changed (breaking)

- Public field-structs `TimeZoneEntry`, `DstOffsetEntry`, and `AttributeReport`
  are now `#[non_exhaustive]` (with `TimeZoneEntry::new` / `DstOffsetEntry::new`
  constructors) so future fields stay non-breaking.
- The low-level provider server — `ProviderServer`, `build_operational_service`,
  and `MatterController::serve_provider_once` — moved behind a new
  **`unstable-provider`** feature (not covered by semver). The stable OTA path,
  `MatterController::serve_ota` / `serve_ota_with_block_size`, is unchanged.
- `Node::open_commissioning_window_with` (7-arg caller-supplied-secrets variant)
  is now `pub(crate)`; use `Node::open_commissioning_window`.
- Raw private-key material is no longer on the public surface: the PKCS#8 fields
  on `FabricEntry` / `CommissionerIdentity` / `IcacIdentity`, and the
  `rcac_signer` / `commissioner_signer` / `to_fabric_record` methods (which
  returned concrete `RingSigner` / `FabricRecord`), are now `pub(crate)`.
- The redundant top-level `create_fabric` free function is no longer re-exported
  (`MatterController::create_fabric` is the API), and the `snapshot` module
  (`serialize` / `deserialize` / `SNAPSHOT_VERSION`) is now `pub(crate)`.

### `matter-interaction`

#### Changed (breaking)

- `ReadPath`, `EventPath`, and `EventFilter` are now `#[non_exhaustive]` so the
  spec's optional path/filter components (e.g. a data-version filter) can be
  added without a break. All construction already goes through their
  constructors; `ReadPath::new(endpoint, cluster, attribute)` is added for the
  raw-optional case. The concrete `CommandPath` / `AttributePath` are left as
  plain structs — spec-complete 3-field addressing types that cannot grow.

## 0.3.0

A `matter-controller` API batch driven by the WeaveHome integration. Only
`matter-controller`'s public API changes (one breaking change); the other
crates are untouched at the API level.

### `matter-controller`

- **BREAKING — `commission()` / `commission_ble()` return `NodeInfo`, not
  `u64`.** Both also take a new `label: Option<String>` argument. The returned
  [`NodeInfo`] carries `node_id`, `fabric_id`, `vendor_id`, `product_id`, and
  the caller-supplied `label`. `vendor_id`/`product_id` are captured
  **best-effort** via a post-commission `BasicInformation` read (endpoint 0,
  cluster `0x0028`, `VendorID` `0x0002` + `ProductID` `0x0004`) — a failed read
  never fails a completed commission; the ids stay `None` and can be re-read
  later. The `label` is persisted atomically with the device entry.
- **`MatterController::nodes() -> Vec<NodeInfo>`** — typed enumeration of every
  commissioned node across all fabrics, so integrators no longer deserialize the
  on-disk snapshot to discover node ids and metadata.
- **`MatterController::forget_node(node_id) -> Result<bool>`** — drops ALL of
  the controller's own local state for a node (device entry, cached CASE
  session, resumption data, live subscriptions, and connect bookkeeping)
  **without contacting the device**. Reclaims a node that is unreachable or
  already factory-reset, where `remove_fabric` (which needs the device to
  cooperate) cannot run. Returns `true` if a node was removed, `false` if none
  matched.
- **`Node::invoke_tlv(path, fields_tlv)` and `Node::invoke_timed_tlv`** — invoke
  a command with **pre-encoded** TLV fields (e.g. the `Vec<u8>` returned by
  `matter_clusters::gen::<cluster>::encode_<command>()`), skipping the
  decode-then-re-encode round trip through `Value`. `invoke()`/`invoke_timed()`
  now delegate to these.
- **Clearer `Error::NoTrust`** — the message now names the concrete fix
  (`builder().attestation_trust(AttestationTrust::from_dirs(paa, cd))`), so a
  controller opened via `MatterController::open()` (no trust) gets an actionable
  error at commission time instead of a bare "no attestation trust configured".
- New persisted `DeviceEntry` fields `vendor_id`/`product_id`/`label` (snapshot
  device-struct tags 4/5/6, additive + optional — pre-0.3.0 stores load
  unchanged, defaulting the three to `None`; the snapshot version is not
  bumped).

## 0.2.0

The first release after `0.1.0`. Bundles a security-remediation batch (from a
connectedhomeip test-coverage gap analysis) with a set of intentional breaking
changes.

### Security & correctness (all crates)

- **Attestation (ATT-1/ATT-6):** enforce the Matter attestation-certificate
  profile (version, signature algorithm, `KeyUsage` bits, `BasicConstraints`,
  SKID/AKID) in our own code — `rustls-webpki` ignores `KeyUsage`; the docs
  claiming otherwise are now true. New `verify_attestation_cert_format`, run by
  the commissioner before `verify_chain`.
- **Attestation (ATT-3):** `example_device_roots()` now bundles chip's real test
  CD authority + CSA production key 001 alongside the synthetic root, so it
  actually verifies real CSA-test / example devices (incl. the ESP32-C6).
- **Attestation (ATT-2):** enforce the CD `authorized_paa_list` (tag 11) against
  the anchoring PAA's SubjectKeyIdentifier.
- **Transport (TRAN-1):** decide the MRP duplicate-ack only *after* decrypt, so
  an unauthenticated replay can no longer emit an ack or burn a counter.
- **Transport:** bound the session table (default 256) with **idle-first**
  eviction — a full table drops a session with no in-flight reliable work
  before one mid-exchange (tie-break oldest) — closing the unbounded-`HashMap`
  DoS without tearing down an active handshake.
- **Transport (MRP-1/MRP-2):** size MRP retransmits to the *peer*, not our own
  transmit timing. The active/idle base is chosen from whether the peer has
  been active within its Session Active Threshold — re-evaluated on every
  retransmit (chip `GetMRPBaseTimeout`) — and the per-session intervals come
  from the peer's advertised operational mDNS `SII`/`SAI`/`SAT`
  (`MrpConfig::for_peer`, `MatterService::peer_mrp_config`,
  `resolve_operational_with_mrp`, `SessionManager::register_case_with_mrp`).
  Stops us hammering a sleepy/ICD device with active-interval spacing it never
  polls fast enough to see.
- **Commissioning:** cap the requested `ArmFailSafe` expiry at the device's
  `BasicCommissioningInfo::MaxCumulativeFailsafeSeconds`, so we never
  round-trip an expiry the device is guaranteed to reject with `BoundsExceeded`.
- **CASE (CASE-1):** test coverage for peer-signature rejection (the auth line).
- **Codec (CODEC-1):** truncate char strings at the IS1 (`0x1F`) localized-string
  separator (matches chip/matter.js).
- **Commissioning (SETUP-1):** reject out-of-range Base38 QR chunks instead of
  silently truncating.
- **Interaction (IM-1/IM-3):** surface read-path `AttributeStatus` IBs; apply the
  `DataVersion` guard to list `Append`.
- **OTA/BDX (BDX-1..4):** send BDX blocks MRP-reliable, resend the ack on a
  duplicate `BlockQuery`, send/receive `StatusReport`, and track a progress vs
  iteration budget + a Thread block-size path.

### Added — operational cert construction & opt-in ICAC

- **`matter-cert`:** a public role-aware operational-certificate API,
  `matter_cert::operational::{rcac, icac, noc}` (each returns an
  `UnsignedCertificate` pre-filled with the Matter §6.5 profile for that role),
  plus `sign_with_ring` for the in-process case. The signer-agnostic flow
  (`build → tbs_der() → sign externally → assemble`) supports HSM/offline
  custody. New `RcacParams`/`IcacParams`/`NocParams` (`#[non_exhaustive]`).
- **`matter-commissioning`:** `issue_icac` (RCAC-signed intermediate CA);
  `issue_noc` refactored onto `operational::noc` so the §6.5 NOC profile lives
  in one place, and now signs the NOC under the fabric's ICAC when the fabric
  carries one (flat RCAC→NOC output is byte-for-byte unchanged, golden-guarded).
  `AddNOC` transmits the ICAC (`ICACValue`, spec §11.18.5.9) for 3-tier fabrics.
- **`matter-controller`:** opt-in per-fabric ICAC via `FabricConfig.issue_icac`
  (default `false`); the issued ICAC cert + key persist in the fabric snapshot
  (new optional tags) and restore into the operational identity, so a 3-tier
  fabric's CASE sessions present the full RCAC→ICAC→NOC chain. New
  `IcacIdentity`; additive `FabricEntry.icac`.

### Changed — behaviour

- **CASE forward-compatibility:** the Sigma1/Sigma2/Sigma2Resume/Sigma3 decoders
  now accept and ignore unknown TLV fields (matching chip) instead of rejecting
  them, so a future device revision that adds a spec-optional field stays
  reachable.

### Breaking

- **Renamed** `AttestationTrust::csa_test_roots` →
  `example_device_roots`, and `{PaaTrustStore,CdSigningRoots}::with_csa_test_roots`
  → `with_example_device_roots`.
- **Removed** the unused `CommissioningError::WifiCredentialsRequired` variant.
- **Added** `verify_certification_declaration_with_paa` (the old
  `verify_certification_declaration` delegates to it), a `paa_skid` field on
  `ChainVerification`, and `AttestationError::{CertFormatViolation,
  CertificationDeclarationPaaNotAuthorized}` (additive; enums are
  `#[non_exhaustive]`).

## matter-codec

### [0.1.1] — M9-A

#### Added

- `TlvReader::skip_container()` — drains the body of an already-opened
  container through its matching end. Enables forward-compatible decoders
  that skip unknown nested containers from newer Matter revisions. Additive
  (non-breaking); satisfies dependents' existing `^0.1.0` requirement.

## matter-ble

### [Unreleased] — M9-C1 crate created: BTP engine + BLE central role

#### Fixed

- **The macOS `CoreBluetooth` GATT hangs are now bounded to a clean failure.**
  On macOS, `discover_services()`, the C1 handshake write, and the C2 subscribe
  could each hang forever: btleplug 0.12.0 drops any errored `CoreBluetooth`
  delegate event (its handlers gate on `error.is_none()`), and `CoreBluetooth`
  rejects the `CHIPoBLE` characteristics' descriptor discovery and C1 write with
  `CBError.uuidNotAllowed`. The three previously-unbounded awaits now have
  timeouts (service discovery 12 s × 2, C1 write 12 s, pre-connect disconnect
  2 s), so the flow fails fast with a clear error instead of stalling past every
  commissioning deadline. **Known limitation (deferred):** this does not make
  macOS BLE commissioning *succeed* — the `uuidNotAllowed` write rejection is an
  upstream btleplug/`CoreBluetooth` issue (and the same rig's macOS `chip-tool`
  hits an equivalent GATT-write failure), so live BLE commissioning stays
  Linux-only. Root-cause writeup under `docs/superpowers/audits/`.
- **BLE scanning never worked on Linux/`BlueZ`.** `BleCentral::find_device`
  passed a service-UUID `ScanFilter` to btleplug; `CoreBluetooth` honours it,
  but the `BlueZ` backend goes silent under it — no service-data events and an
  empty `peripherals()` — so every scan on Linux found nothing while macOS
  worked. The scan is now unfiltered; the Matter service UUID was already
  matched in our own code, so the filter only ever cost portability. Found by
  the first live commission (a Raspberry Pi could not see a device sitting
  inches away that macOS found instantly).
- **The BTP handshake could never complete against a real device** (all
  platforms). We subscribed to C2 before writing the C1 capabilities request.
  chip's peripheral stashes its response and only indicates it when the
  subscribe arrives (`BLEEndPoint::HandleSubscribeReceived`), and requires the
  endpoint to already be in `kState_Connecting` with a non-empty send queue —
  the state the request establishes. Subscribing first is rejected as
  `CHIP_ERROR_INCORRECT_STATE`, leaving the queued response with nothing to
  trigger it: the device went silent for exactly the 15 s handshake timeout.
  The C1 request is now written before subscribing. The local `notifications()`
  stream still opens first (it emits no CCCD and the peripheral cannot observe
  it), preserving the anti-drop property. Not reachable by the loopback test,
  which drives our own `BtpSession` as the peer and accepts either order.

#### Added

- **New crate `matter-ble`** — Matter BLE commissioning transport. Always
  compiled: the sans-IO BTP (Bluetooth Transport Protocol) core —
  commissionable-advertisement parsing (`advert`), the handshake
  request/response codec (`handshake`), and `BtpSession` (RX reassembly +
  TX segmentation, window/ack-timeout accounting, sequence wraparound) —
  proven byte-for-byte against chip's `TestBleLayer`/`TestBtpEngine` vectors
  and dual-grounded hand-encodes (`test-vectors/btp/`).
- **`central` feature** (opt-in; pulls `btleplug` pinned `=0.12.0`, plus
  `tokio`, `uuid`, `futures`) — `BleCentral`: scan for a commissionable
  device by discriminator, connect, discover the C1/C2 GATT characteristics,
  and pump a `BtpChannel` (continuous `notifications()` drain feeding
  `BtpSession`, strictly-serialized C1 writes, disconnect detection). Needs
  a Tokio runtime (`Manager::adapters()` panics outside one). Off-CLAUDE.md-list
  deps `uuid`/`futures` are confined to this optional feature (flagged for
  review per the M9-C1 design).
- **macOS TCC handling** — `BleCentral::new()` explicitly checks
  `adapter_state() == PoweredOn` and returns an error pointing at
  `docs/runbooks/ble-commissioning.md` rather than silently finding no
  devices (a known `btleplug` gap on an unauthorized/undecided permission).

## matter-clusters

### [Unreleased] — M9-D2 OperationalCredentials cluster

#### Added

- **`OperationalCredentials` cluster (0x003E) generated** into
  `matter_clusters::gen::operational_credentials` — typed attribute/command/struct
  codecs for the full cluster surface: `FabricDescriptorStruct` (root public key,
  vendor id, fabric id, node id, label, fabric index), `NOCSStruct`, and
  `NocStatus` enum. Command codecs cover `AttestationRequest`/`Response`,
  `CertificateChainRequest`/`Response`, `CSRRequest`/`Response`, `AddNOC`,
  `UpdateNOC`, `UpdateFabricLabel`, `RemoveFabric`, `AddTrustedRootCertificate`,
  and `OpenCommissioningWindow`/`OpenBasicCommissioningWindow`. Total cluster
  count: **33 → 34**.

### [Unreleased] — M7.4b generated clusters, M7.3 foundation

#### M7.4b — generated cluster modules (the 10 M7 clusters)

- The 10 target clusters are generated into `matter_clusters::gen` (typed
  attribute/command/struct codecs + feature/datatype enums & bitmaps), proven
  **byte-parity** against the matter.js 0.16.11 `test-vectors/clusters/`
  vectors, with proptest roundtrips and a `cargo-fuzz` target on the weekly
  schedule. `SemanticTagStruct` global added (`Descriptor.TagList`).
  Generator fixes: datatype-aware enum/bitmap codecs (correct backing width;
  bare `enum8`/`status` as plain integers), struct encode, and list decode.
  `cargo xtask codegen --check` now gates codegen drift in CI.

#### M7.3 — hand-written foundation for generated code

- `Nullable<T>` (distinct from `Option`) and `ClusterError` (no
  `InvalidEnumValue` — unknown enum discriminants decode to `Unknown(n)`).
  Adds the `bitflags` dependency for generated bitmaps. The generated cluster
  modules themselves land in M7.4.

## xtask (tooling)

### [Unreleased] — M7.5 trace-diff write + onoff oracle, M7.4a capture-clusters, M7.3 codegen, M7.2 dump-model

#### M7.5 — operational trace cross-verification tooling

- `cargo xtask trace-diff` now decodes IM `WriteRequest` (0x06) /
  `WriteResponse` (0x07): named in the verdict table and aligned on their
  `(cluster, attribute)` target like reads, so an extra write on one side
  cannot mis-pair.
- `xtask/scripts/capture-onoff-trace/`: matter.js sibling of
  `capture-commission-trace` that continues past commissioning — connects and
  runs the same read/toggle/read + NodeLabel write/read the Rust
  `control_onoff` example does, capturing the operational dialogue as the
  trace-diff oracle. Same `@matter` 0.17.1 pins; operator-run (needs a device).

#### M7.4a — `capture-clusters`: cluster byte-parity vectors

- `cargo xtask capture-clusters`: encodes a curated set of cluster attribute
  values and command requests with matter.js 0.16.11 TLV combinators into
  `test-vectors/clusters/`, covering the type matrix (scalars, enum, bitmap,
  struct, lists, nullable, optional). The frozen oracle the generated cluster
  codecs are byte-parity-tested against in M7.4b. A `serde_json` freeze test
  gates the vectors in CI (no Node).

#### M7.3 — cluster code generator (`cargo xtask codegen`)

- `xtask/src/codegen/`: `model.rs` (typed `clusters.json` + strict
  validation — unknown types, duplicate IDs, dangling `responseId`),
  `rustgen/types.rs` (type mapping + identifier helpers),
  `rustgen/emit.rs` + `emit_codecs.rs` (string-building emitter for the
  uniform per-cluster module shape). `cargo xtask codegen [--check]`
  regenerates clusters into `matter-clusters`. A golden test compiles the
  generator's output for a synthetic fixture against the crate, proving it
  emits valid Rust; a smoke test confirms all 10 real clusters generate
  rustfmt-valid source. (The real generated modules are committed in M7.4,
  gated by byte-parity.)

#### M7.2 — `dump-model`: frozen codegen input (`clusters.json`)

#### M7.2 — `dump-model`: frozen codegen input (`clusters.json`)

New `cargo xtask dump-model` subcommand: walks the pinned `@matter/model`
0.17.1 standard data model and emits `xtask/model/clusters.json` — the
frozen input the M7.3 codegen will consume for `matter-clusters`.

##### Added

- `xtask/scripts/dump-model/` — Node script (pins `@matter/model` exact,
  the spec-revision pin) allowlisted to the 10 M7 target clusters. Records
  each cluster's local attributes, request/response commands, enum/bitmap/
  struct datatypes, and features in a flat JSON contract.
- Dump-time exclusions, each recorded in the header with a reason (no
  silent caps): provisional, deprecated, disallowed, and DoorLock
  Aliro-feature-gated elements (an AST-based `ALIRO`/`ALBU` filter — the
  "DoorLock limited" realization), events, and the six global attributes.
- `xtask/tests/clusters_json_freeze.rs` — a `serde_json` freeze test that
  gates the committed `clusters.json` in CI (reads the JSON; no Node).

## matter-interaction

### [Unreleased] — M9-D3 chunked list-write (B4)

#### Added

- **`build_list_write_chunks(path, element_tlvs, budget, timed) -> Vec<Vec<u8>>`** —
  the general chunked list-write mechanism (B4). Greedily packs pre-encoded element
  TLVs into `WriteRequestMessage` frames, emitting the first frame as a
  `ReplaceAll` (partial list, replaces everything seen so far) and subsequent
  frames as `AppendItem` requests, all with `MoreChunkedMessages` set on every
  frame except the last. When all elements fit a single frame the output is a
  single-element `Vec` whose bytes are **byte-identical** to
  `build_write_request(&[AttributeWriteRequest { path, value_tlv: <full-array> }])`,
  so the single-chunk path carries no overhead. An empty `element_tlvs` yields a
  single empty-array `ReplaceAll`. Accepts a caller-supplied `budget` (maximum
  frame size in bytes) and a `timed` flag that propagates to the `TimedRequest`
  header field.

### [Unreleased] — M9-B1 event reads, M9-B2 event subscribe, M9-B3 timed interactions, M9-B5 multi-command invoke

#### Added

- `event` module: `EventPath` / `EventFilter` (encode `EventPathIB` as a TLV
  list, `EventFilterIB` as a TLV struct — both byte-parity-verified against
  matter.js), and `EventReport` / `EventReportItem` / `EventPriority` /
  `EventTimestamp` with `EventReportIB` / `EventDataIB` / `EventStatusIB`
  parsing.
- `read::build_read_request_full(attr_paths, event_paths, event_filters)` —
  `ReadRequest` carrying event paths/filters (`EventRequests[1]` /
  `EventFilters[2]`). `build_read_request_paths` now delegates to it
  (byte-identical for attribute-only reads).
- `ReportData` gains `events: Vec<EventReport>` (populated from
  `eventReports[2]`); `ReportData::new` stays 4-arg (events default empty —
  no caller ripple).
- `SubscribeRequest` gains `event_paths` / `event_filters`;
  `build_subscribe_request` emits `EventRequests[4]` / `EventFilters[5]`
  (byte-parity vs matter.js; attribute-only requests stay byte-identical).
- `matter-controller`: `Node::read_events(paths, filters)` (M9-B1) over the
  chunked-read transaction; event types re-exported. **M9-B2:**
  `SubscriptionEvent::Event(EventReport)` and a **breaking**
  `Node::subscribe(attrs, events, min_interval, max_interval)` — one
  subscription carries attributes and events; event reports are delivered as
  they arrive (bypassing the chunked-attribute reassembler) and the
  auto-resubscribe engine re-requests the same events.
- **M9-B3 timed interactions:** `build_timed_request` (`TimedRequest`, opcode
  `0x0a`), `build_write_request_timed` / `build_invoke_request_timed` (the
  `TimedRequest` flag), and `parse_status_response` — all byte-parity vs matter.js.
  `matter-controller`: plain `Node::write`/`invoke` transparently handle timed
  attributes/commands — on a `NEEDS_TIMED_INTERACTION` rejection they retry as a
  timed interaction and remember the path in a learned cache (so later ops skip
  the wasted plain attempt; covers manufacturer clusters, no codegen). Explicit
  `Node::write_timed`/`invoke_timed` (`TIMED_DEFAULT_MS = 10s`) force the timed
  path. The `TimedRequest` and the Write/Invoke ride one exchange (chip-faithful).
- **M9-B5 multi-command invoke (wire-level):** `build_invoke_request_batch` (one
  `CommandDataIB` per command, each with a sequential `CommandRef` at tag 2) and
  `parse_invoke_response_batch` → `Vec<InvokeResponseEntry>` (each carrying its
  `CommandRef` for matching). Byte-parity vs matter.js. The single-command
  `build_invoke_request`/`parse_invoke_response` are unchanged. **Deferred:** the
  controller-side `Node` batch verb + `MaxPathsPerInvoke` SessionParameters
  plumbing land when a device advertising `MaxPathsPerInvoke > 1` exists to
  validate against (a batch >1 is non-conformant otherwise).

### [Unreleased] — M7.1 crate created (IM lift + Write support)

#### M7.1 — Interaction Model framing lifted out of matter-commissioning

New crate (`0.1.0-pre`): the `im` module moved here as a file-move (the
M6.6.1 design kept it free of state-machine dependencies for exactly this).
`matter-commissioning` re-exports it as `im`, so existing import paths are
unchanged — its full test suite passes with zero test edits.

##### Added

- `write` module: `build_write_request` / `parse_write_response` —
  `WriteRequestMessage` builder and `WriteResponseMessage` parser with
  per-path `AttributeStatusIB` statuses (success included). Concrete paths
  only; no timed, chunked, or wildcard writes (M7 scope).
- `path` module unifying `CommandPath` + `AttributePath`.
- Container helpers (`expect_message_struct`, `read_container_members`,
  `read_container_value`, `skip_container`) promoted to `pub` — the
  commissioning driver consumes them across the crate boundary.
- xtask `capture-im`: captures IM invoke/read/write byte-parity fixtures
  from matter.js 0.16.11 into `test-vectors/commissioning/im/`. The
  invoke/read parity tests promised in M6.6.1 now assert against real
  fixtures (previously they skipped); write fixtures were captured before
  `write.rs` was implemented (vectors before code).

##### Changed

- One commissioning-driver match gained a wildcard arm: `ImStatus`'s
  `#[non_exhaustive]` now binds across the crate boundary; unknown status
  variants map to generic FAILURE (0x01), never success.

## matter-controller

### [Unreleased] — M9-C2 `commission_ble` Thread support

#### Changed

- **BREAKING (pre-release):** `MatterController::commission_ble(setup_code,
  wifi: WiFiCredentials)` is now `commission_ble(setup_code, network:
  matter_commissioning::NetworkCredentials)`. `NetworkCredentials` is an
  enum (`WiFi(WiFiCredentials)` / `Thread(ThreadDataset)` /
  `AlreadyOnNetwork`), so a Wi-Fi caller updates by wrapping its existing
  `WiFiCredentials` in `NetworkCredentials::WiFi(..)`. All callers are
  ours (examples + the actor spawn) and are already updated. See
  `docs/runbooks/c2-thread-commission.md` for the Thread call shape.

### [Unreleased] — M9-C1 `commission_ble`

#### Added

- **`MatterController::commission_ble(setup_code, wifi)`** (feature `ble`,
  pulls in `matter-ble`'s `central` role) — commissions a factory-fresh
  Wi-Fi device over BLE/BTP: scans by discriminator, opens a BTP session,
  and drives the full pre-operational sequence over BLE before completing
  the operational CASE handshake over IP once the device joins Wi-Fi.
  `wifi: matter_commissioning::WiFiCredentials` is required — a BLE-only
  Wi-Fi device with no network credentials to install is unprovisionable.
  Requires the one-time macOS Bluetooth permission (TCC) — see
  `docs/runbooks/ble-commissioning.md`.
- **`examples/ble_scan.rs`** (feature `ble`) — a hardware/permission
  diagnostic: sweeps all 16 short-discriminator nibbles for answering
  commissionable devices. Gated behind `MATTER_BLE_LIVE=1` so it never
  touches Bluetooth (and never raises the TCC prompt) in a default run or
  CI; this is also the one-time flow used to grant the macOS Bluetooth
  permission itself.

### [Unreleased] — multicast interface builder option

#### Added

- **`MatterControllerBuilder::multicast_interface(if_index: u32)`** — sets
  the IPv6 multicast egress interface for group commands (`invoke_group`):
  the transport binds with `IPV6_MULTICAST_IF` and group destinations carry
  the scope id. On a multi-homed host the kernel default has no route for
  the admin-local `ff35:` group address ("No route to host") without it.
  The `MATTER_MULTICAST_IF` env var remains as a compat fallback when the
  builder option is unset (promoting the M9-E3 stopgap to a real API).

### [Unreleased] — multi-session OTA provider

#### Added

- **`serve_ota` runs a sequential session loop** backed by a **4-entry
  credential pool** (first session + post-reboot session + retry slack, per
  spec). Each accepted CASE session is served with its own credential entry,
  and the loop continues until the requestor sends `NotifyUpdateApplied`.
- **Per-session resumption record persistence via sink** — each accepted
  session's fresh `ResumptionRecord` is immediately stored (best-effort, off
  the serve loop via `tokio::spawn`) through the provider server's
  `record_sink`. A failed store only costs the fast path on the next connect.

#### Changed

- **BREAKING (pre-release):** `serve_ota` now completes when the requestor
  sends `NotifyUpdateApplied` — which for a real chip requestor arrives only
  after the device reboots into the new image over a fresh CASE session.
  Previously the call completed at `ApplyUpdateResponse` with a short
  same-session grace window and did not cover the post-reboot notification.
  Callers should bound the wait with `tokio::time::timeout`.

### [Unreleased] — OTA provider accepts CASE resumption

#### Added

- **The OTA provider server accepts CASE session resumption** — chip's OTA
  requestor always asks to *resume* the session the controller's
  `AnnounceOTAProvider` connect just established, which previously
  hard-failed the serve. Now: every completed CASE connect persists its
  fresh resumption record in `DeviceEntry.resumption_record` (serialized by
  the new `resumption` module); `serve_ota` announces first, seeds the
  provider server with the persisted record
  (`ProviderServer::with_resumption_records`), and the server answers a
  matching resumption-requesting Sigma1 with `Sigma2_Resume` (awaiting and
  acking the initiator's success `StatusReport`). An unknown resumption id
  still falls back to `reject_resumption` + full handshake. The rotated
  record returned by `serve_ota_once` is persisted after the serve so the
  requestor's next session can resume again.
- **OTA provider LIVE-VALIDATED vs chip's `ota-requestor-app`**
  (`just integration-ota` / `crates/integration-tests/tests/ota_flow.rs`):
  commission → announce → the requestor resumes the announce session
  against the provider (`Sigma2_Resume`) → `QueryImage` → 64 KiB BDX
  download → `ApplyUpdateRequest` → Proceed → the app applies (execs the
  image). Live-interop fixes shipped alongside: the provider pumps MRP
  timers while receiving (`SessionManager::handle_timeout`), so the
  requestor's reliable `BlockAckEOF` gets its standalone ack — without it
  chip marks the session defunct and never applies; served BDX block size
  is 960 (1024 overflowed the secured-payload budget once framed); and
  `serve_ota_once` completes at ApplyUpdateResponse after a short
  same-session `NotifyUpdateApplied` grace window — real requestors send
  NotifyUpdateApplied only after REBOOTING into the new image over a fresh
  session, which a single-session server intentionally does not serve.

### [Unreleased] — M9-E3 group multicast send

#### Added

- **`MatterController::create_group(key_set_id: u16, epoch_start_time: u64) -> Result<GroupKeySet>`** —
  generates a fresh 16-byte epoch key from the CSPRNG, persists a
  `GroupKeySetConfig` under `key_set_id` in the controller's TLV snapshot
  (context tags t6 / t7), and returns a [`GroupKeySet`] so the caller can
  immediately program it onto each member device via
  [`Node::write_group_key_set`]. The key set is stored durably before this
  call returns — the controller can encrypt outbound group messages for it
  right away. Returns `Error::NotCommissioned` if no fabric exists.
- **`MatterController::invoke_group(group_id: u16, key_set_id: u16, path: CommandPath, fields: Value) -> Result<()>`** —
  fire-and-forget multicast group invoke: derives the operational group key
  (via `derive_operational_ipk`, reusing the E2 derivation) and group session
  id (via `derive_group_session_id`) from the persisted epoch key; builds and
  encrypts the group secured message (`encode_group_secured`); sends the
  datagram to the Matter per-group multicast IPv6 address
  (`group_multicast_ipv6(fabric_id, group_id)`) computed from the raw fabric
  id. The outbound group message counter is bumped and persisted **before** the
  send so no counter is reused across a crash. Returns as soon as the datagram
  leaves the socket — group commands are unacknowledged; there is no response.
- **`Error::GroupNotProvisioned(u16)`** — returned by `invoke_group` when
  `key_set_id` has no matching `GroupKeySetConfig` in the persisted fabric
  state. Call `create_group` first. The raw key-set id is carried in the
  variant.

#### Persistence changes (snapshot t6 / t7)

The controller snapshot gains two new context-tagged fields per fabric:

- **t6 — group key array** — a TLV list of `GroupKeySetConfig` records (key
  set id, 16-byte epoch key, epoch start time). Persisted by `create_group`
  before returning.
- **t7 — outbound group counter** — a monotonic `u32` that advances with
  every `invoke_group` call and is written before the UDP send. Guards against
  counter reuse across process restarts.

Snapshots without t6/t7 decode cleanly (empty key array, counter = 0) — no
migration step is needed for snapshots from M9-E1 or earlier.

#### Notes

- `invoke_group` does not look up a group→key-set map: the caller supplies
  both `group_id` and `key_set_id` explicitly. This is intentional — a
  controller may bind the same key set to multiple groups, and the
  group→key-set relationship is already captured on the device via
  `write_group_key_map`.
- Real multicast delivery requires the host network to route `ff35:…`
  datagrams to the device's L2 segment. The send returns `Ok` even when the
  host has no route (the bytes are correct at the socket layer). See the E3
  runbook (`docs/runbooks/m9-e3-group-multicast.md`) for the full hardware
  validation loop and multicast-interface troubleshooting.
- The group-message crypto path (key derivation in `matter-crypto` E2 +
  AES-CCM group framing in `matter-transport` E3) is byte-parity verified
  against connectedhomeip test vectors. See the E2 CHANGELOG entry in `matter-crypto`.

### [Unreleased] — M9-E1 group provisioning

#### Added

- **`Node::write_group_key_set(set: &GroupKeySet) -> Result<()>`** — provisions
  a key set on the device via `KeySetWrite` on the `GroupKeyManagement` cluster
  (0x003F, endpoint 0). Caller supplies a fully constructed [`GroupKeySet`]
  (key set id, 16-byte epoch key, epoch start time). Non-success status from the
  device surfaces as `Error::GroupCommandRejected`.
- **`Node::write_group_key_map(entries: &[GroupKeyMapEntry]) -> Result<Vec<(AttributePath, ImStatus)>>`** —
  writes the `GroupKeyMap` attribute (0x003F/0x0000) via the B4 chunked
  list-write mechanism. Each [`GroupKeyMapEntry`] binds a group id to a key set
  id. Returns one `(AttributePath, ImStatus)` per entry path; all statuses are
  `Success` on acceptance.
- **`Node::add_group(endpoint: u16, group_id: u16, name: &str) -> Result<()>`** —
  invokes `AddGroup` on the `Groups` cluster (0x0004) at the given endpoint.
  Adds the endpoint to `group_id` under the supplied name. Non-success status
  surfaces as `Error::GroupCommandRejected`.
- **`Node::remove_group(endpoint: u16, group_id: u16) -> Result<()>`** — invokes
  `RemoveGroup` on the `Groups` cluster (0x0004). Removes the endpoint from
  `group_id`. Non-success status surfaces as `Error::GroupCommandRejected`.
- **`GroupKeySet`** — public type re-exported at the crate root. Constructor:
  `GroupKeySet::new(key_set_id: u16, epoch_key: Vec<u8>, epoch_start_time: u64)`.
  Carries the key set id, the 16-byte epoch key (EpochKey0), and the epoch start
  time (0 for "use immediately"). `#[non_exhaustive]`.
- **`GroupKeyMapEntry`** — public type re-exported at the crate root. Constructor:
  `GroupKeyMapEntry::new(group_id: u16, group_key_set_id: u16)`. Binds a group id
  to a key set, forming one row of the `GroupKeyMap` attribute. `#[non_exhaustive]`.
- **`Error::GroupCommandRejected(u8)`** — returned by `write_group_key_set`,
  `add_group`, and `remove_group` when the device returns a non-success status.
  The raw status code is carried in the variant.

#### Notes

- `write_group_key_map` delegates to the B4 chunked-write mechanism
  (`build_list_write_chunks` in `matter-interaction`). When all entries fit one
  frame the write is byte-identical to a plain `write` call; when the encoded
  list exceeds the per-chunk budget (800 bytes) the write is split across
  multiple `MoreChunkedMessages`-flagged frames.
- The `group` module (`pub(crate)`) contains the encoding helpers
  (`key_set_write_fields`, `group_key_map_entry_value`, `add_group_fields`,
  `remove_group_fields`, `parse_group_status`) and cluster/attribute constants.
  Only `GroupKeySet`, `GroupKeyMapEntry`, and `Error::GroupCommandRejected` are
  part of the stable API.
- This is the **provisioning foundation** for group communication. The multicast
  send that exercises a provisioned group lands in E3. See
  `docs/runbooks/m9-e1-group-provisioning.md` for the operator validation steps.

### [Unreleased] — M9-D3 ACL read/write

#### Added

- **`Node::read_acl() -> Result<Vec<AclEntry>>`** — reads `AccessControl.Acl`
  (cluster 0x001F, attribute 0x0000, endpoint 0) on the accessing fabric and
  returns the decoded entry list. Uses the existing chunked-read path; always
  safe to call (read-only, no guard required).
- **`Node::write_acl(entries: &[AclEntry]) -> Result<Vec<(AttributePath, ImStatus)>>`** —
  replaces the device's ACL list atomically. When all entries fit one
  `WriteRequestMessage` the write is byte-identical to a plain `write` call
  and transparently upgrades through the `NEEDS_TIMED_INTERACTION` (0xc6) path
  when required. When the encoded list exceeds the per-chunk budget (800 bytes),
  the write is split across multiple frames using the B4 chunked-write mechanism
  (`MoreChunkedMessages` + `ReplaceAll`/`AppendItem` sequence).
  **Lockout guard:** before sending any bytes, `write_acl` fetches the
  commissioner node id via the actor and checks that `entries` contains at least
  one `Administer`/`Case` entry covering our node id. If the check fails it
  returns `Error::AclWouldLockOut` immediately — no network I/O occurs.
- **`AclEntry`** — public struct re-exported at the crate root. Fields:
  `privilege: AclPrivilege`, `auth_mode: AclAuthMode`,
  `subjects: Option<Vec<u64>>` (`None` = wildcard), `targets: Option<Vec<AclTarget>>`
  (`None` = wildcard), `fabric_index: Option<u8>` (omit on write; always
  `Some` on read). `#[non_exhaustive]`.
- **`AclTarget`** — public struct re-exported at the crate root. Fields:
  `cluster: Option<u32>`, `endpoint: Option<u16>`, `device_type: Option<u32>`
  (each `None` = wildcard). `#[non_exhaustive]`.
- **`AclPrivilege`** — public enum re-exported at the crate root: `View`,
  `ProxyView`, `Operate`, `Manage`, `Administer`, `Unknown(u8)`. `#[non_exhaustive]`.
- **`AclAuthMode`** — public enum re-exported at the crate root: `Pase`, `Case`,
  `Group`, `Unknown(u8)`. `#[non_exhaustive]`.
- **`Error::AclWouldLockOut`** — returned by `write_acl` when the proposed entry
  list would strip our own Administer/CASE access. The guard fires client-side
  (no bytes sent) so there is no risk of accidentally orphaning the device.

#### Notes

- Internal actor primitives `Command::ChunkedWrite` and `Command::CommissionerNodeId`
  support `write_acl`: `ChunkedWrite` drives the multi-frame send loop against the
  device, and `CommissionerNodeId` retrieves the controller's node id for the
  lockout predicate. Both remain `pub(crate)`.
- The `acl` module (`pub(crate)`) contains the encoding/parsing helpers
  (`acl_entry_value`, `parse_acl`, `acl_retains_admin`) and the cluster/attribute
  constants. Only the four public types and the error variant are part of the
  stable API.
- Multi-chunk writes are validated against a synthetic in-process fixture (loopback)
  and by `write_acl_with_budget` tests with an injected small budget. Real-device
  validation covers the single-chunk path only (see `docs/runbooks/m9-d3-acl.md`).

### [Unreleased] — M9-D2 fabric management

#### Added

- **`Node::list_fabrics() -> Result<Vec<FabricDescriptor>>`** — reads the
  `Fabrics` attribute (0x0001) from the device's `OperationalCredentials` cluster
  (0x003E) and returns the full fabric table. Each entry carries `root_public_key`,
  `vendor_id`, `fabric_id: u64`, `node_id`, `label`, and `fabric_index`.
- **`Node::remove_fabric(fabric_index: u8) -> Result<()>`** — invokes
  `RemoveFabric` on the device's `OperationalCredentials` cluster to remove the
  fabric at `fabric_index`. **Self-protected:** reads `CurrentFabricIndex` first
  and returns `Error::WouldRemoveSelf` if `fabric_index` matches our own fabric.
  Fails closed if `CurrentFabricIndex` cannot be read. There is intentionally no
  force override.
- **`Node::update_fabric_label(label: &str) -> Result<()>`** — invokes
  `UpdateFabricLabel` on `OperationalCredentials` to relabel the **accessing
  fabric** (i.e. our own fabric entry on this device). Takes no `fabric_index`
  argument — the cluster command acts on the fabric of the session peer.
- **`FabricDescriptor`** — new public type re-exported at the crate root. Fields:
  `root_public_key: Vec<u8>`, `vendor_id: u16`, `fabric_id: u64`, `node_id: u64`,
  `label: String`, `fabric_index: u8`.
- **`Error::WouldRemoveSelf`** — returned by `remove_fabric` when the requested
  index is our own.
- **`Error::OperationalCredentialsRejected(u8)`** — returned by `remove_fabric`
  and `update_fabric_label` when the device returns a non-success `NocStatus`
  code; the raw status code is carried in the variant.

#### Notes

- `remove_fabric` and `update_fabric_label` are plain invokes (not timed); the
  device returns a `NOCResponse` TLV and non-success codes surface as
  `OperationalCredentialsRejected`. The `NocStatus` enum and the raw `opcreds`
  module remain `pub(crate)` — only `FabricDescriptor` is re-exported.
- The self-protection in `remove_fabric` reads `CurrentFabricIndex` (attr 0x0005)
  from `OperationalCredentials` before issuing the invoke. If the read fails (e.g.
  the device is offline or permission is denied), the function fails closed rather
  than risking an accidental self-removal.

### [Unreleased] — M9-D1 commissioning window

#### Added

- **`Node::open_commissioning_window(opts: OpenWindowOpts) -> Result<CommissioningWindow>`** —
  generates a fresh passcode/salt/discriminator via the system RNG, computes the
  PAKE verifier (`matter-crypto::pake_passcode_verifier`), and sends
  `OpenCommissioningWindow` as a timed invoke to the device's
  `AdministratorCommissioning` cluster (0x003C). Returns a
  [`CommissioningWindow`] carrying the 11-digit `manual_code` (always) and
  `qr_code` (`Some` when `opts.vendor_id`/`opts.product_id` are set). The
  onboarding payload is composed from the existing `matter-commissioning` setup-
  payload encoders (`encode_manual_code` / `encode_qr`) — no new payload code.
- **`Node::open_commissioning_window_with(timeout_s, passcode, salt, discriminator, iterations, vendor_id, product_id) -> Result<CommissioningWindow>`** —
  deterministic seam for tests: caller supplies all secrets, no RNG involved.
  Computes the verifier from the supplied `passcode`/`salt`/`iterations` and
  drives the same timed invoke path.
- **`Node::open_basic_commissioning_window(timeout_s: u16) -> Result<()>`** —
  opens a basic commissioning window (device reuses its original passcode; no
  new onboarding payload returned). Timed invoke.
- **`Node::revoke_commissioning() -> Result<()>`** — revokes any open
  commissioning window. Timed invoke.
- **`Node::commissioning_window_status() -> Result<WindowStatus>`** — reads
  `WindowStatus` (attr 0x0000), `AdminFabricIndex` (0x0001), and `AdminVendorId`
  (0x0002) from the `AdministratorCommissioning` cluster and returns a
  [`WindowStatus`] snapshot.
- New public types re-exported from `matter-controller`:
  [`OpenWindowOpts`], [`CommissioningWindow`], [`WindowStatus`],
  [`CommissioningWindowStatus`], and constants
  `DEFAULT_WINDOW_ITERATIONS` (1000) / `DEFAULT_WINDOW_TIMEOUT_S` (180 s).
- `Error::CommissioningWindowRejected(u8)` — emitted when the device returns an
  IM failure status on any `AdminComm` command.

#### Notes

- All four node verbs route through an internal `admin_timed_command` helper that
  sends a `TimedRequest` + the command in one exchange (chip-faithful). The M9-B3
  timed-interaction path provides this automatically.
- `open_basic_commissioning_window` is deliberately separate from
  `open_commissioning_window`: the basic variant carries no new verifier and its
  security characteristics differ (it re-exposes the original setup passcode).
- `open_commissioning_window_with` is the test / power-user seam; production code
  uses `open_commissioning_window`.

## matter-commissioning

### [Unreleased] — M9-C2 Thread commissioning

#### Documentation

- **Clarified which CD signing root real devices actually need.** No code
  change — the CD verifier was already correct — but `CdSigningRoots::with_csa_test_roots()`
  (and `AttestationTrust::csa_test_roots()` above it) carries a *synthetic* CD
  root that verifies no real device, which is now stated plainly. chip's example
  CDs do not share one signer: the VID=0xFFF1 CD served by every
  `CONFIG_EXAMPLE_DAC_PROVIDER` device is signed by the CSA's **production**
  "CD Signing Key 001", not chip's test CD authority, so a live commission needs
  `--cd-dir credentials/production/cd-certs`. chip's own verifier trusts both
  keys, which is why chip-tool never surfaces the difference. Pinned by
  `tests/chip_cd_vector.rs` (three vectors, including a negative test that fires
  if the upstream example-CD signer ever changes).

#### Added

- **`NetworkCredentials` enum** (`state_machine/commissioner.rs`) —
  replaces `CommissionerConfig`'s `wifi_credentials: Option<WiFiCredentials>`
  field with `network: NetworkCredentials`, an enum of `WiFi(WiFiCredentials)`
  / `Thread(ThreadDataset)` / `AlreadyOnNetwork`. `AlreadyOnNetwork` makes
  the previously-implicit "no credentials = skip provisioning" behavior
  explicit. `Commissioner::new` validates the variant (existing Wi-Fi
  bounds; Thread dataset validation lives in `ThreadDataset::new`) and
  routes network provisioning by the supplied variant, cross-checked
  against the device's `NetworkCommissioning.FeatureMap` — a mismatch
  (e.g. `Thread(..)` supplied against a Wi-Fi-only device) surfaces as
  `CommissioningError::NetworkFeatureUnsupported`.
- **`ThreadDataset`** (new module `thread_dataset.rs`) — wraps and
  validates a Thread operational dataset (Thread's own flat TLV format,
  *not* Matter TLV; obtained from a border router, e.g. `ot-ctl dataset
  active -x`, hex-decoded by the caller). `ThreadDataset::new` validates
  non-empty, ≤254 bytes, well-formed TLVs, and the presence of an
  Extended PAN ID TLV (type `0x02`, length 8). `as_bytes()` returns the
  opaque dataset for `AddOrUpdateThreadNetwork`; `ext_pan_id()` returns
  the cached 8-byte Extended PAN ID used as `ConnectNetwork`'s
  `network_id` for Thread.
- **`encode_add_or_update_thread_network(operational_dataset, breadcrumb)`**
  (`clusters/network_commissioning.rs`) — `NetworkCommissioning` cluster
  `0x0031`, command `ADD_OR_UPDATE_THREAD_NETWORK` (`0x03`), TLV struct
  `{ ctx0: dataset octet-string, ctx1: breadcrumb uint }` per spec
  §11.9.6.4. `ConnectNetwork` (`0x06`) is reused unchanged — only the
  caller-supplied `network_id` differs (Extended PAN ID for Thread vs.
  SSID for Wi-Fi).
- **Genericized network stages** (`state_machine/stage.rs`) — the two
  Wi-Fi-specific stages are renamed to the network-agnostic
  `NetworkSetup` / `NetworkEnable` (the shared failsafe-extension stage
  becomes `FailsafeBeforeNetworkEnable`), dispatched by
  `NetworkCredentials` variant to build either
  `AddOrUpdateWiFiNetwork`/`AddOrUpdateThreadNetwork`. Internal rename
  only (`Stage` is `#[non_exhaustive]`, not a wire contract);
  `EvictPreviousCaseSessions` remains the shared convergence point after
  either network type.
- **`ConnectMaxTimeSeconds`-sized failsafe/response deadlines** — Thread
  attach + SRP registration is slower than Wi-Fi association, so
  `ReadNetworkCommissioningInfo` now also reads
  `NetworkCommissioning.ConnectMaxTimeSeconds` (attribute `0x0009`)
  alongside `FeatureMap`, and both the `FailsafeBeforeNetworkEnable`
  extension and the BLE-path `ConnectNetwork` response deadline are sized
  from it (chip-faithful). The failsafe extension uses the reported value
  as-is, falling back to a generous 90 s default
  (`DEFAULT_CONNECT_MAX_TIME_SECONDS`) if unread or zero. The
  `ConnectNetwork` response deadline uses the same reported value but
  **floored at that same 90 s default** — so it can never fire before the
  same-sized failsafe extension would expire — and falls back to the
  original fixed 60 s deadline only when the device hasn't reported the
  attribute (unread or zero). **Behavior change:** a device that reports
  `ConnectMaxTimeSeconds` below 90 s (e.g. the Thread loopback mock's 30 s)
  now gets a 90 s `ConnectNetwork` deadline instead of the raw reported
  value; the Wi-Fi path adopts the same sizing harmlessly (unread
  `ConnectMaxTimeSeconds` keeps the original 60 s deadline), but has not
  yet been re-exercised live against a real Wi-Fi device since the change
  — see `docs/runbooks/c2-thread-commission.md`'s carry-forward note.
- **Hermetic Thread loopback proof** — `commission_ble_loopback.rs` gains
  a Thread-FeatureMap mock device (M9-C2 Task 7) exercising the full fork
  end-to-end (FeatureMap→Thread route, dataset provisioning via
  `AddOrUpdateThreadNetwork`, `ConnectNetwork` keyed by Extended PAN ID,
  convergence to CASE) without hardware.
- **Byte-parity vectors** — `test-vectors/thread/network_commissioning.json`
  covers `ThreadDataset::ext_pan_id` extraction and
  `encode_add_or_update_thread_network` wire bytes against a captured
  OTBR dataset. Live validation procedure (real C6 DUT, chip-tool
  reference trace diff): `docs/runbooks/c2-thread-commission.md`.

This completes M9 sub-project C (BLE commissioning transport): C1 (Wi-Fi,
shipped 2026-07-13/14) + C2 (Thread, this entry) — both landed, live
hardware validation for C2 is the one remaining operator-gated step (see
the runbook above).

### [Unreleased] — M9-C1 BLE/BTP commissioning driver

#### Added

- **`driver::TransportReliability`** (`Mrp` / `TransportProvides`) — lets the
  unsecured-exchange path (PASE, and the unsecured phase of CASE) defer
  reliability to the underlying transport instead of always driving MRP.
  `TransportProvides` is used for BTP: the session's
  `Session::transport_reliable` flag (matter-transport) is set so the R-flag,
  retransmits, and standalone acks are all suppressed for that session.
- **`driver::run_pase_with`** — generalises the PASE driver over
  `TransportReliability` and an explicit `(SessionId, SocketAddr)` /
  `AsyncDatagram`, so the same PASE state machine drives over UDP+MRP or
  over a BTP channel with MRP off. The existing UDP-path `run_pase` now
  delegates to it with `TransportReliability::Mrp`.
- **`driver::commission_ble`** — the BLE/BTP commissioning driver fn: scans
  and opens a BTP session (via the caller-supplied `BleDriverConfig`), drives
  PASE and every pre-operational stage (attestation, NOC install, Wi-Fi
  network commissioning) over BTP with MRP off, then hands off to the
  existing operational-CASE path over IP once the device joins Wi-Fi and is
  reachable by mDNS. Bounds every BLE-path stage with an explicit response
  deadline (unbounded hangs are a documented BTP failure mode with MRP off),
  and widens `resolve_operational`'s poll-attempt budget for the BLE path
  (~60 s, vs. the UDP path's ~30 s) since the device has only just started
  Wi-Fi association + DHCP + mDNS announce. BTP teardown happens only after
  `commission_ble` returns, and a failed post-PASE rollback over an
  already-dead BTP channel surfaces the original driver error rather than
  masking it with a transport error.
- **`STREAM_PEER`** — sentinel `SocketAddr` used as the nominal "peer
  address" for BTP sends (a BTP channel has no IP peer; the underlying
  `AsyncDatagram` impl for a BTP channel ignores the address and always
  targets the connected GATT peer).

#### Changed

- **Behavior change:** on the **IP** path, post-CASE secured traffic now
  targets the device's **mDNS-resolved operational address** (discovered via
  `resolve_operational`) rather than the commissionable address the PASE
  phase used. This is the same physical device and socket on IP — strictly
  more correct, since the commissionable and operational mDNS records are not
  guaranteed to resolve to the same address — but it is a behavior change for
  anything that was relying on post-CASE traffic reusing the commissionable
  address. Required groundwork for the BLE path, where PASE happens over BTP
  (no IP address at all) and CASE must dial the freshly-Wi-Fi-joined device's
  real operational address.

### [Unreleased] — responder-side unsecured replies (OTA provider interop)

#### Added

- **`driver::encode_unsecured_reply`** — encodes a responder-side unsecured
  message carrying the DESTINATION node id (the initiator's ephemeral source
  node id echoed back). Matter Core §4.4.1 / chip's
  `SessionManager::UnauthenticatedMessageDispatch` require exactly one of
  {source, destination} node id on unsecured messages; chip silently drops
  responder replies without the destination id as "malformed unsecure
  packet". This was the root cause of chip's OTA requestor never processing
  our Sigma2/`Sigma2_Resume` (it MRP-retransmitted Sigma1 forever) — the
  provider server's handshake replies now interop. (Our own initiator-side
  driver was unaffected: it always stamped a source node id.)

### [Unreleased] — M6.1 setup payload codec, M6.2.x attestation, M6.3.x NOC issuance, M6.4 commissioning state machine (M6.4.1 → M6.4.6, complete), M6.5 network commissioning (M6.5.1 → M6.5.3, complete), M6.6.1 IM framing, M6.6.2 driver skeleton, M6.6.3b PASE/CASE bridges, M6.6.4 commission() orchestrator + loopback E2E gate, M6.6.5 example + runbook (M6.6 / M6 complete), M6.6.5a production CD-root ingestion, M7.5 control_onoff example

#### M7.5 — `control_onoff` example (cluster control on a real device)

- New `examples/control_onoff.rs` (behind `driver`): commissions a device, then
  opens a **fresh operational CASE session** and drives the generated
  `matter-clusters` codecs over `matter-interaction` framing — read
  `OnOff.OnOff`, invoke `OnOff.Toggle`, re-read, write
  `BasicInformation.NodeLabel`, read it back. Built on the public driver
  primitives (`resolve_operational`, `run_case`, `secured_round_trip`) and
  `noc::issue_noc`. `matter-clusters` is an **example-only dev-dependency**, so
  the crate's dependency graph is unchanged. The validation artifact for M7 (see
  `docs/runbooks/m7.5-control-onoff.md`).

#### M6.6.5a — production CD signing-root ingestion (`CdSigningRoots::from_cert_der`)

Surfaced by real-device M6 validation: production CD signing roots (the CSA
Distributed Compliance Ledger, mirrored at connectedhomeip
`credentials/production/cd-certs/`) are X.509 **certificates**, but the only
ingestion path was `CdSigningRoots::from_pem`, which expects bare
`SubjectPublicKeyInfo` PEMs — so `commission_ip` could not consume real CD roots.

##### Added

- `CdSigningRoots::from_cert_der` — builds the CD-signing trust store from one or
  more X.509 CD signing **certificate** DERs, extracting each cert's SEC1
  uncompressed P-256 subject public key (no signature/validity/chain checks — the
  operator vouches for the supplied roots). Additive; `from_pem` is unchanged.

##### Changed

- `examples/commission_ip.rs`: `--cd-root` now accepts a **directory** of `*.der`
  CD signing certs (or a single `*.der` cert), loading them all via
  `from_cert_der` — so a device's CD verifies regardless of which CSA CD signing
  key signed it. Validated against the real 40 production PAA roots + 5 CSA CD
  signing certs.

#### M6.6.5 — `commission_ip` example + first-commission runbook (M6.6 / M6 complete)

The operator-facing close-out of M6.6 and Milestone 6.

##### Added

- `examples/commission_ip.rs` (behind the `driver` feature) — an operator binary
  that commissions an IP-reachable device end to end: parses a `--qr`/`--manual`
  setup payload, builds attestation trust roots (bundled CSA **test** roots by
  default with a loud banner, or production roots via `--paa-dir`/`--cd-root`),
  self-generates an ephemeral fabric, and drives `commission()` over a real
  `TokioUdpTransport` + `MdnsSdDiscovery`. `--addr` dials directly (skips mDNS);
  `--out` writes a JSON fabric summary; `-v/-vv` enables tracing spans.
- `docs/runbooks/m6.6-first-commission.md` — manual real-device runbook (real LAN
  device via open commissioning window; rs-matter test device; matter.js
  cross-verification; troubleshooting; BLE/Tuya deferral).
- `docs/tested-devices.md` — the "devices we've tested against" list.

##### Notes

- No library protocol changes — this slice is the example binary + docs only.
- The example mints an **ephemeral** per-run commissioner identity; durable fabric
  persistence (including a stable operational signing key) is M8.

#### M6.6.4 — `commission()` orchestrator + in-process loopback E2E gate

The headline "first commission, no hardware" slice: the real `commission()`
driver walks a device through the full Ethernet-path commissioning sequence
(discover → PASE → attestation/CSR/AddNOC command loop → CASE →
`CommissioningComplete`) against a self-contained in-process mock device, with
every Commissioner verifier (`verify_chain`, `verify_attestation_response`,
NOC/CSR, CASE) running unmodified.

##### Added

- `driver::commission` + `driver::DriverConfig` — the async orchestrator that
  drives the sans-IO `Commissioner` cursor over the M6.6.2/M6.6.3 driver:
  resolve → `run_pase` → poll loop mapping each `Action` to IO
  (`Invoke`/`ReadAttribute` → `im` framing over `secured_round_trip`;
  `EstablishCase` → operational discovery + `run_case`; `Abort` → best-effort
  `ArmFailSafe(0)` rollback; `Done` → `CommissionedFabric`).
- `driver::resolve_commissionable` — mDNS resolution of a commissionable device
  by long discriminator (the `D` TXT record), mirroring `resolve_operational`.
- `DriverError::Aborted` variant (state-machine `Abort` with a reason).
- The in-process loopback E2E gate (`tests/commission_loopback.rs`): the real
  `commission()` commissions a self-contained mock device built from a
  self-generated PAA→PAI→DAC PKI, the bundled CSA CD fixture, and real
  `PaseVerifier`/`CaseResponder`s — hardware-free, over an `InMemoryDatagram`
  pair. (Supported by a new reusable X.509 DER cert builder in `matter-cert`
  test-support — see that crate's changelog.)

##### Fixed

- `commission()` now sources the PASE attestation challenge from the **live**
  established session (`SessionManager` `attestation_key`), not a static config
  input — the device signs attestation/CSR over the SPAKE2+-derived value, so
  the Commissioner must verify against the same live value.

##### Flagged (deferred)

- **Commissioner operational identity (→ M8):** `commission()` mints the
  controller's own NOC inline with a fresh keypair on every call, so the
  controller has no *stable/persistent* operational identity. Correct for a
  single commissioning run; persisting one admin identity across runs is M8
  (fabric create/persist/restore) work.
- **→ M6.6.5:** the Wi-Fi-path loopback (the gate pins the mock to the Ethernet
  feature so the Commissioner skips Wi-Fi network config), SecureChannel
  `StatusReport` parsing (a *rejecting* device is not yet detected), link-local
  `fe80::` operational scope-id dialing, and the real-device example + runbook.
- The loopback pins the mock to **VID 0xFFF1 / PID 0x8001** to match the bundled
  CSA Certification Declaration fixture (the DAC/PAI VID/PID and setup-payload
  VID/PID must agree with the CD cross-check).

#### M6.6.3b — PASE/CASE driver bridges + operational discovery

##### Added

- `driver::run_pase` — drives the sans-IO `PaseProver` over the unsecured
  (session-id 0) datagram path and registers the resulting secured PASE session
  under the id it advertised (via M6.6.3a `allocate_session_id` +
  `register_pase_with_local_id`). Validated by an in-process loopback against a
  real `PaseVerifier` (byte-for-byte key agreement + peer-id threading).
- `driver::run_case` — drives the sans-IO `CaseInitiator` (fresh SIGMA-I, also
  unsecured) and registers the operational session via `register_case`.
  Validated by an in-process loopback against a real `CaseResponder` with a
  test fabric / NOC chain.
- `driver::operational_instance_name` + `driver::resolve_operational` — build
  the `<compressed-fabric-id>-<node-id>` operational mDNS instance name (from
  `matter_crypto::derive_compressed_fabric_id`) and resolve it via the
  `Discovery` trait. Tested with an in-memory `Discovery` double.
- `UnsecuredExchange::send` — fire-once terminal-message send (Pake3/Sigma3).
- `DriverError::Handshake` variant.

##### Flagged (deferred)

- SecureChannel `StatusReport` is not parsed: the terminal handshake message is
  sent fire-once and `finish()` is called; a *rejecting* device's StatusReport
  is not yet detected (M6.6.4/M6.6.5). Link-local `fe80::` operational addresses
  cannot be dialed (no scope id in `MatterService`) — M6.6.5. Unsecured counter
  seeding stays fixed (production randomness later). `commission()` orchestration
  is M6.6.4.

#### M6.6.2 — Tokio commissioning driver (skeleton)

##### Added

- New `driver` cargo feature (Tokio; off by default) carrying the commissioning
  driver's IO foundation. The sans-IO state machine, codecs, and `im` module
  remain fully usable without it.
- `driver::AsyncDatagram` — a datagram-only async transport seam (`send_to` /
  `recv_from`), with a real `TokioUdpTransport` implementation and an in-memory
  `InMemoryDatagram` test double (with drop injection for retransmit tests).
- `driver::secured_round_trip` — a secured-exchange round-trip over
  `matter-transport`'s `SessionManager`, owning the MRP retransmit/ack timer
  loop so the policy layer never sees MRP mechanics.
- `driver::{encode_unsecured, decode_unsecured, UnsecuredMessage,
  UnsecuredExchange}` — unsecured (session-id 0) PASE framing plus a
  stop-and-wait reliable sender, since `matter-transport` has no unsecured path
  and the PASE handshake runs unsecured. The exact unsecured-PASE header
  conventions are flagged for byte-parity confirmation against matter.js when
  PASE flows (M6.6.3 / real device).
- `driver::DriverError` — the IO-layer error type bridging transport, crypto,
  IM-framing, and state-machine errors.
- Validated by hardware-free tests: in-memory datagram delivery + drop, a
  real-socket UDP loopback, an encrypted `secured_round_trip` with MRP
  retransmit, and unsecured encode/decode + stop-and-wait round-trips.

#### M6.6.1 — Interaction Model framing

##### Added

- `matter-commissioning`: `im` module — Interaction Model `InvokeRequestMessage` /
  `ReadRequestMessage` builders and `InvokeResponseMessage` / `ReportDataMessage`
  parsers (the subset commissioning needs). Dependency-isolated for a future
  `matter-interaction` extraction. (M6.6.1)
- `matter-codec`: `TlvWriter::put_preencoded` — splice a pre-encoded
  anonymous-tagged element under a new tag.

#### M6.5.1 — NetworkCommissioning cluster codecs + RemediationHint

- New `clusters::network_commissioning` module: `encode_add_or_update_wifi_network`,
  `encode_connect_network`, `decode_feature_map`, `decode_network_config_response`,
  `decode_connect_network_response`, `WiFiNetworkFeature` bitflags,
  `NetworkConfigResponse` + `ConnectNetworkResponse` structs.
- New `RemediationHint` enum (spec'd as `#[non_exhaustive]` with a documented
  stability promise) + `remediation_for(status_code)` mapping table.
- Re-exports added to crate root for ergonomic access.
- No state-machine wiring yet (M6.5.2 lands the dispatch arms + the new `Stage`
  variants that consume these codecs).

#### M6.5.2 — Wi-Fi network commissioning state machine

- Four new `Stage` variants: `ReadNetworkCommissioningInfo`,
  `WiFiNetworkSetup`, `FailsafeBeforeWiFiEnable`, `WiFiNetworkEnable`.
  The M6.4 placeholder `Stage::NetworkCommissioning` is removed.
- Three new `Expectation` variants: `NetworkCommissioningInfo`,
  `NetworkConfigResponse`, `ConnectNetworkResponse`.
- Three new `CommissioningError` variants: `NetworkFeatureUnsupported`,
  `NetworkRejected`, `WifiCredentialsRequired`.
- `WiFiCredentials` struct (with hand-written `Debug` that redacts the
  passphrase) and `CommissionerConfig::wifi_credentials: Option<WiFiCredentials>`
  field. `None` is valid for Ethernet-only devices.
- Ethernet-only devices auto-skip the Wi-Fi sub-cursor via FeatureMap
  branching. Thread-only devices fail fast with
  `NetworkFeatureUnsupported { needed: Thread }`.
- **Behavioural change:** failsafe-expiry now derives from
  `BasicCommissioningInfo::failsafe_expiry_length_seconds` (was hardcoded
  60s in M6.4). Both `ArmFailSafe` invocations use the device-declared
  value. M6.4 fallback of 60s preserved for malformed
  `BasicCommissioningInfo`.
- **Behavioural change:** `CommissioningError::NetworkRejected` carries a
  `RemediationHint` for downstream UI rendering. `OtherConnectionFailure`
  and `UnknownError` map to `RemediationHint::None`; see
  `clusters::network_commissioning::remediation_for` for the full
  mapping table.
- **New feature flag:** `tracing` (optional, default off). Adds
  `#[instrument]` spans on `Commissioner::poll`,
  `Commissioner::on_response`, and `Commissioner::on_case_established`.
  Field names align best-effort with matter.js's log-event format.
- **New feature flag:** `test-helpers` (optional, default off). Exposes
  test-only shortcut constructors `Commissioner::new_at_read_network_commissioning_info`
  and `Commissioner::new_at_evict_previous_case_sessions` that bypass the
  M6.4 attestation/NOC stages — needed because the M6.4.6 real-fixture
  e2e driver is deferred. **Never use these in production.**
- `breadcrumb_counter` plumbed monotonically through every
  breadcrumb-bearing command.

#### M6.5.3 — matter.js byte-parity gate covers M6.5 stages (closes M6.5)

- Existing `commissioning_byte_parity.rs` data-driven schema already
  accommodates the new M6.5 stages (`ReadNetworkCommissioningInfo`,
  `WiFiNetworkSetup`, `FailsafeBeforeWiFiEnable`, `WiFiNetworkEnable`)
  without Rust-side changes — the test replays whatever stage records
  appear in `test-vectors/commissioning/e2e/happy-path.json`. The four
  new stages are RNG-free; `rng_bearing` allowlist unchanged.
- `xtask/scripts/capture-commissioning/index.js` updated with capture-
  point comments for the four new M6.5 payloads. Operator-wiring still
  pending (same posture as M6.4.6).
- `crates/matter-commissioning/README.md` gains a Wi-Fi
  `CommissionerConfig` example + optional `tracing` feature note.

Closes M6.5.

#### Pre-M6.6 naming cleanup

- **Renamed:** `WiFiNetworkFeature` → `NetworkCommissioningFeature` to
  mirror the spec exactly (the bitflag is the `NetworkCommissioning`
  cluster's `FeatureMap`, covering WIFI/THREAD/ETHERNET bits — the
  Wi-Fi-centric name was misleading). Variant constants (`WIFI`,
  `THREAD`, `ETHERNET`) unchanged.
- **Renamed:** Cargo feature `test-helpers` → `__test_shortcuts`
  (double-underscore prefix follows the Tokio / Serde convention for
  "internal, do not depend on").
- **Consolidated:** the two M6.5.2 shortcut constructors
  (`Commissioner::new_at_read_network_commissioning_info`,
  `Commissioner::new_at_evict_previous_case_sessions`) into a single
  `Commissioner::position_at_stage_for_test(self, stage, seeds)` that
  consumes `self` and applies opt-in synthetic-state seeds via a new
  `TestStateSeeds` struct. Caller now explicitly opts into the
  synthetic NOC public key seeding.

Pre-1.0 / pre-publish change. Behind the `__test_shortcuts` feature
flag, which itself signals "do not enable in production."

### M6.4 — Commissioning state machine — COMPLETE

All six sub-phases shipped (M6.4.1 → M6.4.6). The state machine drives
end-to-end from `SecurePairing` through `Action::Done(CommissionedFabric)`
on canned responses + a mock `on_case_established` callback. matter.js
byte-parity gate infrastructure is in place; operator-touch wiring is
deferred and documented in `TODO-1.0.md`.

`matter-commissioning` stays at `0.0.0` — `cargo publish` is deferred
per standing user instruction until the user opts in. M6.5 (Wi-Fi network
commissioning subgraph) and M6.6 (Tokio driver + first real-device
commission) are the remaining M6 sub-milestones.

#### M6.4.6 — matter.js byte-parity gate (infrastructure)

- `xtask capture-commissioning` subcommand scaffolded with a placeholder
  `index.js` matter.js capture script + a Rust dispatcher that spawns
  node and verifies the output JSON. Matches the established
  `xtask/scripts/<name>/` pattern from M5 / M6.3.
- `tests/commissioning_byte_parity.rs` integration test scaffolded
  to replay a captured matter.js trace through `Commissioner` and
  assert byte-parity on emitted Invoke + ReadAttribute payloads.
  Skips with `eprintln!` when the fixture is missing/empty (CI stays
  green during operator wiring).
- M6.4.6 baseline asserts byte-parity only on RNG-free payloads
  (ArmFailSafe, SetRegulatoryConfig, CertChainRequest,
  AddTrustedRootCertificate). RNG-bearing payloads
  (SendAttestationRequest nonce, SendOpCertSigningRequest nonce,
  SendNoc IPK) are walked but not strict-asserted — operator wiring
  upgrades this when it lands.
- TODO-1.0.md entry documents the operator activation recipe:
  pin `@matter/protocol` version, write the JS capture logic, run
  `cargo xtask capture-commissioning`, drop the test's skip path.

#### M6.4.5 — PASE→CASE handoff + CommissioningComplete

- State machine: four new stages (`NetworkCommissioning` no-op,
  `EvictPreviousCaseSessions` no-op for new-fabric flow,
  `FindOperationalForComplete` emitting `Action::EstablishCase`,
  `SendComplete` over `SessionContext::Case`, `Cleanup` emitting
  `Action::Done(CommissionedFabric)`).
- New public API: `Commissioner::on_case_established()` advances the
  cursor when the caller (M6.6 driver) reports successful mDNS
  find-operational + SIGMA handshake. `Expectation::CaseFailed` signal
  surfaces CASE-establishment failure as
  `CommissioningError::CaseEstablishmentFailed`.
- Six new inline glass-box tests covering EstablishCase emission,
  on_case_established happy + out-of-order paths, SendComplete invoke +
  success transition, and the Cleanup → Done emission.
- Two new glass-box tests for the `CaseFailed` path
  (`case_failed_response_aborts_with_case_establishment_failed`,
  `case_failed_when_not_awaiting_returns_out_of_order`).
- `tests/state_machine_unit.rs` gains a `transitions_are_total`
  proptest case alongside the existing two from M6.4.1 T10.
- `tests/commissioning_e2e.rs` placeholder for the public-API
  drive-through pending M6.4.6 fixtures.
- With this sub-phase the state machine drives end-to-end from
  `SecurePairing` through `Action::Done(CommissionedFabric)` on canned
  responses plus a mock `on_case_established` callback. M6.4 substance
  is feature-complete — M6.4.6 adds the matter.js byte-parity gate.

#### M6.4.4 — CSR + NOC issuance flow

- State machine: five new stages (`SendOpCertSigningRequest`,
  `ValidateCsr`, `GenerateNocChain`, `SendTrustedRootCert`, `SendNoc`)
  wired into `Commissioner`.
- Integrates M6.3's `verify_csr_response` + `issue_noc` + the OpCreds
  `AddTrustedRootCertificate` and `AddNOC` encoders.
- `Commissioner` gains five storage slots (`csr_nonce`, `csr_response`,
  `verified_csr`, `issued_noc`, `issued_noc_public_key`).
- `NocResponse.status != 0` and the AddTrustedRootCertificate
  status-only ack both surface as `CommissioningError::DeviceImStatus`.
- On success the cursor advances to `Stage::NetworkCommissioning`
  (M6.4.5 implements that no-op slot + the PASE→CASE handoff).
- Four new inline glass-box tests covering CSR-nonce randomness,
  drive-through to SendNoc, SendNoc failure status, and
  SendTrustedRootCert dispatch + ack.
- `tests/state_machine_noc.rs` placeholder integration test pending
  M6.4.6's synthetic-CSR fixtures.

#### Added (M6.4.3 — Certification Declaration verification)

- New `cms` dependency (RustCrypto 0.2.x) for CMS/PKCS#7 SignedData parsing.
- `attestation::cd` module: `CdSigningRoots`, `verify_certification_declaration`.
  Five-stage verifier: CMS parse → envelope shape → ECDSA-P256/SHA-256
  signature → inner CD TLV decode → VID/PID cross-check.
- Bundled CSA-test CD signing root at
  `src/attestation/cd/csa_cd_signing_roots/csa-test-cd-signing-root.pem`
  (for tests + examples only; production callers supply CSA-published
  roots via `CdSigningRoots::from_pem`).
- Five new `AttestationError` variants:
  `CertificationDeclarationMalformed`,
  `CertificationDeclarationSignatureInvalid`,
  `CertificationDeclarationTlvMalformed`,
  `CertificationDeclarationVidMismatch { declared, expected }`,
  `CertificationDeclarationPidMismatch(ProductId)`.
- State machine's `AttestationVerification` stage now calls CD verification —
  the M6.4.2 `CdVerificationUnavailable` placeholder is removed; the cursor
  advances past attestation on a valid CD. The hard gate for M6.6
  documented in `TODO-1.0.md` is now closed.
- `xtask capture-cd` subcommand generates synthetic CD fixtures
  (happy + tampered + wrong-vid) for testing.
- New integration test `tests/cd_verification.rs` (5 cases) exercising
  the verifier against the synthetic fixtures.

#### Added (M6.4.2 — Attestation on-wire flow + verifier glue, CD-incomplete)

- `noc::commands`: `CertChainType` enum + `encode_certificate_chain_request` /
  `decode_certificate_chain_response` (OpCreds CertificateChainRequest);
  `encode_attestation_request` / `decode_attestation_response`
  (OpCreds AttestationRequest).
- `attestation::extract_attestation_elements_fields` +
  `AttestationElementsFields` — parses the device's `attestation_elements`
  TLV blob into CD bytes + 32-byte nonce + timestamp; new
  `AttestationError::ResponseElementsMalformed` variant.
- State machine: four new stages (`SendPaiCertRequest`, `SendDacCertRequest`,
  `SendAttestationRequest`, off-wire `AttestationVerification`) wired into
  `Commissioner`. The off-wire stage chains M6.2's `verify_chain` +
  `verify_attestation_response` + the nonce-echo check.
- CD verification is intentionally absent — the off-wire stage returns
  `CommissioningError::CdVerificationUnavailable` until M6.4.3 lands the
  CMS-based CD verifier. The state machine refuses to advance past
  attestation without CD verification.
- Negative-path coverage for tampered PAI DER + the `#[ignore]`-d
  integration test placeholder pending captured DAC/PAI/AttestationResponse
  fixtures.

#### Added (M6.4.1 — Commissioning state machine skeleton)

- `state_machine` module: cursor-driven `Commissioner` modeled on
  `connectedhomeip`'s `AutoCommissioner`. Public re-exports of
  `Stage`, `Action`, `Expectation`, `SessionContext`,
  `CommissioningError`, `CommissionedFabric`, `Commissioner`,
  `CommissionerConfig`.
- `clusters::general_commissioning` codecs for `ArmFailSafe`,
  `SetRegulatoryConfig`, `CommissioningComplete`, and their responses.
- M6.4.1 implements stages `SecurePairing` → `ReadCommissioningInfo` →
  `ArmFailsafe` → `ConfigRegulatory`. Subsequent stages short-circuit
  to `Failed` with `CdVerificationUnavailable` until M6.4.2 / M6.4.3
  land.
- Negative-path matrix (`tests/state_machine_unit.rs`) + proptest
  totality coverage (256 cases each for `poll_never_panics` and
  `on_response_never_panics`).

#### Added (M6.3.3 — OpCreds command codecs + matter.js byte-parity)

- `noc::commands` — OperationalCredentials cluster (`0x003E`)
  NOC-issuance subset: `encode_csr_request`, `decode_csr_response`,
  `encode_add_trusted_root`, `encode_add_noc`, `encode_update_noc`,
  `decode_noc_response`. Free functions; M7's codegen will replace
  them with generated equivalents preserving the signatures.
- `CsrResponse { nocsr_elements: Vec<u8>, attestation_signature:
  [u8; 64] }` and `NocResponse { status: u8, fabric_index: Option<u8>,
  debug_text: Option<String> }` value types.
- New `xtask capture-noc` subcommand scaffolds matter.js capture of
  CSRRequest, CSRResponse, NOC chain, and AddNOC payload fixtures.
  Operator wires the matter.js NOC-mint API call (symbol path shifts
  per `@matter/protocol` minor version); RFC 6979 deterministic ECDSA
  guarantees the captured bytes reproduce.
- `crates/matter-commissioning/tests/noc_byte_parity.rs` — asserts
  our `issue_noc` + command codecs produce bytes identical to
  matter.js's for the captured fixtures. Skips with a warning if
  fixtures are not yet captured or have empty `expected_*_b64`
  fields, keeping CI green during the operator-touch capture work.
- `crates/matter-commissioning/fuzz/fuzz_targets/nocsr_parse.rs` —
  libfuzzer target on `parse_nocsr` + `parse_and_verify_csr`. Weekly
  CI only.
- `noc/mod.rs` rustdoc lists M6.3 as **feature-complete** with an
  explicit "What's deferred past M6.3" block (ICAC issuance, M6.4
  GeneralCommissioning, M6.5 NetworkCommissioning, M8 persistence,
  M6.6 real-device commission).

#### Crypto-sensitive areas in M6.3

The following areas warrant careful review for spec-correctness:
1. `noc/issuer.rs::issue_noc` — NOC Subject DN contents (FabricId /
   NodeId / CAT layout per spec §6.5.6), Extension contents
   (BasicConstraints / KeyUsage / EKU / SKI / AKI per §6.5.4),
   validity-window propagation, serial-number entropy.
2. `noc/csr.rs::verify_csr_response` — composition order
   (`elements || challenge`), constant-time nonce-echo gate, PKCS#10
   self-sig path via x509-parser + ring's `ECDSA_P256_SHA256_ASN1`.
3. `matter_cert::builder::UnsignedCertificate::tbs_der` + `assemble` —
   TBS DER bytes returned by `tbs_der()` are EXACTLY what gets signed
   and what the resulting cert's signature field covers (byte-identical
   to matter.js's `Certificate.asUnsignedDer()`); `assemble` is
   infallible by construction.
4. The shared `attestation::verify_dac_signed_elements` — extracted
   from M6.2.3's `verify_attestation_response` without changing the
   `elements || challenge` order or the
   `ring::signature::ECDSA_P256_SHA256_FIXED` algorithm. M6.2 tests
   pass bit-identical, confirming the refactor.
5. NOCResponse status-code → `NocError` mapping.
6. Negative-path fixtures at
   `test-vectors/commissioning/noc/negative/`.

#### Added (M6.3.2 — NOCSR verify + NOC issuance)

- `noc::csr` — `parse_nocsr` (NOCSR TLV envelope), `parse_and_verify_csr`
  (embedded PKCS#10 via x509-parser, self-sig verified by
  `ring::ECDSA_P256_SHA256_ASN1`), `verify_csr_response` (the
  three-check atomic gate: PKCS#10 self-sig, constant-time CSRNonce
  echo compare, DAC attestation sig via the shared
  `verify_dac_signed_elements` primitive). `VerifiedCsr`'s existence
  is proof verification happened.
- `noc::issuer::issue_noc` — builds NOC Subject DN (FabricId + NodeId
  + CATs), Extensions (cA=false, DIGITAL_SIGNATURE KU, client_auth +
  server_auth EKU, SKI=SHA1(csr_pub[1..]), AKI=fabric.root SKI),
  validates via the matter-cert builder, signs via
  `fabric.root_signer.sign_p256_sha256`, assembles.
- 8 synthetic negative-path fixtures under
  `test-vectors/commissioning/noc/negative/` generated by
  `scripts/gen-noc-negative-fixtures.py` (committed; CI does NOT
  recompute). Each pairs a tampered NOCSR with the expected
  `NocError` variant.
- `crates/matter-commissioning/tests/noc_happy_path.rs` — synthetic
  end-to-end (mint device CSR, mint DAC key, sign NOCSR, verify,
  issue NOC).
- `crates/matter-commissioning/tests/noc_negative.rs` — table-driven
  matrix asserting each fixture surfaces its expected variant.
- `crates/matter-commissioning/tests/noc_round_trip.rs` — issued NOC
  parses back through `MatterCertificate::from_tlv` and validates
  against the issuing RCAC via `CertificateChain::validate`.
- `crates/matter-commissioning/tests/noc_proptest.rs` — random
  `(node_id, cats)` → NOC TLV round-trip.
- `base64` + `hex` workspace deps added (negative-fixture decode).

#### Added (M6.3.1 — Foundation)

- `matter-cert` public Builder API. Two-step
  `builder()...build_unsigned()?.tbs_der()?` → external signer →
  `assemble(sig)`. matter-cert bumps to `0.2.0-pre`. The signer
  trait is NOT a matter-cert dep — keeps the layering clean.
- `matter-crypto::Signer` re-export (alias for `CaseSigner`) — cleaner
  import path for non-CASE callers.
- `attestation::verify_dac_signed_elements` extracted from
  `verify_attestation_response`. The M6.2.3 public API
  (`verify_attestation_response`) signature is byte-identical; one
  audited primitive now serves both callers.
- `noc/` module replaces the `noc.rs` placeholder. `NocError`
  (coarse-grained), `NocRng` + `SystemNocRng` (caller-supplied RNG
  abstraction).
- `FabricRecord::new_root_only` — builds + self-signs the RCAC via
  the matter-cert builder + a caller-supplied
  `Arc<dyn matter_crypto::Signer>`. ICAC slots reserved
  (`icac_signer: Option<...>`, `icac_cert: Option<...>`) so a future
  `new_with_icac` constructor is non-breaking.
- `crates/matter-commissioning/tests/noc_fabric_record.rs`
  integration test — RCAC round-trips through TLV, distinct IPK per
  fabric.

#### Added (M6.2.3 — `AttestationResponse` + matter.js byte-parity)

- `attestation::verify_attestation_response(&AttestationResponse, &[u8; 16],
  &[u8]) -> Result<(), AttestationError>` — pure sans-I/O ECDSA P-256 /
  SHA-256 verification via `ring` over `attestation_elements ||
  attestation_challenge`. Closes the M6.2 device-attestation surface.
- `attestation::AttestationResponse { attestation_elements: Vec<u8>,
  signature: [u8; 64] }` value type. `signature` is raw IEEE P1363 r||s
  per Matter §3.5.3 — not ASN.1 DER.
- New `AttestationError::BadResponseSignature` variant. Deliberately
  coarse: a single outcome covers signature corruption, wrong key,
  wrong challenge, tampered elements, and malformed-key bytes, so the
  error channel cannot leak which secret an attacker probed close to.
- New `xtask capture-attestation` subcommand. Mints a P-256 keypair
  via `@matter/general 0.16.11`'s `NodeJsStyleCrypto`, signs an opaque
  `(elements, challenge)` blob, cross-verifies happy-path + four
  single-byte mutations under matter.js's verifier, and emits
  `test-vectors/attestation/response/happy-path.json` with a verdict
  matrix.
- New `crates/matter-commissioning/tests/attestation_response_byte_parity.rs`
  integration test — asserts Rust and matter.js agree on accept/reject
  for every tuple in the fixture (1 happy-path + 4 mutations).
- New `crates/matter-commissioning/tests/attestation_response_proptest.rs`
  property test — 4 properties: sign+verify round-trip with random
  P-256 keypairs + single-bit-flip rejections on signature, challenge,
  and elements.
- `ring` added as a direct dep on `matter-commissioning`; `p256`
  promoted to dev-dep for proptest keypair generation. Both already in
  `[workspace.dependencies]` — no new third-party ingress.
- `TODO-1.0.md` gains a new `matter-commissioning` section with the
  **CD-before-M6.6 hard gate**: Certification Declaration verification
  must land before M6.6 attempts a real-device commission. Without it,
  a genuine DAC for product X could fraudulently claim to commission
  product Y.
- `attestation/mod.rs` rustdoc now lists M6.2 as **feature-complete**
  with an explicit "What's deferred past M6.2" block.

#### Notes on the byte-parity claim

ECDSA signing uses a fresh random `k` per call, so the raw signature
bytes differ across capture runs. Byte-parity is on the **verdict
matrix** (one happy-path accept + four mutation rejects), not the raw
bytes. Re-running `cargo xtask capture-attestation` rewrites the
fixture file; the test assertions remain stable.

#### Added (M6.2.2 — chain validation)

- `attestation::verify_chain(&Dac, &Pai, &PaaTrustStore, MatterTime)
  -> Result<ChainVerification, AttestationError>` runs `rustls-webpki`
  0.103 path validation with `KeyUsage::client_auth()` enforcement
  (Matter §6.5 EKU is enforced by webpki itself), then layers Matter
  §6.2.3's VID/PID equality overlay.
- `attestation::ChainVerification { vendor_id, product_id,
  dac_public_key, paa_subject }` is the success type. `dac_public_key`
  flows into M6.2.3's `verify_attestation_response`; `paa_subject` is
  the DER-encoded PAA Name for audit logging.
- Six new `AttestationError` variants: `InvalidChain` (boxed source),
  `TimeBoundsViolation`, `BasicConstraintsViolation`, `UntrustedRoot`,
  `VidMismatch { dac, pai }`, `PaiVidNotAuthorized`. The
  `webpki::Error` -> typed variant mapping is documented as a table
  in `error.rs`'s rustdoc.
- 8 synthetic negative-path fixtures under
  `test-vectors/certs/attestation/negative/` generated by
  `scripts/gen-negative-fixtures.py` (one-shot Python, output
  committed). Each fixture exercises one row of the spec's matrix:
  expired/not-yet-valid validity, broken DAC/PAI signatures, mismatched
  VID, untrusted PAA, DAC with `cA = true`, wrong EKU.
- `tests/attestation_negative.rs` table-driven integration test
  asserting each fixture yields its spec-mandated variant.
- `tests/attestation::chain` happy-path test against the bundled CSA
  test attestation chain (DAC + PAI for VID `0xFFF1`).
- Third libfuzzer target: `fuzz_dac_from_der`. Corpus seeded with
  happy-path + a signature-tampered DER.
- Crate-root re-exports for `verify_chain` and `ChainVerification`.
- `attestation::x509::Pai::issuer_raw()` accessor — returns the
  DER-encoded issuer Name SEQUENCE, cached at construction so
  `verify_chain`'s hot path stays infallible.

#### Spec deviations recorded for M6.2.2

- M6.2 spec mandated `rustls-webpki = "0.102"`; bumped to `0.103`
  because four RUSTSEC advisories (2026-0049/0098/0099/0104) opened
  against the 0.102 line after the spec was written, all fixed only
  in `>=0.103.13`.
- M6.2 spec listed `webpki::Error::BasicConstraintsViolated` in the
  mapping table. webpki 0.103 splits that case across
  `EndEntityUsedAsCa`, `CaUsedAsEndEntity`, and
  `PathLenConstraintViolated`; all three fold into our single
  `BasicConstraintsViolation` variant.
- M6.2 spec specified a `missing-eku` negative fixture. webpki
  (correctly, per RFC 5280 §4.2.1.12) treats an absent EKU
  extension as unconstrained, so a missing-EKU fixture would not
  exercise any rejection path. Replaced with `wrong-eku`: DAC EKU
  contains `id-kp-serverAuth` instead of `id-kp-clientAuth`, which
  webpki rejects with `RequiredEkuNotFound`.

#### Added (M6.2.1 — attestation foundation)

- `attestation::Dac`, `attestation::Pai`, `attestation::Paa` — typed
  X.509 wrappers around DER-encoded Matter Device Attestation
  Certificates, Product Attestation Intermediates, and Product
  Attestation Authorities (Matter Core Spec §6.2). Each exposes
  `from_der`, `der`, `public_key`, and Matter-specific subject-DN
  accessors (`subject_vid` / `subject_pid`). Parsing only — chain
  validation arrives in M6.2.2 and `AttestationResponse` signature
  verification in M6.2.3.
- `attestation::PaaTrustStore` with `empty()` / `add()` / `len()` /
  `is_empty()` / `iter()` and a `with_csa_test_roots()` constructor
  that embeds the vendored CSA test PAAs via `include_bytes!` —
  test-roots only; production callers build their own store.
- `attestation::VendorId` and `attestation::ProductId` newtypes around
  `u16` with `new()` constructors and Matter VID/PID OID extraction
  helpers used by the cert wrappers.
- `attestation::AttestationError` enum (`#[non_exhaustive]`) with the
  `Parse` variant carrying a boxed source error. Future
  validation/signature variants land in M6.2.2 / M6.2.3.
- Crate-root re-exports for `Dac`, `Pai`, `Paa`, `PaaTrustStore`,
  `VendorId`, `ProductId`, `AttestationError`.
- New dependency: `x509-parser` 0.16 for X.509 DER field extraction.
- Vendored CSA test attestation fixtures (PAA / PAI / DAC, VID
  `0xFFF1`) from `project-chip/connectedhomeip` (Apache-2.0) under
  `crates/matter-commissioning/src/attestation/csa_test_roots/` and
  `test-vectors/commissioning/attestation/`.
- Integration test `tests/attestation_parse.rs` covering happy-path
  DAC + PAI + PAA parsing against the bundled CSA test chain.

#### Added (M6.1 — setup payload codec)

- `setup::SetupPayload` — canonical in-memory representation of a Matter
  onboarding payload (Matter Core Spec §5.1).
- `setup::Discriminator` and `setup::Passcode` newtypes with
  range-validating constructors. The 12-bit discriminator's `short()`
  accessor returns the 4-bit short form carried by manual pairing codes.
- `setup::CommissioningFlow` enum (Standard / UserIntent / Custom);
  reserved values rejected on parse.
- `setup::DiscoveryCapabilities` bitflags preserving spec-reserved bits
  on roundtrip.
- `setup::parse_qr` / `setup::encode_qr` — `MT:`-prefixed Base38 codec
  for the 88-bit fixed block. Vendor TLV extensions are not yet supported
  (deferred to a later phase).
- `setup::parse_manual_code` / `setup::encode_manual_code` — 11- and
  21-digit manual pairing codes with Verhoeff (ISO/IEC 7064 mod-11,10)
  check digit.
- Byte parity against matter.js across 13 captured fixtures
  (spec-example, edge discriminators / passcodes, all-discovery, UserIntent,
  high VID/PID, 11- and 21-digit manual codes).
- Fuzz targets for `parse_qr` and `parse_manual_code` (no-panic property).
- Proptest roundtrip suite (3 properties × 256 cases default).

## matter-transport

### [Unreleased] — M9-C1 `transport_reliable` (BTP prep)

#### Added

- **`Session::transport_reliable` flag** + `SessionManager::set_transport_reliable`/
  `is_transport_reliable` — marks a session as riding a transport that is
  itself reliable and ordered (BTP over BLE, or an in-memory channel), per
  Matter Core §4.12 ("MRP off over BLE"). When set, the MRP layer never sets
  the R-flag on outbound messages, never registers a retransmit, and never
  arms a standalone-ack timer for that session, regardless of the peer's own
  `mrp_flags.reliable` bit. UDP sessions are unaffected — the flag defaults
  `false` and existing MRP behavior is unchanged.

## matter-transport

### [Unreleased] — M9-E3 group-secured framing + IPv6 multicast send

#### Added

- **`encode_group_secured(key, group_session_id, source_node_id, group_id, counter, protocol_header, app_payload) -> Result<Vec<u8>>`** —
  encodes and AES-CCM-128 encrypts a Matter group secured message (Matter Core
  Spec §4.15 / §4.4 / §4.8.2). Differs from the unicast `encode_secured` path
  in five spec-mandated ways: the operational group key is supplied directly
  (no per-session i2r/r2i split); `SecurityFlags::SESSION_TYPE_GROUP` (`0x01`)
  is set; the message-flags byte is `0x06` (`DEST_GROUP | SOURCE_PRESENT` — both
  source node id and 2-byte group id are present in the header); the AES-CCM
  nonce is `SecurityFlags(1) || MessageCounter(4 LE) || SourceNodeId(8 LE)`;
  and there is no MRP (group commands are unacknowledged). Byte-parity confirmed
  against an independent matter.js group-message vector
  (`test-vectors/transport/group-message.json`). Re-exported at the crate root.
- **`decode_group_secured(bytes, key) -> Result<(SecuredMessageHeader, Vec<u8>)>`** —
  decrypts and decodes a group secured message produced by `encode_group_secured`
  or a matter.js group sender. Returns the parsed header (carries source node id
  and group id) plus the decrypted plaintext. No replay window — the caller owns
  per-group replay tracking. Re-exported at the crate root.
- **IPv6 multicast send** — `TokioUdpTransport::bind_addr` now sets
  `IPV6_MULTICAST_HOPS` to `MATTER_GROUP_MULTICAST_HOPS` (8) at bind time via
  `socket2`, so the existing `Transport::send` call routes `ff35:…` group
  datagrams at the correct hop limit without any API change. `set_multicast_if_v6`
  is deliberately **not** called: macOS rejects interface index 0 with `EINVAL`;
  the OS kernel default (equivalent to index 0 on Linux) gives the same routing
  behaviour. A `bind_addr_with_if` variant for explicit interface selection on
  multi-NIC hosts is the noted follow-up (see E3 runbook).
- **`MATTER_GROUP_MULTICAST_HOPS`** (= 8) — public constant for the hop limit
  applied to all multicast sends. `ff35:…` is site-local scope (scope nibble 5);
  a limit of 8 clears any realistic intra-site path while staying well clear of
  global scope.

### [0.1.0-pre] — 2026-05-22 (not yet published)

#### Changed (M6.6.3a — session-id foundation)

- `SessionManager` gains `allocate_session_id()` (reserve a local id without
  registering) and `register_pase_with_local_id(...)` (register a PASE session
  under a caller-chosen local id). `register_case` now registers under
  `output.local.session_id` (the id advertised in Sigma1) instead of
  auto-allocating, so the peer's secured packets demux to the right session.

#### Changed (M6.6.2 — driver support)

- Re-exported `encode_header` / `decode_header` from the crate root (needed by
  `matter-commissioning`'s unsecured PASE framing layer; previously only
  `encode_secured` / `decode_secured` were re-exported).

#### Added (M5.1 — framing + session manager skeleton)

- Secured-message header encode/decode with bit positions matching matter.js's
  `PacketHeaderFlag` (matter.js's actual wire layout differs from a literal
  reading of Matter Core Spec §4.4.1; matter.js is the byte-parity source
  of truth).
- AES-CCM-128 payload wrapping (consumes `matter_crypto::aead`).
- 32-bit sliding-window replay protection.
- `SessionManager` skeleton: `register_pase`, `register_case`, encode/decode
  outbound/inbound.
- `framing::encode_secured` / `decode_secured` byte-identical to matter.js
  across 3 captured fixtures (PASE-session keys, CASE-session keys, MRP-payload
  variant).
- `matter-crypto`: new public `aead` module promoting `aead_encrypt` /
  `aead_decrypt` out of `case/sigma.rs` so `matter-transport` consumes
  AES-CCM via one source of truth.

#### Added (M5.2 — MRP + protocol header)

- Matter application protocol header codec
  (`protocol_header::{encode, decode, build_standalone_ack_header}`),
  skip-and-ignore SX/V extensions.
- Byte-identical to matter.js across 3 captured fixtures
  (initiator-reliable, responder-ack, standalone-ack). Wire layout
  rewritten from initial spec-text reading: matter.js conditionally
  emits `vendor_id` and orders `protocol_short` before `vendor`.
- Per-session `MrpState` sans-IO state machine: pending retransmits,
  piggyback ack queue with 200ms standalone-ack deadline, exchange
  table tracking `is_local_initiator`, 32-entry recent-reliable cache
  for duplicate-reliable detection.
- `MrpConfig` defaults match Matter Core Spec §4.11.8 (300ms / 4200ms
  / ×1.6 / 5 attempts / 200ms ack-deadline / 5s idle threshold). No
  jitter — controllers don't have the thundering-herd problem.
- `SessionManager` now threads protocol header + MrpState through
  `encode_outbound` / `decode_inbound`; new `poll_timeout` /
  `handle_timeout` API; new `DecodeInboundOutput::DuplicateReliableAckResent`
  variant for the duplicate-resend path.

#### Added (M5.3 — Tokio UDP + mdns-sd adapters)

- `transport::Transport` trait + `PeerAddress` newtype (around
  `SocketAddr`; carries IPv6 link-local `scope_id` natively).
- `discovery::Discovery` trait + `MatterService` + `ServiceKind`
  (Commissionable / Commissioner / Operational) + `QueryHandle`.
- `TokioUdpTransport` (cfg `tokio`): dual-stack
  `[::]:port` binding with `IPV6_V6ONLY = false` via `socket2`; sync
  `try_send_to` / `try_recv_from`; caller drives readiness.
- `MdnsSdDiscovery` (cfg `mdns-sd`): two constructors (`new()` spawns
  own daemon; `with_daemon(d)` reuses an injected one); publish + query
  + stop_query + poll_results; `ServiceResolved` → `MatterService`.
- New `Error::Io(io::Error)` cfg tokio + `Error::Mdns(String)` cfg
  mdns-sd variants.
- `xtask check` extended with feature-matrix smoke (no-default-features,
  tokio-only, mdns-sd-only) catching cfg-gating bugs.
- New deps: `tokio` 1.x (workspace, optional, features `net + rt + io-util`),
  `mdns-sd` 0.13 (CLAUDE.md approved), `socket2` 0.5 (for the
  `IPV6_V6ONLY` configure-before-bind step).
- Loopback integration test: two `TokioUdpTransport` instances exchange
  one reliable request + piggyback-acked response across the full M5
  stack on real sockets.

#### Not yet shipped

- Real-device interop testing (M6 commissioning).
- `cargo publish` (deferred per standing user stance).
- Cross-host mDNS interop verification.
- IPv4-only build path (Matter is IPv6-primary).
- TCP transport (post-1.0).
- BLE commissioning transport (post-1.0).
- Group messaging (post-1.0).

## matter-transport

### [Unreleased] — explicit multicast egress interface

#### Added

- **`TokioUdpTransport::bind_with_multicast_if` / `bind_addr_with_multicast_if`**
  — bind variants taking an explicit IPv6 multicast egress interface index
  (`IPV6_MULTICAST_IF`); `None`/`Some(0)` falls back to the
  `MATTER_MULTICAST_IF` env var, then the kernel default. Consumed by
  `MatterControllerBuilder::multicast_interface`.

## matter-crypto

### [Unreleased] — CASE resumption records on the full handshake (OTA follow-up)

#### Changed

- **BREAKING (pre-release): `ResumptionRecord.shared_secret` widened
  `[u8; 16]` → `[u8; 32]`** — the record now stores the session's full raw
  ECDH `SharedSecret` (Matter Core §4.14.8), matching what chip's
  `SessionResumptionStorage` and matter.js persist and use as the HKDF IKM
  for the resumption MICs and resumed session keys. The previous 16-byte
  width was a fixture artefact and could never interoperate with a real
  peer. All `sigma::*_resume_*` helpers take the 32-byte secret; CASE
  resumption fixtures regenerated with a 32-byte prior-session secret.

#### Added

- **Full CASE handshakes now produce a `ResumptionRecord`** in
  `CaseSessionOutput.resumption_record` on BOTH sides (previously `None` —
  resumption was unreachable in practice). The initiator pairs the
  responder's fresh `resumption_id` from TBEData2 with the session's ECDH
  secret; the responder samples that id (`SystemRandom`; previously a
  hardcoded all-zero id was sent) and keeps the same pair. Either peer can
  later present the id in Sigma1 and the other can `accept_resumption` —
  proven by the new role-flipped roundtrip test
  (`full_handshake_records_flip_roles_for_resumption`), which is exactly the
  OTA provider-server scenario (device resumes against the controller).
- Byte-parity tests for the resumption paths un-ignored: the pinned
  Sigma1-resume MIC and `Sigma2_Resume` bytes match our output exactly (the
  old `#[ignore]` reasons were test-input bugs, not composition bugs).
- **BREAKING (pre-release): `CaseInitiator::new_with_resumption` takes an
  `initiator_session_id: u16`** (mirroring `new`) — it previously hardcoded
  session id 0, which collides with the unsecured session and made the
  resumption initiator unusable for real secured traffic.

#### Fixed

- **Resumed-session key split corrected to i2r-first** — both resumption
  paths assigned `r2i = keys[0..16], i2r = keys[16..32]` (a misreading of
  matter.js's `isResumption` branch), the reverse of what chip's
  `CryptoContext::InitFromSecret` does for `kSessionResumption` (identical
  to session establishment: `I2RKey || R2IKey || AttestationChallenge`).
  Self-consistent loopback tests could never catch this (both sides agreed
  with each other); chip's OTA requestor rejected every secured message on
  a resumed session with a decryption failure. Live-verified against
  `chip-ota-requestor-app`.

### [Unreleased] — M9-E2 operational group crypto

#### Added

- **`derive_group_session_id(operational_group_key: &[u8; 16]) -> Result<u16>`** —
  derives the 16-bit group session id from a 16-byte operational group key
  (Matter Core Spec §4.15.2). KDF: HKDF-SHA256, IKM = operational group key,
  salt = empty, info = `"GroupKeyHash"` (12 bytes, no ` v1.0` suffix —
  confirmed against connectedhomeip `CHIPCryptoPAL.cpp::DeriveGroupSessionId`
  and `TestGroup_SessionIdDerivation`), output = 2 bytes interpreted as
  big-endian `u16`, no bit-masking applied. Re-exported at the crate root.
- **`group_multicast_ipv6(fabric_id: u64, group_id: u16) -> std::net::Ipv6Addr`** —
  constructs the operational group multicast IPv6 address (Matter Core Spec
  §2.5.6): `ff35:0040:fd<fabric_id_be>:00<group_id>`. Takes the **raw
  operational Fabric ID** (`u64`) — NOT the Compressed Fabric Identifier
  (the 8-byte HKDF output of `derive_compressed_fabric_id`). Mirrors chip's
  `BuildMatterPerGroupMulticastAddress` which takes `FabricId` (raw `uint64_t`)
  and writes its 8 big-endian bytes into the prefix. Pure byte assembly; no
  HKDF or crypto primitive involved. Re-exported at the crate root. Byte-parity
  confirmed against connectedhomeip
  `PeerAddress.h::BuildMatterPerGroupMulticastAddress` and
  `TestPeerAddress.cpp::TestPeerAddressMulticast`; a second KAT
  (fabric `0x2906C908D115D362`, group `0x0007`) regression-locks the
  raw-vs-compressed distinction (compressed id `87e1b004e235a130` would produce
  a different address).
- The **operational group key** itself reuses the existing
  `derive_operational_ipk(epoch_key, compressed_fabric_id)` — the same
  `"GroupKey v1.0"` HKDF derivation that produces the CASE Sigma1 IPK also
  produces the operational group key per spec §4.15.2. No new function needed.

#### Test vectors

- `test-vectors/operational/group-crypto.json` — known-answer vectors sourced
  from **connectedhomeip** (`TestGroup_SessionIdDerivation`,
  `TestPeerAddressMulticast`), independently verified via a Python3
  HKDF-SHA256 reproduction. Two independent sources; no self-derived vectors.

### [Unreleased] — M9-D1 commissioning window helpers

#### Added

- **`pake_passcode_verifier(passcode: u32, salt: &[u8], iterations: u32) -> Result<[u8; 97]>`** —
  derives the PAKE2+ verifier bytes from a setup passcode using PBKDF2-HMAC-SHA256
  with the supplied salt and iteration count. The 97-byte output is the
  `PAKEPasscodeVerifier` field required by `OpenCommissioningWindow` (Matter Core
  Spec §3.10.7.2). Re-exported at the crate root; was previously an internal PASE
  helper, now part of the public surface.
- **`random_bytes(buf: &mut [u8]) -> Result<()>`** — fills `buf` with
  cryptographically secure random bytes via `ring::rand::SystemRandom`. Exposed
  so callers generating commissioning-window secrets (passcode, salt,
  discriminator) can use the same RNG primitive without reaching inside the pase
  module. Re-exported at the crate root.

### [0.1.0-pre] — 2026-05-20 (not yet published)

#### M6.6.3a — session-id plumbing + operational identity (foundation)

- `PaseProver::new_with_negotiation` / `new_with_known_params` now take an
  `initiator_session_id` (the non-zero secured-session id advertised to the
  peer; previously hardcoded 0). `PaseProver::responder_session_id()` exposes
  the peer's id captured from `PBKDFParamResponse`.
- `PaseVerifier::new` / `new_from_pin` take a `responder_session_id`.
- `CaseInitiator::new` takes an `initiator_session_id`; `CaseResponder::new`
  takes a `responder_session_id` (threaded through the resumption-path states
  too). `CaseSessionOutput.local/.peer.session_id` already recorded both.
- New `operational` module: `derive_compressed_fabric_id` (Matter Core Spec
  §4.3.2.2; HKDF-SHA256 via `ring`, IKM = root pubkey X‖Y, salt = fabric-id
  big-endian, info `"CompressedFabric"`, 8-byte output). Byte-parity confirmed
  against the spec worked example (connectedhomeip `TestCompressedFabricIdentifier`);
  vector at `test-vectors/operational/compressed_fabric_id.json`.
- New `Error::KeyDerivationFailed` variant for the operational HKDF path.
- No cryptographic *math* changed — these expose existing wire fields and add
  an identity derivation.

#### Added (M4 — CASE / SIGMA-I)

- `CaseInitiator` + `CaseResponder` sans-IO state machines for Matter
  operational session establishment (SIGMA-I, spec §4.13). [M4.1]
- `CaseSigner` trait + `RingSigner` in-tree implementation. Embedded
  callers can wire HSM/TPM/secure-element signers by providing their own
  `CaseSigner` impl. [M4.1]
- Full Sigma1/2/3 new-session handshake: ephemeral P-256 ECDH, mutual
  ECDSA signatures, AES-CCM-128 encrypted blobs, NOC chain validation
  via `matter-cert::CertificateChain::validate`. [M4.1]
- Session resumption: Sigma1 + Sigma2_Resume fast path. Responder exposes
  `accept_resumption` / `reject_resumption` for caller-driven store lookup
  (sans-IO purity). [M4.2]
- `CaseSessionOutput` with split `keys` / `peer` / `local` /
  `resumption_record`. [M4.1–M4.2]
- `Sigma1Outcome` enum surfaces resumption requests for the caller. [M4.2]
- `xtask capture-case` subcommand — Node script using @noble/curves +
  Node ECDH + matter.js TLV codecs to drive CASE handshakes with fixed
  scalars and emit JSON fixtures. [M4.3]
- Three captured test-vector scenarios in `test-vectors/case/`:
  handshake-new-session, handshake-resumption-accepted,
  handshake-resumption-declined. [M4.3]
- `tests/case_byte_parity.rs` — new-session byte-parity passes
  byte-for-byte against matter.js. Resumption byte-parity deferred
  (see TODO-1.0.md). [M4.3]
- Two proptest properties: random NodeID roundtrip; byte-flip-in-Sigma2
  never panics. [M4.3]
- New deps: `ccm 0.5` + `aes 0.8` (RustCrypto) for AES-CCM-128 —
  `ring 0.17` does not expose AES-CCM which Matter requires.

#### Added (M3 — PASE / SPAKE2+)

- PASE state machines (`PaseProver`, `PaseVerifier`) with sans-IO API. [M3.1–M3.3]
- TLV wire-format codec for the 5 PASE messages (PbkdfParamReq/Resp, Pake1/2/3). [M3.2]
- SPAKE2+ math over P-256 with Matter's M and N constants. [M3.1]
- PBKDF2 setup-PIN derivation, HKDF confirmation/session-key derivation. [M3.1]
- `PasePbkdfParams`, `PaseSessionKeys`, `PaseMessageKind` public types. [M3.2]
- `test-support` Cargo feature gating `prover_with_scalar` /
  `verifier_with_scalar` constructors. [M3.2]
- Byte-parity tests against matter.js: negotiation, known-params,
  max-iterations scenarios. [M3.3]
- Two proptest properties: random PIN roundtrips; random byte-flip
  never panics. [M3.3]
- New deps: `p256 0.13` (P-256 scalar/point math), `subtle 2.6`
  (constant-time compare). ring stays as primary crypto provider.

#### Fixed

- `RingSigner::sign_p256_sha256` now applies low-s normalization via
  `Signature::normalize_s()`. The `p256` crate's `SigningKey::sign()`
  does not guarantee low-s output (depends on RFC 6979 nonce); matter.js
  via @noble/curves always normalizes. Without this, ECDSA byte-parity
  with matter.js fails roughly half the time at random. This affects every
  signature produced by this crate, including matter-cert signing paths.

#### Not yet shipped

- CASE resumption byte-parity (known divergences documented in TODO-1.0.md).

## matter-cert

### [0.1.0-pre] — 2026-05-18 (not yet published)

#### Added

- Matter TLV-encoded certificate parsing and serialisation (`MatterCertificate::from_tlv` / `to_tlv`). [M2.1]
- `DistinguishedName` with typed `DnAttribute` variants for Matter-specific (NodeId, FabricId, RcacId, IcacId, CaseAuthenticatedTag, VendorId, ProductId) and standard X.509 attributes.
- `Extensions` parsing for `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`, `SubjectKeyIdentifier`, `AuthorityKeyIdentifier`.
- `MatterTime` newtype with Unix-time conversions and the `NO_EXPIRY` sentinel.
- `PublicKey::verify` — ECDSA-P256-SHA256 signature verification via `ring`. [M2.2]
- `MatterCertificate::to_x509_tbs_der` — Matter-to-X.509 DER TBSCertificate conversion, byte-identical to matter.js's `asUnsignedDer()`. [M2.3]
- `MatterCertificate::verify_signed_by(&issuer_key)` — full single-cert signature verification against an issuer's public key. [M2.3]
- `CertificateChain::validate(&roots, at)` + `TrustedRoots` + `TrustAnchor` — end-to-end chain walk with time, CA-bit, path-length, DN linkage, and signature checks. [M2.4]
- `test-support` Cargo feature gating a `test_support` module for cert construction in test code (not part of the stable API).
- [M6.6.4] `test_support::build_x509_der` — builds a fully-signed X.509 DER certificate (TBS via `to_x509_tbs_der`, signed with the issuer's P-256 key via `ring`, wrapped as the outer `Certificate`). Used to synthesise webpki-valid PAA→PAI→DAC attestation chains for hardware-free commissioning tests.
- [M6.6.4] `DnAttribute::VendorId`/`ProductId` now encode to X.509 RDNs (4-char uppercase-hex `PrintableString` under the Matter VID/PID OIDs) in `to_x509_tbs_der`, matching `matter-commissioning`'s `extract_vid`/`extract_pid`. Additive to the `#[non_exhaustive]` enum.

#### Test infrastructure

- 3-tier captured chain (`rcac.bin`, `icac.bin`, `noc.bin`) produced by matter.js's `CertificateAuthority` API.
- Per-cert X.509 TBS oracles (`*.tbs.bin`) for byte-parity verification.
- proptest properties: synthesised chains validate; random byte-flip never panics.

## [Unreleased]

### Added

- Initial Cargo workspace scaffolding (Milestone 0).
- Empty crate skeletons for `matter-codec`, `matter-cert`, `matter-crypto`,
  `matter-transport`, `matter-commissioning`, `matter-clusters`,
  `matter-controller`, and `xtask`.
- CI pipeline: `fmt`, `clippy`, `test` (Linux + macOS, stable), MSRV build
  (1.75), `cargo audit`, `cargo deny`.
- Project documentation: `README.md`, `CONTRIBUTING.md`, `docs/`.
- Pull request template.

### Changed

- Workspace MSRV raised from Rust 1.75 to Rust 1.88. Required to
  land `time >= 0.3.47` (RUSTSEC-2026-0009) pulled in transitively
  by `x509-parser` / `asn1-rs` in `matter-commissioning`. The
  patched `time` crate's `rust-version` is 1.88. Rationale captured
  in `docs/decisions/0001-workspace-layout.md`.

[Unreleased]: https://github.com/phunapps/matter-rust/commits/main
