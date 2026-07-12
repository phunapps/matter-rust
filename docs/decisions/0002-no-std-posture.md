# ADR 0002: no_std posture for 1.0

- **Status:** accepted
- **Date:** 2026-07-12
- **Milestone:** pre-1.0 cross-cutting (TODO-1.0 "no_std posture")

## Context

Embedded device makers — a natural audience for a Rust Matter library —
often require `no_std`. Retrofitting `no_std` late is expensive, so
TODO-1.0 required an explicit per-crate decision before 1.0: add a
default-on `std` feature now, or ship 1.0 as `std`-only.

Two facts shape the decision:

1. **This is a controller library.** The controller side of Matter runs on
   hubs, bridges, gateways and phones — Linux-class targets with an OS,
   sockets and mDNS daemons — not on the battery-class endpoints where
   `no_std` is mandatory. The device side (where `no_std` demand is real)
   is explicitly out of scope (`rs-matter` covers it).
2. **The transport core is already sans-io.** `matter-transport` builds
   and tests with `--no-default-features` (no tokio, no mdns-sd) in CI
   (the `embedded` gate job): framing, sessions, replay protection and MRP
   are pure state machines over byte slices. The codec (`matter-codec`)
   has a single dependency (`thiserror`). These are the crates an embedded
   consumer would actually want, and their *structure* is already portable.

## Decision

**1.0 ships `std`-only across all crates. `no_std` stays
deferred-until-requested (as CLAUDE.md's post-v1.0 list already states),
and we protect the retrofit path rather than pre-building it:**

- `matter-codec` and `matter-bdx` (alloc-only logic, trivial dep trees) are
  the designated first candidates if a real `no_std` consumer appears; the
  work there is mechanical (`alloc` imports + a `std` feature for
  `std::error::Error` impls).
- `matter-transport`'s sans-io core stays the seam: the CI `embedded` job
  keeps the tokio/mdns-sd-free build compiling so OS coupling cannot creep
  into the state machines.
- `matter-crypto`/`matter-cert` are gated on their crypto backend: `ring`
  has no first-class `no_std` story. A future `no_std` request means a
  backend abstraction (e.g. RustCrypto stacks) — that is a deliberate
  post-1.0 project, not a feature flag, and per the CLAUDE.md dependency
  rules it needs an explicit decision anyway.
- No crate adds a `std` cargo feature today: an untested feature
  combination is CI surface without a consumer, and feature-gating error
  types prematurely bakes in guesses about which `no_std` profile (alloc?
  bare-metal?) a hypothetical consumer needs.

## Consequences

- 1.0 documentation states the posture plainly: controller-focused,
  `std`-only, `no_std` on request — so embedded evaluators know where they
  stand without reading CI configs.
- The first genuine `no_std` request reopens this ADR with a concrete
  profile (which crates, alloc or not, which crypto backend) instead of an
  abstract one.
- Cost accepted: if that request arrives the day after 1.0, codec/bdx are
  days of work, crypto/cert are a real project. That ordering matches
  demand we have actually seen (none, to date).
