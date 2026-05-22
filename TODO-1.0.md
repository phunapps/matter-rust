# TODO before any matter-rust crate hits 1.0

This file tracks gaps deliberately deferred during M0–M2. Each item
must be resolved before claiming production readiness for the affected
crate.

## matter-cert

### Cross-verification against `project-chip/connectedhomeip`

**Status:** open.

**Why it matters:** `matter-cert`'s byte-parity gate currently runs
against matter.js's `Certificate.asUnsignedDer()` only. matter.js is
an excellent reference but has diverged from the CSA C++ canonical
implementation in the past. For interoperability claims, we want
identical output against both.

**Concrete deliverable:** a second set of captured cert fixtures
produced from `project-chip/connectedhomeip`'s cert-issuance tooling,
plus the byte-parity test extended to validate against both sets.
Probably lives under `test-vectors/certs/connectedhomeip/`.

### CSA test PAA roots not bundled

**Status:** open.

**Why it matters:** the M2.1 spec called for them ("Tier 1 — bundled
CSA test certificates"). What we shipped is matter.js-synthesised
operational certs (NOC/ICAC/RCAC). Attestation chains (DAC → PAI →
PAA) have different shape — VendorId/ProductId DN attributes, EKU =
`id-kp-codeSigning`, possibly different criticality flags — and the
parser may have untested code paths. M6 commissioning will need
attestation chains anyway.

**Concrete deliverable:** captured CSA test PAA roots in
`test-vectors/certs/csa-paa/`, plus a parse/validate test that
exercises the attestation-chain shape end-to-end.

### Public cert-construction API

**Status:** design pending.

**Why it matters:** `MatterCertificate::from_fields` exists as
`pub(crate)` solely for test use (via the `test-support` feature).
M6's commissioning work needs production NOC/ICAC issuance.

**Concrete deliverable:** either promote `from_fields` to public (with
appropriate validation gates and renaming, e.g.,
`MatterCertificateBuilder::new(...).build()`), OR design a separate
issuance crate. Decision deferred to whichever milestone first needs
it.

## matter-crypto

### External cryptographic protocol review (M3 PASE + M4 CASE)

**Status:** owned by the user; pending arrangement.

**Why it matters:** CLAUDE.md mandates external review for any crate
implementing cryptographic protocols. PASE (M3) and CASE (M4) are both
in scope. Implementations are complete; review is the remaining gate.

**Concrete deliverable:** review completed, feedback applied, sign-off
captured in a comment on `matter-crypto/README.md` or in a new
`docs/` artefact. Required before any `cargo publish matter-crypto`.

### CASE / SIGMA-I (M4) — DONE (new-session path)

**Status:** feature-complete and byte-parity verified for new-session
scenario against matter.js (M4.1 + M4.2 + M4.3).

New-session byte-parity passes byte-for-byte for Sigma1, Sigma2, and
Sigma3 against matter.js's `CaseClient.ts` / `CaseServer.ts`.

### CASE resumption byte-parity — OPEN

**Status:** open follow-up. Two specific divergences from matter.js.

**Why it matters:** The resumption fast-path (Sigma1 with resume fields
→ Sigma2_Resume) works correctly in local roundtrip (all M4.2 tests
pass). However, two byte-parity issues remain that prevent the
fixture-driven `tests/case_byte_parity.rs` resumption tests from
passing. Both tests are `#[ignore]`d with inline TODO comments.

**Issue 1 — `sigma1_resume_mic` composition:**
Our `compute_sigma1_resume_mic` in `initiator.rs` uses
`HKDF(shared_secret, salt=initiatorRandom||resumptionId, info="...")`.
matter.js's `CaseClient.ts` derives the MIC differently — the exact
HKDF input / AEAD construction needs realignment against the TypeScript
reference. The captured fixture's `initiator_resume_mic` field
diverges from our output for the same inputs.

**Issue 2 — fresh `resumption_id` in Sigma2_Resume:**
Our `CaseResponder::accept_resumption` generates a fresh
`resumption_id` via `SystemRandom::fill`. For byte-parity testing we
need a `_with_new_resumption_id` constructor on `CaseResponder`
(under the `test-support` feature) so the fixture's known
`new_resumption_id` value can be injected. Without this, the random
field causes Sigma2_Resume to differ from the fixture on every run.

**Concrete deliverable before publish:**
1. Align `compute_sigma1_resume_mic` with matter.js's derivation and
   update the `handshake-resumption-accepted` fixture accordingly.
2. Add `responder_with_new_resumption_id` to the `test-support` feature
   and wire it into `case_byte_parity.rs`'s resumption tests.
3. Remove the `#[ignore]` from both resumption byte-parity tests.

### matter.js capture-pase / capture-case RNG patching

**Status:** working, but fragile.

**Why it matters:** `xtask capture-pase` monkey-patches matter.js's
`Crypto.randomBytes` to inject fixed scalars; `xtask capture-case`
injects fixed ECDH scalars into `@noble/curves`. Both scripts are
sensitive to matter.js and @noble/curves version bumps. Hardcoded
scenario inputs live in the scripts.

**Concrete deliverable:** before 1.0, either upstream a public RNG
injection point to matter.js OR document the monkey-patch paths
clearly enough that they can be re-pinned against new matter.js /
@noble/curves versions in <30 minutes.

## Cross-cutting

### Benchmark suite

**Status:** open.

**Why it matters:** matter.js is slow (TypeScript + Node). One of our
positioning claims for matter-rust is "embedded-grade performance."
Without benchmarks, we won't know when we regress or whether the
claim holds. CASE handshake throughput vs matter.js is the most
load-bearing comparison.

**Concrete deliverable:** a `benches/` directory under each substantive
crate (`matter-codec`, `matter-cert`, `matter-crypto` once it lands)
running representative workloads via `criterion`.

### no_std posture

**Status:** open.

**Why it matters:** the embedded device makers who'd most want a
Rust Matter library typically require `no_std`. The current crates
default to `std`. Late-stage retrofitting `no_std` is expensive.

**Concrete deliverable:** decide, per crate, whether to add a `std`
Cargo feature (default-on) and gate `std`-only paths behind it. The
decision can wait until a real consumer surfaces, but should not wait
until after 1.0.

## matter-transport

### Real-device MRP timing tests (M6)

**Status:** deferred from M5.3 per Q5 design choice.

**Why it matters:** M5.2's simulated-clock tests cover the MRP state
machine exhaustively. M5.3's loopback test verifies the full stack on
real sockets but DOES NOT assert MRP retransmit timing (CI flake risk).
We have no integration test that confirms `tokio::time::sleep_until`
fires at the right moment under load.

**Concrete deliverable:** at M6's first-real-device commissioning, add
a timing-assertion integration test that observes the actual retransmit
counter on a deliberately-dropped packet and confirms the deadlines
match `MrpConfig::default()`. Bounded-time, with a generous upper bound
to tolerate CI variance.

### M8 `SessionRegistry` design

**Status:** open architectural decision for M8.

**Why it matters:** matter-transport's `SessionManager` deliberately
holds NO peer-address state. Sessions are transport-agnostic. The
caller (M6 commissioning, M8 controller) maintains its own
`HashMap<SessionId, PeerAddress>` populated at session-establishment
time.

**Concrete deliverable:** M8's `MatterController` introduces a
long-lived `SessionRegistry` mapping `SessionId → (PeerAddress,
peer_info, last_seen)` with lifecycle management
(register-on-session-establish, evict-on-session-close, refresh-on-
mDNS-update). M8 spec defines the exact shape; M6 may foreshadow with
a smaller commissioning-scope map.

### mDNS loopback interop in CI

**Status:** known limitation; test marked `#[ignore]`.

**Why it matters:** `mdns_sd_discovery::tests::self_publish_self_discover`
runs two `ServiceDaemon` instances on loopback (`::1`) and verifies the
querier observes the publisher's service. The test passes locally on
macOS and Linux dev hosts (~1s observed) but fails on both GitHub
Actions `ubuntu-latest` and `macos-latest` CI runners — the
containerized/VM network stacks don't deliver loopback mDNS announces
even when `enable_interface(IfKind::LoopbackV{4,6})` is set on both
daemons. The other 6 mDNS adapter tests cover the publish/query/
poll_results API surface; only the full publish→discover roundtrip is
affected.

**Concrete deliverable:** before 1.0, either (a) move the test to a
manual `xtask test-mdns-interop` invocation that runs outside CI, (b)
diagnose what GitHub Actions' network namespace blocks (likely
multicast on `lo`), and document the workaround, or (c) replace with
an in-process mDNS mock that doesn't touch sockets. Until then, run
`cargo test --features tokio,mdns-sd -- --ignored self_publish_self_discover`
locally to verify the full path.

### mdns-sd background-thread fragility

**Status:** known, not blocking M5.3 publish.

**Why it matters:** the `mdns-sd` crate spawns a process-wide
background daemon thread on `ServiceDaemon::new()`. If that thread
dies (panic, OS resource exhaustion, channel close), our
`MdnsSdDiscovery` adapter doesn't currently detect the death — the
caller just sees empty `poll_results` and timeouts.

**Concrete deliverable:** before 1.0, add either (a) a heartbeat check
(`MdnsSdDiscovery::is_healthy() -> bool` that pings the daemon), or
(b) automatic daemon respawn on detected channel disconnection. Track
upstream mdns-sd issue tracker for a "watchdog" API; consider
contributing one if not present.

### External cryptographic protocol review

**Status:** owned by the user; runs in parallel with development.

**Why it matters:** CLAUDE.md mandates external review for M3
(PASE/SPAKE2+) and M4 (CASE/SIGMA). The user has stated review runs
in parallel and does not block development. This item is here so
the requirement isn't lost — review must complete (and feedback be
applied) before any cargo publish of a crate touching protocol-level
crypto.
