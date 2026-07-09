# TODO before any matter-rust crate hits 1.0

This file tracks gaps deliberately deferred during M0–M2. Each item
must be resolved before claiming production readiness for the affected
crate.

## Deferred from the 2026-06-12 full-codebase audit → fold into M9

The 2026-06-12 audit (29 fixes landed on `main`, commits `3d1bb405`..`34457ecc`)
deferred four items into M9. **M9-A (2026-06-14) resolved the two matter-clusters
codegen forward-compat items** — unknown-nested-container skip (now drained via
`TlvReader::skip_container`), bitmap `from_bits_retain`, and `#[non_exhaustive]` on
generated data structs, all proven by synthetic forward-compat fixtures (commits
`143a2c15`..`6179aa31`). The two remaining items below are a large async
re-architecture and a perf follow-up — independent of the codegen work. Audit
backlog (uncommitted, local): `docs/audit/2026-06-12-backlog.md` +
`2026-06-12-findings.json`.

### 1. Controller actor serializes long commission/connect handlers — RESOLVED (M9-G-d)

**Status:** ✅ resolved in M9-G-d (commits `4b8a6028` commission, `bc309e39` +
`a50a8bc3` connect). See the `Actor::run` rustdoc in
`crates/matter-controller/src/actor.rs`.

Both multi-round-trip flows now run off the actor loop on `tokio::spawn`ed tasks
that report back over channels the `select!` drains, so other sessions' MRP +
liveness continue for the whole handshake window:
- **Commission** runs on its own freshly bound socket + discovery
  (`spawn_commission` → `handle_commission_completion`).
- **CASE connect** parks the triggering verb and drives the handshake off-loop
  through the actor's own socket via `HandshakeSocket` (no second socket, no
  session migration); `run_connect_task` → `handle_connect_done` registers the
  session and re-dispatches the parked verbs. Device resolution stays inline (a
  brief bounded mDNS poll) to preserve the discovery seam.

Proven by hermetic concurrency tests
(`commission_completion_drains_while_loop_stays_responsive`,
`connect_handshake_runs_off_loop_which_stays_responsive`) — a stalled
commission/handshake no longer blocks unrelated commands.

**Residual (minor):** the two low-frequency *recovery* connects (a pending
round-trip's post-timeout reconnect and a stranded resubscribe, both from the
timer arm) still use the inline `connect()`. Not a steady-state concern.

### 2. matter-codec per-element budget check has a measurable decode cost

**Status:** open perf follow-up; not blocking.

The element-budget DoS defense added in the audit (`b4ab6a65`, `charge_element`
in `read_container_body`) is charged once per materialised `Value`, including
struct/scalar fields. Benchmarking audit-HEAD vs pre-audit (`f362533a`) showed
report parsing **-22%** and array decode **-9%** (faster), but a
`struct_500_uint` micro-bench **+10% slower** — the per-element charge with no
offsetting array-alloc win. Only bites pathological tiny-scalar-heavy containers
(atypical for Matter). If a real profile flags it: charge the budget per
*container* rather than per *scalar*, or skip fixed-width scalars. The criterion
benches live in `crates/matter-codec/benches/decode.rs` and
`crates/matter-interaction/benches/report_parse.rs` (added during the audit;
partially closes the "Benchmark suite" cross-cutting item below).

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

**Status:** done in M6.2.1 (for `matter-commissioning`); open for
`matter-cert` itself.

The CSA test PAA roots are now bundled at
`crates/matter-commissioning/src/attestation/csa_test_roots/`
and consumed by `verify_chain` happy-path tests (M6.2.2) plus the
attestation-chain shape exercise the original item asked for. The
`matter-cert` side of this item — bundling them for use inside
`matter-cert` itself, e.g. for CSR parsing or future X.509 paths —
stays open until a `matter-cert` consumer needs them.

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

## matter-commissioning

### Certification Declaration verification — HARD GATE BEFORE M6.6

**Status:** **closed in M6.4.3** — see commits `10e3a81e` through
`d227db5b` and `docs/superpowers/specs/2026-05-28-m6.4-commissioning-state-machine-design.md`.

[original body retained for historical context]

**Status (historical):** open. **Blocks M6.6 (first real-device commissioning).**

**Why it matters:** M6.2 ships chain validation + device-signature
verification. It does NOT parse or verify the Certification
Declaration (CD) embedded inside `attestation_elements`. Without CD
verification, a genuine DAC for product X can be re-purposed by an
attacker to fraudulently commission as product Y — the device's
signature over `attestation_elements || attestation_challenge`
proves only that the DAC private key signed *something*, not that
the device's claimed VID/PID match what the CSA actually certified.

Matter Core Spec §6.3.1 mandates CD verification on the
commissioner side: the CD is a CMS/PKCS#7 SignedData blob signed
by the CSA's CD signing root, carrying VID/PID/category and
product identity. The commissioner must parse the CD, verify its
signature against the CSA CD signing root, and cross-check the
declared VID/PID against the DAC's subject VID/PID.

**Concrete deliverable:**

1. New module `matter-commissioning::attestation::cd` exposing
   `verify_certification_declaration(elements_tlv: &[u8],
   expected_vid: VendorId, expected_pid: ProductId, trust_root:
   &CdSigningRoot) -> Result<(), AttestationError>`.
2. CMS/PKCS#7 SignedData parser (likely via `cms` crate or
   hand-rolled if the surface is small enough — defer the
   library-choice decision to the M6.4.x design).
3. Bundled CSA CD signing root analogous to the bundled PAA test
   roots in `crates/matter-commissioning/src/attestation/csa_test_roots/`.
4. New `AttestationError` variants for CD-specific failures (at
   minimum: `CertificationDeclarationInvalid`, possibly more).
5. Update `verify_attestation_response` flow in the M6.4 state
   machine to call `verify_certification_declaration` between
   chain validation and proceeding to NOC issuance.

**Until this lands, `matter-commissioning` MUST NOT be used to
commission a real device.** The M6.4 state machine should refuse
to advance past the AttestationRequest stage if `cd` module is
absent.

### ICAC issuance — deferred to M6.3.x or M8

**Status:** open. Not a hard gate, but required for v1.0 production use.

`FabricRecord` (M6.3.1) carries `icac_signer: Option<Arc<dyn Signer>>` +
`icac_cert: Option<MatterCertificate>` slots, but only
`FabricRecord::new_root_only` is implemented. Real production
controllers (Apple Home, Google Home, SmartThings) all use ICAC for
operational-key rotation without breaking the durable fabric root.
Add `FabricRecord::new_with_icac(...)` plus the ICAC-issuance code
path before v1.0 ships.

The schema is already non-breaking — adding the issuer code does
not change `FabricRecord`'s shape, only adds a new constructor +
new code path inside `issue_noc` that emits the NOC under an ICAC
issuer DN instead of the RCAC.

### NetworkCommissioning endpoint discovery — deferred to post-v1.0

**Status:** open. M6.5.2 hardcodes endpoint 0 for the
`NetworkCommissioning` cluster reads and invokes. Multi-network-endpoint
devices (rare for Wi-Fi-only plugs, possible for hybrid Wi-Fi+Ethernet
devices) will not commission correctly until full Descriptor-cluster
endpoint discovery lands. Additive: a future PR plumbs `endpoint` through
`CommissionerConfig` (or reads `Descriptor::PartsList` during
`ReadCommissioningInfo`).

### Non-concurrent-connection device handling — deferred to post-v1.0

**Status:** open. Devices that tear down PASE at `ConnectNetwork` time
(rare for modern Wi-Fi plugs) cause the M6.5 state machine to wait
forever for a `ConnectNetworkResponse` it will never receive. The M6.6
driver surfaces this as a transport-layer timeout. A future PR adds a
`Commissioner::on_pase_torn(...)` callback (or an
`Expectation::ConnectNetworkPaseTorn` variant) so the state machine can
treat torn PASE as success and advance to `EvictPreviousCaseSessions`.

### `WiFiCredentialsRef` for `no_std` consumers — deferred to post-v1.0

**Status:** open. `WiFiCredentials` uses `Vec<u8>` which requires `alloc`.
Embedded callers will eventually want a borrowing variant
`WiFiCredentialsRef<'a> { ssid: &'a [u8], credentials: &'a [u8] }`.
Additive — does not change the existing owned variant.

### NetworkCommissioning `MaxNetworks` cap enforcement — deferred to post-v1.0

**Status:** open. M6.5 does not enforce
`BasicCommissioningInfo::max_cumulative_failsafe_seconds`. The device
will reject `ArmFailSafe` with a non-OK status if the requested expiry
exceeds the cap. A future PR caps `failsafe_expiry_seconds` against
`max_cumulative_failsafe_seconds` so we never round-trip a
guaranteed-fail value.

### `test-helpers` feature naming + scope review — pre-v1.0

**Status:** open. M6.5.2 ships a `test-helpers` Cargo feature exposing
two shortcut constructors (`new_at_read_network_commissioning_info`,
`new_at_evict_previous_case_sessions`) needed because the M6.4.6 real-
fixture e2e driver is deferred. Before v1.0, consider:
- Renaming to `_unstable-test-helpers` (underscore prefix) to signal
  "not for production use" in dependency-graph audits.
- Reviewing whether to consolidate the two shortcuts into a single
  `position_at_stage_for_test(self, stage: Stage)` API.
- Removing entirely once M6.4.6's real-fixture e2e driver lands.

### `WiFiNetworkFeature` naming — open question

**Status:** open from M6.5.1 PR review. The `WiFiNetworkFeature` bitflags
struct carries WIFI, THREAD, and ETHERNET bits — the Wi-Fi-centric type
name is technically misleading. The spec uses this name; rename to
`NetworkInterfaceFeature` (or similar) is a cheap pre-v1.0 search-and-
replace if desired.

### matter.js NOC byte-parity capture — operator wiring

**Status:** scaffolding only. `xtask capture-noc` ships in M6.3.3
with a placeholder `index.js`. The `@matter/protocol` NOC-mint API
surface shifts between minor versions; wiring the capture against
the current symbol path is an operator-touch step.

The byte-parity test (`crates/matter-commissioning/tests/noc_byte_parity.rs`)
skips with `eprintln!` when fixtures are absent or carry empty
`expected_*_b64` fields, so CI stays green during the operator wiring.

### BLE commissioning transport

**Status:** open (deferred post-v1.0 per CLAUDE.md).

Factory-fresh Wi-Fi devices are BLE-only until they receive network credentials.
Until BLE lands, `commission_ip` requires an IP-reachable device (already on the
network, in an open commissioning window). The Tuya-plug-over-BLE validation is
blocked on this.

### Live DCL client

**Status:** open (optional per CLAUDE.md M6).

Production PAA roots currently come from a cached connectedhomeip snapshot passed via
`--paa-dir`. A snapshot can miss recently-approved vendor PAAs. A live Distributed
Compliance Ledger client (or scheduled snapshot refresh) removes that staleness window.

### `xtask capture-commissioning` — matter.js operator wiring

**Status:** open. Operator-touch wiring deferred from M6.4.6.

The M6.4.6 byte-parity gate's infrastructure (xtask dispatcher,
placeholder JS script, integration test that skips on empty fixture)
is in place — see commits introducing
`xtask/scripts/capture-commissioning/` and
`crates/matter-commissioning/tests/commissioning_byte_parity.rs`.
Activation requires:

1. Pin a known-good `@matter/protocol` version in
   `xtask/scripts/capture-commissioning/package.json`. The
   `@matter/protocol` commissioner / controller API has shifted
   meaningfully between minor versions, so pinning matters.
2. Run `npm install` in `xtask/scripts/capture-commissioning/`.
3. Replace the placeholder `index.js` with real capture logic:
   - Construct a `CommissionerNode` (or the current top-level
     commissioner symbol) pointing at matter.js's `device-simulator`
     (or a real device's IP + setup code).
   - Monkey-patch the device-network layer to capture every outgoing
     Invoke + ReadAttribute payload + the corresponding device
     responses.
   - Write `test-vectors/commissioning/e2e/happy-path.json` matching
     the schema documented in
     `crates/matter-commissioning/tests/commissioning_byte_parity.rs`
     (top-level keys: `fabric_id`, `commissioner_node_id`,
     `assigned_node_id`, `ipk_epoch_key_b64`,
     `pase_attestation_challenge_b64`, `stages[]`).
4. Run `cargo xtask capture-commissioning` to drive the script.
5. Run `cargo test -p matter-commissioning --test commissioning_byte_parity`
   — the test stops skipping and asserts byte-parity on emitted
   RNG-free Invoke + ReadAttribute payloads.

**RNG-bearing payloads** (SendAttestationRequest nonce,
SendOpCertSigningRequest nonce, SendNoc IPK) are walked but NOT
byte-asserted in the current test — see the `rng_bearing` allow-list
inside the test. Promoting them to strict byte-parity requires
injecting a deterministic RNG into `Commissioner` that mirrors
matter.js's capture-time RNG state. A follow-up commit can add a
`test-support` feature on `matter-commissioning` exposing a
`SeededTestRng: NocRng` and a `Commissioner::new_with_rng(...)` or
similar constructor accepting an `Arc<dyn NocRng>` derived from
fixture-side metadata (the capture script writes the seed bytes
alongside the trace).

**Negative byte-parity** (the M6.4.6 T57 tampered-DAC verdict-parity
check) is also deferred until the happy-path wiring lands — the
operator extends `index.js` with a `--tamper=dac` mode that flips one
byte in the DAC DER + writes a sibling `tampered-dac.json` fixture
that the byte-parity test consumes as a `verdict_only_reject` case.

Once both happy-path + tampered-DAC fixtures land, drop the
`#[ignore]`-d placeholders in
`tests/commissioning_e2e.rs`,
`tests/state_machine_noc.rs`, and
`tests/state_machine_attestation.rs` — they'll exercise the captured
fixtures via the public API.

## matter-clusters

### Codegen scalar narrowing: `fabric-id` fields emitted as `u32` instead of `u64`

**Status:** open. Documented residual from M9-D2 final review 2026-06-25.

The generated `FabricDescriptorStruct.fabric_id` (and any other
`fabric-id`-typed field produced by the codegen scalar table) is emitted as
`u32`. `FabricId` is `uint64` in the Matter spec — a device sending a
high-bit FabricId would fail decode. This is a codegen scalar-table narrowing
bug affecting all `fabric-id` fields.

Not yet impactful because `matter-controller` hand-parses `fabric_id` as `u64`
via the raw `Value` path and does not consume the generated `FabricDescriptorStruct`
for operational reads. No real-device regression observed.

**Concrete deliverable:** fix the codegen scalar table to map `fabric-id` →
`u64`, regenerate affected structs, update any decode/encode call sites. Revisit
when the generated `OperationalCredentials` codec is wired into a typed read
path.

## matter-controller

### OTA provider server availability hardening (multi-session, 2026-07-10 final review)

**Status:** open. Follow-ups from the multi-session provider's whole-branch
review (all fail-closed today; the live flow is green):

1. **Unauthenticated frames burn pooled credentials** — `accept_case` pops a
   credential before validating the first frame, so stray LAN datagrams to the
   advertised port can exhaust the 4-entry pool and end the serve. Fix:
   discard undecodable / non-Sigma1 frames while awaiting Sigma1 instead of
   erroring the accept.
2. **Stale secured frame errors a live serve** — the session loop propagates
   `decode_inbound` failures; a late retransmit from a prior (discarded)
   session should be skipped (`continue`) instead.
3. **Peer identity not pinned** — `serve_ota` never compares the accepted
   session's peer node id against `target_node_id`; any fabric member can
   consume the serve. Compare the accept's peer identity (pre-existing in the
   single-session server; slightly wider now).
4. `complete_full`'s closing ack-absorb `recv` could swallow a fast post-reboot
   Sigma1 (costs one retry credential); a cross-session BDX `ReceiveInit`
   without a fresh `QueryImage` aborts the serve (chip re-queries after
   reconnect — acceptable, documented here).
