# TODO before any matter-rust crate hits 1.0

This file tracks gaps deliberately deferred during M0–M2. Each item
must be resolved before claiming production readiness for the affected
crate.

## Deferred from the 2026-06-12 full-codebase audit → fold into M9

The 2026-06-12 audit (29 fixes landed on `main`, commits `3d1bb405`..`34457ecc`)
deferred four items into M9 — ALL FOUR are now resolved. **M9-A (2026-06-14)
resolved the two matter-clusters codegen forward-compat items** —
unknown-nested-container skip (now drained via `TlvReader::skip_container`),
bitmap `from_bits_retain`, and `#[non_exhaustive]` on generated data structs,
all proven by synthetic forward-compat fixtures (commits
`143a2c15`..`6179aa31`). **M9-G-d resolved the actor async re-architecture**
(off-loop connect + spawned commission, `bc309e39`..`143180cd` — no inline
CASE handshake left). **The matter-codec per-element budget perf follow-up
closed 2026-07-12** (byte-bound fast path; see the entry below). Audit
backlog (uncommitted, local): `docs/audit/2026-06-12-backlog.md` +
`2026-06-12-findings.json`.

### matter-codec per-element budget check has a measurable decode cost

**Status:** CLOSED 2026-07-12.

The element-budget DoS defense added in the audit (`b4ab6a65`) charged a
`self.element_budget` read-modify-write once per materialised `Value`,
costing the `struct_500_uint` micro-bench +10% vs pre-audit. Fixed two ways
without weakening the bound (invariant statements live in the
`read_value` / `read_container_body` rustdoc):

1. **Byte-bound fast path:** every materialised element consumes ≥ 1 input
   byte, so a `read_value` whose remaining input is no larger than the
   remaining budget provably cannot exceed it — the decode monomorphises
   with accounting compiled out (`read_container_body::<CHARGE=false>`).
   Real Matter payloads (≲ 1.5 KiB vs the 2^20 default budget) always take
   this path; observably equivalent error behaviour, proven in the rustdoc.
2. **Local budget mirror on the charged path:** the counter lives in a
   register across `next()` calls, synced to the field around recursion.

Measured vs the `pre_budget_opt` criterion baseline (two stable runs):
`struct_500_uint` **-8.4/-8.7%** (recovers the audit's +10%),
`struct_5_uint` -2.5/-2.8%, arrays ±1%, `report_170attr_64B` improved in
every clean run (-4.8% to -15%). Byte-parity vectors, proptest roundtrip and
a 2M-iteration local `fuzz_decode` run all green.

## matter-cert

### Cross-verification against `project-chip/connectedhomeip`

**Status:** CLOSED 2026-07-12. `cargo xtask capture-cert-chip` generates a
3-tier RCAC→ICAC→NOC fixture set with `chip-cert` (chain-validated by the
tool itself) under `test-vectors/certs/connectedhomeip/` — raw CHIP TLV plus
the TBSCertificate slice of chip-cert's X.509 DER (the exact signed bytes).
Every test in `crates/matter-cert/tests/certificates.rs` (parse, TLV
round-trip, X.509 TBS byte-parity, signature chain) now runs against BOTH
the matter.js and connectedhomeip sets; all passed byte-for-byte on the
first capture.

Original finding, for history:

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

### matter.js capture-pase / capture-case RNG patching

**Status:** CLOSED 2026-07-12 — documented to the <30-minute re-pin
standard in `docs/runbooks/capture-rng-repinning.md` (per-seam checklist:
the capture-pase `randomBytes` queue, capture-case's fixed-scalar
`ECDH.setPrivateKey` + `@noble/curves` RFC 6979 signing + absolute-path
internal imports). New captures should prefer the capture-commissioning
pattern (fixture-carried nonces scripting the Rust RNG) over RNG patching.

Original finding, for history:

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

**Status:** stood up 2026-07-12 (`just bench` / `just bench-one <crate>`;
not part of the gate). Criterion suites now cover:

- `matter-codec`: `benches/decode.rs` (arrays, wide struct, small scalar
  struct, 30-deep nesting, the 170-attr wildcard-report shape) +
  `benches/encode.rs` (writer counterparts).
- `matter-interaction`: `benches/report_parse.rs` (IM-layer report parse).
- `matter-crypto`: `benches/case.rs` (per-step SIGMA costs + full
  handshake — the load-bearing matter.js comparison workload).
- `matter-transport`: `benches/frame.rs` (secured frame encode/decode,
  32 B and 960 B payloads).

**Remaining:** a `matter-cert` suite when a parse/validate hot path is
identified. The matter.js CASE comparison landed 2026-07-12: full CASE
0.64 ms (ours, state-machine criterion) vs ≈5.1 ms (matter.js 0.17.1
in-process loopback wall-clock) — methodology + caveats in
`docs/matter-js-comparison.md`.

### no_std posture

**Status:** DECIDED 2026-07-12 — ADR 0002 (`docs/decisions/0002-no-std-posture.md`):
1.0 ships std-only; no_std stays deferred-until-requested per CLAUDE.md.
Codec/bdx are the designated first candidates, matter-transport's sans-io
core is protected by the CI `embedded` job, crypto/cert are gated on a
ring-replacement decision. No `std` cargo features until a real consumer
defines the profile.

Original finding, for history:

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

### `ArmFailSafe` cumulative-cap enforcement — RESOLVED 2026-07-21

**Status:** done. The commissioner now caps `failsafe_expiry_seconds`
against `BasicCommissioningInfo::max_cumulative_failsafe_seconds` when it
reads the device's commissioning info, so it never round-trips an expiry
the device is guaranteed to reject with `BoundsExceeded`. (This item was
mis-headed "MaxNetworks"; the `MaxNetworks`/`BoundsExceeded` network-add
rejection is already surfaced as a typed error.)

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

**Status:** C1 (Wi-Fi) landed pending live validation (2026-07-13/14); C2
(Thread) landed pending live validation (2026-07-17) — **both halves of M9
sub-project C now landed**; each still has its own operator-gated live
hardware pass outstanding.

**C1 — Wi-Fi (M9-C1):** BLE/BTP commissioning is implemented and gate-green:
`matter-ble` (sans-IO BTP engine + `btleplug` central role),
`matter-transport`'s `transport_reliable` (MRP off over BTP),
`matter-commissioning`'s `TransportReliability`/`run_pase_with`/
`commission_ble` driver, and `MatterController::commission_ble` (feature
`ble`) all merged with a byte-parity BTP test-vector suite and an
in-process PASE-over-BTP floor test. What remains is the live hardware pass
— first-ever BLE central-vs-DUT handshake, macOS TCC approval, and an
end-to-end BLE commission with real Wi-Fi credentials — which is
**operator-gated** (needs a Mac + a BLE-capable Pi DUT in the same room)
and walked step-by-step in `docs/runbooks/ble-commissioning.md`'s morning
checklist (Pi DUT bring-up: `docs/runbooks/ble-dut-pi.md`). One BTP test
vector (`test-vectors/btp/handshake.json`'s
`expected_chip_peripheral_response`) is still `provisional: true` (a
hand-encoded fragment-size assumption) until that live capture confirms or
corrects it.

**C2 — Thread (M9-C2):** Thread network provisioning over the same BLE/BTP
path is implemented and gate-green: `NetworkCredentials` enum (replacing
the Wi-Fi-only `wifi_credentials` field) + `ThreadDataset` (Thread TLV
dataset validation + Extended PAN ID extraction) in `matter-commissioning`,
`encode_add_or_update_thread_network` + genericized `NetworkSetup`/
`NetworkEnable`/`FailsafeBeforeNetworkEnable` stages routing by the
supplied credential variant cross-checked against the device's
`FeatureMap`, `ConnectMaxTimeSeconds`-sized failsafe/response deadlines
(90 s default, up from the prior fixed 60 s — see the CHANGELOG behavior
note), and `MatterController::commission_ble`'s signature widened to
`NetworkCredentials` (a breaking pre-release API change; all callers
updated). Byte-parity vectors
(`test-vectors/thread/network_commissioning.json`) and a hermetic
Thread-mock loopback test (`commission_ble_loopback.rs`) both pass. The
rig is validated (a chip-tool `pairing ble-thread` reference commission
already succeeded against the Pi OTBR + ESP32-C6 DUT) but the **live
matter-rust commission itself has not yet been run** — walked step-by-step
in `docs/runbooks/c2-thread-commission.md` (re-derive the current dataset's
Extended PAN ID before every attempt; the OTBR's rotates on network
re-form). That runbook also flags a real-device Wi-Fi recheck against C1
now that the failsafe default changed, and notes there is no packaged
`commission_ble`-with-Thread example binary yet (follow-up after the first
live run).

With C1 + C2 both landed (code-complete, live-validation-pending), M9
sub-project C's BLE-first split decision is resolved: BLE commissioning now
covers both Wi-Fi and Thread network provisioning.

### Live DCL client

**Status:** open (optional per CLAUDE.md M6).

Production PAA roots currently come from a cached connectedhomeip snapshot passed via
`--paa-dir`. A snapshot can miss recently-approved vendor PAAs. A live Distributed
Compliance Ledger client (or scheduled snapshot refresh) removes that staleness window.

### `xtask capture-commissioning` — matter.js operator wiring

**Status:** CLOSED 2026-07-12. `cargo xtask capture-commissioning` is fully
wired: the matter.js half runs a virtual ethernet device (ServerNode) and a
CommissioningController IN-PROCESS over loopback, captures every decrypted
message at the MessageCodec boundary plus the out-of-wire inputs (PASE
attestation challenge via a NodeSession patch, capture timestamp, CD-signer
SPKI), and the Rust half maps the dialogue onto the Commissioner stage
sequence and writes `happy-path.json` + `tampered-dac.json` under
`test-vectors/commissioning/e2e/` (committed).

The parity test byte-asserts ArmFailSafe, both CertificateChainRequests,
AttestationRequest and CSRRequest (the capture-time nonces ride in the
fixture and script the test's `NocRng`, so RNG-bearing payloads are now
STRICT) plus CommissioningComplete. Only AddTrustedRootCertificate and
AddNOC stay unasserted (locally-minted certificates, necessarily
different keys per run). ConfigRegulatory carries no expected payload:
matter.js per spec §5.5 sends SetRegulatoryConfig only to Wi-Fi/Thread
devices, so against the ethernet virtual device the fixture synthesizes a
success response (regulatory byte-parity was validated live by the M6.6
trace-diff run against the P110M).

The tampered-DAC sibling (one bit flipped inside the captured DAC) is
asserted to be REJECTED during attestation verification
(`tampered_dac_is_rejected_during_attestation`), and the three formerly
`#[ignore]`d public-API placeholders (`commissioning_e2e.rs`,
`state_machine_noc.rs`, `state_machine_attestation.rs`) now run for real
against the fixture via the shared `tests/e2e_fixture` harness.

## matter-clusters

### Codegen scalar narrowing: `fabric-id` fields emitted as `u32` instead of `u64`

**Status:** CLOSED 2026-07-12. The scalar table now maps `fabric-id` → `u64`
(Matter Core §2.5.1); the dead `fabric-id64` alias was removed and
`FabricDescriptorStruct` regenerated. Regression-guarded by a `base_type`
unit test in `xtask/src/codegen/rustgen/types.rs`.

Original finding, for history:

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

### OTA provider server — residual hardening notes

**Status:** CLOSED 2026-07-12. The three Importants from the multi-session
final review were fixed first (stray frames no longer burn pooled
credentials `4a26ab31`; stale secured frames are skipped, not fatal
`77815604`; the serve is pinned to its target peer `47357b61`), and both
remaining fail-closed residuals are now fixed with loopback regressions:

1. `complete_full`'s closing ack-absorb hands a fast post-reboot Sigma1
   back into the next accept instead of swallowing it (no retry
   credential burned; same-exchange Sigma1 duplicates still absorbed).
2. A cross-session BDX `ReceiveInit` without a fresh `QueryImage` re-arms
   the `BlockSender` and serves the transfer from the start (tolerant
   choice; BDX still never starts before the serve's first `QueryImage`,
   and the per-session step budget still bounds re-init loops).

## matter-ble

### BLE central hangs on macOS (`CoreBluetooth`) — Linux-only for live commissioning

**Status:** open; found 2026-07-17 during the M9-C live validation, not investigated.

Live BLE commissioning works from Linux/`BlueZ` (both C1/Wi-Fi and C2/Thread
were commissioned from the Pi against the ESP32-C6). The same binary run from
**macOS hangs**: it gets past the scan and far enough to install a NOC — the
device's NVS held a fabric afterwards, which is how we know it reached AddNOC —
then stalls indefinitely. It ran >5 minutes, past every deadline in the
commissioning driver, so this is a **stalled BTP pump, not a rejected
response**: the driver's response deadlines only bound *awaited* responses, and
nothing bounds a pump that never delivers.

**Scanning on macOS is fine** (`ble_scan` finds the DUT reliably, and the
`ScanFilter` fix `a8e07c72` was about the opposite platform). It is GATT/BTP
that hangs.

Candidate causes, none confirmed:

- The known GATT-slot invariant: `gatt_in_flight` latches on ack emission and
  the pump must call `gatt_write_completed` after **every** C1 write including
  standalone acks, or the slot sticks and the session deadlocks (this bit us
  once already, in the C1 floor test). `CoreBluetooth`'s write-completion
  semantics differ from `BlueZ`'s and could re-open it.
- `CoreBluetooth` write/indication behaviour generally: the same rig has
  long-standing "macOS chip-tool BLE is broken (0x407 GATT write fail)"
  behaviour, so the platform is suspect — but that is chip's stack, not
  evidence about ours.

**Why it matters:** macOS is a first-class dev platform for this library, and
`BleCentral::new`'s whole TCC story is written for it. A central that hangs
makes `commission_ble` unusable there.

**How to attack it:** macOS has no `btmon`, and the examples print nothing
between "commissioning…" and the result, so the first step is visibility —
tracing through the pump (which C1 write was issued, which indication arrived,
what the session/window/GATT-slot state is), then decide from a real trace. A
watchdog bounding the whole handshake/pump would turn the hang into a
diagnosable error, but is a symptom fix, not the cause.
