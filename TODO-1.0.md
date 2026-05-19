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

### External cryptographic protocol review (M3 PASE)

**Status:** owned by the user; pending arrangement.

**Why it matters:** CLAUDE.md mandates external review for any crate
implementing cryptographic protocols. PASE is the first such crate.

**Concrete deliverable:** review completed, feedback applied, sign-off
captured in a comment on `matter-crypto/README.md` or in a new
`docs/` artefact. Required before any `cargo publish matter-crypto`.

### CASE / SIGMA-I (M4)

**Status:** not yet started.

**Why it matters:** PASE only bootstraps commissioning sessions.
Operational Matter communication uses CASE — certificate-authenticated
sessions running on top of the NOC/ICAC/RCAC chain `matter-cert`
validates.

**Concrete deliverable:** M4 design + implementation + matter.js
byte-parity + external review. Modelled on M3's structure.

### matter.js capture-pase RNG patching

**Status:** working, but fragile.

**Why it matters:** `xtask capture-pase` monkey-patches matter.js's
`Crypto.randomBytes` to inject fixed scalars. matter.js version bumps
may break the patch. Hardcoded scenario inputs (PIN, salt, iterations,
scalar bytes) live in the script.

**Concrete deliverable:** before 1.0, either upstream a public RNG
injection point to matter.js OR document the monkey-patch path
clearly enough that it can be re-pinned against new matter.js
versions in <30 minutes.

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

### External cryptographic protocol review

**Status:** owned by the user; runs in parallel with development.

**Why it matters:** CLAUDE.md mandates external review for M3
(PASE/SPAKE2+) and M4 (CASE/SIGMA). The user has stated review runs
in parallel and does not block development. This item is here so
the requirement isn't lost — review must complete (and feedback be
applied) before any cargo publish of a crate touching protocol-level
crypto.
