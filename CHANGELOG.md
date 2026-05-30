# Changelog

All notable changes to crates in the `matter-rust` workspace.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## matter-commissioning

### [Unreleased] — M6.1 setup payload codec, M6.2.x attestation, M6.3.x NOC issuance, M6.4 commissioning state machine (M6.4.1 → M6.4.6, complete), M6.5 network commissioning (M6.5.1 → M6.5.3, complete)

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

#### Crypto-review attention for M6.3

External-review request (non-blocking per standing user stance) targets:
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

### [0.1.0-pre] — 2026-05-22 (not yet published)

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

## matter-crypto

### [0.1.0-pre] — 2026-05-20 (not yet published)

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
- External cryptographic review (in progress; tracked in TODO-1.0.md).

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
