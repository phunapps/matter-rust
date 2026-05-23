# Changelog

All notable changes to crates in the `matter-rust` workspace.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## matter-commissioning

### [Unreleased] — M6.1 setup payload codec, M6.2.1 attestation foundation

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
