# Changelog

All notable changes to crates in the `matter-rust` workspace.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## matter-crypto

### [0.1.0-pre] — 2026-05-19 (not yet published)

#### Added

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

#### Not yet shipped

- CASE / SIGMA-I (M4 territory).
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

[Unreleased]: https://github.com/phunapps/matter-rust/commits/main
