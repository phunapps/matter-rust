# Changelog

Each crate in this workspace maintains its own version. This file records
workspace-wide changes; per-crate changes will live in each crate's own
`CHANGELOG.md` once that crate has its first release.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
