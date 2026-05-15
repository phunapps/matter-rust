# ADR 0001: Cargo workspace layout

- **Status:** accepted
- **Date:** 2026-05-15
- **Milestone:** 0

## Context

`matter-rust` is a Rust controller-side implementation of the Matter
protocol. The project is sequenced into eight milestones, each producing one
publishable crate. We needed to choose how to lay the workspace out before
any code was written.

## Decision

A single Cargo workspace at the repository root, with each milestone's
deliverable as an independent member crate under `crates/`. Each crate is
independently versioned and independently publishable to crates.io.

```
crates/
  matter-codec/           Milestone 1
  matter-cert/            Milestone 2
  matter-crypto/          Milestones 3, 4
  matter-transport/       Milestone 5
  matter-commissioning/   Milestone 6
  matter-clusters/        Milestone 7
  matter-controller/      Milestone 8
xtask/                    workspace automation (not published)
```

Supporting top-level directories:

```
test-vectors/   binary fixtures captured from matter.js / spec test vectors
examples/       how to use the published crates
docs/           protocol notes, spec references, ADRs
.github/        CI workflows and PR template
```

Shared metadata (edition, MSRV, license, repository, lints) lives in
`[workspace.package]` and `[workspace.lints]` in the root `Cargo.toml`. Each
member crate inherits these via `field.workspace = true`.

## Alternatives considered

### One large crate with feature flags

Pattern: `matter` crate, `[features]` for `codec`, `cert`, `crypto`, `controller`.

Rejected: feature flags would couple the release cadence of all layers, and
crypto changes would force version bumps on TLV consumers. We want the
opposite — small, sharply versioned crates.

### Separate repositories per crate

Pattern: `matter-rust/matter-codec`, `matter-rust/matter-cert`, …

Rejected: cross-crate refactors (which we expect to do often pre-1.0) become
much harder with separate repos. Single workspace, multiple crates, gets us
the publishing independence without the workflow tax.

### Devices and controller in one workspace alongside `rs-matter`

Rejected: `rs-matter` is a separate project with different design choices. We
do not fork it. We may converge later — see CLAUDE.md.

## Consequences

- Contributors run `cargo build` / `cargo test` at the workspace root, not
  per crate.
- Each crate has its own `CHANGELOG.md` once it ships its first release.
- Internal cross-crate dependencies use `path` plus `version` so the same
  manifests work both in-tree and after publishing.
- Codegen for `matter-clusters` and test-vector capture both live in `xtask`.

## Edition and MSRV

- Edition: `2021`.
- MSRV: `1.75`. Picked as a low ceiling that still gives us `let … else`,
  `OnceLock`, and async-fn-in-trait. Revise upwards when a concrete need
  arises; document the bump and the reason in a new ADR.

## References

- CLAUDE.md "Workspace structure" section.
- Cargo book, [Workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html).
