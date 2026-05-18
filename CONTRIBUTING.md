# Contributing to matter-rust

Thank you for considering a contribution. This is a security-sensitive protocol
library — please read this whole document before opening a PR that touches code.

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
Be kind, be patient, assume good faith.

## Ground rules

1. **Correctness over speed.** Matter is a security protocol. A subtly wrong
   implementation can leak credentials or commission a rogue device into a
   user's home. We move slowly on purpose.
2. **No cryptographic primitives.** We use [`ring`](https://docs.rs/ring) (and
   eventually possibly `aws-lc-rs`) for AES, ECDSA, ECDH, SHA, HKDF, HMAC. We
   implement protocols on top of those primitives, not the math underneath. If
   you find yourself reaching for `num-bigint` to do EC math by hand, stop.
3. **No `unwrap()` / `expect()` in library code.** Return `Result`. Test code may
   use them, but add a one-line comment explaining the invariant.
4. **Test vectors before code.** For any protocol behaviour, capture the
   expected input/output from `matter.js` (or the Matter spec) first, save it
   under `test-vectors/`, then write Rust that produces matching output.
5. **Every public item gets rustdoc.** This is a library others will depend on.
6. **Semver from day one.** Breaking changes bump major. Additive changes bump
   minor. Bug fixes bump patch. No exceptions.

## What kinds of contributions are welcome

- Implementing planned milestone work (check the milestone tracking issue).
- Capturing matter.js test vectors for upcoming protocol pieces.
- Documentation: rustdoc gaps, `docs/spec-references.md`, ADRs.
- Bug fixes with a regression test.
- Reproducing and reporting interop issues with real Matter devices.

Please **open an issue first** before starting work on:

- A new milestone or feature outside the published roadmap.
- An API change to an already-published crate.
- Any change to `matter-crypto` (PASE / CASE). Crypto changes go through extra
  review and need to be sequenced with releases.

## Workflow

1. Open or comment on an issue describing the work.
2. Fork, branch, write code, write tests.
3. Run the full local check:
   ```
   cargo xtask check
   ```
   This runs every gate CI runs: `rustfmt --check`, `clippy -D warnings`,
   `cargo test`, `cargo doc -D warnings`, `cargo audit`, and
   `cargo deny check`. See **Local toolchain** below for one-time
   installation of `cargo-audit` and `cargo-deny` — without them,
   `cargo xtask check` skips those two gates (CI will still run them,
   so the gap can surface only after push).
4. Open a PR. Fill in the template completely.
5. Address review feedback. Expect at least one full reviewer pass on anything
   that touches protocol code.

## Local toolchain

CI runs six gates on every PR. To run them locally with one command, install
these once:

```
cargo install cargo-audit --locked
cargo install cargo-deny --locked
```

`rustfmt` and `clippy` ship with `rustup` and don't need separate installation.
`cargo doc` is in the base toolchain too.

Once installed, `cargo xtask check` runs the full battery. It's the same set of
checks CI runs, so a green local result means CI will be green too.

If you can't or don't want to install `cargo-audit` and `cargo-deny`, push
anyway — CI will catch the cases those gates would have. The local command
will just skip them with an install hint rather than fail.

## Crypto-touching changes

Any PR that modifies code inside `crates/matter-crypto/` — or anything that
affects the bytes on the wire during PASE or CASE — is subject to extra rules:

- Label the PR `crypto`.
- The PR is **not eligible for release** until external cryptographic review has
  signed off on the diff. The maintainer will arrange this.
- Include the matter.js test vectors that prove the change is correct.
- Do not change cryptographic primitives or their parameters without a written
  justification in the PR description.

## Commit style

- One logical change per commit where practical.
- Subject line ≤ 72 chars, imperative mood, lowercase: `add tlv tag decoder`.
- Body explains *why* the change is correct, not *what* it does (the diff
  already shows the what).

## Releasing

Releases are cut by the maintainer at the end of each milestone. The flow is:

1. Update `CHANGELOG.md` for the crate(s) being released.
2. Bump versions in the relevant `crates/*/Cargo.toml`.
3. Tag `<crate>-vX.Y.Z`.
4. `cargo publish` from a clean checkout of the tag.

Contributors are not expected to publish — open a PR with the changelog and
version bump, and the maintainer will tag and publish.

## Questions

Open a [Discussion](https://github.com/phunapps/matter-rust/discussions) for
design questions, an [Issue](https://github.com/phunapps/matter-rust/issues)
for bugs and tracked work.
