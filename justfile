# matter-rust task runner — run `just` (no args) to list recipes.
#
# This file is the SINGLE SOURCE OF TRUTH for the CI gate: every job in
# .github/workflows/ci.yml runs one of these recipes, so the local gate and CI
# cannot drift. Run `just gate` before every push to mirror CI end-to-end.
#
# `-euo pipefail` so a multi-line recipe (embedded, gate deps) aborts on the
# first failing command rather than marching on.
set shell := ["bash", "-euo", "pipefail", "-c"]

# List available recipes.
default:
    @just --list

# ---------------------------------------------------------------- format ---

# Apply rustfmt across the workspace.
fmt:
    cargo fmt --all

# Check formatting without writing (CI: fmt job).
fmt-check:
    cargo fmt --all -- --check

# ------------------------------------------------------------------ lint ---

# Clippy across all targets/features with warnings denied (CI: clippy job).
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# ----------------------------------------------------------------- tests ---

# ~7x faster than `cargo test` here; does NOT run doctests (nextest #16),
# so the gate pairs this with `doctest`.

# Unit + integration tests via nextest (CI: test job).
test:
    cargo nextest run --workspace --all-features --no-fail-fast

# Run only tests matching a filter, e.g. `just test-one byte_parity`.
test-one PATTERN:
    cargo nextest run --workspace --all-features -E 'test(/{{PATTERN}}/)'

# Doctests only — the piece nextest cannot run on stable Rust (CI: test job).
doctest:
    cargo test --workspace --all-features --doc

# Local convenience: every test that exists (nextest + doctests).
test-all: test doctest

# --------------------------------------------------------------- codegen ---

# Regenerate clusters.json + the generated cluster modules.
codegen:
    cargo xtask codegen

# Fail if the committed generated code is stale (CI: test job).
codegen-check:
    cargo xtask codegen --check

# ------------------------------------------------------------------ docs ---

# Build rustdoc with warnings denied (CI: docs job).
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# --------------------------------------------- embedded (sans-io core) ---

# matter-transport no-default-features build/test/doc matrix (CI: embedded job).
embedded:
    cargo build -p matter-transport --no-default-features
    cargo nextest run -p matter-transport --no-default-features --no-fail-fast
    cargo test -p matter-transport --no-default-features --doc
    RUSTDOCFLAGS="-D warnings" cargo doc -p matter-transport --no-default-features --no-deps
    cargo build -p matter-transport --no-default-features --features tokio
    cargo build -p matter-transport --no-default-features --features mdns-sd

# -------------------------------------------------------- build / msrv ---

# Build the whole workspace (CI: msrv job runs this under the 1.88 toolchain).
build:
    cargo build --workspace --all-features

# ---------------------------------------------------------- supply chain ---

# Dependency license / ban / advisory checks (CI: deny job).
deny:
    cargo deny check

# Vulnerability scan against the RustSec advisory DB (CI: audit job).
audit:
    cargo audit

# ------------------------------------------------------------- aggregate ---

# Stops at the first failing recipe.

# Full pre-push gate, mirroring CI end-to-end (run before every push).
gate: fmt-check lint test doctest codegen-check docs embedded deny audit
    @echo "gate: all green ✓"

# ---------------------------------------------------------- integration ---

# Build + launch all-clusters-app and run the integration sweep (local/nightly).
integration:
    cargo run -p xtask -- integration

# Build + launch lock-app and run the DoorLock integration tests.
integration-lock:
    cargo run -p xtask -- integration lock

# Build + launch evse-app and run the Electrical* integration tests.
integration-energy:
    cargo run -p xtask -- integration evse
