# matter.js comparison notes

`matter.js` is the production-grade controller library in the Matter ecosystem
today. It is our primary cross-reference for byte-level correctness. This
document records places where `matter-rust`'s shape differs from matter.js, so
that contributors moving between the two projects understand why.

## High-level shape

| Aspect               | matter.js                                      | matter-rust                                                 |
| -------------------- | ---------------------------------------------- | ----------------------------------------------------------- |
| Language             | TypeScript                                     | Rust                                                        |
| Runtime              | Node.js, browsers, React Native                | Tokio (later milestones); plain Rust at lower layers        |
| Crypto primitives    | `node:crypto`, browser SubtleCrypto, fallbacks | `ring`                                                      |
| Distribution         | Single npm package (`@project-chip/matter.js`) | Many small crates, independently versioned                  |
| Cluster definitions  | Generated at runtime from spec descriptors     | Generated at build time by `xtask` codegen                  |
| Async style          | Promises, async iterators                      | `async fn`, `Stream`, `tokio::sync` channels                |

## Why workspace of small crates instead of one mega-crate

`matter.js` ships as one importable package. For Rust, we prefer many small
crates so that:

- An embedded user who only needs TLV decoding can depend on `matter-codec` and
  pay nothing for the rest.
- Cryptographic code lives in its own crate (`matter-crypto`) with a clear
  release-review boundary.
- Each crate's API surface is small enough to actually keep stable across
  versions.

The trade-off is more `Cargo.toml`s to maintain. We accept it.

## Why code generation at build time instead of runtime

`matter.js` builds cluster definitions at runtime from descriptor objects. That
suits a dynamic language well. In Rust, build-time code generation gives us:

- Typed `read` / `write` / `invoke` calls with compile-time field checking.
- Zero runtime cost for descriptor traversal.
- IDE autocomplete on real types, not stringly-typed cluster IDs.

The cost is a `build.rs` / `xtask` step. We accept it.

## Where we expect to disagree at the bytes

In principle, never. If `matter-rust` produces different bytes than
`matter.js` for the same input, **`matter-rust` is wrong by default** and we
investigate. Add the divergence as a test vector, then fix the Rust side.

## Where we will diverge on ergonomics

- Error types are typed enums (`thiserror`), not stringly typed.
- Streams of attribute reports are `impl Stream` rather than `EventEmitter`.
- Subscriptions are explicit handles with `Drop` cancelling the subscription,
  rather than callback registration.

These are language-idiomatic differences. They do not affect interop.

## CASE handshake performance (measured 2026-07-12)

The load-bearing perf comparison for the "embedded-grade performance"
positioning. Same machine (Apple M-series), both sides measuring the full
SIGMA-I exchange (Sigma1 → Sigma2 → Sigma3 → session keys):

| implementation | measurement basis | full CASE handshake |
|---|---|---|
| matter-rust (`just bench-one matter-crypto`, `case/full_handshake`) | state machines only, in-memory, criterion median | **0.64 ms** |
| matter.js 0.17.1 (`cargo xtask capture-commissioning` trace timestamps, Sigma1 tx → SigmaFinished StatusReport tx) | in-process loopback UDP wall-clock, 5-run range | **4.2–5.7 ms (median ≈ 5.1 ms)** |

The bases differ: the matter.js number includes loopback UDP + MRP +
event-loop scheduling that the criterion number excludes, so the ~8×
ratio *overstates* matter.js's cost by some transport overhead — the
honest claim is "several times faster", not a precise multiplier. Both
sides pay the same ECDH/ECDSA/HKDF work; the gap is the surrounding
runtime. Per-step Rust costs (sigma1/2/3 handle: 227 / 336 / 101 µs)
live in the criterion output.
