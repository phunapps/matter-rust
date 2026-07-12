# Runbook: re-pinning the capture-pase / capture-case RNG patches

**Goal:** when `@matter/protocol` or `@noble/curves` is version-bumped, get
`cargo xtask capture-pase` and `cargo xtask capture-case` producing valid
fixtures again in under 30 minutes (TODO-1.0 "matter.js capture-pase /
capture-case RNG patching").

Both scripts make matter.js produce **deterministic** handshakes so the Rust
byte-parity tests can assert exact bytes. They do it by different mechanisms,
and each mechanism has exactly one seam that can break on a version bump.

## capture-pase — the `randomBytes` queue

File: `xtask/scripts/capture-pase/index.js`.

Mechanism: a `NodeJsStyleCrypto` subclass whose `randomBytes(length)` serves
values from a fixed queue (`fixedRandomBytes`, around line 141). Everything
random in a PASE handshake — the SPAKE2+ `w0`/rejection-sampled scalars via
`Spake2p.create → randomBigInt(32, curve.p)`, plus `initiatorRandom` /
`responderRandom` — flows through that single method, so controlling it
controls the whole exchange.

Re-pinning checklist when the matter.js version moves:

1. `npm install` in the script dir with the new pin in `package.json`.
2. Confirm `NodeJsStyleCrypto` is still exported from `@matter/general` and
   that SPAKE2+ scalar sampling still routes through `crypto.randomBytes`
   (grep the new `node_modules/@matter/crypto*`/`general` dist for
   `randomBigInt` — it must call `randomBytes`, not an internal CSPRNG).
   If sampling moved to a new method, override THAT method on the subclass
   instead; the queue logic is reusable as-is.
3. The queue's expected consumption order is documented at the top of the
   script (header comment, "We call randomBytes explicitly for"). If a new
   matter.js version consumes an extra draw, the fixtures shift — compare
   the first divergent field in `pase_byte_parity.rs` output to identify
   which draw was inserted, and pad the queue accordingly.

## capture-case — fixed ephemeral scalars + RFC 6979 signing

File: `xtask/scripts/capture-case/index.js`.

Mechanism (two seams):

1. **Ephemeral keypairs are built from fixed scalar bytes** via Node's
   `ECDH.setPrivateKey`, NOT via matter.js's `createKeyPair()` (which calls
   `ECDH.generateKeys()` internally and never touches `randomBytes` — this
   is why the capture-pase queue approach does not work for CASE).
2. **Signatures use `@noble/curves`' `p256`** (import
   `@noble/curves/nist.js`), because RFC 6979 deterministic ECDSA is what
   ring produces on the Rust side; Node's `crypto.createSign` uses random
   nonces and would break byte-parity on every Sigma2/Sigma3 signature.

The script also imports matter.js-internal modules **by absolute file
path** (e.g. `node_modules/@matter/protocol/dist/esm/session/case/
CaseMessages.js`) because they are not in the package `exports` map. These
paths are the fragile part.

Re-pinning checklist:

1. `npm install` with the new pins.
2. Fix the absolute-path imports first: `ls node_modules/@matter/protocol/
   dist/esm/session/case/` and update file names if the module moved
   (grep the dist tree for `TlvCaseSigma1` if it vanished).
3. Confirm `@noble/curves`' export layout: `p256` moved from
   `@noble/curves/p256` to `@noble/curves/nist.js` at v2 — check the
   package's `exports` map on any bump and update the import specifier.
4. Regenerate (`cargo xtask capture-case`) and run
   `cargo nextest run -p matter-crypto -E 'test(/byte_parity/)'`. The first
   mismatching field names the seam that shifted (dest_id → RCAC key
   handling; signature → noble import; TLV layout → CaseMessages schema).

## General notes

- Version pins live in each script dir's `package.json` +
  `package-lock.json` (committed). Never rely on a floating range.
- The newer captures (`capture-commissioning`, 0.17.x) deliberately avoid
  RNG patching altogether by shipping capture-time nonces in the fixture
  and scripting the RUST side's RNG instead — prefer that pattern for any
  new capture, and consider migrating these two to it if a bump ever costs
  more than the 30-minute budget.
