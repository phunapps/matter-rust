# TLV test vectors

Captured fixtures used by `matter-codec` to verify TLV encoding and decoding
byte-for-byte. Two tiers, distinguished by how the bytes are sourced:

- **Tier 1 — pre-declared bytes, cross-checked against matter.js.** Lives in
  `xtask/scripts/capture-tlv/spec-vectors.js`. Each entry declares the
  expected bytes by hand, either transcribed directly from a Matter Core
  Specification §A.2 example or derived from §A.2's encoding rules for a
  case the spec did not enumerate (e.g. wider integer widths or extra edge
  values). The capture driver encodes each input via matter.js and aborts
  the run on any byte disagreement.
- **Tier 2 — recorded from matter.js, no pre-declaration.** Lives in
  `xtask/scripts/capture-tlv/matterjs-vectors.js`. Used for cases the
  spec §A.2 examples don't cover well — primarily non-anonymous tags,
  empty containers, and nested compositions. Whatever bytes matter.js
  produces are taken as canonical and recorded.

## File layout

```
manifest.toml                    # index of every vector
<id>.bin                         # canonical bytes for one vector
```

`<id>` is a zero-padded sequence number plus a slug describing the case.
`manifest.toml` lists every vector in `id` order with metadata
(description, source, file) and an `encode` block describing the tag and
value the bytes represent.

## Regenerating

```
cargo xtask capture-tlv
```

This:

1. Runs `node xtask/scripts/capture-tlv/index.js`.
2. Encodes every Tier-1 case via matter.js and asserts the output matches
   the spec-derived bytes.
3. Encodes every Tier-2 case via matter.js and records the bytes.
4. Rewrites `manifest.toml` and every `<id>.bin`.

Prerequisites:

- Node.js 20 or later (matches the `engines` field in
  `xtask/scripts/capture-tlv/package.json`).
- `npm install` has been run inside `xtask/scripts/capture-tlv/`. The
  committed `package-lock.json` pins matter.js so two contributors
  regenerating produce identical bytes; use `npm ci` instead of `npm
  install` if you want to enforce the lock exactly.

## Adding a vector

- **Tier 1 (preferred whenever you can write the bytes by hand from the
  spec):** add an entry to `spec-vectors.js` with `expectedBytes`
  derived from spec §A.2 or its encoding rules, plus a `source`
  citation (cite the specific example, or write
  `"derived from spec §A.2 encoding rules"` for cases not enumerated
  directly). The driver's cross-check protects against transcription
  typos.
- **Tier 2 (for dimensions where pre-declaring bytes is impractical —
  non-anonymous tags, deep nesting, runtime-determined widths):** add
  an entry to `matterjs-vectors.js` with the input structure and an
  `encode` description. Bytes are recorded automatically.

In both cases, run `cargo xtask capture-tlv` and commit the new `.bin`
plus the updated `manifest.toml`.

## Known gaps

- No standalone `null` vector. matter.js exposes `null` only as
  `TlvNullable(inner)`, which prepends the inner codec's tag rather
  than producing a bare `0x14` element. The M1 codec implementation
  will add a hand-written `null` vector once a Rust encoder exists.
- No `end-of-container` standalone vector. The marker `0x18` only
  appears inside containers; it has no standalone meaning.
- No `2-byte length` UTF-8 / octet string vectors. Trivially achievable
  with strings longer than 255 bytes; deferred to M1.
- No common-profile / implicit-profile / fully-qualified tag vectors.
  matter.js does emit these via lower-level codec primitives; deferred
  to M1.

## What the future Rust harness does with these

`matter-codec` ships an integration test that loads `manifest.toml`,
encodes each `encode` block via `TlvWriter`, asserts byte equality with
the matching `.bin`, then round-trips the `.bin` through `TlvReader`
and asserts structural equality. The harness lives with the codec
crate, not here; see the M1 plan when it lands.
