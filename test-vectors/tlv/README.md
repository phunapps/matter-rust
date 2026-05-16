# TLV test vectors

Captured fixtures used by `matter-codec` to verify TLV encoding and decoding
byte-for-byte. Two sources:

- **Tier 1 — Matter Core Specification §A.2.** Bytes are pre-declared in
  `xtask/scripts/capture-tlv/spec-vectors.js`. The capture driver
  cross-checks each entry against matter.js at capture time. Any
  disagreement aborts the run.
- **Tier 2 — matter.js.** Inputs are defined in
  `xtask/scripts/capture-tlv/matterjs-vectors.js`. Bytes are whatever
  matter.js produces — recorded, not pre-declared.

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

Prerequisite: `npm install` has been run inside
`xtask/scripts/capture-tlv/`. The committed `package-lock.json` pins
matter.js so two contributors regenerating produce identical bytes.

## Adding a vector

- **Tier 1 (preferred for anything covered in spec §A.2):** add an entry
  to `spec-vectors.js` with `expectedBytes` derived from the spec, plus
  a `source` citation. The driver's cross-check protects against
  transcription typos.
- **Tier 2 (for dimensions spec §A.2 does not cover — non-anonymous
  tags, deep nesting, etc.):** add an entry to `matterjs-vectors.js`
  with the input structure and an `encode` description. Bytes are
  recorded automatically.

In both cases, run `cargo xtask capture-tlv` and commit the new `.bin`
plus the updated `manifest.toml`.

## What the future Rust harness does with these

`matter-codec` ships an integration test that loads `manifest.toml`,
encodes each `encode` block via `TlvWriter`, asserts byte equality with
the matching `.bin`, then round-trips the `.bin` through `TlvReader`
and asserts structural equality. The harness lives with the codec
crate, not here; see the M1 plan when it lands.
