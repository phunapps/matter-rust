# matter-codec

Matter TLV (Tag-Length-Value) encoder and decoder.

Part of the [`matter-rust`](https://github.com/phunapps/matter-rust) workspace.

[![Crates.io](https://img.shields.io/crates/v/matter-codec.svg)](https://crates.io/crates/matter-codec)
[![Docs.rs](https://docs.rs/matter-codec/badge.svg)](https://docs.rs/matter-codec)

## What this crate does

Encodes and decodes Matter TLV per the Matter Core Specification §A.2:

- All 11 element types: `bool`, signed/unsigned integers (1/2/4/8 byte),
  IEEE 754 floats (4/8 byte), UTF-8 strings, octet strings, `null`,
  structures, arrays, lists.
- All 5 tag forms: anonymous, context-specific, common profile, implicit
  profile, fully qualified. Writer picks the minimum-width sub-form (2 vs
  4 byte tag numbers; 6 vs 8 byte fully-qualified).
- All 4 length-field widths for strings and octet strings (1/2/4/8 byte
  little-endian). Writer picks the minimum.
- Recursive `read_value` / `write_value` for containers, with a 32-level
  nesting limit enforced by the reader.

## What this crate does not do

- Cluster definitions. See `matter-clusters` (future).
- Certificates. See `matter-cert` (future).
- Anything network. See `matter-transport` (future).
- Cryptographic primitives. See `ring` / `aws-lc-rs`.

## Usage

```rust
use matter_codec::{Tag, TlvReader, TlvWriter, Value};

let mut bytes = Vec::new();
let mut writer = TlvWriter::new(&mut bytes);
writer.put_uint(Tag::Context(0), 42)?;
assert_eq!(bytes, [0x24, 0x00, 0x2A]);

let mut reader = TlvReader::new(&bytes);
let (tag, value) = reader.read_value()?;
assert_eq!(tag, Tag::Context(0));
assert_eq!(value, Value::Uint(42));
# Ok::<(), matter_codec::Error>(())
```

For streaming use cases that need to avoid the allocating tree builder,
call `TlvReader::next()` directly. It returns `Element::Scalar`,
`Element::ContainerStart`, or `Element::ContainerEnd` and tracks the
nesting depth internally.

## Correctness posture

`matter-codec` is verified by:

- **Spec test vectors** transcribed from Matter Core Spec §A.2 (in the
  `test-vectors/tlv/` directory of the workspace), cross-checked against
  matter.js's TLV codec at capture time.
- **An integration test** that loads every captured vector and asserts
  byte-for-byte encode equality and structural decode round-trip.
- **`proptest` round-trip property** over arbitrary `(Tag, Value)` trees
  bounded to depth 4 — `decode(encode(v)) == v`.
- **A `cargo-fuzz` target** (`fuzz_decode`) that runs `TlvReader::read_value`
  on adversarial bytes. The weekly CI workflow runs it for 5 minutes every
  Monday. The decoder never panics; malformed input surfaces as `Error`.

If `matter-codec`'s output differs from matter.js for the same input, we
treat it as a bug in `matter-codec` and investigate.

## Cryptographic posture

`matter-codec` performs no cryptography. It is pure data encoding.

## MSRV

Rust 1.88. The workspace MSRV was raised from 1.75 to 1.88 on
2026-05-24 to land patched `time >= 0.3.47` (RUSTSEC-2026-0009)
pulled in transitively by `x509-parser` / `asn1-rs` in the
`matter-commissioning` crate. See the workspace `CHANGELOG.md`.

## License

Apache 2.0. See `LICENSE` at the workspace root.
