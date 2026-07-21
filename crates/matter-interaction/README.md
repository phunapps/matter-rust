# matter-interaction

Matter Interaction Model (IM) message framing: `InvokeRequestMessage`,
`ReadRequestMessage`, `WriteRequestMessage` builders and the corresponding
response parsers. Depends only on `matter-codec`.

Part of [matter-rust](https://github.com/phunapps/matter-rust). Lifted out
of `matter-commissioning` in M7 so cluster control (M7) and the controller
API (M8) can use IM framing without depending on commissioning.

Status: 0.2.0.

Scope (deliberate subset): one command per invoke, concrete (non-wildcard)
paths, no subscriptions, no events, no timed actions, no chunked writes.
The full IM engine is M8 work.

Verification: byte-parity against matter.js fixtures in
`test-vectors/commissioning/im/` (see `tests/im_byte_parity.rs`), captured
via `cargo xtask capture-im`.
