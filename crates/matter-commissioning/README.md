# matter-commissioning

Matter commissioning: setup payloads, the ten-stage state machine, device
attestation, NOC issuance, and network commissioning.

Part of [`matter-rust`](https://github.com/phunapps/matter-rust). Milestone 6.

> Status: **pre-release (`0.0.0`)**.
>
> Phase **M6.1 is available**: the setup-payload codec (QR + manual
> pairing code). Remaining phases (M6.2 attestation, M6.3 NOC issuance,
> M6.4 state machine, M6.5 network commissioning, M6.6 wire-up) are
> in flight.

## Example: parse a QR code

```rust
use matter_commissioning::setup::parse_qr;

let payload = parse_qr("MT:Y.K90AFN00KA0648G00")?;
assert_eq!(payload.vendor_id, Some(0xFFF1));
assert_eq!(payload.passcode.as_u32(), 20_202_021);
```

(Replace the QR string with the actual captured value from
`test-vectors/commissioning/setup/qr-spec-example.json`.)

## Example: parse a manual pairing code

```rust
use matter_commissioning::setup::parse_manual_code;

let payload = parse_manual_code("11693312331")?;
assert_eq!(payload.discriminator.short(), 0x5);
```

## Byte parity

Every fixture in `test-vectors/commissioning/setup/` is captured from
matter.js by `cargo xtask capture-setup`. The integration test in
`tests/setup_byte_parity.rs` asserts that `encode_qr` / `encode_manual_code`
produce byte-identical output and that `parse_qr` / `parse_manual_code`
recover the same `SetupPayload`.
