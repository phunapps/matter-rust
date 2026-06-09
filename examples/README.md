# examples

Example programs that demonstrate how to use the `matter-rust` crates against a
real Matter device. Both live in `crates/matter-commissioning/examples/` (they
need the commissioning + transport stack) and build behind the `driver` feature.

## `commission_ip` (M6.6)

Commission an IP-reachable Matter device end to end (PASE → attestation → NOC →
CASE → CommissioningComplete).

```bash
cargo run --example commission_ip --features driver -- --help
```

Walkthrough: `docs/runbooks/m6.6-first-commission.md`.

## `control_onoff` (M7.5)

Commission a device, then open an operational session and exercise the
`matter-clusters` codecs: read/toggle `OnOff` and write/read
`BasicInformation.NodeLabel`.

```bash
cargo run --example control_onoff --features driver -- --help
```

Walkthrough: `docs/runbooks/m7.5-control-onoff.md`.
