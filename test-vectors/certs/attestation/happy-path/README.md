# Happy-path attestation chain fixtures

DAC + PAI test certificates vendored from
[project-chip/connectedhomeip](https://github.com/project-chip/connectedhomeip)
at commit `43aa98c2d30ee547c6b587b9de7bbb794f175ece` (tag `v1.4.0.0`),
from `credentials/test/attestation/`.

> Note: an earlier draft of this task referenced
> `credentials/development/attestation/`. At `v1.4.0.0` the
> `Chip-Test-*` fixtures live under `credentials/test/attestation/`
> instead. Filenames are unchanged.

| File | Role | Subject VID | Subject PID |
|---|---|---|---|
| `Chip-Test-DAC-FFF1-8000-0004-Cert.der` | DAC | `0xFFF1` | `0x8000` |
| `Chip-Test-PAI-FFF1-8000-Cert.der` | PAI | `0xFFF1` | `0x8000` |

Both chain to `crates/matter-commissioning/src/attestation/csa_test_roots/Chip-Test-PAA-FFF1-Cert.der`.

## Scope (M6.2.1)

Used by `tests/attestation_parse.rs` to verify `Dac::from_der` /
`Pai::from_der` extract VID, PID, and public key correctly.

Chain validation against the PAA root happens in M6.2.2.
`AttestationResponse` signature verification happens in M6.2.3.

## License

Apache License 2.0.
