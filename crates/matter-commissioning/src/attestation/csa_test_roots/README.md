# CSA test PAA roots

These DER-encoded Product Attestation Authority (PAA) certificates are
vendored from
[project-chip/connectedhomeip](https://github.com/project-chip/connectedhomeip)
at commit `43aa98c2d30ee547c6b587b9de7bbb794f175ece` (tag `v1.4.0.0`),
from the directory `credentials/test/attestation/`.

> Note: an earlier draft of this task referenced
> `credentials/development/attestation/`. At `v1.4.0.0` the
> `Chip-Test-*` fixtures live under `credentials/test/attestation/`
> instead (byte-identical copies of the two PAAs also exist under
> `credentials/development/paa-root-certs/`). Filenames are unchanged.

| File | Subject VID | Purpose |
|---|---|---|
| `Chip-Test-PAA-FFF1-Cert.der` | `0xFFF1` | VID-scoped PAA used by the test attestation chain (DAC/PAI for VID `0xFFF1`, PID `0x8000`). |
| `Chip-Test-PAA-NoVID-Cert.der` | (none) | Non-VID-scoped PAA. Exercises the `Paa::subject_vid() -> Option<VendorId>` path. |

## Why these files live inside the crate

`PaaTrustStore::with_csa_test_roots()` embeds them at compile time via
`include_bytes!`. cargo only packages files under the crate root in the
published tarball, so keeping these inside the crate guarantees
`with_csa_test_roots()` keeps working if/when `matter-commissioning` is
ever published to crates.io. (Publishing is currently deferred.)

## License

Apache License 2.0 — same as both upstream connectedhomeip and this
crate. No additional NOTICE attribution is required by the upstream
LICENSE file.

## Re-vendoring

To update against a newer upstream tag:

1. Bump the tag in this README and re-run the steps in
   `docs/superpowers/plans/2026-05-23-matter-commissioning-attestation-phase-1.md` Task 1.
2. Re-run `cargo test -p matter-commissioning attestation` to confirm
   the new DER still parses through `Paa::from_der`.
3. If parsing fails, the upstream file format may have changed
   meaningfully — escalate.
