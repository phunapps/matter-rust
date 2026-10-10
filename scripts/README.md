# Repo-wide scripts

One-shot utility scripts. NOT run from CI.

## gen-negative-fixtures.py

Generates the 8 synthetic negative-path attestation chain fixtures
consumed by `crates/matter-commissioning/tests/attestation_negative.rs`.
Run once when the spec's negative matrix changes; commit the output
under `test-vectors/certs/attestation/negative/`.

**Requires:** Python 3.10+, `cryptography>=41`.

**Run:**

    python3 -m venv .venv
    . .venv/bin/activate
    pip install 'cryptography>=41'
    python3 scripts/gen-negative-fixtures.py
    deactivate

Output is timestamped against an anchor `AT_UNIX = 1_800_000_000`
(2027-01-15T08:00:00Z). The integration test pins the same anchor
via `MatterTime::from_unix_secs(1_800_000_000)` so the expired /
not-yet-valid fixtures evaluate deterministically.

If `AT_UNIX` is changed, also update
`crates/matter-commissioning/tests/attestation_negative.rs`'s
constant in the same commit.

## chip-xml-conformance.py

Checks the codegen input `xtask/model/clusters.json` against connectedhomeip's
Matter 1.4.2 spec XML for decoder strictness (M9-A3 spec §5.2): a field the
model calls mandatory but 1.4.2 lets a device omit (P), a non-nullable field
1.4.2 allows to be null (N), and an integer or enum type narrower than
1.4.2's (W). Exits 1 on any such finding not listed in
`chip-xml-conformance.allow`; 2 on a usage or input error.

**Requires:** Python 3 (standard library only) and a connectedhomeip checkout.
Not part of `just gate` (CI has no chip checkout): each cluster batch runs it
and quotes the output in its review.

**Run:**

    python3 scripts/chip-xml-conformance.py ~/code/connectedhomeip
    python3 scripts/chip-xml-conformance.py ~/code/connectedhomeip --cluster AccessControl

Resolve a P or N finding by relaxing the field in the dump script (recorded in
`clusters.json` `meta.relaxed`), a W finding by widening the type. Add an
allow-list line only when chip's own generated type is equally strict.
