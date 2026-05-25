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
