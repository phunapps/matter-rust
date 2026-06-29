# M9-H1 — Integration harness runbook (`just integration`)

The integration harness drives connectedhomeip's `all-clusters-app` as a live
device-under-test (DUT) and exercises the `matter-controller` **public API**
against it: commissioning, the core Interaction-Model operations, OnOff
behavior, group provisioning + ACL + group-cast actuation, AccessControl
enforcement, and a multi-admin loop. It is the M9-H pilot that H2–H5 build on.

The whole sweep is software-only (the DUT is a process, not hardware), so it is
fully automatable — unlike the operator-gated real-device runbooks (m6.6, m7.5).

---

## What it does

`just integration` → `cargo run -p xtask -- integration`, which:

1. Finds (or builds) `chip-all-clusters-app` under the connectedhomeip checkout
   (`out/<host-target>-all-clusters/chip-all-clusters-app`). If absent, it builds
   it via `scripts/build/build_examples.py` (this is slow the first time).
2. Clears prior per-run DUT state under `target/integration-dut/`
   (`kvs.json`, `controller-store.bin`, `node-id.txt`, `controller-b-store.bin`,
   …) so the app boots **uncommissioned** and the controllers start fresh.
3. `pkill`s any stale `chip-*-app` (frees UDP 5540), then launches the app with a
   fresh `--KVS target/integration-dut/kvs.json`, logging to
   `target/integration-dut/app.log`.
4. Waits up to 30 s for the app to log `Server Listening`.
5. Resolves the multicast egress interface index (`en0` via `if_nametoindex`,
   or honors a pre-set `MATTER_MULTICAST_IF`).
6. Runs `cargo test -p integration-tests -- --nocapture --test-threads=1` with:
   - `MATTER_INTEGRATION_DUT=MT:-24J042C00KA0648G00` (the app's QR setup code),
   - `CHIP_ROOT=<checkout>`,
   - `MATTER_INTEGRATION_DUT_DIR=<workspace>/target/integration-dut`,
   - `MATTER_MULTICAST_IF=<idx>` (when resolved).
7. **Always** tears the DUT down (kills the child) on the way out, then
   propagates the test exit status.

The fixture (`integration_tests::fixture::connect`) commissions the DUT on the
**first** test that runs in a sweep (writing a node-id sidecar), and reconnects
from the persisted store + sidecar on every later test in the same sweep.

---

## Prerequisites

- A connectedhomeip checkout, default `/Users/hemanshubhojak/code/connectedhomeip`
  (override with `CHIP_ROOT`). It must be **bootstrapped** (pigweed env) so the
  build step can `source scripts/activate.sh` and run `build_examples.py`.
- Development attestation roots present in the checkout (the all-clusters-app
  uses TEST attestation):
  - `credentials/development/paa-root-certs/` (PAA `.der`)
  - `credentials/development/cd-certs/` (CD signing `.der`)
  The fixture points `AttestationTrust::from_dirs` straight at these (it loads
  only `.der`, ignoring the `.pem` siblings).
- A pre-built `chip-all-clusters-app` saves several minutes — build it once with
  `build_examples.py --target <host>-all-clusters build`.

## Run it

```sh
just integration
```

Expected tail:

```
integration: DUT ready — Server Listening detected
integration: MATTER_MULTICAST_IF=11
   …
test result: ok. … (clusters_onoff)
test result: ok. … (enforcement)
test result: ok. … (groups_acl)
test result: ok. … (im_ops, 6 tests)
test result: ok. … (integration, 2 tests)
test result: ok. … (multi_admin)
integration: all tests passed ✓
```

Under a plain `cargo test` (no DUT env) every integration test **skips**
(early-returns and passes), so the normal `just gate` compiles them without a DUT.

---

## Troubleshooting

- **`commissionable device with discriminator 3840 not found via mDNS`** — a
  transient macOS mDNS discovery miss (the app log shows it WAS advertising
  `discriminator=3840/15 cm=1`). Re-run `just integration`; it is not
  deterministic. The fixture commissions on whichever test binary sorts first
  (alphabetical), so a discovery miss surfaces as a failure on that first test.
- **`Server Listening` never detected (30 s timeout)** — the app failed to boot.
  Inspect `target/integration-dut/app.log`. A stale instance may be holding 5540;
  clear it with `pkill -f chip-.*-app` and re-run (the harness also `pkill`s, but
  a wedged process can survive).
- **All group-cast tests skip** (`groups_acl`, `enforcement`) — `MATTER_MULTICAST_IF`
  did not resolve (no `en0`, or the Python `if_nametoindex` lookup failed). Set it
  explicitly: `MATTER_MULTICAST_IF=<idx> just integration`.
- **Group-cast sent but the device does not actuate** — the group is missing its
  AccessControl grant. The device decrypts the group command but DENIES it at
  AccessControl without an `AclEntry(Operate, Group, [gid])`. This is exactly
  what `enforcement.rs` asserts (deny without the grant, allow with it).
- **`multi_admin` re-run fails creating controller B's fabric** — a stale
  `controller-b-store.bin` survived. The harness clears it at the start of each
  run; if you ran the test outside the harness, delete
  `target/integration-dut/controller-b-store.bin` and re-run.
- **Build is slow / fails** — the first build of `all-clusters-app` is minutes.
  Pre-build it in the checkout and confirm pigweed is bootstrapped.

---

## Coverage

See `docs/coverage/controller-vs-chip.md` for the controller-operation × DUT
coverage matrix. H1 covers the vertical slice (IM ops, OnOff, groups/ACL, ACE,
multi-admin); H2–H4 widen to per-cluster behavioral batches across the ~33 typed
clusters; H5 adds the nightly CI job + coverage reporting.
