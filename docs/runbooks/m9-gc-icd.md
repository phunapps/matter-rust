# M9-G-c runbook — ICD (Intermittently Connected Devices) vs lit-icd-app

**What this validates:** the full ICD client flow on a real network — the
controller registers as a check-in client with a Long-Idle-Time (LIT) device,
the device sends its periodic unsolicited **Check-In**, and our listener resolves
+ receives it, decrypts it with the registered key, verifies the counter, and
reports it. This makes an otherwise-unreachable LIT device manageable.

> The automated CI floor is the in-process **fake-ICD** test
> (`recv_checkin_once` in `crates/matter-controller/src/icd_listener.rs`) plus the
> Check-In **byte-parity** vs chip's test vectors
> (`matter_crypto::checkin`). The live `lit-icd-app` run is operator-gated (like
> every prior hardware/live validation).

## Prerequisites

- connectedhomeip checkout at `/Users/hemanshubhojak/code/connectedhomeip`,
  pigweed-bootstrapped.
- A persisted controller store with a fabric.

## Steps

1. **Build chip's lit-icd-app** (a Long-Idle-Time ICD device):

   ```sh
   cd /Users/hemanshubhojak/code/connectedhomeip
   ./scripts/examples/gn_build_example.sh examples/lit-icd-app/linux out/lit-icd-app
   # (macOS: use the darwin target, mirroring the H6 app builds)
   ```

2. **Commission the lit-icd-app** onto our fabric with dev attestation (same path
   as H1–H6):

   ```sh
   cargo run -p matter-controller --example controller_quickstart -- \
       --store /tmp/matter-icd.bin --commission \
       --paa-dir /Users/hemanshubhojak/code/connectedhomeip/credentials/development/paa-root-certs \
       --cd-dir  /Users/hemanshubhojak/code/connectedhomeip/credentials/development/cd-certs
   # note the assigned ICD node id (e.g. 5).
   ```

3. **Register + listen** for a Check-In:

   ```sh
   cargo run -p matter-controller --example icd_register_listen -- \
       --store /tmp/matter-icd.bin --node 5 --port 5580
   ```

   It invokes `RegisterClient` on the ICD (generating + persisting a 16-byte key),
   prints the returned start counter, advertises our operational service, and
   blocks until the device's periodic Check-In arrives.

4. **Confirm.** When the ICD next enters its check-in cycle (LIT devices check in
   on `IdleModeDuration`), the example prints
   `[icd] Check-In received from node 5 (counter N, …)` and then issues a
   `StayActiveRequest`. That proves register → advertise → receive → decrypt →
   verify → act on real silicon.

## Caveats

- **Interface / address** — same as F3/F4: the listener advertises the socket's
  `local_addr`; a wildcard bind may not be routable to the device. Run the
  controller and the ICD on the same host/interface (and mind
  `MATTER_MULTICAST_IF`). A specific bind interface is a G-hardening follow-up.
- **Counter persistence** — `listen_for_checkin_once` verifies `counter >
  start_counter` (the registration floor) but does not yet persist the bumped
  counter as the new floor across calls; multi-check-in replay-window hardening
  is a follow-up. Within a single call there is no replay window.
- **Key refresh** — the `RefreshKeySender` flow (re-keying as the counter nears
  rollover) is deferred.
