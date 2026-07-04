# Hardware validation checklist (batch session)

A single place to run **every operator-gated validation** in one sitting when a
device / free hour is available. Each item links to its detailed runbook, says
what it needs, and gives the headline command + pass criterion. Tick the box
when it passes on real hardware.

Most of the library is *already* validated automatically — `just integration`
(+ `just integration-lock` / `just integration-energy`) drives connectedhomeip's
all-clusters-app / lock-app / evse-app as software DUTs on every run, now also
green on CI (`docs/coverage/controller-vs-chip.md`). This checklist is only the
things that harness cannot cover: chip example apps not yet wired into it, and
real-silicon confidence on a commercial device.

> Convention in the older runbooks: many say "to-be-run-for-real, NOT yet run".
> Where the underlying verbs were since validated on hardware in a sweep, this
> checklist marks them **✅ done** with the date so we don't redo them.

---

## Prerequisites for the session

- **connectedhomeip checkout** at `~/code/connectedhomeip` (already present;
  used by the integration harness). Needs pigweed bootstrapped
  (`source scripts/bootstrap.sh`).
- **Physical device:** Tapo P110M (node `0x2` in prior runs), commissionable via
  its app (Matter → Add device → get the manual pairing code).
- **Production attestation roots** (for the Tapo): `--paa-dir` / `--cd-dir` →
  `~/code/connectedhomeip/credentials/production/{paa-root-certs,cd-certs}`.
- **Dev attestation roots** (for chip example apps): `.../credentials/development/{paa-root-certs,cd-certs}`.
- Put example stores under the repo `target/` (not `/tmp`) — the FileStore
  spawn-blocking persist thread hits intermittent ENOENT under the run sandbox.

---

## A. connectedhomeip example apps (software DUTs — no physical device)

These are the two chip apps the automated harness does **not** yet drive. Each
runs as a local macOS/Linux process. **Candidate future work:** add them to
`xtask integration <app>` the way H6 added lock-app/evse-app, which would make
these automatic and retire this section.

- [ ] **OTA Provider end-to-end (M9-F3 + F4)** — matter-rust serves a firmware
      image over BDX to chip's `ota-requestor-app`, which applies it.
  - Build `ota-requestor-app` (darwin/linux target); create an image with
    `src/app/ota_image_tool.py create -v 0xFFF1 -p 0x8000 -vn <ver> …`.
  - Run `cargo run -p matter-controller --example serve_ota -- --store … --node … --version … --image …`
  - **Pass:** requestor downloads the image over BDX, reassembles it byte-exact,
    and applies (ApplyUpdateRequest → NotifyUpdateApplied).
  - Detail: [`m9-f4-ota-end-to-end.md`](m9-f4-ota-end-to-end.md) (+ provider
    server [`m9-f3-provider-server.md`](m9-f3-provider-server.md)). Validated
    in-process only so far.

- [ ] **ICD full client (M9-G-c)** — register with chip's `lit-icd-app` and
      receive + verify a real Check-In.
  - Build `lit-icd-app`; commission it; then
    `cargo run -p matter-controller --example icd_register_listen -- --store … --node … --port 5580`
  - **Pass:** `RegisterClient` succeeds, the device's periodic Check-In (SC
    opcode 0x50) is received + decoded + counter-verified, `StayActiveRequest`
    returns a promised duration.
  - Detail: [`m9-gc-icd.md`](m9-gc-icd.md). Validated with a fake-ICD in-process
    only so far.

## B. Physical device — real-silicon confidence (Tapo P110M)

- [ ] **Full 2-controller multi-admin loop (M9-D completeness demo)** — the one
      multi-admin scenario not yet run end-to-end (individual verbs are done —
      see below). Controller A opens a window → a *second* matter-controller
      instance commissions the device onto a 2nd fabric → both control OnOff →
      `list_fabrics` shows 2 → remove the **2nd** fabric (never our own).
  - `cargo run -p matter-controller --example fabric_management` for the A side;
    a second store/instance for B.
  - **Pass:** device ends on 2 fabrics then back to 1; both admins actuate it.
  - Detail: [`m9-d2-fabric-management.md`](m9-d2-fabric-management.md).

- [ ] **(Optional) Re-run the onboarding manual-pairing-code fix on silicon** —
      `open_commissioning_window` now only emits spec-valid passcodes (fix
      `60ba0027`). Sanity: open a window with `examples/open_window.rs`, then
      pair a second controller / phone app with the emitted manual code.
  - **Pass:** the manual code is accepted (no "invalid setup payload").

## C. Optional / low-priority

- [ ] **TimeSync `SetUTCTime` on an accepting device (M9-G-a)** — all-clusters-app
      rejects it (host-synced clock, spec-legal); a device that accepts it would
      exercise the accept path + read-back. Low value — the command path is
      already validated live.
- [ ] **Typed-decode of real Tapo energy bytes** — the M9-D sweep captured real
      ElectricalPower/EnergyMeasurement bytes but only decoded them to generic
      `Value`. Feed them through `matter_clusters::gen::*::decode_*`. (evse-app
      in `just integration-energy` already covers typed-decode-vs-real-bytes, so
      this is confidence-only.)

---

## Already validated on hardware (do NOT redo)

- **M6.6 first commission** — Tapo P110M, 2026-06-06; matter.js cross-verified 2026-06-07.
- **M7.5 OnOff control** — hardware-validated.
- **M9-B events + timed** — B1 read_events, B2 subscribe-with-events, B3 timed
  interaction all run on the Tapo in the 2026-06-26 extended sweep.
- **M9-D verbs** — D1 open-window, D2 list/remove/update-fabric (WouldRemoveSelf
  guard fired), D3 read/write ACL (+ chunked-write + lockout guard) all validated
  on the Tapo 2026-06-26 (join-and-exercise). Only the *full 2-controller loop*
  above remains.
- **M9-E group multicast** — proven end-to-end on connectedhomeip lighting-app
  (physical actuation, 4/4) 2026-06-28, cross-verified with chip-tool. Headline
  finding: group provisioning must also add a group **ACL** entry.
- **M9-G-d async re-arch** — commission + connect decoupling validated live
  against all-clusters-app via `just integration` 2026-07-02 (caught + fixed the
  IPv4-mapped-IPv6 route-key bug).
