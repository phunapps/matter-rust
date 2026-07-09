# M9-F4 runbook — OTA end-to-end vs chip's ota-requestor-app

**What this validates:** the complete OTA Provider flow on a real network — we
announce ourselves to a commissioned requestor, it resolves us via operational
mDNS, opens CASE, invokes `QueryImage`, downloads a real `.ota` image over BDX,
and applies it. The CI floor is the in-process
`serve_ota_once_full_flow_over_loopback` / `..._resumed_session_over_loopback`
tests (full flows with byte-exact image reassembly, no external apps).

> **This flow is now AUTOMATED: `just integration-ota`** builds/launches the
> requestor, commissions it, announces, and serves end-to-end (~16s once the
> app is built) — see `crates/integration-tests/tests/ota_flow.rs`. This
> runbook remains for manual/operator runs. Live-validated 2026-07-09;
> findings baked into the automation:
>
> - The requestor **resumes** the CASE session established by the announce
>   connect; the provider seeds the persisted resumption record and answers
>   with `Sigma2_Resume` (unknown ids fall back to a full handshake).
> - Launch the requestor with **`--autoApplyImage`** or it idles after the
>   download and never sends `ApplyUpdateRequest`.
> - `NotifyUpdateApplied` arrives only after the app REBOOTS into the new
>   image (it execs the downloaded file), over a fresh CASE session.
>   `serve_ota` now serves sessions until that Notify arrives (multi-session
>   provider, 2026-07-10): the harness's `.ota` payload is a trampoline
>   script that boots a VERSION-2 requestor build
>   (`out/<host>-ota-requestor-v2`, built automatically by the harness via
>   `gn_build_example.sh` with `chip_device_config_device_software_version=2`)
>   — chip's `GetSoftwareVersion` is compile-time, and the rebooted process
>   only notifies when its running version equals the persisted target
>   (`ConfirmCurrentImage`). Manual runs serving a REAL image to a REAL
>   device get the same semantics: `serve_ota` returns once the device
>   reboots into the new firmware and notifies; bound it with a timeout
>   sized to the device's reboot time.

## Prerequisites

- connectedhomeip checkout at `/Users/hemanshubhojak/code/connectedhomeip`
  (confirmed), pigweed-bootstrapped.
- A persisted controller store with a fabric (e.g. from `controller_quickstart`).

## Steps

1. **Build chip's ota-requestor-app** (the DUT / requestor):

   ```sh
   cd /Users/hemanshubhojak/code/connectedhomeip
   ./scripts/examples/gn_build_example.sh examples/ota-requestor-app/linux \
       out/ota-requestor-app
   # (on macOS use the darwin target, mirroring the H6 app builds)
   ```

2. **Generate an unsigned test image** with chip's image tool. The `-vn` version
   must match the `--version` you serve, and exceed the requestor's current
   `SoftwareVersion`:

   ```sh
   cd /Users/hemanshubhojak/code/connectedhomeip
   # payload can be any file; the requestor only checks the OTAImageHeader.
   head -c 200000 /dev/urandom > /tmp/payload.bin
   python3 src/app/ota_image_tool.py create \
       -v 0xFFF1 -p 0x8000 -vn 2 -vs "2.0" -da sha256 \
       /tmp/payload.bin /tmp/test.ota
   ```

3. **Commission the requestor onto our fabric** with our controller (dev
   attestation, same path as H1–H6):

   ```sh
   cargo run -p matter-controller --example controller_quickstart -- \
       --store /tmp/matter-ota.bin --commission \
       --paa-dir  /Users/hemanshubhojak/code/connectedhomeip/credentials/development/paa-root-certs \
       --cd-dir   /Users/hemanshubhojak/code/connectedhomeip/credentials/development/cd-certs
   # note the assigned requestor node id (e.g. 5).
   ```

4. **Announce + serve the image**:

   ```sh
   cargo run -p matter-controller --example serve_ota -- \
       --store /tmp/matter-ota.bin --node 5 --version 2 --image /tmp/test.ota
   ```

   It prints `[ota] loaded … announcing … + serving …`, triggers
   `AnnounceOTAProvider` on the requestor, advertises our operational service,
   accepts the requestor's CASE session, answers `QueryImage` with
   `QueryImageResponse` (UpdateAvailable, `ImageURI = bdx://<our-node>/fw.ota`),
   serves the `.ota` over BDX, and answers `ApplyUpdateRequest` (Proceed) +
   `NotifyUpdateApplied`.

5. **Confirm.** The requestor logs the QueryImage → BDX block download →
   ApplyUpdateRequest → NotifyUpdateApplied sequence and reports the image
   applied; our example prints `[ota] done — requestor downloaded + applied the
   image`.

## Caveats

- **Interface / address** — same as F3: `serve_ota` advertises the socket's
  `local_addr`, which for a wildcard bind may not be routable to a foreign
  requestor. Run provider and requestor on the same host/interface (and mind the
  `MATTER_MULTICAST_IF` consideration from M9-E). A specific bind interface is an
  F-hardening follow-up.
- **Reliability** — all provider replies are unreliable (piggyback ack); correct
  on localhost (no loss). A lossy real network would need reliable BDX + MRP
  retransmit-driving (noted hardening follow-up).
- **Unsigned image** — we serve the bytes verbatim; the requestor parses the
  `OTAImageHeader` but does not enforce the (optional) signature. The offered
  `SoftwareVersion` must match the image header's version.
