# M9-F3 runbook — operational mDNS advertising + CASE-responder provider server

**What this validates:** the F3 provider server end to end on a real network — we
advertise our operational `_matter._tcp` service, a **foreign requestor** resolves
us, opens a CASE session, invokes a command, and gets our response. This is the
operator-gated counterpart to the automated in-process loopback test
(`provider_server_accepts_case_and_dispatches_invoke_over_loopback` in
`crates/matter-controller/src/actor.rs`), which is the CI floor.

> mDNS discovery across processes/hosts is too timing-dependent for CI, so the
> real-network path lives here as a manual runbook (same pattern as the M9-D/E
> hardware runbooks).

## Prerequisites

- A persisted controller snapshot that already holds a fabric — i.e. one used to
  commission at least one device (e.g. the `/tmp/matter-d-test.bin` store from
  the M9-D run). The provider authenticates as that fabric's **commissioner**
  identity (NOC/derived-IPK/root).
- A second Matter controller to act as the requestor: another `matter-rust`
  controller instance, or connectedhomeip's `chip-tool` (F4 swaps this for the
  real `ota-requestor-app`).

## Steps

1. **Start our provider server** (terminal 1):

   ```sh
   cargo run -p matter-controller --example provider_server -- \
       --store /tmp/matter-d-test.bin --port 5541
   ```

   It prints `[provider] advertising operational service on port 5541; waiting …`
   and blocks on the first inbound CASE session.

2. **From the requestor**, resolve `_matter._tcp.local.` and CASE-connect +
   invoke any command on our node. The provider's operational instance name is
   `<compressed-fabric-id>-<commissioner-node-id>` in uppercase hex (the same form
   `operational_instance_name` produces). With a second `matter-rust` controller
   on the **same fabric**, point its discovery at us and `node(<our-node-id>).invoke(...)`.

3. **Confirm.** The provider logs
   `[provider] dispatching server-side invoke (...) → SUCCESS` and then
   `[provider] done; dispatched 1 invoke(s)`, and exits. The requestor receives a
   SUCCESS `InvokeResponse`. That proves advertise + CASE-accept + server-side IM
   dispatch on a real socket, independent of OTA/BDX.

## Caveat — advertised address / interface selection

`serve_provider_once` advertises the address the socket reports (`local_addr`). A
wildcard bind (`[::]`) reports an unspecified address that a foreign requestor may
not be able to route to. On a multi-homed/macOS host you may need to bind a
specific interface address and/or set the multicast egress interface (the same
`MATTER_MULTICAST_IF` consideration as M9-E group multicast). Promoting this to a
`builder().provider_interface(...)` knob is an F4/hardening follow-up; for this
runbook, run provider and requestor on the same host/interface.

## What F4 adds

F4 replaces the generic SUCCESS handler with the real OTA flow: the handler
answers `QueryImage` with a `QueryImageResponse` (from `matter-ota`), then the
same session switches to `ProtocolId::BDX` and serves the image via
`matter-bdx::BlockSender` — validated live against chip's `ota-requestor-app`
through the H6 multi-DUT harness.
