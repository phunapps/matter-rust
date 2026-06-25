# M9-D1 Runbook — Open a commissioning window (first leg of the multi-admin loop)

Operator-gated validation for M9-D1: confirm `Node::open_commissioning_window`
works against a real device and that the returned onboarding payload lets a
**second** commissioner bring the same device onto its own fabric.

**This runbook covers the first leg only** — opening the window and handing
off to a second commissioner. The second leg (D2: reading operational credentials,
D3: removal / multi-admin cleanup) follows in separate runbooks.

**Status: TO BE RUN FOR REAL.** (User chose the full hardware loop.)

---

## Device

Tapo P110M (the device validated in M6.6 / M7.5 / M8 / M9-B1). The device must
already be commissioned onto our fabric (Fabric A). **Do not factory-reset** — the
whole point of this runbook is that the device remains on Fabric A while we open a
window for Fabric B.

If you need to commission fresh first, run `m8.3-commission.md` and come back here.
Keep the resulting snapshot path (`controller-state.bin`) — you will need it.

Trust material (production PAA/CD roots):

- PAA roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/paa-root-certs`
- CD roots: `/Users/hemanshubhojak/code/connectedhomeip/credentials/production/cd-certs`

---

## Steps

### Step 1 — Read vendor/product ID from Basic Information (optional but recommended)

Reading `VendorID` (attr `0x0001`) and `ProductID` (attr `0x0002`) from Basic
Information (cluster `0x0028`, endpoint 0) lets `open_commissioning_window`
emit a full QR code in addition to the manual pairing code.

```rust
use matter_controller::{ReadPath, Value};

// cluster 0x0028 = BasicInformation
let bi = node.read(&[ReadPath::cluster(0, 0x0028)]).await?;
let mut vid: Option<u16> = None;
let mut pid: Option<u16> = None;
for (path, value) in &bi {
    match (path.attribute, value) {
        (0x0001, Value::Uint(v)) => vid = Some(*v as u16), // VendorID
        (0x0002, Value::Uint(v)) => pid = Some(*v as u16), // ProductID
        _ => {}
    }
}
println!("VendorID={vid:?}  ProductID={pid:?}");
```

Expected for the Tapo P110M: `VendorID=Some(0x1217)` (TP-Link), `ProductID` varies
by firmware. Record both — you will need them in Step 2.

### Step 2 — Open the enhanced commissioning window

```rust
use matter_controller::{OpenWindowOpts, CommissioningWindow};

let win: CommissioningWindow = node.open_commissioning_window(OpenWindowOpts {
    timeout_s: 180,            // window stays open 3 minutes
    iterations: 1000,          // spec minimum; sufficient for testing
    vendor_id: vid,            // from Step 1
    product_id: pid,           // from Step 1
    ..Default::default()
}).await?;

println!("manual_code: {}", win.manual_code);
if let Some(ref qr) = win.qr_code {
    println!("qr_code:     {qr}");
}
println!("passcode: {}  discriminator: {}  iterations: {}",
    win.passcode, win.discriminator, win.iterations);
```

**Expected:** `open_commissioning_window` returns `Ok(win)` without error.
`win.manual_code` is an 11-digit string (e.g. `349-79-1234567`). `win.qr_code` is
`Some("MT:…")` when vid/pid were supplied.

**If the call returns `CommissioningWindowRejected`:** the device rejected the timed
invoke. Common causes: a window is already open (check `commissioning_window_status`
first), or the device is busy. Close any existing window with
`node.revoke_commissioning().await?` and retry.

### Step 3 — Confirm the window is open

```rust
use matter_controller::CommissioningWindowStatus;

let status = node.commissioning_window_status().await?;
println!("window status: {:?}", status.status);
assert_eq!(status.status, CommissioningWindowStatus::EnhancedWindowOpen,
    "window should be open immediately after Step 2");
```

**Expected:** `EnhancedWindowOpen`.

### Step 4 — Commission the device onto Fabric B using the returned code

Use the `manual_code` (or `qr_code`) from Step 2 as the onboarding payload for a
**second** commissioner. The window is open for 180 s — run this promptly.

**Option A — matter.js** (preferred, if it can act as an IP commissioner against an
already-commissioned device on the same LAN):

```text
# In a matter.js shell / pairing script:
$ node pairing-example.js --manual-code <win.manual_code>
# or, using chip-tool:
$ chip-tool pairing code <node-id-for-fabric-b> <win.manual_code>
```

Wait for "commissioning complete" or equivalent. The second commissioner must reach
the point where it has successfully issued its own NOC on the device.

**Option B — second instance of our own controller** (fallback if matter.js cannot
commission an already-paired device over IP):

```rust
// Build a *second* MatterController with a *different* store file (Fabric B).
let store_b = Arc::new(FileStore::new("controller-state-fabric-b.bin"));
let ctrl_b = MatterController::builder(store_b)
    .attestation_trust(AttestationTrust::from_dirs(paa_dir, cd_dir)?)
    .build()
    .await?;
let _ = ctrl_b.create_fabric(FabricConfig::new(2, 2, 1,
    (MatterTime::from_unix_secs(0), MatterTime::NO_EXPIRY))).await?;
let node_id_b = ctrl_b.commission(&win.manual_code).await?;
println!("Fabric B commissioned node_id={node_id_b}");
```

**Option C — chip-tool** (if Options A and B both fail): use chip-tool's
`pairing code` subcommand with the manual code.

> **TOP RISK:** matter.js's built-in commissioner may not correctly act as a
> second IP commissioner against a device that is already fully commissioned
> onto another fabric. If matter.js or chip-tool fails to complete commissioning
> (it hangs after PASE, cannot discover the device as commissionable, or fails
> during NOC issuance), do **NOT** proceed to D2. Instead:
>
> 1. Record the exact failure mode and which option (A / B / C) you attempted.
> 2. Stop here and raise a decision: does D2 require a working second-fabric
>    commission, or can D2's OperationalCredentials reads be validated on a
>    single-fabric device?
>
> This stop point exists because D2 tests multi-fabric reads; if Fabric B was
> never commissioned, those results are meaningless.

### Step 5 — Confirm the window closed

After the second commissioner completes (or the 180-second timeout elapses),
verify the window is closed on Fabric A:

```rust
let status_after = node.commissioning_window_status().await?;
println!("window status after: {:?}", status_after.status);
assert_eq!(status_after.status, CommissioningWindowStatus::WindowNotOpen,
    "window should be closed after successful commission or timeout");
```

**Expected:** `WindowNotOpen`.

---

## Pass criteria

1. `open_commissioning_window` returns `Ok` with a non-empty `manual_code` and
   (if vid/pid were supplied) a `qr_code` starting with `MT:`.
2. `commissioning_window_status` returns `EnhancedWindowOpen` immediately
   after opening.
3. The second commissioner (Option A, B, or C) reaches commissioning-complete
   without error.
4. `commissioning_window_status` returns `WindowNotOpen` after the window closes.

---

## Notes

- The `open_basic_commissioning_window` path (which re-exposes the original device
  passcode rather than a fresh one) is **not** exercised in this runbook — it is
  tested in unit tests. Use it only when the second commissioner needs the factory
  passcode and you understand the security implications.
- `revoke_commissioning` is available to close the window early if needed:
  `node.revoke_commissioning().await?`. This is useful if you realise the wrong
  window is open or want to clean up before a retry.
- Record: the date, which option (A / B / C) was used for Step 4, whether all five
  criteria passed, and any deviations. Update `docs/tested-devices.md`.
