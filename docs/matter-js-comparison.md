# matter.js comparison notes

`matter.js` is the production-grade controller library in the Matter ecosystem
today. It is our primary cross-reference for byte-level correctness. This
document records places where `matter-rust`'s shape differs from matter.js, so
that contributors moving between the two projects understand why.

## High-level shape

| Aspect               | matter.js                                      | matter-rust                                                 |
| -------------------- | ---------------------------------------------- | ----------------------------------------------------------- |
| Language             | TypeScript                                     | Rust                                                        |
| Runtime              | Node.js, browsers, React Native                | Tokio (later milestones); plain Rust at lower layers        |
| Crypto primitives    | `node:crypto`, browser SubtleCrypto, fallbacks | `ring`                                                      |
| Distribution         | Single npm package (`@project-chip/matter.js`) | Many small crates, independently versioned                  |
| Cluster definitions  | Generated at runtime from spec descriptors     | Generated at build time by `xtask` codegen                  |
| Async style          | Promises, async iterators                      | `async fn`, `Stream`, `tokio::sync` channels                |

## Why workspace of small crates instead of one mega-crate

`matter.js` ships as one importable package. For Rust, we prefer many small
crates so that:

- An embedded user who only needs TLV decoding can depend on `matter-codec` and
  pay nothing for the rest.
- Cryptographic code lives in its own crate (`matter-crypto`) with a clear
  release-review boundary.
- Each crate's API surface is small enough to actually keep stable across
  versions.

The trade-off is more `Cargo.toml`s to maintain. We accept it.

## Why code generation at build time instead of runtime

`matter.js` builds cluster definitions at runtime from descriptor objects. That
suits a dynamic language well. In Rust, build-time code generation gives us:

- Typed `read` / `write` / `invoke` calls with compile-time field checking.
- Zero runtime cost for descriptor traversal.
- IDE autocomplete on real types, not stringly-typed cluster IDs.

The cost is a `build.rs` / `xtask` step. We accept it.

## Where we expect to disagree at the bytes

In principle, never. If `matter-rust` produces different bytes than
`matter.js` for the same input, **`matter-rust` is wrong by default** and we
investigate. Add the divergence as a test vector, then fix the Rust side.

## Where we will diverge on ergonomics

- Error types are typed enums (`thiserror`), not stringly typed.
- Streams of attribute reports are `impl Stream` rather than `EventEmitter`.
- Subscriptions are explicit handles with `Drop` cancelling the subscription,
  rather than callback registration.

These are language-idiomatic differences. They do not affect interop.

## Where we decode more leniently than matter.js

- **Fabric-sensitive fields of fabric-scoped structs are `Option`**
  (`matter-clusters` 0.6.0, M9-A3). Our reads are unfiltered
  (`IsFabricFiltered=false`), so for a fabric-scoped list such as AccessControl
  `Acl` a device returns every fabric's entries and leaves the fabric-sensitive
  fields out of the entries that belong to another fabric (connectedhomeip
  `zzz_generated/app-common/clusters/AccessControl/Structs.ipp`: written only
  when `includeSensitive`). matter.js `@matter/types` 0.16.11 declares those
  fields mandatory (`TlvAccessControlEntry.privilege: TlvField(1, …)`,
  `clusters/access-control.js`). We decode them as `Option`, where `None` means
  "withheld: another fabric's entry".

  Writing is guarded by one rule: a withheld field is never written. The
  reason is a chip hazard: chip's ACL write path reads a missing `Subjects` as
  null, which grants the entry to every CASE node on the fabric. Only two of
  these structs have generated encoders, `AccessControlExtensionStruct` and
  `MonitoringRegistrationStruct`; their `encode`/`write_fields` return
  `ClusterError::MissingField` for a `None` in a `mandatoryOnWrite` field, and a
  complete entry encodes byte-identically to before. `AccessControlEntryStruct`
  and `AccessRestrictionEntryStruct` are decode-only. ACL writes go through
  matter-controller's hand-written `acl.rs`, whose `read_acl` drops any entry
  with a withheld field rather than reading it as a wildcard.

- **ModeBase `ChangeToModeResponse.StatusText` is `Option`** (`matter-clusters`
  0.6.0, M9-A3 B2). Its 1.4 conformance is `[Status == Success], M`, and
  matter.js `@matter/types` 0.16.11 declares it mandatory
  (`statusText: TlvField(1, TlvString…)`, `clusters/mode-base.js`). chip's
  ModeBase server leaves it out of the replies it builds itself, including
  `UnsupportedMode`, where the conformance requires it, and `Success` for
  `ChangeToMode(CurrentMode)`
  (`src/app/clusters/mode-base-server/ModeBaseCluster.cpp`
  `HandleChangeToMode`). Any other reply comes from the application's
  delegate, which may set it: rvc-app does on the four changes it refuses
  (`examples/rvc-app/rvc-common/src/rvc-device.cpp`). A mandatory field would
  fail to decode chip's `UnsupportedMode` reply, so our codegen treats only an
  unconditional `M` field as mandatory and decodes it as `Option<String>`.

## Where our generated surface follows chip, not matter.js

- **A feature a derived cluster disallows is not generated, nor is anything
  only it enables** (M9-A3 B2). ModeBase's OnOff dependency (DEPONOFF) is
  disallowed in every ModeBase-derived cluster, so they have no `Feature` flag
  for it. The authority is chip's 1.4.2 cluster XML
  (`data_model/1.4.2/clusters/Mode_*.xml`), which marks DEPONOFF
  `<disallowConform/>` in all ten. matter.js 0.16.11 keeps `Feature.OnOff`
  (`clusters/dishwasher-mode.d.ts`, and likewise for the other nine). chip's
  controller codegen (`src/controller/data_model/controller-clusters.matter`)
  agrees with the XML for seven: OvenMode, LaundryWasherMode,
  RefrigeratorAndTemperatureControlledCabinetMode, DishwasherMode and
  MicrowaveOvenMode have no feature bitmap, and RvcRunMode and RvcCleanMode
  carry only `kDirectModeChange`. For EnergyEvseMode, WaterHeaterMode and
  DeviceEnergyManagementMode it still declares `kOnOff = 0x1`; we follow the
  XML there (the 1.4.2 XML outranks chip's codegen in our ambiguity order).
  Nothing a device reports is lost: FeatureMap reads as a raw `u32`
  (`clusters::globals::decode_u32`), so a set bit 0 is still visible.
  RefrigeratorAlarm disallows AlarmBase's RESET, so it has no `Latch`,
  `Reset` or `Feature::RESET`; matter.js keeps them as its `ResetComponent`
  (`clusters/refrigerator-alarm.d.ts`), chip's controller codegen omits them.

- **ModeSelect `StandardNamespace` is `Nullable<u16>`** (M9-A3 B2). The
  matter.js model (`@matter/model` 0.17.1, which the dump reads) types it as the global `namespace`
  enum, which is enum8. chip's 1.4.2 XML
  (`data_model/1.4.2/clusters/ModeSelect.xml`), its zap XML
  (`mode-select-cluster.xml`) and its controller codegen
  (`readonly attribute nullable enum16 standardNamespace`) all declare enum16,
  so our dump widens the type (`TYPE_WIDENINGS`, recorded in `meta.relaxed` as
  class W). On the wire, matter.js's codec is wider still
  (`TlvNullable(TlvEnum())`, where `TlvEnum` is `TlvUInt32`), so a value above
  `0xFFFF` decodes there and is an error here.
- **The global location descriptor is `LocationDescriptorStruct`**
  (`matter-clusters` 0.6.0, M9-A3 B3). The specification's lowercase
  `locationdesc` struct, used by ServiceArea's `AreaInfoStruct.LocationInfo`,
  takes chip's name (`global-structs.xml`, `controller-clusters.matter`);
  matter.js 0.16.11 calls it `TlvLocationdesc` (`globals`). The wire format is
  the same. Each cluster that uses it gets its own copy of the struct, as with
  `MeasurementAccuracyStruct`.

## CASE handshake performance (measured 2026-07-12)

The load-bearing perf comparison for the "embedded-grade performance"
positioning. Same machine (Apple M-series), both sides measuring the full
SIGMA-I exchange (Sigma1 → Sigma2 → Sigma3 → session keys):

| implementation | measurement basis | full CASE handshake |
|---|---|---|
| matter-rust (`just bench-one matter-crypto`, `case/full_handshake`) | state machines only, in-memory, criterion median | **0.64 ms** |
| matter.js 0.17.1 (`cargo xtask capture-commissioning` trace timestamps, Sigma1 tx → SigmaFinished StatusReport tx) | in-process loopback UDP wall-clock, 5-run range | **4.2–5.7 ms (median ≈ 5.1 ms)** |

The bases differ: the matter.js number includes loopback UDP + MRP +
event-loop scheduling that the criterion number excludes, so the ~8×
ratio *overstates* matter.js's cost by some transport overhead — the
honest claim is "several times faster", not a precise multiplier. Both
sides pay the same ECDH/ECDSA/HKDF work; the gap is the surrounding
runtime. Per-step Rust costs (sigma1/2/3 handle: 227 / 336 / 101 µs)
live in the criterion output.
