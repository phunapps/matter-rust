# matter-clusters

Typed Matter cluster definitions: per-cluster attribute/command/struct codecs,
feature flags, enums (with `Unknown(n)` forward-compat) and bitmaps. The modules
under `gen/` are generated from a pinned `@matter/model` dump by the `xtask`
codegen tool.

Part of [`matter-rust`](https://github.com/phunapps/matter-rust).

```toml
[dependencies]
matter-clusters = "0.4"
```

## What this crate does

- Provides encode/decode functions for the attributes, commands, and structs of
  47 Matter clusters (mandatory **and** optional attributes), as Matter TLV.
- Models cluster enums with an `Unknown(n)` variant (forward-compatible decode),
  feature maps as `bitflags`, and nullable fields as `Nullable<T>` (distinct
  from `Option<T>`).
- Generates all of the above from the spec model, gated against drift in CI.

## What this crate does not do

- It is **not** the full Matter cluster set — only the 47 listed below. More
  are generated as they are needed.
- It does **not** provide generic or wildcard attribute access, or
  manufacturer-specific typed codecs. Reading arbitrary attributes a device
  publishes is the Interaction Model layer / high-level controller (see *Reading
  attributes beyond these clusters*).
- It is **codecs only**. Encoding a command is not the same as running the
  protocol around it: ACL evaluation, group multicast, commissioning-window
  orchestration, and OTA live in `matter-controller` and its siblings.
- It performs no IO and no session/transport work — it only encodes/decodes
  bytes.

## Status

**0.4.1**, published on crates.io. Stability: a `0.x` crate, so a **minor** bump
may break API — and adding clusters is a routine minor bump.

## Clusters

47 clusters are generated today, covering their **mandatory and optional**
attributes, by area:

- **Core / identity** — BasicInformation, Descriptor, Identify, Groups, Binding,
  FixedLabel, UserLabel, PowerSource, GeneralDiagnostics.
- **Lighting and actuators** — OnOff, LevelControl, ColorControl, DoorLock
  (Aliro features excluded), WindowCovering, Thermostat,
  ThermostatUserInterfaceConfiguration, FanControl,
  PumpConfigurationAndControl.
- **Sensing** — OccupancySensing, TemperatureMeasurement,
  RelativeHumidityMeasurement, IlluminanceMeasurement, PressureMeasurement,
  FlowMeasurement, BooleanState, Switch, AirQuality, and the ten
  ConcentrationMeasurement clusters (CarbonMonoxide 0x040C, CarbonDioxide
  0x040D, NitrogenDioxide 0x0413, Ozone 0x0415, Pm25 0x042A, Formaldehyde
  0x042B, Pm1 0x042C, Pm10 0x042D, TotalVolatileOrganicCompounds 0x042E, Radon
  0x042F).
- **Energy** — ElectricalPowerMeasurement, ElectricalEnergyMeasurement.
- **Administration** — AccessControl, GroupKeyManagement,
  AdministratorCommissioning, OperationalCredentials, IcdManagement,
  TimeSynchronization, OtaSoftwareUpdateRequestor, OtaSoftwareUpdateProvider.

Verification varies by cluster, and the level is deliberate rather than
accidental. Every cluster has decode-smoke coverage. matter.js 0.16.11
byte-parity vectors (`test-vectors/clusters/`) cover the core, lighting, and
sensing sets, plus one vector for each novel wire shape a later cluster
introduced: the nested `MeasurementAccuracyStruct`, the list-typed
`AtomicRequest` command, GeneralDiagnostics' struct-with-byte-fields
`NetworkInterface`, the recursive list-of-struct in
`AccessControl.ReviewFabricRestrictions`, and FLOAT32 attributes. The read/write
actuator clusters additionally carry `decode(encode(x)) == x` roundtrips, and
floats get both a binary32-edge roundtrip (signed zero, subnormals, infinities,
NaN — compared by bits) and a `proptest` roundtrip drawn uniformly from the
whole binary32 bit space. A `single` attribute accepts a FLOAT32 element only,
matching chip's strict `TLVReader::Get(float&)`.

For any attribute not covered by these typed codecs — manufacturer-specific, or
a cluster not in this list — the generic `Value` path in `matter-controller`
remains the universal answer. Hand-written support lives in `types`
(`Nullable<T>`), `error` (`ClusterError`), and `datatypes`
(`SemanticTagStruct`).

## Usage

```rust
use matter_clusters::gen::{basic_information, on_off};

// Command payload — embed in an InvokeRequest.
let _toggle = on_off::encode_toggle();

// Attribute roundtrips: encode a value, decode it back.
let tlv = on_off::encode_on_time(30);
assert_eq!(on_off::decode_on_time(&tlv)?, 30);

let tlv = basic_information::encode_node_label(&"living room".to_string());
assert_eq!(basic_information::decode_node_label(&tlv)?, "living room");
# Ok::<(), matter_clusters::error::ClusterError>(())
```

See `crates/matter-commissioning/examples/control_onoff.rs` for an end-to-end
read / toggle / write against a real device (runbook:
`docs/runbooks/m7.5-control-onoff.md`).

## Generated code

`cargo xtask codegen` writes `src/gen/<cluster>.rs` (+ `globals.rs`, `mod.rs`)
from `xtask/model/clusters.json`. Do not edit the generated files by hand —
change the emitter (`xtask/src/codegen/`) and regenerate. `cargo xtask codegen
--check` gates drift in CI.

## Reading attributes beyond these clusters

Typed codecs cover these clusters' mandatory and optional attributes (a device
may not implement a given optional attribute — it then returns
`UNSUPPORTED_ATTRIBUTE`). To read attributes of other clusters, or
manufacturer-specific attributes, use the generic Interaction Model path:
`matter_interaction::parse_report_data` yields
`(AttributePath, matter_codec::Value)` for any attribute without a typed codec,
and `matter-controller` wraps that in a generic read/write/subscribe API with
wildcard paths.

## Correctness posture

- **Decode-smoke coverage** for every generated cluster.
- **Byte-parity** against matter.js 0.16.11 TLV combinators
  (`test-vectors/clusters/`) for the core, lighting, and sensing sets, plus one
  vector per novel wire shape — see [Clusters](#clusters) for exactly which.
- **`proptest` roundtrips** over attribute values.
- **A `cargo-fuzz` target** over the generated decoders (weekly CI).
- **`cargo xtask codegen --check`** fails CI if the committed `src/gen/` drifts
  from what the emitter + `clusters.json` produce.

## Cryptographic posture

`matter-clusters` performs no cryptography. It is pure data encoding.

## MSRV

Rust 1.88 (workspace MSRV). See the workspace `CHANGELOG.md`.

## License

Apache 2.0. See `LICENSE` at the workspace root.
