# matter-clusters

Typed Matter cluster definitions: per-cluster attribute/command/struct codecs,
feature flags, enums (with `Unknown(n)` forward-compat) and bitmaps. The modules
under `gen/` are generated from a pinned `@matter/model` dump by the `xtask`
codegen tool.

Part of [`matter-rust`](https://github.com/phunapps/matter-rust). Milestone 7.

## What this crate does

- Provides encode/decode functions for the attributes, commands, and structs of
  19 Matter clusters (mandatory **and** optional attributes), as Matter TLV.
- Models cluster enums with an `Unknown(n)` variant (forward-compatible decode),
  feature maps as `bitflags`, and nullable fields as `Nullable<T>` (distinct
  from `Option<T>`).
- Generates all of the above from the spec model, gated against drift in CI.

## What this crate does not do

- It is **not** a full cluster set — only the 19 clusters below today. More
  arrive in later M9-A2 batches.
- It does **not** provide generic or wildcard attribute access, or
  manufacturer-specific typed codecs. Reading arbitrary attributes a device
  publishes is the Interaction Model layer / high-level controller (see *Reading
  attributes beyond these clusters*).
- It performs no IO and no session/transport work — it only encodes/decodes
  bytes.

## Status

Pre-release (`0.0.0`). The 10 M7 clusters are generated and **byte-parity
tested against matter.js 0.16.11** (`test-vectors/clusters/`): BasicInformation,
Descriptor, Identify, OnOff, LevelControl, ColorControl, OccupancySensing,
TemperatureMeasurement, RelativeHumidityMeasurement, and DoorLock (Aliro
features excluded). The M9-A2.1 pilot batch adds 5 read-only clusters —
IlluminanceMeasurement, PressureMeasurement, FlowMeasurement, BooleanState, and
Switch — decode-smoke tested (they reuse datatype shapes already byte-parity
proven by the M7 set). The M9-A2.2 energy batch adds 4 more read-only clusters —
PowerSource, ElectricalPowerMeasurement, ElectricalEnergyMeasurement, and
AirQuality — decode-smoke tested, with a byte-parity vector for the new nested
`MeasurementAccuracyStruct` (a struct holding a list-of-struct with optional
fields). The M9-A2.3 actuator batch adds 5 read/write clusters — Thermostat,
FanControl, ThermostatUserInterfaceConfiguration, PumpConfigurationAndControl,
and WindowCovering — roundtrip (`decode(encode(x)) == x`) and decode-smoke
tested, with a byte-parity vector for the list-typed `AtomicRequest` command.
For any attribute not covered by these typed codecs — optional,
manufacturer-specific, or a cluster not in this list — the generic `Value` path
in `matter-controller` remains the universal answer. Hand-written support lives
in `types` (`Nullable<T>`), `error` (`ClusterError`), and `datatypes`
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

Typed codecs cover these clusters' mandatory and optional attributes. To read
attributes of other clusters, or manufacturer-specific attributes, use the
generic Interaction Model path: `matter_interaction::parse_report_data` yields
`(AttributePath, matter_codec::Value)` for any attribute without a typed codec.
A high-level generic + wildcard read API (and more typed clusters) arrive in
later milestones.

## Correctness posture

- **Byte-parity** against matter.js 0.16.11 TLV combinators
  (`test-vectors/clusters/`): every generated codec round-trips to the captured
  oracle.
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
