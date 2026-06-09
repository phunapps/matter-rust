# matter-clusters

Typed Matter cluster definitions: per-cluster attribute/command/struct codecs,
feature flags, enums (with `Unknown(n)` forward-compat) and bitmaps. The
modules under `gen/` are generated from a pinned `@matter/model` dump by the
`xtask` codegen tool (`cargo xtask codegen`); CI gates drift with
`cargo xtask codegen --check`.

Part of [`matter-rust`](https://github.com/phunapps/matter-rust). Milestone 7.

## Status

Pre-release (`0.0.0`). The 10 initial clusters are generated and **byte-parity
tested against matter.js 0.16.11** (`test-vectors/clusters/`): BasicInformation,
Descriptor, Identify, OnOff, LevelControl, ColorControl, OccupancySensing,
TemperatureMeasurement, RelativeHumidityMeasurement, and DoorLock (Aliro
features excluded). Hand-written support lives in `types` (`Nullable<T>`),
`error` (`ClusterError`), and `datatypes` (`SemanticTagStruct`).

## Generated code

`cargo xtask codegen` writes `src/gen/<cluster>.rs` (+ `globals.rs`, `mod.rs`)
from `xtask/model/clusters.json`. Do not edit the generated files by hand —
change the emitter (`xtask/src/codegen/`) and regenerate.
