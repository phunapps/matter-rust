# M9-B1 Runbook — Read events from a real device

Operator-gated validation for M9-B1: confirm `Node::read_events` returns a real
event report from a commissioned device. **Loopback + byte-parity already cover
the wire format; this runbook confirms a live device answers an event read.**

## Device
Tapo P110M (the device validated in M6.6 / M7.5 / M8). Either commission fresh or
reconnect from an existing snapshot via `--node` (no re-commission needed — open a
pairing window only if commissioning anew). See `m8.3-commission.md` for trust
material (production PAA/CD roots) and the commission flow.

## What to read
`BasicInformation` (cluster `0x0028`) defines the **StartUp** event (`0x00`),
emitted once per boot. To guarantee at least one StartUp is buffered, **power-cycle
the plug** shortly before the run. Other always-present candidates: `ShutDown`
(`0x01`), `Leave` (`0x02`) — StartUp is the reliable one.

## Steps
1. Build/connect a `MatterController` + `Node` for the device (reuse
   `examples/controller_quickstart.rs` or `examples/dump_attributes.rs` plumbing;
   reconnect with `--node <id>` from the persisted snapshot).
2. Read events for BasicInformation on endpoint 0, from the beginning:

   ```rust
   use matter_controller::{EventPath, EventReport};

   let events = node.read_events(&[EventPath::cluster(0, 0x0028)], &[]).await?;
   println!("got {} event(s)", events.len());
   for e in &events {
       if let EventReport::Data(it) = e {
           println!(
               "  ep={:?} cl={:?} ev={:?} num={} prio={:?} ts={:?}",
               it.path.endpoint, it.path.cluster, it.path.event,
               it.event_number, it.priority, it.timestamp,
           );
       }
   }
   ```

## Pass criteria
- At least one `EventReport::Data` is returned for `(endpoint 0, cluster 0x0028)`.
- A `StartUp` (`event 0x00`) report is present after a fresh power-cycle, carrying
  a non-empty payload (`SoftwareVersion`) and a plausible event number/timestamp.
- If the device buffers more events than fit one MTU, the result spans multiple
  `ReportData` chunks and `read_events` returns them all (reassembly is the same
  path proven by the M8 chunked-read work).

## Notes
- A device that has emitted **no** events since boot returns an empty `Vec` — that
  is not a failure; power-cycle and retry.
- Record the result (event count + a sample report) on the M9-B1 tracking note.
