# Changelog — matter-controller

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the crate adheres to
semantic versioning once published.

## [Unreleased]

### Added
- **M8.1** — Persistence foundation: `ControllerStore` trait + `FileStore`
  (atomic, `0600`); a versioned TLV snapshot of controller state; `create_fabric`
  mints and persists a **stable commissioner operational identity** once per
  fabric.
- **M8.2** — `MatterController` + `Node` over a single owning async task:
  transparent operational CASE connect / cache / reconnect; raw IM round-trip
  primitive.
- **M8.3** — `MatterController::commission` (QR or manual pairing code) brings a
  device onto the controller's fabric using the persisted commissioner identity,
  allocates a device node id, and persists a `DeviceEntry`. Attestation trust is
  configured on the controller via `MatterController::builder(store)
  .attestation_trust(AttestationTrust::csa_test_roots() | AttestationTrust::from_dirs(..))`.
  The per-call throwaway commissioner-NOC mint (former M6.6.4 simplification) is
  retired — one stable identity is used for commission-time and operational CASE
  alike.
- **M8.4** — `Node::read` / `write` / `invoke` over raw `matter_codec::Value`,
  including **wildcard reads** (`ReadPath::cluster` / `ReadPath::all`) for reading
  every attribute of a cluster or device. Re-exports `ReadPath` / `AttributePath`
  / `CommandPath` / `ImStatus` / `Value` / `InvokeResult`. Wildcard read encoding
  is byte-parity verified against matter.js.
- **M8.5** — `Node::subscribe` — live attribute-report streams via a concrete
  `Subscription` (`next().await` + `cancel()`) yielding `AttributeReport`s. The
  actor now conditionally listens for unsolicited steady-state reports while any
  subscription is active (between command handlers), acking each with a
  `StatusResponse`; the round-trip / read / commission paths are unchanged.
  Subscription IM messages (`SubscribeRequest`, `SubscribeResponse`,
  `StatusResponse`, steady-state `ReportData` with `subscriptionId`) are
  byte-parity verified against matter.js. _Known limitations (subscription
  hardening follow-up): (1) liveness-driven auto-resubscribe on staleness /
  session loss is not yet implemented — a report gap surfaces as a stalled
  stream rather than a transparent re-establish; (2) a steady-state report
  arriving while a concurrent round-trip (read/write/invoke) on the same node
  owns the socket is acked but its value is not delivered to the consumer (a
  pure subscription stream loses nothing). Both are fixed by routing off-exchange
  reports out of the round-trip path / the full always-listening demux._
