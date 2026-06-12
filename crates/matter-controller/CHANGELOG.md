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
  pure subscription stream loses nothing). Limitation (2) is fixed by SH.1 (see
  below); limitation (1) is fixed by SH.2 (auto-resubscribe / liveness)._
- **M8.6** — v1.0 documentation pass: crate rustdoc with a runnable quickstart,
  README feature overview, `docs/matter-js-migration-guide.md`, and an
  `examples/controller_quickstart.rs` (commission → read / invoke / subscribe →
  reconnect from snapshot). Re-exports `MatterTime` so `FabricConfig` is
  constructible without a direct `matter-cert` dependency.
- **SH.2b** — Auto-resubscribe: a subscription that goes silent past its liveness
  deadline (negotiated max interval + grace) is transparently re-established on a
  chip-faithful Fibonacci backoff (10 s base, ~92 min cap, 30–100 % jitter, retry
  forever). The consumer sees `SubscriptionEvent::Resubscribing` → `Established` →
  a re-primed snapshot behind a **stable `Subscription` handle** — the device's
  wire subscription id changes across a resubscribe, the handle does not. Report
  delivery moved to an unbounded channel so a full re-prime is never truncated.

### Changed
- **SH.1** — The controller actor now runs a single always-listening demux that
  owns the UDP socket continuously, regardless of whether subscriptions are
  active. Round-trips and reads register a pending oneshot keyed by
  `(session, exchange)` instead of owning recv inside `secured_round_trip` /
  `secured_read`; steady-state subscription reports are routed to their consumer
  by **SubscriptionId**. MRP is driven centrally for all sessions, preserving the
  reconnect-once policy via a transparent reconnect-and-retry on timeout.
- **SH.2a** — `Node::subscribe`'s stream now yields a `SubscriptionEvent` enum
  (`Report(AttributeReport)` / `Established { subscription_id }` /
  `Resubscribing { cause }`) instead of a bare `AttributeReport`, and emits an
  `Established` event on each successful `SubscribeResponse`. (Breaking change to
  the M8.5 `Subscription::next()` signature; nothing published yet.)
  `Resubscribing` is wired by SH.2b (auto-resubscribe).

### Fixed
- **SH.1** — Subscription reports are no longer dropped when a round-trip
  (read / write / invoke) is concurrently in flight on the same node (M8.5 known
  limitation #2 — previously a bounded silent data-loss window).
- **SH.1** — Steady-state `ReportData` is now matched to its subscription by
  `SubscriptionId` rather than the original `SubscribeRequest` exchange. The prior
  exchange-keying was not spec-correct for a device that reports on a fresh,
  device-initiated exchange.
- **SH.2b** — A reconnect now evicts the prior session from the `SessionManager`,
  so a stale session's dead MRP retransmits stop instead of firing until expiry.
