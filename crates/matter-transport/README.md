# matter-transport

Matter network transport — secured-message framing, MRP reliability,
session management, and default Tokio UDP + mdns-sd adapters. Part of
the [matter-rust](https://github.com/phunapps/matter-rust) workspace.

## Scope

Implements Matter Core Specification §4 (network transport) plus the
MRP reliability layer (§4.11) and the application protocol header
(§4.4.5).

- **Framing (M5.1):** secured-message header encode/decode + AES-CCM-128
  payload encryption + sliding-window replay protection. Byte-identical
  to matter.js across 3 captured fixtures.
- **MRP + protocol header (M5.2):** per-session sans-IO state machine
  (pending acks, piggyback queue, exchange table, recent-reliable
  cache); Matter application protocol header codec (skip-and-ignore
  SX/V extensions). Byte-identical to matter.js across 3 more captured
  fixtures. Retransmit timing is sized to the **peer** — the active/idle
  base is chosen from the peer's activity within its Session Active
  Threshold (re-evaluated per retransmit, chip `GetMRPBaseTimeout`) using
  the peer's advertised `SII`/`SAI`/`SAT` (`MrpConfig::for_peer`), so a
  sleepy/ICD device is never hammered with active-interval spacing.
- **Transport + Discovery adapters (M5.3):** sans-IO `Transport` /
  `Discovery` traits + default Tokio UDP + mdns-sd implementations.

## Status

**0.2.0.** Feature-complete and validated against real silicon (ESP32-C6
over Wi-Fi and Thread) via the higher-level crates. The session table is
bounded with idle-first eviction (DoS defense).

## Cargo features

- `tokio` (default): enables `TokioUdpTransport` and the `Error::Io`
  variant. Pulls `tokio` 1.x with features `net + rt + io-util`.
- `mdns-sd` (default): enables `MdnsSdDiscovery` and the `Error::Mdns`
  variant. Pulls `mdns-sd` 0.13.

Embedded callers disable defaults:

```toml
matter-transport = { version = "0.2.0", default-features = false }
```

…and implement `Transport` + `Discovery` themselves against their HAL.

## Minimal example

```rust,no_run
use std::time::Instant;
use matter_transport::{
    protocol_header::ProtocolId,
    session::{PeerHint, SessionManager, SessionRole},
    MrpFlags, PeerAddress, TokioUdpTransport, Transport,
};
use matter_crypto::pase::PaseSessionKeys;

# async fn run() -> matter_transport::Result<()> {
let mut tx = TokioUdpTransport::bind(5540).await?;
let mut mgr = SessionManager::new();

// Register a session whose keys came from a completed PASE handshake.
let keys = PaseSessionKeys {
    ke: [0; 16], i2r_key: [0x11; 16], r2i_key: [0x22; 16],
    attestation_key: [0; 16],
};
let sid = mgr.register_pase(keys, SessionRole::Initiator, 1, PeerHint::default());

let peer = PeerAddress::from_ipv6("::1".parse().unwrap(), 5541);
let out = mgr.encode_outbound(
    sid, None, 0x02, ProtocolId::INTERACTION_MODEL,
    b"hello matter", MrpFlags { reliable: true }, Instant::now(),
)?;
tx.send(peer, out.wire_bytes)?;
# Ok(()) }
```

See `tests/loopback.rs` for a complete two-side example.

## Cross-verification

Framing and protocol-header layers are verified byte-for-byte against
matter.js across 6 captured fixtures (3 framing, 3 protocol header).
MRP behaviour (including peer-activity classification and peer-config
sizing) is covered by simulated-clock state-machine tests. Real-device
interop is validated end-to-end by the higher-level crates against an
ESP32-C6 over Wi-Fi and Thread.

## License

Apache 2.0. See [LICENSE](../../LICENSE).
