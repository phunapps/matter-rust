# matter-commissioning

Matter commissioning: setup payloads, the ten-stage state machine, device
attestation, NOC issuance, and network commissioning.

Part of [`matter-rust`](https://github.com/phunapps/matter-rust). Milestone 6.

> Status: **0.2.0**.
>
> **Milestone 6.4 (Commissioning State Machine): complete** — the
> state machine drives end-to-end from `SecurePairing` through
> `Action::Done(CommissionedFabric)` on canned responses + a mock
> `on_case_established` callback. matter.js byte-parity gate
> infrastructure shipped (operator-touch wiring deferred —
> see `TODO-1.0.md`).
>
> Phases available:
> - **M6.1:** the setup-payload codec (QR + manual pairing code).
> - **M6.2.1:** typed attestation cert wrappers (`Dac` / `Pai` /
>   `Paa`), `PaaTrustStore` with bundled CSA test roots, `VendorId` /
>   `ProductId` newtypes. Parsing only.
> - **M6.2.2:** `verify_chain` — `rustls-webpki` 0.103 path validation
>   with `KeyUsage::client_auth()` plus a Matter VID/PID equality
>   overlay. Six granular `AttestationError` variants with a
>   documented `webpki::Error` mapping. 8-row negative-fixture matrix.
> - **M6.2.3 (M6.2 feature-complete):** `verify_attestation_response`
>   — pure ECDSA P-256/SHA-256 verification via `ring` over
>   `attestation_elements || attestation_challenge`. Single coarse
>   `BadResponseSignature` error variant; matter.js byte-parity for
>   happy-path + four single-byte mutations.
> - **M6.3 (feature-complete):** NOC issuance — `FabricRecord`,
>   `verify_csr_response`, `issue_noc`, OpCreds command codecs with
>   matter.js byte-parity.
> - **M6.4 (complete):** commissioning state machine — all six
>   sub-phases (M6.4.1 skeleton → M6.4.6 byte-parity gate
>   infrastructure) shipped.
>
> Next: **M6.5** (Wi-Fi network commissioning subgraph) and **M6.6**
> (Tokio driver + first real-device commission). With M6.6 lands the
> first public demo of the library commissioning a real Matter device.

## Example: parse a QR code

```rust
use matter_commissioning::setup::parse_qr;

let payload = parse_qr("MT:Y.K90AFN00KA0648G00")?;
assert_eq!(payload.vendor_id, Some(0xFFF1));
assert_eq!(payload.passcode.as_u32(), 20_202_021);
```

(Replace the QR string with the actual captured value from
`test-vectors/commissioning/setup/qr-spec-example.json`.)

## Example: parse a manual pairing code

```rust
use matter_commissioning::setup::parse_manual_code;

let payload = parse_manual_code("11693312331")?;
assert_eq!(payload.discriminator.short(), 0x5);
```

## Example: parse a DAC and reach for a trusted root (M6.2.1)

```rust,no_run
use matter_commissioning::{Dac, PaaTrustStore, VendorId};

# fn run(dac_der: &[u8]) -> Result<(), matter_commissioning::AttestationError> {
let dac = Dac::from_der(dac_der)?;
assert_eq!(dac.subject_vid(), VendorId::new(0xFFF1));

let trust_store = PaaTrustStore::with_example_device_roots();
assert!(trust_store.len() > 0);
# Ok(())
# }
```

Chain validation against the trust store is M6.2.2.

## Example: validate an attestation chain (M6.2.2)

```rust,no_run
use matter_cert::time::MatterTime;
use matter_commissioning::{verify_chain, Dac, Pai, PaaTrustStore};

# fn run(dac_der: &[u8], pai_der: &[u8])
#   -> Result<(), matter_commissioning::AttestationError> {
let dac = Dac::from_der(dac_der)?;
let pai = Pai::from_der(pai_der)?;
let store = PaaTrustStore::with_example_device_roots();
let now = MatterTime::from_unix_secs(1_704_067_200);

let chain = verify_chain(&dac, &pai, &store, now)?;
println!("DAC verified for VID={} PID={}", chain.vendor_id, chain.product_id);
# Ok(())
# }
```

Production callers build their own `PaaTrustStore` from CSA-published
production roots (M8 deliverable). The bundled `with_example_device_roots()`
is for examples and integration tests only.

## Example: verify an attestation response (M6.2.3)

```rust,no_run
use matter_commissioning::{
    verify_attestation_response, AttestationResponse,
};

# fn run(
#     attestation_elements: Vec<u8>,
#     signature: [u8; 64],
#     dac_public_key: &[u8],
#     attestation_challenge: &[u8; 16],
# ) -> Result<(), matter_commissioning::AttestationError> {
let response = AttestationResponse {
    attestation_elements,
    signature,
};
verify_attestation_response(&response, attestation_challenge, dac_public_key)?;
# Ok(())
# }
```

The `dac_public_key` is exactly what `Dac::public_key()` returns
(raw SEC1 uncompressed P-256, 65 bytes). The `attestation_challenge`
is the 16-byte session value at `[32..48]` of the PASE/CASE session
key blob (exposed as `CaseSessionKeys::attestation_challenge` or
`PaseSessionKeys::attestation_key`). Any verification failure folds
into the single coarse `AttestationError::BadResponseSignature`.

## Example: drive the early commissioning stages (M6.4.1)

```rust,no_run
use std::sync::Arc;

use matter_cert::time::MatterTime;
use matter_commissioning::attestation::CdSigningRoots;
use matter_commissioning::noc::{FabricRecord, NocRng, SystemNocRng};
use matter_commissioning::{
    Action, Commissioner, CommissionerConfig, Expectation, PaaTrustStore, SetupPayload,
};
use matter_crypto::{RingSigner, Signer};

# fn run(
#     pase_attestation_challenge: [u8; 16],
#     setup: &SetupPayload,
# ) -> Result<(), Box<dyn std::error::Error>> {
let (signer, _pkcs8) = RingSigner::generate()?;
let signer: Arc<dyn Signer> = Arc::new(signer);
let rng_for_fabric = SystemNocRng;
let fabric = FabricRecord::new_root_only(
    /* fabric_id */ 0x0000_0000_0000_0001,
    signer,
    MatterTime::from_unix_secs(1_704_067_200),
    MatterTime::from_unix_secs(1_735_689_600),
    /* rcac_id */ 0xDEAD_BEEF_CAFE_F00D,
    &rng_for_fabric,
)?;

let paa = PaaTrustStore::with_example_device_roots();
let cd_signing_roots = CdSigningRoots::with_example_device_roots();
let rng: Arc<dyn NocRng> = Arc::new(SystemNocRng);
let cfg = CommissionerConfig {
    pase_attestation_challenge,
    fabric: &fabric,
    setup_payload: setup,
    paa_trust_store: &paa,
    cd_signing_roots: &cd_signing_roots,
    commissioner_node_id: 0x1,
    assigned_node_id: 0x2,
    ipk_epoch_key: [0x42_u8; 16],
    case_admin_subject: 0x1,
    admin_vendor_id: 0xFFF1,
    now: MatterTime::from_unix_secs(1_704_067_200),
    rng,
};
let mut sm = Commissioner::new(cfg)?;
loop {
    match sm.poll()? {
        Action::ReadAttribute { expect, .. } | Action::Invoke { expect, .. } => {
            // The caller (M6.6 driver) frames the request into an
            // Invoke/Read envelope, routes via matter-transport over
            // the PASE session, and feeds the decoded response back:
            let response_bytes: &[u8] = unimplemented!("driver supplies the bytes");
            sm.on_response(expect, response_bytes)?;
        }
        Action::Abort { send_disarm_failsafe, reason } => {
            eprintln!("commissioning aborted at {:?}: {reason}", sm.stage());
            if send_disarm_failsafe {
                // ... send DisarmFailsafe (ArmFailSafe with expiry=0) over PASE ...
            }
            break;
        }
        Action::Done(_) => break,
        other => unreachable!("M6.4.1 doesn't emit {other:?} yet"),
    }
}
# Ok(())
# }
```

M6.4.1 only drives `SecurePairing` → `ReadCommissioningInfo` →
`ArmFailsafe` → `ConfigRegulatory`. M6.4.2 extends the flow through
the attestation request/response stages, and M6.4.3 wires the
CSA-signed Certification Declaration check into the off-wire
`AttestationVerification` step so the cursor can advance past
attestation into the (M6.4.4) CSR + NOC issuance stages.

## Example: attestation flow through CD verification (M6.4.3)

The same driver loop from the M6.4.1 example works unchanged — after
`ConfigRegulatory` the state machine emits four more `Action::Invoke`
calls (PAI cert, DAC cert, AttestationRequest) and one off-wire
`AttestationVerification` step. M6.4.3 wires the CD-verify step in,
so on a valid CD the cursor advances past attestation:

```rust,no_run
use matter_commissioning::{
    Action, Commissioner, CommissionerConfig, CommissioningError, Expectation,
};

# fn run(
#     sm: &mut Commissioner,
#     pai_response_tlv: &[u8],
#     dac_response_tlv: &[u8],
#     attestation_response_tlv: &[u8],
# ) -> Result<(), Box<dyn std::error::Error>> {
// After ConfigRegulatory, cursor reaches SendPaiCertRequest.

// Stage 4: PAI cert request.
let _ = sm.poll()?;
sm.on_response(Expectation::PaiCertChainResponse, pai_response_tlv)?;

// Stage 5: DAC cert request.
let _ = sm.poll()?;
sm.on_response(Expectation::DacCertChainResponse, dac_response_tlv)?;

// Stage 6: AttestationRequest with fresh 32-byte random nonce.
let _ = sm.poll()?;
sm.on_response(Expectation::AttestationResponse, attestation_response_tlv)?;

// Stage 7: AttestationVerification (off-wire). Runs the M6.2/M6.4.3
// verifier chain — chain validation, attestation signature, nonce
// echo, then CD verification — and advances past attestation on
// success. On failure, `poll()` returns a typed `CommissioningError`
// and the cursor transitions to `Failed`.
let _ = sm.poll()?;
# Ok(())
# }
```

M6.4.4 will land the CSR / NOC issuance stages that consume the
advanced cursor.

## Example: verify a Certification Declaration standalone (M6.4.3)

`verify_certification_declaration` can be called directly without
involving the state machine — useful for offline analysis of captured
CD blobs:

```rust,no_run
use matter_commissioning::{
    verify_certification_declaration, AttestationError, CdSigningRoots,
    ProductId, VendorId,
};

# fn run(cd_bytes: &[u8]) -> Result<(), AttestationError> {
let trust = CdSigningRoots::with_example_device_roots();
verify_certification_declaration(
    cd_bytes,
    VendorId::new(0xFFF1),
    ProductId::new(0x8001),
    &trust,
)?;
# Ok(())
# }
```

Production callers replace `with_example_device_roots()` with
`CdSigningRoots::from_pem(&[my_root_pem])` loading the CSA-published
signing root(s) supplied by deployment.

The verifier performs five checks in order:
1. Parse the CMS/PKCS#7 SignedData via the `cms` crate.
2. Validate the CMS envelope shape (single signer, attached content,
   `ecdsa-with-SHA256`).
3. Verify the ECDSA-P256/SHA-256 signature against each trusted root;
   accept on first match.
4. Decode the inner Matter-TLV CD body to extract `vendor_id` +
   `product_id_array`.
5. Cross-check the declared VID/PID against the `expected_vid` /
   `expected_pid` arguments.

Any failure surfaces as a specific
`AttestationError::CertificationDeclaration*` variant.

## Example: full commissioning driver loop reaching `Action::Done` (M6.4.5)

The complete cursor walks from `SecurePairing` through
`Action::Done(CommissionedFabric)`. The caller (M6.6's Tokio driver in
the next major milestone) frames Invoke envelopes + routes via
`matter-transport`, then performs mDNS find-operational + the SIGMA
handshake when the state machine signals `Action::EstablishCase`:

```rust,no_run
use matter_commissioning::{
    Action, CommissionedFabric, Commissioner, CommissionerConfig,
    CommissioningError, Expectation,
};

# fn run(mut sm: Commissioner) -> Result<CommissionedFabric, CommissioningError> {
loop {
    match sm.poll()? {
        Action::Invoke { expect, .. } | Action::ReadAttribute { expect, .. } => {
            // Caller frames the request into Invoke/Read envelope and
            // routes via matter-transport. The session is PASE for all
            // pre-NOC stages and CASE after EstablishCase succeeds.
            let response_bytes: &[u8] = unimplemented!("driver supplies the bytes");
            sm.on_response(expect, response_bytes)?;
        }
        Action::EstablishCase { fabric_id, peer_node_id } => {
            // M6.6 driver: mDNS find-operational for the operational
            // service name keyed off (compressed_fabric_id, peer_node_id),
            // then run the SIGMA-I handshake from matter-crypto.
            // Pretend success here:
            let _ = (fabric_id, peer_node_id);
            sm.on_case_established()?;

            // On failure instead:
            //   sm.on_response(Expectation::CaseFailed, &[])?;
        }
        Action::EvictCase { .. } => {
            // Reserved for M8 multi-fabric work; never emitted by
            // M6.4's new-fabric flow.
        }
        Action::Done(commissioned_fabric) => {
            return Ok(commissioned_fabric);
        }
        Action::Abort { send_disarm_failsafe, reason } => {
            eprintln!("commissioning aborted: {reason}");
            if send_disarm_failsafe {
                // ... send ArmFailSafe(expiry=0) over PASE ...
            }
            return Err(CommissioningError::CaseEstablishmentFailed); // pick a representative error
        }
    }
}
# }
```

The returned `CommissionedFabric` carries the long-lived fabric record
(RCAC + IPK + fabric ID), the peer's operational node ID, the device's
NOC public key, and the terminal stage cursor (always
`Stage::Cleanup`).

## Wi-Fi commissioning configuration (M6.5+)

```rust
use matter_commissioning::{CommissionerConfig, NetworkCredentials, WiFiCredentials};

let config = CommissionerConfig {
    pase_attestation_challenge,
    fabric: &fabric,
    setup_payload: &setup,
    paa_trust_store: &paa,
    cd_signing_roots: &cd_signing_roots,
    commissioner_node_id: 0x1,
    assigned_node_id: 0x2,
    ipk_epoch_key: [0x42_u8; 16],
    case_admin_subject: 0x1,
    admin_vendor_id: 0xFFF1,
    now: MatterTime::from_unix_secs(1_704_067_200),
    rng,
    network: NetworkCredentials::WiFi(WiFiCredentials {
        ssid: b"matter".to_vec(),
        credentials: b"hunter22".to_vec(),
    }),
};
let mut sm = Commissioner::new(config)?;
```

For Ethernet-only devices (or devices already on their operational
network), set `network: NetworkCredentials::AlreadyOnNetwork` — the state
machine detects the network shape at `Stage::ReadNetworkCommissioningInfo`
and skips the Wi-Fi sub-cursor.

Thread commissioning is supported: set
`network: NetworkCredentials::Thread(dataset)` with a
[`ThreadDataset`](src/thread_dataset.rs) built from an operational dataset
(e.g. `ot-ctl dataset active -x`, hex-decoded). If the supplied credential
type doesn't match what the device actually offers — e.g. `Thread`
credentials against a device whose `NetworkCommissioning::FeatureMap` lacks
the Thread bit — commissioning fails fast with
`CommissioningError::NetworkFeatureUnsupported { needed }`, naming the
network type the device is missing.

### Optional `tracing` feature

Enable per-method spans for observability:

```toml
matter-commissioning = { version = "...", features = ["tracing"] }
```

Span field names (`stage`, `expectation`) align best-effort with
matter.js's log-event format so operators can grep across both
implementations.

## Byte parity

Every fixture in `test-vectors/commissioning/setup/` is captured from
matter.js by `cargo xtask capture-setup`. The integration test in
`tests/setup_byte_parity.rs` asserts that `encode_qr` / `encode_manual_code`
produce byte-identical output and that `parse_qr` / `parse_manual_code`
recover the same `SetupPayload`.

For attestation-response verification, `test-vectors/attestation/response/`
is captured by `cargo xtask capture-attestation`. The integration test
in `tests/attestation_response_byte_parity.rs` asserts that Rust and
matter.js's `NodeJsStyleCrypto.verifyEcdsa` produce the same
accept/reject verdict for a happy-path tuple plus four single-byte
mutations. (Byte-parity is on verdicts, not raw bytes — ECDSA's `k`
is randomized per signing call, so the captured signature varies
across script runs while the test assertions remain stable.)
