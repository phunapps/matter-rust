# Matter specification references

This document collects the specific specification sections, matter.js modules,
and `connectedhomeip` source files we rely on, so we never have to hunt for
"where is the source of truth for X?".

The Matter specification ships under the Connectivity Standards Alliance. The
public version is downloadable from <https://csa-iot.org/all-solutions/matter/>.
Citations below refer to **Matter Core Specification version 1.4** unless
noted otherwise; bump the column when we adopt a later version.

| Topic                              | Matter Core §        | matter.js path                                    | connectedhomeip path                              |
| ---------------------------------- | -------------------- | ------------------------------------------------- | ------------------------------------------------- |
| TLV encoding                       | A.2                  | `packages/matter.js/src/codec/`                   | `src/lib/core/TLV*`                               |
| Matter certificate format          | 6.5                  | `packages/matter.js/src/certificate/`             | `src/credentials/CHIPCert.cpp`                    |
| PASE / SPAKE2+                     | 3.10                 | `packages/matter.js/src/session/pase/`            | `src/protocols/secure_channel/PASE*`              |
| CASE / SIGMA                       | 4.13                 | `packages/matter.js/src/session/case/`            | `src/protocols/secure_channel/CASE*`              |
| Secured message framing            | 4.4                  | `packages/matter.js/src/codec/MessageCodec.ts`    | `src/transport/SecureMessageCodec.cpp`            |
| Message Reliability Protocol (MRP) | 4.11                 | `packages/matter.js/src/protocol/`                | `src/messaging/ReliableMessageMgr.cpp`            |
| Operational Discovery (mDNS)       | 4.3                  | `packages/matter.js/src/mdns/`                    | `src/lib/dnssd/`                                  |
| Commissioning state machine        | 5.5                  | `packages/matter.js/src/behavior/CommissioningServerHandler.ts` | `src/app/server/CommissioningWindowManager.cpp` |
| Setup payload (QR / manual code)   | 5.1.3                | `packages/matter.js/src/schema/PairingCodeSchema.ts` | `src/setup_payload/`                            |
| Device attestation                 | 6.2                  | `packages/matter.js/src/certificate/` (DAC / PAI) | `src/credentials/DeviceAttestation*`              |
| Cluster: BasicInformation          | Device Lib §11.1     | `packages/matter.js/src/cluster/definitions/BasicInformation.ts` | `src/app/clusters/basic-information/` |
| Cluster: OnOff                     | Device Lib §1.5      | `packages/matter.js/src/cluster/definitions/OnOff.ts` | `src/app/clusters/on-off-server/`            |

## Conventions

- When a paragraph below uses "shall" / "may" / "should", it is quoting the
  Matter Core Specification directly. Treat them with RFC 2119 semantics.
- When matter.js and the C++ reference disagree, we treat the **C++ reference**
  as authoritative for protocol bytes and matter.js as authoritative for
  ergonomics. File an issue if you hit a divergence.
- Open questions about spec interpretation belong in
  `docs/decisions/` as an ADR, not as inline comments.
