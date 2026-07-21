# matter-cert

Matter protocol certificate format — parsing, serialisation, X.509 DER
conversion, signature verification, and chain validation. Part of the
[matter-rust](https://github.com/phunapps/matter-rust) workspace.

## Scope

Implements Matter Core Specification §6.5: a TLV-encoded variant of
X.509 used for both attestation chains (DAC → PAI → PAA) and
operational chains (NOC → ICAC → RCAC). This crate covers reading
and validating Matter certs; issuing new certs lives in higher
milestones.

- TLV parser + serialiser (round-trip byte-exact)
- Distinguished-name attributes including Matter-specific OIDs
- Extension parsing (BasicConstraints, KeyUsage, ExtKeyUsage, SKI, AKI)
- ECDSA-P256-SHA256 public-key extraction
- X.509 DER TBSCertificate conversion (byte-identical to matter.js)
- Signature verification via `ring`
- Chain validation against configurable trust anchors

## Status

**0.2.0.** Feature-complete; API claimed stable;
not yet on crates.io. Cross-verified against matter.js for byte-level
compatibility on a 3-tier RCAC/ICAC/NOC chain.

See [`TODO-1.0.md`](../../TODO-1.0.md) for known gaps before any 1.0
release (notably: connectedhomeip cross-verification and CSA test PAA
bundle).

## Minimal example

```rust
use matter_cert::{
    CertificateChain, MatterCertificate, MatterTime, TrustAnchor, TrustedRoots,
};

let rcac = MatterCertificate::from_tlv(&std::fs::read("rcac.bin")?)?;
let icac = MatterCertificate::from_tlv(&std::fs::read("icac.bin")?)?;
let noc = MatterCertificate::from_tlv(&std::fs::read("noc.bin")?)?;

let mut roots = TrustedRoots::new();
roots.add(TrustAnchor::from_root_cert(&rcac));

let chain = CertificateChain::new(&[noc, icac]);
let now = MatterTime::from_unix_secs(1_750_000_000);
chain.validate(&roots, now)?;
// Ok(()) means: every cert is time-valid, the issuer/subject chain
// is structurally sound, every signature verifies, and the top cert
// anchors against rcac.
```

## Cryptographic primitives

This crate **does not implement crypto primitives.** It delegates to
[`ring`](https://github.com/briansmith/ring) for ECDSA-P256-SHA256
signature verification. ASN.1 DER encoding uses
[`der`](https://crates.io/crates/der).

## Cross-verification

`MatterCertificate::to_x509_tbs_der()` produces bytes byte-identical
to matter.js's `Certificate.asUnsignedDer()`. This parity is enforced
in CI against a captured 3-tier RCAC/ICAC/NOC chain. Future work
adds cross-verification against `project-chip/connectedhomeip` (see
`TODO-1.0.md`).

## License

Apache 2.0. See [LICENSE](../../LICENSE).
