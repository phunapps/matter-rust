# matter-cert

Matter certificate format parsing and chain validation.

Part of [`matter-rust`](https://github.com/phunapps/matter-rust). Milestone 2.

> Status: **pre-release (`0.0.0`)**, not yet implemented.

Matter uses a TLV-encoded variant of X.509 with a Matter-specific Distinguished
Name layout. This crate parses those certificates, exposes their fields, and
validates chains (NOC → ICAC → RCAC, and DAC → PAI → PAA) against a configurable
set of trusted roots. Signature verification is performed by `ring`.
