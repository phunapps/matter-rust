# matter-codec

Matter TLV (Tag-Length-Value) encoder and decoder.

Part of the [`matter-rust`](https://github.com/phunapps/matter-rust) workspace.
This crate implements **Milestone 1** of the project roadmap.

> Status: **pre-release (`0.0.0`)**. Nothing is implemented yet; this crate is a
> placeholder so the workspace builds.

## What this crate does

Matter encodes everything on the wire — cluster reads, command invocations,
certificates, attestation responses — using TLV. TLV is a compact, schema-less
encoding loosely related to BER but with Matter-specific tag forms.

This crate provides:

- A streaming `TlvReader` that decodes bytes without allocating.
- A streaming `TlvWriter` that encodes into a caller-provided buffer.
- All five tag forms (anonymous, context, common profile, implicit, fully
  qualified).
- Every element type the Matter spec defines.

## What this crate does not do

- Cluster definitions. See `matter-clusters`.
- Certificates. See `matter-cert`.
- Anything network. See `matter-transport`.

## Stability

`matter-codec` is the foundation crate for the whole workspace. Once it
publishes `0.1.0`, the wire-level behaviour is locked. API changes are still
allowed pre-`1.0`.
