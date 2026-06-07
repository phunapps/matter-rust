# M6 cross-verification report — matter.js vs matter-rust

**Status:** COMPLETE — PASSED 2026-06-07. Final verdict: **10 MATCH, 16
MATCH\*, 0 DIVERGENT, 0 DECODE-FAIL** (12 reference-only and 6 allowed
ours-only messages, all documented below).

Discharges the M6 validation requirement (CLAUDE.md): "Cross-verify the
commissioning trace against matter.js performing the same operation on the
same device."

## Method

Both controllers commission the same Tapo P110M (production attestation
chain) via an Enhanced Commissioning Method window. Each side captures its
decrypted dialogue as JSON lines; `cargo xtask trace-diff` aligns the
sequences (MRP acks excluded, comparison window cut at
CommissioningComplete, greedy content-keyed pairing — each side's unique
messages are isolated rather than blocking alignment) and compares TLV
trees with a default-exact rules table (`xtask/src/trace_diff.rs::rules()`
and `invoke_rules()`). Raw traces are NOT committed
(they contain the DAC chain, NOC/IPK, and fabric ids); this report is the
redacted artifact.

## Trace schema

One JSON object per decrypted message:
`{"seq":N,"dir":"tx"|"rx","session_id":N,"exchange":N,"protocol":N,"opcode":N,"payload":"<hex>"}`
`protocol` carries the 16-bit protocol short id (vendor id dropped — all
commissioning protocols are vendor 0). Session kinds are inferred per
trace by first-seen order PER DIRECTION (the wire carries the
destination's session id, so codec-level captures see different ids per
direction for one logical session): 0 → unsecured, first nonzero → PASE,
next → CASE.

## Verdict semantics

| verdict | meaning |
|---|---|
| MATCH | byte-identical TLV |
| MATCH* | differs only in fields with a classified variance rule (Random / RunSpecific) |
| DIVERGENT | any unclassified difference — wrong by default until triaged |
| DECODE-FAIL | matter-codec could not decode a payload — itself a finding |
| THEIRS-ONLY | message only in the matter.js dialogue (richer read pattern) — reported, never a failure |
| OURS-ONLY | message only in our dialogue — fails unless allowlisted with a documented reason |

## Runs

| | controller | date | result |
|---|---|---|---|
| A | matter.js 0.17.1 (`capture-commission-trace`) | 2026-06-07 | commissioned + decommissioned; 67 messages captured |
| B | matter-rust `commission_ip` | 2026-06-07 | commissioned (fabric `91ecf35e30505826`); 34 messages captured |

## Verdict table

```text
ignored tail after CommissioningComplete: ours=0 theirs=3 messages
[  0] tx unsecured PBKDFParamRequest proto=0x0000 op=0x20 | MATCH* [[]/1: Random (32 bytes differ), []/2: RunSpecific, []/5: OptionalField (present only in theirs)]
[  1] rx unsecured PBKDFParamResponse proto=0x0000 op=0x21 | MATCH* [[]/1: Random (32 bytes differ), []/2: Random (32 bytes differ), []/3: RunSpecific]
[  2] tx unsecured PASE Pake1 proto=0x0000 op=0x22 | MATCH* [[]/1: Random (65 bytes differ)]
[  3] rx unsecured PASE Pake2 proto=0x0000 op=0x23 | MATCH* [[]/1: Random (65 bytes differ), []/2: Random (32 bytes differ)]
[  4] tx unsecured PASE Pake3 proto=0x0000 op=0x24 | MATCH* [[]/1: Random (32 bytes differ)]
[  5] rx unsecured StatusReport proto=0x0000 op=0x40 | MATCH
[  6] seq=7   tx pase IM ReadRequest proto=0x0001 op=0x02 | OURS-ONLY (allowed: ReadCommissioningInfo stage (matter.js reads the same attributes in batched reads)) targets=(cluster=0x0030 id=0x0000),(cluster=0x0030 id=0x0001),(cluster=0x0030 id=0x0002),(cluster=0x0030 id=0x0004)
[  7] seq=8   rx pase IM ReportData proto=0x0001 op=0x05 | OURS-ONLY (allowed: ReadCommissioningInfo stage (matter.js reads the same attributes in batched reads)) targets=(cluster=0x0030 id=0x0004),(cluster=0x0030 id=0x0002),(cluster=0x0030 id=0x0001),(cluster=0x0030 id=0x0000)
[  8] seq=10  tx pase IM ReadRequest proto=0x0001 op=0x02 | THEIRS-ONLY targets=(cluster=0x003e id=0x0002),(cluster=0x003e id=0x0003),(cluster=0x001d id=0x0003),(cluster=0x001d id=0x0001),(cluster=0x0028 id=0x0002),(cluster=0x0028 id=0x0004),(cluster=0x0028 id=0x0003),(cluster=0x0030 id=0x0004)
[  9] seq=11  rx pase IM ReportData proto=0x0001 op=0x05 | THEIRS-ONLY targets=(cluster=0x0030 id=0x0004),(cluster=0x0028 id=0x0003),(cluster=0x0028 id=0x0004),(cluster=0x0028 id=0x0002),(cluster=0x001d id=0x0001),(cluster=0x001d id=0x0003),(cluster=0x003e id=0x0003),(cluster=0x003e id=0x0002)
[ 10] seq=13  tx pase IM ReadRequest proto=0x0001 op=0x02 | THEIRS-ONLY targets=(cluster=0x0031 id=0xfffc),(cluster=0x0031 id=0x0001),(cluster=0x002a id=0x0000)
[ 11] seq=14  rx pase IM ReportData proto=0x0001 op=0x05 | THEIRS-ONLY targets=(cluster=0x002a id=0x0000),(cluster=0x0031 id=0x0001),(cluster=0x0031 id=0xfffc)
[ 12] seq=16  tx pase IM ReadRequest proto=0x0001 op=0x02 | THEIRS-ONLY targets=(cluster=0x0030 id=0x0001)
[ 13] seq=17  rx pase IM ReportData proto=0x0001 op=0x05 | THEIRS-ONLY targets=(cluster=0x0030 id=0x0001)
[ 14] tx pase IM InvokeRequest proto=0x0001 op=0x08 | MATCH
[ 15] rx pase IM InvokeResponse proto=0x0001 op=0x09 | MATCH
[ 16] seq=22  tx pase IM ReadRequest proto=0x0001 op=0x02 | THEIRS-ONLY targets=(cluster=0x0030 id=0x0003)
[ 17] seq=23  rx pase IM ReportData proto=0x0001 op=0x05 | THEIRS-ONLY targets=(cluster=0x0030 id=0x0003)
[ 18] tx pase IM InvokeRequest proto=0x0001 op=0x08 | MATCH* [[]/2/[]/1/2: RunSpecific]
[ 19] rx pase IM InvokeResponse proto=0x0001 op=0x09 | MATCH
[ 20] seq=28  tx pase IM InvokeRequest proto=0x0001 op=0x08 | THEIRS-ONLY targets=(cluster=0x003e id=0x0002)
[ 21] seq=29  rx pase IM InvokeResponse proto=0x0001 op=0x09 | THEIRS-ONLY targets=(cluster=0x003e id=0x0003)
[ 22] tx pase IM InvokeRequest proto=0x0001 op=0x08 | MATCH
[ 23] rx pase IM InvokeResponse proto=0x0001 op=0x09 | MATCH
[ 24] seq=15  tx pase IM InvokeRequest proto=0x0001 op=0x08 | OURS-ONLY (allowed: CertificateChainRequest — DAC/PAI fetch order differs (chip: PAI first; matter.js: DAC first)) targets=(cluster=0x003e id=0x0002)
[ 25] seq=16  rx pase IM InvokeResponse proto=0x0001 op=0x09 | OURS-ONLY (allowed: CertificateChainResponse — DAC/PAI fetch order differs (chip: PAI first; matter.js: DAC first)) targets=(cluster=0x003e id=0x0003)
[ 26] tx pase IM InvokeRequest proto=0x0001 op=0x08 | MATCH* [[]/2/[]/1/0: Random (32 bytes differ)]
[ 27] rx pase IM InvokeResponse proto=0x0001 op=0x09 | MATCH* [[]/1/[]/0/1/0: RunSpecific, []/1/[]/0/1/1: Random (64 bytes differ)]
[ 28] tx pase IM InvokeRequest proto=0x0001 op=0x08 | MATCH* [[]/2/[]/1/0: Random (32 bytes differ)]
[ 29] rx pase IM InvokeResponse proto=0x0001 op=0x09 | MATCH* [[]/1/[]/0/1/0: RunSpecific, []/1/[]/0/1/1: Random (64 bytes differ)]
[ 30] tx pase IM InvokeRequest proto=0x0001 op=0x08 | MATCH* [[]/2/[]/1/0: RunSpecific]
[ 31] rx pase IM InvokeResponse proto=0x0001 op=0x09 | MATCH
[ 32] tx pase IM InvokeRequest proto=0x0001 op=0x08 | MATCH* [[]/2/[]/1/0: RunSpecific, []/2/[]/1/2: RunSpecific, []/2/[]/1/3: RunSpecific, []/2/[]/1/1: OptionalField (present only in theirs)]
[ 33] rx pase IM InvokeResponse proto=0x0001 op=0x09 | MATCH* [[]/1/[]/0/1/1: RunSpecific]
[ 34] seq=25  tx pase IM ReadRequest proto=0x0001 op=0x02 | OURS-ONLY (allowed: M6.5 NetworkCommissioning FeatureMap probe (matter.js uses its cluster model instead)) targets=(cluster=0x0031 id=0xfffc)
[ 35] seq=26  rx pase IM ReportData proto=0x0001 op=0x05 | OURS-ONLY (allowed: M6.5 NetworkCommissioning FeatureMap probe (matter.js uses its cluster model instead)) targets=(cluster=0x0031 id=0xfffc)
[ 36] seq=50  tx pase IM InvokeRequest proto=0x0001 op=0x08 | THEIRS-ONLY targets=(cluster=0x0030 id=0x0000)
[ 37] seq=51  rx pase IM InvokeResponse proto=0x0001 op=0x09 | THEIRS-ONLY targets=(cluster=0x0030 id=0x0001)
[ 38] tx unsecured CASE Sigma1 proto=0x0000 op=0x30 | MATCH* [[]/1: Random (32 bytes differ), []/2: RunSpecific, []/3: RunSpecific, []/4: Random (65 bytes differ), []/5: OptionalField (present only in theirs)]
[ 39] rx unsecured CASE Sigma2 proto=0x0000 op=0x31 | MATCH* [[]/1: Random (32 bytes differ), []/2: RunSpecific, []/3: Random (65 bytes differ), []/4: RunSpecific]
[ 40] tx unsecured CASE Sigma3 proto=0x0000 op=0x32 | MATCH* [[]/1: RunSpecific]
[ 41] rx unsecured StatusReport proto=0x0000 op=0x40 | MATCH
[ 42] tx case IM InvokeRequest proto=0x0001 op=0x08 | MATCH
[ 43] rx case IM InvokeResponse proto=0x0001 op=0x09 | MATCH
summary: 10 MATCH, 16 MATCH*, 0 DIVERGENT, 0 DECODE-FAIL, 12 THEIRS-ONLY, 6 OURS-ONLY-allowed, 0 OURS-ONLY-unclassified
```

Highlights: the PASE handshake, ArmFailSafe, SetRegulatoryConfig (modulo
breadcrumb), the PAI CertificateChainRequest/Response pair, both
StatusReports, and the CASE-session CommissioningComplete exchange are
byte-identical between the two controllers.

## Divergences found and resolutions

Every DIVERGENT from the initial runs was triaged to zero. None was a
wire-format bug in matter-rust.

| # | message | TLV path | finding | resolution |
|---|---|---|---|---|
| 1 | (all rx, matter.js trace) | — | session-kind inference mislabelled rx-PASE as CASE: the wire carries the destination's session id, so matter.js's codec-level capture sees different ids per direction | differ fix: per-direction first-seen inference |
| 2 | sequence alignment | — | each controller sends IM traffic the other doesn't (matter.js: batched reads, SetRegulatoryConfig position, final re-ArmFailSafe; us: focused GC info read, NetworkCommissioning FeatureMap probe) | greedy content-keyed alignment; THEIRS-ONLY reported, OURS-ONLY allowlisted with reasons |
| 3 | CertificateChainRequest | `[]/2/[]/1/0` | fetch order: we follow connectedhomeip (PAI→DAC, `AutoCommissioner.cpp` `kSendPAICertificateRequest` → `kSendDACCertificateRequest`); matter.js fetches DAC→PAI | certificate type folded into the alignment key; same-type exchanges pair across the reorder and are byte-identical; the leftover swapped pair is allowlisted |
| 4 | PBKDFParamRequest / Sigma1 | `[]/5` | matter.js sends the spec-optional `initiatorSessionParams` struct; we omit it | `OptionalField` rule |
| 5 | AddNOC | `[]/2/[]/1/1` | matter.js issues an ICAC; we issue the NOC from the RCAC directly | `OptionalField` rule |
| 6 | Sigma2/Sigma3 encrypted blobs | `[]/4`, `[]/1` | AEAD blobs embed the fabric-issued NOC — length varies per controller (ours=364 vs theirs=355) | reclassified Random → RunSpecific |
| 7 | AttestationResponse / NOCSRResponse elements | `[]/1/[]/0/1/0` | elements echo the request nonce / embed a fresh operational key | command-constrained RunSpecific rules |
| 8 | AddTrustedRootCertificate | `[]/2/[]/1/0` | each controller mints its own RCAC (249 vs 231 bytes) | command-constrained RunSpecific |
| 9 | SetRegulatoryConfig | `[]/2/[]/1/2` | breadcrumb progress counter advances differently (ours=2, theirs=1); config + country code match exactly | command-constrained RunSpecific |
| 10 | NOCResponse | `[]/1/[]/0/1/1` | device-assigned fabricIndex depends on the device's fabric-table history (ours=5, theirs=4) | command-constrained RunSpecific |

One controller-side fix surfaced on the matter.js side: its
`commissionNode` options must include `regulatoryLocation`/
`regulatoryCountryCode` (step 8.1 fails otherwise); the capture script now
sends values matching our driver.

## Rules-table rationale

Every rule lives in `xtask/src/trace_diff.rs` (`rules()`,
`invoke_rules()`, `ours_only_allowed()`) with an inline comment explaining
WHY the variance is legitimate — the code is the canonical record. The
classes:

| class | check | typical fields |
|---|---|---|
| Random | same type + same length | nonces, ephemeral keys, raw 64-byte signatures, SPAKE2+ shares |
| RunSpecific | same type | session ids, breadcrumbs, fabric credentials (RCAC/NOC/IPK), AEAD blobs embedding them, device fabricIndex |
| OptionalField | may be absent on one side | `initiatorSessionParams`, AddNOC ICAC |
| ours-only allowlist | exact (cluster, attr/cmd) targets | GC info read, NC FeatureMap probe, swapped DAC/PAI exchange |
