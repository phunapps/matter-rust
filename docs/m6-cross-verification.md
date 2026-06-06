# M6 cross-verification report — matter.js vs matter-rust

**Status:** PENDING — awaiting the P110M operator run.

Discharges the M6 validation requirement (CLAUDE.md): "Cross-verify the
commissioning trace against matter.js performing the same operation on the
same device."

## Method

Both controllers commission the same Tapo P110M (production attestation
chain) via an Enhanced Commissioning Method window. Each side captures its
decrypted dialogue as JSON lines; `cargo xtask trace-diff` aligns the
sequences (MRP acks excluded, comparison window cut at
CommissioningComplete) and compares TLV trees with a default-exact rules
table (`xtask/src/trace_diff.rs::rules()`). Raw traces are NOT committed
(they contain the DAC chain, NOC/IPK, and fabric ids); this report is the
redacted artifact.

## Trace schema

One JSON object per decrypted message:
`{"seq":N,"dir":"tx"|"rx","session_id":N,"exchange":N,"protocol":N,"opcode":N,"payload":"<hex>"}`
`protocol` carries the 16-bit protocol short id (vendor id dropped — all
commissioning protocols are vendor 0). Session kinds are inferred per
trace by first-seen order: 0 → unsecured, first nonzero → PASE, next → CASE.

## Verdict semantics

| verdict | meaning |
|---|---|
| MATCH | byte-identical TLV |
| MATCH* | differs only in fields with a classified variance rule (Random / RunSpecific) |
| DIVERGENT | any unclassified difference — wrong by default until triaged |
| DECODE-FAIL | matter-codec could not decode a payload — itself a finding |

## Runs

| | controller | date | result |
|---|---|---|---|
| A | matter.js 0.17.1 (`capture-commission-trace`) | — | — |
| B | matter-rust `commission_ip` | — | — |

## Verdict table

(paste the `cargo xtask trace-diff` output here — it contains no key
material, only message names, TLV paths, and verdicts)

## Divergences found and resolutions

| # | message | TLV path | finding | resolution |
|---|---|---|---|---|
| — | — | — | — | — |

## Rules-table rationale

Every variance rule added during triage, with the WHY:

| rule | class | why legitimate |
|---|---|---|
| — | — | — |
