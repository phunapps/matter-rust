//! `xtask trace-diff` — structural comparison of two decrypted
//! commissioning dialogues (ours vs matter.js). M6 cross-verification.
//!
//! Input: two JSON-lines files produced by `commission_ip --trace-out`
//! and `xtask/scripts/capture-commission-trace/`. Output: a per-message
//! verdict table (MATCH / MATCH* / DIVERGENT / DECODE-FAIL). Exit
//! nonzero unless every aligned message is MATCH or MATCH*.
//!
//! # Protocol field notes
//!
//! The `protocol` field in each [`TraceRecord`] carries the 16-bit protocol
//! short-id only — the vendor-id portion of the fully-qualified protocol-id
//! is dropped by both capture sides (all commissioning protocols use vendor
//! 0x0000). A trace schema extension would be needed to distinguish
//! vendor-namespaced protocols.

#![forbid(unsafe_code)]
// xtask is build tooling, not library code; the CLAUDE.md no-unwrap
// rule is for library code only. The existing capture-* modules apply
// the same allow.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use matter_codec::{ContainerKind, Element, Tag, TlvReader};
use serde::Deserialize;
use std::path::Path;

/// One captured wire message (schema per the M6 cross-verification design).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TraceRecord {
    pub seq: u64,
    pub dir: String,
    pub session_id: u64,
    #[allow(dead_code)] // informational: exchange allocators differ per run
    pub exchange: u64,
    pub protocol: u16,
    pub opcode: u8,
    #[allow(dead_code)] // retained for Task 7 TLV comparison and human-readable output
    pub payload: String,
}

/// Session kind, inferred per trace by first-seen order of session ids:
/// 0 → Unsecured, first nonzero → Pase, any later new id → Case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionKind {
    Unsecured,
    Pase,
    Case,
}

/// A record annotated with its inferred session kind.
#[derive(Debug, Clone)]
pub(crate) struct Annotated {
    pub record: TraceRecord,
    pub kind: SessionKind,
}

const OPCODE_MRP_ACK: u8 = 0x10;
const PROTO_SECURE_CHANNEL: u16 = 0;
const PROTO_INTERACTION_MODEL: u16 = 1;

// IM opcode constants used in rules and CommissioningComplete detection.
const IM_OPCODE_READ_REQUEST: u8 = 0x02;
const IM_OPCODE_REPORT_DATA: u8 = 0x05;
const IM_OPCODE_INVOKE_REQUEST: u8 = 0x08;
const IM_OPCODE_INVOKE_RESPONSE: u8 = 0x09;

// SC opcode constants used in rules.
const SC_PBKDF_PARAM_REQUEST: u8 = 0x20;
const SC_PBKDF_PARAM_RESPONSE: u8 = 0x21;
const SC_PAKE1: u8 = 0x22;
const SC_PAKE2: u8 = 0x23;
const SC_PAKE3: u8 = 0x24;
const SC_SIGMA1: u8 = 0x30;
const SC_SIGMA2: u8 = 0x31;
const SC_SIGMA3: u8 = 0x32;
const SC_STATUS_REPORT: u8 = 0x40;

/// Parse a JSONL trace: drop MRP standalone acks, annotate session kinds.
///
/// # Errors
///
/// Returns a descriptive string if any line is not a valid
/// [`TraceRecord`] JSON object.
pub(crate) fn load_trace_str(text: &str) -> Result<Vec<Annotated>, String> {
    let mut out = Vec::new();
    // Session-kind inference is tracked PER DIRECTION. The wire session id is
    // direction-asymmetric: a Matter message carries the DESTINATION's local
    // session id, so a codec-level capture (matter.js) sees one id on tx
    // (the peer's) and a different id on rx (its own) for the SAME logical
    // session. Our driver-level capture records the local demuxed id for
    // both directions. Either way, the Nth distinct secured id within one
    // direction is the Nth logical session: first → PASE, later → CASE.
    // (Observed on the P110M first run: a single-list inference mislabelled
    // every matter.js rx-PASE message as Case.)
    let mut seen_secured_tx: Vec<u64> = Vec::new();
    let mut seen_secured_rx: Vec<u64> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: TraceRecord = serde_json::from_str(line)
            .map_err(|e| format!("line {}: malformed trace record: {e}", i + 1))?;
        if record.protocol == PROTO_SECURE_CHANNEL && record.opcode == OPCODE_MRP_ACK {
            continue; // MRP timing artifact, never aligned
        }
        let kind = if record.session_id == 0 {
            SessionKind::Unsecured
        } else {
            let seen = if record.dir == "tx" {
                &mut seen_secured_tx
            } else {
                &mut seen_secured_rx
            };
            if !seen.contains(&record.session_id) {
                seen.push(record.session_id);
            }
            // position is always Some — the id was just ensured present above
            match seen.iter().position(|s| *s == record.session_id) {
                Some(0) => SessionKind::Pase,
                _ => SessionKind::Case,
            }
        };
        out.push(Annotated { record, kind });
    }
    Ok(out)
}

/// Load a JSONL trace from a file path.
///
/// # Errors
///
/// Returns a descriptive string if the file cannot be read or any line
/// is not a valid [`TraceRecord`] JSON object.
pub(crate) fn load_trace(path: &Path) -> Result<Vec<Annotated>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    load_trace_str(&text)
}

/// Human label for a (protocol, opcode) pair.
pub(crate) fn opcode_name(protocol: u16, opcode: u8) -> &'static str {
    match (protocol, opcode) {
        (PROTO_SECURE_CHANNEL, 0x20) => "PBKDFParamRequest",
        (PROTO_SECURE_CHANNEL, 0x21) => "PBKDFParamResponse",
        (PROTO_SECURE_CHANNEL, 0x22) => "PASE Pake1",
        (PROTO_SECURE_CHANNEL, 0x23) => "PASE Pake2",
        (PROTO_SECURE_CHANNEL, 0x24) => "PASE Pake3",
        (PROTO_SECURE_CHANNEL, 0x30) => "CASE Sigma1",
        (PROTO_SECURE_CHANNEL, 0x31) => "CASE Sigma2",
        (PROTO_SECURE_CHANNEL, 0x32) => "CASE Sigma3",
        (PROTO_SECURE_CHANNEL, 0x33) => "CASE Sigma2Resume",
        (PROTO_SECURE_CHANNEL, 0x40) => "StatusReport",
        (PROTO_INTERACTION_MODEL, 0x01) => "IM StatusResponse",
        (PROTO_INTERACTION_MODEL, 0x02) => "IM ReadRequest",
        (PROTO_INTERACTION_MODEL, 0x05) => "IM ReportData",
        (PROTO_INTERACTION_MODEL, 0x08) => "IM InvokeRequest",
        (PROTO_INTERACTION_MODEL, 0x09) => "IM InvokeResponse",
        (PROTO_INTERACTION_MODEL, 0x0a) => "IM TimedRequest",
        _ => "unknown",
    }
}

/// One slot of the aligned dialogue.
#[derive(Debug)]
pub(crate) enum AlignedPair<'a> {
    /// A message both controllers sent/received — payloads get compared.
    Matched(&'a Annotated, &'a Annotated),
    /// A message only the reference (theirs/matter.js) dialogue contains.
    /// Expected: matter.js's commissioning flow issues more IM reads and
    /// invokes (e.g. `SetRegulatoryConfig`) than our minimal driver. Reported,
    /// never compared, and not a failure.
    TheirsOnly(&'a Annotated),
    /// A message only OUR dialogue contains. Wrong by default: it fails the
    /// run unless [`ours_only_allowed`] classifies it with a documented
    /// rationale (e.g. our M6.5 `NetworkCommissioning` `FeatureMap` probe).
    OursOnly(&'a Annotated),
}

/// The identity used to pair messages across the two dialogues.
///
/// `(kind, dir, protocol, opcode)` plus — for IM `ReadRequest`s, `ReportData`s,
/// and `InvokeRequest`s — the decoded (cluster, attribute-or-command) targets,
/// so that an extra message on either side (e.g. their `SetRegulatoryConfig`
/// invoke, our `FeatureMap` read) cannot pair with a different-content message
/// of the same opcode. Decode failures leave the target list empty; the
/// payload comparison reports them on matched pairs.
#[derive(Debug, Clone, PartialEq)]
struct AlignKey {
    kind: SessionKind,
    dir: String,
    protocol: u16,
    opcode: u8,
    /// (cluster, attribute-or-command) pairs; `None` components are wildcard
    /// path elements (matter.js issues wildcard reads).
    targets: Vec<(Option<u64>, Option<u64>)>,
    /// Extra content key for commands sent multiple times with different
    /// arguments — currently the `CertificateChainRequest` type field, so the
    /// DAC and PAI fetches pair correctly despite opposite fetch order.
    discriminator: Option<u64>,
}

fn align_key(a: &Annotated) -> AlignKey {
    let mut discriminator = None;
    let targets = if a.record.protocol == PROTO_INTERACTION_MODEL
        && matches!(
            a.record.opcode,
            IM_OPCODE_READ_REQUEST
                | IM_OPCODE_REPORT_DATA
                | IM_OPCODE_INVOKE_REQUEST
                | IM_OPCODE_INVOKE_RESPONSE
        ) {
        let tree = hex::decode(&a.record.payload)
            .ok()
            .and_then(|bytes| parse_tree(&bytes).ok());
        let targets = tree
            .as_deref()
            .map(|t| im_targets(a.record.opcode, t))
            .unwrap_or_default();
        // CertificateChainRequest (0x3E/0x02): both controllers send this
        // command TWICE (DAC and PAI), distinguished only by the field-0
        // certificate-type value — and in OPPOSITE order (we follow
        // connectedhomeip: PAI→DAC; matter.js fetches DAC→PAI). Fold the
        // type into the key so same-type requests pair across the reorder.
        if targets.contains(&(Some(0x3E), Some(0x02))) {
            discriminator = tree
                .as_deref()
                .and_then(|t| scalar_uint_at(t, "[]/2/[]/1/0"));
        }
        targets
    } else {
        Vec::new()
    };
    AlignKey {
        kind: a.kind,
        dir: a.record.dir.clone(),
        protocol: a.record.protocol,
        opcode: a.record.opcode,
        targets,
        discriminator,
    }
}

/// Fetch the Uint scalar at an exact rules-syntax path, if present.
fn scalar_uint_at(tree: &[Node], wanted: &str) -> Option<u64> {
    fn walk(nodes: &[Node], path: &str, wanted: &str) -> Option<u64> {
        for node in nodes {
            match node {
                Node::Scalar {
                    tag,
                    value: matter_codec::Value::Uint(v),
                } if join_path(path, tag) == wanted => return Some(*v),
                Node::Container { tag, children, .. } => {
                    let child_path = join_path(path, tag);
                    // Prune: only descend while the wanted path can still
                    // start with this prefix.
                    if wanted.starts_with(&child_path) {
                        if let Some(v) = walk(children, &child_path, wanted) {
                            return Some(v);
                        }
                    }
                }
                Node::Scalar { .. } => {}
            }
        }
        None
    }
    walk(tree, "", wanted)
}

/// Align the two dialogues with a greedy two-pointer walk. Where the streams
/// disagree, the walker looks ahead in the reference for a counterpart of our
/// next message: reference messages skipped over become
/// [`AlignedPair::TheirsOnly`]; one of ours with no in-order reference
/// counterpart becomes [`AlignedPair::OursOnly`].
///
/// Rationale: the two controllers share the structural protocol skeleton
/// (PASE, attestation, NOC, CASE) but each issues IM traffic the other does
/// not — matter.js reads more attributes and sends `SetRegulatoryConfig`; our
/// driver probes `NetworkCommissioning::FeatureMap`. Pairing is by [`AlignKey`]
/// (content-aware for IM reads/reports/invokes), and unique messages are
/// surfaced rather than failing alignment outright; `run()` decides which
/// unique messages are acceptable.
pub(crate) fn align<'a>(ours: &'a [Annotated], theirs: &'a [Annotated]) -> Vec<AlignedPair<'a>> {
    let mut out = Vec::new();
    let mut j = 0;
    for a in ours {
        let ka = align_key(a);
        // Look ahead: does the reference contain a counterpart for `a`
        // anywhere at or after the cursor?
        match (j..theirs.len()).find(|&jj| align_key(&theirs[jj]) == ka) {
            Some(found) => {
                for b in &theirs[j..found] {
                    out.push(AlignedPair::TheirsOnly(b));
                }
                out.push(AlignedPair::Matched(a, &theirs[found]));
                j = found + 1;
            }
            None => out.push(AlignedPair::OursOnly(a)),
        }
    }
    // Reference messages after our last one (still inside the comparison
    // window) are theirs-only too.
    for b in &theirs[j..] {
        out.push(AlignedPair::TheirsOnly(b));
    }
    out
}

/// Messages OUR driver sends that the matter.js reference flow does not.
/// Same discipline as the variance-rules table: every entry carries a WHY,
/// and anything not listed fails the run ("wrong by default").
fn ours_only_allowed(a: &Annotated) -> Option<&'static str> {
    const NC_FEATURE_MAP: (Option<u64>, Option<u64>) = (Some(0x31), Some(0xFFFC));
    const GC_INFO: [(Option<u64>, Option<u64>); 4] = [
        (Some(0x30), Some(0x0000)),
        (Some(0x30), Some(0x0001)),
        (Some(0x30), Some(0x0002)),
        (Some(0x30), Some(0x0004)),
    ];
    let key = align_key(a);
    if key.protocol != PROTO_INTERACTION_MODEL {
        return None;
    }
    // M6.5: the driver reads `NetworkCommissioning::FeatureMap` (cluster 0x31,
    // global attribute 0xFFFC) to decide whether network setup can be
    // skipped (Wi-Fi device already on-network for IP commissioning).
    // matter.js derives the same decision from its internal cluster model
    // without an explicit read, so the read and its `ReportData` exist only in
    // our trace.
    if matches!(key.opcode, IM_OPCODE_READ_REQUEST | IM_OPCODE_REPORT_DATA)
        && !key.targets.is_empty()
        && key.targets.iter().all(|t| *t == NC_FEATURE_MAP)
    {
        return Some(
            "M6.5 NetworkCommissioning FeatureMap probe (matter.js uses its cluster model instead)",
        );
    }
    // ReadCommissioningInfo: the driver reads exactly the four
    // GeneralCommissioning attributes it needs (Breadcrumb 0x0000,
    // BasicCommissioningInfo 0x0001, RegulatoryConfig 0x0002,
    // SupportsConcurrentConnection 0x0004). matter.js reads the same data
    // inside larger batched reads (descriptor + basic-info + operational
    // credentials in one request), so our focused read has no 1:1
    // counterpart.
    if matches!(key.opcode, IM_OPCODE_READ_REQUEST | IM_OPCODE_REPORT_DATA)
        && !key.targets.is_empty()
        && key.targets.iter().all(|t| GC_INFO.contains(t))
    {
        return Some(
            "ReadCommissioningInfo stage (matter.js reads the same attributes in batched reads)",
        );
    }
    // DAC/PAI fetch order: we follow connectedhomeip (PAI then DAC —
    // AutoCommissioner.cpp kSendPAICertificateRequest →
    // kSendDACCertificateRequest); matter.js fetches DAC then PAI. The
    // same-type exchanges pair across the reorder via the alignment-key
    // discriminator, but the LAST cert exchange on our side has no in-order
    // counterpart left, so its request and response surface as ours-only
    // (with matching theirs-only rows on the matter.js side).
    if key.opcode == IM_OPCODE_INVOKE_REQUEST && key.targets.contains(&(Some(0x3E), Some(0x02))) {
        return Some("CertificateChainRequest — DAC/PAI fetch order differs (chip: PAI first; matter.js: DAC first)");
    }
    if key.opcode == IM_OPCODE_INVOKE_RESPONSE && key.targets.contains(&(Some(0x3E), Some(0x03))) {
        return Some("CertificateChainResponse — DAC/PAI fetch order differs (chip: PAI first; matter.js: DAC first)");
    }
    None
}

/// Compact verdict-table row prefix: `seq=.. dir kind name proto=.. op=..`.
fn describe_row(a: &Annotated) -> String {
    let proto = a.record.protocol;
    let op = a.record.opcode;
    let kind_str = match a.kind {
        SessionKind::Unsecured => "unsecured",
        SessionKind::Pase => "pase",
        SessionKind::Case => "case",
    };
    format!(
        "seq={:<3} {} {} {} proto={proto:#06x} op={op:#04x}",
        a.record.seq,
        a.record.dir,
        kind_str,
        opcode_name(proto, op),
    )
}

/// ` targets=(cluster=…, attr/cmd=…)…` suffix for IM rows; empty otherwise.
fn targets_str(a: &Annotated) -> String {
    let targets = align_key(a).targets;
    if targets.is_empty() {
        return String::new();
    }
    let fmt_part = |v: Option<u64>| v.map_or("*".to_string(), |x| format!("{x:#06x}"));
    format!(
        " targets={}",
        targets
            .iter()
            .map(|(c, m)| format!("(cluster={} id={})", fmt_part(*c), fmt_part(*m)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

// ---------------------------------------------------------------------------
// TLV tree materialisation
// ---------------------------------------------------------------------------

/// A fully-materialised TLV tree node.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Node {
    Scalar {
        tag: Tag,
        value: matter_codec::Value,
    },
    Container {
        tag: Tag,
        kind: ContainerKind,
        children: Vec<Node>,
    },
}

/// Decode a TLV payload byte slice into a sequence of top-level nodes.
///
/// Uses the streaming [`TlvReader::next`] API so we maintain our own
/// stack rather than relying on `read_value`'s recursive descent — this
/// gives us `ContainerKind` per node, which we need for the comparison.
///
/// # Errors
///
/// Returns a human-readable error string on any TLV decode failure.
pub(crate) fn parse_tree(bytes: &[u8]) -> Result<Vec<Node>, String> {
    let mut reader = TlvReader::new(bytes);
    // Stack entries: (opening tag, container kind, children accumulated so far).
    let mut stack: Vec<(Tag, ContainerKind, Vec<Node>)> = Vec::new();
    let mut top: Vec<Node> = Vec::new();

    loop {
        match reader.next().map_err(|e| format!("TLV decode: {e:?}"))? {
            None => break,
            Some(Element::Scalar { tag, value }) => {
                let node = Node::Scalar { tag, value };
                match stack.last_mut() {
                    Some((_, _, children)) => children.push(node),
                    None => top.push(node),
                }
            }
            Some(Element::ContainerStart { tag, kind }) => {
                stack.push((tag, kind, Vec::new()));
            }
            Some(Element::ContainerEnd) => {
                let (tag, kind, children) = stack
                    .pop()
                    .ok_or_else(|| "unbalanced container end".to_string())?;
                let node = Node::Container {
                    tag,
                    kind,
                    children,
                };
                match stack.last_mut() {
                    Some((_, _, parent)) => parent.push(node),
                    None => top.push(node),
                }
            }
            // Element is #[non_exhaustive]; future variants are not TLV
            // elements we can structurally compare, so treat them as decode
            // failures.
            Some(_) => {
                return Err("unexpected Element variant (codec version mismatch?)".into());
            }
        }
    }
    if !stack.is_empty() {
        return Err("unterminated container".into());
    }
    Ok(top)
}

// ---------------------------------------------------------------------------
// Variance rules
// ---------------------------------------------------------------------------

/// Variance classes for legitimate cross-run differences. Everything not
/// covered by a rule must match EXACTLY (CLAUDE.md: wrong by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VarianceClass {
    /// Fresh randomness of fixed size: nonces, ephemeral keys, raw
    /// signatures. Same TLV type AND same byte length required.
    Random,
    /// Run- or controller-chosen values whose LENGTH may also vary:
    /// session ids, fabric/node ids, certificates and CSRs minted per
    /// controller, AEAD blobs that embed fabric-issued credentials.
    /// Same TLV type required.
    RunSpecific,
    /// A field one implementation sends and the other legitimately omits
    /// (optional per spec or an implementation choice — e.g. matter.js's
    /// `initiatorSessionParams`, or the ICAC matter.js issues and we don't).
    /// When present on both sides it must still compare clean under the
    /// other rules (or exactly).
    OptionalField,
}

/// One variance rule: (protocol, opcode, TLV path) → class.
///
/// Path syntax: "/"-joined segments from the message root; context tag =
/// decimal number, anonymous = "[]". Example: "[]/2/[]/1/0".
/// Paths match the output of [`parse_tree`] walking the node tree starting
/// from path "": the outermost anonymous structure is "[]", its context-1
/// child is "[]/1", etc.
///
/// **Invariant — scalar leaves only (Random/RunSpecific):** value-variance
/// rule paths must resolve to a SCALAR leaf node; they are consulted only
/// inside the `(Scalar, Scalar)` arm of the comparison, so a Random or
/// `RunSpecific` rule whose path points at a container never fires. If two
/// traces differ structurally at a container node, classify the differing
/// scalar leaves individually. `OptionalField` rules are the exception:
/// they are consulted at the struct-field level when a tag is present on
/// only one side, and may therefore name a container field (e.g. a
/// sessionParams struct).
///
/// **Anonymous array elements:** all anonymous array elements share the `[]`
/// path segment. A rule cannot disambiguate array elements by index — this
/// is intentional and fine for single-command commissioning invokes where
/// every array element has the same shape.
pub(crate) struct Rule {
    pub protocol: u16,
    pub opcode: u8,
    pub path: &'static str,
    pub class: VarianceClass,
}

/// The seed rules table. Grown during P110M triage — every addition needs
/// a comment saying WHY the variance is legitimate.
#[allow(clippy::too_many_lines)] // Table of protocol constants — can't be shortened meaningfully.
pub(crate) fn rules() -> &'static [Rule] {
    // SAFETY: static slice — no heap allocation needed. Declared as a
    // module-level static rather than a const to avoid duplication.
    static RULES: &[Rule] = &[
        // ---------------------------------------------------------------
        // SC 0x20 PBKDFParamRequest
        // ---------------------------------------------------------------
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PBKDF_PARAM_REQUEST,
            // ctx-1: initiatorRandom — fresh 32-byte nonce per session
            path: "[]/1",
            class: VarianceClass::Random,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PBKDF_PARAM_REQUEST,
            // ctx-2: initiatorSessionId — controller-chosen ephemeral id
            path: "[]/2",
            class: VarianceClass::RunSpecific,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PBKDF_PARAM_REQUEST,
            // ctx-5: initiatorSessionParams (spec-optional struct) —
            // matter.js sends its MRP parameters here, our driver omits it
            // (observed: P110M run 2026-06-07).
            path: "[]/5",
            class: VarianceClass::OptionalField,
        },
        // ---------------------------------------------------------------
        // SC 0x21 PBKDFParamResponse
        // ---------------------------------------------------------------
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PBKDF_PARAM_RESPONSE,
            // ctx-1: initiatorRandom echo — reflected back by device
            path: "[]/1",
            class: VarianceClass::Random,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PBKDF_PARAM_RESPONSE,
            // ctx-2: responderRandom — fresh 32-byte nonce from device
            path: "[]/2",
            class: VarianceClass::Random,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PBKDF_PARAM_RESPONSE,
            // ctx-3: responderSessionId — device-chosen ephemeral id
            path: "[]/3",
            class: VarianceClass::RunSpecific,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PBKDF_PARAM_RESPONSE,
            // ctx-4/ctx-2: pbkdf salt — device-chosen, changes each pairing window
            path: "[]/4/2",
            class: VarianceClass::Random,
        },
        // ---------------------------------------------------------------
        // SC 0x22 PASE Pake1
        // ---------------------------------------------------------------
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PAKE1,
            // ctx-1: pA — SPAKE2+ public share, ephemeral per session
            path: "[]/1",
            class: VarianceClass::Random,
        },
        // ---------------------------------------------------------------
        // SC 0x23 PASE Pake2
        // ---------------------------------------------------------------
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PAKE2,
            // ctx-1: pB — SPAKE2+ public share, ephemeral per session
            path: "[]/1",
            class: VarianceClass::Random,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PAKE2,
            // ctx-2: cB — SPAKE2+ verifier, derived from ephemeral material
            path: "[]/2",
            class: VarianceClass::Random,
        },
        // ---------------------------------------------------------------
        // SC 0x24 PASE Pake3
        // ---------------------------------------------------------------
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_PAKE3,
            // ctx-1: cA — SPAKE2+ verifier, derived from ephemeral material
            path: "[]/1",
            class: VarianceClass::Random,
        },
        // ---------------------------------------------------------------
        // SC 0x30 CASE Sigma1
        // ---------------------------------------------------------------
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA1,
            // ctx-1: initiatorRandom — fresh 32-byte nonce per CASE session
            path: "[]/1",
            class: VarianceClass::Random,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA1,
            // ctx-2: initiatorSessionId — controller-chosen ephemeral id
            path: "[]/2",
            class: VarianceClass::RunSpecific,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA1,
            // ctx-3: destinationId — HKDF of fabric root + node id, fabric-bound
            path: "[]/3",
            class: VarianceClass::RunSpecific,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA1,
            // ctx-4: initiatorEphPubKey — ephemeral P-256 public key
            path: "[]/4",
            class: VarianceClass::Random,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA1,
            // ctx-5: initiatorSessionParams (spec-optional struct) —
            // matter.js sends it, our driver omits it (P110M run 2026-06-07).
            path: "[]/5",
            class: VarianceClass::OptionalField,
        },
        // ---------------------------------------------------------------
        // SC 0x31 CASE Sigma2
        // ---------------------------------------------------------------
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA2,
            // ctx-1: responderRandom — fresh 32-byte nonce from device
            path: "[]/1",
            class: VarianceClass::Random,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA2,
            // ctx-2: responderSessionId — device-chosen ephemeral id
            path: "[]/2",
            class: VarianceClass::RunSpecific,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA2,
            // ctx-3: responderEphPubKey — ephemeral P-256 public key
            path: "[]/3",
            class: VarianceClass::Random,
        },
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA2,
            // ctx-4: encrypted2 — AEAD ciphertext embedding the DEVICE's NOC,
            // which is whatever the commissioning controller issued via
            // AddNOC. NOC sizes differ between controllers (matter.js issues
            // an ICAC chain, we issue from the RCAC directly), so the blob
            // LENGTH legitimately varies → RunSpecific, not Random
            // (observed: ours=364 vs theirs=355, P110M run 2026-06-07).
            path: "[]/4",
            class: VarianceClass::RunSpecific,
        },
        // ---------------------------------------------------------------
        // SC 0x32 CASE Sigma3
        // ---------------------------------------------------------------
        Rule {
            protocol: PROTO_SECURE_CHANNEL,
            opcode: SC_SIGMA3,
            // ctx-1: encrypted3 — AEAD ciphertext embedding the CONTROLLER's
            // NOC; length varies per controller for the same reason as
            // Sigma2's encrypted2 → RunSpecific.
            path: "[]/1",
            class: VarianceClass::RunSpecific,
        },
        // IM rules live in `invoke_rules()` — they are constrained to a
        // specific (cluster, command) so e.g. an attestation nonce rule
        // cannot classify a CertificateChainRequest type field.
    ];
    RULES
}

/// A variance rule constrained to one IM command.
///
/// For `InvokeRequest` payloads the (cluster, command) key is the REQUEST
/// command (e.g. `AttestationRequest` 0x3E/0x00); for `InvokeResponse`
/// payloads it is the RESPONSE command carried in the `InvokeResponseIB`
/// path (e.g. `AttestationResponse` 0x3E/0x01). Path syntax and the
/// scalar-leaf/`OptionalField` invariants match [`Rule`].
pub(crate) struct InvokeRule {
    pub cluster: u64,
    pub command: u64,
    pub path: &'static str,
    pub class: VarianceClass,
}

/// Command-constrained IM rules (see [`InvokeRule`]). Grown during triage —
/// every entry carries a WHY.
pub(crate) fn invoke_rules() -> &'static [InvokeRule] {
    static RULES: &[InvokeRule] = &[
        // AttestationRequest (OperationalCredentials 0x3E / 0x00):
        // field-0 = attestationNonce — fresh 32 bytes per run.
        InvokeRule {
            cluster: 0x3E,
            command: 0x00,
            path: "[]/2/[]/1/0",
            class: VarianceClass::Random,
        },
        // CSRRequest (0x3E / 0x04): field-0 = csrNonce — fresh 32 bytes.
        InvokeRule {
            cluster: 0x3E,
            command: 0x04,
            path: "[]/2/[]/1/0",
            class: VarianceClass::Random,
        },
        // AddTrustedRootCertificate (0x3E / 0x0B): field-0 = the RCAC.
        // Each controller mints its own root — content AND length differ.
        InvokeRule {
            cluster: 0x3E,
            command: 0x0B,
            path: "[]/2/[]/1/0",
            class: VarianceClass::RunSpecific,
        },
        // AddNOC (0x3E / 0x06): every credential field is fabric-specific.
        InvokeRule {
            cluster: 0x3E,
            command: 0x06,
            // field-0: NOCValue — issued by each controller's own CA.
            path: "[]/2/[]/1/0",
            class: VarianceClass::RunSpecific,
        },
        InvokeRule {
            cluster: 0x3E,
            command: 0x06,
            // field-1: ICACValue — matter.js issues an intermediate CA, our
            // driver issues the NOC from the RCAC directly and omits it
            // (observed: P110M run 2026-06-07).
            path: "[]/2/[]/1/1",
            class: VarianceClass::OptionalField,
        },
        InvokeRule {
            cluster: 0x3E,
            command: 0x06,
            // field-2: IPKValue — random epoch key per fabric.
            path: "[]/2/[]/1/2",
            class: VarianceClass::RunSpecific,
        },
        InvokeRule {
            cluster: 0x3E,
            command: 0x06,
            // field-3: caseAdminSubject — each controller's admin node id.
            path: "[]/2/[]/1/3",
            class: VarianceClass::RunSpecific,
        },
        // AttestationResponse (0x3E / 0x01):
        InvokeRule {
            cluster: 0x3E,
            command: 0x01,
            // field-0: attestationElements — echoes the request nonce, so it
            // differs per run; the embedded CD is identical but the blob as a
            // whole is run-specific.
            path: "[]/1/[]/0/1/0",
            class: VarianceClass::RunSpecific,
        },
        InvokeRule {
            cluster: 0x3E,
            command: 0x01,
            // field-1: attestationSignature — raw 64-byte P-256 signature
            // over run-specific elements (fixed length → Random).
            path: "[]/1/[]/0/1/1",
            class: VarianceClass::Random,
        },
        // CSRResponse / NOCSRResponse (0x3E / 0x05):
        InvokeRule {
            cluster: 0x3E,
            command: 0x05,
            // field-0: nocsrElements — embeds a freshly-generated operational
            // public key and the csrNonce; DER integer lengths vary ±1 byte.
            path: "[]/1/[]/0/1/0",
            class: VarianceClass::RunSpecific,
        },
        InvokeRule {
            cluster: 0x3E,
            command: 0x05,
            // field-1: attestationSignature — raw 64 bytes (fixed → Random).
            path: "[]/1/[]/0/1/1",
            class: VarianceClass::Random,
        },
        // SetRegulatoryConfig (GeneralCommissioning 0x30 / 0x02):
        InvokeRule {
            cluster: 0x30,
            command: 0x02,
            // field-2: breadcrumb — a controller-chosen progress counter;
            // the two flows advance it differently (ours=2 vs matter.js=1
            // at this stage, P110M run 2026-06-07). Fields 0/1 (config,
            // country) must still match exactly.
            path: "[]/2/[]/1/2",
            class: VarianceClass::RunSpecific,
        },
        // NOCResponse (0x3E / 0x08, response to AddNOC):
        InvokeRule {
            cluster: 0x3E,
            command: 0x08,
            // field-1: fabricIndex — the device assigns the next free slot
            // in ITS fabric table, so the value depends on how many fabrics
            // the device has accumulated (observed: ours=5 vs theirs=4).
            path: "[]/1/[]/0/1/1",
            class: VarianceClass::RunSpecific,
        },
        // CertificateChainRequest (0x3E / 0x02) and its response (0x3E /
        // 0x03) carry NO rules: the requested type and the returned device
        // certificates are static for a given device and must match exactly
        // when paired. (Fetch ORDER differs between us and matter.js — see
        // `ours_only_allowed` — but paired exchanges must be byte-equal.)
    ];
    RULES
}

// ---------------------------------------------------------------------------
// Verdict type and comparison
// ---------------------------------------------------------------------------

/// Per-message comparison verdict.
#[derive(Debug)]
pub(crate) enum Verdict {
    /// Payloads are structurally and value-identical.
    Match,
    /// Payloads are structurally identical; all differences are covered by
    /// variance rules (`Random` / `RunSpecific`).
    MatchStar { classified: Vec<String> },
    /// One or more structural or value differences are NOT covered by rules.
    Divergent { diffs: Vec<String> },
    /// The payload could not be decoded as TLV on at least one side.
    DecodeFail { side: &'static str, error: String },
}

fn tag_segment(tag: &Tag) -> String {
    match tag {
        Tag::Anonymous => "[]".to_string(),
        Tag::Context(n) => n.to_string(),
        // Only Anonymous and Context tags appear in commissioning TLV. Other
        // tag forms (CommonProfile, ImplicitProfile, FullyQualified) render
        // debug-only here and will not match any rule path, so any scalar
        // difference under such a tag always falls through to an unclassified
        // diff — which is the safe, conservative behaviour.
        other => format!("{other:?}"),
    }
}

/// Join a parent path and a child tag — no leading separator at the root,
/// so paths look exactly like the rules table's paths ("[]/1", not "/[]/1").
fn join_path(path: &str, tag: &Tag) -> String {
    if path.is_empty() {
        tag_segment(tag)
    } else {
        format!("{path}/{}", tag_segment(tag))
    }
}

/// Look up the byte length of a value when its type is Bytes or Utf8.
/// Returns None for other variants.
fn value_len(v: &matter_codec::Value) -> Option<usize> {
    match v {
        matter_codec::Value::Bytes(b) => Some(b.len()),
        matter_codec::Value::Utf8(s) => Some(s.len()),
        _ => None,
    }
}

/// Returns true if two Values have the same variant (ignoring content).
fn same_variant(a: &matter_codec::Value, b: &matter_codec::Value) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

/// Look up the variance class for (protocol, opcode, exact path), consulting
/// the generic table first, then — for IM invoke traffic — the
/// command-constrained [`invoke_rules`] against the message's decoded
/// (cluster, command) targets.
fn find_class(
    protocol: u16,
    opcode: u8,
    path: &str,
    targets: &[(u64, u64)],
    rules: &[Rule],
) -> Option<VarianceClass> {
    if let Some(rule) = rules
        .iter()
        .find(|r| r.protocol == protocol && r.opcode == opcode && r.path == path)
    {
        return Some(rule.class);
    }
    if protocol == PROTO_INTERACTION_MODEL {
        if let Some(rule) = invoke_rules().iter().find(|r| {
            r.path == path
                && targets
                    .iter()
                    .any(|&(c, m)| c == r.cluster && m == r.command)
        }) {
            return Some(rule.class);
        }
    }
    None
}

/// Shared context for one payload comparison: the message identity used by
/// rule lookups.
struct CompareCtx<'r> {
    protocol: u16,
    opcode: u8,
    /// Decoded IM (cluster, command) targets — empty for non-invoke traffic.
    targets: Vec<(u64, u64)>,
    rules: &'r [Rule],
}

impl CompareCtx<'_> {
    fn class_at(&self, path: &str) -> Option<VarianceClass> {
        find_class(self.protocol, self.opcode, path, &self.targets, self.rules)
    }
}

/// Compare two child sequences.
///
/// STRUCTURE children are paired BY TAG — TLV structs are tag-keyed maps,
/// implementations may order or omit optional fields differently — and a
/// field present on only one side is classified via an `OptionalField` rule
/// or reported as a diff. Array/List children (and the payload root) are
/// positional with a strict count check.
fn compare_children(
    ctx: &CompareCtx<'_>,
    path: &str,
    parent_kind: Option<ContainerKind>,
    a: &[Node],
    b: &[Node],
    classified: &mut Vec<String>,
    diffs: &mut Vec<String>,
) {
    if parent_kind == Some(ContainerKind::Structure) {
        // By-tag pairing. Duplicate tags within a struct are spec-illegal;
        // first match wins.
        for an in a {
            let ta = node_tag(an);
            match b.iter().find(|bn| node_tag(bn) == ta) {
                Some(bn) => compare_pair(ctx, path, an, bn, classified, diffs),
                None => one_sided(ctx, path, ta, "ours", classified, diffs),
            }
        }
        for bn in b {
            let tb = node_tag(bn);
            if !a.iter().any(|an| node_tag(an) == tb) {
                one_sided(ctx, path, tb, "theirs", classified, diffs);
            }
        }
        return;
    }
    if a.len() != b.len() {
        diffs.push(format!(
            "child count mismatch at path {path:?}: ours={} theirs={}",
            a.len(),
            b.len()
        ));
        return;
    }
    for (an, bn) in a.iter().zip(b.iter()) {
        compare_pair(ctx, path, an, bn, classified, diffs);
    }
}

fn node_tag(n: &Node) -> &Tag {
    match n {
        Node::Scalar { tag, .. } | Node::Container { tag, .. } => tag,
    }
}

/// A struct field present on only one side: legitimate when an
/// `OptionalField` rule names its path, a diff otherwise.
fn one_sided(
    ctx: &CompareCtx<'_>,
    path: &str,
    tag: &Tag,
    side: &str,
    classified: &mut Vec<String>,
    diffs: &mut Vec<String>,
) {
    let child_path = join_path(path, tag);
    if ctx.class_at(&child_path) == Some(VarianceClass::OptionalField) {
        classified.push(format!(
            "{child_path}: OptionalField (present only in {side})"
        ));
    } else {
        diffs.push(format!("field present only in {side} at {child_path:?}"));
    }
}

/// Compare one same-position (or same-tag) node pair.
fn compare_pair(
    ctx: &CompareCtx<'_>,
    path: &str,
    an: &Node,
    bn: &Node,
    classified: &mut Vec<String>,
    diffs: &mut Vec<String>,
) {
    match (an, bn) {
        (Node::Scalar { tag: ta, value: va }, Node::Scalar { tag: tb, value: vb }) => {
            let child_path = join_path(path, ta);
            if ta != tb {
                diffs.push(format!(
                    "tag mismatch at {child_path:?}: ours={ta:?} theirs={tb:?}"
                ));
                return;
            }
            if va == vb {
                return; // exact match — nothing to record
            }
            // Values differ — check rules.
            match ctx.class_at(&child_path) {
                Some(VarianceClass::Random) => {
                    // Same type required; same byte length required for
                    // length-bearing types (Bytes / Utf8).
                    if same_variant(va, vb) {
                        if let (Some(la), Some(lb)) = (value_len(va), value_len(vb)) {
                            if la == lb {
                                classified
                                    .push(format!("{child_path}: Random ({la} bytes differ)"));
                            } else {
                                diffs.push(format!(
                                    "length mismatch under Random rule at \
                                     {child_path:?}: ours={la} theirs={lb}"
                                ));
                            }
                        } else {
                            // Non-length-bearing scalar (uint, int, bool…): same
                            // type is sufficient for Random class.
                            classified.push(format!("{child_path}: Random (scalar value differs)"));
                        }
                    } else {
                        diffs.push(format!(
                            "type mismatch under Random rule at {child_path:?}: \
                             ours={va:?} theirs={vb:?}"
                        ));
                    }
                }
                // OptionalField on a both-sides-present field still permits
                // value variance only at the same-type level (it exists for
                // presence variance; treat like RunSpecific when present).
                Some(VarianceClass::RunSpecific | VarianceClass::OptionalField) => {
                    if same_variant(va, vb) {
                        classified.push(format!("{child_path}: RunSpecific"));
                    } else {
                        diffs.push(format!(
                            "type mismatch under RunSpecific rule at {child_path:?}: \
                             ours={va:?} theirs={vb:?}"
                        ));
                    }
                }
                None => {
                    diffs.push(format!(
                        "unclassified value difference at {child_path:?}: \
                         ours={va:?} theirs={vb:?}"
                    ));
                }
            }
        }
        (
            Node::Container {
                tag: ta,
                kind: ka,
                children: ca,
            },
            Node::Container {
                tag: tb,
                kind: kb,
                children: cb,
            },
        ) => {
            let child_path = join_path(path, ta);
            if ta != tb {
                diffs.push(format!(
                    "container tag mismatch at {child_path:?}: ours={ta:?} theirs={tb:?}"
                ));
                return;
            }
            if ka != kb {
                diffs.push(format!(
                    "container kind mismatch at {child_path:?}: ours={ka:?} theirs={kb:?}"
                ));
                return;
            }
            compare_children(ctx, &child_path, Some(*ka), ca, cb, classified, diffs);
        }
        _ => {
            // One is a Scalar and the other is a Container.
            diffs.push(format!(
                "node kind mismatch at path {path:?}: \
                 ours={an:?} theirs={bn:?}"
            ));
        }
    }
}

/// Returns true when a (protocol, opcode) payload is NOT TLV and should be
/// compared raw.
///
/// `StatusReport` (SC 0x40) is a fixed binary struct, not TLV. Any other
/// non-TLV opcodes discovered during triage should be added here with a
/// comment.
fn is_raw_payload(protocol: u16, opcode: u8) -> bool {
    protocol == PROTO_SECURE_CHANNEL && opcode == SC_STATUS_REPORT
}

/// Compare two hex-encoded payloads and return a [`Verdict`].
pub(crate) fn compare_payload(
    protocol: u16,
    opcode: u8,
    ours_hex: &str,
    theirs_hex: &str,
    rules: &[Rule],
) -> Verdict {
    // StatusReport is NOT TLV — raw byte equality. Case-insensitive so a
    // future capture source emitting uppercase hex cannot false-DIVERGENT
    // a byte-identical payload (both current producers emit lowercase).
    if is_raw_payload(protocol, opcode) {
        if ours_hex.eq_ignore_ascii_case(theirs_hex) {
            return Verdict::Match;
        }
        return Verdict::Divergent {
            diffs: vec![format!(
                "raw payload mismatch: ours={ours_hex} theirs={theirs_hex}"
            )],
        };
    }

    // Hex-decode both sides.
    let ours_bytes = match hex::decode(ours_hex) {
        Ok(b) => b,
        Err(e) => {
            return Verdict::DecodeFail {
                side: "ours",
                error: format!("hex decode: {e}"),
            };
        }
    };
    let theirs_bytes = match hex::decode(theirs_hex) {
        Ok(b) => b,
        Err(e) => {
            return Verdict::DecodeFail {
                side: "theirs",
                error: format!("hex decode: {e}"),
            };
        }
    };

    // Parse TLV trees.
    let ours_tree = match parse_tree(&ours_bytes) {
        Ok(t) => t,
        Err(e) => {
            return Verdict::DecodeFail {
                side: "ours",
                error: e,
            }
        }
    };
    let theirs_tree = match parse_tree(&theirs_bytes) {
        Ok(t) => t,
        Err(e) => {
            return Verdict::DecodeFail {
                side: "theirs",
                error: e,
            }
        }
    };

    // Structural comparison. The invoke-command targets constrain IM rules;
    // derive them from OUR side (the aligned pair shares targets by
    // construction of the alignment key).
    let targets = if protocol == PROTO_INTERACTION_MODEL
        && matches!(opcode, IM_OPCODE_INVOKE_REQUEST | IM_OPCODE_INVOKE_RESPONSE)
    {
        if opcode == IM_OPCODE_INVOKE_REQUEST {
            invoke_targets(&ours_tree)
        } else {
            invoke_response_targets(&ours_tree)
        }
    } else {
        Vec::new()
    };
    let ctx = CompareCtx {
        protocol,
        opcode,
        targets,
        rules,
    };
    let mut classified = Vec::new();
    let mut diffs = Vec::new();
    compare_children(
        &ctx,
        "",
        None,
        &ours_tree,
        &theirs_tree,
        &mut classified,
        &mut diffs,
    );

    if !diffs.is_empty() {
        Verdict::Divergent { diffs }
    } else if !classified.is_empty() {
        Verdict::MatchStar { classified }
    } else {
        Verdict::Match
    }
}

// ---------------------------------------------------------------------------
// CommissioningComplete window detection
// ---------------------------------------------------------------------------

/// Extract (cluster, command) pairs from the top-level node of an IM
/// `InvokeRequest` payload.
///
/// `InvokeRequest` TLV layout (per Matter spec §10.6.8):
/// ```text
/// anonymous struct {
///   ctx-0: bool (suppressResponse)
///   ctx-1: bool (timedRequest)
///   ctx-2: array [       ← CommandDataIB list
///     anonymous struct {
///       ctx-0: LIST {    ← CommandPathIB
///         ctx-0: uint (endpointId)
///         ctx-1: uint (clusterId)
///         ctx-2: uint (commandId)
///       }
///       ctx-1: struct {} ← command fields
///     }
///   ]
/// }
/// ```
///
/// Returns a vec of (clusterId, commandId) pairs found in the payload.
pub(crate) fn invoke_targets(tree: &[Node]) -> Vec<(u64, u64)> {
    let mut result = Vec::new();
    // Top level: look for the first anonymous structure.
    for top_node in tree {
        let Node::Container {
            tag: Tag::Anonymous,
            kind: ContainerKind::Structure,
            children,
        } = top_node
        else {
            continue;
        };
        // Find ctx-2 (CommandDataIB array).
        for child in children {
            let Node::Container {
                tag: Tag::Context(2),
                kind: ContainerKind::Array,
                children: array_items,
            } = child
            else {
                continue;
            };
            // Each array item is an anonymous struct with ctx-0 (CommandPathIB LIST)
            for item in array_items {
                let Node::Container {
                    tag: Tag::Anonymous,
                    kind: ContainerKind::Structure,
                    children: item_fields,
                } = item
                else {
                    continue;
                };
                // Find ctx-0 (CommandPathIB LIST)
                for field in item_fields {
                    let Node::Container {
                        tag: Tag::Context(0),
                        kind: ContainerKind::List,
                        children: path_fields,
                    } = field
                    else {
                        continue;
                    };
                    let mut cluster_id: Option<u64> = None;
                    let mut command_id: Option<u64> = None;
                    for path_field in path_fields {
                        match path_field {
                            Node::Scalar {
                                tag: Tag::Context(1),
                                value: matter_codec::Value::Uint(v),
                            } => {
                                cluster_id = Some(*v);
                            }
                            Node::Scalar {
                                tag: Tag::Context(2),
                                value: matter_codec::Value::Uint(v),
                            } => {
                                command_id = Some(*v);
                            }
                            _ => {}
                        }
                    }
                    if let (Some(c), Some(cmd)) = (cluster_id, command_id) {
                        result.push((c, cmd));
                    }
                }
            }
        }
    }
    result
}

/// Decoded (cluster, command) targets of an `InvokeResponse` payload: the
/// RESPONSE command ids carried in the `InvokeResponseIB` paths (e.g.
/// `AttestationResponse` 0x3E/0x01). Shape:
///
/// ```text
/// anonymous struct {
///   ctx-1: array [                      ← InvokeResponseIB array
///     anonymous struct {
///       ctx-0: struct {                 ← CommandDataIB
///         ctx-0: LIST { 0: endpoint, 1: cluster, 2: command }
///         ctx-1: fields
///       }
///       // (or ctx-1: CommandStatusIB { ctx-0: same path LIST, ... })
///     }
///   ]
/// }
/// ```
pub(crate) fn invoke_response_targets(tree: &[Node]) -> Vec<(u64, u64)> {
    let mut result = Vec::new();
    for top_node in tree {
        let Node::Container {
            tag: Tag::Anonymous,
            kind: ContainerKind::Structure,
            children,
        } = top_node
        else {
            continue;
        };
        for child in children {
            let Node::Container {
                tag: Tag::Context(1),
                kind: ContainerKind::Array,
                children: array_items,
            } = child
            else {
                continue;
            };
            for item in array_items {
                let Node::Container {
                    tag: Tag::Anonymous,
                    kind: ContainerKind::Structure,
                    children: ib_fields,
                } = item
                else {
                    continue;
                };
                // ctx-0 = CommandDataIB, ctx-1 = CommandStatusIB; both carry
                // the path LIST at their own ctx-0.
                for ib in ib_fields {
                    let Node::Container {
                        kind: ContainerKind::Structure,
                        children: data_fields,
                        ..
                    } = ib
                    else {
                        continue;
                    };
                    for field in data_fields {
                        let Node::Container {
                            tag: Tag::Context(0),
                            kind: ContainerKind::List,
                            children: path_fields,
                        } = field
                        else {
                            continue;
                        };
                        let mut cluster_id: Option<u64> = None;
                        let mut command_id: Option<u64> = None;
                        for path_field in path_fields {
                            match path_field {
                                Node::Scalar {
                                    tag: Tag::Context(1),
                                    value: matter_codec::Value::Uint(v),
                                } => cluster_id = Some(*v),
                                Node::Scalar {
                                    tag: Tag::Context(2),
                                    value: matter_codec::Value::Uint(v),
                                } => command_id = Some(*v),
                                _ => {}
                            }
                        }
                        if let (Some(c), Some(cmd)) = (cluster_id, command_id) {
                            result.push((c, cmd));
                        }
                    }
                }
            }
        }
    }
    result
}

/// Decoded (cluster, attribute-or-command) targets for the IM messages the
/// aligner keys by content.
///
/// - `InvokeRequest` → (cluster, command) from each `CommandPathIB`
///   (delegates to [`invoke_targets`]).
/// - `InvokeResponse` → (cluster, response-command) from each
///   `InvokeResponseIB` (delegates to [`invoke_response_targets`]).
/// - `ReadRequest` / `ReportData` → (cluster, attribute) from every
///   `AttributePathIB` LIST in the tree (ctx-3 = cluster, ctx-4 = attribute;
///   either may be absent in wildcard paths → `None`).
fn im_targets(opcode: u8, tree: &[Node]) -> Vec<(Option<u64>, Option<u64>)> {
    if opcode == IM_OPCODE_INVOKE_REQUEST {
        return invoke_targets(tree)
            .into_iter()
            .map(|(c, m)| (Some(c), Some(m)))
            .collect();
    }
    if opcode == IM_OPCODE_INVOKE_RESPONSE {
        return invoke_response_targets(tree)
            .into_iter()
            .map(|(c, m)| (Some(c), Some(m)))
            .collect();
    }
    let mut out = Vec::new();
    collect_attribute_paths(tree, &mut out);
    out
}

/// Depth-first scan for `AttributePathIB` LISTs: any List whose children carry
/// a ctx-3 (cluster) or ctx-4 (attribute) uint is treated as one attribute
/// path. Traversal order is deterministic (document order), so two payloads
/// reading the same attributes in the same order produce equal target lists.
fn collect_attribute_paths(nodes: &[Node], out: &mut Vec<(Option<u64>, Option<u64>)>) {
    for node in nodes {
        let Node::Container { kind, children, .. } = node else {
            continue;
        };
        if *kind == ContainerKind::List {
            let mut cluster = None;
            let mut attribute = None;
            for child in children {
                match child {
                    Node::Scalar {
                        tag: Tag::Context(3),
                        value: matter_codec::Value::Uint(v),
                    } => cluster = Some(*v),
                    Node::Scalar {
                        tag: Tag::Context(4),
                        value: matter_codec::Value::Uint(v),
                    } => attribute = Some(*v),
                    _ => {}
                }
            }
            if cluster.is_some() || attribute.is_some() {
                out.push((cluster, attribute));
                continue; // an attribute-path list nests nothing of interest
            }
        }
        collect_attribute_paths(children, out);
    }
}

/// Find the index of the `CommissioningComplete` `InvokeResponse` in the trace.
///
/// Scans forward for a tx IM `InvokeRequest` whose decoded tree contains
/// (cluster 0x0030, command 0x04). From there, scans forward for the first
/// rx IM `InvokeResponse` and returns its index.
///
/// The comparison window is `[0, returned_index]` inclusive.
///
/// # Errors
///
/// - `"no CommissioningComplete (cluster 0x0030 cmd 0x04) invoke found — truncated trace"`
///   if no matching `InvokeRequest` is found.
/// - `"...: truncated trace"` if the `InvokeRequest` was found but no `InvokeResponse` followed.
pub(crate) fn commissioning_complete_end(trace: &[Annotated]) -> Result<usize, String> {
    let mut invoke_idx: Option<usize> = None;

    for (i, ann) in trace.iter().enumerate() {
        // "tx" / "rx" are the only legal values in the trace schema — both
        // capture sides (our commission_ip and the matter.js script) emit
        // exactly these lowercase ASCII literals. Anything else is a schema
        // violation that will fail safe: the string simply never matches,
        // leaving invoke_idx None and returning the truncated-trace error.
        if ann.record.dir == "tx"
            && ann.record.protocol == PROTO_INTERACTION_MODEL
            && ann.record.opcode == IM_OPCODE_INVOKE_REQUEST
        {
            // Try to decode payload and check if it carries CommissioningComplete.
            if let Ok(bytes) = hex::decode(&ann.record.payload) {
                if let Ok(tree) = parse_tree(&bytes) {
                    let targets = invoke_targets(&tree);
                    // Cluster 0x0030 = GeneralCommissioning, command 0x04 = CommissioningComplete
                    if targets.iter().any(|(c, cmd)| *c == 0x0030 && *cmd == 0x04) {
                        invoke_idx = Some(i);
                        break;
                    }
                }
            }
        }
    }

    let start = invoke_idx.ok_or_else(|| {
        "no CommissioningComplete (cluster 0x0030 cmd 0x04) invoke found — truncated trace"
            .to_string()
    })?;

    // Scan forward from start+1 for the first rx IM InvokeResponse.
    // "rx" is one of only two legal dir values in the schema (see "tx" note
    // above); a non-matching dir fails safe into the truncated-trace error.
    for (i, ann) in trace.iter().enumerate().skip(start + 1) {
        if ann.record.dir == "rx"
            && ann.record.protocol == PROTO_INTERACTION_MODEL
            && ann.record.opcode == IM_OPCODE_INVOKE_RESPONSE
        {
            return Ok(i);
        }
    }

    Err(format!(
        "CommissioningComplete invoke found at index {start} but no InvokeResponse followed — \
         truncated trace"
    ))
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run the trace-diff pipeline.
///
/// 1. Load both traces.
/// 2. Cut each at the `CommissioningComplete` `InvokeResponse` (inclusive).
/// 3. Align the windows.
/// 4. Compare each aligned pair, printing a verdict table.
/// 5. Return `Err` if any DIVERGENT or DECODE-FAIL verdicts were found.
///
/// # Errors
///
/// Returns a descriptive string on load failure, alignment failure, or if
/// any messages in the comparison window are DIVERGENT or DECODE-FAIL.
///
/// # Note on `protocol` field
///
/// The `protocol` field carries the 16-bit protocol short-id only. The
/// vendor-id portion is dropped by both capture sides (all commissioning
/// protocols are vendor 0x0000). A vendor-namespaced protocol would need
/// a trace schema extension.
#[allow(clippy::too_many_lines)] // Linear verdict-table printer — splitting obscures the flow.
pub(crate) fn run(ours: &Path, theirs: &Path) -> Result<(), String> {
    let ours_full = load_trace(ours)?;
    let theirs_full = load_trace(theirs)?;

    let ours_end = commissioning_complete_end(&ours_full).map_err(|e| format!("ours: {e}"))?;
    let theirs_end =
        commissioning_complete_end(&theirs_full).map_err(|e| format!("theirs: {e}"))?;

    let ours_window = &ours_full[..=ours_end];
    let theirs_window = &theirs_full[..=theirs_end];

    let ours_tail = ours_full.len() - ours_window.len();
    let theirs_tail = theirs_full.len() - theirs_window.len();
    if ours_tail > 0 || theirs_tail > 0 {
        println!(
            "ignored tail after CommissioningComplete: ours={ours_tail} theirs={theirs_tail} messages"
        );
    }

    let aligned = align(ours_window, theirs_window);

    let rule_table = rules();

    let mut n_match: usize = 0;
    let mut n_match_star: usize = 0;
    let mut n_divergent: usize = 0;
    let mut n_decode_fail: usize = 0;
    let mut n_theirs_only: usize = 0;
    let mut n_ours_only_allowed: usize = 0;
    let mut n_ours_only_unclassified: usize = 0;

    for (idx, pair) in aligned.iter().enumerate() {
        let (a, b) = match pair {
            AlignedPair::Matched(a, b) => (a, b),
            AlignedPair::TheirsOnly(b) => {
                // Reference-only message: matter.js's flow is richer than our
                // minimal driver (extra IM reads, SetRegulatoryConfig, ...).
                // Surfaced for triage; never compared, never a failure.
                n_theirs_only += 1;
                println!(
                    "[{idx:3}] {} | THEIRS-ONLY{}",
                    describe_row(b),
                    targets_str(b)
                );
                continue;
            }
            AlignedPair::OursOnly(a) => {
                // A message only WE send. Wrong by default unless the
                // allowlist documents why it is legitimate.
                if let Some(reason) = ours_only_allowed(a) {
                    n_ours_only_allowed += 1;
                    println!(
                        "[{idx:3}] {} | OURS-ONLY (allowed: {reason}){}",
                        describe_row(a),
                        targets_str(a)
                    );
                } else {
                    n_ours_only_unclassified += 1;
                    println!(
                        "[{idx:3}] {} | OURS-ONLY (UNCLASSIFIED){}",
                        describe_row(a),
                        targets_str(a)
                    );
                }
                continue;
            }
        };
        let proto = a.record.protocol;
        let op = a.record.opcode;
        let name = opcode_name(proto, op);
        let kind_str = match a.kind {
            SessionKind::Unsecured => "unsecured",
            SessionKind::Pase => "pase",
            SessionKind::Case => "case",
        };
        let verdict = compare_payload(proto, op, &a.record.payload, &b.record.payload, rule_table);

        match &verdict {
            Verdict::Match => {
                n_match += 1;
                println!(
                    "[{idx:3}] {} {} {} {} | MATCH",
                    a.record.dir,
                    kind_str,
                    name,
                    format_args!("proto={proto:#06x} op={op:#04x}")
                );
            }
            Verdict::MatchStar { classified } => {
                n_match_star += 1;
                println!(
                    "[{idx:3}] {} {} {} {} | MATCH* [{}]",
                    a.record.dir,
                    kind_str,
                    name,
                    format_args!("proto={proto:#06x} op={op:#04x}"),
                    classified.join(", ")
                );
            }
            Verdict::Divergent { diffs } => {
                n_divergent += 1;
                println!(
                    "[{idx:3}] {} {} {} {} | DIVERGENT",
                    a.record.dir,
                    kind_str,
                    name,
                    format_args!("proto={proto:#06x} op={op:#04x}")
                );
                for d in diffs {
                    println!("      diff: {d}");
                }
            }
            Verdict::DecodeFail { side, error } => {
                n_decode_fail += 1;
                println!(
                    "[{idx:3}] {} {} {} {} | DECODE-FAIL [{side}: {error}]",
                    a.record.dir,
                    kind_str,
                    name,
                    format_args!("proto={proto:#06x} op={op:#04x}")
                );
            }
        }
    }

    println!(
        "summary: {n_match} MATCH, {n_match_star} MATCH*, {n_divergent} DIVERGENT, {n_decode_fail} DECODE-FAIL, {n_theirs_only} THEIRS-ONLY, {n_ours_only_allowed} OURS-ONLY-allowed, {n_ours_only_unclassified} OURS-ONLY-unclassified"
    );

    if n_divergent > 0 || n_decode_fail > 0 || n_ours_only_unclassified > 0 {
        return Err(
            "divergences found — investigate before declaring success (CLAUDE.md: wrong by default)"
                .to_string(),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use matter_codec::{Tag, TlvWriter};

    fn rec(seq: u64, dir: &str, sid: u64, proto: u16, op: u8, payload: &str) -> String {
        format!(
            r#"{{"seq":{seq},"dir":"{dir}","session_id":{sid},"exchange":1,"protocol":{proto},"opcode":{op},"payload":"{payload}"}}"#
        )
    }

    #[test]
    fn loads_and_filters_acks() {
        let text = [
            rec(0, "tx", 0, 0, 0x20, "1518"),
            rec(1, "rx", 0, 0, 0x10, ""), // standalone ack — filtered
            rec(2, "rx", 0, 0, 0x21, "1518"),
        ]
        .join("\n");
        let t = load_trace_str(&text).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].record.opcode, 0x20);
        assert_eq!(t[1].record.opcode, 0x21);
    }

    #[test]
    fn session_kinds_inferred_by_first_seen_order() {
        let text = [
            rec(0, "tx", 0, 0, 0x20, "1518"),
            rec(1, "tx", 7, 1, 0x08, "1518"), // first nonzero → pase
            rec(2, "tx", 0, 0, 0x30, "1518"), // sigma1, unsecured
            rec(3, "tx", 12, 1, 0x08, "1518"), // second nonzero → case
        ]
        .join("\n");
        let t = load_trace_str(&text).unwrap();
        assert_eq!(t[0].kind, SessionKind::Unsecured);
        assert_eq!(t[1].kind, SessionKind::Pase);
        assert_eq!(t[2].kind, SessionKind::Unsecured);
        assert_eq!(t[3].kind, SessionKind::Case);
    }

    #[test]
    fn session_kinds_inferred_per_direction() {
        // matter.js codec-level captures carry the DESTINATION's session id
        // on tx and the local id on rx — two DIFFERENT numbers for one
        // logical PASE session (observed on the P110M first run). Each
        // direction's first-seen secured id must map to Pase, the next new
        // one to Case.
        let text = [
            rec(0, "tx", 0, 0, 0x20, "1518"),
            rec(1, "tx", 7, 1, 0x02, "1518"), // tx PASE (peer's id 7)
            rec(2, "rx", 9, 1, 0x05, "1518"), // rx PASE (their local id 9)
            rec(3, "tx", 12, 1, 0x08, "1518"), // tx CASE (peer's id 12)
            rec(4, "rx", 14, 1, 0x09, "1518"), // rx CASE (their local id 14)
        ]
        .join("\n");
        let t = load_trace_str(&text).unwrap();
        assert_eq!(t[1].kind, SessionKind::Pase);
        assert_eq!(t[2].kind, SessionKind::Pase);
        assert_eq!(t[3].kind, SessionKind::Case);
        assert_eq!(t[4].kind, SessionKind::Case);
    }

    #[test]
    fn align_skips_reference_only_messages_and_keys_invokes_by_target() {
        // theirs = [Invoke(SetRegulatoryConfig 0x30/0x02), its response,
        //           Invoke(AttestationRequest 0x3E/0x00)]
        // ours   = [Invoke(AttestationRequest 0x3E/0x00)]
        // The reference-only invoke must NOT pair with ours despite the
        // identical (kind, dir, protocol, opcode) — the (cluster, command)
        // part of the alignment key keeps them apart.
        let ours_text = rec(0, "tx", 5, 1, 0x08, &invoke_hex(0x3E, 0x00));
        let theirs_text = [
            rec(0, "tx", 7, 1, 0x08, &invoke_hex(0x30, 0x02)),
            rec(1, "rx", 9, 1, 0x09, &invoke_response_hex()),
            rec(2, "tx", 7, 1, 0x08, &invoke_hex(0x3E, 0x00)),
        ]
        .join("\n");
        let ours = load_trace_str(&ours_text).unwrap();
        let theirs = load_trace_str(&theirs_text).unwrap();
        let aligned = align(&ours, &theirs);
        assert_eq!(aligned.len(), 3);
        assert!(matches!(aligned[0], AlignedPair::TheirsOnly(_)));
        assert!(matches!(aligned[1], AlignedPair::TheirsOnly(_)));
        let AlignedPair::Matched(a, b) = &aligned[2] else {
            panic!("expected the attestation invokes to pair");
        };
        assert_eq!(a.record.payload, b.record.payload);

        // A message of OURS with no reference counterpart becomes OursOnly
        // (run() then fails it unless the allowlist classifies it). The
        // unmatched message comes first, so all reference messages follow
        // as theirs-only slots.
        let ours_unmatched =
            load_trace_str(&rec(0, "tx", 5, 1, 0x08, &invoke_hex(0x11, 0x01))).unwrap();
        let aligned = align(&ours_unmatched, &theirs);
        assert_eq!(aligned.len(), 4);
        let AlignedPair::OursOnly(a) = &aligned[0] else {
            panic!("expected OursOnly for the unmatched invoke");
        };
        // ...and an arbitrary invoke is not in the ours-only allowlist.
        assert!(ours_only_allowed(a).is_none());
    }

    #[test]
    fn ours_only_featuremap_probe_is_allowed() {
        // Our M6.5 NetworkCommissioning::FeatureMap read (cluster 0x31,
        // global attribute 0xFFFC) exists only in our trace and is the one
        // classified ours-only message; its ReportData counterpart shares
        // the classification via the report's attribute path.
        let read = {
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_array(Tag::Context(0)).unwrap(); // AttributePathIB array
            w.start_list(Tag::Anonymous).unwrap(); // AttributePathIB LIST
            w.put_uint(Tag::Context(2), 0).unwrap(); // endpoint
            w.put_uint(Tag::Context(3), 0x31).unwrap(); // cluster
            w.put_uint(Tag::Context(4), 0xFFFC).unwrap(); // attribute
            w.end_container().unwrap();
            w.end_container().unwrap();
            w.put_bool(Tag::Context(3), true).unwrap(); // fabricFiltered
            w.end_container().unwrap();
            hex::encode(&buf)
        };
        let ours = load_trace_str(&rec(0, "tx", 5, 1, 0x02, &read)).unwrap();
        assert!(ours_only_allowed(&ours[0]).is_some());

        // A read of anything else stays unclassified.
        let other = {
            let mut buf = Vec::new();
            let mut w = TlvWriter::new(&mut buf);
            w.start_structure(Tag::Anonymous).unwrap();
            w.start_array(Tag::Context(0)).unwrap();
            w.start_list(Tag::Anonymous).unwrap();
            w.put_uint(Tag::Context(3), 0x28).unwrap(); // BasicInformation
            w.put_uint(Tag::Context(4), 0x01).unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap();
            hex::encode(&buf)
        };
        let ours = load_trace_str(&rec(0, "tx", 5, 1, 0x02, &other)).unwrap();
        assert!(ours_only_allowed(&ours[0]).is_none());
    }

    #[test]
    fn alignment_pairs_equal_sequences_and_isolates_mismatches() {
        let a = [
            rec(0, "tx", 0, 0, 0x20, "1518"),
            rec(1, "rx", 0, 0, 0x21, "1518"),
        ]
        .join("\n");
        let b_ok = a.clone();
        let b_bad = [
            rec(0, "tx", 0, 0, 0x20, "1518"),
            rec(1, "rx", 0, 0, 0x40, "1518"), // StatusReport instead
        ]
        .join("\n");
        let ta = load_trace_str(&a).unwrap();
        let tb_ok = load_trace_str(&b_ok).unwrap();
        let ok = align(&ta, &tb_ok);
        assert!(ok.iter().all(|p| matches!(p, AlignedPair::Matched(..))));
        // The 0x21 response has no counterpart (theirs has 0x40 instead):
        // each side's unique message is isolated, the rest still pairs.
        let tb = load_trace_str(&b_bad).unwrap();
        let mixed = align(&ta, &tb);
        assert_eq!(mixed.len(), 3);
        assert!(matches!(mixed[0], AlignedPair::Matched(..)));
        assert!(matches!(mixed[1], AlignedPair::OursOnly(_)));
        assert!(matches!(mixed[2], AlignedPair::TheirsOnly(_)));
    }

    #[test]
    fn malformed_line_is_an_error() {
        assert!(load_trace_str("not json").is_err());
    }

    // -----------------------------------------------------------------------
    // TLV fixture helper
    // -----------------------------------------------------------------------

    /// Build: anonymous struct `{ ctx-1: bytes(random_bytes), ctx-2: uint(session_id) }`
    /// Matches the shape of `PBKDFParamRequest` for rules-testing purposes.
    fn tlv_struct(random_bytes: &[u8], session_id: u64) -> String {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bytes(Tag::Context(1), random_bytes).unwrap();
        w.put_uint(Tag::Context(2), session_id).unwrap();
        w.end_container().unwrap();
        hex::encode(&buf)
    }

    // -----------------------------------------------------------------------
    // compare_payload / Verdict tests
    // -----------------------------------------------------------------------

    #[test]
    fn identical_payloads_match() {
        let p = tlv_struct(&[0xaa; 32], 7);
        let v = compare_payload(0, 0x20, &p, &p, rules());
        assert!(matches!(v, Verdict::Match));
    }

    #[test]
    fn classified_random_field_gives_match_star() {
        // PBKDFParamRequest ctx-1 (initiatorRandom) is class Random:
        // same length, different bytes → MATCH*. ctx-2 differs too: RunSpecific.
        let a = tlv_struct(&[0xaa; 32], 7);
        let b = tlv_struct(&[0xbb; 32], 9);
        let v = compare_payload(0, 0x20, &a, &b, rules());
        assert!(
            matches!(v, Verdict::MatchStar { .. }),
            "expected MatchStar, got {v:?}"
        );
    }

    #[test]
    fn random_field_length_change_is_divergent() {
        let a = tlv_struct(&[0xaa; 32], 7);
        let b = tlv_struct(&[0xbb; 16], 7); // wrong length
        let v = compare_payload(0, 0x20, &a, &b, rules());
        assert!(
            matches!(v, Verdict::Divergent { .. }),
            "expected Divergent, got {v:?}"
        );
    }

    #[test]
    fn unclassified_difference_is_divergent() {
        // Same shape, differing bytes, on IM ReadRequest (proto=1, opcode=0x02):
        // no variance rules → default-exact means DIVERGENT.
        let a = tlv_struct(&[0xaa; 32], 7);
        let b = tlv_struct(&[0xbb; 32], 7);
        let v = compare_payload(1, 0x02, &a, &b, rules());
        assert!(
            matches!(v, Verdict::Divergent { .. }),
            "expected Divergent, got {v:?}"
        );
    }

    #[test]
    fn statusreport_is_raw_compared() {
        // StatusReport is NOT TLV: byte-equal → MATCH, else DIVERGENT.
        let v = compare_payload(0, 0x40, "0000000000000000", "0000000000000000", rules());
        assert!(matches!(v, Verdict::Match), "expected Match, got {v:?}");
        let v = compare_payload(0, 0x40, "0000000000000000", "0100000000000000", rules());
        assert!(
            matches!(v, Verdict::Divergent { .. }),
            "expected Divergent, got {v:?}"
        );
    }

    #[test]
    fn undecodable_tlv_is_decode_fail() {
        // 0xff is not a valid TLV control byte.
        let v = compare_payload(1, 0x08, "ff", "ff", rules());
        assert!(
            matches!(v, Verdict::DecodeFail { .. }),
            "expected DecodeFail, got {v:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Path sanity check: encode a PBKDFParamRequest-shaped struct and verify
    // that parse_tree produces nodes at the expected paths.
    // -----------------------------------------------------------------------

    #[test]
    fn parse_tree_path_sanity_pbkdf_param_request_shape() {
        // anonymous struct { ctx-1: bytes([0xaa; 32]), ctx-2: uint(7) }
        let hex = tlv_struct(&[0xaa; 32], 7);
        let bytes = hex::decode(&hex).unwrap();
        let tree = parse_tree(&bytes).unwrap();

        // Top-level: one anonymous Structure node.
        assert_eq!(tree.len(), 1, "expected one top-level node");
        let Node::Container {
            tag: Tag::Anonymous,
            kind: ContainerKind::Structure,
            ref children,
        } = tree[0]
        else {
            panic!("expected anonymous structure at root, got {:?}", tree[0]);
        };
        // Path of top node is "[]" (join_path("", &Tag::Anonymous)).

        // ctx-1 child → path "[]/1"
        let Node::Scalar {
            tag: Tag::Context(1),
            value: matter_codec::Value::Bytes(ref b),
        } = children[0]
        else {
            panic!("expected ctx-1 bytes, got {:?}", children[0]);
        };
        assert_eq!(b.len(), 32);

        // ctx-2 child → path "[]/2"
        let Node::Scalar {
            tag: Tag::Context(2),
            value: matter_codec::Value::Uint(v),
        } = children[1]
        else {
            panic!("expected ctx-2 uint, got {:?}", children[1]);
        };
        assert_eq!(v, 7);
    }

    // -----------------------------------------------------------------------
    // commissioning_complete_end + run() level tests
    // -----------------------------------------------------------------------

    /// Build the `InvokeRequest` payload for `CommissioningComplete` (cluster 0x0030, cmd 0x04).
    ///
    /// Structure:
    /// ```
    /// anon struct {
    ///   ctx-0: bool (suppressResponse = false)
    ///   ctx-1: bool (timedRequest = false)
    ///   ctx-2: array [
    ///     anon struct {
    ///       ctx-0: LIST {
    ///         ctx-0: uint endpoint=0
    ///         ctx-1: uint cluster=0x30
    ///         ctx-2: uint command=0x04
    ///       }
    ///       ctx-1: struct {}  (empty fields)
    ///     }
    ///   ]
    /// }
    /// ```
    fn commissioning_complete_invoke_hex() -> String {
        invoke_hex(0x30, 0x04)
    }

    /// Build a single-command `InvokeRequest` payload targeting
    /// (`cluster`, `command`) on endpoint 0, with empty command fields.
    fn invoke_hex(cluster: u64, command: u64) -> String {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap(); // outer anon struct
        w.put_bool(Tag::Context(0), false).unwrap(); // suppressResponse
        w.put_bool(Tag::Context(1), false).unwrap(); // timedRequest
        w.start_array(Tag::Context(2)).unwrap(); // CommandDataIB array
        w.start_structure(Tag::Anonymous).unwrap(); // CommandDataIB entry
        w.start_list(Tag::Context(0)).unwrap(); // CommandPathIB LIST
        w.put_uint(Tag::Context(0), 0).unwrap(); // endpointId
        w.put_uint(Tag::Context(1), cluster).unwrap(); // clusterId
        w.put_uint(Tag::Context(2), command).unwrap(); // commandId
        w.end_container().unwrap(); // end LIST
        w.start_structure(Tag::Context(1)).unwrap(); // command fields (empty)
        w.end_container().unwrap(); // end fields struct
        w.end_container().unwrap(); // end CommandDataIB entry struct
        w.end_container().unwrap(); // end CommandDataIB array
        w.end_container().unwrap(); // end outer struct
        hex::encode(&buf)
    }

    /// Build a minimal `InvokeResponse` payload (one `InvokeResponseIB` with
    /// status SUCCESS).
    fn invoke_response_hex() -> String {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        // ctx-0: suppressResponse
        w.put_bool(Tag::Context(0), false).unwrap();
        // ctx-1: array of InvokeResponseIBs (we use empty array for simplicity)
        w.start_array(Tag::Context(1)).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        hex::encode(&buf)
    }

    /// Write a minimal valid trace to a temp file with:
    ///   1. `PBKDFParamRequest` tx (unsecured)
    ///   2. `PBKDFParamResponse` rx (unsecured)
    ///   3. `CommissioningComplete` `InvokeRequest` tx (CASE session)
    ///   4. `InvokeResponse` rx (CASE session)
    fn write_synthetic_trace(path: &std::path::Path, case_session_id: u64) {
        let pbkdf_req = tlv_struct(&[0xaa; 32], 1);
        let pbkdf_resp = tlv_struct(&[0xbb; 32], 2);
        let invoke_req = commissioning_complete_invoke_hex();
        let invoke_resp = invoke_response_hex();

        let lines = [
            rec(
                0,
                "tx",
                0,
                PROTO_SECURE_CHANNEL,
                SC_PBKDF_PARAM_REQUEST,
                &pbkdf_req,
            ),
            rec(
                1,
                "rx",
                0,
                PROTO_SECURE_CHANNEL,
                SC_PBKDF_PARAM_RESPONSE,
                &pbkdf_resp,
            ),
            rec(
                2,
                "tx",
                case_session_id,
                PROTO_INTERACTION_MODEL,
                IM_OPCODE_INVOKE_REQUEST,
                &invoke_req,
            ),
            rec(
                3,
                "rx",
                case_session_id,
                PROTO_INTERACTION_MODEL,
                IM_OPCODE_INVOKE_RESPONSE,
                &invoke_resp,
            ),
        ]
        .join("\n");

        std::fs::write(path, lines).unwrap();
    }

    #[test]
    fn run_succeeds_on_identical_synthetic_dialogues() {
        let dir = std::env::temp_dir();
        let ours_path = dir.join("trace_diff_test_ours_identical.jsonl");
        let theirs_path = dir.join("trace_diff_test_theirs_identical.jsonl");
        write_synthetic_trace(&ours_path, 42);
        write_synthetic_trace(&theirs_path, 42);
        let result = run(&ours_path, &theirs_path);
        assert!(result.is_ok(), "run failed: {result:?}");
    }

    #[test]
    fn run_fails_when_no_commissioning_complete() {
        let dir = std::env::temp_dir();
        let path_a = dir.join("trace_diff_test_no_cc_a.jsonl");
        let path_b = dir.join("trace_diff_test_no_cc_b.jsonl");

        // Trace without CommissioningComplete invoke.
        let pbkdf_req = tlv_struct(&[0xaa; 32], 1);
        let pbkdf_resp = tlv_struct(&[0xbb; 32], 2);
        let lines = [
            rec(
                0,
                "tx",
                0,
                PROTO_SECURE_CHANNEL,
                SC_PBKDF_PARAM_REQUEST,
                &pbkdf_req,
            ),
            rec(
                1,
                "rx",
                0,
                PROTO_SECURE_CHANNEL,
                SC_PBKDF_PARAM_RESPONSE,
                &pbkdf_resp,
            ),
        ]
        .join("\n");
        std::fs::write(&path_a, &lines).unwrap();
        std::fs::write(&path_b, &lines).unwrap();

        let result = run(&path_a, &path_b);
        assert!(result.is_err(), "expected Err for truncated trace");
        let err = result.unwrap_err();
        assert!(
            err.contains("truncated") || err.contains("no CommissioningComplete"),
            "error message should mention truncated or no CommissioningComplete: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Item 4: run() returns Err("divergences found") when an UNCLASSIFIED
    // field differs between the two traces.
    //
    // We build two otherwise-identical dialogues but give the InvokeResponse
    // a different uint value in one trace. The InvokeResponse payload uses a
    // context-99 uint child that has no variance rule, so compare_payload
    // produces Divergent — and run() must propagate that as Err.
    // -----------------------------------------------------------------------

    /// Build an `InvokeResponse` payload with an extra context-99 uint field
    /// that has no variance rule. Varying this field across traces produces an
    /// UNCLASSIFIED diff → DIVERGENT verdict.
    fn invoke_response_with_extra_uint_hex(extra: u64) -> String {
        let mut buf = Vec::new();
        let mut w = TlvWriter::new(&mut buf);
        w.start_structure(Tag::Anonymous).unwrap();
        w.put_bool(Tag::Context(0), false).unwrap(); // suppressResponse
        w.start_array(Tag::Context(1)).unwrap(); // InvokeResponseIBs (empty)
        w.end_container().unwrap();
        // ctx-99: a vendor-specific uint with no variance rule — any difference
        // here must be caught as DIVERGENT.
        w.put_uint(Tag::Context(99), extra).unwrap();
        w.end_container().unwrap();
        hex::encode(&buf)
    }

    /// Write a synthetic trace whose `InvokeResponse` carries a custom uint
    /// value in an unclassified field.
    fn write_synthetic_trace_with_invoke_resp_uint(
        path: &std::path::Path,
        case_session_id: u64,
        invoke_resp_extra_uint: u64,
    ) {
        let pbkdf_req = tlv_struct(&[0xaa; 32], 1);
        let pbkdf_resp = tlv_struct(&[0xbb; 32], 2);
        let invoke_req = commissioning_complete_invoke_hex();
        let invoke_resp = invoke_response_with_extra_uint_hex(invoke_resp_extra_uint);

        let lines = [
            rec(
                0,
                "tx",
                0,
                PROTO_SECURE_CHANNEL,
                SC_PBKDF_PARAM_REQUEST,
                &pbkdf_req,
            ),
            rec(
                1,
                "rx",
                0,
                PROTO_SECURE_CHANNEL,
                SC_PBKDF_PARAM_RESPONSE,
                &pbkdf_resp,
            ),
            rec(
                2,
                "tx",
                case_session_id,
                PROTO_INTERACTION_MODEL,
                IM_OPCODE_INVOKE_REQUEST,
                &invoke_req,
            ),
            rec(
                3,
                "rx",
                case_session_id,
                PROTO_INTERACTION_MODEL,
                IM_OPCODE_INVOKE_RESPONSE,
                &invoke_resp,
            ),
        ]
        .join("\n");

        std::fs::write(path, lines).unwrap();
    }

    #[test]
    fn run_returns_err_divergent_when_unclassified_field_differs() {
        let dir = std::env::temp_dir();
        let ours_path = dir.join("trace_diff_test_divergent_ours.jsonl");
        let theirs_path = dir.join("trace_diff_test_divergent_theirs.jsonl");

        // Both traces have the same structure; only the unclassified ctx-99
        // uint in the InvokeResponse differs (1 vs 2).
        write_synthetic_trace_with_invoke_resp_uint(&ours_path, 42, 1);
        write_synthetic_trace_with_invoke_resp_uint(&theirs_path, 42, 2);

        let result = run(&ours_path, &theirs_path);
        assert!(
            result.is_err(),
            "expected Err for DIVERGENT unclassified field"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("divergences found"),
            "error should say 'divergences found': {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Item 5a: run() returns Ok when a CLASSIFIED-variance field differs.
    //
    // PBKDFParamRequest ctx-1 (initiatorRandom) is class Random: same length,
    // different bytes → MATCH* verdict. run() must succeed (Ok).
    //
    // Item 5b: run() returns Ok when one trace has extra messages AFTER the
    // CommissioningComplete InvokeResponse (tail is ignored).
    //
    // Combined into one test for brevity.
    // -----------------------------------------------------------------------

    /// Write a synthetic trace like `write_synthetic_trace` but with:
    /// - a distinct random value in the `PBKDFParamRequest` (different bytes,
    ///   same length → classified Random variance → MATCH*)
    /// - optional extra messages appended after the `InvokeResponse` (ignored tail)
    fn write_synthetic_trace_with_classified_variance_and_tail(
        path: &std::path::Path,
        case_session_id: u64,
        pbkdf_random_byte: u8,
        extra_tail_messages: usize,
    ) {
        let pbkdf_req = tlv_struct(&[pbkdf_random_byte; 32], 1);
        let pbkdf_resp = tlv_struct(&[0xbb; 32], 2);
        let invoke_req = commissioning_complete_invoke_hex();
        let invoke_resp = invoke_response_hex();

        let mut records = vec![
            rec(
                0,
                "tx",
                0,
                PROTO_SECURE_CHANNEL,
                SC_PBKDF_PARAM_REQUEST,
                &pbkdf_req,
            ),
            rec(
                1,
                "rx",
                0,
                PROTO_SECURE_CHANNEL,
                SC_PBKDF_PARAM_RESPONSE,
                &pbkdf_resp,
            ),
            rec(
                2,
                "tx",
                case_session_id,
                PROTO_INTERACTION_MODEL,
                IM_OPCODE_INVOKE_REQUEST,
                &invoke_req,
            ),
            rec(
                3,
                "rx",
                case_session_id,
                PROTO_INTERACTION_MODEL,
                IM_OPCODE_INVOKE_RESPONSE,
                &invoke_resp,
            ),
        ];

        // Append extra IM ReadRequest messages after CommissioningComplete as
        // an ignored tail (seq 4, 5, …). The dir "tx" and opcode 0x02
        // (IM ReadRequest) do not match the CommissioningComplete window
        // sentinel, so commissioning_complete_end returns the InvokeResponse
        // index and the tail is silently dropped.
        for i in 0..extra_tail_messages {
            records.push(rec(
                (4 + i) as u64,
                "tx",
                case_session_id,
                PROTO_INTERACTION_MODEL,
                0x02, // IM ReadRequest
                "1518",
            ));
        }

        std::fs::write(path, records.join("\n")).unwrap();
    }

    #[test]
    fn run_succeeds_with_classified_variance_and_ignored_tail() {
        let dir = std::env::temp_dir();
        let ours_path = dir.join("trace_diff_test_matchstar_ours.jsonl");
        let theirs_path = dir.join("trace_diff_test_matchstar_theirs.jsonl");

        // 5a: PBKDFParamRequest random bytes differ (0xaa vs 0xcc, same 32-byte
        //     length) → MATCH* verdict; run() must still return Ok.
        // 5b: "ours" has 2 extra messages after the InvokeResponse; they are
        //     outside the CommissioningComplete window and must be ignored.
        write_synthetic_trace_with_classified_variance_and_tail(&ours_path, 42, 0xaa, 2);
        write_synthetic_trace_with_classified_variance_and_tail(&theirs_path, 42, 0xcc, 0);

        let result = run(&ours_path, &theirs_path);
        assert!(
            result.is_ok(),
            "expected Ok for classified-variance + ignored tail, got: {result:?}"
        );
    }
}
