//! `xtask trace-diff` — structural comparison of two decrypted
//! commissioning dialogues (ours vs matter.js). M6 cross-verification.
//!
//! Input: two JSON-lines files produced by `commission_ip --trace-out`
//! and `xtask/scripts/capture-commission-trace/`. Output: a per-message
//! verdict table (MATCH / MATCH* / DIVERGENT / DECODE-FAIL). Exit
//! nonzero unless every aligned message is MATCH or MATCH*.

#![forbid(unsafe_code)]
// xtask is build tooling, not library code; the CLAUDE.md no-unwrap
// rule is for library code only. The existing capture-* modules apply
// the same allow.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;

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

/// Parse a JSONL trace: drop MRP standalone acks, annotate session kinds.
///
/// # Errors
///
/// Returns a descriptive string if any line is not a valid
/// [`TraceRecord`] JSON object.
pub(crate) fn load_trace_str(text: &str) -> Result<Vec<Annotated>, String> {
    let mut out = Vec::new();
    let mut seen_secured: Vec<u64> = Vec::new();
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
            if !seen_secured.contains(&record.session_id) {
                seen_secured.push(record.session_id);
            }
            match seen_secured.iter().position(|s| *s == record.session_id) {
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

/// Verify both traces walk the same (kind, dir, protocol, opcode) sequence.
///
/// On mismatch, reports the first divergence with ±3 messages of context.
///
/// # Errors
///
/// Returns a descriptive string describing the first divergence (including
/// ±3-message context) if the traces do not align, or if they differ in
/// length after filtering.
pub(crate) fn align<'a>(
    ours: &'a [Annotated],
    theirs: &'a [Annotated],
) -> Result<Vec<(&'a Annotated, &'a Annotated)>, String> {
    let n = ours.len().min(theirs.len());
    for i in 0..n {
        let (a, b) = (&ours[i], &theirs[i]);
        let ka = (
            a.kind,
            a.record.dir.as_str(),
            a.record.protocol,
            a.record.opcode,
        );
        let kb = (
            b.kind,
            b.record.dir.as_str(),
            b.record.protocol,
            b.record.opcode,
        );
        if ka != kb {
            return Err(format!(
                "sequence diverges at aligned index {i}:\n  ours:   {}\n  theirs: {}\n{}",
                describe(a),
                describe(b),
                context(ours, theirs, i),
            ));
        }
    }
    if ours.len() != theirs.len() {
        // Length mismatch inside the comparison window (the caller cuts both
        // traces at CommissioningComplete in Task 7) means one dialogue truly
        // has extra messages.
        return Err(format!(
            "trace lengths differ inside the comparison window: ours={} theirs={}\n{}",
            ours.len(),
            theirs.len(),
            context(ours, theirs, n),
        ));
    }
    Ok(ours.iter().zip(theirs.iter()).collect())
}

fn describe(a: &Annotated) -> String {
    format!(
        "seq={} {} {:?} proto={} opcode={:#04x} ({})",
        a.record.seq,
        a.record.dir,
        a.kind,
        a.record.protocol,
        a.record.opcode,
        opcode_name(a.record.protocol, a.record.opcode),
    )
}

/// ±3 messages of context around index `i` from both traces.
fn context(ours: &[Annotated], theirs: &[Annotated], i: usize) -> String {
    let mut s = String::from("context (ours | theirs):\n");
    let lo = i.saturating_sub(3);
    for j in lo..(i + 4) {
        let l = ours.get(j).map_or_else(|| "—".into(), describe);
        let r = theirs.get(j).map_or_else(|| "—".into(), describe);
        let _ = writeln!(s, "  [{j}] {l}  |  {r}");
    }
    s
}

/// Temporary entry point — loads both traces, aligns them, and prints a
/// summary. Task 7 replaces this with the full verdict pipeline.
///
/// # Errors
///
/// Returns a descriptive string if either trace fails to load, or if
/// the sequences do not align.
pub(crate) fn run(ours: &Path, theirs: &Path) -> Result<(), String> {
    let ours_trace = load_trace(ours)?;
    let theirs_trace = load_trace(theirs)?;
    let aligned = align(&ours_trace, &theirs_trace)?;
    println!("alignment OK ({} messages)", aligned.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn alignment_passes_on_equal_sequences_and_reports_first_mismatch() {
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
        assert!(align(&ta, &load_trace_str(&b_ok).unwrap()).is_ok());
        let err = align(&ta, &load_trace_str(&b_bad).unwrap()).unwrap_err();
        assert!(err.contains("0x21") && err.contains("0x40"), "{err}");
    }

    #[test]
    fn malformed_line_is_an_error() {
        assert!(load_trace_str("not json").is_err());
    }
}
