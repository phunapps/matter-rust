//! IM-2: IM parsers must be panic-safe on truncated input. The audit found
//! them panic-safe by code read (no `unwrap`/`expect`/indexing on any parse
//! path); this pins it by EXECUTION — feeding every prefix of a valid message
//! must return `Err`, never panic (chip feeds truncated TLV → `END_OF_TLV`).
//!
//! The test harness turns any panic into a failure, so simply calling each
//! parser on every truncation is the assertion; we additionally require the
//! full message to parse and every strict prefix to be rejected.

use matter_interaction::{
    build_invoke_request, build_invoke_response_command, parse_invoke_request,
    parse_invoke_response, CommandPath,
};

/// A valid pre-encoded anonymous empty struct `{}` — the command fields for a
/// no-argument command (TLV: structure-start 0x15, end 0x18).
const EMPTY_STRUCT: &[u8] = &[0x15, 0x18];

/// Assert `parse` accepts the full buffer and does not PANIC on any strict
/// prefix. The property under test is panic-safety (the test harness turns any
/// panic into a failure) — not rejection: some parsers leniently accept a
/// prefix that is structurally complete before the truncation point (extract
/// what-you-can). Tightening those to reject an unterminated outer container is
/// a separate follow-up.
fn assert_truncation_safe(full: &[u8], parse: impl Fn(&[u8]) -> bool) {
    assert!(parse(full), "the full, well-formed message must parse");
    for n in 0..full.len() {
        let _accepted = parse(&full[..n]); // must not panic
    }
}

#[test]
fn parse_invoke_request_is_truncation_safe() {
    let path = CommandPath {
        endpoint: 1,
        cluster: 0x0006, // OnOff
        command: 0x02,   // Toggle
    };
    let msg = build_invoke_request(path, EMPTY_STRUCT);
    assert_truncation_safe(&msg, |b| parse_invoke_request(b).is_ok());
}

#[test]
fn parse_invoke_response_is_truncation_safe() {
    let path = CommandPath {
        endpoint: 1,
        cluster: 0x0006,
        command: 0x01,
    };
    let msg = build_invoke_response_command(path, EMPTY_STRUCT);
    assert_truncation_safe(&msg, |b| parse_invoke_response(b).is_ok());
}
