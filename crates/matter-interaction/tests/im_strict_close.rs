//! Every top-level IM parser requires one complete message and nothing more.
//!
//! chip parses every Interaction Model message through
//! `MessageParser::ExitContainer` (`src/app/MessageDef/MessageParser.cpp`,
//! master 5cd2917a and v1.4.2.0). It fails when end of input comes before the
//! top-level end-of-container, and when anything follows that
//! end-of-container. Our parsers used to treat end of input as the close and
//! ignore trailing bytes. So a truncated `ReportData` that had lost its
//! trailing `MoreChunkedMessages = true` decoded as the final chunk, and a
//! chunked read silently returned partial data.
//!
//! The inputs are the matter.js-captured messages under
//! `test-vectors/commissioning/im/`, so real wire bytes are exercised, not
//! just our own builders. For each message and each parser:
//!
//! - the full message parses;
//! - every strict prefix is rejected, which covers a missing final
//!   end-of-container and truncation inside every nested container;
//! - the message followed by trailing bytes is rejected.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)] // Test-code carve-out: see CLAUDE.md.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use matter_interaction::{
    build_invoke_request, build_invoke_response_command, build_invoke_response_status,
    parse_invoke_request, parse_invoke_response, parse_invoke_response_batch, parse_report_data,
    parse_status_response, parse_subscribe_response, parse_write_response, CommandPath, ImStatus,
};
use std::path::PathBuf;

/// Trailing data of several shapes: a single zero byte, a complete anonymous
/// uint8 element, a second empty message, a stray end-of-container, and a
/// byte that is not valid TLV at all.
const SUFFIXES: &[&[u8]] = &[&[0x00], &[0x04, 0x00], &[0x15, 0x18], &[0x18], &[0xFF]];

/// Load `test-vectors/commissioning/im/<rel>` and base64-decode field `key`.
/// The fixtures are committed, so a missing one is a test failure, not a skip.
fn fixture(rel: &str, key: &str) -> Vec<u8> {
    let mut p: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    p.extend(["..", "..", "test-vectors", "commissioning", "im"]);
    p.push(rel);
    let json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
    )
    .unwrap();
    B64.decode(
        json[key]
            .as_str()
            .unwrap_or_else(|| panic!("{rel}: no {key}")),
    )
    .unwrap()
}

/// Every message in a fixture's `chunks_b64` array.
fn fixture_chunks(rel: &str) -> Vec<Vec<u8>> {
    let mut p: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    p.extend(["..", "..", "test-vectors", "commissioning", "im"]);
    p.push(rel);
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    json["chunks_b64"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| B64.decode(c.as_str().unwrap()).unwrap())
        .collect()
}

/// The property under test, for one message and one parser.
fn assert_strict(name: &str, full: &[u8], accepts: impl Fn(&[u8]) -> bool) {
    assert!(accepts(full), "{name}: the full message must parse");
    for suffix in SUFFIXES {
        let mut tailed = full.to_vec();
        tailed.extend_from_slice(suffix);
        assert!(
            !accepts(&tailed),
            "{name}: accepted with trailing bytes {suffix:02x?}"
        );
    }
    for n in 0..full.len() {
        assert!(
            !accepts(&full[..n]),
            "{name}: prefix of {n} / {} bytes accepted (truncated message)",
            full.len()
        );
    }
}

#[test]
fn parse_report_data_is_strict() {
    for (name, msg) in [
        (
            "report_data_event",
            fixture("report/report_data_event.json", "response_message_b64"),
        ),
        (
            "report_data_subscribed",
            fixture(
                "subscribe/report_data_subscribed.json",
                "response_message_b64",
            ),
        ),
    ] {
        assert_strict(name, &msg, |b| parse_report_data(b).is_ok());
    }
    for rel in [
        "report/report_data_chunked_list.json",
        "report/report_data_chunked_message.json",
    ] {
        for (i, chunk) in fixture_chunks(rel).iter().enumerate() {
            assert_strict(&format!("{rel} chunk {i}"), chunk, |b| {
                parse_report_data(b).is_ok()
            });
        }
    }
}

/// The review's motivating case: a non-final chunk cut just before its
/// end-of-container must not decode as a final chunk.
#[test]
fn a_truncated_non_final_chunk_is_not_read_as_the_last() {
    let chunks = fixture_chunks("report/report_data_chunked_message.json");
    let first = &chunks[0];
    assert!(parse_report_data(first).unwrap().more_chunked_messages);
    assert!(parse_report_data(&first[..first.len() - 1]).is_err());
    // The bare struct header the review found accepted as an empty report.
    assert!(parse_report_data(&[0x15]).is_err());
}

#[test]
fn parse_subscribe_response_is_strict() {
    let msg = fixture("subscribe/subscribe_response.json", "response_message_b64");
    assert_strict("subscribe_response", &msg, |b| {
        parse_subscribe_response(b).is_ok()
    });
}

#[test]
fn parse_status_response_is_strict() {
    for (name, msg) in [
        (
            "status_response_success",
            fixture(
                "subscribe/status_response_success.json",
                "expected_message_b64",
            ),
        ),
        (
            "status_needs_timed",
            fixture("timed/status_needs_timed.json", "response_message_b64"),
        ),
    ] {
        assert_strict(name, &msg, |b| {
            matches!(parse_status_response(b), Ok(Some(_)))
        });
    }
}

/// `Ok(None)` ("not a bare status response") is also a successful parse, so
/// it too requires a complete message.
#[test]
fn parse_status_response_none_is_strict() {
    let msg = fixture("write/node_label_response.json", "response_message_b64");
    assert_strict("write response as status", &msg, |b| {
        matches!(parse_status_response(b), Ok(None))
    });
}

#[test]
fn parse_write_response_is_strict() {
    for rel in [
        "write/node_label_response.json",
        "write/mixed_status_response.json",
    ] {
        let msg = fixture(rel, "response_message_b64");
        assert_strict(rel, &msg, |b| parse_write_response(b).is_ok());
    }
}

#[test]
fn parse_invoke_response_batch_is_strict() {
    let msg = fixture("invoke/batch_response.json", "response_message_b64");
    assert_strict("batch_response", &msg, |b| {
        parse_invoke_response_batch(b).is_ok()
    });
}

/// The single-command parser returns after the first `InvokeResponseIB`. It
/// still has to validate the rest of the message.
#[test]
fn parse_invoke_response_is_strict() {
    let path = CommandPath {
        endpoint: 1,
        cluster: 0x0006,
        command: 0x01,
    };
    for (name, msg) in [
        (
            "batch_response",
            fixture("invoke/batch_response.json", "response_message_b64"),
        ),
        (
            "command",
            build_invoke_response_command(path, &[0x15, 0x24, 0x00, 0x07, 0x18]),
        ),
        (
            "status",
            build_invoke_response_status(path, ImStatus::Success),
        ),
    ] {
        assert_strict(name, &msg, |b| parse_invoke_response(b).is_ok());
    }
}

#[test]
fn parse_invoke_request_is_strict() {
    for rel in [
        "invoke/arm_fail_safe.json",
        "invoke/commissioning_complete.json",
        "invoke/on_off_toggle.json",
        "invoke/batch_request.json",
        "timed/invoke_request_timed.json",
    ] {
        let msg = fixture(rel, "expected_message_b64");
        assert_strict(rel, &msg, |b| parse_invoke_request(b).is_ok());
    }
    let built = build_invoke_request(
        CommandPath {
            endpoint: 0,
            cluster: 0x0029,
            command: 0x00,
        },
        &[0x15, 0x24, 0x00, 0x01, 0x18],
    );
    assert_strict("built", &built, |b| parse_invoke_request(b).is_ok());
}

/// A fixture (path, base64 key) and the parser that must accept it.
type Case = (&'static str, &'static str, fn(&[u8]) -> bool);

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// Any non-empty suffix after a complete message is rejected by every
    /// parser that accepts the message, whatever the suffix bytes are
    /// (`SUFFIXES` above is a hand-picked sample).
    #[test]
    fn any_trailing_suffix_is_rejected(
        suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=16),
    ) {
        let cases: [Case; 6] = [
            ("report/report_data_event.json", "response_message_b64", |b| parse_report_data(b).is_ok()),
            ("subscribe/subscribe_response.json", "response_message_b64", |b| parse_subscribe_response(b).is_ok()),
            ("subscribe/status_response_success.json", "expected_message_b64", |b| parse_status_response(b).is_ok()),
            ("write/mixed_status_response.json", "response_message_b64", |b| parse_write_response(b).is_ok()),
            ("invoke/batch_response.json", "response_message_b64", |b| parse_invoke_response(b).is_ok() || parse_invoke_response_batch(b).is_ok()),
            ("invoke/batch_request.json", "expected_message_b64", |b| parse_invoke_request(b).is_ok()),
        ];
        for (rel, key, accepts) in cases {
            let mut msg = fixture(rel, key);
            proptest::prop_assert!(accepts(&msg), "{} must parse", rel);
            msg.extend_from_slice(&suffix);
            proptest::prop_assert!(!accepts(&msg), "{} accepted with suffix {:02x?}", rel, suffix);
        }
    }
}
