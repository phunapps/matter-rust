//! Ties `matter-controller`'s string-secret path table to the cluster dump.
//!
//! `InvokeResult`'s hand-written `Debug` (`crates/matter-controller/src/node.rs`)
//! hides byte strings everywhere, but it can hide a *string* only by the
//! response it arrived in: its private `STRING_SECRET_RESPONSES` table lists
//! `(cluster id, response command id)` pairs. The source of truth for which
//! fields are secret is the dump's `SECRET_FIELDS`, which marks each field
//! `secret: true` in `xtask/model/clusters.json`. This test checks the two
//! agree: every string-typed secret in a response command has its row, and
//! every row is such a response. A secret added to `SECRET_FIELDS` without a
//! row (or a mistyped id) fails here, not in a log.
//!
//! The table's ids are literals so the controller builds against every
//! `matter-clusters` release it supports, which is why the tie lives here
//! (xtask is unpublished) and reads the table from source instead of
//! importing it: nothing in matter-controller's public API changes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// The name of the table in `node.rs`.
const TABLE: &str = "const STRING_SECRET_RESPONSES";

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Parse one `0x…` (or decimal) integer literal.
fn int(literal: &str) -> u32 {
    let literal = literal.trim();
    match literal
        .strip_prefix("0x")
        .or_else(|| literal.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => literal.parse(),
    }
    .unwrap_or_else(|e| panic!("not an integer literal {literal:?}: {e}"))
}

/// The `(cluster, command)` rows of `STRING_SECRET_RESPONSES`, read from
/// `node.rs`'s source: the text between the declaration and its `];`, with
/// `//` comments stripped, one `(a, b)` tuple per row. The declared length
/// (`[(u32, u32); N]`) must equal the number of rows parsed, so a row the
/// parser misses fails rather than passing silently.
fn controller_table(source: &str) -> BTreeSet<(u32, u32)> {
    let start = source
        .find(TABLE)
        .unwrap_or_else(|| panic!("{TABLE} not found in node.rs"));
    let decl = &source[start..];
    let declared: usize = {
        let semi = decl.find(';').expect("the array type's `; N]`");
        let close = decl[semi..].find(']').expect("the array type's `]`") + semi;
        decl[semi + 1..close]
            .trim()
            .parse()
            .expect("the declared length")
    };
    let body_start = decl.find("= [").expect("the table's `= [`") + 3;
    let body_end = decl[body_start..].find("];").expect("the table's `];`") + body_start;

    let mut rows = Vec::new();
    for line in decl[body_start..body_end].lines() {
        let code = line.split("//").next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }
        let inner = code
            .strip_prefix('(')
            .and_then(|c| c.strip_suffix("),"))
            .unwrap_or_else(|| panic!("unexpected table line {code:?}"));
        let (cluster, command) = inner
            .split_once(',')
            .unwrap_or_else(|| panic!("unexpected table row {code:?}"));
        rows.push((int(cluster), int(command)));
    }
    assert_eq!(
        rows.len(),
        declared,
        "parsed {} rows but the table declares {declared}",
        rows.len()
    );
    let set: BTreeSet<_> = rows.iter().copied().collect();
    assert_eq!(set.len(), rows.len(), "a duplicate row in the table");
    set
}

/// Every string-typed secret field in a response command, as
/// `(cluster id, response command id)`. A string secret anywhere else (a
/// request, an event, a struct) has no row to map to, so it fails here with
/// a pointer to extend the table and this test.
fn string_secret_responses(model: &Value) -> BTreeSet<(u32, u32)> {
    let mut found = BTreeSet::new();
    for cluster in model["clusters"].as_array().expect("clusters array") {
        let cluster_id = u32::try_from(cluster["id"].as_u64().expect("cluster id")).unwrap();
        for key in ["commands", "events", "datatypes"] {
            for element in cluster[key].as_array().into_iter().flatten() {
                for field in element["fields"].as_array().into_iter().flatten() {
                    if field["secret"] != true || field["metatype"] != "string" {
                        continue;
                    }
                    let what = format!(
                        "{}.{}.{}",
                        cluster["name"].as_str().unwrap(),
                        element["name"].as_str().unwrap(),
                        field["name"].as_str().unwrap()
                    );
                    assert!(
                        key == "commands" && element["direction"] == "response",
                        "{what} is a string secret outside a response command: \
                         InvokeResult's path table cannot reach it; extend the \
                         table's design and this test"
                    );
                    let command_id =
                        u32::try_from(element["id"].as_u64().expect("command id")).unwrap();
                    found.insert((cluster_id, command_id));
                }
            }
        }
    }
    found
}

#[test]
fn controller_table_covers_every_string_secret_response() {
    let model: Value =
        serde_json::from_str(&read("model/clusters.json")).expect("clusters.json is JSON");
    let wanted = string_secret_responses(&model);
    let table = controller_table(&read("../crates/matter-controller/src/node.rs"));

    // Not vacuous: the dump marks two string secrets today (AccountLogin
    // GetSetupPINResponse, ContentControl ResetPINResponse).
    assert!(!wanted.is_empty(), "the dump marks no string secret");

    let missing: Vec<_> = wanted.difference(&table).collect();
    assert!(
        missing.is_empty(),
        "STRING_SECRET_RESPONSES in matter-controller's node.rs lacks a row for \
         (cluster, response command) {missing:#x?}: its strings would print in \
         InvokeResult's Debug"
    );
    let stale: Vec<_> = table.difference(&wanted).collect();
    assert!(
        stale.is_empty(),
        "STRING_SECRET_RESPONSES has rows {stale:#x?} that no string secret in \
         clusters.json backs: a mistyped id, or a SECRET_FIELDS entry removed"
    );
}

#[test]
fn table_parser_reads_rows_and_ignores_comments() {
    let source = "\
const STRING_SECRET_RESPONSES: [(u32, u32); 2] = [
    // a comment (0x9999, 0x01),
    (0x050E, 0x01),
    (1295, 0x02), // trailing
];";
    assert_eq!(
        controller_table(source),
        BTreeSet::from([(0x050E, 0x01), (0x050F, 0x02)])
    );
}

#[test]
#[should_panic(expected = "parsed 1 rows but the table declares 2")]
fn table_parser_refuses_a_row_count_mismatch() {
    controller_table("const STRING_SECRET_RESPONSES: [(u32, u32); 2] = [\n    (0x050E, 0x01),\n];");
}
