//! Public files point to no private planning document.
//!
//! The maintainer's design specs, implementation plans and review notes live
//! outside this repository, so a tracked file that names one (a path, a
//! "Task 7", a "review B1") points a reader at nothing. This test fails on
//! any such pointer the patterns below recognise without false positives; a
//! Matter specification citation (`spec §11.18.5.7`) is not one. It reads the
//! tracked tree with `git grep -P`, so it needs git built with PCRE, as the CI
//! runners' and the macOS and Linux distribution gits are.

#![allow(clippy::unwrap_used, clippy::expect_used)] // Test code: a failed git call fails the test.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

/// One pattern: what it catches, its Perl regex, lines it must match, and
/// pathspecs it never searches. A regex with several alternatives has one
/// example per alternative, each matched by that alternative alone, so a
/// broken alternative fails the self-test.
struct Rule {
    what: &'static str,
    regex: &'static str,
    examples: &'static [&'static str],
    except: &'static [&'static str],
}

/// Searched in every tracked file.
const EVERYWHERE: &[Rule] = &[Rule {
    what: "a path into the private planning directories",
    regex: r"docs/superpowers|\.superpowers/",
    examples: &["see docs/superpowers/specs/x.md"],
    except: &[],
}];

/// Searched in the [`POINTER_SCOPE`] pathspecs.
const POINTERS: &[Rule] = &[
    Rule {
        what: "a plan task",
        // "task 8", "Task-8", "Tasks 7b-11" and "Task 7b" too.
        regex: r"\b[Tt]asks?[- ]\d+",
        examples: &["added in Task 7", "added in M2.1 task 8"],
        except: &[],
    },
    Rule {
        what: "a plan task number",
        regex: r"\bT\d{1,2}\b",
        examples: &["(M6.4.2 T18-T21)"],
        // Thermostat's generated enums have members named `T1`..`T3` (the
        // model's names, not pointers).
        except: &[
            ":!crates/matter-clusters/src/gen",
            ":!xtask/model/clusters.json",
        ],
    },
    Rule {
        what: "a review id",
        regex: r"(?i:\breview (?:finding|focus|ruling)\b)|\breview [BCIMNS]\d+\b|\bT\d+ review\b|(?i:\b(?:final|whole-batch|per-task)[- ]review\b)",
        examples: &[
            "see review finding 3",
            "is unchanged (review B1)",
            "the T6 review said",
            "caught in the final review",
            "a Final-review F1 regression",
        ],
        except: &[],
    },
    Rule {
        what: "a fix wave",
        regex: r"(?i)\bfix[- ]wave\b",
        examples: &["(B5 fix wave)"],
        except: &[],
    },
    Rule {
        what: "a design-spec citation",
        regex: r"\b(?:A3|M7) spec\b|\bspec rev(?:ision)? \d+\b|(?i:\bspec tests? \d+)|\bSpec 20\d\d-\d\d-\d\d\b|(?i:\bdesign doc\b)",
        examples: &[
            "/// M9-A3 spec §5.4 against real chip encoding",
            "as of spec rev 3",
            "Spec test 4 covers it",
            "as Spec 2026-10-04 says",
            "see the design doc",
        ],
        except: &[],
    },
    Rule {
        what: "the planning brief",
        regex: r"(?i)\b(?:the|per the|vs) brief\b(?! description)",
        examples: &["per the brief's advice"],
        except: &[],
    },
    Rule {
        what: "batch jargon outside a plain `//` comment",
        regex: r"^(?!\s*//(?![/!])).*\bM9-A3\b",
        examples: &["/// Edition 2024 (M9-A3 B4): `gen` is reserved"],
        except: &[],
    },
    Rule {
        what: "an A3 batch label outside a plain `//` comment",
        regex: r"^(?!\s*//(?![/!])).*(?<![-\w.])B[1-7]\b(?! chunked)",
        examples: &["/// Every B3 cluster all-clusters serves lives on endpoint 1."],
        // The released CHANGELOG and the runbooks use the public M9-B1..B5
        // milestone labels (CHANGELOG's 0.6.0 section is checked by hand),
        // and so does the M9-B hardware example.
        except: &[
            ":!CHANGELOG.md",
            ":!docs/runbooks",
            ":!crates/matter-controller/examples/d_hardware_extras.rs",
        ],
    },
    Rule {
        what: "an A3-B<n> batch label outside a plain `//` comment",
        regex: r"^(?!\s*//(?![/!])).*\bA3-B[1-7]\b",
        examples: &["\"10 A3-B2 ModeBase + 1 ModeSelect\""],
        except: &[],
    },
    Rule {
        what: "a design-decision number",
        regex: r"\b(?:design|spec|[Ss]pec:\s*[\w-]+|matter-hardening|M9-C\d(?: design)?) [CD]\d+(?:\.\d+)?\b|\((?:design |spec )?D\d+(?:\.\d+)?(?:/D\d+(?:\.\d+)?)*\)|\(D\d+(?:\.\d+)?[ ,+]|\bpre-D\d+\b|(?<![-\w])D\d+(?:\.\d+)?/D\d+\b|\bthe D\d+ backstop\b|\bper D\d+\b|\b(?:matter-hardening )?C\d/D\d+\b|(?<![-\w\[/])D\d+(?:\.\d+)?(?::|'s\b)|(?<![-\w])D\d+\.\d+\b",
        examples: &[
            "decided in spec D7; see",
            "(D7)",
            "(D1 + review B2)",
            "the pre-D7 behaviour",
            "see D3/D11 here",
            "the D3 backstop",
            "per D1 the drop",
            "see C1/D6 for",
            "D7's floor",
            "the D11.3 rollback test",
        ],
        // The runbooks name the public M9-D1..D3 milestones ("D2: reading
        // operational credentials").
        except: &[":!docs/runbooks"],
    },
    Rule {
        what: "a planning-process phrase",
        regex: r"(?i:\bthe plan(?:'s)?\b(?! to))|\bplan template\b|\bmaintainer ruling\b|\bsee the spec's\b|\bthe spec's (?:B\d|negative matrix)",
        examples: &[
            "these vectors are the roundtrip floor the plan names",
            "not in our plan template",
            "per a maintainer ruling",
            "see the spec's deferral",
            "row 3 of the spec's negative matrix",
        ],
        except: &[],
    },
    Rule {
        what: "a milestone's plan or design",
        // The label must be capitalised ("the M1 plan", "the F design"), so
        // English such as "the corrected design" or "the whole design" passes.
        regex: r"\b(?i:the) [A-Z][\w.-]* (?i:plan|design)\b(?! doc)",
        examples: &["see the M1 plan when it lands"],
        except: &[],
    },
];

/// Where [`POINTERS`] are searched: every tracked file.
const POINTER_SCOPE: &[&str] = &["."];

/// Never searched: `.gitignore` names the private directory in order to
/// ignore it, this file holds the patterns, and fuzz corpora are binary.
const EXCLUDED: &[&str] = &[
    ":!.gitignore",
    ":!xtask/tests/no_planning_refs.rs",
    ":!*/fuzz/corpus/*",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Run `git grep` with `args` in `dir`: the matching lines, or `""` for none.
fn git_grep(dir: &std::path::Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .arg("grep")
        .args(args)
        .output()
        .expect("run git grep");
    // git grep exits 0 on a match, 1 on none, and anything else on an error.
    match out.status.code() {
        Some(0) => String::from_utf8_lossy(&out.stdout).into_owned(),
        Some(1) => String::new(),
        other => panic!(
            "git grep failed ({other:?}): {}",
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

#[test]
fn public_files_point_to_no_private_planning_document() {
    let mut found = String::new();
    let rules = EVERYWHERE
        .iter()
        .map(|r| (r, &["."][..]))
        .chain(POINTERS.iter().map(|r| (r, POINTER_SCOPE)));
    for (rule, scope) in rules {
        if scope.is_empty() {
            continue;
        }
        let mut args = vec!["-n", "-I", "-P", "-e", rule.regex, "--"];
        args.extend_from_slice(scope);
        args.extend_from_slice(EXCLUDED);
        args.extend_from_slice(rule.except);
        let hits = git_grep(&repo_root(), &args);
        if !hits.is_empty() {
            writeln!(found, "{} (`{}`):\n{hits}", rule.what, rule.regex).unwrap();
        }
    }
    assert!(
        found.is_empty(),
        "rewrite these as self-contained text (see this file's docs):\n{found}"
    );
}

#[test]
fn every_rule_catches_its_example() {
    // The negative control, kept: a typo in a regex would otherwise pass
    // everything.
    let dir = std::env::temp_dir().join(format!("planning-refs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for rule in EVERYWHERE.iter().chain(POINTERS) {
        // A control character in a regex is a corrupted escape (a `\b`
        // written through a string that turned it into a backspace), and
        // matches nothing in a text file.
        assert!(
            rule.regex.bytes().all(|b| b >= 0x20),
            "{}: the regex holds a control character: {:?}",
            rule.what,
            rule.regex
        );
        assert!(!rule.examples.is_empty(), "{}: no example", rule.what);
        for example in rule.examples {
            std::fs::write(dir.join("planted.txt"), format!("{example}\n")).unwrap();
            let hits = git_grep(
                &dir,
                &["--no-index", "-P", "-e", rule.regex, "--", "planted.txt"],
            );
            assert!(
                !hits.is_empty(),
                "{}: `{}` misses {:?}",
                rule.what,
                rule.regex,
                example
            );
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Whether the git pathspec `spec` (an exclusion's `:!` prefix stripped)
/// selects at least one tracked file.
fn names_tracked_files(spec: &str) -> bool {
    let out = Command::new("git")
        .current_dir(repo_root())
        .args(["ls-files", "--", spec.trim_start_matches(":!")])
        .output()
        .expect("run git ls-files");
    assert!(out.status.success(), "git ls-files -- {spec} failed");
    !out.stdout.is_empty()
}

#[test]
fn every_pathspec_names_tracked_files() {
    // `git grep` exits 1 both for "no match" and for "no file selected", so a
    // misspelt or renamed scope entry would stop its area being searched, and
    // a misspelt exclusion would hide nothing, without any test failing.
    let specs = POINTER_SCOPE
        .iter()
        .chain(EXCLUDED)
        .chain(EVERYWHERE.iter().chain(POINTERS).flat_map(|r| r.except));
    let missing: Vec<&str> = specs
        .copied()
        .filter(|spec| !names_tracked_files(spec))
        .collect();
    assert_eq!(
        missing,
        Vec::<&str>::new(),
        "these pathspecs select no tracked file"
    );
    // The negative control, kept: a path that does not exist selects nothing.
    assert!(!names_tracked_files("crates/no-such-crate"));
}
