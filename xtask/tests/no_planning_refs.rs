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

/// One pattern: what it catches, its Perl regex, a line it must match, and
/// pathspecs it never searches.
struct Rule {
    what: &'static str,
    regex: &'static str,
    example: &'static str,
    except: &'static [&'static str],
}

/// Searched in every tracked file.
const EVERYWHERE: &[Rule] = &[Rule {
    what: "a path into the private planning directories",
    regex: r"docs/superpowers|\.superpowers/",
    example: "see docs/superpowers/specs/x.md",
    except: &[],
}];

/// Searched in the [`POINTER_SCOPE`] pathspecs.
const POINTERS: &[Rule] = &[];

/// Where [`POINTERS`] are searched (git pathspecs). Widened area by area as
/// each area is cleaned; `"."` is every tracked file.
const POINTER_SCOPE: &[&str] = &[];

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
    // The negative control, kept: a typo in a regex, or a git without PCRE,
    // would otherwise pass everything.
    let dir = std::env::temp_dir().join(format!("planning-refs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for rule in EVERYWHERE.iter().chain(POINTERS) {
        std::fs::write(dir.join("planted.txt"), format!("{}\n", rule.example)).unwrap();
        let hits = git_grep(
            &dir,
            &["--no-index", "-P", "-e", rule.regex, "--", "planted.txt"],
        );
        assert!(
            !hits.is_empty(),
            "{}: `{}` misses {:?}",
            rule.what,
            rule.regex,
            rule.example
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
