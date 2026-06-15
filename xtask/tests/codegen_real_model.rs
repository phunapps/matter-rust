//! Smoke test: the generator runs on the real clusters.json and every cluster
//! emits rustfmt-parseable source. Compilation of the real output against the
//! crate is M7.4 (with byte-parity); here we only prove no cluster crashes the
//! generator or produces unformattable source.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

#[test]
fn all_real_clusters_generate_and_format() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let model = xtask::codegen::model::load(&root.join("xtask/model/clusters.json"))
        .expect("real model loads + validates");
    assert_eq!(
        model.clusters.len(),
        19,
        "expected the 10 M7 clusters + 5 M9-A2.1 pilot + 4 M9-A2.2 energy clusters"
    );
    for c in &model.clusters {
        let src = xtask::codegen::rustgen::emit::generate_cluster(c);
        let formatted = xtask::codegen::rustfmt_source(&src)
            .unwrap_or_else(|e| panic!("{}: generated source is not rustfmt-valid: {e}", c.name));
        assert!(
            formatted.contains("pub const CLUSTER_ID"),
            "{}: missing CLUSTER_ID",
            c.name
        );
    }
}
