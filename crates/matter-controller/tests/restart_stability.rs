//! M8.1 acceptance: a fabric minted, persisted via `FileStore`, and
//! reloaded yields a byte-identical commissioner identity whose key still
//! signs. This is the "stable operational identity across restart" gate.

// Integration tests are their own crate; allow unwrap/expect at crate level
// (CLAUDE.md permits unwrap/expect in test code with justification).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use matter_cert::MatterTime;
use matter_commissioning::SystemNocRng;
use matter_controller::snapshot::{deserialize, serialize};
use matter_controller::{create_fabric, ControllerState, ControllerStore, FabricConfig, FileStore};
use matter_crypto::Signer as _;

fn temp_path(name: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    // Unique per (process, call): a fixed shared path races when two test
    // processes (or a re-run overlapping a prior run) touch the same file.
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let uniq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "matter-controller-restart-{name}-{}-{uniq}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(p.with_extension("tmp"));
    p
}

#[test]
fn commissioner_identity_is_stable_across_restart() {
    let cfg = FabricConfig::new(
        0x0102_0304_0506_0708,
        1,
        0x0000_0000_0000_0001,
        (
            MatterTime::from_unix_secs(1_700_000_000),
            MatterTime::NO_EXPIRY,
        ),
    );
    let fabric = create_fabric(&cfg, &SystemNocRng).expect("create_fabric");
    let original_state = ControllerState::new(vec![fabric]);

    // "First boot": serialize and persist.
    let path = temp_path("identity");
    let store = FileStore::new(&path);
    store
        .save(&serialize(&original_state).expect("serialize"))
        .expect("save");

    // "Second boot": load and deserialize from disk.
    let loaded = store.load().expect("load").expect("snapshot present");
    let restored = deserialize(&loaded).expect("deserialize");

    let before = &original_state.fabrics[0];
    let after = &restored.fabrics[0];

    // Same stable commissioner node ID and NOC bytes.
    assert_eq!(after.commissioner.node_id, before.commissioner.node_id);
    assert_eq!(
        after.commissioner.noc.to_tlv().unwrap(),
        before.commissioner.noc.to_tlv().unwrap(),
        "commissioner NOC must survive restart byte-for-byte"
    );

    // The reloaded operational key still signs and matches the NOC.
    let signer = after
        .commissioner_signer()
        .expect("reload commissioner signer");
    assert_eq!(
        signer.public_key().as_bytes(),
        after.commissioner.noc.public_key().as_bytes()
    );
    let sig_bytes = signer.sign_p256_sha256(b"post-restart").expect("sign");
    // `PublicKey::verify` takes a `&matter_cert::Signature`, not a raw `[u8; 64]`.
    let sig = matter_cert::Signature::new(sig_bytes);
    signer
        .public_key()
        .verify(b"post-restart", &sig)
        .expect("post-restart signature verifies");

    // The reconstructed FabricRecord is usable (RCAC signer reloads).
    let record = after.to_fabric_record().expect("to_fabric_record");
    assert_eq!(record.fabric_id, cfg.fabric_id);

    let _ = std::fs::remove_file(&path);
}
