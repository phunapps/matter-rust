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
        76,
        "expected the 10 M7 + 5 A2.1 + 4 A2.2 + 5 A2.3 + 5 A2.4 + 4 A2.5 mgmt + 1 D2 + 1 F1 + 1 G-a + 1 G-c + 10 concentration-measurement + 1 bridge (BDBI) + 10 A3-B2 ModeBase + 1 ModeSelect + 2 AlarmBase + 3 ResourceMonitoring + 3 A3-B3 OperationalState + 4 appliance-control + 1 ServiceArea + 2 A3-B4 safety-sensor + 1 valve + 1 ScenesManagement clusters"
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

/// Every datatype struct the emitter gives `write_fields`/`encode`, as
/// `(cluster, struct)`, sorted (M9-A3 B4 rule, `emit_codecs::struct_is_encoded`:
/// reachable from a request command, or a scalar struct reachable from a
/// writable attribute). A new entry is a new public encoder to review; a
/// missing one is a breaking removal.
const ENCODED_STRUCTS: [(&str, &str); 18] = [
    ("AccessControl", "AccessControlExtensionStruct"),
    ("AccessControl", "AccessControlTargetStruct"),
    ("AccessControl", "AccessRestrictionStruct"),
    ("AccessControl", "CommissioningAccessRestrictionEntryStruct"),
    ("Binding", "TargetStruct"),
    ("DoorLock", "CredentialStruct"),
    ("GroupKeyManagement", "GroupKeyMapStruct"),
    ("GroupKeyManagement", "GroupKeySetStruct"),
    ("OtaSoftwareUpdateRequestor", "ProviderLocation"),
    // M9-A3 B4: AddScene's extension field sets.
    ("ScenesManagement", "AttributeValuePairStruct"),
    ("ScenesManagement", "ExtensionFieldSetStruct"),
    ("Thermostat", "PresetStruct"),
    ("Thermostat", "ScheduleTransitionStruct"),
    ("Thermostat", "WeeklyScheduleTransitionStruct"),
    ("TimeSynchronization", "DSTOffsetStruct"),
    ("TimeSynchronization", "FabricScopedTrustedTimeSourceStruct"),
    ("TimeSynchronization", "TimeZoneStruct"),
    ("UserLabel", "LabelStruct"),
];

#[test]
fn encoders_exist_only_for_structs_a_client_sends() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let model = xtask::codegen::model::load(&root.join("xtask/model/clusters.json"))
        .expect("real model loads + validates");
    let mut got: Vec<(&str, &str)> = model
        .clusters
        .iter()
        .flat_map(|c| {
            xtask::codegen::rustgen::emit_codecs::encoded_struct_names(c)
                .into_iter()
                .map(move |s| (c.name.as_str(), s))
        })
        .collect();
    got.sort_unstable();
    assert_eq!(got, ENCODED_STRUCTS);
}
