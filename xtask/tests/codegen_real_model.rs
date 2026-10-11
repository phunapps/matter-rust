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
        113,
        "expected the 10 M7 + 5 A2.1 + 4 A2.2 + 5 A2.3 + 5 A2.4 + 4 A2.5 mgmt + 1 D2 + 1 F1 + 1 G-a + 1 G-c + 10 concentration-measurement + 1 bridge (BDBI) + 10 A3-B2 ModeBase + 1 ModeSelect + 2 AlarmBase + 3 ResourceMonitoring + 3 A3-B3 OperationalState + 4 appliance-control + 1 ServiceArea + 2 A3-B4 safety-sensor + 1 valve + 1 ScenesManagement + 2 A3-B5 attribute-only energy clusters + 1 WaterHeaterManagement + 1 DeviceEnergyManagement + 1 EnergyEvse + 1 Messages + 4 A3-B6 localization / power-source configuration clusters + 4 flat diagnostics and DiagnosticLogs + 1 ThreadNetworkDiagnostics + 2 commissioning (codecs only) + 1 Actions + 2 Fabric Synchronization + 3 network infrastructure + 6 A3-B7 media basics + 4 Content App platform + 1 MediaPlayback + 1 ContentLauncher + 1 Channel + 1 ContentControl (provisional)"
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
const ENCODED_STRUCTS: [(&str, &str); 40] = [
    ("AccessControl", "AccessControlExtensionStruct"),
    ("AccessControl", "AccessControlTargetStruct"),
    ("AccessControl", "AccessRestrictionStruct"),
    ("AccessControl", "CommissioningAccessRestrictionEntryStruct"),
    // M9-A3 B7: LaunchApp / StopApp / HideApp's Application.
    ("ApplicationLauncher", "ApplicationStruct"),
    ("Binding", "TargetStruct"),
    // M9-A3 B7: GetProgramGuide's ChannelList, PageToken and ExternalIdList
    // (RecordProgram and CancelRecordProgram send the last too).
    ("Channel", "AdditionalInfoStruct"),
    ("Channel", "ChannelInfoStruct"),
    ("Channel", "PageTokenStruct"),
    // M9-A3 B7: the block-list requests.
    ("ContentControl", "AppInfoStruct"),
    ("ContentControl", "BlockChannelStruct"),
    ("ContentControl", "TimePeriodStruct"),
    ("ContentControl", "TimeWindowStruct"),
    // M9-A3 B7: LaunchContent's and LaunchURL's structs (AdditionalInfoStruct
    // is ParameterStruct's ExternalIdList entry).
    ("ContentLauncher", "AdditionalInfoStruct"),
    ("ContentLauncher", "BrandingInformationStruct"),
    ("ContentLauncher", "ContentSearchStruct"),
    ("ContentLauncher", "DimensionStruct"),
    ("ContentLauncher", "ParameterStruct"),
    ("ContentLauncher", "PlaybackPreferencesStruct"),
    ("ContentLauncher", "StyleInformationStruct"),
    ("ContentLauncher", "TrackPreferenceStruct"),
    // M9-A3 B5: ModifyForecastRequest and RequestConstraintBasedForecast.
    ("DeviceEnergyManagement", "ConstraintsStruct"),
    ("DeviceEnergyManagement", "SlotAdjustmentStruct"),
    ("DoorLock", "CredentialStruct"),
    // M9-A3 B5: SetTargets' schedules.
    ("EnergyEvse", "ChargingTargetScheduleStruct"),
    ("EnergyEvse", "ChargingTargetStruct"),
    ("GroupKeyManagement", "GroupKeyMapStruct"),
    ("GroupKeyManagement", "GroupKeySetStruct"),
    // M9-A3 B5: PresentMessagesRequest's Responses.
    ("Messages", "MessageResponseOptionStruct"),
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
    // M9-A3 B5: Boost's BoostInfo.
    ("WaterHeaterManagement", "WaterHeaterBoostInfoStruct"),
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

#[test]
fn the_provisional_doc_names_the_models_spec_revision() {
    // PROVISIONAL_DOC says which revision marks an element provisional; a
    // model upgrade that changes meta.specRevision must update it too.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let model = xtask::codegen::model::load(&root.join("xtask/model/clusters.json"))
        .expect("real model loads + validates");
    let revision = model.meta["specRevision"]
        .as_str()
        .expect("meta.specRevision");
    assert!(
        xtask::codegen::rustgen::emit::PROVISIONAL_DOC
            .starts_with(&format!("Provisional in Matter {revision}, ")),
        "{revision}"
    );
}

/// The structs that have an encoder only because a writable attribute carries
/// them, and so stay `#[non_exhaustive]` with
/// `WRITABLE_ATTRIBUTE_ENCODER_DOC` on them (M9-A3 B4 review finding 3, which
/// listed seven: `AccessControlTargetStruct`, the all-scalar entry of `Acl`'s
/// `Targets` list, is the eighth; the `#[non_exhaustive]` decision is open in
/// TODO-1.0.md).
const WRITABLE_ATTRIBUTE_ONLY_ENCODED: [(&str, &str); 8] = [
    ("AccessControl", "AccessControlExtensionStruct"),
    ("AccessControl", "AccessControlTargetStruct"),
    ("Binding", "TargetStruct"),
    ("GroupKeyManagement", "GroupKeyMapStruct"),
    ("OtaSoftwareUpdateRequestor", "ProviderLocation"),
    ("Thermostat", "PresetStruct"),
    ("Thermostat", "ScheduleTransitionStruct"),
    ("UserLabel", "LabelStruct"),
];

#[test]
fn writable_attribute_only_encoded_structs_say_they_are_not_constructible() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let model = xtask::codegen::model::load(&root.join("xtask/model/clusters.json"))
        .expect("real model loads + validates");
    let doc = format!(
        "/// {}\n#[derive(Clone, Debug, PartialEq)]\n#[non_exhaustive]\npub struct ",
        xtask::codegen::rustgen::emit::WRITABLE_ATTRIBUTE_ENCODER_DOC
    );
    let mut got = Vec::new();
    for c in &model.clusters {
        let src = xtask::codegen::rustgen::emit::generate_cluster(c);
        for (at, _) in src.match_indices(&doc) {
            let rest = &src[at + doc.len()..];
            let name = rest.split_whitespace().next().unwrap();
            got.push((c.name.as_str(), name.to_string()));
        }
    }
    got.sort_unstable();
    let want: Vec<(&str, String)> = WRITABLE_ATTRIBUTE_ONLY_ENCODED
        .iter()
        .map(|(c, s)| (*c, (*s).to_string()))
        .collect();
    assert_eq!(got, want);
}

/// The generated fields that carry a `relaxedReason` line, as `(cluster,
/// line, next line)` (M9-A3 B5 fix wave, T7 M3): the four Messages
/// `fabric_index` fields, which chip's servers do not send.
#[test]
fn fields_chip_omits_say_why_they_are_optional() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let model = xtask::codegen::model::load(&root.join("xtask/model/clusters.json"))
        .expect("real model loads + validates");
    let mut got = Vec::new();
    for c in &model.clusters {
        let src = xtask::codegen::rustgen::emit::generate_cluster(c);
        let lines: Vec<&str> = src.lines().map(str::trim).collect();
        for (i, l) in lines.iter().enumerate() {
            if l.starts_with("/// Optional: ") {
                got.push((c.name.as_str(), (*l).to_string(), lines[i + 1].to_string()));
            }
        }
    }
    let field = "pub fabric_index: Option<u8>,";
    let event =
        "/// Optional: chip's servers do not send it (the event is not fabric-scoped in chip).";
    let strukt =
        "/// Optional: chip's servers do not send it (the struct is not fabric-scoped in chip).";
    let want: Vec<(&str, String, String)> = [strukt, event, event, event]
        .into_iter()
        .map(|doc| ("Messages", doc.to_string(), field.to_string()))
        .collect();
    assert_eq!(got, want);
}
