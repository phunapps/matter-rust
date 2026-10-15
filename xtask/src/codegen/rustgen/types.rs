//! Pure mapping from Matter type strings + names to Rust.
//!
//! No I/O, no model access — just `&str` in, `String`/`bool` out — so every
//! branch is cheaply unit-tested (the M7 spec calls this out explicitly).

// Items in this module are scaffolding wired up by the emitter (next task).

/// Map a non-list scalar/semantic Matter type to its backing Rust scalar,
/// or `None` if `ty` is not a known scalar (then it is a datatype name).
///
/// Semantic globals map to their underlying primitive (semantic newtypes are
/// deferred — YAGNI per spec §2). Bare `enum8`/`enum16` (an attribute typed
/// as a generic enum with no named datatype) map to the raw integer.
fn scalar_rust(ty: &str) -> Option<&'static str> {
    Some(match ty {
        "bool" => "bool",
        // u8: primitive + semantic globals. `namespace` is the global
        // semantic-tag namespace enum, enum8 in both references (chip's zap
        // `global-structs.xml` types SemanticTagStruct.NamespaceID `enum8`;
        // matter.js `@matter/model` `namespace.element.js` declares
        // `type: "enum8"`): mapped to its raw integer like `status`/`priority`,
        // never emitted as a type.
        // `tag` is the semantic tag within a namespace (Core spec 7.19.2.42,
        // uint8; ServiceArea's LandmarkTag / RelativePositionTag / AreaType,
        // M9-A3 B3), whose values depend on the namespace, so it stays a
        // raw integer too.
        "uint8" | "percent" | "fabric-idx" | "action-id" | "status" | "priority" | "namespace"
        | "tag" | "enum8" | "map8" => "u8",
        // u16: primitive + semantic globals (unsigned 16-bit)
        "uint16" | "group-id" | "endpoint-no" | "vendor-id" | "percent100ths" | "enum16"
        | "map16" => "u16",
        // i8 / i16: signed integers + temperature (0.01 °C, signed)
        "int8" => "i8",
        "int16" | "temperature" => "i16",
        "int24" | "int32" => "i32",
        // i64: signed primitives + energy/electrical semantic globals
        "int40" | "int48" | "int56" | "int64" | "voltage-mV" | "amperage-mA" | "power-mW"
        | "power-mVAR" | "power-mVA" | "energy-mWh" | "energy-mVAh" | "energy-mVARh" => "i64",
        "single" => "f32",
        "double" => "f64",
        "string" => "String",
        // byte strings: generic + hardware/IP address octet-string semantics.
        // `ipv6pre` is the IPv6 Prefix data type (Core spec §7.19.2: an octstr
        // of 1 to 17 bytes; ThreadNetworkDiagnostics MeshLocalPrefix, M9-A3
        // B6), carried as its raw bytes like `ipv6adr`.
        "octstr" | "hwadr" | "ipadr" | "ipv4adr" | "ipv6adr" | "ipv6pre" => "Vec<u8>",
        // u32: primitive + semantic globals
        "uint24" | "uint32" | "cluster-id" | "attrib-id" | "command-id" | "event-id"
        | "devtype-id" | "epoch-s" | "elapsed-s" | "map32" => "u32",
        // u64: primitive + semantic globals. `fabric-id` is the 64-bit
        // FabricID (Matter Core §2.5.1); the scalar table wrongly narrowed it
        // to u32 until the 2026-06 audit residual was fixed (the former
        // `fabric-id64` alias was dead — no model field uses it).
        "uint40" | "uint48" | "uint56" | "uint64" | "node-id" | "epoch-us" | "posix-ms"
        | "systime-us" | "systime-ms" | "fabric-id" | "subject-id" => "u64",
        _ => return None,
    })
}

/// Matter *global* composite types referenced by the 10 clusters but not
/// defined cluster-locally — mapped to hand-written foundation structs.
///
/// Currently just `semtag` (the `SemanticTagStruct` in `Descriptor.TagList`).
/// The foundation struct is added to `matter-clusters` when the real
/// Descriptor module is first compiled (M7.4); in M7.3 the mapping only needs
/// to produce a valid type name so the generator does not reject the cluster.
fn global_type_rust(ty: &str) -> Option<&'static str> {
    match ty {
        "semtag" => Some("SemanticTagStruct"),
        _ => None,
    }
}

/// True if `ty` is a type the generator knows how to map on its own (a
/// scalar/semantic primitive or a known global composite) — i.e. not a
/// cluster-local datatype name. Used by validation and the emitter.
#[must_use]
pub fn is_known_type(ty: &str) -> bool {
    scalar_rust(ty).is_some() || global_type_rust(ty).is_some()
}

/// Position of a value, which decides whether `optional` adds `Option<…>`.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Position {
    /// A top-level attribute value: `optional` does NOT wrap in `Option`
    /// (you only decode/encode an attribute that is present).
    Attribute,
    /// A struct or command field: `optional` wraps in `Option` (the tag may
    /// be absent inside the container).
    Field,
}

/// The fully-qualified Rust type for an element.
///
/// `base` is `scalar_rust(ty)` for scalars, the datatype name for named
/// types, or `Vec<…>` for lists. Then `nullable` wraps `Nullable<…>` and
/// (for [`Position::Field`]) `optional` wraps `Option<…>`:
/// `Option<Nullable<base>>`.
#[must_use]
pub fn rust_type(
    ty: &str,
    entry_type: Option<&str>,
    nullable: bool,
    optional: bool,
    pos: Position,
) -> String {
    let mut t = base_type(ty, entry_type);
    if nullable {
        t = format!("Nullable<{t}>");
    }
    if optional && pos == Position::Field {
        t = format!("Option<{t}>");
    }
    t
}

/// The unwrapped Rust type (no `Nullable`/`Option`): scalar, datatype name,
/// or `Vec<element>`.
#[must_use]
pub fn base_type(ty: &str, entry_type: Option<&str>) -> String {
    if ty == "list" {
        let inner = entry_type.unwrap_or("octstr");
        return format!("Vec<{}>", base_type(inner, None));
    }
    if let Some(s) = scalar_rust(ty) {
        return s.to_string();
    }
    if let Some(s) = global_type_rust(ty) {
        return s.to_string();
    }
    ty.to_string() // a cluster-local datatype name, used verbatim (PascalCase)
}

/// Words [`snake`] keeps whole: each is rewritten to its one-word form
/// before splitting, so its inner capitals and digits start no new word.
///
/// Without this table the case-boundary rule splits them mid-word
/// (`MessageIDs` → `message_i_ds`, `TargetSoC` → `target_so_c`, `IPv4` →
/// `i_pv4`, `WiFi` → `wi_fi`, `V2X` → `v2_x`). Order matters only where one
/// entry contains another (none do).
pub const WHOLE_WORDS: [(&str, &str); 5] = [
    ("WiFi", "Wifi"),
    ("IPv", "Ipv"),
    ("SoC", "Soc"),
    ("IDs", "Ids"),
    ("V2X", "V2x"),
];

/// Convert a `PascalCase`/`camelCase` name to `snake_case` (module/fn names).
///
/// A word boundary falls before an uppercase letter that follows a lowercase
/// letter or a digit, or that starts a capitalised word (`ACLEntry` →
/// `acl_entry`). The [`WHOLE_WORDS`] acronyms are one word each
/// (`SupportedWiFiBands` → `supported_wifi_bands`, `MessageIDs` →
/// `message_ids`).
#[must_use]
pub fn snake(name: &str) -> String {
    let mut name = name.to_string();
    for (word, one_word) in WHOLE_WORDS {
        name = name.replace(word, one_word);
    }
    split_words(&name)
}

/// The case-boundary split [`snake`] applies after its [`WHOLE_WORDS`]
/// rewrite, on its own: public so a test can list exactly the model names
/// the word list changes.
#[must_use]
pub fn split_words(name: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        if ch == '_' || ch == '-' || ch == ' ' {
            out.push('_');
            continue;
        }
        if ch.is_ascii_uppercase() {
            let prev_lower = i > 0 && chars[i - 1].is_ascii_lowercase();
            let prev_digit = i > 0 && chars[i - 1].is_ascii_digit();
            let next_lower = i + 1 < chars.len() && chars[i + 1].is_ascii_lowercase();
            if i > 0 && (prev_lower || prev_digit || next_lower) && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Convert a name to `SCREAMING_SNAKE_CASE` (const names).
#[must_use]
pub fn screaming(name: &str) -> String {
    snake(name).to_ascii_uppercase()
}

/// Rust names for enum members whose model name starts with a digit, which
/// cannot start a Rust identifier: `(enum, member, name)`. The quantity's
/// unit or kind goes first (`12Hr` → `Hr12`, Wi-Fi band `2G4` → `Band2G4`).
pub const DIGIT_MEMBER_NAMES: [(&str, &str, &str); 8] = [
    ("HourFormatEnum", "12Hr", "Hr12"),
    ("HourFormatEnum", "24Hr", "Hr24"),
    ("WiFiBandEnum", "2G4", "Band2G4"),
    ("WiFiBandEnum", "3G65", "Band3G65"),
    ("WiFiBandEnum", "5G", "Band5G"),
    ("WiFiBandEnum", "6G", "Band6G"),
    ("WiFiBandEnum", "60G", "Band60G"),
    ("WiFiBandEnum", "1G", "Band1G"),
];

/// Enums whose digit-initial members keep the `_` prefix [`ident`] gives
/// them: `PowerSource`'s battery designations (`4V5`, `18650`, `523`) are
/// product numbers with no unit or kind to lead with, so `_4V5` reads as the
/// designation itself.
pub const UNDERSCORE_DIGIT_ENUMS: [&str; 1] = ["BatCommonDesignationEnum"];

/// The Rust name of member `member` of enum `enum_name`: [`ident`], except a
/// digit-initial member, named by [`DIGIT_MEMBER_NAMES`] or (in an
/// [`UNDERSCORE_DIGIT_ENUMS`] enum) `_`-prefixed.
///
/// # Panics
///
/// At codegen time, if a digit-initial member is in neither table: a new one
/// needs a deliberate name, not a silent `_` prefix.
#[must_use]
pub fn variant_ident(enum_name: &str, member: &str) -> String {
    if !member.starts_with(|c: char| c.is_ascii_digit()) {
        return ident(member);
    }
    if let Some((_, _, name)) = DIGIT_MEMBER_NAMES
        .iter()
        .find(|(e, m, _)| *e == enum_name && *m == member)
    {
        return (*name).to_string();
    }
    assert!(
        UNDERSCORE_DIGIT_ENUMS.contains(&enum_name),
        "codegen: {enum_name}.{member} starts with a digit; give it a name in \
         DIGIT_MEMBER_NAMES (or list {enum_name} in UNDERSCORE_DIGIT_ENUMS)"
    );
    ident(member)
}

/// Escape a Rust reserved word so it is a valid identifier (`type` →
/// `r#type`). Names that are not keywords pass through unchanged.
#[must_use]
pub fn ident(name: &str) -> String {
    // Raw identifiers are illegal for these three, so suffix instead.
    const SUFFIX: [&str; 3] = ["crate", "self", "super"];
    const RAW: [&str; 49] = [
        "as", "break", "const", "continue", "dyn", "else", "enum", "extern", "false", "fn", "for",
        "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
        "static", "struct", "trait", "true", "type", "unsafe", "use", "where", "while", "async",
        "await", "abstract", "become", "box", "do", "final", "macro", "override", "priv", "try",
        "typeof", "unsized", "virtual", "yield", "gen", "Self",
    ];
    // A leading digit is not a valid Rust identifier start: prefix `_`.
    // Enum members reach this only through `variant_ident`, which names
    // every digit-initial member except the battery designations
    // (`UNDERSCORE_DIGIT_ENUMS`).
    if name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return format!("_{name}");
    }
    if SUFFIX.contains(&name) {
        format!("{name}_")
    } else if RAW.contains(&name) {
        format!("r#{name}")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_and_semantics() {
        assert_eq!(base_type("uint16", None), "u16");
        assert_eq!(base_type("uint8", None), "u8");
        assert_eq!(base_type("int16", None), "i16");
        assert_eq!(base_type("temperature", None), "i16");
        assert_eq!(base_type("bool", None), "bool");
        assert_eq!(base_type("octstr", None), "Vec<u8>");
        // M9-A2.4 hardware/IP-address byte-string semantic globals.
        assert_eq!(base_type("hwadr", None), "Vec<u8>");
        assert_eq!(base_type("ipadr", None), "Vec<u8>");
        assert_eq!(base_type("ipv4adr", None), "Vec<u8>");
        assert_eq!(base_type("ipv6adr", None), "Vec<u8>");
        assert_eq!(base_type("string", None), "String");
        assert_eq!(base_type("vendor-id", None), "u16");
        assert_eq!(base_type("cluster-id", None), "u32");
        assert_eq!(base_type("endpoint-no", None), "u16");
        assert_eq!(base_type("fabric-idx", None), "u8");
        // FabricID is uint64 (Matter Core §2.5.1) — regression guard for the
        // audit-found u32 narrowing.
        assert_eq!(base_type("fabric-id", None), "u64");
        assert_eq!(base_type("epoch-s", None), "u32");
        assert_eq!(base_type("enum8", None), "u8");
        // M9-A2.2 energy/electrical semantic globals (all int64-based)…
        assert_eq!(base_type("voltage-mV", None), "i64");
        assert_eq!(base_type("amperage-mA", None), "i64");
        assert_eq!(base_type("power-mW", None), "i64");
        assert_eq!(base_type("power-mVAR", None), "i64");
        assert_eq!(base_type("power-mVA", None), "i64");
        assert_eq!(base_type("energy-mWh", None), "i64");
        assert_eq!(base_type("energy-mVAh", None), "i64");
        assert_eq!(base_type("energy-mVARh", None), "i64");
        // …and the millisecond system-time global (uint64-based).
        assert_eq!(base_type("systime-ms", None), "u64");
        // M9-A2.5 ACL subject id (node/group/CAT id as uint64).
        assert_eq!(base_type("subject-id", None), "u64");
    }

    #[test]
    fn named_datatype_passthrough() {
        assert_eq!(base_type("StartUpOnOffEnum", None), "StartUpOnOffEnum");
    }

    #[test]
    fn lists() {
        assert_eq!(base_type("list", Some("cluster-id")), "Vec<u32>");
        assert_eq!(
            base_type("list", Some("CredentialStruct")),
            "Vec<CredentialStruct>"
        );
    }

    #[test]
    fn nullable_and_optional_wrapping() {
        // Attribute position: optional does NOT add Option.
        assert_eq!(
            rust_type("uint16", None, true, true, Position::Attribute),
            "Nullable<u16>"
        );
        // Field position: both wrap, Option outside Nullable.
        assert_eq!(
            rust_type("uint16", None, true, true, Position::Field),
            "Option<Nullable<u16>>"
        );
        assert_eq!(
            rust_type("uint16", None, false, true, Position::Field),
            "Option<u16>"
        );
        assert_eq!(
            rust_type("bool", None, false, false, Position::Field),
            "bool"
        );
    }

    #[test]
    fn snake_case() {
        assert_eq!(snake("OnOff"), "on_off");
        assert_eq!(snake("StartUpOnOff"), "start_up_on_off");
        assert_eq!(snake("ColorControl"), "color_control");
        assert_eq!(snake("ACL"), "acl");
        assert_eq!(snake("OnWithTimedOff"), "on_with_timed_off");
    }

    #[test]
    fn snake_keeps_whole_words_whole() {
        // WiFi
        assert_eq!(snake("WiFiNetworkDiagnostics"), "wifi_network_diagnostics");
        assert_eq!(snake("SupportedWiFiBands"), "supported_wifi_bands");
        assert_eq!(
            snake("AddOrUpdateWiFiNetwork"),
            "add_or_update_wifi_network"
        );
        // IPv
        assert_eq!(snake("IPv4Addresses"), "ipv4_addresses");
        assert_eq!(
            snake("OffPremiseServicesReachableIPv6"),
            "off_premise_services_reachable_ipv6"
        );
        // SoC
        assert_eq!(snake("TargetSoC"), "target_soc");
        assert_eq!(snake("NextChargeTargetSoC"), "next_charge_target_soc");
        // IDs
        assert_eq!(snake("ActiveMessageIDs"), "active_message_ids");
        assert_eq!(
            snake("UniqueLocationIDsLastEdit"),
            "unique_location_ids_last_edit"
        );
        assert_eq!(snake("GroupKeySetIDs"), "group_key_set_ids");
        // V2X
        assert_eq!(snake("V2X"), "v2x");
        assert_eq!(screaming("V2X"), "V2X");
        // Without the word list, the case-boundary split alone.
        assert_eq!(split_words("ActiveMessageIDs"), "active_message_i_ds");
    }

    #[test]
    fn snake_leaves_the_kept_names_alone() {
        // Acronyms the model already spells in PascalCase (`Pin`, `Url`,
        // `Dvbi`) are one word, and a singular `ID` is unchanged.
        assert_eq!(snake("GetSetupPinResponse"), "get_setup_pin_response");
        assert_eq!(snake("LaunchUrl"), "launch_url");
        assert_eq!(snake("DvbiUrl"), "dvbi_url");
        assert_eq!(snake("GroupKeySetID"), "group_key_set_id");
    }

    #[test]
    fn digit_initial_enum_members_get_a_name() {
        assert_eq!(variant_ident("HourFormatEnum", "12Hr"), "Hr12");
        assert_eq!(variant_ident("HourFormatEnum", "24Hr"), "Hr24");
        assert_eq!(variant_ident("WiFiBandEnum", "2G4"), "Band2G4");
        assert_eq!(variant_ident("WiFiBandEnum", "3G65"), "Band3G65");
        assert_eq!(variant_ident("WiFiBandEnum", "60G"), "Band60G");
        // Battery designations keep the `_` prefix.
        assert_eq!(variant_ident("BatCommonDesignationEnum", "4V5"), "_4V5");
        assert_eq!(variant_ident("BatCommonDesignationEnum", "18650"), "_18650");
        // Every other member is `ident`'s, the kept names included.
        assert_eq!(
            variant_ident("HourFormatEnum", "UseActiveLocale"),
            "UseActiveLocale"
        );
        assert_eq!(variant_ident("PhyRateEnum", "Rate25G"), "Rate25G");
        assert_eq!(variant_ident("CecKeyCodeEnum", "Numbers1"), "Numbers1");
    }

    #[test]
    #[should_panic(expected = "Weird.9Lives starts with a digit")]
    fn an_unnamed_digit_initial_member_stops_codegen() {
        let _ = variant_ident("Weird", "9Lives");
    }

    #[test]
    fn screaming_case() {
        assert_eq!(screaming("OnOff"), "ON_OFF");
        assert_eq!(screaming("AcceptOnlyWhenOn"), "ACCEPT_ONLY_WHEN_ON");
    }

    #[test]
    fn reserved_words() {
        assert_eq!(ident("type"), "r#type");
        assert_eq!(ident("match"), "r#match");
        assert_eq!(ident("self"), "self_");
        assert_eq!(ident("normal"), "normal");
        // Leading-digit enum members (e.g. PowerSource BatCommonDesignationEnum).
        assert_eq!(ident("4V5"), "_4V5");
        assert_eq!(ident("523"), "_523");
        assert_eq!(ident("12Aa"), "_12Aa");
    }

    #[test]
    fn known_type_predicate() {
        assert!(is_known_type("uint16"));
        assert!(is_known_type("cluster-id"));
        assert!(!is_known_type("StartUpOnOffEnum"));
    }

    #[test]
    fn global_enum_namespace_is_its_raw_enum8() {
        // `namespace` is a lowercase model-global enum (ModeSelect references
        // it). As a type name it would emit `pub enum namespace`, which fails
        // `non_camel_case_types`; like `status` it maps to the raw integer.
        assert!(is_known_type("namespace"));
        assert_eq!(base_type("namespace", None), "u8");
        assert_eq!(
            rust_type("namespace", None, true, false, Position::Attribute),
            "Nullable<u8>"
        );
    }

    #[test]
    fn global_semantic_tag_value_tag_is_its_raw_uint8() {
        // `tag` is the model-global semantic tag value (Core spec 7.19.2.42,
        // uint8). ServiceArea uses it for LandmarkTag, RelativePositionTag
        // and the global `locationdesc` AreaType; codegen stopped with
        // "unknown type `tag`" before it was mapped (M9-A3 B3).
        assert!(is_known_type("tag"));
        assert_eq!(base_type("tag", None), "u8");
        assert_eq!(
            rust_type("tag", None, true, false, Position::Field),
            "Nullable<u8>"
        );
        assert_eq!(base_type("list", Some("tag")), "Vec<u8>");
    }

    #[test]
    fn ipv6_prefix_is_a_byte_string() {
        // `ipv6pre` (Core spec §7.19.2, an octstr of 1 to 17 bytes) is
        // ThreadNetworkDiagnostics MeshLocalPrefix's type. codegen stopped with
        // "unknown type `ipv6pre`" before it was mapped (M9-A3 B6).
        assert!(is_known_type("ipv6pre"));
        assert_eq!(base_type("ipv6pre", None), "Vec<u8>");
        assert_eq!(
            rust_type("ipv6pre", None, true, false, Position::Attribute),
            "Nullable<Vec<u8>>"
        );
        assert_eq!(base_type("list", Some("ipv6pre")), "Vec<Vec<u8>>");
    }

    #[test]
    fn global_composite_semtag() {
        // `semtag` is a Matter global struct (Descriptor.TagList = list[semtag]).
        assert!(is_known_type("semtag"));
        assert_eq!(base_type("semtag", None), "SemanticTagStruct");
        assert_eq!(base_type("list", Some("semtag")), "Vec<SemanticTagStruct>");
    }
}
