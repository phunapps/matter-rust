//! String-building emitter for the uniform cluster module shape (spec §2).
//!
//! Plain `String` building with an indent helper — no template engine (the
//! CHIP codegen's templating is the cautionary tale the spec cites). Output
//! is later normalized by rustfmt, so we optimise for correctness, not
//! whitespace.

use crate::codegen::model::{Choice, Cluster, Datatype, FieldDef, RequiredWhen, Supplemented};
use crate::codegen::rustgen::types::{
    base_type, ident, rust_type, screaming, snake, variant_ident, Position,
};
use std::collections::HashSet;
use std::fmt::Write as _;

/// The rustdoc sentence on every generated item the specification marks
/// provisional (`FieldDef::provisional` and its siblings; M9-A3 B4). It names
/// the revision the mark comes from: the codegen model follows Matter 1.5.1
/// (`meta.specRevision` in `clusters.json`; `codegen_real_model` pins the two
/// together), and an element provisional there may be plain in 1.4.2. An
/// element added from the Matter 1.4 supplement gets `element_note`'s
/// supplement line instead.
pub const PROVISIONAL_DOC: &str =
    "Provisional in Matter 1.5.1, the codegen model's revision: a later revision may change or remove it.";

/// The rustdoc paragraph on a struct that has an encoder only because a
/// writable attribute carries it (in `encoded_struct_names` but not reachable
/// from a request command). Like every struct with an encoder it is
/// constructible (no `#[non_exhaustive]`), so a caller can build a new entry,
/// not only re-encode a decoded one.
pub const WRITABLE_ATTRIBUTE_ENCODER_DOC: &str = "Encodable because a writable attribute carries \
     it: build one and write it with `encode` (or `write_fields`, inside the list that carries it).";

/// The rustdoc lines on the `fabric_index` field of a struct whose encoder
/// leaves `FabricIndex` out
/// ([`fabric_index_omitted_on_write`](super::emit_codecs::fabric_index_omitted_on_write)).
pub const OMITTED_FABRIC_INDEX_FIELD_DOC: [&str; 3] = [
    "    /// Not written by `encode` or `write_fields`: the server sets it to the",
    "    /// accessing fabric (a read returns it), so decoding `encode`'s own output",
    "    /// fails with `ClusterError::MissingField(\"FabricIndex\")`.",
];

/// The rustdoc line on a field that carries a secret (`FieldDef::secret`,
/// M9-A3 B6): its struct's `Debug` output shows a placeholder instead.
pub const SECRET_DOC: &str =
    "Secret: this struct's `Debug` output shows `<redacted>` instead, even when it is null or absent.";

/// The rustdoc paragraph on a datatype the dump copied from the cluster that
/// owns it (`Datatype::copied_from`, M9-A3 B7): Channel's
/// `AdditionalInfoStruct` is `ContentLauncher`'s, referenced by qualified name.
pub(crate) fn copied_from_doc(owner: &str, name: &str) -> String {
    format!(
        "A copy of the `{owner}` cluster's `{name}`, which this cluster's elements reference. \
         The two encode identically but are distinct Rust types."
    )
}

/// The one rustdoc note of a generated feature, attribute or command item, or
/// `None` (M9-A3 B4). An element added from the Matter 1.4 supplement
/// (`supplemented`) gets a line saying where it comes from, whether 1.4 itself
/// deprecates it (its own conformance, or its feature's) or marks it
/// provisional, and which Matter release and cluster revision removed it. That
/// line replaces [`PROVISIONAL_DOC`], which names the 1.5.1 revision the
/// element is not in. Any other element gets [`PROVISIONAL_DOC`] when
/// `provisional`.
///
/// # Panics
///
/// At codegen time, if a supplemented element names a feature `c` does not
/// have (`model::validate` rejects that first).
pub(crate) fn element_note(
    c: &Cluster,
    provisional: bool,
    deprecated: bool,
    supplemented: Option<&Supplemented>,
) -> Option<String> {
    let Some(s) = supplemented else {
        return provisional.then(|| PROVISIONAL_DOC.to_string());
    };
    let Some(feature) = c.features.iter().find(|f| f.code == s.feature) else {
        panic!(
            "codegen: {} supplemented element names feature `{}`, which the cluster lacks",
            c.name, s.feature
        );
    };
    let origin = format!(
        "Matter 1.4 element (from chip's {} data model via the 1.4 supplement)",
        s.from
    );
    let removed = format!(
        "removed in Matter {} ({} revision {})",
        s.removed_in, c.name, s.removed_in_revision
    );
    Some(if deprecated {
        format!(
            "{origin}; deprecated in 1.4 itself (`{}`) and {removed}.",
            s.conformance
        )
    } else if let Some(fs) = feature.supplemented.as_ref().filter(|_| feature.deprecated) {
        format!(
            "{origin}; deprecated in 1.4 itself (feature `{}` is `{}`) and {removed}.",
            feature.code, fs.conformance
        )
    } else if provisional {
        format!("{origin}; provisional in Matter {} and {removed}.", s.from)
    } else {
        format!("{origin}; {removed}.")
    })
}

/// The module rustdoc paragraph of a cluster the specification marks
/// provisional as a whole (`Cluster::provisional`; M9-A3 B5, spec §2).
pub(crate) const PROVISIONAL_CLUSTER_DOC: [&str; 3] = [
    "Provisional cluster: the Matter specification marks the whole cluster",
    "provisional (Matter 1.4.2, and still 1.5.1), so a later revision may change",
    "its shape. A shape change is still a breaking `matter-clusters` release.",
];

/// The rustdoc line on a struct field whose presence depends on a sibling
/// field (`FieldDef::required_when`; M9-A3 B5). The sibling is named by its
/// generated Rust identifier. An exclusive dependency (a bare conformance
/// such as `Endpoint` or `!Group`) also states the disallowed half: chip's
/// Binding server refuses a target carrying Group with Endpoint or Node.
pub(crate) fn required_when_doc(dep: &RequiredWhen) -> String {
    let (when, otherwise) = if dep.present {
        ("present", "absent")
    } else {
        ("absent", "present")
    };
    let field = ident(&snake(&dep.field));
    if dep.exclusive {
        format!(
            "Required when `{field}` is {when}, and must be omitted when it is {otherwise}. \
             Neither encoding nor decoding checks it."
        )
    } else {
        format!("Required when `{field}` is {when}. Neither encoding nor decoding checks it.")
    }
}

/// The rustdoc line on a field the dump made optional because chip's servers
/// do not send it (`FieldDef::relaxed_reason`, a `FIELD_RELAXATIONS` entry;
/// M9-A3 B5 fix wave): `Optional: <reason>.`.
pub(crate) fn relaxed_reason_doc(reason: &str) -> String {
    format!("Optional: {reason}.")
}

/// The rustdoc line on a field the dump made nullable because chip's servers
/// send it null (`FieldDef::nullable_reason`, a class-N `FIELD_RELAXATIONS`
/// entry; M9-A3 B7): `Nullable: <reason>.`.
pub(crate) fn nullable_reason_doc(reason: &str) -> String {
    format!("Nullable: {reason}.")
}

/// One rustdoc sentence per choice-conformance group among `fields`, in the
/// order the groups first appear (M9-A3 B4): the generated types take every
/// field of a group as an `Option`, so the rule "exactly one" (`O.a`) or "at
/// least one" (`O.a+`) is stated, not enforced. Field names are the generated
/// Rust identifiers.
pub(crate) fn choice_docs(fields: &[FieldDef]) -> Vec<String> {
    let mut groups: Vec<(&Choice, Vec<String>)> = Vec::new();
    for f in fields {
        let Some(choice) = &f.choice else { continue };
        let name = format!("`{}`", ident(&snake(&f.name)));
        match groups.iter_mut().find(|(c, _)| c.group == choice.group) {
            Some((_, names)) => names.push(name),
            None => groups.push((choice, vec![name])),
        }
    }
    groups
        .into_iter()
        .map(|(c, names)| {
            let how = if c.or_more {
                "at least"
            } else if c.or_less {
                "at most"
            } else {
                "exactly"
            };
            let count = if c.count == 1 {
                "one".to_string()
            } else {
                c.count.to_string()
            };
            format!(
                "Choice group `{}`: a sender includes {how} {count} of {}. Neither encoding nor \
                 decoding checks it.",
                c.group,
                names.join(", ")
            )
        })
        .collect()
}

/// Emit the full Rust module source for one cluster.
#[must_use]
pub fn generate_cluster(c: &Cluster) -> String {
    let mut s = String::new();
    emit_header(&mut s, c);
    emit_ids(&mut s, c);
    emit_feature_bitflags(&mut s, c);
    // A struct that gets an encoder (a request reaches it, or a writable
    // attribute carries it) is built by callers, so its declaration stays
    // constructible (no `#[non_exhaustive]`).
    let dts = c.datatypes.iter().map(|d| (d.name.as_str(), d)).collect();
    let encode_reachable = super::emit_codecs::command_encode_reachable_structs(c, &dts);
    let encoded = super::emit_codecs::encoded_struct_names(c);
    for d in &c.datatypes {
        emit_datatype(&mut s, d, &encode_reachable, &encoded);
    }
    super::emit_codecs::emit_codecs(&mut s, c);
    s
}

/// Emit the shared globals module (`gen/globals.rs`). IDs + generic decoders
/// generated once; per-cluster typed interpretation composes on top.
#[must_use]
pub fn generate_globals() -> String {
    let mut s = String::new();
    s.push_str(
        "//! Global attributes present on every cluster (Matter spec §7.13).\n\
         //! @generated by `cargo xtask codegen` — do not edit.\n\n\
         #![allow(clippy::all, clippy::pedantic, dead_code, unreachable_pub, unused_imports)]\n\n\
         use crate::error::ClusterError;\n\
         use matter_codec::{Element, TlvReader, Value};\n\n\
         /// FeatureMap (0xFFFC).\n\
         pub const FEATURE_MAP: u32 = 0xFFFC;\n\
         /// ClusterRevision (0xFFFD).\n\
         pub const CLUSTER_REVISION: u32 = 0xFFFD;\n\
         /// AttributeList (0xFFFB).\n\
         pub const ATTRIBUTE_LIST: u32 = 0xFFFB;\n\
         /// AcceptedCommandList (0xFFF9).\n\
         pub const ACCEPTED_COMMAND_LIST: u32 = 0xFFF9;\n\
         /// GeneratedCommandList (0xFFF8).\n\
         pub const GENERATED_COMMAND_LIST: u32 = 0xFFF8;\n\n",
    );
    s.push_str(
        "/// Decode a FeatureMap / any `u32` global attribute value.\n\
         ///\n\
         /// # Errors\n\
         /// Returns [`ClusterError`] if the element is not an unsigned int.\n\
         pub fn decode_u32(tlv: &[u8]) -> Result<u32, ClusterError> {\n\
         \x20   let mut r = TlvReader::new(tlv);\n\
         \x20   match r.next()? {\n\
         \x20       Some(Element::Scalar { value: Value::Uint(v), .. }) => {\n\
         \x20           u32::try_from(v).map_err(|_| ClusterError::InvalidLength(\"global u32\"))\n\
         \x20       }\n\
         \x20       _ => Err(ClusterError::UnexpectedType { context: \"global u32\" }),\n\
         \x20   }\n\
         }\n",
    );
    s
}

/// `writeln!` into the buffer (the `Vec`/`String` formatter is infallible).
macro_rules! line {
    ($s:expr, $($arg:tt)*) => {{
        let _ = writeln!($s, $($arg)*);
    }};
}
#[allow(unused_imports)]
pub(crate) use line;

/// The `#[derive(..)]` line of a generated struct with these fields: `Debug`
/// is derived unless a field is secret, in which case
/// [`emit_redacting_debug`] writes it by hand (M9-A3 B6). Every other derived
/// trait is the same either way, so marking a field secret never changes a
/// struct's trait set.
pub(crate) fn struct_derive(fields: &[FieldDef]) -> &'static str {
    if fields.iter().any(|f| f.secret) {
        "#[derive(Clone, PartialEq)]"
    } else {
        "#[derive(Clone, Debug, PartialEq)]"
    }
}

/// Emit (into `s`) a hand-written `Debug` impl for struct `name` when one of
/// its `fields` is secret, nothing otherwise (M9-A3 B6). It prints what the
/// derive would, except that each secret field reads `"<redacted>"`: a Thread
/// dataset or a Wi-Fi passphrase logged with `{:?}` must not leak (the same
/// discipline as `matter-commissioning`'s `ThreadDataset` and
/// `WiFiCredentials`).
pub(crate) fn emit_redacting_debug(s: &mut String, name: &str, fields: &[FieldDef]) {
    if !fields.iter().any(|f| f.secret) {
        return;
    }
    line!(s, "impl core::fmt::Debug for {name} {{");
    line!(
        s,
        "    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {{"
    );
    line!(s, "        f.debug_struct(\"{name}\")");
    for field in fields {
        // The derive prints the field's identifier without a raw prefix:
        // `r#type` as `type`, but `self_` and `_4v5` as they are.
        let id = ident(&snake(&field.name));
        let shown = id.trim_start_matches("r#");
        if field.secret {
            line!(s, "            .field(\"{shown}\", &\"<redacted>\")");
        } else {
            line!(s, "            .field(\"{shown}\", &self.{id})");
        }
    }
    line!(s, "            .finish()");
    line!(s, "    }}");
    line!(s, "}}\n");
}

fn emit_header(s: &mut String, c: &Cluster) {
    line!(s, "//! {} cluster (0x{:04X}).", c.name, c.id);
    if c.provisional {
        line!(s, "//!");
        for doc in PROVISIONAL_CLUSTER_DOC {
            line!(s, "//! {doc}");
        }
        line!(s, "//!");
    }
    line!(
        s,
        "//! @generated by `cargo xtask codegen` — do not edit.\n"
    );
    line!(
        s,
        "#![allow(clippy::all, clippy::pedantic, dead_code, unreachable_pub, unused_imports)]\n"
    );
    if !defines_local_semantic_tag_struct(c) {
        line!(s, "use crate::datatypes::SemanticTagStruct;");
    }
    line!(s, "use crate::error::ClusterError;");
    line!(s, "use crate::types::Nullable;");
    // Only a cluster with a secret request argument names `Secret`, so the
    // other modules' imports are unchanged.
    if c.commands
        .iter()
        .any(|cmd| cmd.direction == "request" && cmd.fields.iter().any(|f| f.secret))
    {
        line!(s, "use crate::types::Secret;");
    }
    line!(
        s,
        "use matter_codec::{{ContainerKind, Element, Tag, TlvReader, TlvWriter, Value}};\n"
    );
    line!(s, "/// Cluster ID.");
    line!(s, "pub const CLUSTER_ID: u32 = 0x{:04X};", c.id);
    for doc in cluster_revision_doc(c) {
        line!(s, "{doc}");
    }
    line!(s, "pub const CLUSTER_REVISION: u16 = {};\n", c.revision);
}

/// The rustdoc lines of `CLUSTER_REVISION`: the Matter 1.4.2 revision this
/// crate was generated against, and that a device reports its own. When the
/// codegen model's revision is higher, a last line says the module follows
/// the model for what changed after 1.4.2.
pub(crate) fn cluster_revision_doc(c: &Cluster) -> Vec<String> {
    let mut doc = vec![
        "/// The cluster revision this crate was generated against (Matter 1.4.2); a device"
            .to_string(),
        "/// reports its own in the `ClusterRevision` attribute.".to_string(),
    ];
    if let Some(m) = c.model_revision.filter(|m| *m > c.revision) {
        doc.push("///".to_string());
        doc.push(format!(
            "/// The codegen model (Matter 1.5.1) is at revision {m}: an element it added or \
             changed after revision {} is generated as the model has it.",
            c.revision
        ));
    }
    doc
}

/// True when the cluster defines its own `SemanticTagStruct` datatype, so the
/// module must not import the hand-written global one (the `semtag` struct,
/// `crate::datatypes::SemanticTagStruct`): the two names would collide
/// (E0255). `ModeSelect` is the case: its cluster-local `SemanticTagStruct`
/// (`MfgCode`, `Value`; 1.4.2 `ModeSelect.xml`) is a different struct from the
/// global `semtag` (`MfgCode`, `NamespaceID`, `Tag`, `Label`).
///
/// # Panics
///
/// At codegen time, if such a cluster also references `semtag`: without the
/// import, `SemanticTagStruct` would silently name the local struct there.
fn defines_local_semantic_tag_struct(c: &Cluster) -> bool {
    if !c.datatypes.iter().any(|d| d.name == "SemanticTagStruct") {
        return false;
    }
    let refs_semtag = |ty: &str, entry: Option<&str>| ty == "semtag" || entry == Some("semtag");
    let mut fields = c
        .commands
        .iter()
        .flat_map(|cmd| &cmd.fields)
        .chain(c.events.iter().flat_map(|e| &e.fields))
        .chain(c.datatypes.iter().flat_map(|d| &d.fields));
    let uses_global = c
        .attributes
        .iter()
        .any(|a| refs_semtag(&a.ty, a.entry_type.as_deref()))
        || fields.any(|f| refs_semtag(&f.ty, f.entry_type.as_deref()));
    assert!(
        !uses_global,
        "codegen: {} defines its own SemanticTagStruct and also references the global \
         `semtag`; the two would share one name — rename one before allowlisting it",
        c.name
    );
    true
}

fn emit_ids(s: &mut String, c: &Cluster) {
    line!(s, "/// Command IDs (requests and responses).");
    line!(s, "pub mod command_id {{");
    for cmd in &c.commands {
        line!(s, "    /// `{}` ({}).", cmd.name, cmd.direction);
        if let Some(note) = element_note(
            c,
            cmd.provisional,
            cmd.deprecated,
            cmd.supplemented.as_ref(),
        ) {
            line!(s, "    /// {note}");
        }
        line!(
            s,
            "    pub const {}: u32 = 0x{:02X};",
            screaming(&cmd.name),
            cmd.id
        );
    }
    line!(s, "}}\n");

    line!(s, "/// Attribute IDs (cluster-specific).");
    line!(s, "pub mod attribute_id {{");
    for a in &c.attributes {
        line!(s, "    /// `{}`.", a.name);
        if let Some(note) = element_note(c, a.provisional, a.deprecated, a.supplemented.as_ref()) {
            line!(s, "    /// {note}");
        }
        line!(
            s,
            "    pub const {}: u32 = 0x{:04X};",
            screaming(&a.name),
            a.id
        );
    }
    line!(s, "}}\n");

    // Emitted only when the cluster has dumped events, so clusters without
    // them keep their exact previous output (no empty `event_id` churn).
    if !c.events.is_empty() {
        line!(s, "/// Event IDs.");
        line!(s, "pub mod event_id {{");
        for ev in &c.events {
            line!(s, "    /// `{}` ({} priority).", ev.name, ev.priority);
            if ev.provisional {
                line!(s, "    /// {PROVISIONAL_DOC}");
            }
            line!(
                s,
                "    pub const {}: u32 = 0x{:02X};",
                screaming(&ev.name),
                ev.id
            );
        }
        line!(s, "}}\n");
    }
}

fn emit_feature_bitflags(s: &mut String, c: &Cluster) {
    if c.features.is_empty() {
        return;
    }
    line!(s, "bitflags::bitflags! {{");
    line!(s, "    /// `{}` feature bits (FeatureMap).", c.name);
    line!(s, "    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]");
    line!(s, "    pub struct Feature: u32 {{");
    for f in &c.features {
        line!(s, "        /// {} ({}).", f.name, f.code);
        if let Some(note) = element_note(c, f.provisional, f.deprecated, f.supplemented.as_ref()) {
            line!(s, "        /// {note}");
        }
        line!(s, "        const {} = 1 << {};", screaming(&f.code), f.bit);
    }
    line!(s, "    }}");
    line!(s, "}}\n");
}

fn emit_datatype(
    s: &mut String,
    d: &Datatype,
    encode_reachable: &HashSet<&str>,
    encoded: &HashSet<&str>,
) {
    match d.kind.as_str() {
        "enum" => emit_enum(s, d),
        "bitmap" => emit_bitmap(s, d),
        "struct" => emit_struct(s, d, encode_reachable, encoded),
        _ => {} // "scalar": a named alias of a primitive — referenced inline, no decl needed.
    }
}

fn enum_backing(base: &str) -> &'static str {
    if base == "enum16" {
        "u16"
    } else {
        "u8"
    }
}

/// The catch-all "unknown discriminant" variant name for a generated enum.
///
/// Normally `Unknown`, but some Matter enums (`AirQualityEnum`, `PowerModeEnum`,
/// `BatChargeStateEnum`, …) define a member literally named `Unknown`; for those
/// the catch-all becomes `Unrecognized` so the two do not collide. Panics only
/// if a model defines BOTH `Unknown` and `Unrecognized` members (no known Matter
/// enum does) — a loud failure, never a silent miscompile.
fn catch_all_variant(d: &Datatype) -> &'static str {
    let has = |n: &str| d.values.iter().any(|v| v.name == n);
    if !has("Unknown") {
        "Unknown"
    } else if !has("Unrecognized") {
        "Unrecognized"
    } else {
        panic!(
            "enum {} defines both Unknown and Unrecognized members",
            d.name
        )
    }
}

fn emit_enum(s: &mut String, d: &Datatype) {
    let backing = enum_backing(&d.base);
    let catch_all = catch_all_variant(d);
    line!(s, "/// `{}` ({}).", d.name, d.base);
    if let Some(kept_for) = &d.kept_for {
        line!(s, "///");
        line!(s, "/// {kept_for}");
    }
    if let Some(owner) = &d.copied_from {
        line!(s, "///");
        line!(s, "/// {}", copied_from_doc(owner, &d.name));
    }
    line!(s, "#[derive(Copy, Clone, Debug, PartialEq, Eq)]");
    // Members like `4V5`/`523` (PowerSource BatCommonDesignationEnum) get an
    // `_`-prefixed variant name (see `variant_ident`), which is not
    // upper-camel-case.
    if d.values
        .iter()
        .any(|v| variant_ident(&d.name, &v.name).starts_with('_'))
    {
        line!(s, "#[allow(non_camel_case_types)]");
    }
    line!(s, "pub enum {} {{", d.name);
    for v in &d.values {
        line!(s, "    /// {} = {}.", v.name, v.value);
        line!(s, "    {},", variant_ident(&d.name, &v.name));
    }
    line!(s, "    /// A value not known to this codegen revision.");
    line!(s, "    {catch_all}({backing}),");
    line!(s, "}}\n");

    line!(s, "impl {} {{", d.name);
    line!(
        s,
        "    /// Decode from its raw discriminant (unknown → `{catch_all}`)."
    );
    line!(s, "    #[must_use]");
    line!(s, "    pub fn from_raw(v: {backing}) -> Self {{");
    line!(s, "        match v {{");
    for v in &d.values {
        line!(
            s,
            "            {} => Self::{},",
            v.value,
            variant_ident(&d.name, &v.name)
        );
    }
    line!(s, "            other => Self::{catch_all}(other),");
    line!(s, "        }}");
    line!(s, "    }}");
    line!(s, "    /// The raw discriminant.");
    line!(s, "    #[must_use]");
    line!(s, "    pub fn to_raw(self) -> {backing} {{");
    line!(s, "        match self {{");
    for v in &d.values {
        line!(
            s,
            "            Self::{} => {},",
            variant_ident(&d.name, &v.name),
            v.value
        );
    }
    line!(s, "            Self::{catch_all}(v) => v,");
    line!(s, "        }}");
    line!(s, "    }}");
    line!(s, "}}\n");
}

fn emit_bitmap(s: &mut String, d: &Datatype) {
    let backing = match d.base.as_str() {
        "map16" => "u16",
        "map32" => "u32",
        _ => "u8",
    };
    line!(s, "bitflags::bitflags! {{");
    line!(s, "    /// `{}` ({}).", d.name, d.base);
    if let Some(owner) = &d.copied_from {
        line!(s, "    ///");
        line!(s, "    /// {}", copied_from_doc(owner, &d.name));
    }
    line!(s, "    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]");
    line!(s, "    pub struct {}: {} {{", d.name, backing);
    for b in &d.bits {
        if let Some(bit) = b.bit {
            line!(s, "        /// {}.", b.name);
            line!(s, "        const {} = 1 << {};", screaming(&b.name), bit);
        }
    }
    line!(s, "    }}");
    line!(s, "}}\n");
}

/// `encode_reachable`: structs a request command reaches; `encoded`: structs
/// that get an encoder (`encoded_struct_names`), which are constructible (no
/// `#[non_exhaustive]`). One in `encoded` but not `encode_reachable` gets
/// [`WRITABLE_ATTRIBUTE_ENCODER_DOC`].
fn emit_struct(
    s: &mut String,
    d: &Datatype,
    encode_reachable: &HashSet<&str>,
    encoded: &HashSet<&str>,
) {
    line!(s, "/// `{}` struct.", d.name);
    if let Some(global) = &d.global_name {
        line!(s, "///");
        line!(s, "/// Generated from the Matter global type `{global}`.");
    }
    if let Some(owner) = &d.copied_from {
        line!(s, "///");
        line!(s, "/// {}", copied_from_doc(owner, &d.name));
    }
    for doc in choice_docs(&d.fields) {
        line!(s, "///");
        line!(s, "/// {doc}");
    }
    let name = d.name.as_str();
    if encoded.contains(name) && !encode_reachable.contains(name) {
        line!(s, "///");
        line!(s, "/// {WRITABLE_ATTRIBUTE_ENCODER_DOC}");
    }
    line!(s, "{}", struct_derive(&d.fields));
    // `#[non_exhaustive]` future-proofs decode-only data structs, but blocks the
    // struct-literal construction a caller needs to encode one; a struct that
    // gets an encoder (a request command or a writable attribute reaches it)
    // is built to be encoded, so it is constructible.
    if !encoded.contains(name) {
        line!(s, "#[non_exhaustive]");
    }
    line!(s, "pub struct {} {{", d.name);
    let fabric_scoped = super::emit_codecs::struct_is_fabric_scoped(d);
    let omits_fabric_index =
        super::emit_codecs::struct_omits_fabric_index_on_write(d, encode_reachable, encoded);
    for f in &d.fields {
        let ty = rust_type(
            &f.ty,
            f.entry_type.as_deref(),
            f.nullable,
            f.optional,
            Position::Field,
        );
        line!(s, "    /// Field {} (tag {}).", f.name, f.id);
        if omits_fabric_index && f.id == 254 {
            for doc in OMITTED_FABRIC_INDEX_FIELD_DOC {
                line!(s, "{doc}");
            }
        }
        if f.provisional {
            line!(s, "    /// {PROVISIONAL_DOC}");
        }
        if let Some(dep) = &f.required_when {
            line!(s, "    /// {}", required_when_doc(dep));
        }
        if let Some(reason) = &f.relaxed_reason {
            line!(s, "    /// {}", relaxed_reason_doc(reason));
        }
        if let Some(reason) = &f.nullable_reason {
            line!(s, "    /// {}", nullable_reason_doc(reason));
        }
        if fabric_scoped && f.fabric_sensitive {
            if f.mandatory_on_write {
                // Mandatory in the model, relaxed for decode only: `None`
                // means withheld, and nothing else.
                line!(
                    s,
                    "    /// Fabric-sensitive: `None` when the device withheld it because the entry"
                );
                line!(s, "    /// belongs to another fabric (unfiltered read).");
            } else {
                // Optional in the model itself (Messages `Responses`): `None`
                // also means the sender left it out.
                line!(
                    s,
                    "    /// Fabric-sensitive: `None` when not sent (optional), including when"
                );
                line!(s, "    /// withheld for another fabric's entry.");
            }
        }
        if f.secret {
            line!(s, "    /// {SECRET_DOC}");
        }
        // Escape reserved-word field names (`Type` -> `r#type`); see field_ident
        // in emit_codecs (the codec pass uses the same rule).
        line!(s, "    pub {}: {},", ident(&snake(&f.name)), ty);
    }
    line!(s, "}}\n");
    emit_redacting_debug(s, &d.name, &d.fields);
    // The struct's encode/decode impls are emitted by the codec pass (next
    // task), since they share the scalar read/write helpers.
    let _ = base_type; // keep import used regardless of branch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::model::{Datatype, EnumValue};

    fn enum_dt(name: &str, base: &str, values: &[(u32, &str)]) -> Datatype {
        Datatype {
            name: name.to_string(),
            base: base.to_string(),
            kind: "enum".to_string(),
            values: values
                .iter()
                .map(|(v, n)| EnumValue {
                    value: *v,
                    name: (*n).to_string(),
                })
                .collect(),
            bits: vec![],
            fields: vec![],
            global_name: None,
            kept_for: None,
            copied_from: None,
        }
    }

    #[test]
    fn enum_without_unknown_member_keeps_unknown_catch_all() {
        let mut s = String::new();
        emit_enum(
            &mut s,
            &enum_dt("StartUpOnOffEnum", "enum8", &[(0, "Off"), (1, "On")]),
        );
        assert!(
            s.contains("Unknown(u8),"),
            "expected Unknown catch-all:\n{s}"
        );
        assert!(s.contains("other => Self::Unknown(other),"), "{s}");
        assert!(s.contains("Self::Unknown(v) => v,"), "{s}");
    }

    #[test]
    fn enum_with_unknown_member_uses_unrecognized_catch_all() {
        let mut s = String::new();
        emit_enum(
            &mut s,
            &enum_dt("AirQualityEnum", "enum8", &[(0, "Unknown"), (1, "Good")]),
        );
        // The model member stays `Unknown` (a fieldless variant); the catch-all
        // is renamed to `Unrecognized` to avoid a duplicate-variant collision.
        assert!(
            s.contains("    Unknown,\n"),
            "model member Unknown missing:\n{s}"
        );
        assert!(
            s.contains("Unrecognized(u8),"),
            "catch-all not renamed:\n{s}"
        );
        assert!(
            !s.contains("Unknown(u8)"),
            "colliding catch-all present:\n{s}"
        );
        assert!(s.contains("other => Self::Unrecognized(other),"), "{s}");
        assert!(s.contains("Self::Unrecognized(v) => v,"), "{s}");
    }

    #[test]
    fn fabric_sensitive_field_doc_says_none_means_withheld() {
        use crate::codegen::model::FieldDef;
        // `relaxed_for_decode`: mandatory in the model, dumped optional with
        // mandatoryOnWrite (§5.4); otherwise a sensitive field is optional in
        // the model itself.
        let f = |id: u32, name: &str, sensitive: bool, relaxed_for_decode: bool| FieldDef {
            id,
            name: name.to_string(),
            ty: "uint16".to_string(),
            metatype: "integer".to_string(),
            entry_type: None,
            nullable: false,
            optional: sensitive,
            fabric_sensitive: sensitive,
            mandatory_on_write: relaxed_for_decode,
            provisional: false,
            choice: None,
            required_when: None,
            relaxed_reason: None,
            nullable_reason: None,
            secret: false,
        };
        let d = Datatype {
            name: "ScopedStruct".to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields: vec![
                f(1, "Secret", true, true),
                f(2, "Note", true, false),
                f(3, "Plain", false, false),
                f(254, "FabricIndex", false, false),
            ],
            global_name: None,
            kept_for: None,
            copied_from: None,
        };
        let mut s = String::new();
        emit_struct(&mut s, &d, &HashSet::new(), &HashSet::new());
        assert_eq!(s.matches("Fabric-sensitive: `None`").count(), 2, "{s}");
        // A field relaxed for decode only: None means withheld, nothing else.
        assert!(
            s.contains(
                "    /// Field Secret (tag 1).\n    /// Fabric-sensitive: `None` when the device withheld it because the entry\n"
            ),
            "{s}"
        );
        // A field optional in the model (M9-A3 B5 fix wave, T7 M2): None also
        // means the sender left it out.
        assert!(
            s.contains(
                "    /// Field Note (tag 2).\n    /// Fabric-sensitive: `None` when not sent (optional), including when\n    /// withheld for another fabric's entry.\n"
            ),
            "{s}"
        );
        assert!(s.contains("pub secret: Option<u16>,"), "{s}");
        assert!(s.contains("pub note: Option<u16>,"), "{s}");
        assert!(s.contains("pub plain: u16,"), "{s}");
    }

    #[test]
    fn a_relaxed_field_states_why_it_is_optional() {
        // M9-A3 B5 fix wave, T7 M3: a FIELD_RELAXATIONS field (Messages'
        // FabricIndex) carries its relaxedReason, on a datatype struct and on
        // an event payload alike.
        use crate::codegen::model::FieldDef;
        let field = |reason: Option<&str>| FieldDef {
            id: 254,
            name: "FabricIndex".to_string(),
            ty: "fabric-idx".to_string(),
            metatype: "integer".to_string(),
            entry_type: None,
            nullable: false,
            optional: true,
            fabric_sensitive: false,
            mandatory_on_write: false,
            provisional: false,
            choice: None,
            required_when: None,
            relaxed_reason: reason.map(str::to_string),
            nullable_reason: None,
            secret: false,
        };
        let want = "    /// Field FabricIndex (tag 254).\n    /// Optional: chip's servers do not send it.\n    pub fabric_index: Option<u8>,";
        let d = Datatype {
            fields: vec![field(Some("chip's servers do not send it"))],
            ..struct_dt("MessageStruct")
        };
        let mut s = String::new();
        emit_struct(&mut s, &d, &HashSet::new(), &HashSet::new());
        assert!(s.contains(want), "{s}");
        let c = Cluster {
            events: vec![crate::codegen::model::EventDef {
                id: 0,
                name: "MessageQueued".to_string(),
                priority: "info".to_string(),
                fields: vec![field(Some("chip's servers do not send it"))],
                provisional: false,
            }],
            ..cluster_with(vec![], vec![])
        };
        let src = generate_cluster(&c);
        assert!(src.contains(want), "{src}");
        // Without a reason, no line.
        let d = Datatype {
            fields: vec![field(None)],
            ..struct_dt("MessageStruct")
        };
        let mut s = String::new();
        emit_struct(&mut s, &d, &HashSet::new(), &HashSet::new());
        assert!(!s.contains("Optional:"), "{s}");
    }

    fn cluster_with(
        datatypes: Vec<Datatype>,
        attributes: Vec<crate::codegen::model::Attribute>,
    ) -> Cluster {
        Cluster {
            id: 0x0050,
            name: "Shadowing".to_string(),
            revision: 1,
            model_revision: None,
            provisional: false,
            features: vec![],
            attributes,
            commands: vec![],
            events: vec![],
            datatypes,
        }
    }

    fn struct_dt(name: &str) -> Datatype {
        Datatype {
            name: name.to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields: vec![],
            global_name: None,
            kept_for: None,
            copied_from: None,
        }
    }

    #[test]
    fn global_semantic_tag_import_is_kept_unless_a_local_struct_shadows_it() {
        const IMPORT: &str = "use crate::datatypes::SemanticTagStruct;";
        let mut plain = String::new();
        emit_header(&mut plain, &cluster_with(vec![], vec![]));
        assert!(plain.contains(IMPORT), "{plain}");
        // ModeSelect's shape: a cluster-local struct of the same name.
        let mut shadowed = String::new();
        emit_header(
            &mut shadowed,
            &cluster_with(vec![struct_dt("SemanticTagStruct")], vec![]),
        );
        assert!(!shadowed.contains(IMPORT), "{shadowed}");
    }

    #[test]
    #[should_panic(expected = "defines its own SemanticTagStruct and also references")]
    fn a_local_semantic_tag_struct_next_to_a_semtag_reference_stops_codegen() {
        use crate::codegen::model::Attribute;
        let tag_list = Attribute {
            id: 0,
            name: "TagList".to_string(),
            ty: "list".to_string(),
            metatype: "array".to_string(),
            entry_type: Some("semtag".to_string()),
            nullable: false,
            optional: false,
            writable: false,
            provisional: false,
            deprecated: false,
            supplemented: None,
        };
        let mut s = String::new();
        emit_header(
            &mut s,
            &cluster_with(vec![struct_dt("SemanticTagStruct")], vec![tag_list]),
        );
    }

    #[test]
    fn cluster_revision_doc_names_1_4_2_and_a_newer_model_revision() {
        let mut c = cluster_with(vec![], vec![]);
        c.revision = 6;
        c.model_revision = Some(7);
        let mut s = String::new();
        emit_header(&mut s, &c);
        assert!(
            s.contains(
                "/// The cluster revision this crate was generated against (Matter 1.4.2); a device\n\
                 /// reports its own in the `ClusterRevision` attribute.\n///\n\
                 /// The codegen model (Matter 1.5.1) is at revision 7: an element it added or \
                 changed after revision 6 is generated as the model has it.\n\
                 pub const CLUSTER_REVISION: u16 = 6;\n"
            ),
            "{s}"
        );
        // The same revision, or none recorded: no model line.
        for model_revision in [Some(6), None] {
            c.model_revision = model_revision;
            assert_eq!(cluster_revision_doc(&c).len(), 2, "{model_revision:?}");
        }
    }

    #[test]
    fn non_exhaustive_only_on_structs_without_an_encoder() {
        use std::collections::HashSet;
        let d = Datatype {
            name: "EncStruct".to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields: vec![],
            global_name: None,
            kept_for: None,
            copied_from: None,
        };
        // A normal data struct keeps #[non_exhaustive].
        let mut normal = String::new();
        emit_struct(&mut normal, &d, &HashSet::new(), &HashSet::new());
        assert!(normal.contains("#[non_exhaustive]"), "{normal}");
        // A command-encode-reachable struct must stay constructible by callers
        // (they build it to pass to encode_*) -> no #[non_exhaustive].
        let reachable: HashSet<&str> = std::iter::once("EncStruct").collect();
        let mut enc = String::new();
        emit_struct(&mut enc, &d, &reachable, &reachable);
        assert!(!enc.contains("#[non_exhaustive]"), "{enc}");
        assert!(!enc.contains(WRITABLE_ATTRIBUTE_ENCODER_DOC), "{enc}");
        // Encoded only because a writable attribute carries it: constructible
        // too (a caller builds a new entry to write), and its rustdoc says how
        // it is written.
        let mut writable = String::new();
        emit_struct(&mut writable, &d, &HashSet::new(), &reachable);
        assert!(!writable.contains("#[non_exhaustive]"), "{writable}");
        assert!(
            writable.starts_with(&format!(
                "/// `EncStruct` struct.\n///\n/// {WRITABLE_ATTRIBUTE_ENCODER_DOC}\n"
            )),
            "{writable}"
        );
        assert!(!normal.contains(WRITABLE_ATTRIBUTE_ENCODER_DOC), "{normal}");
    }
    #[test]
    fn a_write_only_fabric_scoped_struct_says_its_fabric_index_is_not_written() {
        use std::collections::HashSet;
        let fabric_index = FieldDef {
            id: 254,
            optional: false,
            ..note_field("FabricIndex", false, None)
        };
        let d = Datatype {
            name: "TargetStruct".to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields: vec![note_field("Node", false, None), fabric_index],
            global_name: None,
            kept_for: None,
            copied_from: None,
        };
        let this: HashSet<&str> = std::iter::once("TargetStruct").collect();
        let want = format!(
            "    /// Field FabricIndex (tag 254).\n{}\n",
            OMITTED_FABRIC_INDEX_FIELD_DOC.join("\n")
        );
        // Encoded only because a writable attribute carries it: the field
        // says the encoder leaves it out.
        let mut writable = String::new();
        emit_struct(&mut writable, &d, &HashSet::new(), &this);
        assert!(writable.contains(&want), "{writable}");
        // A request reaches it (its encoder writes the index), or it has no
        // encoder: no such line.
        for (reachable, encoded) in [(&this, &this), (&HashSet::new(), &HashSet::new())] {
            let mut s = String::new();
            emit_struct(&mut s, &d, reachable, encoded);
            assert!(s.contains("    /// Field FabricIndex (tag 254).\n"), "{s}");
            assert!(!s.contains(OMITTED_FABRIC_INDEX_FIELD_DOC[0]), "{s}");
        }
    }

    // ---- M9-A3 B4: provisional, choice-group and global-origin rustdoc ----

    fn note_field(
        name: &str,
        provisional: bool,
        choice: Option<(&str, u32, bool, bool)>,
    ) -> FieldDef {
        FieldDef {
            id: 0,
            name: name.to_string(),
            ty: "uint8".to_string(),
            metatype: "integer".to_string(),
            entry_type: None,
            nullable: false,
            optional: true,
            fabric_sensitive: false,
            mandatory_on_write: false,
            provisional,
            choice: choice.map(|(group, count, or_more, or_less)| Choice {
                group: group.to_string(),
                count,
                or_more,
                or_less,
            }),
            required_when: None,
            relaxed_reason: None,
            nullable_reason: None,
            secret: false,
        }
    }

    #[test]
    fn provisional_ids_and_features_carry_the_provisional_doc() {
        use crate::codegen::model::{Attribute, CommandDef, EventDef, Feature};
        let attr = |name: &str, provisional: bool| Attribute {
            id: u32::from(provisional),
            name: name.to_string(),
            ty: "uint8".to_string(),
            metatype: "integer".to_string(),
            entry_type: None,
            nullable: false,
            optional: true,
            writable: false,
            provisional,
            deprecated: false,
            supplemented: None,
        };
        let mut c = cluster_with(vec![], vec![attr("Plain", false), attr("Draft", true)]);
        c.commands = vec![CommandDef {
            id: 0,
            name: "GoDraft".to_string(),
            direction: "request".to_string(),
            response_id: None,
            fields: vec![],
            provisional: true,
            deprecated: false,
            supplemented: None,
        }];
        c.events = vec![EventDef {
            id: 0,
            name: "Drafted".to_string(),
            priority: "info".to_string(),
            fields: vec![],
            provisional: true,
        }];
        c.features = vec![
            Feature {
                bit: 0,
                code: "PL".to_string(),
                name: "Plain".to_string(),
                provisional: false,
                deprecated: false,
                supplemented: None,
            },
            Feature {
                bit: 1,
                code: "DR".to_string(),
                name: "Draft".to_string(),
                provisional: true,
                deprecated: false,
                supplemented: None,
            },
        ];
        let mut s = String::new();
        emit_ids(&mut s, &c);
        emit_feature_bitflags(&mut s, &c);
        // One line each: the Draft attribute, the command, the event, the DR bit.
        assert_eq!(s.matches(PROVISIONAL_DOC).count(), 4, "{s}");
        assert!(
            s.contains(&format!("/// `Draft`.\n    /// {PROVISIONAL_DOC}\n")),
            "{s}"
        );
        assert!(
            !s.contains(&format!("/// `Plain`.\n    /// {PROVISIONAL_DOC}")),
            "{s}"
        );
    }

    #[test]
    fn choice_groups_are_stated_once_per_group() {
        let fields = vec![
            note_field("ValueUnsigned8", false, Some(("a", 1, false, false))),
            note_field("Other", false, None),
            note_field("CookTime", false, Some(("b", 1, true, false))),
            note_field("ValueSigned8", false, Some(("a", 1, false, false))),
            note_field("CookMode", false, Some(("b", 2, true, false))),
            note_field("OneShot", false, Some(("c", 1, false, true))),
        ];
        assert_eq!(
            choice_docs(&fields),
            [
                "Choice group `a`: a sender includes exactly one of `value_unsigned8`, \
                 `value_signed8`. Neither encoding nor decoding checks it.",
                "Choice group `b`: a sender includes at least one of `cook_time`, `cook_mode`. \
                 Neither encoding nor decoding checks it.",
                "Choice group `c`: a sender includes at most one of `one_shot`. Neither encoding \
                 nor decoding checks it.",
            ]
        );
        assert_eq!(
            choice_docs(&[note_field("Other", false, None)]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn struct_docs_state_global_origin_choice_and_provisional_fields() {
        let d = Datatype {
            name: "LocationDescriptorStruct".to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields: vec![
                note_field("A", false, Some(("a", 1, false, false))),
                note_field("B", true, Some(("a", 1, false, false))),
            ],
            global_name: Some("locationdesc".to_string()),
            kept_for: None,
            copied_from: None,
        };
        let mut s = String::new();
        emit_struct(&mut s, &d, &HashSet::new(), &HashSet::new());
        assert!(
            s.starts_with(
                "/// `LocationDescriptorStruct` struct.\n///\n/// Generated from the Matter \
                 global type `locationdesc`.\n///\n/// Choice group `a`: a sender includes \
                 exactly one of `a`, `b`. Neither encoding nor decoding checks it.\n"
            ),
            "{s}"
        );
        assert!(
            s.contains(&format!(
                "/// Field B (tag 0).\n    /// {PROVISIONAL_DOC}\n"
            )),
            "{s}"
        );
        assert_eq!(s.matches(PROVISIONAL_DOC).count(), 1, "{s}");
    }

    // ---- M9-A3 B4 fix wave: supplemented-element rustdoc ----

    fn supplemented(feature: &str, conformance: &str, removed_in: &str, rev: u16) -> Supplemented {
        Supplemented {
            from: "1.4.2".to_string(),
            removed_in: removed_in.to_string(),
            removed_in_revision: rev,
            feature: feature.to_string(),
            conformance: conformance.to_string(),
        }
    }

    fn supplemented_feature(
        code: &str,
        provisional: bool,
        deprecated: bool,
        s: Supplemented,
    ) -> crate::codegen::model::Feature {
        crate::codegen::model::Feature {
            bit: 3,
            code: code.to_string(),
            name: code.to_string(),
            provisional,
            deprecated,
            supplemented: Some(s),
        }
    }

    #[test]
    fn supplemented_elements_carry_their_provenance_instead_of_the_provisional_doc() {
        let sch = supplemented("SCH", "[Zigbee], D", "1.5.1", 10);
        let mut thermostat = cluster_with(vec![], vec![]);
        thermostat.name = "Thermostat".to_string();
        thermostat.features = vec![supplemented_feature("SCH", false, true, sch.clone())];
        assert_eq!(
            element_note(&thermostat, false, true, Some(&sch)).as_deref(),
            Some(
                "Matter 1.4 element (from chip's 1.4.2 data model via the 1.4 supplement); \
                 deprecated in 1.4 itself (`[Zigbee], D`) and removed in Matter 1.5.1 \
                 (Thermostat revision 10)."
            )
        );
        // An element SCH gates: the deprecation is its feature's.
        let gated = supplemented("SCH", "SCH", "1.5.1", 10);
        assert_eq!(
            element_note(&thermostat, false, false, Some(&gated)).as_deref(),
            Some(
                "Matter 1.4 element (from chip's 1.4.2 data model via the 1.4 supplement); \
                 deprecated in 1.4 itself (feature `SCH` is `[Zigbee], D`) and removed in \
                 Matter 1.5.1 (Thermostat revision 10)."
            )
        );
        let abs = supplemented("ABS", "P, O", "1.5", 7);
        let mut window = cluster_with(vec![], vec![]);
        window.name = "WindowCovering".to_string();
        window.features = vec![supplemented_feature("ABS", true, false, abs.clone())];
        let want_abs = "Matter 1.4 element (from chip's 1.4.2 data model via the 1.4 supplement); \
                        provisional in Matter 1.4.2 and removed in Matter 1.5 (WindowCovering \
                        revision 7).";
        assert_eq!(
            element_note(&window, true, false, Some(&abs)).as_deref(),
            Some(want_abs)
        );
        // The generic provisional note never lands on a supplemented element,
        // and a plain element gets no note at all.
        assert_eq!(
            element_note(&window, true, false, None).as_deref(),
            Some(PROVISIONAL_DOC)
        );
        assert_eq!(element_note(&window, false, false, None), None);
        let mut s = String::new();
        emit_feature_bitflags(&mut s, &window);
        assert!(
            s.contains(&format!("        /// ABS (ABS).\n        /// {want_abs}\n")),
            "{s}"
        );
        assert!(!s.contains(PROVISIONAL_DOC), "{s}");
    }

    #[test]
    fn a_kept_enum_says_what_it_interprets() {
        let mut d = enum_dt("MovementStatus", "enum8", &[(0, "Stopped")]);
        d.kept_for = Some("The value of each two-bit field of `X`.".to_string());
        let mut s = String::new();
        emit_enum(&mut s, &d);
        assert!(
            s.starts_with(
                "/// `MovementStatus` (enum8).\n///\n/// The value of each two-bit field of `X`.\n#[derive("
            ),
            "{s}"
        );
    }

    #[test]
    fn a_copied_datatype_names_its_owning_cluster() {
        // M9-A3 B7: Channel's copy of ContentLauncher's AdditionalInfoStruct,
        // and ContentLauncher's of MediaPlayback's CharacteristicEnum.
        let d = Datatype {
            name: "AdditionalInfoStruct".to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields: vec![note_field("Name", false, None)],
            global_name: None,
            kept_for: None,
            copied_from: Some("ContentLauncher".to_string()),
        };
        let mut s = String::new();
        emit_struct(&mut s, &d, &HashSet::new(), &HashSet::new());
        assert!(
            s.starts_with(
                "/// `AdditionalInfoStruct` struct.\n///\n/// A copy of the `ContentLauncher` \
                 cluster's `AdditionalInfoStruct`, which this cluster's elements reference. The \
                 two encode identically but are distinct Rust types.\n"
            ),
            "{s}"
        );
        let mut e = enum_dt("CharacteristicEnum", "enum8", &[(0, "ForcedSubtitles")]);
        e.copied_from = Some("MediaPlayback".to_string());
        let mut s = String::new();
        emit_enum(&mut s, &e);
        assert!(
            s.starts_with(
                "/// `CharacteristicEnum` (enum8).\n///\n/// A copy of the `MediaPlayback` \
                 cluster's `CharacteristicEnum`"
            ),
            "{s}"
        );
        let mut b = enum_dt("FlagsBitmap", "map8", &[]);
        b.kind = "bitmap".to_string();
        b.copied_from = Some("Other".to_string());
        let mut s = String::new();
        emit_bitmap(&mut s, &b);
        assert!(
            s.contains("    /// `FlagsBitmap` (map8).\n    ///\n    /// A copy of the `Other` cluster's `FlagsBitmap`"),
            "{s}"
        );
        // A datatype the cluster owns gets no such line.
        let mut s = String::new();
        emit_enum(&mut s, &enum_dt("OwnEnum", "enum8", &[(0, "A")]));
        assert!(!s.contains("A copy of"), "{s}");
    }

    #[test]
    fn a_field_relaxed_to_nullable_states_why() {
        // M9-A3 B7: MediaPlayback TrackStruct.TrackAttributes, a class-N
        // FIELD_RELAXATIONS entry.
        let mut f = note_field("TrackAttributes", false, None);
        f.ty = "TrackAttributesStruct".to_string();
        f.metatype = "object".to_string();
        f.optional = false;
        f.nullable = true;
        f.nullable_reason = Some("chip's servers may send it null".to_string());
        let d = Datatype {
            fields: vec![f],
            ..struct_dt("TrackStruct")
        };
        let mut s = String::new();
        emit_struct(&mut s, &d, &HashSet::new(), &HashSet::new());
        assert!(
            s.contains(
                "    /// Field TrackAttributes (tag 0).\n    /// Nullable: chip's servers may send it null.\n    pub track_attributes: Nullable<TrackAttributesStruct>,"
            ),
            "{s}"
        );
        assert!(!s.contains("Optional:"), "{s}");
    }

    #[test]
    fn a_response_or_event_field_relaxed_to_nullable_states_why() {
        // M9-A3 B7: responses and events are declared by
        // emit_struct_decl_and_codec, which renders nullableReason too.
        use crate::codegen::model::{CommandDef, EventDef};
        let field = |name: &str| FieldDef {
            nullable: true,
            optional: false,
            nullable_reason: Some("synthetic reason".to_string()),
            ..note_field(name, false, None)
        };
        let command = |id: u32, name: &str, direction: &str, fields: Vec<FieldDef>| CommandDef {
            id,
            name: name.to_string(),
            direction: direction.to_string(),
            response_id: (direction == "request").then_some(1),
            fields,
            provisional: false,
            deprecated: false,
            supplemented: None,
        };
        let mut c = cluster_with(vec![], vec![]);
        c.commands = vec![
            command(0, "GetStatus", "request", vec![]),
            command(1, "GetStatusResponse", "response", vec![field("Status")]),
        ];
        c.events = vec![EventDef {
            id: 0,
            name: "StatusChanged".to_string(),
            priority: "info".to_string(),
            fields: vec![field("NewStatus")],
            provisional: false,
        }];
        let src = generate_cluster(&c);
        for (name, ident) in [("Status", "status"), ("NewStatus", "new_status")] {
            let want = format!(
                "    /// Field {name} (tag 0).\n    /// Nullable: synthetic reason.\n    pub {ident}: Nullable<u8>,"
            );
            assert!(src.contains(&want), "{want}\n---\n{src}");
        }
    }

    // ---- M9-A3 B5: provisional clusters and presence dependencies ----------

    #[test]
    fn provisional_cluster_gets_the_module_paragraph() {
        let mut c = cluster_with(vec![], vec![]);
        let mut plain = String::new();
        emit_header(&mut plain, &c);
        assert!(!plain.contains(PROVISIONAL_CLUSTER_DOC[0]), "{plain}");
        c.provisional = true;
        let mut s = String::new();
        emit_header(&mut s, &c);
        let [first, second, third] = PROVISIONAL_CLUSTER_DOC;
        assert!(
            s.starts_with(&format!(
                "//! Shadowing cluster (0x0050).\n//!\n//! {first}\n//! {second}\n//! {third}\n//!\n//! @generated"
            )),
            "{s}"
        );
        assert_eq!(s.matches(PROVISIONAL_CLUSTER_DOC[0]).count(), 1, "{s}");
    }

    #[test]
    fn presence_dependent_fields_name_their_sibling() {
        let dep = |name: &str, on: &str, present: bool, exclusive: bool| FieldDef {
            required_when: Some(RequiredWhen {
                field: on.to_string(),
                present,
                exclusive,
            }),
            ..note_field(name, false, None)
        };
        let d = Datatype {
            name: "TargetStruct".to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields: vec![
                // A bare conformance (`Endpoint`, `!Endpoint`): mandatory when
                // it holds, disallowed when it does not.
                dep("Node", "Endpoint", true, true),
                dep("Group", "Endpoint", false, true),
                // An otherwise-form (`TargetReheat, [TP]`): only the first half.
                dep("TargetPercentage", "TargetReheat", true, false),
                note_field("Cluster", false, None),
            ],
            global_name: None,
            kept_for: None,
            copied_from: None,
        };
        let mut s = String::new();
        emit_struct(&mut s, &d, &HashSet::new(), &HashSet::new());
        assert!(
            s.contains(
                "/// Field Node (tag 0).\n    /// Required when `endpoint` is present, and must be \
                 omitted when it is absent. Neither encoding nor decoding checks it.\n"
            ),
            "{s}"
        );
        assert!(
            s.contains(
                "/// Field Group (tag 0).\n    /// Required when `endpoint` is absent, and must be \
                 omitted when it is present. Neither encoding nor decoding checks it.\n"
            ),
            "{s}"
        );
        assert!(
            s.contains(
                "/// Field TargetPercentage (tag 0).\n    /// Required when `target_reheat` is \
                 present. Neither encoding nor decoding checks it.\n"
            ),
            "{s}"
        );
        assert_eq!(s.matches("Required when").count(), 3, "{s}");
        assert_eq!(s.matches("must be omitted").count(), 2, "{s}");
    }

    // ---- M9-A3 B6: secret fields stay out of `Debug` ----------------------

    #[test]
    fn a_struct_with_a_secret_field_redacts_it_in_a_hand_written_debug() {
        let key = FieldDef {
            ty: "octstr".to_string(),
            metatype: "bytes".to_string(),
            secret: true,
            ..note_field("EpochKey0", false, None)
        };
        let d = Datatype {
            name: "KeySetStruct".to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields: vec![note_field("Type", false, None), key],
            global_name: None,
            kept_for: None,
            copied_from: None,
        };
        let mut s = String::new();
        emit_struct(&mut s, &d, &HashSet::new(), &HashSet::new());
        assert!(s.contains("#[derive(Clone, PartialEq)]\n"), "{s}");
        assert!(!s.contains("Debug, PartialEq"), "{s}");
        assert!(
            s.contains(&format!(
                "/// Field EpochKey0 (tag 0).\n    /// {SECRET_DOC}\n"
            )),
            "{s}"
        );
        assert!(
            s.contains("impl core::fmt::Debug for KeySetStruct {"),
            "{s}"
        );
        assert!(s.contains("f.debug_struct(\"KeySetStruct\")"), "{s}");
        // A non-secret field prints as the derive would, reserved words
        // included (`r#type` prints as `type`).
        assert!(s.contains(".field(\"type\", &self.r#type)"), "{s}");
        assert!(s.contains(".field(\"epoch_key0\", &\"<redacted>\")"), "{s}");
        assert!(!s.contains("&self.epoch_key0"), "{s}");
    }

    #[test]
    fn redacting_debug_prints_each_field_under_its_derived_name() {
        // `ident` suffixes `self` and prefixes a leading digit, and the derive
        // prints those identifiers as they are; only `r#` is stripped.
        let key = FieldDef {
            ty: "octstr".to_string(),
            metatype: "bytes".to_string(),
            secret: true,
            ..note_field("Self", false, None)
        };
        let fields = vec![
            key,
            note_field("4V5", false, None),
            note_field("Crate", false, None),
            note_field("Type", false, None),
        ];
        let mut s = String::new();
        emit_redacting_debug(&mut s, "OddNames", &fields);
        assert!(s.contains(".field(\"self_\", &\"<redacted>\")"), "{s}");
        assert!(s.contains(".field(\"_4_v5\", &self._4_v5)"), "{s}");
        assert!(s.contains(".field(\"crate_\", &self.crate_)"), "{s}");
        assert!(s.contains(".field(\"type\", &self.r#type)"), "{s}");
    }

    #[test]
    fn a_struct_without_secrets_keeps_the_derived_debug() {
        let d = Datatype {
            name: "PlainStruct".to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields: vec![note_field("Level", false, None)],
            global_name: None,
            kept_for: None,
            copied_from: None,
        };
        let mut s = String::new();
        emit_struct(&mut s, &d, &HashSet::new(), &HashSet::new());
        assert!(s.contains("#[derive(Clone, Debug, PartialEq)]\n"), "{s}");
        assert!(!s.contains("impl core::fmt::Debug"), "{s}");
        assert!(!s.contains(SECRET_DOC), "{s}");
    }
}
