//! Deserialization + validation of `clusters.json` (the JS↔Rust contract).
//!
//! Validation is intentionally strict: anything the generator cannot map
//! faithfully is a hard error naming the offending element, never a silent
//! skip. The semantic checks here (unknown type strings, duplicate IDs,
//! dangling response IDs, dangling type references, and `mandatoryOnWrite`
//! appearing anywhere but an optional fabric-sensitive field of a
//! fabric-scoped struct, and a class-C `meta.relaxed` entry on a field we
//! encode) are the Rust-side half of the contract the dump script enforces
//! on the JS side.

use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

/// Top-level `clusters.json` document.
#[derive(Debug, Deserialize)]
pub struct Model {
    /// Provenance header (model version, exclusions). Not used by codegen
    /// beyond being carried for audit.
    pub meta: serde_json::Value,
    /// The clusters to generate.
    pub clusters: Vec<Cluster>,
}

/// One cluster definition.
#[derive(Debug, Deserialize)]
pub struct Cluster {
    /// Cluster ID (e.g. `0x0006`).
    pub id: u32,
    /// `PascalCase` cluster name (e.g. `OnOff`).
    pub name: String,
    /// Cluster revision.
    pub revision: u16,
    /// Feature bits.
    #[serde(default)]
    pub features: Vec<Feature>,
    /// Cluster-specific attributes (globals already stripped by the dump).
    pub attributes: Vec<Attribute>,
    /// Request and response commands.
    pub commands: Vec<CommandDef>,
    /// Cluster events. Empty for clusters whose events the dump script has
    /// not (yet) allowlisted — event codegen is rolled out per cluster.
    #[serde(default)]
    pub events: Vec<EventDef>,
    /// Cluster-local datatypes (enums, bitmaps, structs).
    pub datatypes: Vec<Datatype>,
}

/// A feature-map bit.
#[derive(Debug, Deserialize)]
pub struct Feature {
    /// Bit position.
    pub bit: u8,
    /// Short code (e.g. `LT`).
    pub code: String,
    /// Long name (e.g. `Lighting`).
    pub name: String,
    /// Provisional in the specification (see [`FieldDef::provisional`]).
    #[serde(default)]
    pub provisional: bool,
}

/// A cluster attribute.
#[derive(Debug, Deserialize)]
// A one-to-one serde mirror of a clusters.json attribute object (as FieldDef).
#[allow(clippy::struct_excessive_bools)]
pub struct Attribute {
    /// Attribute ID.
    pub id: u32,
    /// `PascalCase` attribute name.
    pub name: String,
    /// Matter type string (see [`crate::codegen::rustgen::types`]).
    #[serde(rename = "type")]
    pub ty: String,
    /// Categorical kind (`integer`, `enum`, `array`, …).
    pub metatype: String,
    /// List element type, when `metatype == "array"`.
    #[serde(default, rename = "entryType")]
    pub entry_type: Option<String>,
    /// Wire-null allowed (quality `X`).
    pub nullable: bool,
    /// Tag may be absent (conformance `O`).
    pub optional: bool,
    /// Writable (access `W`).
    pub writable: bool,
    /// Provisional in the specification (see [`FieldDef::provisional`]).
    #[serde(default)]
    pub provisional: bool,
}

/// A request or response command.
#[derive(Debug, Deserialize)]
pub struct CommandDef {
    /// Command ID.
    pub id: u32,
    /// `PascalCase` command name.
    pub name: String,
    /// `"request"` or `"response"`.
    pub direction: String,
    /// For requests: ID of the paired response command, or `null` (default
    /// status response). Always `null` for responses.
    #[serde(rename = "responseId")]
    pub response_id: Option<u32>,
    /// Command fields.
    pub fields: Vec<FieldDef>,
    /// Provisional in the specification (see [`FieldDef::provisional`]).
    #[serde(default)]
    pub provisional: bool,
}

/// A cluster event.
#[derive(Debug, Deserialize)]
pub struct EventDef {
    /// Event ID.
    pub id: u32,
    /// `PascalCase` event name.
    pub name: String,
    /// Spec priority (`debug`, `info`, `critical`). Carried for rustdoc.
    pub priority: String,
    /// Event payload fields (an anonymous structure of context-tagged
    /// fields on the wire — the same shape as a response command payload).
    pub fields: Vec<FieldDef>,
    /// Provisional in the specification (see [`FieldDef::provisional`]).
    #[serde(default)]
    pub provisional: bool,
}

/// A struct or command field.
#[derive(Debug, Deserialize)]
// A one-to-one serde mirror of a clusters.json field object: each flag is an
// independent JSON key, so folding them into an enum would not model it.
#[allow(clippy::struct_excessive_bools)]
pub struct FieldDef {
    /// Field tag number.
    pub id: u32,
    /// `PascalCase` field name.
    pub name: String,
    /// Matter type string.
    #[serde(rename = "type")]
    pub ty: String,
    /// Categorical kind.
    pub metatype: String,
    /// List element type, when `metatype == "array"`.
    #[serde(default, rename = "entryType")]
    pub entry_type: Option<String>,
    /// Wire-null allowed.
    pub nullable: bool,
    /// Tag may be absent.
    pub optional: bool,
    /// The field has the fabric-sensitive (`S`) access quality: in a
    /// fabric-scoped struct (one carrying field 254, `FabricIndex`) a device
    /// withholds it for another fabric's entries on an unfiltered read (M9-A3
    /// spec §5.4). The dump records it on **datatype struct** fields only
    /// (never on event or command payload fields); it drives the generated
    /// "`None` when withheld" rustdoc. Absent in the JSON means `false`.
    #[serde(default, rename = "fabricSensitive")]
    pub fabric_sensitive: bool,
    /// The dump relaxed this field from mandatory to `optional` only for
    /// decoding (M9-A3 spec §5.4: a fabric-sensitive field the device
    /// withholds for other fabrics' entries). On write it is still required,
    /// so every encoder of its struct refuses `None` instead of omitting it.
    /// A field optional in the model itself never carries it. Absent in the
    /// JSON means `false`.
    #[serde(default, rename = "mandatoryOnWrite")]
    pub mandatory_on_write: bool,
    /// The specification marks the element provisional (conformance `P`, or
    /// an otherwise-form starting with `P` such as `P, WATTS`): a later
    /// revision may change or remove it. Drives a generated rustdoc line.
    /// Absent in the JSON means `false`.
    #[serde(default)]
    pub provisional: bool,
    /// The field's choice group (conformance `O.a`, `O.a+`, `[F].b+`): how
    /// many fields of the group a sender includes. The generated encoders do
    /// not enforce it, so it drives a generated rustdoc line.
    #[serde(default)]
    pub choice: Option<Choice>,
}

/// A choice-conformance group (Matter Core spec 7.3: `O.a` = exactly one field
/// of group `a`; `O.a+` = at least one; `O.a-` = at most one).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Choice {
    /// Group name (`a`, `b`, ...), shared by the fields of one group.
    pub group: String,
    /// How many fields of the group the sender includes.
    pub count: u32,
    /// `true`: at least `count` (`O.a+`).
    #[serde(rename = "orMore")]
    pub or_more: bool,
    /// `true`: at most `count` (`O.a-`). Neither flag: exactly `count`.
    #[serde(default, rename = "orLess")]
    pub or_less: bool,
}

/// A cluster-local datatype.
#[derive(Debug, Deserialize)]
pub struct Datatype {
    /// `PascalCase` datatype name.
    pub name: String,
    /// Underlying base (`enum8`, `map8`, `struct`, …).
    pub base: String,
    /// Discriminator: `"enum"`, `"bitmap"`, `"struct"`, or `"scalar"`.
    pub kind: String,
    /// Enum members (when `kind == "enum"`).
    #[serde(default)]
    pub values: Vec<EnumValue>,
    /// Bitmap bits (when `kind == "bitmap"`).
    #[serde(default)]
    pub bits: Vec<BitDef>,
    /// Struct fields (when `kind == "struct"`).
    #[serde(default)]
    pub fields: Vec<FieldDef>,
    /// The model's own name when the dump inlined a lowercase model-global
    /// type under a generated one (`locationdesc` as
    /// `LocationDescriptorStruct`). Drives a generated rustdoc line.
    #[serde(default, rename = "globalName")]
    pub global_name: Option<String>,
}

/// An enum member.
#[derive(Debug, Deserialize)]
pub struct EnumValue {
    /// Discriminant.
    pub value: u32,
    /// `PascalCase` member name.
    pub name: String,
}

/// A bitmap bit.
#[derive(Debug, Deserialize)]
pub struct BitDef {
    /// Bit position (single-bit fields only; ranges decode to `None`).
    pub bit: Option<u8>,
    /// `PascalCase` bit name.
    pub name: String,
}

/// One `meta.relaxed` entry: a field the dump made optional although the model
/// does not (`class` `P`: fabric-sensitive, §5.4; `W`: a recorded type
/// widening, §5.3; `C`: a conditional conformance the §3.1 rule relaxes). Only
/// the keys [`validate`] checks are parsed; the rest of `meta` stays an opaque
/// [`serde_json::Value`].
#[derive(Debug, Deserialize)]
pub struct Relaxation {
    /// `PascalCase` name of the cluster the field belongs to.
    pub cluster: String,
    /// `<Owner>.<Field>`: the owning command, event or struct, then the field.
    pub element: String,
    /// Relaxation class (`P`, `W` or `C`).
    pub class: String,
}

/// Load and validate `clusters.json` from `path`.
///
/// # Errors
///
/// Returns a human-readable message if the file is unreadable, the JSON is
/// malformed, or any [`validate`] check fails.
pub fn load(path: &Path) -> Result<Model, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let model: Model =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
    validate(&model)?;
    Ok(model)
}

/// Strict semantic validation. See module docs for what is checked.
///
/// # Errors
///
/// Returns a message naming the first offending element.
pub fn validate(model: &Model) -> Result<(), String> {
    for c in &model.clusters {
        let datatype_names: HashSet<&str> = c.datatypes.iter().map(|d| d.name.as_str()).collect();

        // Duplicate attribute IDs.
        let mut attr_ids = HashSet::new();
        for a in &c.attributes {
            if !attr_ids.insert(a.id) {
                return Err(format!("{}: duplicate attribute id {}", c.name, a.id));
            }
            check_type(
                &c.name,
                &a.name,
                &a.ty,
                a.entry_type.as_deref(),
                &datatype_names,
            )?;
        }

        // Duplicate command IDs *within a direction* (request and response may
        // legitimately share an id).
        let mut req_ids = HashSet::new();
        let mut resp_ids = HashSet::new();
        for cmd in &c.commands {
            let set = if cmd.direction == "response" {
                &mut resp_ids
            } else {
                &mut req_ids
            };
            if !set.insert(cmd.id) {
                return Err(format!(
                    "{}: duplicate {} command id {}",
                    c.name, cmd.direction, cmd.id
                ));
            }
            for f in &cmd.fields {
                check_type(
                    &c.name,
                    &f.name,
                    &f.ty,
                    f.entry_type.as_deref(),
                    &datatype_names,
                )?;
                reject_payload_write_marker(&c.name, &cmd.name, f, "a command")?;
            }
        }

        // Duplicate event IDs.
        let mut event_ids = HashSet::new();
        for ev in &c.events {
            if !event_ids.insert(ev.id) {
                return Err(format!("{}: duplicate event id {}", c.name, ev.id));
            }
            for f in &ev.fields {
                check_type(
                    &c.name,
                    &f.name,
                    &f.ty,
                    f.entry_type.as_deref(),
                    &datatype_names,
                )?;
                reject_payload_write_marker(&c.name, &ev.name, f, "an event")?;
            }
        }

        // Dangling responseId: every request's responseId must name a real
        // response command in this cluster.
        for cmd in &c.commands {
            if let Some(rid) = cmd.response_id {
                let found = c
                    .commands
                    .iter()
                    .any(|o| o.direction == "response" && o.id == rid);
                if !found {
                    return Err(format!(
                        "{}: command {} has dangling responseId {}",
                        c.name, cmd.name, rid
                    ));
                }
            }
        }

        // Struct-field type references, and where `mandatoryOnWrite` may sit.
        for d in &c.datatypes {
            for f in &d.fields {
                check_type(
                    &c.name,
                    &f.name,
                    &f.ty,
                    f.entry_type.as_deref(),
                    &datatype_names,
                )?;
                check_struct_write_marker(&c.name, d, f)?;
            }
        }
    }
    check_conditional_relaxations(model)
}

/// A class-C relaxation (a field whose conformance is conditional, which the
/// §3.1 rule dumps optional) is safe only on a field we **decode**: a field we
/// send would make its encoder take an `Option` and could silently omit a
/// field the model says is mandatory. So every class-C `meta.relaxed` entry
/// must resolve to a response command, event, or decode-only struct field —
/// never a request command field, nor a field of a struct the emitter encodes
/// ([`encoded_struct_names`](crate::codegen::rustgen::emit_codecs::encoded_struct_names),
/// the emitter's own rule). The dump enforces the same on regeneration; this
/// half runs on every `codegen --check`. An entry naming no generated field is
/// an error too, so a stale or misspelled entry cannot disable the check.
fn check_conditional_relaxations(model: &Model) -> Result<(), String> {
    // Every class-C entry is written by the dump, so the fix is never a
    // hand edit of clusters.json: point at the rule that produced it.
    const FIX_AT: &str = "class-C entries come from the spec §3.1 rule in \
        xtask/scripts/dump-model/index.js (isConditionalRelaxation, checkConditionalRelaxations): \
        fix the model or the dump and regenerate, not clusters.json";
    let relaxed: Vec<Relaxation> = match model.meta.get("relaxed") {
        None => Vec::new(),
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| format!("meta.relaxed: malformed entry: {e}"))?,
    };
    for r in relaxed.iter().filter(|r| r.class == "C") {
        let at = format!("{}.{}", r.cluster, r.element);
        let c = model
            .clusters
            .iter()
            .find(|c| c.name == r.cluster)
            .ok_or_else(|| {
                format!(
                    "{at}: class-C meta.relaxed entry names {}, not a generated cluster; {FIX_AT}",
                    r.cluster
                )
            })?;
        let (owner, field) = r.element.split_once('.').ok_or_else(|| {
            format!("{at}: class-C meta.relaxed element is not <Owner>.<Field>; {FIX_AT}")
        })?;
        let has = |fields: &[FieldDef]| fields.iter().any(|f| f.name == field);
        let commands = |direction: &str| {
            c.commands
                .iter()
                .any(|cmd| cmd.direction == direction && cmd.name == owner && has(&cmd.fields))
        };
        if commands("request") {
            return Err(format!(
                "{at}: class-C relaxation (conditional conformance dumped optional) of a request command field; \
                 the encoder would take an Option and could omit a field the model makes mandatory — review it; {FIX_AT}"
            ));
        }
        let structs = |pred: &dyn Fn(&Datatype) -> bool| {
            c.datatypes
                .iter()
                .any(|d| d.kind == "struct" && d.name == owner && has(&d.fields) && pred(d))
        };
        let encoded = crate::codegen::rustgen::emit_codecs::encoded_struct_names(c);
        if structs(&|d| encoded.contains(d.name.as_str())) {
            return Err(format!(
                "{at}: class-C relaxation (conditional conformance dumped optional) of a field of {owner}, \
                 which the emitter encodes; its encoder could omit a field the model makes mandatory — review it; {FIX_AT}"
            ));
        }
        let decoded = commands("response")
            || c.events
                .iter()
                .any(|ev| ev.name == owner && has(&ev.fields))
            || structs(&|_| true);
        if !decoded {
            return Err(format!(
                "{at}: class-C meta.relaxed entry names no command, event or struct field of {}; {FIX_AT}",
                c.name
            ));
        }
    }
    Ok(())
}

/// `mandatoryOnWrite` (M9-A3 spec §5.4) is legal only on a datatype struct
/// field that is `optional` (relaxed for decode), `fabricSensitive`, and in a
/// struct carrying field 254 (`FabricIndex`, the fabric-scoped signal). The
/// emitter's encoder guard keys only on field 254 plus the marker, so a marker
/// elsewhere would be ignored or misgenerate: in a struct without field 254 it
/// is ignored and the encoder omits a `None` the device must receive (the
/// hazard §5.4 closes); on a non-optional field the guard does not compile; on
/// a non-sensitive optional field it refuses a `None` that is legal to omit.
/// Reject it.
fn check_struct_write_marker(cluster: &str, d: &Datatype, f: &FieldDef) -> Result<(), String> {
    if !f.mandatory_on_write {
        return Ok(());
    }
    let at = format!("{cluster}.{}.{}", d.name, f.name);
    if d.kind != "struct" {
        return Err(format!(
            "{at}: mandatoryOnWrite on a field of `{}` datatype (not a struct)",
            d.kind
        ));
    }
    if !f.optional {
        return Err(format!(
            "{at}: mandatoryOnWrite on a field that is not optional (the marker means \"relaxed to optional for decode only\")"
        ));
    }
    if !f.fabric_sensitive {
        return Err(format!(
            "{at}: mandatoryOnWrite on a field that is not fabricSensitive"
        ));
    }
    if !d.fields.iter().any(|g| g.id == 254) {
        return Err(format!(
            "{at}: mandatoryOnWrite in a struct with no field 254 (FabricIndex), i.e. not fabric-scoped"
        ));
    }
    Ok(())
}

/// Event and command payload fields never carry `mandatoryOnWrite`: the
/// encoder guard exists only for datatype structs (spec §5.4, "Events are
/// exempt"; request payloads are never write-guarded).
fn reject_payload_write_marker(
    cluster: &str,
    payload: &str,
    f: &FieldDef,
    kind: &str,
) -> Result<(), String> {
    if f.mandatory_on_write {
        return Err(format!(
            "{cluster}.{payload}.{}: mandatoryOnWrite on {kind} field (allowed only on datatype struct fields)",
            f.name
        ));
    }
    Ok(())
}

/// A type string (and, for lists, its element type) must be a known
/// primitive/semantic global or a datatype defined in this cluster.
fn check_type(
    cluster: &str,
    element: &str,
    ty: &str,
    entry: Option<&str>,
    datatypes: &HashSet<&str>,
) -> Result<(), String> {
    if ty == "list" {
        let entry = entry.ok_or_else(|| format!("{cluster}.{element}: list without entryType"))?;
        return check_type(cluster, element, entry, None, datatypes);
    }
    if crate::codegen::rustgen::types::is_known_type(ty) || datatypes.contains(ty) {
        Ok(())
    } else {
        Err(format!(
            "{cluster}.{element}: unknown type `{ty}` (not a known scalar/semantic type or a datatype of this cluster)"
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn cluster(json: serde_json::Value) -> Cluster {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn accepts_a_minimal_valid_cluster() {
        let m = Model {
            meta: serde_json::Value::Null,
            clusters: vec![cluster(serde_json::json!({
                "id": 6, "name": "OnOff", "revision": 6,
                "features": [], "datatypes": [],
                "attributes": [{ "id": 0, "name": "OnOff", "type": "bool",
                    "metatype": "boolean", "nullable": false, "optional": false, "writable": false }],
                "commands": []
            }))],
        };
        assert!(validate(&m).is_ok());
    }

    #[test]
    fn rejects_unknown_type() {
        let m = Model {
            meta: serde_json::Value::Null,
            clusters: vec![cluster(serde_json::json!({
                "id": 6, "name": "OnOff", "revision": 6, "features": [], "datatypes": [], "commands": [],
                "attributes": [{ "id": 0, "name": "Mystery", "type": "frobnicator",
                    "metatype": "integer", "nullable": false, "optional": false, "writable": false }]
            }))],
        };
        let err = validate(&m).unwrap_err();
        assert!(err.contains("unknown type `frobnicator`"), "got: {err}");
    }

    #[test]
    fn rejects_duplicate_attribute_id() {
        let m = Model {
            meta: serde_json::Value::Null,
            clusters: vec![cluster(serde_json::json!({
                "id": 6, "name": "OnOff", "revision": 6, "features": [], "datatypes": [], "commands": [],
                "attributes": [
                    { "id": 0, "name": "A", "type": "bool", "metatype": "boolean", "nullable": false, "optional": false, "writable": false },
                    { "id": 0, "name": "B", "type": "bool", "metatype": "boolean", "nullable": false, "optional": false, "writable": false }
                ]
            }))],
        };
        assert!(validate(&m)
            .unwrap_err()
            .contains("duplicate attribute id 0"));
    }

    #[test]
    fn rejects_dangling_response_id() {
        let m = Model {
            meta: serde_json::Value::Null,
            clusters: vec![cluster(serde_json::json!({
                "id": 6, "name": "OnOff", "revision": 6, "features": [], "datatypes": [], "attributes": [],
                "commands": [{ "id": 0, "name": "Go", "direction": "request", "responseId": 99, "fields": [] }]
            }))],
        };
        assert!(validate(&m).unwrap_err().contains("dangling responseId 99"));
    }

    #[test]
    fn accepts_a_cluster_with_events() {
        let m = Model {
            meta: serde_json::Value::Null,
            clusters: vec![cluster(serde_json::json!({
                "id": 0x3b, "name": "Switch", "revision": 2, "features": [], "datatypes": [],
                "attributes": [], "commands": [],
                "events": [{ "id": 6, "name": "MultiPressComplete", "priority": "info",
                    "fields": [{ "id": 1, "name": "TotalNumberOfPressesCounted", "type": "uint8",
                        "metatype": "integer", "nullable": false, "optional": false }] }]
            }))],
        };
        assert!(validate(&m).is_ok());
    }

    #[test]
    fn rejects_duplicate_event_id() {
        let m = Model {
            meta: serde_json::Value::Null,
            clusters: vec![cluster(serde_json::json!({
                "id": 0x3b, "name": "Switch", "revision": 2, "features": [], "datatypes": [],
                "attributes": [], "commands": [],
                "events": [
                    { "id": 1, "name": "InitialPress", "priority": "info", "fields": [] },
                    { "id": 1, "name": "LongPress", "priority": "info", "fields": [] }
                ]
            }))],
        };
        assert!(validate(&m).unwrap_err().contains("duplicate event id 1"));
    }

    #[test]
    fn rejects_unknown_event_field_type() {
        let m = Model {
            meta: serde_json::Value::Null,
            clusters: vec![cluster(serde_json::json!({
                "id": 0x3b, "name": "Switch", "revision": 2, "features": [], "datatypes": [],
                "attributes": [], "commands": [],
                "events": [{ "id": 0, "name": "SwitchLatched", "priority": "info",
                    "fields": [{ "id": 0, "name": "NewPosition", "type": "frobnicator",
                        "metatype": "integer", "nullable": false, "optional": false }] }]
            }))],
        };
        assert!(validate(&m)
            .unwrap_err()
            .contains("unknown type `frobnicator`"));
    }

    #[test]
    fn field_def_reads_the_write_markers_and_defaults_them_to_false() {
        let marked: FieldDef = serde_json::from_value(serde_json::json!({
            "id": 1, "name": "Data", "type": "octstr", "metatype": "bytes",
            "nullable": false, "optional": true, "fabricSensitive": true
        }))
        .unwrap();
        assert!(marked.fabric_sensitive);
        let plain: FieldDef = serde_json::from_value(serde_json::json!({
            "id": 254, "name": "FabricIndex", "type": "fabric-idx", "metatype": "integer",
            "nullable": false, "optional": false
        }))
        .unwrap();
        assert!(!plain.fabric_sensitive);
        assert!(!plain.mandatory_on_write);
        let relaxed: FieldDef = serde_json::from_value(serde_json::json!({
            "id": 1, "name": "Data", "type": "octstr", "metatype": "bytes",
            "nullable": false, "optional": true, "fabricSensitive": true,
            "mandatoryOnWrite": true
        }))
        .unwrap();
        assert!(relaxed.mandatory_on_write);
        assert!(!marked.mandatory_on_write);
    }

    // ---- mandatoryOnWrite placement (M9-A3 spec §5.4) -------------------

    /// The marked field as the dump writes it: optional for decode,
    /// fabric-sensitive, still required on write.
    fn guarded_field() -> serde_json::Value {
        serde_json::json!({ "id": 1, "name": "Data", "type": "octstr", "metatype": "bytes",
            "nullable": false, "optional": true, "fabricSensitive": true,
            "mandatoryOnWrite": true })
    }

    fn fabric_index_field() -> serde_json::Value {
        serde_json::json!({ "id": 254, "name": "FabricIndex", "type": "fabric-idx",
            "metatype": "integer", "nullable": false, "optional": false })
    }

    /// A one-cluster model whose only datatype is `kind` `ExtStruct` with
    /// `fields`, plus the given events and commands.
    fn model_with(
        kind: &str,
        fields: &[serde_json::Value],
        events: &serde_json::Value,
        commands: &serde_json::Value,
    ) -> Model {
        Model {
            meta: serde_json::Value::Null,
            clusters: vec![cluster(serde_json::json!({
                "id": 0x1f, "name": "AccessControl", "revision": 2, "features": [],
                "attributes": [], "commands": commands, "events": events,
                "datatypes": [{ "name": "ExtStruct", "base": "struct", "kind": kind,
                    "fields": fields }]
            }))],
        }
    }

    fn struct_model(fields: &[serde_json::Value]) -> Model {
        model_with(
            "struct",
            fields,
            &serde_json::json!([]),
            &serde_json::json!([]),
        )
    }

    #[test]
    fn accepts_mandatory_on_write_on_an_optional_sensitive_field_of_a_fabric_scoped_struct() {
        let m = struct_model(&[guarded_field(), fabric_index_field()]);
        assert_eq!(validate(&m), Ok(()));
    }

    #[test]
    fn rejects_mandatory_on_write_on_a_non_optional_field() {
        let mut f = guarded_field();
        f["optional"] = serde_json::json!(false);
        let err = validate(&struct_model(&[f, fabric_index_field()])).unwrap_err();
        assert!(
            err.contains("AccessControl.ExtStruct.Data") && err.contains("not optional"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_mandatory_on_write_without_fabric_sensitive() {
        let mut f = guarded_field();
        f["fabricSensitive"] = serde_json::json!(false);
        let err = validate(&struct_model(&[f, fabric_index_field()])).unwrap_err();
        assert!(
            err.contains("AccessControl.ExtStruct.Data") && err.contains("not fabricSensitive"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_mandatory_on_write_in_a_struct_without_field_254() {
        let err = validate(&struct_model(&[guarded_field()])).unwrap_err();
        assert!(
            err.contains("AccessControl.ExtStruct.Data") && err.contains("no field 254"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_mandatory_on_write_in_a_non_struct_datatype() {
        let m = model_with(
            "enum",
            &[guarded_field(), fabric_index_field()],
            &serde_json::json!([]),
            &serde_json::json!([]),
        );
        let err = validate(&m).unwrap_err();
        assert!(
            err.contains("AccessControl.ExtStruct.Data") && err.contains("not a struct"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_mandatory_on_write_on_an_event_field() {
        let m = model_with(
            "struct",
            &[],
            &serde_json::json!([{ "id": 0, "name": "EntryChanged", "priority": "info",
                "fields": [guarded_field(), fabric_index_field()] }]),
            &serde_json::json!([]),
        );
        let err = validate(&m).unwrap_err();
        assert!(
            err.contains("AccessControl.EntryChanged.Data") && err.contains("event field"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_mandatory_on_write_on_a_command_field() {
        let m = model_with(
            "struct",
            &[],
            &serde_json::json!([]),
            &serde_json::json!([{ "id": 0, "name": "Review", "direction": "request",
                "responseId": null, "fields": [guarded_field(), fabric_index_field()] }]),
        );
        let err = validate(&m).unwrap_err();
        assert!(
            err.contains("AccessControl.Review.Data") && err.contains("command field"),
            "got: {err}"
        );
    }

    // ---- class-C relaxations are decode-only (M9-A3 B3) -----------------

    /// A ModeBase-shaped cluster: a request command, its response, a
    /// scalar-only struct (encoded: write-capable), a struct with a list field
    /// that a request command reaches (encoded: command-reachable), and a
    /// struct with a list field nothing sends (decode-only), and an event, with
    /// one class-C `meta.relaxed` entry on `element`.
    fn relaxed_model(element: &str) -> Model {
        let u8_field = |id: u32, name: &str| {
            serde_json::json!({ "id": id, "name": name, "type": "uint8",
                "metatype": "integer", "nullable": false, "optional": true })
        };
        let list_field = serde_json::json!({ "id": 1, "name": "Items", "type": "list",
            "entryType": "uint8", "metatype": "array", "nullable": false, "optional": false });
        let reach_field = serde_json::json!({ "id": 1, "name": "Target", "type": "SentStruct",
            "metatype": "object", "nullable": false, "optional": false });
        Model {
            meta: serde_json::json!({ "specRevision": "1.4", "relaxed": [
                { "cluster": "RvcRunMode", "element": element, "class": "C",
                  "reason": "conditional conformance" }
            ] }),
            clusters: vec![cluster(serde_json::json!({
                "id": 0x54, "name": "RvcRunMode", "revision": 3, "features": [],
                // M9-A3 B4: a scalar struct is encoded only when a writable
                // attribute (or a request) reaches it.
                "attributes": [
                    { "id": 0, "name": "Scalars", "type": "list", "entryType": "ScalarStruct",
                      "metatype": "array", "nullable": false, "optional": false, "writable": true }
                ],
                "commands": [
                    { "id": 0, "name": "ChangeToMode", "direction": "request", "responseId": 1,
                      "fields": [u8_field(0, "NewMode"), reach_field] },
                    { "id": 1, "name": "ChangeToModeResponse", "direction": "response",
                      "responseId": null, "fields": [u8_field(0, "Status"), u8_field(1, "StatusText")] }
                ],
                "events": [
                    { "id": 0, "name": "ModeChanged", "priority": "info",
                      "fields": [u8_field(0, "NewMode")] }
                ],
                "datatypes": [
                    { "name": "ScalarStruct", "base": "struct", "kind": "struct",
                      "fields": [u8_field(0, "Label")] },
                    { "name": "SentStruct", "base": "struct", "kind": "struct",
                      "fields": [u8_field(0, "Label"), list_field.clone()] },
                    { "name": "ReadStruct", "base": "struct", "kind": "struct",
                      "fields": [u8_field(0, "Label"), list_field] }
                ]
            }))],
        }
    }

    #[test]
    fn rejects_a_conditional_relaxation_of_a_request_command_field() {
        let err = validate(&relaxed_model("ChangeToMode.NewMode")).unwrap_err();
        assert!(
            err.contains("RvcRunMode.ChangeToMode.NewMode") && err.contains("request command"),
            "got: {err}"
        );
        // Points at the source of the relaxation, not at clusters.json.
        assert!(
            err.contains("xtask/scripts/dump-model/index.js") && err.contains("not clusters.json"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_a_conditional_relaxation_of_a_writable_attribute_struct_field() {
        let err = validate(&relaxed_model("ScalarStruct.Label")).unwrap_err();
        assert!(
            err.contains("RvcRunMode.ScalarStruct.Label") && err.contains("encodes"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_a_conditional_relaxation_of_a_command_reachable_struct_field() {
        let err = validate(&relaxed_model("SentStruct.Label")).unwrap_err();
        assert!(
            err.contains("RvcRunMode.SentStruct.Label") && err.contains("encodes"),
            "got: {err}"
        );
    }

    #[test]
    fn accepts_a_conditional_relaxation_of_a_response_or_decode_only_struct_field() {
        assert_eq!(
            validate(&relaxed_model("ChangeToModeResponse.StatusText")),
            Ok(())
        );
        assert_eq!(validate(&relaxed_model("ReadStruct.Label")), Ok(()));
    }

    #[test]
    fn accepts_a_conditional_relaxation_of_an_event_field() {
        // Events are decode-only: a relaxed event field never reaches an encoder.
        assert_eq!(validate(&relaxed_model("ModeChanged.NewMode")), Ok(()));
    }

    #[test]
    fn rejects_a_conditional_relaxation_naming_no_field() {
        // A stale or misspelled entry must not silently disable the check.
        let err = validate(&relaxed_model("ChangeToMode.NoSuchField")).unwrap_err();
        assert!(
            err.contains("RvcRunMode.ChangeToMode.NoSuchField") && err.contains("names no"),
            "got: {err}"
        );
        let mut m = relaxed_model("ChangeToModeResponse.StatusText");
        m.meta["relaxed"][0]["cluster"] = serde_json::json!("OvenMode");
        let err = validate(&m).unwrap_err();
        assert!(
            err.contains("OvenMode.ChangeToModeResponse.StatusText")
                && err.contains("not a generated cluster"),
            "got: {err}"
        );
    }

    #[test]
    fn other_relaxation_classes_are_not_checked_here() {
        // Class P (fabric-sensitive, mandatoryOnWrite-guarded) legitimately
        // sits on encoded struct fields; only class C is decode-only.
        let mut m = relaxed_model("ScalarStruct.Label");
        m.meta["relaxed"][0]["class"] = serde_json::json!("P");
        assert_eq!(validate(&m), Ok(()));
    }

    #[test]
    fn list_resolves_entry_type() {
        let m = Model {
            meta: serde_json::Value::Null,
            clusters: vec![cluster(serde_json::json!({
                "id": 0x1d, "name": "Descriptor", "revision": 3, "features": [], "datatypes": [], "commands": [],
                "attributes": [{ "id": 1, "name": "ServerList", "type": "list", "entryType": "cluster-id",
                    "metatype": "array", "nullable": false, "optional": false, "writable": false }]
            }))],
        };
        assert!(validate(&m).is_ok());
    }
}
