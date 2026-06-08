//! Deserialization + validation of `clusters.json` (the JS↔Rust contract).
//!
//! Validation is intentionally strict: anything the generator cannot map
//! faithfully is a hard error naming the offending element, never a silent
//! skip. The semantic checks here (unknown type strings, duplicate IDs,
//! dangling response IDs, dangling type references) are the Rust-side half
//! of the contract the dump script enforces on the JS side.

// Structs and functions are scaffolding used by the emitter (next task).

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
}

/// A cluster attribute.
#[derive(Debug, Deserialize)]
pub struct Attribute {
    /// Attribute ID.
    pub id: u32,
    /// `PascalCase` attribute name.
    pub name: String,
    /// Matter type string (see [`rustgen::types`]).
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
}

/// A struct or command field.
#[derive(Debug, Deserialize)]
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

        // Struct-field type references.
        for d in &c.datatypes {
            for f in &d.fields {
                check_type(
                    &c.name,
                    &f.name,
                    &f.ty,
                    f.entry_type.as_deref(),
                    &datatype_names,
                )?;
            }
        }
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
