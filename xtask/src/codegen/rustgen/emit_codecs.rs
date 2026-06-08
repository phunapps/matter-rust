//! Codec emission: struct, attribute, and command encode/decode.

use crate::codegen::model::{Attribute, Cluster, CommandDef, Datatype, FieldDef};
use crate::codegen::rustgen::emit::line;
use crate::codegen::rustgen::types::{base_type, ident, rust_type, snake, Position};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Name → datatype lookup for the cluster being emitted, so the scalar codec
/// can resolve a named enum/bitmap's backing width (and tell named types from
/// bare `enum8`/`map8`/`status` scalars).
type DatatypeMap<'a> = HashMap<&'a str, &'a Datatype>;

/// Emit every codec for the cluster.
pub fn emit_codecs(s: &mut String, c: &Cluster) {
    let dts: DatatypeMap<'_> = c.datatypes.iter().map(|d| (d.name.as_str(), d)).collect();
    for d in &c.datatypes {
        if d.kind == "struct" {
            emit_struct_codec(s, d, &dts);
        }
    }
    for a in &c.attributes {
        emit_attr_decoder(s, a, &dts);
        if a.writable {
            emit_attr_encoder(s, a, &dts);
        }
    }
    for cmd in &c.commands {
        if cmd.direction == "request" {
            emit_command_encoder(s, cmd, &dts);
        } else {
            emit_response_decoder(s, cmd, &dts);
        }
    }
}

/// Backing Rust integer for a NAMED enum/bitmap datatype, or `None` if `ty`
/// is not a named datatype in this cluster (i.e. a bare scalar like `enum8`,
/// `map8`, `status`).
fn named_backing(ty: &str, dts: &DatatypeMap<'_>) -> Option<&'static str> {
    let d = dts.get(ty)?;
    if d.kind != "enum" && d.kind != "bitmap" {
        return None;
    }
    Some(match d.base.as_str() {
        "enum16" | "map16" => "u16",
        "map32" => "u32",
        _ => "u8",
    })
}

/// Read one TLV scalar into a Rust value expression. Returns
/// `(match_pattern, build_expr)` for use inside a decoder arm.
fn read_scalar(
    metatype: &str,
    ty: &str,
    entry: Option<&str>,
    context: &str,
    dts: &DatatypeMap<'_>,
) -> (String, String) {
    match metatype {
        "boolean" => ("Value::Bool(v)".into(), "v".into()),
        "integer" => {
            let rust = base_type(ty, entry);
            let pat = if rust.starts_with('i') {
                "Value::Int(v)"
            } else {
                "Value::Uint(v)"
            };
            (
                pat.into(),
                format!(
                    "{rust}::try_from(v).map_err(|_| ClusterError::InvalidLength(\"{context}\"))?"
                ),
            )
        }
        "string" => ("Value::Utf8(v)".into(), "v".into()),
        "bytes" => ("Value::Bytes(v)".into(), "v".into()),
        "enum" => {
            if let Some(backing) = named_backing(ty, dts) {
                (
                    "Value::Uint(v)".into(),
                    format!("{ty}::from_raw({backing}::try_from(v).map_err(|_| ClusterError::InvalidLength(\"{context}\"))?)"),
                )
            } else {
                // bare enum8/enum16 — a plain integer on the wire.
                let rust = base_type(ty, entry);
                (
                    "Value::Uint(v)".into(),
                    format!("{rust}::try_from(v).map_err(|_| ClusterError::InvalidLength(\"{context}\"))?"),
                )
            }
        }
        "bitmap" => {
            if let Some(backing) = named_backing(ty, dts) {
                (
                    "Value::Uint(v)".into(),
                    format!("{ty}::from_bits_truncate({backing}::try_from(v).map_err(|_| ClusterError::InvalidLength(\"{context}\"))?)"),
                )
            } else {
                // bare map8/map16/map32 — a plain integer on the wire.
                let rust = base_type(ty, entry);
                (
                    "Value::Uint(v)".into(),
                    format!("{rust}::try_from(v).map_err(|_| ClusterError::InvalidLength(\"{context}\"))?"),
                )
            }
        }
        _ => ("Value::Uint(v)".into(), "v".into()),
    }
}

/// Write a Rust value expression `expr` of the given metatype as a scalar at
/// `tag` into writer `w`. Returns the `w.put_*` statement.
fn write_scalar(
    metatype: &str,
    ty: &str,
    entry: Option<&str>,
    tag: &str,
    expr: &str,
    dts: &DatatypeMap<'_>,
) -> String {
    match metatype {
        "boolean" => format!("w.put_bool({tag}, {expr}).expect(\"infallible: vec writer\");"),
        "integer" => {
            let rust = base_type(ty, entry);
            if rust.starts_with('i') {
                format!("w.put_int({tag}, i64::from({expr})).expect(\"infallible: vec writer\");")
            } else {
                format!("w.put_uint({tag}, u64::from({expr})).expect(\"infallible: vec writer\");")
            }
        }
        "string" => format!("w.put_utf8({tag}, &{expr}).expect(\"infallible: vec writer\");"),
        "bytes" => format!("w.put_bytes({tag}, &{expr}).expect(\"infallible: vec writer\");"),
        "enum" => {
            if named_backing(ty, dts).is_some() {
                format!("w.put_uint({tag}, u64::from({expr}.to_raw())).expect(\"infallible: vec writer\");")
            } else {
                format!("w.put_uint({tag}, u64::from({expr})).expect(\"infallible: vec writer\");")
            }
        }
        "bitmap" => {
            if named_backing(ty, dts).is_some() {
                format!("w.put_uint({tag}, u64::from({expr}.bits())).expect(\"infallible: vec writer\");")
            } else {
                format!("w.put_uint({tag}, u64::from({expr})).expect(\"infallible: vec writer\");")
            }
        }
        _ => format!("w.put_uint({tag}, u64::from({expr})).expect(\"infallible: vec writer\");"),
    }
}

/// The `read_scalar` metatype of a list element, inferred from its Matter
/// type string: a named struct datatype (or a global `*Struct`, e.g. `semtag`
/// -> `SemanticTagStruct`) → "object"; every scalar list element in the 10
/// clusters is an integer id (`cluster-id`/`endpoint-no`/`uint32`/...) → so
/// the scalar case is "integer".
fn entry_metatype(entry: &str, dts: &DatatypeMap<'_>) -> &'static str {
    if matches!(dts.get(entry), Some(d) if d.kind == "struct") {
        return "object";
    }
    if base_type(entry, None).ends_with("Struct") {
        return "object"; // a global struct (e.g. semtag -> SemanticTagStruct)
    }
    "integer"
}

/// Emit (into `s`, indented by `indent`) statements that read a TLV array
/// whose reader `r` is positioned just AFTER its `ContainerStart`, leaving
/// the result in a local `out: Vec<ElementRust>`.
fn emit_list_read_into(
    s: &mut String,
    indent: &str,
    entry: &str,
    entry_meta: &str,
    context: &str,
    dts: &DatatypeMap<'_>,
) {
    line!(s, "{indent}let mut out = Vec::new();");
    line!(s, "{indent}loop {{");
    line!(s, "{indent}    match r.next()? {{");
    line!(s, "{indent}        Some(Element::ContainerEnd) => break,");
    if entry_meta == "object" {
        line!(s, "{indent}        Some(Element::ContainerStart {{ kind: ContainerKind::Structure, .. }}) => {{");
        line!(s, "{indent}            out.push({entry}::decode_from(r)?);");
        line!(s, "{indent}        }}");
    } else {
        let (pat, build) = read_scalar(entry_meta, entry, None, context, dts);
        line!(
            s,
            "{indent}        Some(Element::Scalar {{ value: {pat}, .. }}) => out.push({build}),"
        );
    }
    line!(s, "{indent}        None => return Err(ClusterError::Tlv(matter_codec::Error::UnclosedContainer)),");
    line!(s, "{indent}        Some(_) => {{}} // skip");
    line!(s, "{indent}    }}");
    line!(s, "{indent}}}");
}

fn emit_attr_decoder(s: &mut String, a: &Attribute, dts: &DatatypeMap<'_>) {
    let ret = rust_type(
        &a.ty,
        a.entry_type.as_deref(),
        a.nullable,
        false,
        Position::Attribute,
    );
    line!(s, "/// Decode the `{}` attribute value.", a.name);
    line!(s, "///");
    line!(s, "/// # Errors");
    line!(
        s,
        "/// Returns [`ClusterError`] on a type mismatch or out-of-range value."
    );
    line!(
        s,
        "pub fn decode_{}(tlv: &[u8]) -> Result<{}, ClusterError> {{",
        snake(&a.name),
        ret
    );

    if a.metatype == "object" {
        // struct attribute (all read-only in scope; no composite attribute is
        // nullable in the 10 clusters).
        line!(s, "    {}::decode(tlv)", a.ty);
        line!(s, "}}\n");
        return;
    }
    if a.metatype == "array" {
        let entry = a.entry_type.as_deref().unwrap_or("octstr");
        let entry_meta = entry_metatype(entry, dts);
        line!(s, "    let mut r = TlvReader::new(tlv);");
        line!(s, "    match r.next()? {{");
        line!(
            s,
            "        Some(Element::ContainerStart {{ kind: ContainerKind::Array, .. }}) => {{}}"
        );
        line!(
            s,
            "        _ => return Err(ClusterError::UnexpectedType {{ context: \"{}\" }}),",
            a.name
        );
        line!(s, "    }}");
        // Reborrow as `&mut` so element struct decode (`decode_from(r)`) shares
        // one code path with the struct-field call site.
        line!(s, "    let r = &mut r;");
        emit_list_read_into(s, "    ", entry, entry_meta, &a.name, dts);
        line!(s, "    Ok(out)");
        line!(s, "}}\n");
        return;
    }

    let ctx = a.name.clone();
    let (pat, build) = read_scalar(&a.metatype, &a.ty, a.entry_type.as_deref(), &ctx, dts);
    line!(s, "    let mut r = TlvReader::new(tlv);");
    line!(s, "    match r.next()? {{");
    if a.nullable {
        line!(
            s,
            "        Some(Element::Scalar {{ value: Value::Null, .. }}) => Ok(Nullable::Null),"
        );
        line!(
            s,
            "        Some(Element::Scalar {{ value: {}, .. }}) => Ok(Nullable::Value({})),",
            pat,
            build
        );
    } else {
        line!(
            s,
            "        Some(Element::Scalar {{ value: {}, .. }}) => Ok({}),",
            pat,
            build
        );
    }
    line!(
        s,
        "        _ => Err(ClusterError::UnexpectedType {{ context: \"{}\" }}),",
        a.name
    );
    line!(s, "    }}");
    line!(s, "}}\n");
}

fn emit_attr_encoder(s: &mut String, a: &Attribute, dts: &DatatypeMap<'_>) {
    if a.metatype == "object" || a.metatype == "array" {
        return;
    }
    let arg_ty = rust_type(
        &a.ty,
        a.entry_type.as_deref(),
        a.nullable,
        false,
        Position::Attribute,
    );
    line!(
        s,
        "/// Encode the `{}` attribute value as a standalone TLV element.",
        a.name
    );
    line!(s, "#[must_use]");
    line!(s, "#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.");
    line!(
        s,
        "pub fn encode_{}(value: {}) -> Vec<u8> {{",
        snake(&a.name),
        borrowed(&arg_ty)
    );
    line!(s, "    let mut buf = Vec::new();");
    line!(s, "    let mut w = TlvWriter::new(&mut buf);");
    let put = write_scalar(
        &a.metatype,
        &a.ty,
        a.entry_type.as_deref(),
        "Tag::Anonymous",
        "value",
        dts,
    );
    if a.nullable {
        line!(s, "    match value {{");
        line!(s, "        Nullable::Null => w.put_null(Tag::Anonymous).expect(\"infallible: vec writer\"),");
        line!(s, "        Nullable::Value(value) => {{ {} }}", put);
        line!(s, "    }}");
    } else {
        line!(s, "    {}", put);
    }
    line!(s, "    buf");
    line!(s, "}}\n");
}

/// For an encoder argument, Copy scalars pass by value; String/Vec by ref.
fn borrowed(ty: &str) -> String {
    if ty == "String" || ty.starts_with("Vec<") {
        format!("&{ty}")
    } else {
        ty.to_string()
    }
}

fn emit_command_encoder(s: &mut String, cmd: &CommandDef, dts: &DatatypeMap<'_>) {
    let args: Vec<String> = cmd
        .fields
        .iter()
        .map(|f| {
            let t = rust_type(
                &f.ty,
                f.entry_type.as_deref(),
                f.nullable,
                f.optional,
                Position::Field,
            );
            format!("{}: {}", snake(&f.name), borrowed(&t))
        })
        .collect();
    line!(s, "/// Encode the `{}` command request payload.", cmd.name);
    line!(s, "#[must_use]");
    line!(s, "#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Vec-backed TlvWriter is infallible.");
    line!(
        s,
        "pub fn encode_{}({}) -> Vec<u8> {{",
        snake(&cmd.name),
        args.join(", ")
    );
    line!(s, "    let mut buf = Vec::new();");
    line!(s, "    let mut w = TlvWriter::new(&mut buf);");
    line!(
        s,
        "    w.start_structure(Tag::Anonymous).expect(\"infallible: vec writer\");"
    );
    for f in &cmd.fields {
        emit_field_write(s, f, &snake(&f.name), dts);
    }
    line!(
        s,
        "    w.end_container().expect(\"infallible: vec writer\");"
    );
    line!(s, "    buf");
    line!(s, "}}\n");
}

/// Emit the field write (with optional/nullable guards) for a command field
/// bound to local `var`, tagged `Tag::Context(f.id)`.
fn emit_field_write(s: &mut String, f: &FieldDef, var: &str, dts: &DatatypeMap<'_>) {
    let tag = format!("Tag::Context({})", f.id);
    let scalar = matches!(
        f.metatype.as_str(),
        "boolean" | "integer" | "string" | "bytes" | "enum" | "bitmap"
    );
    if scalar {
        let inner =
            |expr: &str| write_scalar(&f.metatype, &f.ty, f.entry_type.as_deref(), &tag, expr, dts);
        emit_guarded_write(s, f, var, &tag, &inner);
        return;
    }
    if f.metatype == "object" {
        // A struct field: open a sub-structure at the context tag, write the
        // struct's fields, close. (No request-command `array` field exists.)
        let open = |s: &mut String, expr: &str| {
            line!(
                s,
                "    w.start_structure({tag}).expect(\"infallible: vec writer\");"
            );
            line!(s, "    {expr}.write_fields(&mut w);");
            line!(
                s,
                "    w.end_container().expect(\"infallible: vec writer\");"
            );
        };
        match (f.optional, f.nullable) {
            (false, false) => open(s, var),
            (false, true) => {
                line!(s, "    match &{var} {{");
                line!(s, "        Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),");
                line!(s, "        Nullable::Value({var}) => {{");
                open(s, var);
                line!(s, "        }}");
                line!(s, "    }}");
            }
            (true, false) => {
                line!(s, "    if let Some({var}) = &{var} {{");
                open(s, var);
                line!(s, "    }}");
            }
            (true, true) => {
                line!(s, "    if let Some({var}) = &{var} {{ match {var} {{");
                line!(s, "        Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),");
                line!(s, "        Nullable::Value({var}) => {{");
                open(s, var);
                line!(s, "        }}");
                line!(s, "    }} }}");
            }
        }
        return;
    }
    // No request command has an `array` field in the 10 clusters; surface it
    // rather than silently dropping if one ever appears.
    line!(
        s,
        "    compile_error!(\"list-typed command field {} needs list-encode\");",
        f.name
    );
}

/// The scalar field-write with nullable/optional guards.
fn emit_guarded_write(
    s: &mut String,
    f: &FieldDef,
    var: &str,
    tag: &str,
    inner: &dyn Fn(&str) -> String,
) {
    match (f.optional, f.nullable) {
        (false, false) => line!(s, "    {}", inner(var)),
        (false, true) => {
            line!(s, "    match {var} {{");
            line!(
                s,
                "        Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),"
            );
            line!(s, "        Nullable::Value({var}) => {{ {} }}", inner(var));
            line!(s, "    }}");
        }
        (true, false) => line!(s, "    if let Some({var}) = {var} {{ {} }}", inner(var)),
        (true, true) => {
            line!(s, "    if let Some({var}) = {var} {{");
            line!(s, "        match {var} {{");
            line!(s, "            Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),");
            line!(
                s,
                "            Nullable::Value({var}) => {{ {} }}",
                inner(var)
            );
            line!(s, "        }}");
            line!(s, "    }}");
        }
    }
}

fn emit_response_decoder(s: &mut String, cmd: &CommandDef, dts: &DatatypeMap<'_>) {
    // A response command decodes into an anonymous struct shape; reuse the
    // struct-decode pattern by treating its fields as a struct named after
    // the command.
    let st = Datatype {
        name: cmd.name.clone(),
        base: "struct".into(),
        kind: "struct".into(),
        values: vec![],
        bits: vec![],
        fields: cmd.fields.iter().map(clone_field).collect(),
    };
    emit_struct_decl_and_codec(s, &st, /*decl=*/ true, dts);
}

fn clone_field(f: &FieldDef) -> FieldDef {
    FieldDef {
        id: f.id,
        name: f.name.clone(),
        ty: f.ty.clone(),
        metatype: f.metatype.clone(),
        entry_type: f.entry_type.clone(),
        nullable: f.nullable,
        optional: f.optional,
    }
}

fn emit_struct_codec(s: &mut String, d: &Datatype, dts: &DatatypeMap<'_>) {
    // Struct *decl* was already emitted by emit.rs::emit_struct; emit only the
    // codec here.
    emit_struct_decl_and_codec(s, d, /*decl=*/ false, dts);
}

/// Emit the codec for a struct `d`: `decode_from`(positioned reader) +
/// `decode`(bytes) + `write_fields`(into a writer) + `encode`(standalone
/// bytes). When `decl` is true, also emit the `pub struct` declaration
/// (response payloads aren't in the cluster datatypes).
#[allow(clippy::too_many_lines)] // a code emitter — long but linear.
fn emit_struct_decl_and_codec(s: &mut String, d: &Datatype, decl: bool, dts: &DatatypeMap<'_>) {
    if decl {
        line!(s, "/// Decoded `{}` payload.", d.name);
        line!(s, "#[derive(Clone, Debug, PartialEq)]");
        line!(s, "pub struct {} {{", d.name);
        for f in &d.fields {
            let ty = rust_type(
                &f.ty,
                f.entry_type.as_deref(),
                f.nullable,
                f.optional,
                Position::Field,
            );
            line!(s, "    /// Field {} (tag {}).", f.name, f.id);
            line!(s, "    pub {}: {},", snake(&f.name), ty);
        }
        line!(s, "}}\n");
    }

    line!(s, "impl {} {{", d.name);

    // decode_from: reader positioned just AFTER the struct ContainerStart.
    line!(
        s,
        "    /// Decode the fields of an already-opened anonymous structure"
    );
    line!(
        s,
        "    /// (reader positioned after the struct start; consumes to its end)."
    );
    line!(s, "    ///");
    line!(s, "    /// # Errors");
    line!(
        s,
        "    /// Returns [`ClusterError`] on a malformed structure or missing required field."
    );
    line!(
        s,
        "    pub fn decode_from(r: &mut TlvReader<'_>) -> Result<Self, ClusterError> {{"
    );
    for f in &d.fields {
        line!(
            s,
            "        let mut f_{}: Option<{}> = None;",
            snake(&f.name),
            rust_type(
                &f.ty,
                f.entry_type.as_deref(),
                f.nullable,
                false,
                Position::Attribute
            )
        );
    }
    line!(s, "        loop {{");
    line!(s, "            match r.next()? {{");
    line!(s, "                Some(Element::ContainerEnd) => break,");
    for f in &d.fields {
        emit_struct_field_read_arm(s, f, dts);
    }
    line!(s, "                None => return Err(ClusterError::Tlv(matter_codec::Error::UnclosedContainer)),");
    line!(
        s,
        "                Some(_) => {{}} // unknown/future element — skip"
    );
    line!(s, "            }}");
    line!(s, "        }}");
    line!(s, "        Ok(Self {{");
    for f in &d.fields {
        let var = snake(&f.name);
        if f.optional {
            line!(s, "            {var}: f_{var},");
        } else {
            line!(
                s,
                "            {var}: f_{var}.ok_or(ClusterError::MissingField(\"{}\"))?,",
                f.name
            );
        }
    }
    line!(s, "        }})");
    line!(s, "    }}");

    // decode: from standalone bytes (expects the struct start).
    line!(
        s,
        "    /// Decode from a standalone anonymous TLV structure."
    );
    line!(s, "    ///");
    line!(s, "    /// # Errors");
    line!(s, "    /// Returns [`ClusterError`] if the bytes are not an anonymous structure or a field is malformed.");
    line!(
        s,
        "    pub fn decode(tlv: &[u8]) -> Result<Self, ClusterError> {{"
    );
    line!(s, "        let mut r = TlvReader::new(tlv);");
    line!(s, "        match r.next()? {{");
    line!(s, "            Some(Element::ContainerStart {{ kind: ContainerKind::Structure, .. }}) => {{}}");
    line!(
        s,
        "            _ => return Err(ClusterError::UnexpectedType {{ context: \"{}\" }}),",
        d.name
    );
    line!(s, "        }}");
    line!(s, "        Self::decode_from(&mut r)");
    line!(s, "    }}");

    // write_fields: write this struct's fields into an already-open container.
    line!(
        s,
        "    /// Write this struct's fields into an already-open container."
    );
    line!(
        s,
        "    #[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible."
    );
    line!(
        s,
        "    pub fn write_fields(&self, w: &mut TlvWriter<'_>) {{"
    );
    for f in &d.fields {
        emit_field_write_self(s, f, dts);
    }
    line!(s, "    }}");

    // encode: standalone anonymous structure bytes.
    line!(s, "    /// Encode as a standalone anonymous TLV structure.");
    line!(s, "    #[must_use]");
    line!(
        s,
        "    #[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible."
    );
    line!(s, "    pub fn encode(&self) -> Vec<u8> {{");
    line!(s, "        let mut buf = Vec::new();");
    line!(s, "        let mut w = TlvWriter::new(&mut buf);");
    line!(
        s,
        "        w.start_structure(Tag::Anonymous).expect(\"infallible: vec writer\");"
    );
    line!(s, "        self.write_fields(&mut w);");
    line!(
        s,
        "        w.end_container().expect(\"infallible: vec writer\");"
    );
    line!(s, "        buf");
    line!(s, "    }}");

    line!(s, "}}\n");
}

/// Emit a `write_fields` line for struct field `f`, reading `self.<field>`.
/// (Struct datatypes in scope have only scalar/enum/bitmap fields.)
fn emit_field_write_self(s: &mut String, f: &FieldDef, dts: &DatatypeMap<'_>) {
    let var = snake(&f.name);
    let tag = format!("Tag::Context({})", f.id);
    let inner =
        |expr: &str| write_scalar(&f.metatype, &f.ty, f.entry_type.as_deref(), &tag, expr, dts);
    match (f.optional, f.nullable) {
        (false, false) => line!(s, "        {}", inner(&format!("self.{var}"))),
        (false, true) => {
            line!(s, "        match &self.{var} {{");
            line!(s, "            Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),");
            line!(
                s,
                "            Nullable::Value({var}) => {{ {} }}",
                inner(&format!("*{var}"))
            );
            line!(s, "        }}");
        }
        (true, false) => {
            line!(
                s,
                "        if let Some({var}) = &self.{var} {{ {} }}",
                inner(&format!("*{var}"))
            );
        }
        (true, true) => {
            line!(s, "        if let Some({var}) = &self.{var} {{");
            line!(s, "            match {var} {{");
            line!(s, "                Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),");
            line!(
                s,
                "                Nullable::Value({var}) => {{ {} }}",
                inner(&format!("*{var}"))
            );
            line!(s, "            }}");
            line!(s, "        }}");
        }
    }
}

/// One decoder arm reading struct field `f` at `Tag::Context(f.id)` into the
/// local `f_<name>: Option<…>` accumulator (scalar/object/array).
fn emit_struct_field_read_arm(s: &mut String, f: &FieldDef, dts: &DatatypeMap<'_>) {
    let var = snake(&f.name);
    let scalar = matches!(
        f.metatype.as_str(),
        "boolean" | "integer" | "string" | "bytes" | "enum" | "bitmap"
    );
    if scalar {
        let ctx = f.name.clone();
        let (pat, build) = read_scalar(&f.metatype, &f.ty, f.entry_type.as_deref(), &ctx, dts);
        if f.nullable {
            line!(s, "                Some(Element::Scalar {{ tag: Tag::Context({}), value: Value::Null }}) => f_{} = Some(Nullable::Null),", f.id, var);
            line!(s, "                Some(Element::Scalar {{ tag: Tag::Context({}), value: {} }}) => f_{} = Some(Nullable::Value({})),", f.id, pat, var, build);
        } else {
            line!(s, "                Some(Element::Scalar {{ tag: Tag::Context({}), value: {} }}) => f_{} = Some({}),", f.id, pat, var, build);
        }
        let _ = ident;
        return;
    }
    if f.metatype == "object" {
        let val = format!("{}::decode_from(r)?", f.ty);
        let wrapped = if f.nullable {
            format!("Nullable::Value({val})")
        } else {
            val
        };
        if f.nullable {
            line!(s, "                Some(Element::Scalar {{ tag: Tag::Context({}), value: Value::Null }}) => f_{} = Some(Nullable::Null),", f.id, var);
        }
        line!(s, "                Some(Element::ContainerStart {{ tag: Tag::Context({}), kind: ContainerKind::Structure }}) => f_{} = Some({}),", f.id, var, wrapped);
        return;
    }
    // array field (e.g. GetUserResponse.Credentials = Nullable<Vec<...>>).
    let entry = f.entry_type.as_deref().unwrap_or("octstr");
    let entry_meta = entry_metatype(entry, dts);
    if f.nullable {
        line!(s, "                Some(Element::Scalar {{ tag: Tag::Context({}), value: Value::Null }}) => f_{} = Some(Nullable::Null),", f.id, var);
    }
    line!(s, "                Some(Element::ContainerStart {{ tag: Tag::Context({}), kind: ContainerKind::Array }}) => {{", f.id);
    emit_list_read_into(s, "                    ", entry, entry_meta, &f.name, dts);
    let wrapped = if f.nullable {
        "Nullable::Value(out)"
    } else {
        "out"
    };
    line!(s, "                    f_{} = Some({});", var, wrapped);
    line!(s, "                }}");
}
