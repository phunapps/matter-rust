//! Codec emission: struct, attribute, and command encode/decode.

use crate::codegen::model::{Attribute, Cluster, CommandDef, Datatype, EventDef, FieldDef};
use crate::codegen::rustgen::emit::{
    choice_docs, element_note, emit_redacting_debug, line, struct_derive, PROVISIONAL_DOC,
    SECRET_DOC,
};
use crate::codegen::rustgen::types::{base_type, ident, rust_type, snake, Position};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

/// Name → datatype lookup for the cluster being emitted, so the scalar codec
/// can resolve a named enum/bitmap's backing width (and tell named types from
/// bare `enum8`/`map8`/`status` scalars).
type DatatypeMap<'a> = HashMap<&'a str, &'a Datatype>;

/// A struct/command field name as a Rust identifier: `snake_case`, with reserved
/// words escaped (`Type` -> `r#type`). The `f_`-prefixed decode locals stay bare
/// `snake` (the prefix already makes them keyword-safe).
fn field_ident(name: &str) -> String {
    ident(&snake(name))
}

/// Struct datatype names reachable from a **request** command's field types,
/// transitively through struct fields and list-of-struct entries. These structs
/// need an encodable `write_fields` even when they carry a list field (the
/// scalar-only [`struct_is_write_capable`] rule alone would leave them
/// decode-only). Like every struct that gets an encoder, they are constructible
/// by callers (not `#[non_exhaustive]`).
/// Empty for every cluster whose request commands take only scalars/lists-of-scalar.
pub(crate) fn command_encode_reachable_structs<'a>(
    c: &'a Cluster,
    dts: &DatatypeMap<'a>,
) -> HashSet<&'a str> {
    let seeds = c
        .commands
        .iter()
        .filter(|cmd| cmd.direction == "request")
        .flat_map(|cmd| &cmd.fields)
        .flat_map(|f| [Some(f.ty.as_str()), f.entry_type.as_deref()]);
    reachable_structs(seeds, dts)
}

/// Struct datatype names reachable from a **writable** attribute's type or
/// list entry type, transitively (M9-A3 B4 encoder rule): the structs a client
/// may write back. `AccessControl` `Extension` reaches
/// `AccessControlExtensionStruct`; `IcdManagement` `RegisteredClients` is
/// read-only, so `MonitoringRegistrationStruct` is not reached.
pub(crate) fn writable_attribute_reachable_structs<'a>(
    c: &'a Cluster,
    dts: &DatatypeMap<'a>,
) -> HashSet<&'a str> {
    let seeds = c
        .attributes
        .iter()
        .filter(|a| a.writable)
        .flat_map(|a| [Some(a.ty.as_str()), a.entry_type.as_deref()]);
    reachable_structs(seeds, dts)
}

/// The struct datatypes of `dts` reachable from the type names in `seeds`,
/// following struct fields and list-of-struct entries.
fn reachable_structs<'a>(
    seeds: impl Iterator<Item = Option<&'a str>>,
    dts: &DatatypeMap<'a>,
) -> HashSet<&'a str> {
    let mut out = HashSet::new();
    let consider = |t: Option<&'a str>, q: &mut Vec<&'a str>| {
        if let Some(name) = t {
            if dts.get(name).is_some_and(|d| d.kind == "struct") {
                q.push(name);
            }
        }
    };
    let mut queue: Vec<&str> = Vec::new();
    for t in seeds {
        consider(t, &mut queue);
    }
    while let Some(name) = queue.pop() {
        if !out.insert(name) {
            continue;
        }
        if let Some(d) = dts.get(name) {
            for f in &d.fields {
                consider(Some(f.ty.as_str()), &mut queue);
                consider(f.entry_type.as_deref(), &mut queue);
            }
        }
    }
    out
}

/// Emit every codec for the cluster.
pub fn emit_codecs(s: &mut String, c: &Cluster) {
    let dts: DatatypeMap<'_> = c.datatypes.iter().map(|d| (d.name.as_str(), d)).collect();
    let encode_reachable = command_encode_reachable_structs(c, &dts);
    assert_no_write_guarded_command_structs(c, &dts, &encode_reachable);
    let encoded = encoded_struct_names(c);
    let write_only = fabric_index_omitted_on_write(c);
    for d in &c.datatypes {
        if d.kind == "struct" {
            emit_struct_codec(s, d, &dts, &encoded, &write_only);
        }
    }
    for a in &c.attributes {
        let note = element_note(c, a.provisional, a.deprecated, a.supplemented.as_ref());
        emit_attr_decoder(s, a, &dts, note.as_deref());
        if a.writable {
            emit_attr_encoder(s, a, &dts, note.as_deref());
        }
    }
    for cmd in &c.commands {
        let note = element_note(
            c,
            cmd.provisional,
            cmd.deprecated,
            cmd.supplemented.as_ref(),
        );
        if cmd.direction == "request" {
            emit_command_encoder(s, cmd, &dts, note.as_deref());
        } else {
            emit_response_decoder(s, cmd, &dts, note.as_deref());
        }
    }
    for ev in &c.events {
        emit_event_decoder(s, ev, &dts);
    }
}

/// Stop the generator if a request command can reach a write-guarded struct
/// ([`struct_has_write_guarded_fields`]). Such a struct's `write_fields`
/// returns `Result` (it refuses a `None` guarded field), and the
/// command-encoder bodies call
/// `write_fields` as an infallible statement. No 1.4 cluster has this shape;
/// supporting it means making those encoders fallible, which is a reviewed
/// emitter change, not something to slip through.
///
/// # Panics
///
/// Panics naming the cluster and struct when the shape appears.
fn assert_no_write_guarded_command_structs(
    c: &Cluster,
    dts: &DatatypeMap<'_>,
    encode_reachable: &HashSet<&str>,
) {
    let mut names: Vec<&&str> = encode_reachable.iter().collect();
    names.sort();
    for name in names {
        let guarded = dts
            .get(*name)
            .is_some_and(|d| struct_has_write_guarded_fields(d));
        assert!(
            !guarded,
            "{}: write-guarded struct {name} is reachable from a request command; \
             command encoders cannot propagate its fallible write_fields",
            c.name
        );
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

/// True when a model `float` metatype is double-precision (`double` → `f64`)
/// rather than single (`single` → `f32`).
///
/// The TLV wire types are distinct (FLOAT32 vs FLOAT64) and the reader keeps
/// them apart ([`matter_codec::Value::Float`] vs `Double`), so the decoder
/// pattern and the writer call must follow the width the model declares.
fn is_double(ty: &str, entry: Option<&str>) -> bool {
    base_type(ty, entry) == "f64"
}

/// Read one TLV scalar into a Rust value expression. Returns
/// `(match_pattern, build_expr)` for use inside a decoder arm.
///
/// # Panics
///
/// Panics on a metatype with no emitter arm. This is a hard generator stop by
/// design: the former silent fallthrough emitted an integer read for *any*
/// unknown metatype, which either failed to compile or — worse — compiled and
/// mis-decoded the value. Failing `cargo xtask codegen` loudly is the safe
/// behaviour when a newly allowlisted cluster introduces a shape we cannot yet
/// encode or decode.
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
        // IEEE 754 floats (`single`/`double`), e.g. the concentration
        // measurement clusters' MeasuredValue.
        //
        // These match on the wire width, which the integer arms above do *not*:
        // `TlvReader` folds UINT8..UINT64 into one `Value::Uint(u64)` (and
        // INT8..INT64 into `Value::Int(i64)`) — see
        // `matter-codec/src/reader.rs` — so a single integer pattern matches
        // any encoded width and `try_from` range-checks it. `Value` keeps
        // FLOAT32 and FLOAT64 apart, so floats have to say which they accept.
        //
        // What they accept follows chip's `TLVReader`
        // (`src/lib/core/TLVReader.cpp`, `Get(float&)` / `Get(double&)`):
        // `Get(float&)` is strict — FLOAT32 only — so `single` here rejects a
        // FLOAT64 element; `Get(double&)` is lenient — FLOAT32 *or* FLOAT64 —
        // so `double` also accepts a narrowed float, emitted as the extra arm
        // from [`read_scalar_widened`]. matter.js is lenient in both directions
        // (`TlvFloat` and `TlvDouble` are the same `TlvType.Float`; the width
        // is an encode-time choice only), so where the two references disagree
        // we take the stricter one: device firmware is overwhelmingly built
        // from chip, and that is the behaviour we must interoperate with.
        "float" => {
            if is_double(ty, entry) {
                ("Value::Double(v)".into(), "v".into())
            } else {
                ("Value::Float(v)".into(), "v".into())
            }
        }
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
                    format!("{ty}::from_bits_retain({backing}::try_from(v).map_err(|_| ClusterError::InvalidLength(\"{context}\"))?)"),
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
        other => panic!(
            "codegen: no read_scalar arm for metatype {other:?} (type {ty:?}, at {context}) — \
             add one before allowlisting a cluster that uses it"
        ),
    }
}

/// The extra decoder arm, if any, that accepts a *narrower* wire encoding of
/// the same value. Emitted immediately after the [`read_scalar`] arm at every
/// call site, in the same `(match_pattern, build_expr)` shape.
///
/// Only `double` has one: chip's `TLVReader::Get(double&)`
/// (`src/lib/core/TLVReader.cpp`) accepts a FLOAT32 element and widens it,
/// whereas `Get(float&)` rejects a FLOAT64 — so `single` stays strict and gets
/// no widening arm. See [`read_scalar`] for the full reasoning.
///
/// No cluster in the pinned model has a `double` attribute today, so this
/// changes no generated code; it exists so the first one that does inherits
/// the reference behaviour rather than a stricter guess.
fn read_scalar_widened(metatype: &str, ty: &str, entry: Option<&str>) -> Option<(String, String)> {
    (metatype == "float" && is_double(ty, entry))
        .then(|| ("Value::Float(v)".to_string(), "f64::from(v)".to_string()))
}

/// Write a Rust value expression `expr` of the given metatype as a scalar at
/// `tag` into writer `w`. Returns the `w.put_*` statement.
///
/// # Panics
///
/// Panics on a metatype with no emitter arm — see [`read_scalar`] for why this
/// is a hard stop rather than a silent integer fallthrough.
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
        // IEEE 754 floats: emit the matching wire width. No integer coercion —
        // `u64::from(<f32>)` (the old fallthrough) does not even compile.
        "float" => {
            if is_double(ty, entry) {
                format!("w.put_double({tag}, {expr}).expect(\"infallible: vec writer\");")
            } else {
                format!("w.put_float({tag}, {expr}).expect(\"infallible: vec writer\");")
            }
        }
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
        other => panic!(
            "codegen: no write_scalar arm for metatype {other:?} (type {ty:?}) — \
             add one before allowlisting a cluster that uses it"
        ),
    }
}

/// The `read_scalar` metatype of a list element, inferred from its Matter
/// type string: a named struct datatype (or a global `*Struct`, e.g. `semtag`
/// -> `SemanticTagStruct`) → "object"; a named enum/bitmap datatype → "enum"/
/// "bitmap" (so the element decodes via `from_raw`/`from_bits_retain`, not a
/// bare integer); every other scalar list element is an integer id
/// (`cluster-id`/`endpoint-no`/`uint32`/...) → "integer".
fn entry_metatype(entry: &str, dts: &DatatypeMap<'_>) -> &'static str {
    if let Some(d) = dts.get(entry) {
        match d.kind.as_str() {
            "struct" => return "object",
            "enum" => return "enum",
            "bitmap" => return "bitmap",
            _ => {}
        }
    }
    let rust = base_type(entry, None);
    if rust.ends_with("Struct") {
        return "object"; // a global struct (e.g. semtag -> SemanticTagStruct)
    }
    // Byte-string / string list elements (e.g. GeneralDiagnostics
    // NetworkInterface's IPv4Addresses = list<ipv4adr>) decode as Bytes/Utf8,
    // not as an integer.
    if rust == "Vec<u8>" {
        return "bytes";
    }
    if rust == "String" {
        return "string";
    }
    // list<single> / list<double> elements decode as Float/Double.
    if rust == "f32" || rust == "f64" {
        return "float";
    }
    // list<boolean> elements are TLV Bool (put_bool / Value::Bool), not an
    // unsigned integer. No list<boolean> exists in the model today.
    if rust == "bool" {
        return "boolean";
    }
    "integer"
}

/// How a list's scalar elements are written, as `(iter, put)`: the iterator
/// call on the list (`iter`, appended to the list expression as
/// `list.<iter>`) and the `put` statement for one element bound to `el`, at an
/// anonymous tag.
///
/// Integers, enums, bitmaps, booleans and floats are `Copy`, so the list is
/// iterated by value (`iter().copied()`) and `el` is the value itself. A byte
/// string (`Vec<u8>`) or a string (`String`) is not `Copy`: the list is iterated
/// by reference, and `el` (`&Vec<u8>` / `&String`) is passed straight to
/// `put_bytes` / `put_utf8`, which take `&[u8]` / `&str` (M9-A3 B5: Messages
/// `CancelMessagesRequest.MessageIDs` is a `list<octstr>`).
fn list_scalar_element_write(
    entry_meta: &str,
    entry: &str,
    dts: &DatatypeMap<'_>,
) -> (&'static str, String) {
    match entry_meta {
        "bytes" => (
            "iter()",
            "w.put_bytes(Tag::Anonymous, el).expect(\"infallible: vec writer\");".to_string(),
        ),
        "string" => (
            "iter()",
            "w.put_utf8(Tag::Anonymous, el).expect(\"infallible: vec writer\");".to_string(),
        ),
        _ => (
            "iter().copied()",
            write_scalar(entry_meta, entry, None, "Tag::Anonymous", "el", dts),
        ),
    }
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
        // The element's Rust type name (a cluster-local struct == its name; a
        // global like `semtag` maps via base_type -> `SemanticTagStruct`).
        let elem_ty = base_type(entry, None);
        line!(s, "{indent}        Some(Element::ContainerStart {{ kind: ContainerKind::Structure, .. }}) => {{");
        line!(
            s,
            "{indent}            out.push({elem_ty}::decode_from(r)?);"
        );
        line!(s, "{indent}        }}");
    } else {
        let (pat, build) = read_scalar(entry_meta, entry, None, context, dts);
        line!(
            s,
            "{indent}        Some(Element::Scalar {{ value: {pat}, .. }}) => out.push({build}),"
        );
        if let Some((pat, build)) = read_scalar_widened(entry_meta, entry, None) {
            line!(
                s,
                "{indent}        Some(Element::Scalar {{ value: {pat}, .. }}) => out.push({build}),"
            );
        }
    }
    line!(s, "{indent}        None => return Err(ClusterError::Tlv(matter_codec::Error::UnclosedContainer)),");
    line!(
        s,
        "{indent}        Some(Element::ContainerStart {{ .. }}) => r.skip_container()?,"
    );
    line!(s, "{indent}        Some(_) => {{}} // skip unknown scalar");
    line!(s, "{indent}    }}");
    line!(s, "{indent}}}");
}

#[allow(clippy::too_many_lines)] // a code emitter — long but linear.
/// `note`: the attribute's [`element_note`] (supplement or provisional line).
fn emit_attr_decoder(s: &mut String, a: &Attribute, dts: &DatatypeMap<'_>, note: Option<&str>) {
    let ret = rust_type(
        &a.ty,
        a.entry_type.as_deref(),
        a.nullable,
        false,
        Position::Attribute,
    );
    line!(s, "/// Decode the `{}` attribute value.", a.name);
    if let Some(note) = note {
        line!(s, "///");
        line!(s, "/// {note}");
    }
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
        // struct attribute. Nullable struct attributes (e.g. EEM's energy
        // measurement structs) must peek for a TLV null before opening the
        // structure; non-nullable ones delegate to the struct's own `decode`.
        if a.nullable {
            line!(s, "    let mut r = TlvReader::new(tlv);");
            line!(s, "    match r.next()? {{");
            line!(
                s,
                "        Some(Element::Scalar {{ value: Value::Null, .. }}) => Ok(Nullable::Null),"
            );
            line!(s, "        Some(Element::ContainerStart {{ kind: ContainerKind::Structure, .. }}) => {{");
            line!(
                s,
                "            Ok(Nullable::Value({}::decode_from(&mut r)?))",
                a.ty
            );
            line!(s, "        }}");
            line!(
                s,
                "        _ => Err(ClusterError::UnexpectedType {{ context: \"{}\" }}),",
                a.name
            );
            line!(s, "    }}");
        } else {
            line!(s, "    {}::decode(tlv)", a.ty);
        }
        line!(s, "}}\n");
        return;
    }
    if a.metatype == "array" {
        let entry = a.entry_type.as_deref().unwrap_or("octstr");
        let entry_meta = entry_metatype(entry, dts);
        line!(s, "    let mut r = TlvReader::new(tlv);");
        line!(s, "    match r.next()? {{");
        if a.nullable {
            line!(
                s,
                "        Some(Element::Scalar {{ value: Value::Null, .. }}) => return Ok(Nullable::Null),"
            );
        }
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
        if a.nullable {
            line!(s, "    Ok(Nullable::Value(out))");
        } else {
            line!(s, "    Ok(out)");
        }
        line!(s, "}}\n");
        return;
    }

    let ctx = a.name.clone();
    let mut arms = vec![read_scalar(
        &a.metatype,
        &a.ty,
        a.entry_type.as_deref(),
        &ctx,
        dts,
    )];
    arms.extend(read_scalar_widened(
        &a.metatype,
        &a.ty,
        a.entry_type.as_deref(),
    ));
    line!(s, "    let mut r = TlvReader::new(tlv);");
    line!(s, "    match r.next()? {{");
    if a.nullable {
        line!(
            s,
            "        Some(Element::Scalar {{ value: Value::Null, .. }}) => Ok(Nullable::Null),"
        );
    }
    for (pat, build) in &arms {
        if a.nullable {
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
    }
    line!(
        s,
        "        _ => Err(ClusterError::UnexpectedType {{ context: \"{}\" }}),",
        a.name
    );
    line!(s, "    }}");
    line!(s, "}}\n");
}

/// `note`: the attribute's [`element_note`] (supplement or provisional line).
fn emit_attr_encoder(s: &mut String, a: &Attribute, dts: &DatatypeMap<'_>, note: Option<&str>) {
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
    if let Some(note) = note {
        line!(s, "///");
        line!(s, "/// {note}");
    }
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

/// For an encoder argument, Copy scalars pass by value; String/Vec (and a
/// `Secret` around one, [`arg_type`]) by ref.
fn borrowed(ty: &str) -> String {
    if ty == "String" || ty.starts_with("Vec<") || ty.starts_with("Secret<") {
        format!("&{ty}")
    } else {
        ty.to_string()
    }
}

/// The Rust type of request field `f` as an encoder argument (before
/// [`borrowed`]): [`rust_type`], except that a secret field's value is wrapped
/// in `Secret<T>` inside any `Nullable` and `Option` (`Option<Secret<Vec<u8>>>`),
/// so a `{:?}` of the argument prints `"<redacted>"`.
fn arg_type(f: &FieldDef) -> String {
    if !f.secret {
        return rust_type(
            &f.ty,
            f.entry_type.as_deref(),
            f.nullable,
            f.optional,
            Position::Field,
        );
    }
    let mut t = format!("Secret<{}>", base_type(&f.ty, f.entry_type.as_deref()));
    if f.nullable {
        t = format!("Nullable<{t}>");
    }
    if f.optional {
        t = format!("Option<{t}>");
    }
    t
}

/// The rustdoc paragraph on a request encoder with secret arguments, or
/// `None`: each secret field (wrapped in `Secret<T>`, [`arg_type`]) and each
/// struct argument whose struct has a secret field (its own `Debug` redacts
/// it) is named, and the paragraph says the returned payload carries them in
/// clear.
pub(crate) fn secret_request_doc(cmd: &CommandDef, dts: &DatatypeMap<'_>) -> Option<String> {
    let names: Vec<String> = cmd
        .fields
        .iter()
        .filter(|f| {
            f.secret
                || dts
                    .get(f.ty.as_str())
                    .is_some_and(|d| d.fields.iter().any(|g| g.secret))
        })
        .map(|f| format!("`{}`", field_ident(&f.name)))
        .collect();
    let (list, verb, its, it) = match names.as_slice() {
        [] => return None,
        [one] => (one.clone(), "carries a secret", "its", "it"),
        [rest @ .., last] => (
            format!("{} and {last}", rest.join(", ")),
            "carry secrets",
            "their",
            "them",
        ),
    };
    Some(format!(
        "{list} {verb}: {its} `Debug` output shows `\"<redacted>\"`, but the returned \
         payload carries {it} in clear, so do not log the payload."
    ))
}

/// `note`: the command's [`element_note`] (supplement or provisional line).
fn emit_command_encoder(
    s: &mut String,
    cmd: &CommandDef,
    dts: &DatatypeMap<'_>,
    note: Option<&str>,
) {
    let args: Vec<String> = cmd
        .fields
        .iter()
        .map(|f| format!("{}: {}", field_ident(&f.name), borrowed(&arg_type(f))))
        .collect();
    line!(s, "/// Encode the `{}` command request payload.", cmd.name);
    if let Some(note) = note {
        line!(s, "///");
        line!(s, "/// {note}");
    }
    if let Some(doc) = secret_request_doc(cmd, dts) {
        line!(s, "///");
        line!(s, "/// {doc}");
    }
    for doc in choice_docs(&cmd.fields) {
        line!(s, "///");
        line!(s, "/// {doc}");
    }
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
        emit_field_write(s, f, &field_ident(&f.name), dts);
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
        "boolean" | "integer" | "float" | "string" | "bytes" | "enum" | "bitmap"
    );
    if scalar {
        // A secret argument is a `Secret<T>`: write the value it wraps.
        let inner = |expr: &str| {
            let value = if f.secret {
                format!("{expr}.expose()")
            } else {
                expr.to_string()
            };
            write_scalar(
                &f.metatype,
                &f.ty,
                f.entry_type.as_deref(),
                &tag,
                &value,
                dts,
            )
        };
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
    if f.metatype == "array" {
        emit_list_field_write(s, f, var, &tag, dts);
        return;
    }
    line!(
        s,
        "    compile_error!(\"unhandled command field {} (metatype {})\");",
        f.name,
        f.metatype
    );
}

/// Emit the write for a list-typed command request field (e.g.
/// `AtomicRequest.AttributeRequests = list<attrib-id>`, or
/// `ReviewFabricRestrictions.Arl = list<struct>`): open an array container at
/// the context tag, write each element at an anonymous tag — a scalar inline
/// ([`list_scalar_element_write`]), or a nested struct via its (recursive)
/// `write_fields` — then close.
fn emit_list_field_write(
    s: &mut String,
    f: &FieldDef,
    var: &str,
    tag: &str,
    dts: &DatatypeMap<'_>,
) {
    let entry = f.entry_type.as_deref().unwrap_or("octstr");
    let entry_meta = entry_metatype(entry, dts);
    // Per-element emission differs for struct vs scalar entries: a struct is
    // written as an anonymous container via its (recursive) write_fields; a
    // scalar is written inline. Structs, byte strings and strings are iterated
    // by reference; Copy scalars by value (list_scalar_element_write).
    // Here the writer is `let mut w` (command-encode body), so calls take `&mut w`.
    let open = |s: &mut String, expr: &str| {
        line!(
            s,
            "    w.start_array({tag}).expect(\"infallible: vec writer\");"
        );
        if entry_meta == "object" {
            line!(s, "    for el in {expr}.iter() {{");
            line!(
                s,
                "        w.start_structure(Tag::Anonymous).expect(\"infallible: vec writer\");"
            );
            line!(s, "        el.write_fields(&mut w);");
            line!(
                s,
                "        w.end_container().expect(\"infallible: vec writer\");"
            );
            line!(s, "    }}");
        } else {
            let (iter, put) = list_scalar_element_write(entry_meta, entry, dts);
            line!(s, "    for el in {expr}.{iter} {{");
            line!(s, "        {put}");
            line!(s, "    }}");
        }
        line!(
            s,
            "    w.end_container().expect(\"infallible: vec writer\");"
        );
    };
    match (f.optional, f.nullable) {
        (false, false) => open(s, var),
        (false, true) => {
            line!(s, "    match &{var} {{");
            line!(
                s,
                "        Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),"
            );
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
            line!(
                s,
                "        Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),"
            );
            line!(s, "        Nullable::Value({var}) => {{");
            open(s, var);
            line!(s, "        }}");
            line!(s, "    }} }}");
        }
    }
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

/// `note`: the response's [`element_note`] (supplement or provisional line),
/// written on the payload struct.
fn emit_response_decoder(
    s: &mut String,
    cmd: &CommandDef,
    dts: &DatatypeMap<'_>,
    note: Option<&str>,
) {
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
        global_name: None,
        kept_for: None,
        copied_from: None,
    };
    // Response payloads are decode-only (the gate is `!decl`), so the reachable
    // set is never consulted here — pass an empty one.
    emit_struct_decl_and_codec(
        s,
        &st,
        /*decl=*/ true,
        dts,
        &HashSet::new(),
        &HashSet::new(),
        note,
    );
}

fn emit_event_decoder(s: &mut String, ev: &EventDef, dts: &DatatypeMap<'_>) {
    // An event report's data is an anonymous structure of context-tagged
    // fields — the same wire shape as a response command payload — so the
    // same decode-only struct treatment is reused, named `<Name>Event`
    // (suffixed to keep clear of cluster datatypes; events are received,
    // never sent, so no encoder is emitted). Fieldless events carry no
    // payload to decode and get only their `event_id` const.
    if ev.fields.is_empty() {
        return;
    }
    let st = Datatype {
        name: format!("{}Event", ev.name),
        base: "struct".into(),
        kind: "struct".into(),
        values: vec![],
        bits: vec![],
        fields: ev.fields.iter().map(clone_field).collect(),
        global_name: None,
        kept_for: None,
        copied_from: None,
    };
    emit_struct_decl_and_codec(
        s,
        &st,
        /*decl=*/ true,
        dts,
        &HashSet::new(),
        &HashSet::new(),
        None,
    );
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
        fabric_sensitive: f.fabric_sensitive,
        mandatory_on_write: f.mandatory_on_write,
        provisional: f.provisional,
        choice: f.choice.clone(),
        required_when: f.required_when.clone(),
        relaxed_reason: f.relaxed_reason.clone(),
        nullable_reason: f.nullable_reason.clone(),
        secret: f.secret,
    }
}

/// True for a fabric-scoped datatype struct: one carrying field 254
/// (`FabricIndex`), the only fabric-scoped signal `@matter/model` gives. On an
/// unfiltered read a device sends another fabric's entries of such a struct
/// with their fabric-sensitive fields left out.
pub(crate) fn struct_is_fabric_scoped(d: &Datatype) -> bool {
    d.fields.iter().any(|f| f.id == 254)
}

/// True for a fabric-scoped struct with a field the dump relaxed to optional
/// for decoding only (`mandatory_on_write`, M9-A3 spec §5.4). Every encoder of
/// such a struct must refuse `None` in those fields: writing
/// `{privilege: Administer, subjects: None}` back would grant fabric-wide
/// admin. A sensitive field optional in the model itself is not guarded (it
/// may be omitted on write like any optional field). Event and command
/// payloads never qualify — the dump marks datatype struct fields only.
pub(crate) fn struct_has_write_guarded_fields(d: &Datatype) -> bool {
    struct_is_fabric_scoped(d) && d.fields.iter().any(|f| f.mandatory_on_write)
}

/// True when every field of `d` is a scalar: the rule for a struct a
/// **writable attribute** reaches. Such a struct with a composite field
/// (`object`/`array`) stays **decode-only**, like a response payload. In the
/// Matter 1.4 model this rule keeps two structs decode-only:
/// `AccessControlEntryStruct` (reached by `AccessControl` `ACL`; `Subjects`
/// and `Targets` are lists), which `matter-controller` writes with its own
/// encoder (`acl.rs`), and `ScheduleStruct` (reached by `Thermostat`
/// `Schedules`; `Transitions` is a list). A struct a request command reaches
/// is encoded whatever its fields (`emit_composite_field_write_self` writes
/// nested structs and lists, M9-A3 B7).
fn struct_is_write_capable(d: &Datatype) -> bool {
    d.fields.iter().all(|f| {
        matches!(
            f.metatype.as_str(),
            "boolean" | "integer" | "float" | "string" | "bytes" | "enum" | "bitmap"
        )
    })
}

/// True when the emitter generates `write_fields`/`encode` for the datatype
/// struct `d` (M9-A3 B4 rule): a request command reaches it
/// ([`command_encode_reachable_structs`]), or a writable attribute reaches it
/// ([`writable_attribute_reachable_structs`]) and its fields are all scalars
/// ([`struct_is_write_capable`]: a list or nested-struct field keeps it
/// decode-only). A struct nothing sends is decode-only. The one rule
/// [`encoded_struct_names`] applies, and so the emitter (whose encoder for a
/// struct with `mandatoryOnWrite` fields is the guarded one),
/// `model::validate`'s class-C check and the dump's mirror (`encodedStructs`
/// in index.js) all agree.
fn struct_is_encoded(
    d: &Datatype,
    command_reachable: &HashSet<&str>,
    writable_reachable: &HashSet<&str>,
) -> bool {
    let name = d.name.as_str();
    command_reachable.contains(name)
        || (writable_reachable.contains(name) && struct_is_write_capable(d))
}

/// Names of the datatype structs of `c` whose fields the emitter **encodes**:
/// those a request command reaches, and the all-scalar ones a writable
/// attribute reaches (M9-A3 B4; `struct_is_encoded`). `model::validate` uses
/// it to keep a class-C `meta.relaxed` field (a conditional conformance the
/// dump relaxed to optional) out of every encoder, from the same rule the
/// emitter follows.
pub fn encoded_struct_names(c: &Cluster) -> HashSet<&str> {
    let dts: DatatypeMap<'_> = c.datatypes.iter().map(|d| (d.name.as_str(), d)).collect();
    let command_reachable = command_encode_reachable_structs(c, &dts);
    let writable_reachable = writable_attribute_reachable_structs(c, &dts);
    c.datatypes
        .iter()
        .filter(|d| {
            d.kind == "struct" && struct_is_encoded(d, &command_reachable, &writable_reachable)
        })
        .map(|d| d.name.as_str())
        .collect()
}

/// Names of the fabric-scoped structs of `c` (a `FabricIndex` field, id 254)
/// that get an encoder only because a writable attribute carries them: their
/// `write_fields` leaves `FabricIndex` out, as chip's `EncodeForWrite` does,
/// because a server sets it to the accessing fabric on a write
/// (`AttributeValueDecoder::Decode`). No request command reaches them, so
/// their encoder serves attribute writes only.
#[must_use]
pub fn fabric_index_omitted_on_write(c: &Cluster) -> HashSet<&str> {
    let dts: DatatypeMap<'_> = c.datatypes.iter().map(|d| (d.name.as_str(), d)).collect();
    let command_reachable = command_encode_reachable_structs(c, &dts);
    let encoded = encoded_struct_names(c);
    c.datatypes
        .iter()
        .filter(|d| struct_omits_fabric_index_on_write(d, &command_reachable, &encoded))
        .map(|d| d.name.as_str())
        .collect()
}

/// The rule behind [`fabric_index_omitted_on_write`] for one struct `d`,
/// given the cluster's request-reachable structs (`command_reachable`) and its
/// encoded ones (`encoded`, [`encoded_struct_names`]): it is encoded, no
/// request reaches it, and it is fabric-scoped. `emit.rs` uses it for the
/// `fabric_index` field's rustdoc, from the same rule the encoder follows.
pub(crate) fn struct_omits_fabric_index_on_write(
    d: &Datatype,
    command_reachable: &HashSet<&str>,
    encoded: &HashSet<&str>,
) -> bool {
    let name = d.name.as_str();
    encoded.contains(name) && !command_reachable.contains(name) && struct_is_fabric_scoped(d)
}

fn emit_struct_codec(
    s: &mut String,
    d: &Datatype,
    dts: &DatatypeMap<'_>,
    encoded: &HashSet<&str>,
    write_only: &HashSet<&str>,
) {
    // Struct *decl* was already emitted by emit.rs::emit_struct; emit only the
    // codec here.
    emit_struct_decl_and_codec(s, d, /*decl=*/ false, dts, encoded, write_only, None);
}

/// Emit the codec for a struct `d`: `decode_from`(positioned reader) +
/// `decode`(bytes) + `write_fields`(into a writer) + `encode`(standalone
/// bytes). When `decl` is true, also emit the `pub struct` declaration
/// (response payloads aren't in the cluster datatypes), with `note` (the
/// response's [`element_note`]) as a rustdoc paragraph on it.
#[allow(clippy::too_many_lines)] // a code emitter — long but linear.
fn emit_struct_decl_and_codec(
    s: &mut String,
    d: &Datatype,
    decl: bool,
    dts: &DatatypeMap<'_>,
    encoded: &HashSet<&str>,
    write_only: &HashSet<&str>,
    note: Option<&str>,
) {
    if decl {
        line!(s, "/// Decoded `{}` payload.", d.name);
        if let Some(note) = note {
            line!(s, "///");
            line!(s, "/// {note}");
        }
        line!(s, "{}", struct_derive(&d.fields));
        line!(s, "#[non_exhaustive]");
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
            if f.provisional {
                line!(s, "    /// {PROVISIONAL_DOC}");
            }
            if let Some(reason) = &f.relaxed_reason {
                line!(s, "    /// {}", super::emit::relaxed_reason_doc(reason));
            }
            if let Some(reason) = &f.nullable_reason {
                line!(s, "    /// {}", super::emit::nullable_reason_doc(reason));
            }
            if f.secret {
                line!(s, "    /// {SECRET_DOC}");
            }
            line!(s, "    pub {}: {},", field_ident(&f.name), ty);
        }
        line!(s, "}}\n");
        emit_redacting_debug(s, &d.name, &d.fields);
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
        "                Some(Element::ContainerStart {{ .. }}) => r.skip_container()?,"
    );
    line!(
        s,
        "                Some(_) => {{}} // unknown/future scalar — skip"
    );
    line!(s, "            }}");
    line!(s, "        }}");
    line!(s, "        Ok(Self {{");
    for f in &d.fields {
        let var = snake(&f.name);
        let field = field_ident(&f.name);
        if f.optional {
            line!(s, "            {field}: f_{var},");
        } else {
            line!(
                s,
                "            {field}: f_{var}.ok_or(ClusterError::MissingField(\"{}\"))?,",
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

    // write_fields + encode: ONLY for the datatype structs in `encoded`
    // (`struct_is_encoded`): one a request command reaches, whatever its
    // fields (nested structs and guarded lists go through
    // `emit_composite_field_write_self`), or an all-scalar one a writable
    // attribute reaches. Response-payload structs (`decl`) are decode-only —
    // they may carry composite fields (e.g. list[struct]) that we never
    // re-encode.
    if !decl && encoded.contains(d.name.as_str()) {
        let omit_fabric_index = write_only.contains(d.name.as_str());
        if struct_has_write_guarded_fields(d) {
            emit_guarded_struct_write(s, d, dts, omit_fabric_index);
        } else {
            emit_infallible_write(s, d, dts, omit_fabric_index);
        }
    }

    line!(s, "}}\n");
}

/// The rustdoc paragraph on the `write_fields` of a struct whose encoder
/// leaves `FabricIndex` out ([`fabric_index_omitted_on_write`]).
const OMITTED_FABRIC_INDEX_DOC: [&str; 3] = [
    "    /// `fabric_index` is not written: as in chip's write encoding, the server",
    "    /// sets it to the fabric of the session that writes the attribute, so any",
    "    /// value works in an entry built to write.",
];

/// The rustdoc paragraph on the `encode` of a struct whose encoder leaves
/// `FabricIndex` out ([`fabric_index_omitted_on_write`]).
const OMITTED_FABRIC_INDEX_ENCODE_DOC: [&str; 3] = [
    "    /// `fabric_index` is not written (see [`Self::write_fields`]): the server adds",
    "    /// the accessing fabric's index, so decoding this output fails with",
    "    /// `ClusterError::MissingField(\"FabricIndex\")`.",
];

/// The fields `write_fields` writes: all of `d`'s, less `FabricIndex` (id
/// 254) when `omit_fabric_index`.
fn written_fields(d: &Datatype, omit_fabric_index: bool) -> impl Iterator<Item = &FieldDef> {
    d.fields
        .iter()
        .filter(move |f| !(omit_fabric_index && f.id == 254))
}

/// `write_fields` + `encode` for an ordinary datatype struct: both infallible.
fn emit_infallible_write(
    s: &mut String,
    d: &Datatype,
    dts: &DatatypeMap<'_>,
    omit_fabric_index: bool,
) {
    line!(
        s,
        "    /// Write this struct's fields into an already-open container."
    );
    if omit_fabric_index {
        line!(s, "    ///");
        for doc in OMITTED_FABRIC_INDEX_DOC {
            line!(s, "{doc}");
        }
    }
    line!(
        s,
        "    #[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible."
    );
    line!(
        s,
        "    pub fn write_fields(&self, w: &mut TlvWriter<'_>) {{"
    );
    for f in written_fields(d, omit_fabric_index) {
        emit_field_write_self(s, f, dts);
    }
    line!(s, "    }}");

    line!(s, "    /// Encode as a standalone anonymous TLV structure.");
    if omit_fabric_index {
        line!(s, "    ///");
        for doc in OMITTED_FABRIC_INDEX_ENCODE_DOC {
            line!(s, "{doc}");
        }
    }
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
}

/// `write_fields` + `encode` for a write-guarded struct (see
/// [`struct_has_write_guarded_fields`]): both return `Result` and fail with
/// `ClusterError::MissingField` when a `mandatory_on_write` field is `None`. Every sensitive field is checked **before** anything is written,
/// so a refused `write_fields` leaves the caller's writer untouched. The
/// field writes themselves are the ordinary ones.
fn emit_guarded_struct_write(
    s: &mut String,
    d: &Datatype,
    dts: &DatatypeMap<'_>,
    omit_fabric_index: bool,
) {
    let guarded: Vec<&FieldDef> = d.fields.iter().filter(|f| f.mandatory_on_write).collect();
    line!(
        s,
        "    /// Write this struct's fields into an already-open container."
    );
    if omit_fabric_index {
        line!(s, "    ///");
        for doc in OMITTED_FABRIC_INDEX_DOC {
            line!(s, "{doc}");
        }
    }
    line!(s, "    ///");
    line!(
        s,
        "    /// A device withholds this struct's fabric-sensitive fields for entries of"
    );
    line!(
        s,
        "    /// other fabrics, so a read result can hold entries with them `None`. Filter"
    );
    line!(
        s,
        "    /// a read result to your own `fabric_index` before writing it back."
    );
    line!(s, "    ///");
    line!(s, "    /// # Errors");
    line!(
        s,
        "    /// [`ClusterError::MissingField`] if a fabric-sensitive field required on"
    );
    line!(
        s,
        "    /// write is `None`; nothing is written in that case."
    );
    line!(
        s,
        "    #[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible."
    );
    line!(
        s,
        "    pub fn write_fields(&self, w: &mut TlvWriter<'_>) -> Result<(), ClusterError> {{"
    );
    for f in &guarded {
        line!(
            s,
            "        if self.{}.is_none() {{ return Err(ClusterError::MissingField(\"{}\")); }}",
            field_ident(&f.name),
            f.name
        );
    }
    for f in written_fields(d, omit_fabric_index) {
        emit_field_write_self(s, f, dts);
    }
    line!(s, "        Ok(())");
    line!(s, "    }}");

    line!(s, "    /// Encode as a standalone anonymous TLV structure.");
    if omit_fabric_index {
        line!(s, "    ///");
        for doc in OMITTED_FABRIC_INDEX_ENCODE_DOC {
            line!(s, "{doc}");
        }
    }
    line!(s, "    ///");
    line!(s, "    /// # Errors");
    line!(
        s,
        "    /// [`ClusterError::MissingField`] if a fabric-sensitive field required on"
    );
    line!(s, "    /// write is `None` (see [`Self::write_fields`]).");
    line!(
        s,
        "    #[allow(clippy::expect_used)] // Vec-backed TlvWriter is infallible."
    );
    line!(
        s,
        "    pub fn encode(&self) -> Result<Vec<u8>, ClusterError> {{"
    );
    line!(s, "        let mut buf = Vec::new();");
    line!(s, "        let mut w = TlvWriter::new(&mut buf);");
    line!(
        s,
        "        w.start_structure(Tag::Anonymous).expect(\"infallible: vec writer\");"
    );
    line!(s, "        self.write_fields(&mut w)?;");
    line!(
        s,
        "        w.end_container().expect(\"infallible: vec writer\");"
    );
    line!(s, "        Ok(buf)");
    line!(s, "    }}");
}

/// Emit a `write_fields` line for struct field `f`, reading `self.<field>`.
///
/// Scalars are written inline. A nested struct (`object`) or a list (`array`)
/// field is written through [`emit_composite_field_write_self`]; only a
/// request command reaches a struct with such a field (a writable attribute's
/// encoded struct is all-scalar, [`struct_is_write_capable`]).
fn emit_field_write_self(s: &mut String, f: &FieldDef, dts: &DatatypeMap<'_>) {
    // `field_ident` covers both the `self.<field>` access and the local pattern
    // bindings (`Nullable::Value(<var>)`), so a keyword field name is escaped
    // uniformly.
    let var = field_ident(&f.name);
    let tag = format!("Tag::Context({})", f.id);
    if f.metatype == "object" || f.metatype == "array" {
        emit_composite_field_write_self(s, f, &var, &tag, dts);
        return;
    }
    let inner =
        |expr: &str| write_scalar(&f.metatype, &f.ty, f.entry_type.as_deref(), &tag, expr, dts);
    // A bound `Nullable::Value`/`Some` field needs dereferencing. Named
    // enum/bitmap writes append a method call (`.to_raw()`/`.bits()`), so the
    // deref must be parenthesized; every other scalar write takes the bare
    // `*var` (avoids an `unused_parens` warning under `-D warnings`).
    let needs_method =
        matches!(f.metatype.as_str(), "enum" | "bitmap") && named_backing(&f.ty, dts).is_some();
    let deref = if needs_method {
        format!("(*{var})")
    } else {
        format!("*{var}")
    };
    match (f.optional, f.nullable) {
        (false, false) => line!(s, "        {}", inner(&format!("self.{var}"))),
        (false, true) => {
            line!(s, "        match &self.{var} {{");
            line!(s, "            Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),");
            line!(
                s,
                "            Nullable::Value({var}) => {{ {} }}",
                inner(&deref)
            );
            line!(s, "        }}");
        }
        (true, false) => {
            line!(
                s,
                "        if let Some({var}) = &self.{var} {{ {} }}",
                inner(&deref)
            );
        }
        (true, true) => {
            line!(s, "        if let Some({var}) = &self.{var} {{");
            line!(s, "            match {var} {{");
            line!(s, "                Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),");
            line!(
                s,
                "                Nullable::Value({var}) => {{ {} }}",
                inner(&deref)
            );
            line!(s, "            }}");
            line!(s, "        }}");
        }
    }
}

/// The `write_fields` lines for a nested struct or list field `f` of an
/// encoded struct, bound as `self.<var>`, with its optional (`Option`, absent
/// = left out) and nullable (`Nullable::Null` = a TLV null) guards (M9-A3 B7).
/// Inside `write_fields(&self, w: &mut TlvWriter)` the writer `w` is already
/// `&mut`.
///
/// - A nested struct is a sub-structure at the context tag, written by its own
///   `write_fields` (`ContentLauncher` `StyleInformationStruct.Size`,
///   `PlaybackPreferencesStruct.TextTrack`). It is infallible: a write-guarded
///   struct is never reachable from a request command
///   ([`assert_no_write_guarded_command_structs`]).
/// - A list is an array at the context tag, each element at an anonymous tag:
///   a nested struct via its `write_fields`, or a scalar
///   ([`list_scalar_element_write`]: Copy scalars by value, byte strings and
///   strings by reference). `ContentLauncher` `ParameterStruct.ExternalIdList`
///   is optional; `PlaybackPreferencesStruct.AudioTracks` and
///   `TrackPreferenceStruct.Characteristics` are optional and nullable.
///
/// An unguarded list keeps the form the emitter has always produced
/// (`for el in &self.<var>` / `for el in self.<var>.<iter>`).
fn emit_composite_field_write_self(
    s: &mut String,
    f: &FieldDef,
    var: &str,
    tag: &str,
    dts: &DatatypeMap<'_>,
) {
    // `by_ref` iterates a list of structs; `owner` is the value itself (a
    // nested struct, or a list of scalars, which appends its iterator call).
    let write = |s: &mut String, by_ref: &str, owner: &str| {
        if f.metatype == "object" {
            line!(
                s,
                "        w.start_structure({tag}).expect(\"infallible: vec writer\");"
            );
            line!(s, "        {owner}.write_fields(w);");
            line!(
                s,
                "        w.end_container().expect(\"infallible: vec writer\");"
            );
            return;
        }
        let entry = f.entry_type.as_deref().unwrap_or("octstr");
        let entry_meta = entry_metatype(entry, dts);
        line!(
            s,
            "        w.start_array({tag}).expect(\"infallible: vec writer\");"
        );
        if entry_meta == "object" {
            line!(s, "        for el in {by_ref} {{");
            line!(
                s,
                "            w.start_structure(Tag::Anonymous).expect(\"infallible: vec writer\");"
            );
            line!(s, "            el.write_fields(w);");
            line!(
                s,
                "            w.end_container().expect(\"infallible: vec writer\");"
            );
            line!(s, "        }}");
        } else {
            let (iter, put) = list_scalar_element_write(entry_meta, entry, dts);
            line!(s, "        for el in {owner}.{iter} {{");
            line!(s, "            {put}");
            line!(s, "        }}");
        }
        line!(
            s,
            "        w.end_container().expect(\"infallible: vec writer\");"
        );
    };
    match (f.optional, f.nullable) {
        (false, false) => write(s, &format!("&self.{var}"), &format!("self.{var}")),
        (false, true) => {
            line!(s, "        match &self.{var} {{");
            line!(s, "            Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),");
            line!(s, "            Nullable::Value({var}) => {{");
            write(s, var, var);
            line!(s, "            }}");
            line!(s, "        }}");
        }
        (true, false) => {
            line!(s, "        if let Some({var}) = &self.{var} {{");
            write(s, var, var);
            line!(s, "        }}");
        }
        (true, true) => {
            line!(s, "        if let Some({var}) = &self.{var} {{");
            line!(s, "            match {var} {{");
            line!(s, "                Nullable::Null => w.put_null({tag}).expect(\"infallible: vec writer\"),");
            line!(s, "                Nullable::Value({var}) => {{");
            write(s, var, var);
            line!(s, "                }}");
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
        "boolean" | "integer" | "float" | "string" | "bytes" | "enum" | "bitmap"
    );
    if scalar {
        let ctx = f.name.clone();
        let mut arms = vec![read_scalar(
            &f.metatype,
            &f.ty,
            f.entry_type.as_deref(),
            &ctx,
            dts,
        )];
        arms.extend(read_scalar_widened(
            &f.metatype,
            &f.ty,
            f.entry_type.as_deref(),
        ));
        if f.nullable {
            line!(s, "                Some(Element::Scalar {{ tag: Tag::Context({}), value: Value::Null }}) => f_{} = Some(Nullable::Null),", f.id, var);
        }
        for (pat, build) in &arms {
            if f.nullable {
                line!(s, "                Some(Element::Scalar {{ tag: Tag::Context({}), value: {} }}) => f_{} = Some(Nullable::Value({})),", f.id, pat, var, build);
            } else {
                line!(s, "                Some(Element::Scalar {{ tag: Tag::Context({}), value: {} }}) => f_{} = Some({}),", f.id, pat, var, build);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn field(id: u32, name: &str, ty: &str, metatype: &str, entry: Option<&str>) -> FieldDef {
        FieldDef {
            id,
            name: name.to_string(),
            ty: ty.to_string(),
            metatype: metatype.to_string(),
            entry_type: entry.map(str::to_string),
            nullable: false,
            optional: false,
            fabric_sensitive: false,
            mandatory_on_write: false,
            provisional: false,
            choice: None,
            required_when: None,
            relaxed_reason: None,
            nullable_reason: None,
            secret: false,
        }
    }

    fn struct_dt(name: &str, fields: Vec<FieldDef>) -> Datatype {
        Datatype {
            name: name.to_string(),
            base: "struct".to_string(),
            kind: "struct".to_string(),
            values: vec![],
            bits: vec![],
            fields,
            global_name: None,
            kept_for: None,
            copied_from: None,
        }
    }

    #[test]
    fn scalar_only_struct_is_write_capable() {
        let d = struct_dt(
            "EnergyMeasurementStruct",
            vec![
                field(0, "Energy", "energy-mWh", "integer", None),
                field(1, "StartTimestamp", "epoch-s", "integer", None),
            ],
        );
        assert!(struct_is_write_capable(&d));
    }

    #[test]
    fn struct_with_array_field_is_not_write_capable() {
        let d = struct_dt(
            "MeasurementAccuracyStruct",
            vec![
                field(1, "Measured", "bool", "boolean", None),
                field(
                    4,
                    "AccuracyRanges",
                    "list",
                    "array",
                    Some("MeasurementAccuracyRangeStruct"),
                ),
            ],
        );
        assert!(!struct_is_write_capable(&d));
    }

    #[test]
    fn struct_with_object_field_is_not_write_capable() {
        let d = struct_dt(
            "Outer",
            vec![field(0, "Inner", "InnerStruct", "object", None)],
        );
        assert!(!struct_is_write_capable(&d));
    }

    #[test]
    fn entry_metatype_classifies_named_enum_and_struct_elements() {
        let enum_d = struct_dt("WiredFaultEnum", vec![]);
        let enum_d = Datatype {
            base: "enum8".to_string(),
            kind: "enum".to_string(),
            ..enum_d
        };
        let struct_d = struct_dt("DeviceTypeStruct", vec![]);
        let dts: DatatypeMap<'_> = [
            (enum_d.name.as_str(), &enum_d),
            (struct_d.name.as_str(), &struct_d),
        ]
        .into_iter()
        .collect();
        // A named enum element decodes via from_raw, not as a bare integer.
        assert_eq!(entry_metatype("WiredFaultEnum", &dts), "enum");
        assert_eq!(entry_metatype("DeviceTypeStruct", &dts), "object");
        // A bare scalar id stays integer.
        assert_eq!(entry_metatype("endpoint-no", &dts), "integer");
    }

    #[test]
    fn list_scalar_command_field_encodes_array() {
        // AtomicRequest.AttributeRequests = list<attrib-id> (mandatory).
        let f = field(1, "AttributeRequests", "list", "array", Some("attrib-id"));
        let mut s = String::new();
        emit_field_write(&mut s, &f, "attribute_requests", &HashMap::new());
        assert!(s.contains("w.start_array(Tag::Context(1))"), "{s}");
        assert!(
            s.contains("for el in attribute_requests.iter().copied() {"),
            "{s}"
        );
        assert!(
            s.contains("w.put_uint(Tag::Anonymous, u64::from(el))"),
            "{s}"
        );
        assert!(s.contains("w.end_container()"), "{s}");
        assert!(!s.contains("compile_error!"), "no fallthrough:\n{s}");
    }

    #[test]
    fn byte_string_and_string_list_elements_are_written_by_reference() {
        // M9-A3 B5: Messages CancelMessagesRequest.MessageIDs is a
        // list<octstr>. `Vec<u8>` and `String` are not Copy, so the elements
        // are iterated by reference and passed to put_bytes / put_utf8 as is;
        // `iter().copied()` there does not compile (spec §10).
        let ids = field(0, "MessageIDs", "list", "array", Some("octstr"));
        let mut s = String::new();
        emit_field_write(&mut s, &ids, "message_i_ds", &HashMap::new());
        assert!(s.contains("for el in message_i_ds.iter() {"), "{s}");
        assert!(s.contains("w.put_bytes(Tag::Anonymous, el)"), "{s}");
        assert!(!s.contains(".copied()"), "{s}");

        let labels = field(1, "Labels", "list", "array", Some("string"));
        let mut s = String::new();
        emit_field_write(&mut s, &labels, "labels", &HashMap::new());
        assert!(s.contains("for el in labels.iter() {"), "{s}");
        assert!(s.contains("w.put_utf8(Tag::Anonymous, el)"), "{s}");
        assert!(!s.contains(".copied()"), "{s}");
    }

    #[test]
    fn encoded_struct_byte_string_list_field_is_written_by_reference() {
        // The struct encoder (write_fields) shares the element rule: a
        // list<octstr> field iterates `&self.<field>` by reference.
        let d = struct_dt(
            "TokenSetStruct",
            vec![field(0, "Tokens", "list", "array", Some("octstr"))],
        );
        let dts: DatatypeMap<'_> = HashMap::new();
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &dts, &encoded(&d), &HashSet::new());
        assert!(s.contains("for el in self.tokens.iter() {"), "{s}");
        assert!(s.contains("w.put_bytes(Tag::Anonymous, el)"), "{s}");
        assert!(!s.contains(".copied()"), "{s}");
    }

    #[test]
    fn nested_struct_fields_of_an_encoded_struct_write_sub_structures() {
        // M9-A3 B7: ContentLauncher StyleInformationStruct.Size (optional),
        // PlaybackPreferencesStruct.TextTrack (optional, nullable). Before B7
        // the scalar writer panicked on metatype `object` here.
        let mut maybe = field(1, "Size", "DimensionStruct", "object", None);
        maybe.optional = true;
        let mut both = field(2, "TextTrack", "TrackPreferenceStruct", "object", None);
        both.optional = true;
        both.nullable = true;
        let mut null = field(3, "Pinned", "DimensionStruct", "object", None);
        null.nullable = true;
        let d = struct_dt(
            "OuterStruct",
            vec![
                field(0, "Inner", "DimensionStruct", "object", None),
                maybe,
                both,
                null,
            ],
        );
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &HashMap::new(), &encoded(&d), &HashSet::new());
        for want in [
            "        w.start_structure(Tag::Context(0)).expect(\"infallible: vec writer\");\n        self.inner.write_fields(w);\n",
            "        if let Some(size) = &self.size {\n        w.start_structure(Tag::Context(1)).expect(\"infallible: vec writer\");\n        size.write_fields(w);\n",
            "        if let Some(text_track) = &self.text_track {\n            match text_track {\n                Nullable::Null => w.put_null(Tag::Context(2))",
            "                Nullable::Value(text_track) => {\n        w.start_structure(Tag::Context(2))",
            "        match &self.pinned {\n            Nullable::Null => w.put_null(Tag::Context(3))",
            "        pinned.write_fields(w);\n",
        ] {
            assert!(s.contains(want), "missing {want:?} in:\n{s}");
        }
        assert!(!s.contains("compile_error!"), "{s}");
    }

    #[test]
    fn optional_and_nullable_list_fields_of_an_encoded_struct_are_guarded() {
        // M9-A3 B7: ContentLauncher ParameterStruct.ExternalIdList (optional
        // list of structs), PlaybackPreferencesStruct.AudioTracks (optional,
        // nullable list of structs), TrackPreferenceStruct.Characteristics
        // (optional, nullable list of enums). Before B7 these were a
        // compile_error!.
        let mut ids = field(
            2,
            "ExternalIdList",
            "list",
            "array",
            Some("AdditionalInfoStruct"),
        );
        ids.optional = true;
        let mut tracks = field(
            3,
            "AudioTracks",
            "list",
            "array",
            Some("TrackPreferenceStruct"),
        );
        tracks.optional = true;
        tracks.nullable = true;
        let mut chars = field(
            4,
            "Characteristics",
            "list",
            "array",
            Some("CharacteristicEnum"),
        );
        chars.optional = true;
        chars.nullable = true;
        let mut nums = field(5, "Numbers", "list", "array", Some("uint16"));
        nums.nullable = true;
        let info = struct_dt("AdditionalInfoStruct", vec![]);
        let track = struct_dt("TrackPreferenceStruct", vec![]);
        let characteristic = Datatype {
            base: "enum8".to_string(),
            kind: "enum".to_string(),
            ..struct_dt("CharacteristicEnum", vec![])
        };
        let dts: DatatypeMap<'_> = [&info, &track, &characteristic]
            .into_iter()
            .map(|d| (d.name.as_str(), d))
            .collect();
        let d = struct_dt("PrefsStruct", vec![ids, tracks, chars, nums]);
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &dts, &encoded(&d), &HashSet::new());
        for want in [
            "        if let Some(external_id_list) = &self.external_id_list {\n        w.start_array(Tag::Context(2))",
            "        for el in external_id_list {\n",
            "        if let Some(audio_tracks) = &self.audio_tracks {\n            match audio_tracks {\n                Nullable::Null => w.put_null(Tag::Context(3))",
            "        for el in audio_tracks {\n",
            "                Nullable::Null => w.put_null(Tag::Context(4))",
            "        for el in characteristics.iter().copied() {\n            w.put_uint(Tag::Anonymous, u64::from(el.to_raw()))",
            "        match &self.numbers {\n            Nullable::Null => w.put_null(Tag::Context(5))",
            "        for el in numbers.iter().copied() {\n",
        ] {
            assert!(s.contains(want), "missing {want:?} in:\n{s}");
        }
        assert!(!s.contains("compile_error!"), "{s}");
    }

    #[test]
    fn an_unguarded_list_field_keeps_its_original_form() {
        // The B7 guards leave the existing (mandatory, non-nullable) list
        // writes byte-identical: EnergyEvse, DeviceEnergyManagement and
        // ScenesManagement encode such lists today.
        let info = struct_dt("PointStruct", vec![]);
        let dts: DatatypeMap<'_> = std::iter::once(("PointStruct", &info)).collect();
        let d = struct_dt(
            "ListsStruct",
            vec![
                field(0, "Points", "list", "array", Some("PointStruct")),
                field(1, "Ids", "list", "array", Some("uint32")),
            ],
        );
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &dts, &encoded(&d), &HashSet::new());
        assert!(s.contains("        for el in &self.points {\n"), "{s}");
        assert!(
            s.contains("        for el in self.ids.iter().copied() {\n"),
            "{s}"
        );
    }

    #[test]
    fn a_response_with_a_secret_field_redacts_it_in_its_debug() {
        // M9-A3 B6: WiFiNetworkManagement NetworkPassphraseResponse.Passphrase.
        let mut passphrase = field(0, "Passphrase", "octstr", "bytes", None);
        passphrase.secret = true;
        let cmd = CommandDef {
            id: 1,
            name: "NetworkPassphraseResponse".to_string(),
            direction: "response".to_string(),
            response_id: None,
            fields: vec![passphrase],
            provisional: false,
            deprecated: false,
            supplemented: None,
        };
        let mut s = String::new();
        emit_response_decoder(&mut s, &cmd, &HashMap::new(), None);
        assert!(
            s.contains("#[derive(Clone, PartialEq)]\n#[non_exhaustive]"),
            "{s}"
        );
        assert!(
            s.contains("impl core::fmt::Debug for NetworkPassphraseResponse {"),
            "{s}"
        );
        assert!(s.contains(".field(\"passphrase\", &\"<redacted>\")"), "{s}");
        assert!(!s.contains("&self.passphrase"), "{s}");
        assert!(s.contains(&format!("    /// {SECRET_DOC}\n")), "{s}");
    }

    #[test]
    fn a_secret_request_argument_is_wrapped_and_written_through_expose() {
        // AccountLogin `Login.SetupPin` (a required string) and DoorLock
        // `LockDoor.PINCode` (an optional byte string).
        let mut pin = field(0, "SetupPin", "string", "string", None);
        pin.secret = true;
        let mut code = field(1, "PinCode", "octstr", "bytes", None);
        code.secret = true;
        code.optional = true;
        let plain = field(2, "Hint", "string", "string", None);
        let cmd = request_cmd("Login", vec![pin, code, plain]);
        let mut s = String::new();
        emit_command_encoder(&mut s, &cmd, &HashMap::new(), None);
        for want in [
            "pub fn encode_login(setup_pin: &Secret<String>, pin_code: Option<Secret<Vec<u8>>>, hint: &String) -> Vec<u8> {",
            "    w.put_utf8(Tag::Context(0), &setup_pin.expose())",
            "    if let Some(pin_code) = pin_code { w.put_bytes(Tag::Context(1), &pin_code.expose())",
            "    w.put_utf8(Tag::Context(2), &hint)",
            "/// `setup_pin` and `pin_code` carry secrets: their `Debug` output shows `\"<redacted>\"`, \
             but the returned payload carries them in clear, so do not log the payload.\n",
        ] {
            assert!(s.contains(want), "missing {want:?} in:\n{s}");
        }
    }

    #[test]
    fn a_request_without_secrets_has_no_secret_doc() {
        let cmd = request_cmd("Toggle", vec![field(0, "Hint", "string", "string", None)]);
        assert_eq!(secret_request_doc(&cmd, &HashMap::new()), None);
        let mut s = String::new();
        emit_command_encoder(&mut s, &cmd, &HashMap::new(), None);
        assert!(!s.contains("Secret<") && !s.contains(".expose()"), "{s}");
    }

    #[test]
    fn a_struct_argument_holding_a_secret_is_named_in_the_doc() {
        // GroupKeyManagement `KeySetWrite.GroupKeySet`: the struct's own
        // `Debug` redacts its epoch keys, so the argument is not wrapped.
        let mut key = field(0, "EpochKey0", "octstr", "bytes", None);
        key.secret = true;
        let set = struct_dt("GroupKeySetStruct", vec![key]);
        let dts: DatatypeMap<'_> = std::iter::once((set.name.as_str(), &set)).collect();
        let cmd = request_cmd(
            "KeySetWrite",
            vec![field(0, "GroupKeySet", "GroupKeySetStruct", "object", None)],
        );
        assert_eq!(
            secret_request_doc(&cmd, &dts).as_deref(),
            Some(
                "`group_key_set` carries a secret: its `Debug` output shows `\"<redacted>\"`, \
                 but the returned payload carries it in clear, so do not log the payload."
            )
        );
    }

    #[test]
    fn a_write_only_fabric_scoped_struct_leaves_fabric_index_out() {
        // Binding `TargetStruct`: a writable list attribute carries it, no
        // request does, and it is fabric-scoped (field 254).
        let mut node = field(1, "Node", "uint64", "integer", None);
        node.optional = true;
        let d = struct_dt(
            "TargetStruct",
            vec![
                node,
                field(254, "FabricIndex", "fabric-idx", "integer", None),
            ],
        );
        let write_only: HashSet<&str> = std::iter::once("TargetStruct").collect();
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &HashMap::new(), &encoded(&d), &write_only);
        assert!(
            !s.contains("Tag::Context(254), u64::from(self.fabric_index)"),
            "{s}"
        );
        assert!(s.contains("Tag::Context(1)"), "{s}");
        assert!(s.contains(OMITTED_FABRIC_INDEX_DOC[0]), "{s}");
        // `encode` says so too, right after its summary line.
        assert!(
            s.contains(&format!(
                "    /// Encode as a standalone anonymous TLV structure.\n    ///\n{}\n",
                OMITTED_FABRIC_INDEX_ENCODE_DOC.join("\n")
            )),
            "{s}"
        );
        // A request-reachable one (not in `write_only`) still writes it.
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &HashMap::new(), &encoded(&d), &HashSet::new());
        assert!(
            s.contains("w.put_uint(Tag::Context(254), u64::from(self.fabric_index))"),
            "{s}"
        );
        assert!(!s.contains(OMITTED_FABRIC_INDEX_DOC[0]), "{s}");
        assert!(!s.contains(OMITTED_FABRIC_INDEX_ENCODE_DOC[0]), "{s}");
        // A write-guarded one (AccessControl `AccessControlExtensionStruct`):
        // the same paragraphs, ahead of its `# Errors` sections.
        let mut data = field(1, "Data", "octstr", "bytes", None);
        data.optional = true;
        data.fabric_sensitive = true;
        data.mandatory_on_write = true;
        let d = struct_dt(
            "TargetStruct",
            vec![
                data,
                field(254, "FabricIndex", "fabric-idx", "integer", None),
            ],
        );
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &HashMap::new(), &encoded(&d), &write_only);
        assert!(s.contains("-> Result<(), ClusterError>"), "{s}");
        assert!(
            !s.contains("Tag::Context(254), u64::from(self.fabric_index)"),
            "{s}"
        );
        assert!(s.contains(OMITTED_FABRIC_INDEX_DOC[0]), "{s}");
        assert!(
            s.contains(&format!(
                "    /// Encode as a standalone anonymous TLV structure.\n    ///\n{}\n    ///\n    /// # Errors\n",
                OMITTED_FABRIC_INDEX_ENCODE_DOC.join("\n")
            )),
            "{s}"
        );
    }

    #[test]
    fn optional_list_scalar_command_field_guards_with_if_let() {
        let mut f = field(1, "AttributeRequests", "list", "array", Some("attrib-id"));
        f.optional = true;
        let mut s = String::new();
        emit_field_write(&mut s, &f, "attribute_requests", &HashMap::new());
        assert!(
            s.contains("if let Some(attribute_requests) = &attribute_requests {"),
            "{s}"
        );
        assert!(s.contains("w.start_array(Tag::Context(1))"), "{s}");
    }

    #[test]
    fn keyword_struct_field_is_escaped() {
        // A datatype struct whose field is the Rust keyword `Type`.
        let d = struct_dt(
            "NetworkInterface",
            vec![field(7, "Type", "InterfaceTypeEnum", "enum", None)],
        );
        let mut s = String::new();
        let dts: DatatypeMap<'_> = HashMap::new();
        emit_struct_codec(&mut s, &d, &dts, &encoded(&d), &HashSet::new());
        assert!(s.contains("r#type: f_type"), "construction escaped:\n{s}");
        assert!(
            !s.contains("            type: f_type"),
            "raw keyword field:\n{s}"
        );
    }

    #[test]
    fn field_ident_escapes_keyword_and_passes_through_normal() {
        assert_eq!(field_ident("Type"), "r#type");
        assert_eq!(field_ident("HardwareAddress"), "hardware_address");
    }

    #[test]
    fn entry_metatype_classifies_bytes_and_string_elements() {
        let dts: DatatypeMap<'_> = HashMap::new();
        // list<ipv4adr> / list<octstr> elements decode as bytes, not integers.
        assert_eq!(entry_metatype("ipv4adr", &dts), "bytes");
        assert_eq!(entry_metatype("octstr", &dts), "bytes");
        // list<string> elements decode as Utf8.
        assert_eq!(entry_metatype("string", &dts), "string");
        // a bare integer id stays integer.
        assert_eq!(entry_metatype("group-id", &dts), "integer");
    }

    fn request_cmd(name: &str, fields: Vec<FieldDef>) -> CommandDef {
        CommandDef {
            id: 0,
            name: name.to_string(),
            direction: "request".to_string(),
            response_id: None,
            fields,
            provisional: false,
            deprecated: false,
            supplemented: None,
        }
    }

    /// The encoded set naming only `d`: the emitter then writes its encoder.
    fn encoded(d: &Datatype) -> HashSet<&str> {
        std::iter::once(d.name.as_str()).collect()
    }

    fn cluster_with(commands: Vec<CommandDef>, datatypes: Vec<Datatype>) -> Cluster {
        Cluster {
            id: 0x1,
            name: "T".to_string(),
            revision: 1,
            model_revision: None,
            provisional: false,
            features: vec![],
            attributes: vec![],
            commands,
            events: vec![],
            datatypes,
        }
    }

    #[test]
    fn event_decoder_is_decode_only_with_event_suffix() {
        let ev = EventDef {
            id: 6,
            name: "MultiPressComplete".to_string(),
            priority: "info".to_string(),
            fields: vec![
                field(0, "PreviousPosition", "uint8", "integer", None),
                field(1, "TotalNumberOfPressesCounted", "uint8", "integer", None),
            ],
            provisional: false,
        };
        let mut s = String::new();
        emit_event_decoder(&mut s, &ev, &DatatypeMap::new());
        assert!(
            s.contains("pub struct MultiPressCompleteEvent {"),
            "payload struct missing:\n{s}"
        );
        assert!(s.contains("pub fn decode(tlv: &[u8])"), "{s}");
        assert!(
            !s.contains("pub fn encode") && !s.contains("pub fn write_fields"),
            "events are received, never sent — decode-only:\n{s}"
        );
    }

    #[test]
    fn fieldless_event_emits_no_payload_struct() {
        let ev = EventDef {
            id: 3,
            name: "ReachableChanged".to_string(),
            priority: "critical".to_string(),
            fields: vec![],
            provisional: false,
        };
        let mut s = String::new();
        emit_event_decoder(&mut s, &ev, &DatatypeMap::new());
        assert!(s.is_empty(), "fieldless event emitted code:\n{s}");
    }

    #[test]
    fn command_encode_reachable_collects_transitive_structs() {
        // A request command taking list<Outer>; Outer has a list<Inner> field.
        let inner = struct_dt("Inner", vec![field(0, "Id", "uint32", "integer", None)]);
        let outer = struct_dt(
            "Outer",
            vec![field(0, "Items", "list", "array", Some("Inner"))],
        );
        let cmd = request_cmd(
            "DoIt",
            vec![field(0, "Arg", "list", "array", Some("Outer"))],
        );
        let c = cluster_with(vec![cmd], vec![inner, outer]);
        let dts: DatatypeMap<'_> = c.datatypes.iter().map(|d| (d.name.as_str(), d)).collect();
        let set = command_encode_reachable_structs(&c, &dts);
        assert!(set.contains("Outer"), "{set:?}");
        assert!(set.contains("Inner"), "transitive via list field: {set:?}");
    }

    #[test]
    fn command_encode_reachable_empty_without_struct_command_fields() {
        // A scalar-list request command does NOT reach any struct (the case for
        // every committed cluster -> zero generated-output change).
        let dt = struct_dt("Unused", vec![field(0, "Id", "uint32", "integer", None)]);
        let cmd = request_cmd(
            "Scalar",
            vec![field(0, "Ids", "list", "array", Some("attrib-id"))],
        );
        let c = cluster_with(vec![cmd], vec![dt]);
        let dts: DatatypeMap<'_> = c.datatypes.iter().map(|d| (d.name.as_str(), d)).collect();
        assert!(command_encode_reachable_structs(&c, &dts).is_empty());
    }

    #[test]
    fn list_of_struct_command_field_encodes_array_of_structs() {
        // emit_list_field_write must wrap each element in an anon structure and
        // call write_fields (no compile_error).
        let f = field(1, "Arl", "list", "array", Some("EntryStruct"));
        let entry = struct_dt(
            "EntryStruct",
            vec![field(0, "Id", "uint32", "integer", None)],
        );
        let dts: DatatypeMap<'_> = std::iter::once(("EntryStruct", &entry)).collect();
        let mut s = String::new();
        emit_list_field_write(&mut s, &f, "arl", "Tag::Context(1)", &dts);
        assert!(s.contains("w.start_array(Tag::Context(1))"), "{s}");
        assert!(s.contains("w.start_structure(Tag::Anonymous)"), "{s}");
        assert!(s.contains(".write_fields(&mut w)"), "{s}");
        assert!(!s.contains("compile_error!"), "{s}");
    }

    // ---- float metatype (M9-A2.6 concentration measurement) --------------

    #[test]
    fn read_scalar_float_matches_wire_width() {
        let dts: DatatypeMap<'_> = HashMap::new();
        // `single` -> TLV FLOAT32 -> Value::Float(f32).
        assert_eq!(
            read_scalar("float", "single", None, "MeasuredValue", &dts),
            ("Value::Float(v)".to_string(), "v".to_string())
        );
        // `double` -> TLV FLOAT64 -> Value::Double(f64).
        assert_eq!(
            read_scalar("float", "double", None, "MeasuredValue", &dts),
            ("Value::Double(v)".to_string(), "v".to_string())
        );
    }

    #[test]
    fn only_double_accepts_a_narrowed_float() {
        // chip `TLVReader::Get(double&)` takes FLOAT32 *or* FLOAT64, while
        // `Get(float&)` takes FLOAT32 only — so exactly one of these two has a
        // widening arm. Widening a FLOAT32 to f64 is exact and lossless.
        assert_eq!(
            read_scalar_widened("float", "double", None),
            Some(("Value::Float(v)".to_string(), "f64::from(v)".to_string()))
        );
        assert_eq!(read_scalar_widened("float", "single", None), None);
        // Nothing else widens: integers already match any wire width in
        // `read_scalar` because `TlvReader` folds UINT8..64 into one variant.
        assert_eq!(read_scalar_widened("integer", "uint16", None), None);
        assert_eq!(read_scalar_widened("string", "string", None), None);
    }

    #[test]
    fn double_attribute_decoder_has_both_float_widths() {
        // No cluster in the pinned model has a `double` attribute yet, so this
        // is the only place the widening arm is observable.
        let a = Attribute {
            id: 0,
            name: "MeasuredValue".to_string(),
            ty: "double".to_string(),
            metatype: "float".to_string(),
            entry_type: None,
            nullable: false,
            optional: true,
            writable: false,
            provisional: false,
            deprecated: false,
            supplemented: None,
        };
        let mut s = String::new();
        emit_attr_decoder(&mut s, &a, &HashMap::new(), None);
        assert!(s.contains("value: Value::Double(v), .. }) => Ok(v)"), "{s}");
        assert!(
            s.contains("value: Value::Float(v), .. }) => Ok(f64::from(v))"),
            "{s}"
        );
    }

    #[test]
    fn write_scalar_float_uses_put_float_and_put_double() {
        let dts: DatatypeMap<'_> = HashMap::new();
        let single = write_scalar("float", "single", None, "Tag::Anonymous", "value", &dts);
        assert!(
            single.starts_with("w.put_float(Tag::Anonymous, value)"),
            "{single}"
        );
        // Regression guard: the pre-M9-A2.6 fallthrough emitted
        // `u64::from(<f32>)`, which does not compile.
        assert!(!single.contains("u64::from"), "{single}");
        let double = write_scalar("float", "double", None, "Tag::Context(0)", "value", &dts);
        assert!(
            double.starts_with("w.put_double(Tag::Context(0), value)"),
            "{double}"
        );
    }

    #[test]
    fn nullable_float_attribute_decoder_has_null_and_float_arms() {
        let a = Attribute {
            id: 0,
            name: "MeasuredValue".to_string(),
            ty: "single".to_string(),
            metatype: "float".to_string(),
            entry_type: None,
            nullable: true,
            optional: true,
            writable: false,
            provisional: false,
            deprecated: false,
            supplemented: None,
        };
        let mut s = String::new();
        emit_attr_decoder(&mut s, &a, &HashMap::new(), None);
        assert!(
            s.contains(
                "pub fn decode_measured_value(tlv: &[u8]) -> Result<Nullable<f32>, ClusterError>"
            ),
            "{s}"
        );
        assert!(
            s.contains("value: Value::Null, .. }) => Ok(Nullable::Null)"),
            "{s}"
        );
        assert!(
            s.contains("value: Value::Float(v), .. }) => Ok(Nullable::Value(v))"),
            "{s}"
        );
    }

    #[test]
    fn float_struct_field_writes_and_reads() {
        // A scalar-only struct carrying a float field stays write-capable and
        // both codec halves emit float calls (no generated cluster exercises
        // this yet — the guard is here so the next one that does cannot regress).
        let mut f = field(1, "Value", "single", "float", None);
        f.nullable = true;
        let d = struct_dt("FloatStruct", vec![f]);
        assert!(struct_is_write_capable(&d));
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &HashMap::new(), &encoded(&d), &HashSet::new());
        assert!(s.contains("w.put_float(Tag::Context(1), *value)"), "{s}");
        assert!(
            s.contains("value: Value::Float(v) }) => f_value = Some(Nullable::Value(v))"),
            "{s}"
        );
    }

    #[test]
    fn entry_metatype_classifies_boolean_elements() {
        // A list<boolean> element is a TLV Bool, not an unsigned integer
        // (M9-A3 B5 Task 1 minor: without this arm a future list<boolean>
        // would encode each element with put_uint).
        let dts: DatatypeMap<'_> = HashMap::new();
        assert_eq!(entry_metatype("bool", &dts), "boolean");
        let (iter, put) = list_scalar_element_write("boolean", "bool", &dts);
        assert_eq!(iter, "iter().copied()");
        assert_eq!(
            put,
            "w.put_bool(Tag::Anonymous, el).expect(\"infallible: vec writer\");"
        );
    }

    #[test]
    fn entry_metatype_classifies_float_elements() {
        let dts: DatatypeMap<'_> = HashMap::new();
        assert_eq!(entry_metatype("single", &dts), "float");
        assert_eq!(entry_metatype("double", &dts), "float");
    }

    #[test]
    #[should_panic(expected = "no read_scalar arm for metatype")]
    fn read_scalar_panics_on_unknown_metatype() {
        // The former silent `_ =>` Uint fallthrough turned "unsupported shape"
        // into "emits wrong or uncompilable code"; codegen now hard-stops.
        let _ = read_scalar("quantum", "qubit", None, "Ctx", &HashMap::new());
    }

    #[test]
    #[should_panic(expected = "no write_scalar arm for metatype")]
    fn write_scalar_panics_on_unknown_metatype() {
        let _ = write_scalar(
            "quantum",
            "qubit",
            None,
            "Tag::Anonymous",
            "v",
            &HashMap::new(),
        );
    }

    // ---- write-guarded (fabric-sensitive) structs (M9-A3 spec §5.4) -----

    /// A fabric-scoped struct shaped like `AccessControlExtensionStruct` after
    /// the dump: sensitive `Data` relaxed to optional for decode, still
    /// required on write, plus field 254.
    fn sensitive_dt() -> Datatype {
        let mut data = field(1, "Data", "octstr", "bytes", None);
        data.optional = true;
        data.fabric_sensitive = true;
        data.mandatory_on_write = true;
        struct_dt(
            "ExtensionStruct",
            vec![
                data,
                field(254, "FabricIndex", "fabric-idx", "integer", None),
            ],
        )
    }

    #[test]
    fn write_guard_needs_field_254_and_a_mandatory_on_write_field() {
        assert!(struct_has_write_guarded_fields(&sensitive_dt()));
        // Field 254 but nothing guarded (Binding TargetStruct's shape).
        let target = struct_dt(
            "TargetStruct",
            vec![
                field(1, "Node", "node-id", "integer", None),
                field(254, "FabricIndex", "fabric-idx", "integer", None),
            ],
        );
        assert!(struct_is_fabric_scoped(&target));
        assert!(!struct_has_write_guarded_fields(&target));
        // A guarded field but no field 254: not fabric-scoped.
        let mut lone = field(1, "Data", "octstr", "bytes", None);
        lone.mandatory_on_write = true;
        assert!(!struct_has_write_guarded_fields(&struct_dt(
            "Lone",
            vec![lone]
        )));
    }

    #[test]
    fn write_guarded_struct_refuses_none_before_writing_anything() {
        let mut s = String::new();
        let d = sensitive_dt();
        emit_struct_codec(&mut s, &d, &HashMap::new(), &encoded(&d), &HashSet::new());
        assert!(
            s.contains(
                "pub fn write_fields(&self, w: &mut TlvWriter<'_>) -> Result<(), ClusterError> {"
            ),
            "{s}"
        );
        let guard = "if self.data.is_none() { return Err(ClusterError::MissingField(\"Data\")); }";
        let guard_at = s
            .find(guard)
            .unwrap_or_else(|| panic!("no None guard:\n{s}"));
        let first_write = s.find("w.put_").unwrap_or_else(|| panic!("no write:\n{s}"));
        assert!(
            guard_at < first_write,
            "guard must precede every write:\n{s}"
        );
        assert!(
            s.contains("pub fn encode(&self) -> Result<Vec<u8>, ClusterError> {"),
            "{s}"
        );
        assert!(s.contains("self.write_fields(&mut w)?;"), "{s}");
        assert!(s.contains("Ok(buf)"), "{s}");
        assert!(
            s.contains("Filter") && s.contains("own `fabric_index` before writing it back"),
            "encoder rustdoc must tell callers to filter to their own fabric:\n{s}"
        );
    }

    #[test]
    fn model_optional_sensitive_field_stays_omittable() {
        // EcosystemDeviceStruct.DeviceName's shape: fabric-sensitive, but
        // optional in the model itself, so the dump does not relax it and does
        // not mark it mandatory-on-write. None means "omit" on write.
        let mut name = field(0, "DeviceName", "string", "string", None);
        name.optional = true;
        name.fabric_sensitive = true;
        let d = struct_dt(
            "DeviceStruct",
            vec![
                name,
                field(254, "FabricIndex", "fabric-idx", "integer", None),
            ],
        );
        assert!(!struct_has_write_guarded_fields(&d));
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &HashMap::new(), &encoded(&d), &HashSet::new());
        assert!(
            s.contains("pub fn write_fields(&self, w: &mut TlvWriter<'_>) {"),
            "{s}"
        );
        assert!(s.contains("pub fn encode(&self) -> Vec<u8> {"), "{s}");
        assert!(
            s.contains("if let Some(device_name) = &self.device_name {"),
            "{s}"
        );
        assert!(
            !s.contains("is_none()"),
            "no guard for a model-optional field:\n{s}"
        );
    }

    #[test]
    fn ordinary_struct_write_stays_infallible() {
        let d = struct_dt(
            "PointStruct",
            vec![
                field(0, "X", "uint16", "integer", None),
                field(1, "Y", "uint16", "integer", None),
            ],
        );
        let mut s = String::new();
        emit_struct_codec(&mut s, &d, &HashMap::new(), &encoded(&d), &HashSet::new());
        assert!(
            s.contains("pub fn write_fields(&self, w: &mut TlvWriter<'_>) {"),
            "{s}"
        );
        assert!(s.contains("pub fn encode(&self) -> Vec<u8> {"), "{s}");
        assert!(!s.contains("-> Result<(), ClusterError>"), "{s}");
        assert!(!s.contains("Result<Vec<u8>, ClusterError>"), "{s}");
    }

    #[test]
    #[should_panic(
        expected = "write-guarded struct ExtensionStruct is reachable from a request command"
    )]
    fn write_guarded_struct_reachable_from_a_command_stops_the_generator() {
        let cmd = request_cmd(
            "Push",
            vec![field(0, "Entry", "ExtensionStruct", "object", None)],
        );
        let c = cluster_with(vec![cmd], vec![sensitive_dt()]);
        let mut s = String::new();
        emit_codecs(&mut s, &c);
    }

    #[test]
    fn fabric_sensitive_event_fields_are_not_wrapped() {
        // Even if the markers reached an event payload, the event struct keeps
        // the model's optionality (spec §5.4 "Events are exempt"): chip sends
        // our own fabric's events in full and drops other fabrics'
        // fabric-sensitive events entirely.
        let mut admin = field(1, "AdminNodeId", "node-id", "integer", None);
        admin.nullable = true;
        admin.fabric_sensitive = true;
        admin.mandatory_on_write = true;
        let mut change = field(3, "ChangeType", "uint8", "integer", None);
        change.fabric_sensitive = true;
        let ev = EventDef {
            id: 0,
            name: "AccessControlEntryChanged".to_string(),
            priority: "info".to_string(),
            fields: vec![
                admin,
                change,
                field(254, "FabricIndex", "fabric-idx", "integer", None),
            ],
            provisional: false,
        };
        let mut s = String::new();
        emit_event_decoder(&mut s, &ev, &DatatypeMap::new());
        assert!(
            s.contains("pub struct AccessControlEntryChangedEvent {"),
            "{s}"
        );
        assert!(s.contains("pub admin_node_id: Nullable<u64>,"), "{s}");
        assert!(s.contains("pub change_type: u8,"), "{s}");
        assert!(s.contains("pub fabric_index: u8,"), "{s}");
        assert!(
            !s.contains("pub admin_node_id: Option<") && !s.contains("pub change_type: Option<"),
            "event fields must not be wrapped:\n{s}"
        );
        assert!(
            !s.contains("pub fn write_fields"),
            "events are decode-only:\n{s}"
        );
    }

    #[test]
    fn write_fields_emitted_for_struct_with_list_field_when_reachable() {
        // A struct with a list<scalar> field gains write_fields ONLY when in the
        // reachable set (gate widened beyond struct_is_write_capable).
        let d = struct_dt(
            "HasList",
            vec![field(0, "Ids", "list", "array", Some("uint32"))],
        );
        let dts: DatatypeMap<'_> = std::iter::once(("HasList", &d)).collect();
        let reachable: HashSet<&str> = std::iter::once("HasList").collect();
        let mut s = String::new();
        emit_struct_decl_and_codec(
            &mut s,
            &d,
            /*decl=*/ false,
            &dts,
            &reachable,
            &HashSet::new(),
            None,
        );
        assert!(
            s.contains("pub fn write_fields"),
            "reachable list struct writes: {s}"
        );
        assert!(s.contains("w.start_array(Tag::Context(0))"), "{s}");
    }

    // ---- M9-A3 B4: encoders only for what a client sends ----

    fn attr_of(name: &str, entry: &str, writable: bool) -> Attribute {
        Attribute {
            id: 0,
            name: name.to_string(),
            ty: "list".to_string(),
            metatype: "array".to_string(),
            entry_type: Some(entry.to_string()),
            nullable: false,
            optional: false,
            writable,
            provisional: false,
            deprecated: false,
            supplemented: None,
        }
    }

    #[test]
    fn encoders_follow_requests_and_writable_attributes_only() {
        let scalar = |name: &str| struct_dt(name, vec![field(0, "X", "uint16", "integer", None)]);
        let listy =
            |name: &str| struct_dt(name, vec![field(0, "Ids", "list", "array", Some("uint32"))]);
        let mut c = cluster_with(
            vec![request_cmd(
                "Send",
                vec![field(0, "Arg", "SentStruct", "object", None)],
            )],
            vec![
                listy("SentStruct"),
                scalar("WrittenStruct"),
                listy("WrittenListStruct"),
                scalar("ReadOnlyStruct"),
                scalar("UnusedStruct"),
            ],
        );
        c.attributes = vec![
            attr_of("Written", "WrittenStruct", true),
            attr_of("WrittenLists", "WrittenListStruct", true),
            attr_of("ReadOnly", "ReadOnlyStruct", false),
        ];
        let mut got: Vec<&str> = encoded_struct_names(&c).into_iter().collect();
        got.sort_unstable();
        // A request reaches SentStruct (list field and all); a writable
        // attribute reaches the scalar WrittenStruct. WrittenListStruct (a
        // writable attribute's struct with a list field), the read-only
        // attribute's struct and an unused struct stay decode-only.
        assert_eq!(got, ["SentStruct", "WrittenStruct"]);
        let mut s = String::new();
        emit_codecs(&mut s, &c);
        assert!(
            !s.contains("impl ReadOnlyStruct {\n    pub fn write_fields"),
            "{s}"
        );
        assert_eq!(s.matches("pub fn write_fields").count(), 2, "{s}");
    }
}
