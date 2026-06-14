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
        // u8: primitive + semantic globals
        "uint8" | "percent" | "fabric-idx" | "action-id" | "status" | "priority" | "enum8"
        | "map8" => "u8",
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
        "octstr" => "Vec<u8>",
        // u32: primitive + semantic globals
        "uint24" | "uint32" | "cluster-id" | "attrib-id" | "command-id" | "event-id"
        | "devtype-id" | "epoch-s" | "elapsed-s" | "map32" | "fabric-id" => "u32",
        // u64: primitive + semantic globals
        "uint40" | "uint48" | "uint56" | "uint64" | "node-id" | "epoch-us" | "posix-ms"
        | "systime-us" | "systime-ms" | "fabric-id64" => "u64",
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

/// Convert a `PascalCase`/`camelCase` name to `snake_case` (module/fn names).
#[must_use]
pub fn snake(name: &str) -> String {
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
        assert_eq!(base_type("string", None), "String");
        assert_eq!(base_type("vendor-id", None), "u16");
        assert_eq!(base_type("cluster-id", None), "u32");
        assert_eq!(base_type("endpoint-no", None), "u16");
        assert_eq!(base_type("fabric-idx", None), "u8");
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
    }

    #[test]
    fn known_type_predicate() {
        assert!(is_known_type("uint16"));
        assert!(is_known_type("cluster-id"));
        assert!(!is_known_type("StartUpOnOffEnum"));
    }

    #[test]
    fn global_composite_semtag() {
        // `semtag` is a Matter global struct (Descriptor.TagList = list[semtag]).
        assert!(is_known_type("semtag"));
        assert_eq!(base_type("semtag", None), "SemanticTagStruct");
        assert_eq!(base_type("list", Some("semtag")), "Vec<SemanticTagStruct>");
    }
}
