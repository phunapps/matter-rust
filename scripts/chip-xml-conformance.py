#!/usr/bin/env python3
"""Check the codegen input (xtask/model/clusters.json) against chip's Matter
1.4.2 spec-derived XML, for decoder strictness.

Our generated decoders reject valid device data in three ways (M9-A3 spec
section 3): a field the model calls mandatory but a 1.4 device may omit, a
non-nullable field the device may send as null, and an integer/enum type
narrower than what the device may send. The @matter/model input tracks Matter
1.5.1, so it can be stricter than 1.4. This script finds those cases.

Inputs (read-only):
  * xtask/model/clusters.json (or --model <path>)
  * <chip>/data_model/1.4.2/clusters/*.xml            (spec-derived XML)
  * <chip>/src/app/zap-templates/zcl/data-model/chip/*.xml
                     (global structs and enum/bitmap widths, and response
                      commands 1.4.2 lacks, looked up under their own cluster)
  * scripts/chip-xml-conformance.allow                 (accepted findings)
  * scripts/chip-xml-conformance.ack                   (acknowledged XML-ONLY)

Findings that FAIL the run (exit 1) unless allow-listed:
  P  a struct/event/command-response field that is mandatory in the model
     but optional or absent in 1.4.2
  N  a field or attribute nullable in 1.4.2 but non-nullable in the model
  W  a model integer/enum type whose range does not cover the 1.4.2 type's
     range (narrower width, or unsigned in the model where 1.4.2 is signed)
Findings that always FAIL (never allow-listed: fix the supplement):
  S  an element clusters.json records in meta.supplemented (added by the dump
     from xtask/scripts/dump-model/supplement-1.4.json, not by the model) that
     does not match 1.4.2 exactly: absent from 1.4.2 or from clusters.json, a
     different id, bit, direction or name, a field set that differs, or a
     field or attribute whose type, nullability or optionality differs

Reported without failing:
  MODEL-ONLY   model elements absent from 1.4.2 (expected 1.5 additions)
  XML-ONLY     1.4.2 elements (attributes, events, request and response
               commands, feature bits, fields) absent from the model, not
               recorded as a clusters.json exclusion (matched by kind and
               full element path), and not acknowledged
  ACKNOWLEDGED XML-ONLY items listed in chip-xml-conformance.ack, with the
               reason recorded there
  UNCHECKABLE  model elements with no 1.4.2 (or zap) counterpart, and type
               widths that cannot be compared (only one side resolves to an
               integer, or 1.4.2 leaves the type blank)
  STALE-ALLOW  an allow-list entry that matched no finding
  STALE-ACK    an acknowledgement that matched no XML-ONLY item
  SUPPLEMENTED meta.supplemented elements verified against 1.4.2 (no S finding)

Python 3 standard library only. Dev-only: CI has no chip checkout, so this is
not part of `just gate`; each batch runs it and quotes the output.

Usage:
    python3 scripts/chip-xml-conformance.py <chip-checkout> [--cluster <Name>]...
                                            [--model <clusters.json>]

Exit codes: 0 clean, 1 unresolved P/N/W or any S finding, 2 usage or input error.
"""

import argparse
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MODEL = os.path.join(REPO_ROOT, "xtask", "model", "clusters.json")
ALLOW_PATH = os.path.join(REPO_ROOT, "scripts", "chip-xml-conformance.allow")
ACK_PATH = os.path.join(REPO_ROOT, "scripts", "chip-xml-conformance.ack")

# Conformance element tags (direct children of a field/attribute/event).
CONFORMANCE_TAGS = {
    "mandatoryConform": "M",
    "optionalConform": "O",
    "otherwiseConform": "cond",
    "provisionalConform": "O",
    "describedConform": "O",
    "disallowConform": "X",
    "deprecateConform": "D",
}

# Integer ranges as (signed, bits). Primitive tokens first, then the Matter
# semantic globals (Core spec 7.19.2) at their specified widths. A token not
# listed here is not an integer this script can range-check.
INT_RANGES = {
    "uint8": (False, 8), "uint16": (False, 16), "uint24": (False, 24),
    "uint32": (False, 32), "uint40": (False, 40), "uint48": (False, 48),
    "uint56": (False, 56), "uint64": (False, 64),
    "int8": (True, 8), "int16": (True, 16), "int24": (True, 24),
    "int32": (True, 32), "int40": (True, 40), "int48": (True, 48),
    "int56": (True, 56), "int64": (True, 64),
    "enum8": (False, 8), "enum16": (False, 16),
    "map8": (False, 8), "map16": (False, 16), "map32": (False, 32),
    "map64": (False, 64),
    "percent": (False, 8), "fabric-idx": (False, 8), "action-id": (False, 8),
    "status": (False, 8), "priority": (False, 8), "tag": (False, 8),
    "namespace": (False, 8),
    "percent100ths": (False, 16), "group-id": (False, 16),
    "endpoint-no": (False, 16), "vendor-id": (False, 16),
    "entry-idx": (False, 16),
    "cluster-id": (False, 32), "attrib-id": (False, 32),
    "field-id": (False, 32), "event-id": (False, 32),
    "command-id": (False, 32), "devtype-id": (False, 32),
    "trans-id": (False, 32), "data-ver": (False, 32), "epoch-s": (False, 32),
    "elapsed-s": (False, 32), "utc": (False, 32),
    "node-id": (False, 64), "epoch-us": (False, 64), "posix-ms": (False, 64),
    "systime-us": (False, 64), "systime-ms": (False, 64),
    "fabric-id": (False, 64), "subject-id": (False, 64),
    "event-no": (False, 64),
    "temperature": (True, 16),
    "voltage-mV": (True, 64), "amperage-mA": (True, 64),
    "power-mW": (True, 64), "power-mVA": (True, 64), "power-mVAR": (True, 64),
    "energy-mWh": (True, 64), "energy-mVAh": (True, 64),
    "energy-mVARh": (True, 64), "money": (True, 64),
    # Spellings 1.4.2 uses besides the ones above: Thermostat
    # SetpointChangeAmount is `int16s` (the zap form), and
    # `attribute-id`/`systemtime-us` sit beside `attrib-id`/`systime-us`.
    "attribute-id": (False, 32), "systemtime-us": (False, 64),
}
for _bits in (8, 16, 24, 32, 40, 48, 56, 64):
    INT_RANGES[f"int{_bits}s"] = (True, _bits)
    INT_RANGES[f"int{_bits}u"] = (False, _bits)

# Case-insensitive view: zap spells `power_mw` where 1.4.2 spells `power-mW`.
INT_RANGES_CI = {k.lower(): v for k, v in INT_RANGES.items()}


def int_range(token):
    """(signed, bits) for an integer type token, or None."""
    return INT_RANGES_CI.get((token or "").lower())


# zap-template primitive type names -> 1.4.2 spellings.
ZAP_TYPES = {
    "int8u": "uint8", "int16u": "uint16", "int24u": "uint24",
    "int32u": "uint32", "int40u": "uint40", "int48u": "uint48",
    "int56u": "uint56", "int64u": "uint64",
    "int8s": "int8", "int16s": "int16", "int24s": "int24", "int32s": "int32",
    "int40s": "int40", "int48s": "int48", "int56s": "int56", "int64s": "int64",
    "boolean": "bool", "char_string": "string", "long_char_string": "string",
    "octet_string": "octstr", "long_octet_string": "octstr",
    "bitmap8": "map8", "bitmap16": "map16", "bitmap32": "map32",
    "bitmap64": "map64", "single": "single", "double": "double",
    "enum8": "enum8", "enum16": "enum16",
}


def zap_token(ztype):
    """A zap-template type name in 1.4.2 spelling: primitives via ZAP_TYPES,
    semantic types with `_` -> `-` (`attrib_id` -> `attrib-id`), named
    enums/bitmaps/structs unchanged."""
    ztype = ztype or ""
    return ZAP_TYPES.get(ztype.lower(), ztype.replace("_", "-"))


# Model struct names whose zap-template global struct has a different name.
# `ThermostatAttributeStatusEntryStruct` is the dump's name for the anonymous
# AtomicResponse entry; chip's global-structs.xml calls it
# AtomicAttributeStatusStruct.
ZAP_STRUCT_ALIASES = {
    "ThermostatAttributeStatusEntryStruct": "AtomicAttributeStatusStruct",
}


def norm(name):
    """Compare names case- and punctuation-insensitively (the XML spells
    `AdminNodeID` where the model spells `AdminNodeId`)."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def norm_path(element):
    """`norm` per dot-separated component: an exclusion's full element path
    (`Leave.FabricIndex`) compared component by component."""
    return ".".join(norm(part) for part in (element or "").split("."))


def die(msg):
    print(f"chip-xml-conformance: {msg}", file=sys.stderr)
    sys.exit(2)


def parse_int(text, where):
    """An XML integer attribute (decimal or 0x-hex); malformed input is a
    usage/input error (exit 2), never a crash that would exit 1 like a
    finding."""
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        die(f"{where}: expected an integer, got {text!r}")


# --------------------------------------------------------------- XML side ---


def conformance_of(el):
    """'M' only for an EMPTY <mandatoryConform/>. A feature-gated or
    expression <mandatoryConform> is 'cond' (optional for our purposes,
    mirroring the dump's section 3.1 rule). None when the element states no
    conformance (a derived-cluster override that inherits the base's)."""
    for ch in el:
        kind = CONFORMANCE_TAGS.get(ch.tag)
        if kind is None:
            continue
        if kind == "M" and len(list(ch)) > 0:
            return "cond"
        return kind
    return None


def nullable_of(el):
    """True/False when a <quality> child is present, None when unstated."""
    q = el.find("quality")
    if q is None or q.get("nullable") is None:
        return None
    return q.get("nullable") == "true"


def xml_field(el):
    entry = el.find("entry")
    return {
        "name": el.get("name"),
        "type": el.get("type"),
        "entry": entry.get("type") if entry is not None else None,
        "nullable": nullable_of(el),
        "conf": conformance_of(el),
    }


def xml_fields(el):
    out = {}
    for f in el.findall("field"):  # direct children only: never constraint refs
        if f.get("id") is None:
            continue
        out[parse_int(f.get("id"), f"{el.tag} {el.get('name')!r} field id")] = xml_field(f)
    return out


def merge_field(base, over):
    merged = dict(base)
    for k, v in over.items():
        if v is not None:
            merged[k] = v
    return merged


def merge_fields(base, over):
    out = {i: dict(f) for i, f in base.items()}
    for i, f in over.items():
        out[i] = merge_field(out[i], f) if i in out else dict(f)
    return out


def empty_tables():
    return {"struct": {}, "event": {}, "resp": {}, "cmd": {}, "attr": {},
            "feature": {}, "enum": {}, "bitmap": {}, "number": {}}


def own_tables(root):
    """The element tables one XML <cluster> defines itself."""
    t = empty_tables()
    cname = root.get("name")
    dts = root.find("dataTypes")
    if dts is not None:
        for s in dts.findall("struct"):
            access = s.find("access")
            t["struct"][norm(s.get("name"))] = {
                "name": s.get("name"),
                "fields": xml_fields(s),
                "fabric_scoped": access is not None and access.get("fabricScoped") == "true",
            }
        for e in dts.findall("enum"):
            where = f"{cname}: enum {e.get('name')!r} item value"
            vals = [parse_int(i.get("value"), where) for i in e.findall("item") if i.get("value")]
            t["enum"][norm(e.get("name"))] = max(vals) if vals else 0
        for b in dts.findall("bitmap"):
            # A bitfield is one `bit` or a `from`..`to` range (WindowCovering
            # OperationalStatusBitmap): the top bit is `bit` or `to`.
            where = f"{cname}: bitmap {b.get('name')!r} bitfield"
            bits = [parse_int(f.get("bit") or f.get("to"), where)
                    for f in b.findall("bitfield") if f.get("bit") or f.get("to")]
            t["bitmap"][norm(b.get("name"))] = max(bits) if bits else 0
        for n in dts.findall("number"):
            t["number"][norm(n.get("name"))] = n.get("type")
    evs = root.find("events")
    if evs is not None:
        for e in evs.findall("event"):
            access = e.find("access")
            t["event"][norm(e.get("name"))] = {
                "name": e.get("name"),
                "fields": xml_fields(e),
                "fabric_sensitive": (
                    access.get("fabricSensitive") == "true" if access is not None else None
                ),
                "conf": conformance_of(e),
            }
    cmds = root.find("commands")
    if cmds is not None:
        for c in cmds.findall("command"):
            if c.get("direction") == "responseFromServer":
                t["resp"][norm(c.get("name"))] = {"name": c.get("name"), "fields": xml_fields(c)}
            # Every command, request and response, for XML-ONLY reporting.
            # Keyed by name: a derived cluster's override may omit the id or
            # direction (merged from the base like any other override).
            t["cmd"][norm(c.get("name"))] = {
                "name": c.get("name"),
                "id": (parse_int(c.get("id"), f"{cname}: command id")
                       if c.get("id") is not None else None),
                "direction": c.get("direction"),
                "conf": conformance_of(c),
                "fields": xml_fields(c),
            }
    feats = root.find("features")
    if feats is not None:
        for f in feats.findall("feature"):
            if not f.get("code"):
                continue
            t["feature"][norm(f.get("code"))] = {
                "code": f.get("code"),
                "bit": (parse_int(f.get("bit"), f"{cname}: feature bit")
                        if f.get("bit") is not None else None),
                "conf": conformance_of(f),
            }
    attrs = root.find("attributes")
    if attrs is not None:
        for a in attrs.findall("attribute"):
            if a.get("id") is not None:
                t["attr"][parse_int(a.get("id"), f"{cname}: attribute id")] = xml_field(a)
    return t


def overlay(base, over):
    """Derived-cluster overrides on top of the base cluster's elements."""
    out = empty_tables()
    for kind in ("enum", "bitmap", "number"):
        out[kind] = {**base[kind], **over[kind]}
    out["attr"] = merge_fields(base["attr"], over["attr"])
    for kind in ("cmd", "feature"):
        out[kind] = merge_fields(base[kind], over[kind])
    for kind in ("struct", "event", "resp"):
        merged = {k: dict(v, fields=dict(v["fields"])) for k, v in base[kind].items()}
        for k, v in over[kind].items():
            if k in merged:
                b = merged[k]
                m = dict(b)
                for key, val in v.items():
                    if key != "fields" and val is not None:
                        m[key] = val
                m["fields"] = merge_fields(b["fields"], v["fields"])
                merged[k] = m
            else:
                merged[k] = v
        out[kind] = merged
    return out


IMPLICIT_FABRIC_INDEX = {
    "name": "FabricIndex", "type": "fabric-idx", "entry": None,
    "nullable": False, "conf": "M",
}


def add_implicit_fabric_index(t):
    """1.4.2 leaves field 254 implicit in fabric-scoped structs and
    fabric-sensitive events; treat it as present and mandatory."""
    for s in t["struct"].values():
        if s.get("fabric_scoped") and 254 not in s["fields"]:
            s["fields"][254] = dict(IMPLICIT_FABRIC_INDEX)
    for e in t["event"].values():
        if e.get("fabric_sensitive") and 254 not in e["fields"]:
            e["fields"][254] = dict(IMPLICIT_FABRIC_INDEX)


def load_chip_xml(chip):
    """clusterId -> merged element tables, for every 1.4.2 cluster id."""
    pattern = os.path.join(chip, "data_model", "1.4.2", "clusters", "*.xml")
    paths = sorted(glob.glob(pattern))
    if not paths:
        die(f"no XML under {pattern} (is {chip} a connectedhomeip checkout?)")
    roots_by_name = {}
    roots = []
    for p in paths:
        try:
            root = ET.parse(p).getroot()
        except ET.ParseError as e:
            die(f"cannot parse {p}: {e}")
        if root.tag != "cluster":
            continue
        roots.append(root)
        # `baseCluster="Mode Base"` names the file whose cluster is
        # "Mode Base Cluster": strip the trailing " Cluster" to resolve it.
        roots_by_name[re.sub(r" Cluster$", "", root.get("name") or "")] = root

    def tables_for(root, depth=0):
        if depth > 4:
            die(f"baseCluster chain too deep at {root.get('name')}")
        own = own_tables(root)
        cls = root.find("classification")
        base_name = cls.get("baseCluster") if cls is not None else None
        if base_name:
            base = roots_by_name.get(base_name)
            if base is None:
                die(f"{root.get('name')}: baseCluster {base_name!r} not found")
            return overlay(tables_for(base, depth + 1), own)
        return own

    by_id = {}
    for root in roots:
        ids = root.find("clusterIds")
        if ids is None:
            continue
        for cid in ids.findall("clusterId"):
            # One file can carry several ids (ConcentrationMeasurement.xml,
            # ResourceMonitoring.xml): map by clusterId, never by file name.
            if cid.get("id") is None:
                continue  # an id-less base (Mode Base)
            t = tables_for(root)
            add_implicit_fabric_index(t)
            by_id[parse_int(cid.get("id"), f"{root.get('name')}: clusterId")] = t
    return by_id


def zap_field(el):
    """A zap <item>/<arg> as a field entry in 1.4.2 spelling."""
    t = zap_token(el.get("type"))
    is_list = el.get("array") == "true"
    return {
        "name": el.get("name"),
        "type": "list" if is_list else t,
        "entry": t if is_list else None,
        "nullable": el.get("isNullable") == "true",
        "conf": "O" if el.get("optional") == "true" else "M",
    }


def load_zap_globals(chip):
    """What data_model/1.4.2 does not carry, from chip's zap-templates:

    * "struct": global structs (no <cluster> binding), by normalised name;
    * "int": global enum/bitmap widths, by normalised name, from their
      explicit `type` (global-enums.xml `MeasurementTypeEnum` is enum16);
    * "resp": server commands keyed by (cluster code, normalised name). zap
      nests every command inside a <cluster> (or <clusterExtension>), and
      names collide across clusters (`ChangeToModeResponse` in nine), so a
      response is only ever looked up under its own cluster's id."""
    pattern = os.path.join(chip, "src", "app", "zap-templates", "zcl",
                           "data-model", "chip", "*.xml")
    zap = {"struct": {}, "int": {}, "resp": {}}
    for p in sorted(glob.glob(pattern)):
        try:
            root = ET.parse(p).getroot()
        except ET.ParseError as e:
            die(f"cannot parse {p}: {e}")
        for s in root.iter("struct"):
            if s.get("cluster") is not None or s.find("cluster") is not None:
                continue  # cluster-bound: not a global
            fields = {}
            for item in s.findall("item"):
                where = f"{p}: struct {s.get('name')!r} item fieldId"
                fid = parse_int(item.get("fieldId"), where)
                fields[fid] = zap_field(item)
            if s.get("isFabricScoped") == "true" and 254 not in fields:
                fields[254] = dict(IMPLICIT_FABRIC_INDEX)
            zap["struct"][norm(s.get("name"))] = {"name": s.get("name"), "fields": fields}
        for tag in ("enum", "bitmap"):
            for e in root.iter(tag):
                if e.get("cluster") is not None or e.find("cluster") is not None:
                    continue  # cluster-bound: 1.4.2 carries it
                r = int_range(zap_token(e.get("type")))
                if r is not None:
                    zap["int"][norm(e.get("name"))] = r
        for owner in root.iter():
            if owner.tag not in ("cluster", "clusterExtension"):
                continue
            # <cluster><code>0x0201</code>... or <clusterExtension code=...>.
            # A struct's <cluster code=.../> binding has no commands.
            code_text = owner.findtext("code") or owner.get("code")
            cmds = [c for c in owner.findall("command") if c.get("source") == "server"]
            if not cmds:
                continue
            code = parse_int(code_text, f"{p}: cluster code")
            for c in cmds:
                fields = {}
                for i, arg in enumerate(c.findall("arg")):
                    # zap args carry no usable id (AtomicResponse's are all
                    # id="0"): the field id is the argument's position.
                    where = f"{p}: command {c.get('name')!r} arg fieldId"
                    fid = parse_int(arg.get("fieldId"), where) if arg.get("fieldId") else i
                    fields[fid] = zap_field(arg)
                zap["resp"][(code, norm(c.get("name")))] = {"name": c.get("name"), "fields": fields}
    return zap


# ------------------------------------------------------------- range check ---


def model_range(token, dts):
    """(signed, bits) for a model type token, resolving cluster-local
    enum/bitmap/scalar datatypes to their base; None if not an integer."""
    d = dts.get(token)
    if d is not None:
        if d["kind"] in ("enum", "bitmap", "scalar"):
            return int_range(d["base"])
        return None
    return int_range(token)


def xml_range(token, xt, zap):
    """(signed, bits) for a 1.4.2 type token. A named enum/bitmap carries no
    width in 1.4.2 XML, so its width is the smallest that holds its largest
    value / highest bit (a lower bound: a narrower model type cannot hold it).
    A global enum/bitmap (a field of a zap global struct) takes the explicit
    width zap declares for it."""
    r = int_range(token)
    if r is not None:
        return r
    key = norm(token)
    if key in xt["number"]:
        return int_range(xt["number"][key])
    if key in xt["enum"]:
        return (False, 8 if xt["enum"][key] <= 0xFF else 16)
    if key in xt["bitmap"]:
        top = xt["bitmap"][key]
        return (False, 8 if top < 8 else 16 if top < 16 else 32 if top < 32 else 64)
    return zap["int"].get(key)


def covers(model, xml):
    """True when every value of the 1.4.2 integer type fits the model type."""
    ms, mb = model
    xs, xb = xml
    if ms == xs:
        return mb >= xb
    if xs and not ms:
        return False  # 1.4.2 allows negatives an unsigned model type rejects
    return mb > xb  # signed model holds an unsigned 1.4.2 type only if wider


# ----------------------------------------------------------------- checks ---


class Report:
    def __init__(self, allow, ack):
        self.allow = allow  # {(key, cls): justification}
        self.used = set()
        self.ack = ack  # {xml-only key: reason}
        self.acked = set()
        self.failing, self.allowed = [], []
        self.supplemented = []
        self.model_only, self.xml_only, self.uncheckable = [], [], []
        self.acknowledged = []

    def xml_only_item(self, key, detail):
        """A 1.4.2 element absent from the model: ACKNOWLEDGED when the ack
        file lists `key`, XML-ONLY otherwise."""
        if key in self.ack:
            self.acked.add(key)
            self.acknowledged.append(f"{key} {detail}  [ack: {self.ack[key]}]")
        else:
            self.xml_only.append(f"{key} {detail}")

    def finding(self, cls, key, detail):
        line = f"{cls}  {key}: {detail}"
        if (key, cls) in self.allow:
            self.used.add((key, cls))
            self.allowed.append(f"{line}  [allowed: {self.allow[(key, cls)]}]")
        else:
            self.failing.append(line)


def model_type_token(f):
    return f.get("entryType") if f["type"] == "list" else f["type"]


def xml_type_token(x):
    return x.get("entry") if x.get("type") == "list" else x.get("type")


def check_width(rep, key, mf, xf, dts, xt, zap):
    mtok = model_type_token(mf)
    xtok = xml_type_token(xf) or ""
    mr = model_range(mtok, dts)
    xr = xml_range(xtok, xt, zap)
    if mr and xr:
        if not covers(mr, xr):
            rep.finding("W", key, f"model {mtok} {mr} does not cover 1.4.2 {xtok} {xr}")
    elif mr or xr or not xtok:
        # Never pass silently: one side is an integer the other cannot be
        # resolved to, or 1.4.2 leaves the type blank (`type=""`).
        rep.uncheckable.append(f"{key} (width: model {mtok!r} {mr}, 1.4.2 {xtok!r} {xr})")


def check_fields(rep, cname, ename, mfields, xfields, dts, xt, zap, field_kind, excl):
    seen = set()
    for mf in mfields:
        key = f"{cname}.{ename}.{mf['name']}"
        x = xfields.get(mf["id"])
        if x is None:
            rep.model_only.append(f"{key} (id {mf['id']})")
            if not mf["optional"]:
                rep.finding("P", key, "mandatory in model, absent in 1.4.2")
            continue
        seen.add(mf["id"])
        if not mf["optional"] and x.get("conf") != "M":
            rep.finding("P", key, f"mandatory in model, conformance {x.get('conf')} in 1.4.2")
        if x.get("nullable") and not mf["nullable"]:
            rep.finding("N", key, "nullable in 1.4.2, non-nullable in model")
        check_width(rep, key, mf, x, dts, xt, zap)
    for fid, x in sorted(xfields.items()):
        if fid not in seen and x.get("conf") not in ("X", "D"):
            if any(m["id"] == fid for m in mfields):
                continue
            if (field_kind, norm_path(f"{ename}.{x.get('name')}")) in excl:
                continue
            rep.xml_only_item(f"{cname}.{ename}.{x.get('name')}", f"(id {fid})")


def excluded_elements(meta, cname):
    """`(kind, full element path)` for everything clusters.json records as
    excluded for this cluster (`attribute`/`command`/`event` by name,
    `struct-field`/`event-field`/`command-field` as `<Element>.<Field>`).

    Matched by kind and full path only: an excluded `Leave.FabricIndex` event
    field never hides an XML-only attribute that happens to be named
    `FabricIndex`."""
    excl, events_off = set(), False
    for e in meta.get("excluded", []):
        owner = e.get("cluster", "")
        if owner != cname and not owner.startswith(cname + "."):
            continue
        if e.get("reason") == "event dump not enabled for this cluster":
            events_off = True
        excl.add((e.get("kind"), norm_path(e.get("element"))))
    return excl, events_off


def check_cluster(rep, c, xt, zap, meta):
    cname = c["name"]
    dts = {d["name"]: d for d in c["datatypes"]}
    excl, events_off = excluded_elements(meta, cname)

    for d in c["datatypes"]:
        if d["kind"] != "struct":
            continue
        xs = xt["struct"].get(norm(d["name"]))
        if xs is None:
            alias = ZAP_STRUCT_ALIASES.get(d["name"], d["name"])
            xs = zap["struct"].get(norm(alias))
        if xs is None:
            rep.uncheckable.append(f"{cname}.{d['name']} (struct not in 1.4.2 or zap globals)")
            continue
        check_fields(rep, cname, d["name"], d["fields"], xs["fields"], dts, xt, zap,
                     "struct-field", excl)

    for ev in c.get("events", []):
        xe = xt["event"].get(norm(ev["name"]))
        if xe is None:
            rep.model_only.append(f"{cname}.{ev['name']} (event)")
            continue
        check_fields(rep, cname, ev["name"], ev["fields"], xe["fields"], dts, xt, zap,
                     "event-field", excl)
    if not events_off:
        model_events = {norm(e["name"]) for e in c.get("events", [])}
        for k, xe in sorted(xt["event"].items()):
            if (k not in model_events and ("event", k) not in excl
                    and xe.get("conf") not in ("X", "D")):
                rep.xml_only_item(f"{cname}.Event.{xe['name']}", "(event)")

    for cmd in c["commands"]:
        if cmd["direction"] != "response":
            continue
        xr = (xt["resp"].get(norm(cmd["name"]))
              or zap["resp"].get((c["id"], norm(cmd["name"]))))
        if xr is None:
            rep.uncheckable.append(
                f"{cname}.{cmd['name']} (response not in 1.4.2 or zap cluster {c['id']:#06x})")
            continue
        check_fields(rep, cname, cmd["name"], cmd["fields"], xr["fields"], dts, xt, zap,
                     "command-field", excl)

    # XML-only commands, request and response. A model command matches by
    # direction and id, or by direction and name (an id-less override).
    model_cmds = set()
    for cmd in c["commands"]:
        model_cmds.add((cmd["direction"], cmd["id"]))
        model_cmds.add((cmd["direction"], norm(cmd["name"])))
    for k, xc in sorted(xt["cmd"].items()):
        direction = "response" if xc.get("direction") == "responseFromServer" else "request"
        if xc.get("conf") in ("X", "D") or ("command", k) in excl:
            continue
        if (direction, xc.get("id")) in model_cmds or (direction, k) in model_cmds:
            continue
        cid = f"id {xc['id']:#04x}" if xc.get("id") is not None else "no id"
        rep.xml_only_item(f"{cname}.Command.{xc['name']}", f"({cid}, {direction})")

    # XML-only feature bits.
    model_bits = {f["bit"] for f in c.get("features", [])}
    for k, xf in sorted(xt["feature"].items()):
        if xf.get("bit") is None or xf["bit"] in model_bits or xf.get("conf") in ("X", "D"):
            continue
        if ("feature", k) not in excl:
            rep.xml_only_item(f"{cname}.Feature.{xf['code']}", f"(bit {xf['bit']})")

    model_attr_ids = set()
    for a in c["attributes"]:
        model_attr_ids.add(a["id"])
        key = f"{cname}.Attribute.{a['name']}"
        xa = xt["attr"].get(a["id"])
        if xa is None:
            rep.model_only.append(f"{key} (id {a['id']:#06x})")
            continue
        if xa.get("nullable") and not a["nullable"]:
            rep.finding("N", key, "nullable in 1.4.2, non-nullable in model")
        check_width(rep, key, a, xa, dts, xt, zap)
    for aid, xa in sorted(xt["attr"].items()):
        if aid >= 0xFFF8 or aid in model_attr_ids or xa.get("conf") in ("X", "D"):
            continue
        if ("attribute", norm(xa.get("name"))) not in excl:
            rep.xml_only_item(f"{cname}.Attribute.{xa.get('name')}", f"(id {aid:#06x})")


# ------------------------------------------------------------ supplement ---


def same_type(mtok, xtok, dts, xt, zap):
    """True when a model type token and a 1.4.2 one are the same type: equal
    integer ranges when both resolve to integers, else the same name."""
    mr = model_range(mtok, dts)
    xr = xml_range(xtok, xt, zap)
    if mr is not None or xr is not None:
        return mr == xr
    return norm(mtok) == norm(xtok)


def field_mismatches(mf, xf, dts, xt, zap):
    """How a supplemented field or attribute differs from its 1.4.2
    counterpart (an empty list when it matches)."""
    out = []
    if norm(mf["name"]) != norm(xf.get("name")):
        out.append(f"name {mf['name']!r} vs 1.4.2 {xf.get('name')!r}")
    is_list = mf["type"] == "list"
    if is_list != (xf.get("type") == "list"):
        out.append(f"type {mf['type']!r} vs 1.4.2 {xf.get('type')!r}")
    elif not same_type(model_type_token(mf), xml_type_token(xf) or "", dts, xt, zap):
        out.append(f"type {model_type_token(mf)!r} vs 1.4.2 {xml_type_token(xf)!r}")
    if bool(xf.get("nullable")) != mf["nullable"]:
        out.append(f"nullable {mf['nullable']} vs 1.4.2 {bool(xf.get('nullable'))}")
    if mf["optional"] != (xf.get("conf") != "M"):
        out.append(f"optional {mf['optional']} vs 1.4.2 conformance {xf.get('conf')}")
    return out


def check_supplemented(rep, c, xt, zap, meta):
    """Class S: every meta.supplemented element of cluster `c` matches its
    1.4.2 counterpart exactly (the supplement is hand-transcribed, so a
    'covers' check is not enough)."""
    cname = c["name"]
    dts = {d["name"]: d for d in c["datatypes"]}
    for s in meta.get("supplemented", []):
        if s.get("cluster") != cname:
            continue
        key = f"{cname}.{s.get('element')}"
        label, _, name = (s.get("element") or "").partition(".")
        problems = []
        if label == "Feature":
            mf = next((f for f in c["features"] if f["code"] == name), None)
            xf = xt["feature"].get(norm(name))
            if mf is None or xf is None:
                problems.append("absent from " + ("clusters.json" if mf is None else "1.4.2"))
            elif mf["bit"] != xf.get("bit"):
                problems.append(f"bit {mf['bit']} vs 1.4.2 {xf.get('bit')}")
        elif label == "Attribute":
            ma = next((a for a in c["attributes"] if a["name"] == name), None)
            xa = xt["attr"].get(ma["id"]) if ma is not None else None
            if ma is None or xa is None:
                problems.append("absent from " + ("clusters.json" if ma is None else "1.4.2"))
            else:
                problems += field_mismatches(ma, xa, dts, xt, zap)
        elif label == "Command":
            mc = next((x for x in c["commands"] if x["name"] == name), None)
            xc = xt["cmd"].get(norm(name))
            if mc is None or xc is None:
                problems.append("absent from " + ("clusters.json" if mc is None else "1.4.2"))
            else:
                direction = "response" if xc.get("direction") == "responseFromServer" else "request"
                if (mc["direction"], mc["id"]) != (direction, xc.get("id")):
                    problems.append(f"{mc['direction']} id {mc['id']} vs 1.4.2 {direction} id {xc.get('id')}")
                xfields = xc.get("fields", {})
                mids = sorted(f["id"] for f in mc["fields"])
                if mids != sorted(xfields):
                    problems.append(f"field ids {mids} vs 1.4.2 {sorted(xfields)}")
                for mf in mc["fields"]:
                    if mf["id"] in xfields:
                        problems += [f"{mf['name']}: {p}" for p in
                                     field_mismatches(mf, xfields[mf["id"]], dts, xt, zap)]
        else:
            problems.append(f"unknown element kind {label!r}")
        if problems:
            rep.failing.append(f"S  {key}: " + "; ".join(problems))
        else:
            rep.supplemented.append(f"{key}  [source: {s.get('source')}]")


# ------------------------------------------------------------------- main ---


def load_allow(path):
    allow = {}
    if not os.path.exists(path):
        return allow
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 2)
            if len(parts) < 3 or parts[1] not in ("P", "N", "W") or parts[0].count(".") != 2:
                die(f"{path}:{n}: expected `<Cluster>.<Element>.<Field> <P|N|W> <justification>`")
            if ".Attribute." in parts[0] and parts[1] == "P":
                die(f"{path}:{n}: attributes take N or W only")
            allow[(parts[0], parts[1])] = parts[2]
    return allow


def load_ack(path):
    """Acknowledged XML-ONLY items: `<key> <reason>` per line, where `<key>`
    is the item exactly as XML-ONLY prints it before its parenthesised
    detail (`<Cluster>.Attribute.<Name>`, `<Cluster>.Command.<Name>`,
    `<Cluster>.Event.<Name>`, `<Cluster>.Feature.<CODE>`,
    `<Cluster>.<Element>.<Field>`)."""
    ack = {}
    if not os.path.exists(path):
        return ack
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) < 2 or parts[0].count(".") != 2:
                die(f"{path}:{n}: expected `<Cluster>.<Kind|Element>.<Name> <reason>`")
            if parts[0] in ack:
                die(f"{path}:{n}: duplicate acknowledgement {parts[0]}")
            ack[parts[0]] = parts[1]
    return ack


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("chip", help="connectedhomeip checkout root")
    ap.add_argument("--cluster", action="append", default=[],
                    help="restrict to this cluster name (repeatable)")
    ap.add_argument("--model", default=DEFAULT_MODEL,
                    help="clusters.json to check (default: xtask/model/clusters.json)")
    args = ap.parse_args()

    try:
        with open(args.model, encoding="utf-8") as fh:
            model = json.load(fh)
    except (OSError, ValueError) as e:
        die(f"cannot read {args.model}: {e}")
    clusters = model.get("clusters") if isinstance(model, dict) else None
    if not isinstance(clusters, list) or not all(
            isinstance(c, dict) and isinstance(c.get("id"), int)
            and isinstance(c.get("name"), str) for c in clusters):
        die(f"{args.model}: expected an object whose `clusters` is a list of "
            "clusters with an integer `id` and a string `name`")
    if args.cluster:
        known = {c["name"] for c in clusters}
        for name in args.cluster:
            if name not in known:
                die(f"--cluster {name}: not a generated cluster in {args.model}")
        clusters = [c for c in clusters if c["name"] in args.cluster]

    xml = load_chip_xml(args.chip)
    zap = load_zap_globals(args.chip)
    rep = Report(load_allow(ALLOW_PATH), load_ack(ACK_PATH))
    meta = model.get("meta", {})
    for c in clusters:
        xt = xml.get(c["id"])
        if xt is None:
            rep.uncheckable.append(f"{c['name']} (cluster id {c['id']:#06x} not in 1.4.2)")
            continue
        try:
            check_cluster(rep, c, xt, zap, meta)
            check_supplemented(rep, c, xt, zap, meta)
        except (KeyError, TypeError, AttributeError) as e:
            # A model cluster missing a key the check reads is an input error
            # (exit 2), not a finding (exit 1).
            die(f"{args.model}: malformed cluster {c['name']}: {type(e).__name__}: {e}")

    def section(title, lines):
        print(f"== {title} ({len(lines)})")
        for line in lines:
            print(f"  {line}")

    section("FAIL: P/N/W/S findings", rep.failing)
    section("allowed P/N/W findings", rep.allowed)
    section("MODEL-ONLY (absent from 1.4.2)", rep.model_only)
    section("XML-ONLY (absent from model, not excluded or acknowledged)", rep.xml_only)
    section("ACKNOWLEDGED XML-ONLY", rep.acknowledged)
    section("UNCHECKABLE", rep.uncheckable)
    stale = [f"{k} {c}" for (k, c) in rep.allow if (k, c) not in rep.used and
             (not args.cluster or k.split(".")[0] in args.cluster)]
    section("STALE-ALLOW (matched nothing)", stale)
    stale_ack = [k for k in rep.ack if k not in rep.acked and
                 (not args.cluster or k.split(".")[0] in args.cluster)]
    section("STALE-ACK (matched nothing)", stale_ack)
    section("SUPPLEMENTED (verified against 1.4.2)", rep.supplemented)
    print(f"chip-xml-conformance: {len(clusters)} clusters, "
          f"{len(rep.failing)} failing, {len(rep.allowed)} allowed")
    return 1 if rep.failing else 0


if __name__ == "__main__":
    sys.exit(main())
