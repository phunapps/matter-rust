#!/usr/bin/env python3
"""Freeze the facts the cluster codegen takes from chip's Matter 1.4.2 data
into xtask/scripts/dump-model/chip-1.4.2.json, or check that file against a
connectedhomeip checkout.

The dump script (xtask/scripts/dump-model/index.js) reads the frozen file, so
neither the dump nor the build needs a chip checkout. This script is the only
thing that reads chip, and it is dev-only like scripts/chip-xml-conformance.py.

Facts:
  revisions    each generated cluster's revision in chip's
               data_model/1.4.2/clusters XML (the checkout's working tree),
               1 to 65535. Emitted as CLUSTER_REVISION. A cluster id in two
               XML files stops the script. A generated cluster that is not
               in that XML stops the script unless REVISIONS_BY_HAND below
               names its revision: no silent fallback to the model's.
  provisional  generated elements chip marks provisional that the codegen
               model does not (clusters.json `provisional`), each with where
               chip marks it. Sources, all of chip's 1.4.2:
                 data_model/1.4.2 XML at the working tree, and at the tag
                 v1.4.2.0 (`git show`): <provisionalConform/> on a cluster id,
                 feature, attribute, command, event, field, enum item or
                 bitfield, directly or as the first branch of
                 <otherwiseConform>;
                 controller-clusters.matter at v1.4.2.0: `provisional` on a
                 cluster, attribute or event.
               An element of a cluster that is provisional as a whole (in the
               model or in chip) is not listed on its own. A chip mark on an
               element the model does not generate is listed on stderr (a
               warning, in both modes), never dropped silently. Commands, and
               their fields, are matched by id and direction, not by name.

Element keys use clusters.json names: `<Cluster>` for a whole cluster, else
`<Cluster>.<Kind>.<Name>` with Kind one of Feature, Attribute, Command,
Event, Field (`<Owner>.<Field>`) or Value (`<Enum or bitmap>.<Member>`).

Recovering from a stale file (a cluster added to or removed from the dump's
ALLOWLIST, or a model upgrade that renames, drops or newly marks an element):
the dump refuses a stale file, and this script reads the dump's output, so run
    CHIP_FACTS_BOOTSTRAP=1 cargo xtask dump-model
    python3 scripts/chip-facts.py <chip-checkout> --write
    cargo xtask dump-model
The first dump warns instead of failing and marks its clusters.json
`chipFactsBootstrap`, which a freeze test refuses; the last one is clean.

Python 3 standard library only.

Usage:
    python3 scripts/chip-facts.py <chip-checkout>            # check (exit 1 on drift)
    python3 scripts/chip-facts.py <chip-checkout> --write    # rewrite the file

Check mode also notes (without failing) when the checkout's HEAD or v1.4.2.0
differs from the commits the file records.

Exit codes: 0 clean, 1 drift, 2 usage or input error.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL = os.path.join(REPO_ROOT, "xtask", "model", "clusters.json")
OUT = os.path.join(REPO_ROOT, "xtask", "scripts", "dump-model", "chip-1.4.2.json")
XML_DIR = "data_model/1.4.2/clusters"
CODEGEN = "src/controller/data_model/controller-clusters.matter"
RELEASE = "v1.4.2.0"
# Revisions decided by hand for a generated cluster chip's 1.4.2 XML does not
# have (a Matter 1.5-only cluster): name -> (revision, why). Empty today.
REVISIONS_BY_HAND = {}
FACTS = ("revisions", "provisional")


def die(msg):
    print(f"chip-facts: {msg}", file=sys.stderr)
    sys.exit(2)


def git(chip, *args):
    r = subprocess.run(["git", "-C", chip, *args], capture_output=True, text=True)
    if r.returncode != 0:
        die(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def norm(name):
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def num(text, where):
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        die(f"{where}: not an integer: {text!r}")


def provisional(el):
    """True when el's conformance is <provisionalConform/>, directly or as the
    first branch of <otherwiseConform> (the rule chip-xml-conformance.py uses)."""
    for child in el:
        if child.tag == "provisionalConform":
            return True
        if child.tag == "otherwiseConform":
            branches = list(child)
            return bool(branches) and branches[0].tag == "provisionalConform"
    return False


def xml_roots(read_files):
    """[(file name, <cluster> root)] for every cluster file of one ref."""
    roots = []
    for name, text in read_files():
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            die(f"cannot parse {name}: {e}")
        if root.tag == "cluster":
            roots.append((name, root))
    if not roots:
        die("no cluster XML found")
    return roots


def by_cluster_id(roots):
    """cluster id -> (file name, root, [base roots, nearest first], the
    <clusterId> element). A cluster id in two files stops the script: which
    one chip means would otherwise depend on file-name order."""
    by_name = {re.sub(r" Cluster$", "", r.get("name") or ""): r for _, r in roots}
    out = {}
    for fname, root in roots:
        ids = root.find("clusterIds")
        if ids is None:
            continue
        chain, cur = [], root
        while True:
            cls = cur.find("classification")
            base = cls.get("baseCluster") if cls is not None else None
            if not base:
                break
            if base not in by_name or len(chain) > 4:
                die(f"{fname}: baseCluster {base!r} not found")
            cur = by_name[base]
            chain.append(cur)
        for cid in ids.findall("clusterId"):
            if cid.get("id") is not None:
                k = num(cid.get("id"), f"{fname} clusterId")
                if k in out and out[k][0] != fname:
                    die(f"cluster id {k:#06x} is in both {out[k][0]} and {fname}")
                out[k] = (fname, root, chain, cid)
    return out


DIRECTIONS = {"commandToServer": "request", "responseFromServer": "response"}


def xml_marks(root, chain, fname):
    """Provisional marks of one XML cluster and its bases, as a set of
    (kind, key): ("Feature", code), ("Attribute", id), ("Command", (id,
    direction)), ("Event", id), ("Field", (owner, id)) with owner a command's
    (id, direction) or an event's or datatype's norm name, and ("Value",
    (norm owner, value)). A derived cluster's element overrides its base's
    (the nearest wins)."""
    marks = {}
    # A derived cluster's command override may omit `direction`: it is the
    # base command's of the same id and name.
    base_dirs = {}

    def command_key(e):
        cid = num(e.get("id"), f"{fname} command id")
        d = e.get("direction")
        if d is None:
            d = base_dirs.get((cid, norm(e.get("name"))))
            if d is None:
                die(f"{fname}: command {e.get('name')!r} has no direction, and no base "
                    "command has its id and name")
        elif d not in DIRECTIONS:
            die(f"{fname}: command {e.get('name')!r} has direction {d!r}")
        base_dirs[(cid, norm(e.get("name")))] = d
        return (cid, DIRECTIONS[d])

    def put(key, el):
        # An override without a conformance of its own keeps the base's.
        if key not in marks or any(ch.tag.endswith("Conform") for ch in el):
            marks[key] = provisional(el)

    for r in [*reversed(chain), root]:
        feats = r.find("features")
        for f in feats.findall("feature") if feats is not None else []:
            if f.get("code"):
                put(("Feature", f.get("code")), f)
        attrs = r.find("attributes")
        for a in attrs.findall("attribute") if attrs is not None else []:
            if a.get("id") is not None:
                put(("Attribute", num(a.get("id"), "attribute id")), a)
        for kind, tag in (("Command", "command"), ("Event", "event")):
            group = r.find(f"{tag}s")
            for e in group.findall(tag) if group is not None else []:
                if e.get("id") is None:
                    continue
                if kind == "Command":
                    key = command_key(e)
                    owner = key
                else:
                    key = num(e.get("id"), "event id")
                    owner = norm(e.get("name"))
                put((kind, key), e)
                for fl in e.findall("field"):
                    if fl.get("id") is not None:
                        put(("Field", (owner, num(fl.get("id"), "field id"))), fl)
        dts = r.find("dataTypes")
        for d in list(dts) if dts is not None else []:
            owner = norm(d.get("name"))
            for fl in d.findall("field"):
                if fl.get("id") is not None:
                    put(("Field", (owner, num(fl.get("id"), "field id"))), fl)
            for it in d.findall("item"):
                if it.get("value") is not None:
                    put(("Value", (owner, num(it.get("value"), "item value"))), it)
            for b in d.findall("bitfield"):
                if b.get("bit") is not None:
                    put(("Value", (owner, num(b.get("bit"), "bitfield bit"))), b)
    return {k for k, v in marks.items() if v}


def codegen_marks(text):
    """controller-clusters.matter: cluster id -> set of (kind, key) for
    `provisional` clusters ("Cluster", None), attributes and events (by id)."""
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^(provisional )?(?:client |server )?cluster \w+ = (\d+) \{", line)
        if m:
            cur = int(m.group(2))
            out.setdefault(cur, set())
            if m.group(1):
                out[cur].add(("Cluster", None))
            continue
        if cur is None or not re.match(r"^\s+provisional ", line):
            continue
        m = re.match(r"^\s+provisional .*\battribute\b.*= (\d+);", line)
        if m:
            out[cur].add(("Attribute", int(m.group(1))))
            continue
        m = re.match(r"^\s+provisional .*\bevent\b.*= (\d+) \{", line)
        if m:
            out[cur].add(("Event", int(m.group(1))))
            continue
        die(f"{CODEGEN}: a provisional line this script does not read: {line.strip()}")
    return out


def model_element(c, kind, key):
    """(clusters.json element key, model-provisional) for a chip mark, or None
    when the model has no such element."""
    name = c["name"]
    if kind == "Cluster":
        return name, bool(c.get("provisional"))
    if kind == "Feature":
        for f in c.get("features", []):
            if f["code"] == key:
                return f"{name}.Feature.{f['code']}", bool(f.get("provisional"))
    if kind == "Attribute":
        for a in c["attributes"]:
            if a["id"] == key:
                return f"{name}.Attribute.{a['name']}", bool(a.get("provisional"))
    if kind == "Command":
        for cmd in c["commands"]:
            if (cmd["id"], cmd["direction"]) == key:
                return f"{name}.Command.{cmd['name']}", bool(cmd.get("provisional"))
    if kind == "Event":
        for e in c.get("events", []):
            if e["id"] == key:
                return f"{name}.Event.{e['name']}", bool(e.get("provisional"))
    if kind == "Field":
        owner, fid = key
        if isinstance(owner, tuple):  # a command's (id, direction)
            owners = [o for o in c["commands"] if (o["id"], o["direction"]) == owner]
        else:
            owners = [o for o in [*c.get("events", []), *c["datatypes"]]
                      if norm(o["name"]) == owner]
        for o in owners:
            for f in o.get("fields") or []:
                if f["id"] == fid:
                    return f"{name}.Field.{o['name']}.{f['name']}", bool(f.get("provisional"))
    if kind == "Value":
        owner, value = key
        for d in c["datatypes"]:
            if norm(d["name"]) != owner:
                continue
            for v in d.get("values") or []:
                if v["value"] == value:
                    return f"{name}.Value.{d['name']}.{v['name']}", False
            for b in d.get("bits") or []:
                if b.get("bit") == value:
                    return f"{name}.Value.{d['name']}.{b['name']}", False
    return None


def compute(chip, model):
    if not os.path.isdir(os.path.join(chip, XML_DIR)):
        die(f"no {XML_DIR} under {chip} (is it a connectedhomeip checkout?)")
    head = git(chip, "rev-parse", "HEAD").strip()
    release = git(chip, "rev-parse", f"{RELEASE}^{{commit}}").strip()

    def worktree_files():
        d = os.path.join(chip, XML_DIR)
        for f in sorted(os.listdir(d)):
            if f.endswith(".xml"):
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    yield f, fh.read()

    def release_files():
        for path in git(chip, "ls-tree", "--name-only", f"{RELEASE}:{XML_DIR}").split():
            if path.endswith(".xml"):
                yield path, git(chip, "show", f"{RELEASE}:{XML_DIR}/{path}")

    worktree = by_cluster_id(xml_roots(worktree_files))
    tagged = by_cluster_id(xml_roots(release_files))
    codegen = codegen_marks(git(chip, "show", f"{RELEASE}:{CODEGEN}"))

    revisions, marks, unmatched = {}, {}, []
    for c in model["clusters"]:
        hit = worktree.get(c["id"])
        if hit is not None:
            fname, root, _, _ = hit
            rev = num(root.get("revision"), f"{fname} revision")
            if not 1 <= rev <= 0xFFFF:
                die(f"{fname} revision {rev} is not a cluster revision (1 to 65535)")
            revisions[c["name"]] = rev
        elif c["name"] in REVISIONS_BY_HAND:
            revisions[c["name"]] = REVISIONS_BY_HAND[c["name"]][0]
        else:
            die(f"{c['name']} (cluster id {c['id']:#06x}) is not in chip's {XML_DIR}: "
                "add its revision, and why, to REVISIONS_BY_HAND in this script")

        sources = {}
        for label, table in ((XML_DIR, worktree), (f"{XML_DIR} at {RELEASE}", tagged)):
            if c["id"] in table:
                fname, r, chain, cid = table[c["id"]]
                for m in xml_marks(r, chain, fname):
                    sources.setdefault(m, []).append(label)
                if provisional(cid):
                    sources.setdefault(("Cluster", None), []).append(label)
        for m in codegen.get(c["id"], set()):
            sources.setdefault(m, []).append(f"controller-clusters.matter at {RELEASE}")
        whole = ("Cluster", None) in sources or c.get("provisional")
        for (kind, key), where in sources.items():
            if whole and kind != "Cluster":
                continue
            found = model_element(c, kind, key)
            if found is None:
                # Not generated (a 1.4 element the model dropped, or excluded),
                # or chip and the model disagree on its id or name: say so.
                unmatched.append(f"{c['name']}.{kind}.{key} ({', '.join(sorted(set(where)))})")
                continue
            element, model_provisional = found
            if not model_provisional:
                marks[element] = sorted(set(where))
    if unmatched:
        print(f"chip-facts: warning: {len(unmatched)} chip-provisional marks have no "
              "generated element:", file=sys.stderr)
        for u in sorted(unmatched):
            print(f"  {u}", file=sys.stderr)
    return {
        "comment": "Written by scripts/chip-facts.py from chip's Matter 1.4.2 data; do not edit "
                   "by hand. The dump reads it: `revisions` become CLUSTER_REVISION, and each "
                   "`provisional` element gets a rustdoc note.",
        "chip": {"worktree": head, RELEASE: release},
        "revisions": dict(sorted(revisions.items())),
        "provisional": [{"element": k, "sources": v} for k, v in sorted(marks.items())],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("chip", help="connectedhomeip checkout root")
    ap.add_argument("--write", action="store_true",
                    help=f"rewrite {os.path.relpath(OUT, REPO_ROOT)}")
    args = ap.parse_args()
    try:
        with open(MODEL, encoding="utf-8") as fh:
            model = json.load(fh)
    except (OSError, ValueError) as e:
        die(f"cannot read {MODEL}: {e}")
    facts = compute(args.chip, model)
    if args.write:
        with open(OUT, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(facts, indent=2) + "\n")
        print(f"chip-facts: wrote {len(facts['revisions'])} revisions, "
              f"{len(facts['provisional'])} provisional elements")
        return 0
    try:
        with open(OUT, encoding="utf-8") as fh:
            committed = json.load(fh)
    except (OSError, ValueError) as e:
        die(f"cannot read {OUT}: {e} (run with --write)")
    if committed.get("chip") != facts["chip"]:
        rec = committed.get("chip") or {}
        print(f"chip-facts: note: checkout is {facts['chip']['worktree'][:8]} "
              f"({RELEASE} {facts['chip'][RELEASE][:8]}), file was written from "
              f"{str(rec.get('worktree'))[:8]} ({RELEASE} {str(rec.get(RELEASE))[:8]})")
    drift = [k for k in FACTS if committed.get(k) != facts[k]]
    if drift:
        print(f"chip-facts: {', '.join(drift)} differ from chip; review, then run with --write")
        return 1
    print(f"chip-facts: {len(facts['revisions'])} revisions, "
          f"{len(facts['provisional'])} provisional elements, match chip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
