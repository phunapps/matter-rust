#!/usr/bin/env python3
"""Freeze the facts the cluster codegen takes from chip's Matter 1.4.2 data
into xtask/scripts/dump-model/chip-1.4.2.json, or check that file against a
connectedhomeip checkout.

The dump script (xtask/scripts/dump-model/index.js) reads the frozen file, so
neither the dump nor the build needs a chip checkout. This script is the only
thing that reads chip, and it is dev-only like scripts/chip-xml-conformance.py.

Facts:
  revisions    each generated cluster's revision in chip's
               data_model/1.4.2/clusters XML (the checkout's working tree).
               Emitted as CLUSTER_REVISION. A generated cluster that is not
               in that XML stops the script unless REVISIONS_BY_HAND below
               names its revision: no silent fallback to the model's.

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
RELEASE = "v1.4.2.0"
# Revisions decided by hand for a generated cluster chip's 1.4.2 XML does not
# have (a Matter 1.5-only cluster): name -> (revision, why). Empty today.
REVISIONS_BY_HAND = {}
FACTS = ("revisions",)


def die(msg):
    print(f"chip-facts: {msg}", file=sys.stderr)
    sys.exit(2)


def git(chip, *args):
    r = subprocess.run(["git", "-C", chip, *args], capture_output=True, text=True)
    if r.returncode != 0:
        die(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def num(text, where):
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        die(f"{where}: not an integer: {text!r}")


def worktree_roots(chip):
    """cluster id -> (file name, <cluster> root) for chip's 1.4.2 XML."""
    d = os.path.join(chip, XML_DIR)
    if not os.path.isdir(d):
        die(f"no {XML_DIR} under {chip} (is it a connectedhomeip checkout?)")
    out = {}
    for fname in sorted(os.listdir(d)):
        if not fname.endswith(".xml"):
            continue
        try:
            root = ET.parse(os.path.join(d, fname)).getroot()
        except ET.ParseError as e:
            die(f"cannot parse {fname}: {e}")
        ids = root.find("clusterIds") if root.tag == "cluster" else None
        for cid in ids.findall("clusterId") if ids is not None else []:
            # One file can carry several ids (ConcentrationMeasurement.xml):
            # map by clusterId, never by file name.
            if cid.get("id") is not None:
                out[num(cid.get("id"), f"{fname} clusterId")] = (fname, root)
    if not out:
        die(f"no <clusterId> under {d}")
    return out


def compute(chip, model):
    head = git(chip, "rev-parse", "HEAD").strip()
    release = git(chip, "rev-parse", f"{RELEASE}^{{commit}}").strip()
    worktree = worktree_roots(chip)
    revisions = {}
    for c in model["clusters"]:
        hit = worktree.get(c["id"])
        if hit is not None:
            fname, root = hit
            revisions[c["name"]] = num(root.get("revision"), f"{fname} revision")
        elif c["name"] in REVISIONS_BY_HAND:
            revisions[c["name"]] = REVISIONS_BY_HAND[c["name"]][0]
        else:
            die(f"{c['name']} (cluster id {c['id']:#06x}) is not in chip's {XML_DIR}: "
                "add its revision, and why, to REVISIONS_BY_HAND in this script")
    return {
        "comment": "Written by scripts/chip-facts.py from chip's Matter 1.4.2 data; do not edit "
                   "by hand. The dump reads it: `revisions` become CLUSTER_REVISION.",
        "chip": {"worktree": head, RELEASE: release},
        "revisions": dict(sorted(revisions.items())),
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
        print(f"chip-facts: wrote {len(facts['revisions'])} revisions")
        return 0
    try:
        with open(OUT, encoding="utf-8") as fh:
            committed = json.load(fh)
    except (OSError, ValueError) as e:
        die(f"cannot read {OUT}: {e} (run with --write)")
    drift = [k for k in FACTS if committed.get(k) != facts[k]]
    if drift:
        print(f"chip-facts: {', '.join(drift)} differ from chip; review, then run with --write")
        return 1
    print(f"chip-facts: {len(facts['revisions'])} revisions match chip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
