// xtask/scripts/dump-model/index.js
//
// Walk the @matter/model standard data model and emit the frozen codegen
// input xtask/model/clusters.json. Allowlisted to the 10 M7 target
// clusters. Output is deterministic (sorted) so the committed file is
// stable and `--check`-able in M7.3.
//
// JSON contract (flat — consumed by xtask/src/codegen/model.rs in M7.3):
//   { meta: { matterJsModelVersion, specRevision, dumpScriptVersion,
//             generatedClusters: [name], excluded: [{cluster,element,kind,reason}] },
//     clusters: [ {
//       id, name, revision,
//       features:   [{ bit, code, name, description }],
//       attributes: [{ id, name, type, metatype, entryType?, nullable, optional, writable, description }],
//       commands:   [{ id, name, direction, responseId, fields: [field] }],
//       datatypes:  [{ name, base, kind: "enum"|"bitmap"|"struct"|"scalar",
//                      values?: [{value,name,description}],
//                      bits?:   [{bit,name,description}],
//                      fields?: [field] }]
//     } ] }
//   field = { id, name, type, metatype, entryType?, nullable, optional, description }
//
// All exclusions are recorded in meta.excluded with a reason. Hard error
// on: an allowlisted cluster the model doesn't expose, a missing
// id/name/type, or DoorLock's Aliro features not being found (a model
// rename must not silently widen the DoorLock surface).

import '@matter/model/resources'; // SIDE-EFFECT, FIRST: populates .details
import { Matter, GLOBAL_IDS, Conformance } from '@matter/model';

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..'); // dump-model -> scripts -> xtask -> repo root
const OUT_PATH = join(REPO_ROOT, 'xtask', 'model', 'clusters.json');

// Bump when the JSON shape changes (recorded in the header for audit).
const DUMP_SCRIPT_VERSION = 1;
// @matter/model 0.17.x tracks Matter spec 1.5.1. Recorded for provenance;
// the freeze test only asserts it is a non-empty string, so correcting it
// later does not break the gate.
const SPEC_REVISION = '1.5.1';

// The 10 M7 target clusters (Section 8 of the spec / CLAUDE.md milestone).
const ALLOWLIST = [
  { id: 0x0028, name: 'BasicInformation' },
  { id: 0x001d, name: 'Descriptor' },
  { id: 0x0003, name: 'Identify' },
  { id: 0x0006, name: 'OnOff' },
  { id: 0x0008, name: 'LevelControl' },
  { id: 0x0300, name: 'ColorControl' },
  { id: 0x0406, name: 'OccupancySensing' },
  { id: 0x0402, name: 'TemperatureMeasurement' },
  { id: 0x0405, name: 'RelativeHumidityMeasurement' },
  { id: 0x0101, name: 'DoorLock' },
];

const excluded = [];
function recordExclusion(cluster, element, kind, reason) {
  excluded.push({ cluster, element, kind, reason });
}

function fail(msg) {
  throw new Error(`dump-model: ${msg}`);
}

// --- conformance feature-gating ------------------------------------------

// Collect every `{type:"name", param:"<CODE>"}` identifier in a conformance
// AST. Operators/flags/brackets are distinct node types so they are never
// mistaken for names; value-name refs are filtered out by the caller via
// intersection with the cluster's feature set.
function collectNames(node, out) {
  if (!node || typeof node !== 'object') return out;
  if (node.type === 'name' && typeof node.param === 'string') out.add(node.param);
  const p = node.param;
  if (p && typeof p === 'object') {
    if (p.lhs) collectNames(p.lhs, out);
    if (p.rhs) collectNames(p.rhs, out);
    if (p.type) collectNames(p, out);
    if (Array.isArray(p)) p.forEach((n) => collectNames(n, out));
  }
  return out;
}

function gatingFeatures(el, featureNames) {
  const c = el.effectiveConformance;
  if (!c || !c.ast) return new Set();
  const names = collectNames(c.ast, new Set());
  return new Set([...names].filter((n) => featureNames.has(n)));
}

// Returns an exclusion reason string, or null to keep the element.
function exclusionReason(el, aliroCodes, featureNames) {
  if (el.isDeprecated) return 'deprecated';
  if (el.isDisallowed) return 'disallowed';
  if (el.effectiveConformance && el.effectiveConformance.type === Conformance.Flag.Provisional) {
    return 'provisional';
  }
  const gating = gatingFeatures(el, featureNames);
  if (gating.size > 0 && [...gating].every((f) => aliroCodes.has(f))) {
    return `aliro-feature-gated (${[...gating].join(',')})`;
  }
  return null;
}

// --- element serialisers --------------------------------------------------

function requireIdNameType(el, where) {
  if (el.id === undefined || el.id === null) fail(`${where}: missing id`);
  if (!el.name) fail(`${where} (id ${el.id}): missing name`);
  if (!el.effectiveType) fail(`${where} (${el.name}): missing type`);
}

function entryTypeOf(el) {
  if (el.effectiveMetatype === 'array' && el.listEntry) return el.listEntry.effectiveType;
  return undefined; // omitted by JSON.stringify
}

function dumpField(f, where) {
  requireIdNameType(f, where);
  return {
    id: f.id,
    name: f.name,
    type: f.effectiveType,
    metatype: f.effectiveMetatype,
    entryType: entryTypeOf(f),
    nullable: !!(f.effectiveQuality && f.effectiveQuality.nullable),
    optional: f.effectiveConformance ? !f.effectiveConformance.isMandatory : true,
    description: f.details || null,
  };
}

function dumpAttribute(a, where) {
  requireIdNameType(a, where);
  return {
    id: a.id,
    name: a.name,
    type: a.effectiveType,
    metatype: a.effectiveMetatype,
    entryType: entryTypeOf(a),
    nullable: !!(a.effectiveQuality && a.effectiveQuality.nullable),
    optional: !a.effectiveConformance.isMandatory,
    writable: !!(a.effectiveAccess && a.effectiveAccess.writable),
    description: a.details || null,
  };
}

function dumpCommand(cmd, where) {
  if (cmd.id === undefined || cmd.id === null) fail(`${where}: command missing id`);
  if (!cmd.name) fail(`${where} (id ${cmd.id}): command missing name`);
  const fields = [...cmd.children].map((c, i) => dumpField(c, `${where}.${cmd.name}.field[${i}]`));
  return {
    id: cmd.id,
    name: cmd.name,
    direction: cmd.isResponse ? 'response' : 'request',
    responseId: cmd.responseModel ? cmd.responseModel.id : null,
    fields,
  };
}

function dumpDatatype(dt, where) {
  if (!dt.name) fail(`${where}: datatype missing name`);
  const meta = dt.effectiveMetatype;
  const out = { name: dt.name, base: dt.effectiveType, kind: 'scalar', description: dt.details || null };
  if (meta === 'enum') {
    out.kind = 'enum';
    out.values = [...dt.children].map((c) => {
      if (c.id === undefined || c.id === null) fail(`${where}.${dt.name}: enum member ${c.name} missing value`);
      return { value: c.id, name: c.name, description: c.details || null };
    });
  } else if (meta === 'bitmap') {
    out.kind = 'bitmap';
    out.bits = [...dt.children].map((c) => ({
      bit: c.constraint ? c.constraint.value : null,
      name: c.name,
      description: c.details || null,
    }));
  } else if (meta === 'object') {
    out.kind = 'struct';
    out.fields = [...dt.children].map((c, i) => dumpField(c, `${where}.${dt.name}.field[${i}]`));
  }
  return out;
}

// --- cluster walk ---------------------------------------------------------

function dumpCluster(entry) {
  const cluster = Matter.clusters(entry.id);
  if (!cluster) fail(`allowlisted cluster ${entry.name} (id ${entry.id}) not found in @matter/model`);
  if (cluster.name !== entry.name) {
    fail(`cluster id ${entry.id} is "${cluster.name}", expected "${entry.name}" — allowlist/model drift`);
  }

  const featureNames = new Set(cluster.features.map((f) => f.name));

  // Aliro denylist: the Aliro-titled features (DoorLock has ALIRO + ALBU).
  // Empty for every non-DoorLock cluster. Hard-fail if DoorLock unexpectedly
  // has none, so a model rename cannot silently widen the surface.
  const aliroCodes = new Set(cluster.features.filter((f) => f.title && f.title.startsWith('Aliro')).map((f) => f.name));
  if (cluster.name === 'DoorLock' && aliroCodes.size === 0) {
    fail('DoorLock: no Aliro-titled features found — model shape changed; review the exclusion filter');
  }

  const features = cluster.features.map((f) => ({
    bit: f.constraint ? f.constraint.value : null,
    code: f.name,
    name: f.title || f.name,
    description: f.details || null,
  }));

  // Attributes: drop the 6 global attributes (handled by gen/globals.rs),
  // then apply conformance/feature exclusions.
  const attributes = [];
  for (const a of cluster.attributes) {
    if (GLOBAL_IDS.has(a.id)) continue; // global, not an exclusion to record
    const reason = exclusionReason(a, aliroCodes, featureNames);
    if (reason) {
      recordExclusion(cluster.name, a.name, 'attribute', reason);
      continue;
    }
    attributes.push(dumpAttribute(a, `${cluster.name}.attr`));
  }

  // Commands: both request and response directions; apply exclusions.
  const commands = [];
  for (const cmd of cluster.commands) {
    const reason = exclusionReason(cmd, aliroCodes, featureNames);
    if (reason) {
      recordExclusion(cluster.name, cmd.name, 'command', reason);
      continue;
    }
    commands.push(dumpCommand(cmd, `${cluster.name}.cmd`));
  }

  // Events: not dumped at all (no IM event support until M8). Record a
  // single auditable summary entry per cluster that has any.
  const eventCount = [...cluster.events].length;
  if (eventCount > 0) {
    recordExclusion(cluster.name, `${eventCount} event(s)`, 'events', 'no IM event support until M8');
  }

  const datatypes = [...cluster.datatypes].map((dt) => dumpDatatype(dt, `${cluster.name}.datatype`));

  // Deterministic ordering for a stable committed artifact.
  attributes.sort((x, y) => x.id - y.id);
  commands.sort((x, y) => x.id - y.id || x.direction.localeCompare(y.direction));
  datatypes.sort((x, y) => x.name.localeCompare(y.name));
  features.sort((x, y) => (x.bit ?? 0) - (y.bit ?? 0));

  return { id: cluster.id, name: cluster.name, revision: cluster.revision, features, attributes, commands, datatypes };
}

// --- main -----------------------------------------------------------------

function modelVersion() {
  // Authoritative version: read the installed package's own manifest.
  const pkgPath = join(__dirname, 'node_modules', '@matter', 'model', 'package.json');
  return JSON.parse(readFileSync(pkgPath, 'utf8')).version;
}

const clusters = ALLOWLIST.map(dumpCluster);
clusters.sort((x, y) => x.id - y.id);
excluded.sort(
  (x, y) => x.cluster.localeCompare(y.cluster) || x.kind.localeCompare(y.kind) || x.element.localeCompare(y.element),
);

const doc = {
  meta: {
    matterJsModelVersion: modelVersion(),
    specRevision: SPEC_REVISION,
    dumpScriptVersion: DUMP_SCRIPT_VERSION,
    generatedClusters: clusters.map((c) => c.name),
    excluded,
  },
  clusters,
};

mkdirSync(dirname(OUT_PATH), { recursive: true });
writeFileSync(OUT_PATH, JSON.stringify(doc, null, 2) + '\n');
console.log(`dump-model: wrote ${clusters.length} clusters, ${excluded.length} exclusions -> ${OUT_PATH}`);
