#!/usr/bin/env node
/**
 * UAL Framework content validator.
 *
 * The accuracy rules in the project spec are prompt discipline. This turns them
 * into a build gate: content that invents a RecordType, mislabels a MITRE ID,
 * writes a query against the wrong table schema, or leaks a real-looking
 * identifier fails CI instead of shipping.
 *
 *   node scripts/validate.mjs            # validate everything
 *   node scripts/validate.mjs --strict   # treat warnings as failures
 *
 * No dependencies. Exits non-zero on error.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = join(ROOT, 'data');
const STRICT = process.argv.includes('--strict');
const STALE_DAYS = 180;

const errors = [];
const warnings = [];
const err = (file, msg) => errors.push(`${file}: ${msg}`);
const warn = (file, msg) => warnings.push(`${file}: ${msg}`);

const tx = JSON.parse(readFileSync(join(DATA, 'taxonomy.json'), 'utf8'));
const recordTypesById = new Map(tx.recordTypes.map(r => [r.id, r]));
const mitreIds = new Set(tx.mitre.map(m => m.id));
const workloads = new Set(tx.workloads);

// ---------------------------------------------------------------- helpers
const stripKqlComments = q => q.split('\n').map(l => l.replace(/\/\/.*$/, '')).join('\n');

const ipToInt = ip => ip.split('.').reduce((a, o) => (a << 8 >>> 0) + Number(o), 0) >>> 0;
const inCidr = (ip, cidr) => {
  const [net, bits] = cidr.split('/');
  const mask = bits === '0' ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return (ipToInt(ip) & mask) >>> 0 === (ipToInt(net) & mask) >>> 0;
};
const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '0.0.0.0/8'];

function* walkStrings(node, path = '') {
  if (typeof node === 'string') yield [path, node];
  else if (Array.isArray(node)) for (const [i, v] of node.entries()) yield* walkStrings(v, `${path}[${i}]`);
  else if (node && typeof node === 'object') for (const [k, v] of Object.entries(node)) yield* walkStrings(v, path ? `${path}.${k}` : k);
}

// ---------------------------------------------------------------- checks
function checkPlaceholders(file, doc) {
  const { allowedDomains, allowedIpv4Cidrs } = tx.placeholderPolicy;
  const domainOk = d => allowedDomains.includes(d.toLowerCase()) || d.toLowerCase().endsWith('.onmicrosoft.com')
    && allowedDomains.some(a => d.toLowerCase().startsWith(a.split('.')[0]));

  for (const [path, str] of walkStrings(doc)) {
    for (const m of str.matchAll(/[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g)) {
      if (!domainOk(m[1])) err(file, `non-placeholder email domain "${m[1]}" at ${path}. GitHub Pages is public; use ${allowedDomains.slice(0, 3).join(', ')}.`);
    }
    for (const m of str.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
      const ip = m[0];
      if (ip.split('.').some(o => Number(o) > 255)) continue;
      const ok = allowedIpv4Cidrs.some(c => inCidr(ip, c)) || PRIVATE.some(c => inCidr(ip, c));
      if (!ok) err(file, `non-documentation IP "${ip}" at ${path}. Use RFC 5737 ranges: ${allowedIpv4Cidrs.join(', ')}.`);
    }
  }
}

function checkStaleness(file, doc) {
  const cutoff = Date.now() - STALE_DAYS * 864e5;
  const seen = new Set();
  const scan = node => {
    if (Array.isArray(node)) node.forEach(scan);
    else if (node && typeof node === 'object') {
      if (node.lastVerified && Date.parse(node.lastVerified) < cutoff && !seen.has(node.text)) {
        seen.add(node.text);
        warn(file, `claim last verified ${node.lastVerified} (>${STALE_DAYS}d): "${String(node.text).slice(0, 70)}..."`);
      }
      Object.values(node).forEach(scan);
    }
  };
  scan(doc);
}

function checkKql(file, sid, q) {
  const target = tx.kqlTargets[q.platform];
  const body = stripKqlComments(q.query);
  const at = `${sid}/${q.id}`;

  if (!target) { err(file, `${at}: unknown platform "${q.platform}".`); return; }
  const table = target.tables[q.table];
  if (!table) { err(file, `${at}: table "${q.table}" is not registered for platform "${q.platform}".`); return; }
  if (!new RegExp(`\\b${q.table}\\b`).test(body)) err(file, `${at}: declares table "${q.table}" but the query body never references it.`);

  // The bug the original spec baked in: AuditData exists in neither KQL target.
  if (/\bAuditData\b/.test(body)) err(file, `${at}: references AuditData, which does not exist in ${q.table}. Sentinel OfficeActivity is pre-flattened; Defender CloudAppEvents uses RawEventData.`);

  if (!new RegExp(`\\b${target.timeColumn}\\b`).test(body)) err(file, `${at}: no ${target.timeColumn} bound. Every query needs an explicit time filter.`);

  const wrongTime = Object.entries(tx.kqlTargets).find(([p]) => p !== q.platform)?.[1].timeColumn;
  if (wrongTime && new RegExp(`\\b${wrongTime}\\b`).test(body)) err(file, `${at}: uses ${wrongTime}, which belongs to the other platform. ${q.platform} uses ${target.timeColumn}.`);

  if (table.rawColumn === null && /\bRawEventData\b/.test(body)) err(file, `${at}: ${q.table} has no RawEventData column.`);
  if (table.recordTypeRepresentation === 'string' && /RecordType\s*(==|=~|\bin\b)\s*\(?\s*\d/.test(body)) err(file, `${at}: compares RecordType to an integer. In ${q.table} RecordType holds the enum member name as a string.`);

  for (const [bad, good] of Object.entries(tx.knownBadTableNames)) {
    if (new RegExp(`\\b${bad}\\b`).test(body)) err(file, `${at}: references "${bad}", which is not a real table. Use "${good}".`);
  }
}

function checkTemplateBinding(file, sid, m) {
  const declared = new Set((m.params ?? []).map(p => p.name));
  const used = new Set([...m.template.matchAll(/\{\{(\w+)\}\}/g)].map(x => x[1]));
  for (const u of used) if (!declared.has(u)) err(file, `${sid}/${m.id}: template uses {{${u}}} with no matching param definition.`);
  for (const d of declared) if (!used.has(d)) warn(file, `${sid}/${m.id}: param "${d}" is declared but never used in the template.`);
}

function checkCategory(file, doc) {
  const stem = basename(file, '.json');
  if (doc.id !== stem) err(file, `id "${doc.id}" does not match filename stem "${stem}".`);
  for (const w of doc.workloads ?? []) if (!workloads.has(w)) err(file, `unknown workload "${w}".`);

  for (const rt of doc.recordTypes ?? []) {
    const known = recordTypesById.get(rt.id);
    if (!known) { if (rt.verified !== false) err(file, `RecordType ${rt.id} is not in taxonomy.json. Add it there first, or mark this entry verified:false to render a [VERIFY] badge.`); continue; }
    if (known.member !== rt.member) err(file, `RecordType ${rt.id} declared as "${rt.member}" but taxonomy says "${known.member}".`);
  }
  const declaredIds = new Set((doc.recordTypes ?? []).map(r => r.id));

  for (const s of doc.scenarios ?? []) {
    if (doc.status === 'stub') continue;

    for (const m of s.overview?.mitre ?? []) {
      if (!mitreIds.has(m.id) && m.verified !== false) err(file, `${s.id}: MITRE ${m.id} is not in the verified anchor set. Add it to taxonomy.json or mark verified:false.`);
    }
    if (!(s.overview?.mitre ?? []).some(m => m.role === 'primary')) warn(file, `${s.id}: no primary MITRE technique.`);

    for (const id of s.overview?.ual?.recordTypeIds ?? []) {
      if (!recordTypesById.has(id)) err(file, `${s.id}: RecordType ${id} is not in taxonomy.json.`);
      else if (!declaredIds.has(id)) warn(file, `${s.id}: uses RecordType ${id} but the category header does not declare it.`);
    }
    for (const op of s.overview?.ual?.operations ?? []) {
      if (!recordTypesById.has(op.recordTypeId) && op.verified !== false) err(file, `${s.id}: operation "${op.name}" maps to unknown RecordType ${op.recordTypeId}.`);
    }

    for (const m of s.acquisition?.methods ?? []) checkTemplateBinding(file, s.id, m);
    for (const q of s.hunting?.queries ?? []) checkKql(file, s.id, q);

    for (const cv of s.crossValidation?.correlations ?? []) {
      if (!cv.table) continue;
      if (tx.knownBadTableNames[cv.table]) err(file, `${s.id}: cross-validation names table "${cv.table}", which does not exist. Use "${tx.knownBadTableNames[cv.table]}".`);
      else if (cv.platform && tx.kqlTargets[cv.platform] && !tx.kqlTargets[cv.platform].tables[cv.table]) {
        warn(file, `${s.id}: cross-validation table "${cv.table}" is not registered for platform "${cv.platform}". Add it to taxonomy.json.`);
      }
      if (cv.query) checkKql(file, s.id, { id: `xval-${cv.table}`, platform: cv.platform, table: cv.table, query: cv.query });
    }

    const gaps = s.caveats?.dataGaps ?? [];
    if (!gaps.length) warn(file, `${s.id}: no dataGaps recorded. Every UAL scenario has at least one.`);
    if (!(s.caveats?.latency ?? []).some(l => /no guarantee|no committed|60|90/i.test(l.text))) {
      err(file, `${s.id}: latency caveat must carry the current no-guaranteed-SLA / 60-90 minute language, not a fixed figure.`);
    }
  }
}

// ---------------------------------------------------------------- run
const dir = join(DATA, 'categories');
const files = readdirSync(dir).filter(f => f.endsWith('.json'));
if (!files.length) err('data/categories', 'no category files found.');

for (const f of files) {
  const rel = `data/categories/${f}`;
  let doc;
  try { doc = JSON.parse(readFileSync(join(dir, f), 'utf8')); }
  catch (e) { err(rel, `invalid JSON: ${e.message}`); continue; }
  checkCategory(rel, doc);
  checkPlaceholders(rel, doc);
  checkStaleness(rel, doc);
}

for (const w of warnings) console.log(`  warn  ${w}`);
for (const e of errors) console.log(`  ERROR ${e}`);

const failed = errors.length || (STRICT && warnings.length);
console.log(`\n${files.length} file(s) checked - ${errors.length} error(s), ${warnings.length} warning(s).`);
process.exit(failed ? 1 : 0);
