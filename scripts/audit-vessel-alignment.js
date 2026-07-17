#!/usr/bin/env node
'use strict';

/**
 * Read-only vessel name/prefix alignment audit for CST and VAPT certificates.
 *
 * Flags, per vessel IMO:
 *   - crossSystemMismatch — CST and VAPT both have this IMO, but disagree on
 *     the bare vessel name or the MV/MT prefix (CST is authoritative; see
 *     GET /api/vessels/names in server/index.js).
 *   - withinSystemDrift    — the same IMO appears more than once in one
 *     system (CST or VAPT) with different bare names or prefixes.
 *   - missingPrefix        — a recipient/vessel name has no MV/MT prefix at
 *     all (informational — may legitimately be a person's name, not a bug).
 *
 * Makes no changes to any file. Run with: npm run audit:vessels
 * Optional: TENANT_ID=<id> node scripts/audit-vessel-alignment.js
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TENANT_ID = process.env.TENANT_ID || '';

function candidatePath(file) {
  const tenantPath = TENANT_ID ? path.join(ROOT, 'data', TENANT_ID, file) : null;
  if (tenantPath && fs.existsSync(tenantPath)) return tenantPath;
  const rootPath = path.join(ROOT, 'data', file);
  if (fs.existsSync(rootPath)) return rootPath;
  return tenantPath || rootPath;
}

function loadRecords(file) {
  const filePath = candidatePath(file);
  if (!fs.existsSync(filePath)) return { records: [], file: filePath, missing: true };
  try {
    const raw = fs.readFileSync(filePath, 'utf8').replace(/^﻿/, '');
    const parsed = JSON.parse(raw);
    const records = Array.isArray(parsed) ? parsed : Object.values(parsed || {});
    return { records: records.filter(v => v && typeof v === 'object'), file: filePath, missing: false };
  } catch (err) {
    return { records: [], file: filePath, missing: false, error: err.message };
  }
}

// Same normalisation rules as server/index.js (normalizeVesselIMO + the
// MV/MT-prefix stripping used by deriveQuarterFields / the CSV importers).
function normalizeIMO(raw) {
  return String(raw || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 20);
}
function prefixOf(name) {
  const m = String(name || '').match(/^(MV|MT)\s*[-–]/i);
  return m ? m[1].toUpperCase() : null;
}
// A looser check: does the name START with an MV/MT token at all, dash or not?
// (server/index.js's deriveQuarterFields() only recognises the dash form — a
// name like "MV Efficiency OL" is NOT treated as prefixed there, so this
// distinguishes "no vessel-type signal at all" from "has one, wrong format".)
function looseTokenOf(name) {
  const m = String(name || '').match(/^(MV|MT)\b/i);
  return m ? m[1].toUpperCase() : null;
}
function bareName(name) {
  return String(name || '').replace(/^(MV|MT)\s*[-–]?\s*/i, '').trim().toLowerCase();
}

function buildEntries(records, system) {
  return records
    .map(c => ({
      system,
      id: c.id || '(no id)',
      imo: normalizeIMO(c.vesselIMO),
      displayName: c.recipientName || c.vesselName || '',
      prefix: prefixOf(c.recipientName || c.vesselName),
      looseToken: looseTokenOf(c.recipientName || c.vesselName),
      bare: bareName(c.recipientName || c.vesselName),
    }))
    .filter(e => e.imo);
}

function groupByImo(entries) {
  const map = {};
  entries.forEach(e => { (map[e.imo] = map[e.imo] || []).push(e); });
  return map;
}

function main() {
  const cst = loadRecords('certificates.json');
  const vapt = loadRecords('vapt_certificates.json');
  const cstEntries = buildEntries(cst.records, 'CST');
  const vaptEntries = buildEntries(vapt.records, 'VAPT');

  const missingImo = [...cst.records, ...vapt.records]
    .filter(c => !normalizeIMO(c.vesselIMO))
    .map(c => c.id || '(no id)');

  // No MV/MT signal at all — could legitimately be a person's name, informational only.
  const missingPrefix = [...cstEntries, ...vaptEntries]
    .filter(e => !e.looseToken && e.displayName)
    .map(e => ({ system: e.system, id: e.id, imo: e.imo, name: e.displayName }));

  // Has an MV/MT token but not the "MV - "/"MT - " dash form the app's own
  // prefix-detection (deriveQuarterFields, CSV importers) actually recognises.
  const prefixMissingDash = [...cstEntries, ...vaptEntries]
    .filter(e => e.looseToken && !e.prefix)
    .map(e => ({ system: e.system, id: e.id, imo: e.imo, name: e.displayName }));

  const cstByImo = groupByImo(cstEntries);
  const vaptByImo = groupByImo(vaptEntries);

  function withinSystemDrift(byImo) {
    const out = [];
    Object.entries(byImo).forEach(([imo, list]) => {
      const distinct = [...new Set(list.map(e => `${e.prefix || ''}|${e.bare}`))];
      if (distinct.length > 1) {
        out.push({ imo, entries: list.map(e => ({ id: e.id, name: e.displayName })) });
      }
    });
    return out;
  }

  const crossSystemMismatch = [];
  Object.keys(cstByImo).forEach(imo => {
    if (!vaptByImo[imo]) return;
    const cstNames = new Set(cstByImo[imo].map(e => `${e.prefix || ''}|${e.bare}`));
    const vaptNames = new Set(vaptByImo[imo].map(e => `${e.prefix || ''}|${e.bare}`));
    const agrees = [...cstNames].some(n => vaptNames.has(n));
    if (!agrees) {
      crossSystemMismatch.push({
        imo,
        cst: cstByImo[imo].map(e => ({ id: e.id, name: e.displayName })),
        vapt: vaptByImo[imo].map(e => ({ id: e.id, name: e.displayName })),
      });
    }
  });

  // Same bare vessel name shared by more than one IMO (across CST+VAPT combined).
  // This is what makes the Vessel Groups tab show what looks like the same ship
  // twice with a different prefix — e.g. "GLOBAL HARMONY 9443578" next to
  // "MV - GLOBAL HARMONY 9348881". Flagged for human review only: it may be a
  // genuine IMO typo in one system, or two real, differently-named sister
  // vessels that happen to share a name — this script does not decide which.
  const byBareName = {};
  [...cstEntries, ...vaptEntries].forEach(e => {
    if (!e.bare) return;
    (byBareName[e.bare] = byBareName[e.bare] || []).push(e);
  });
  const possibleImoMismatch = Object.entries(byBareName)
    .map(([bare, list]) => ({ bare, imos: [...new Set(list.map(e => e.imo))], entries: list }))
    .filter(g => g.imos.length > 1)
    .map(g => ({
      vesselName: g.entries[0].bare,
      entries: g.entries.map(e => ({ system: e.system, id: e.id, imo: e.imo, name: e.displayName })),
    }));

  const report = {
    generatedAt: new Date().toISOString(),
    tenantId: TENANT_ID || null,
    source: {
      cst: path.relative(ROOT, cst.file).replace(/\\/g, '/') + (cst.missing ? ' (missing)' : ''),
      vapt: path.relative(ROOT, vapt.file).replace(/\\/g, '/') + (vapt.missing ? ' (missing)' : ''),
    },
    counts: { cstCerts: cst.records.length, vaptCerts: vapt.records.length },
    crossSystemMismatch,
    withinSystemDrift: {
      cst: withinSystemDrift(cstByImo),
      vapt: withinSystemDrift(vaptByImo),
    },
    missingPrefix,
    prefixMissingDash,
    possibleImoMismatch,
    missingImo,
    notes: [
      'Read-only report. No source files were changed.',
      'crossSystemMismatch: same IMO, CST and VAPT disagree on name/prefix — CST is treated as authoritative.',
      'withinSystemDrift: same IMO used with different names/prefixes inside one system.',
      'missingPrefix is informational only — a name with no MV/MT token may legitimately be a person\'s name, not an error.',
      'prefixMissingDash: has an MV/MT token but not the "MV - "/"MT - " dash form — the app\'s own prefix detection (deriveQuarterFields, CSV import) will not recognise it as prefixed, which is what drives the ambiguous-default-to-MV fallback fixed earlier.',
      'possibleImoMismatch: the same vessel name is recorded under more than one IMO — needs a human to confirm whether it\'s an IMO typo or two genuinely different vessels before anything is changed.',
    ],
  };

  console.log(JSON.stringify(report, null, 2));
}

main();
