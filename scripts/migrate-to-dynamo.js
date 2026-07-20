#!/usr/bin/env node
'use strict';
/**
 * ONE-TIME SEED SCRIPT — imports existing JSON-file data into DynamoDB,
 * applying the data-quality gates from docs/data-structure-migration-plan.md
 * before any record is written. Companion to scripts/migrate-to-aws.js
 * (which pushes the same data to S3); this script targets the DynamoDB
 * table provisioned by terraform/dynamodb.tf instead.
 *
 * Reuses server/repositories/dynamoStore.js's diff/batch-write logic rather
 * than reimplementing it: each collection is loaded into a dynamoStore
 * whose `persisted` baseline starts empty (confirmed via init()), so a
 * single save() + flush() naturally becomes a full import.
 *
 * Usage:
 *   export DYNAMO_TABLE_NAME=synergy-cert-portal
 *   export DYNAMO_REGION=ap-south-1
 *   export DYNAMO_ACCESS_KEY=AKIAxxxxxxxxxxxxxxxx
 *   export DYNAMO_SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *   export TENANT_ID=SYNCERT
 *   node scripts/migrate-to-dynamo.js [--dry-run] [--force] [--overwrite]
 *
 *   --dry-run   Run every data-quality check and print intended item counts;
 *               never calls DynamoDB.
 *   --force     Proceed past quality-gate violations by skipping the
 *               offending records (each skip is logged) instead of aborting.
 *   --overwrite Allow importing into a tenant/prefix that already has items
 *               in the table (default: abort, to avoid silently clobbering
 *               a prior migration run).
 */

const fs   = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const DRY_RUN   = args.includes('--dry-run');
const FORCE     = args.includes('--force');
const OVERWRITE = args.includes('--overwrite');

// Bootstrap env from .env if present
const envFile = path.join(__dirname, '..', '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
    const m = line.trim().match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
  }
}

const TENANT_ID = process.env.TENANT_ID || 'SYNCERT';
const ROOT      = path.resolve(__dirname, '..');

if (!DRY_RUN) {
  if (!process.env.DYNAMO_TABLE_NAME) { console.error('ERROR: DYNAMO_TABLE_NAME is not set'); process.exit(1); }
  if (!process.env.DYNAMO_ACCESS_KEY && !process.env.S3_ACCESS_KEY && !process.env.AWS_ACCESS_KEY_ID) {
    console.error('ERROR: DYNAMO_ACCESS_KEY (or S3_ACCESS_KEY / AWS_ACCESS_KEY_ID) is not set'); process.exit(1);
  }
  if (!process.env.DYNAMO_SECRET_KEY && !process.env.S3_SECRET_KEY && !process.env.AWS_SECRET_ACCESS_KEY) {
    console.error('ERROR: DYNAMO_SECRET_KEY (or S3_SECRET_KEY / AWS_SECRET_ACCESS_KEY) is not set'); process.exit(1);
  }
}

const dynamodb = require('../server/services/dynamodb');
const { createDynamoStore } = require('../server/repositories/dynamoStore');

// ── Helpers ───────────────────────────────────────────────────────────────

function findFile(...paths) {
  for (const p of paths) if (fs.existsSync(p)) return p;
  return null;
}

function loadJson(fp) {
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return null; }
}

function normalizeVesselIMO(raw) {
  return String(raw || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 20);
}

const tenantDataDir = path.join(ROOT, 'data', TENANT_ID);
const rootDataDir   = path.join(ROOT, 'data');

function loadCollection(name) {
  const fp = findFile(path.join(tenantDataDir, name), path.join(rootDataDir, name));
  if (!fp) return {};
  return loadJson(fp) || {};
}

// ── Load raw collections ────────────────────────────────────────────────

const cst    = loadCollection('certificates.json');
const vapt   = loadCollection('vapt_certificates.json');
const docs   = loadCollection('documents.json');
const users  = loadCollection('users.json');
const groups = loadCollection('groups.json');

// ── Data-quality gates (docs/data-structure-migration-plan.md) ─────────────

const errors = [];   // hard violations — abort unless --force
const skipped = [];  // records dropped when --force is used

// CST and VAPT certs are kept as two SEPARATE collections here (never
// merged into one `type`-tagged bucket) so they land under the exact same
// entity prefixes — CST_CERT / VAPT_CERT — that server/index.js's live
// dual-write path already uses (cstStore/vaptStore). A prior version of
// this script merged them under a single 'CERT' prefix with a `type`
// field neither the local JSON files nor the live dual-write path ever
// write — importing that way would leave the live app unable to find any
// of this data once DUAL_WRITE_DYNAMO/SHADOW_READ_DYNAMO is enabled.
const certificates = {};
for (const [id, rec] of Object.entries(cst)) {
  if (!id || !rec.id) { errors.push(`certificates.json: record missing id (key="${id}")`); continue; }
  certificates[id] = rec;
}
const vaptCertificates = {};
for (const [id, rec] of Object.entries(vapt)) {
  if (!id || !rec.id) { errors.push(`vapt_certificates.json: record missing id (key="${id}")`); continue; }
  vaptCertificates[id] = rec;
}

// Gate: every document must have vesselIMO, fileName, filePath.
const documents = {};
for (const [id, rec] of Object.entries(docs)) {
  if (!id || !rec.id) { errors.push(`documents.json: record missing id (key="${id}")`); continue; }
  const missing = ['vesselIMO', 'fileName', 'filePath'].filter(f => !rec[f]);
  if (missing.length) {
    const msg = `Document ${id} missing required field(s): ${missing.join(', ')}`;
    if (FORCE) { skipped.push(msg); continue; }
    errors.push(msg);
    continue;
  }
  documents[id] = { ...rec, vesselIMO: normalizeVesselIMO(rec.vesselIMO) };
}

// Gate: groups.vesselIMOs normalized to the same IMO format used by certificates.
const groupsOut = {};
for (const [id, rec] of Object.entries(groups)) {
  if (!id || !rec.id) { errors.push(`groups.json: record missing id (key="${id}")`); continue; }
  const vesselIMOs = Array.isArray(rec.vesselIMOs) ? rec.vesselIMOs.map(normalizeVesselIMO).filter(Boolean) : [];
  groupsOut[id] = { ...rec, vesselIMOs };
}

// Gate: user emails lowercase-normalized and unique per tenant; groupIds must
// reference an existing group.
const usersOut = {};
const seenEmails = new Map();
for (const [id, rec] of Object.entries(users)) {
  if (!id || !rec.id) { errors.push(`users.json: record missing id (key="${id}")`); continue; }
  const email = String(rec.email || '').trim().toLowerCase();
  if (!email) {
    const msg = `User ${id} has no email`;
    if (FORCE) { skipped.push(msg); continue; }
    errors.push(msg);
    continue;
  }
  if (seenEmails.has(email)) {
    const msg = `Duplicate user email "${email}": ${seenEmails.get(email)} and ${id}`;
    if (FORCE) { skipped.push(`User ${id} — ${msg}`); continue; }
    errors.push(msg);
    continue;
  }
  seenEmails.set(email, id);

  const groupIds = Array.isArray(rec.groupIds) ? rec.groupIds : [];
  const danglingGroups = groupIds.filter(gid => !groupsOut[gid]);
  let cleanGroupIds = groupIds;
  if (danglingGroups.length) {
    const msg = `User ${id} references non-existent group(s): ${danglingGroups.join(', ')}`;
    if (FORCE) { skipped.push(`${msg} — dropped from groupIds`); cleanGroupIds = groupIds.filter(gid => groupsOut[gid]); }
    else { errors.push(msg); continue; }
  }
  usersOut[id] = { ...rec, email, groupIds: cleanGroupIds };
}

// ── Report ──────────────────────────────────────────────────────────────

console.log('');
console.log('═══════════════════════════════════════════════════════════');
console.log(' Synergy Cert Portal — DynamoDB Migration');
console.log(`  Tenant : ${TENANT_ID}`);
console.log(`  Table  : ${process.env.DYNAMO_TABLE_NAME || '(dry-run — not set)'}`);
console.log(`  Mode   : ${DRY_RUN ? 'DRY RUN (no writes)' : 'LIVE'}${FORCE ? ' + --force' : ''}${OVERWRITE ? ' + --overwrite' : ''}`);
console.log('═══════════════════════════════════════════════════════════');
console.log('');

if (errors.length) {
  console.log(`STEP 1 — Data quality gate: ${errors.length} violation(s) found`);
  console.log('─────────────────────────────────────────────────────────');
  errors.forEach(e => console.log(`  [FAIL] ${e}`));
  console.log('');
  if (!FORCE) {
    console.log('Aborting — fix the records above, or re-run with --force to skip them.');
    process.exit(1);
  }
}
if (skipped.length) {
  console.log(`  ${skipped.length} record(s) skipped due to --force:`);
  skipped.forEach(s => console.log(`  [SKIP] ${s}`));
  console.log('');
}

console.log('STEP 2 — Records ready to import');
console.log('─────────────────────────────────────────────────────────');
console.log(`  CST certificates        : ${Object.keys(certificates).length}`);
console.log(`  VAPT certificates       : ${Object.keys(vaptCertificates).length}`);
console.log(`  Documents               : ${Object.keys(documents).length}`);
console.log(`  Users                   : ${Object.keys(usersOut).length}`);
console.log(`  Groups                  : ${Object.keys(groupsOut).length}`);
console.log('');

if (DRY_RUN) {
  console.log('Dry run complete — no DynamoDB writes performed.');
  process.exit(0);
}

// ── Import ──────────────────────────────────────────────────────────────

async function importCollection(entityPrefix, label, data) {
  const store = createDynamoStore({
    tenantId: TENANT_ID,
    entityPrefix,
    seedData: {},
    debounceMs: 60_000, // irrelevant here — we call flush() directly
    onError: (err) => console.error(`  [FAIL] ${label}: ${err.message}`),
  });
  await store.init();
  const existing = Object.keys(store.load()).length;
  if (existing > 0 && !OVERWRITE) {
    console.error(`  [FAIL] ${label}: table already has ${existing} item(s) for TENANT#${TENANT_ID}/${entityPrefix}# — re-run with --overwrite to proceed anyway.`);
    return false;
  }
  store.save(data);
  await store.flush();
  console.log(`  [OK]   ${label} → ${Object.keys(data).length} item(s) written`);
  return true;
}

async function main() {
  console.log('STEP 3 — Writing to DynamoDB');
  console.log('─────────────────────────────────────────────────────────');

  const results = await Promise.all([
    importCollection('CST_CERT', 'CST Certificates', certificates),
    importCollection('VAPT_CERT', 'VAPT Certificates', vaptCertificates),
    importCollection('DOC', 'Documents', documents),
    importCollection('USER', 'Users', usersOut),
    importCollection('GROUP', 'Groups', groupsOut),
  ]);

  console.log('');
  if (results.every(Boolean)) {
    console.log('═══════════════════════════════════════════════════════════');
    console.log(' Migration complete!');
    console.log('═══════════════════════════════════════════════════════════');
  } else {
    console.log('Migration finished with failures — see [FAIL] lines above.');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('\nMigration failed:', err.message);
  process.exit(1);
});
