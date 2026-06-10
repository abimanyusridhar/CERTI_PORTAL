#!/usr/bin/env node
'use strict';
/**
 * ONE-TIME MIGRATION SCRIPT — pushes all existing data to S3.
 *
 * Run this ONCE on your EC2 instance after setting environment variables.
 * Uses the same zero-dependency S3 service already built into the app.
 *
 * Usage:
 *   export S3_BUCKET=synergy-cert-portal-uploads
 *   export S3_REGION=ap-south-1
 *   export S3_ACCESS_KEY=AKIAxxxxxxxxxxxxxxxx
 *   export S3_SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *   export TENANT_ID=SYNCERT
 *   node scripts/migrate-to-aws.js
 */

const fs   = require('fs');
const path = require('path');

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

// Validate S3 config before loading the module
if (!process.env.S3_BUCKET)      { console.error('ERROR: S3_BUCKET is not set');      process.exit(1); }
if (!process.env.S3_ACCESS_KEY && !process.env.AWS_ACCESS_KEY_ID) {
  console.error('ERROR: S3_ACCESS_KEY (or AWS_ACCESS_KEY_ID) is not set'); process.exit(1);
}
if (!process.env.S3_SECRET_KEY && !process.env.AWS_SECRET_ACCESS_KEY) {
  console.error('ERROR: S3_SECRET_KEY (or AWS_SECRET_ACCESS_KEY) is not set'); process.exit(1);
}

const s3 = require('../server/services/s3');
const BUCKET = s3.BUCKET;
const REGION = s3.REGION;

// ── Helpers ───────────────────────────────────────────────────────────────────
function findFile(...paths) {
  for (const p of paths) if (fs.existsSync(p)) return p;
  return null;
}

function loadJson(fp) {
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return null; }
}

async function putJson(key, data) {
  await s3.putJson(key, data);
}

async function putFile(key, localPath) {
  const buf  = fs.readFileSync(localPath);
  const ext  = path.extname(localPath).toLowerCase();
  const mime = {
    '.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp',
    '.gif':'image/gif','.pdf':'application/pdf','.doc':'application/msword',
    '.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls':'application/vnd.ms-excel',
    '.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  }[ext] || 'application/octet-stream';
  await s3.uploadFile(key, buf, mime);
}

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  const results = [];
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) results.push(...walk(full));
    else results.push(full);
  }
  return results;
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log('');
  console.log('═══════════════════════════════════════════════════════════');
  console.log(' Synergy Cert Portal — S3 Migration');
  console.log(`  Tenant : ${TENANT_ID}`);
  console.log(`  Bucket : ${BUCKET}`);
  console.log(`  Region : ${REGION}`);
  console.log('═══════════════════════════════════════════════════════════');
  console.log('');

  const tenantDataDir = path.join(ROOT, 'data', TENANT_ID);
  const rootDataDir   = path.join(ROOT, 'data');

  // ── STEP 1: Push JSON data files to S3 ──────────────────────────────────
  console.log('STEP 1 — Uploading data files to S3');
  console.log('─────────────────────────────────────────────────────────');

  const dataFiles = [
    { name: 'certificates.json',       s3Key: `data/${TENANT_ID}/certificates.json` },
    { name: 'vapt_certificates.json',  s3Key: `data/${TENANT_ID}/vapt_certificates.json` },
    { name: 'documents.json',          s3Key: `data/${TENANT_ID}/documents.json` },
    { name: 'doc_access_requests.json',s3Key: `data/${TENANT_ID}/doc_access_requests.json` },
    { name: 'users.json',              s3Key: `data/${TENANT_ID}/users.json` },
    { name: 'groups.json',             s3Key: `data/${TENANT_ID}/groups.json` },
  ];

  for (const { name, s3Key } of dataFiles) {
    const fp = findFile(path.join(tenantDataDir, name), path.join(rootDataDir, name));
    if (!fp) {
      console.log(`  [SKIP] ${name} — not found locally`);
      continue;
    }
    const data = loadJson(fp);
    if (!data) { console.log(`  [SKIP] ${name} — could not parse`); continue; }
    const count = Object.keys(data).length;
    try {
      await putJson(s3Key, data);
      console.log(`  [OK]   ${name} → s3://${BUCKET}/${s3Key}  (${count} records)`);
    } catch (e) {
      console.error(`  [FAIL] ${name}: ${e.message}`);
    }
  }

  console.log('');

  // ── STEP 2: Push upload files to S3 ────────────────────────────────────
  console.log('STEP 2 — Uploading cert images and attachments to S3');
  console.log('─────────────────────────────────────────────────────────');

  const uploadsDir = path.join(ROOT, 'uploads');
  const allFiles   = walk(uploadsDir);

  if (!allFiles.length) {
    console.log('  No files found in uploads/ — skip');
  } else {
    let ok = 0, skip = 0, fail = 0;
    for (const localPath of allFiles) {
      // Build S3 key: uploads/SYNCERT/cert_xxx.png
      const rel = path.relative(uploadsDir, localPath).replace(/\\/g, '/');
      const s3Key = `uploads/${rel.startsWith(TENANT_ID + '/') ? rel : TENANT_ID + '/' + rel}`;
      try {
        await putFile(s3Key, localPath);
        ok++;
        process.stdout.write(`\r  Uploaded ${ok + fail}/${allFiles.length}: ${path.basename(localPath)}        `);
      } catch (e) {
        fail++;
        console.error(`\n  [FAIL] ${localPath}: ${e.message}`);
      }
    }
    console.log(`\r  ${ok} files uploaded to s3://${BUCKET}  (${fail} failed)           `);
  }

  console.log('');
  console.log('═══════════════════════════════════════════════════════════');
  console.log(' Migration complete!');
  console.log('');
  console.log(' NEXT: Set these env vars in your PM2 / systemd config,');
  console.log(' then restart the app:');
  console.log('');
  console.log(`   S3_BUCKET=${BUCKET}`);
  console.log(`   S3_REGION=${REGION}`);
  console.log(`   S3_ACCESS_KEY=<your-access-key>`);
  console.log(`   S3_SECRET_KEY=<your-secret-key>`);
  console.log(`   TENANT_ID=${TENANT_ID}`);
  console.log('');
  console.log(' Verify in AWS Console:');
  console.log(`   S3 → ${BUCKET} → data/ and uploads/`);
  console.log('═══════════════════════════════════════════════════════════');
  console.log('');
}

main().catch(err => {
  console.error('\nMigration failed:', err.message);
  process.exit(1);
});
