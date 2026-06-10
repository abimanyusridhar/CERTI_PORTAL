#!/usr/bin/env node
'use strict';
/**
 * ONE-TIME MIGRATION SCRIPT
 * Reads existing JSON data files + uploads/ directory,
 * writes everything to DynamoDB tables and S3.
 *
 * Run ONCE on EC2 after setting up AWS resources:
 *   node scripts/migrate-to-aws.js
 *
 * Required environment variables (set before running):
 *   AWS_REGION      e.g.  ap-south-1
 *   AWS_ACCOUNT_ID  e.g.  123456789012  (only needed if using explicit creds)
 *   S3_BUCKET       e.g.  synergy-cert-portal-uploads
 *   TENANT_ID       e.g.  SYNCERT
 *
 * If running on EC2 with an IAM role attached, AWS credentials are
 * automatically available — no access keys needed.
 */

const fs   = require('fs');
const path = require('path');

// ── Config ────────────────────────────────────────────────────────────────────
const TENANT_ID  = process.env.TENANT_ID || 'SYNCERT';
const S3_BUCKET  = process.env.S3_BUCKET;
const AWS_REGION = process.env.AWS_REGION || 'ap-south-1';

const ROOT       = path.resolve(__dirname, '..');
const DATA_DIR   = path.join(ROOT, 'data', TENANT_ID);
const DATA_ROOT  = path.join(ROOT, 'data');
const UPLOADS    = path.join(ROOT, 'uploads');

// DynamoDB table names — must match what you created in AWS console
const TABLES = {
  cst:       'synergy-cst-certs',
  vapt:      'synergy-vapt-certs',
  documents: 'synergy-documents',
  docAccess: 'synergy-doc-access',
  users:     'synergy-users',
  groups:    'synergy-groups',
};

if (!S3_BUCKET) {
  console.error('ERROR: S3_BUCKET environment variable is required.');
  process.exit(1);
}

// ── AWS SDK (installed via npm install) ───────────────────────────────────────
const { DynamoDBClient }         = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient,
        BatchWriteCommand }       = require('@aws-sdk/lib-dynamodb');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const rawDdb = new DynamoDBClient({ region: AWS_REGION });
const ddb    = DynamoDBDocumentClient.from(rawDdb, {
  marshallOptions: { removeUndefinedValues: true },
});
const s3     = new S3Client({ region: AWS_REGION });

// ── Helpers ───────────────────────────────────────────────────────────────────
function loadJson(filePath) {
  if (!fs.existsSync(filePath)) { console.log(`  (skip — not found: ${filePath})`); return {}; }
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch (e) { console.warn(`  WARNING: could not parse ${filePath}:`, e.message); return {}; }
}

async function batchPutDdb(tableName, tenantId, records) {
  const ids = Object.keys(records);
  if (!ids.length) { console.log(`  ${tableName}: 0 records — skip`); return; }
  const chunks = [];
  for (let i = 0; i < ids.length; i += 25) chunks.push(ids.slice(i, i + 25));
  let count = 0;
  for (const chunk of chunks) {
    await ddb.send(new BatchWriteCommand({
      RequestItems: {
        [tableName]: chunk.map(id => ({
          PutRequest: { Item: { pk: tenantId, sk: id, ...records[id] } },
        })),
      },
    }));
    count += chunk.length;
    process.stdout.write(`\r  ${tableName}: ${count}/${ids.length} records written`);
  }
  console.log(`\r  ${tableName}: ${ids.length} records migrated ✓`);
}

function mimeFor(filename) {
  const ext = path.extname(filename).toLowerCase();
  return { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
           '.webp': 'image/webp', '.pdf': 'application/pdf',
           '.doc': 'application/msword',
           '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
           '.xls': 'application/vnd.ms-excel',
           '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
         }[ext] || 'application/octet-stream';
}

async function uploadToS3(localPath, s3Key) {
  const buf  = fs.readFileSync(localPath);
  const mime = mimeFor(localPath);
  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET, Key: s3Key,
    Body: buf, ContentType: mime,
    ServerSideEncryption: 'AES256',
  }));
}

// ── Walk all upload directories ───────────────────────────────────────────────
function collectUploadFiles() {
  const result = [];
  function walk(dir, prefix) {
    if (!fs.existsSync(dir)) return;
    for (const name of fs.readdirSync(dir)) {
      const full = path.join(dir, name);
      const rel  = prefix ? `${prefix}/${name}` : name;
      if (fs.statSync(full).isDirectory()) {
        walk(full, rel);
      } else {
        result.push({ local: full, rel });
      }
    }
  }
  // uploads/<file> (flat) — tenant root files
  walk(UPLOADS, TENANT_ID);
  return result;
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log('');
  console.log('═══════════════════════════════════════════════════');
  console.log(' Synergy Cert Portal — AWS Migration Script');
  console.log(`  Tenant   : ${TENANT_ID}`);
  console.log(`  S3 Bucket: ${S3_BUCKET}`);
  console.log(`  Region   : ${AWS_REGION}`);
  console.log('═══════════════════════════════════════════════════');
  console.log('');

  // ── STEP 1: Migrate JSON data to DynamoDB ──────────────────────────────────
  console.log('STEP 1 — Migrating JSON data files → DynamoDB');
  console.log('─────────────────────────────────────────────');

  // Try tenant-specific dir first, fall back to root data dir
  const dataDirs = [DATA_DIR, DATA_ROOT];
  function findJson(filename) {
    for (const d of dataDirs) {
      const fp = path.join(d, filename);
      if (fs.existsSync(fp)) return fp;
    }
    return null;
  }

  const cstPath  = findJson('certificates.json');
  const vaptPath = findJson('vapt_certificates.json');
  const docsPath = findJson('documents.json');
  const daPath   = findJson('doc_access_requests.json');
  const usrPath  = findJson('users.json');
  const grpPath  = findJson('groups.json');

  await batchPutDdb(TABLES.cst,       TENANT_ID, cstPath  ? loadJson(cstPath)  : {});
  await batchPutDdb(TABLES.vapt,      TENANT_ID, vaptPath ? loadJson(vaptPath) : {});
  await batchPutDdb(TABLES.documents, TENANT_ID, docsPath ? loadJson(docsPath) : {});
  await batchPutDdb(TABLES.docAccess, TENANT_ID, daPath   ? loadJson(daPath)   : {});
  await batchPutDdb(TABLES.users,     TENANT_ID, usrPath  ? loadJson(usrPath)  : {});
  await batchPutDdb(TABLES.groups,    TENANT_ID, grpPath  ? loadJson(grpPath)  : {});

  console.log('');

  // ── STEP 2: Migrate upload files to S3 ────────────────────────────────────
  console.log('STEP 2 — Migrating upload files → S3');
  console.log('─────────────────────────────────────');

  const files = collectUploadFiles();
  if (!files.length) {
    console.log('  No upload files found — skip');
  } else {
    let ok = 0, fail = 0;
    for (const { local, rel } of files) {
      try {
        await uploadToS3(local, rel);
        ok++;
        process.stdout.write(`\r  Uploaded ${ok + fail}/${files.length}: ${path.basename(local)}`);
      } catch (e) {
        fail++;
        console.error(`\n  FAILED ${local}: ${e.message}`);
      }
    }
    console.log(`\r  ${ok} files uploaded to s3://${S3_BUCKET}  (${fail} failed) ✓`);
  }

  console.log('');
  console.log('═══════════════════════════════════════════════════');
  console.log(' Migration complete!');
  console.log('');
  console.log(' Next steps:');
  console.log('  1. Set environment variables in your EC2 process manager:');
  console.log(`       AWS_REGION=${AWS_REGION}`);
  console.log(`       S3_BUCKET=${S3_BUCKET}`);
  console.log(`       STORAGE_BACKEND=dynamodb`);
  console.log('  2. Restart the application: pm2 restart cert-portal');
  console.log('  3. Verify data in AWS Console (DynamoDB → Tables → Items)');
  console.log('  4. Verify files in S3 Console');
  console.log('  5. After confirming everything works, backup and remove data/');
  console.log('═══════════════════════════════════════════════════');
  console.log('');
}

main().catch(err => {
  console.error('\nMigration failed:', err.message);
  process.exit(1);
});
