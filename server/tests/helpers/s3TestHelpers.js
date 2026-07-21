'use strict';
/**
 * Integration tests spin up a real server process against a randomly-named
 * tenantId. Since local disk is no longer used for any app data (S3 is the
 * only store), these tests need three things this file provides:
 *
 *   - fetchTenantKeys(tenantId): the server generates its crypto keys and
 *     pushes them to S3 during boot (before it reports healthy) — tests that
 *     need the actual jwtSecret/urlMacKey (to mint tokens or verify
 *     signatures independently of the server) must read them back from S3
 *     instead of a local .keys.json file, which no longer exists.
 *
 *   - cleanupTenantS3Data(tenantId): without this, every test run leaves
 *     data/<tenantId>/*.json and uploads/<tenantId>/* objects behind in the
 *     real bucket forever. Call this from each test's teardown alongside
 *     killing the child process.
 *
 *   - readRealS3Env(): some tests spawn a server with AWS_ACCESS_KEY_ID /
 *     AWS_SECRET_ACCESS_KEY deliberately blanked (to test Cognito/SES "not
 *     configured" behaviour). Since the server now refuses to start at all
 *     without S3 configured, those tests need to hand it working S3
 *     credentials through the *separate* S3_BUCKET/S3_ACCESS_KEY/S3_SECRET_KEY
 *     env vars s3.js also accepts, independent of the ones being blanked.
 *
 * IMPORTANT: this module reads the repo's .env file and populates
 * process.env BEFORE requiring services/s3.js below — s3.js reads its AWS
 * credentials into top-level `const`s at require time, and the test-RUNNER
 * process (unlike the spawned server, which calls loadDotEnv() itself) never
 * otherwise loads .env at all. Without this, every s3.getJson/listObjects/
 * deleteFile call in this file would silently throw "S3 not configured",
 * even though the spawned child server has real, working credentials.
 */
const fs = require('node:fs');
const path = require('node:path');

function readRealS3Env() {
  const envPath = path.join(__dirname, '..', '..', '..', '.env');
  const out = {};
  if (!fs.existsSync(envPath)) return out;
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    const eqIdx = trimmed.indexOf('=');
    if (!trimmed || trimmed.startsWith('#') || eqIdx < 1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let val = trimmed.slice(eqIdx + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1);
    if (key === 'S3_BUCKET') out.S3_BUCKET = val;
    if (key === 'AWS_REGION') out.S3_REGION = val;
    if (key === 'AWS_ACCESS_KEY_ID') out.S3_ACCESS_KEY = val;
    if (key === 'AWS_SECRET_ACCESS_KEY') out.S3_SECRET_KEY = val;
  }
  return out;
}

// Populate THIS process's env from .env before services/s3.js is required,
// so its module-level S3_ENABLED/BUCKET/ACCESS_KEY/SECRET_KEY consts resolve
// correctly. Only fills in keys not already set (never clobbers an explicit
// env var a test-runner invocation may have provided).
for (const [key, val] of Object.entries(readRealS3Env())) {
  if (process.env[key] === undefined) process.env[key] = val;
}

const s3 = require('../../services/s3');

async function fetchTenantKeys(tenantId, { retries = 20, delayMs = 250 } = {}) {
  const key = `data/${tenantId}/.keys.json`;
  for (let i = 0; i < retries; i++) {
    try {
      const keys = await s3.getJson(key);
      if (keys && keys.jwtSecret) return keys;
    } catch { /* not written yet — retry */ }
    await new Promise(r => setTimeout(r, delayMs));
  }
  throw new Error(`Crypto keys never appeared in S3 at ${key} — server may not have booted successfully`);
}

async function cleanupTenantS3Data(tenantId) {
  if (!s3.S3_ENABLED || !tenantId) return;
  try {
    const keys = await Promise.all([
      s3.listObjects(`data/${tenantId}/`),
      s3.listObjects(`uploads/${tenantId}/`),
    ]);
    const allKeys = keys.flat();
    await Promise.all(allKeys.map(k => s3.deleteFile(k).catch(() => {})));
  } catch {
    // Best-effort cleanup — a failure here must never fail the test itself.
  }
}

module.exports = { fetchTenantKeys, cleanupTenantS3Data, readRealS3Env };
