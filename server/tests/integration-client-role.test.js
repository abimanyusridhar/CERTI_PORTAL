'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { createSecurityService } = require('../services/security');

const ROOT = path.join(__dirname, '..', '..');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');

function requestJson({ method = 'GET', port, urlPath, token, body }) {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : null;
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: urlPath,
      method,
      headers: {
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { /* ignore */ }
        resolve({ status: res.statusCode, json, text });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function waitForHealth(port, timeoutMs = 12000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await requestJson({ port, urlPath: '/api/health' });
      if (res.status === 200 && res.json && res.json.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('Server did not become healthy in time');
}

// Every mutating ("Bucket A") route gated by hasAdminRole() in server/index.js.
// Bodies are intentionally minimal/invalid — for the client-role assertion the exact
// downstream status doesn't matter, only that the gate itself returns 403 before any
// business logic runs. For the admin-role assertion we only assert the gate does NOT
// block (i.e. status is neither 401 nor 403); the resulting 400/404/503 from invalid
// bodies or missing records is expected and irrelevant here.
const MUTATING_ROUTES = [
  { method: 'POST',   urlPath: '/api/certs' },
  { method: 'PUT',    urlPath: '/api/certs/FAKE-ID' },
  { method: 'DELETE', urlPath: '/api/certs/FAKE-ID' },
  { method: 'POST',   urlPath: '/api/certs/FAKE-ID/send-email' },
  { method: 'DELETE', urlPath: '/api/certs/FAKE-ID/attachments/0' },
  { method: 'POST',   urlPath: '/api/import-csv', body: [] },
  { method: 'POST',   urlPath: '/api/vapt/certs' },
  { method: 'PUT',    urlPath: '/api/vapt/certs/FAKE-ID' },
  { method: 'DELETE', urlPath: '/api/vapt/certs/FAKE-ID' },
  { method: 'POST',   urlPath: '/api/vapt/certs/FAKE-ID/send-email' },
  { method: 'DELETE', urlPath: '/api/vapt/certs/FAKE-ID/attachments/0' },
  { method: 'POST',   urlPath: '/api/vapt/import-csv', body: [] },
  { method: 'POST',   urlPath: '/api/docs/upload' },
  { method: 'PUT',    urlPath: '/api/docs/DOC-1' },
  { method: 'DELETE', urlPath: '/api/docs/DOC-1' },
  { method: 'POST',   urlPath: '/api/admin/users', body: {} },
  { method: 'PUT',    urlPath: '/api/admin/users/USR-1' },
  { method: 'DELETE', urlPath: '/api/admin/users/USR-1' },
  { method: 'POST',   urlPath: '/api/admin/groups', body: {} },
  { method: 'PUT',    urlPath: '/api/admin/groups/GRP-1' },
  { method: 'POST',   urlPath: '/api/admin/groups/GRP-1/vessels', body: {} },
  { method: 'DELETE', urlPath: '/api/admin/groups/GRP-1/vessels/ABC' },
  { method: 'DELETE', urlPath: '/api/admin/groups/GRP-1' },
  { method: 'POST',   urlPath: '/api/admin/cognito-sync' },
];

// Read-only ("Bucket B") routes — must stay fully open to the client role, same as admin.
const READ_ROUTES = [
  '/api/certs',
  '/api/vapt/certs',
  '/api/admin/users',
  '/api/admin/groups',
  '/api/docs',
  '/api/vessels/names',
  '/api/stats',
];

test('client role — mutating routes 403, read routes 200, admin/legacy tokens unaffected', async () => {
  const port = 3521;
  const tenantId = `tenant_test_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  const child = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      BASE_ORIGIN: `http://127.0.0.1:${port}`,
      ADMIN_USER: 'admin_test',
      ADMIN_PASS: 'Admin@Test_123!',
      TENANT_ID: tenantId,
      LOG_LEVEL: 'silent',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    await waitForHealth(port);

    const keysPath = path.join(ROOT, 'data', tenantId, '.keys.json');
    const keys = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    const { jwtSecret } = keys;
    const sec = createSecurityService({ keys, cfg: {} });

    function mintToken(username, role) {
      if (role === undefined) {
        // True legacy shape: a token issued before the role claim existed at all
        // (not merely role:'admin') — hasAdminRole() must still treat a missing
        // role as admin. issueToken() always sets a role, so this constructs the
        // encrypted payload directly to omit the field entirely.
        const nowS = Math.floor(Date.now() / 1000);
        const payload = { sub: username, iat: nowS, exp: nowS + 8 * 60 * 60, jti: crypto.randomBytes(16).toString('hex') };
        const header = Buffer.from(JSON.stringify({ alg: 'A256GCM+HS256', typ: 'JWE' })).toString('base64url');
        const body = sec.encryptSessionPayload(payload);
        const sig = crypto.createHmac('sha256', jwtSecret).update(header + '.' + body).digest('base64url');
        return `${header}.${body}.${sig}`;
      }
      return sec.issueToken(username, role);
    }

    const adminToken  = mintToken('admin_test', 'admin');
    const clientToken = mintToken('client_test', 'client');
    const legacyToken = mintToken('admin_test'); // no role claim — every pre-existing token

    for (const route of MUTATING_ROUTES) {
      const asClient = await requestJson({ ...route, port, token: clientToken });
      assert.equal(asClient.status, 403, `client role must get 403 on ${route.method} ${route.urlPath}, got ${asClient.status}`);

      const asAdmin = await requestJson({ ...route, port, token: adminToken });
      assert.notEqual(asAdmin.status, 403, `admin role must not be blocked on ${route.method} ${route.urlPath}`);
      assert.notEqual(asAdmin.status, 401, `admin role must not be unauthorized on ${route.method} ${route.urlPath}`);

      const asLegacy = await requestJson({ ...route, port, token: legacyToken });
      assert.notEqual(asLegacy.status, 403, `legacy (no-role) token must not be blocked on ${route.method} ${route.urlPath}`);
      assert.notEqual(asLegacy.status, 401, `legacy (no-role) token must not be unauthorized on ${route.method} ${route.urlPath}`);
    }

    for (const urlPath of READ_ROUTES) {
      const asClient = await requestJson({ port, urlPath, token: clientToken });
      assert.equal(asClient.status, 200, `client role must have read access to ${urlPath}, got ${asClient.status}`);
    }
  } finally {
    child.kill();
  }
});
