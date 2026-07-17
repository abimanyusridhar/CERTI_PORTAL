'use strict';

const test = require('node:test');
const { before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..', '..');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');
const PORT = 3423;

// ── Boilerplate copied verbatim from server/tests/integration.test.js ──────

function requestJson({ method = 'GET', port, urlPath, token, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: urlPath,
      method,
      headers: {
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
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

function requestBinary({ method = 'GET', port, urlPath, token, headers = {}, bodyBuffer } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: urlPath,
      method,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
        ...(bodyBuffer ? { 'Content-Length': bodyBuffer.length } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        const data = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, data, text: data.toString('utf8') });
      });
    });
    req.on('error', reject);
    if (bodyBuffer) req.write(bodyBuffer);
    req.end();
  });
}

function requestMultipart({ method = 'POST', port, urlPath, token, fields = {}, files = [] } = {}) {
  return new Promise((resolve, reject) => {
    const boundary = '----itBoundary' + Math.random().toString(16).slice(2);
    const parts = [];

    for (const [k, v] of Object.entries(fields)) {
      parts.push(Buffer.from(`--${boundary}\r\n`));
      parts.push(Buffer.from(`Content-Disposition: form-data; name="${k}"\r\n\r\n`));
      parts.push(Buffer.from(String(v)));
      parts.push(Buffer.from('\r\n'));
    }

    for (const f of files) {
      const {
        fieldName,
        filename,
        contentType = 'application/octet-stream',
        data,
      } = f;
      parts.push(Buffer.from(`--${boundary}\r\n`));
      parts.push(Buffer.from(`Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n`));
      parts.push(Buffer.from(`Content-Type: ${contentType}\r\n\r\n`));
      parts.push(data);
      parts.push(Buffer.from('\r\n'));
    }

    parts.push(Buffer.from(`--${boundary}--\r\n`));
    const body = Buffer.concat(parts);

    const req = http.request({
      host: '127.0.0.1',
      port,
      path: urlPath,
      method,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': body.length,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        const text = buf.toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { /* ignore */ }
        resolve({ status: res.statusCode, json, text, data: buf });
      });
    });
    req.on('error', reject);
    req.write(body);
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

// ── Suite-wide fixtures: one spawned server instance shared by every test ──

let child;
let tenantId;
let jwtSecret;
let urlMacKey;
let adminToken;

function mintAdminToken(username) {
  const nowS = Math.floor(Date.now() / 1000);
  const payload = { sub: username, iat: nowS, exp: nowS + 8 * 60 * 60, jti: crypto.randomBytes(16).toString('hex') };
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', jwtSecret).update(header + '.' + body).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function mintUserSession(userId) {
  const sessionPayload = { kind: 'usersession', sub: userId, iat: Date.now(), exp: Date.now() + 24 * 60 * 60 * 1000 };
  const sessionB64 = Buffer.from(JSON.stringify(sessionPayload)).toString('base64url');
  const sessionSig = crypto.createHmac('sha256', urlMacKey).update(sessionB64).digest('base64url');
  return `${sessionB64}.${sessionSig}`;
}

// Mirrors issueDocClaimToken() at server/index.js:1062
function mintDocClaimToken(reqId) {
  const b64 = Buffer.from(JSON.stringify({ kind: 'docclaim', reqId, iat: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', urlMacKey).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}

function tamperToken(token) {
  // Flip the last character so the HMAC signature no longer verifies, keeping length identical.
  const last = token.slice(-1);
  const replacement = last === 'A' ? 'B' : 'A';
  return token.slice(0, -1) + replacement;
}

before(async () => {
  tenantId = `tenant_test_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  child = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      BASE_ORIGIN: `http://127.0.0.1:${PORT}`,
      ADMIN_USER: 'admin_test',
      ADMIN_PASS: 'Admin@Test_123!',
      TENANT_ID: tenantId,
      LOG_LEVEL: 'silent',
      // This machine's repo-root .env carries real Cognito/AWS credentials for
      // local dev use. server/config/env.js's loadDotEnv() only fills in a key
      // when it is `undefined` in process.env, so an explicit empty string here
      // wins over whatever is on disk and keeps the "Cognito/AWS not configured"
      // assertions below deterministic regardless of the host machine's .env.
      COGNITO_USER_POOL_ID: '',
      COGNITO_CLIENT_ID: '',
      COGNITO_CLIENT_SECRET: '',
      COGNITO_DOMAIN: '',
      COGNITO_ACCESS_KEY_ID: '',
      COGNITO_SECRET_ACCESS_KEY: '',
      AWS_ACCESS_KEY_ID: '',
      AWS_SECRET_ACCESS_KEY: '',
      AWS_SES_ACCESS_KEY: '',
      AWS_SES_SECRET_KEY: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitForHealth(PORT);

  const keysPath = path.join(ROOT, 'data', tenantId, '.keys.json');
  ({ jwtSecret, urlMacKey } = JSON.parse(fs.readFileSync(keysPath, 'utf8')));
  adminToken = mintAdminToken('admin_test');
});

after(() => {
  if (child) child.kill('SIGTERM');
  for (const dir of [path.join(ROOT, 'data', tenantId), path.join(ROOT, 'uploads', tenantId)]) {
    if (dir.startsWith(ROOT + path.sep)) fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── 1. GET /api/stats — public ──────────────────────────────────────────────

test('GET /api/stats is public and returns aggregate cert counts', async () => {
  const res = await requestJson({ port: PORT, urlPath: '/api/stats' });
  assert.equal(res.status, 200, 'stats must be public, no token supplied');
  for (const key of ['total', 'valid', 'expired', 'pending', 'revoked', 'lastIssued']) {
    assert.ok(key in res.json, `stats response must include ${key}`);
  }
});

// ── 2. GET /api/stats/quarterly — admin ─────────────────────────────────────

test('GET /api/stats/quarterly requires admin and returns per-quarter breakdown', async () => {
  const unauth = await requestJson({ port: PORT, urlPath: '/api/stats/quarterly?year=2030' });
  assert.equal(unauth.status, 401);

  const res = await requestJson({ port: PORT, urlPath: '/api/stats/quarterly?year=2030', token: adminToken });
  assert.equal(res.status, 200);
  assert.equal(res.json.year, 2030);
  for (const q of ['Q1', 'Q2', 'Q3', 'Q4']) {
    assert.ok(res.json.quarters[q], `quarters must include ${q}`);
    for (const key of ['total', 'valid', 'expired', 'pending', 'revoked']) {
      assert.ok(key in res.json.quarters[q], `${q} must include ${key}`);
    }
  }
});

// ── 3. GET /api/vapt/stats — public ─────────────────────────────────────────

test('GET /api/vapt/stats is public and returns aggregate VAPT counts', async () => {
  const res = await requestJson({ port: PORT, urlPath: '/api/vapt/stats' });
  assert.equal(res.status, 200, 'vapt stats must be public, no token supplied');
  for (const key of ['total', 'valid', 'expired', 'pending', 'revoked', 'lastIssued']) {
    assert.ok(key in res.json, `vapt stats response must include ${key}`);
  }
});

// ── 4. GET /api/vapt/stats/quarterly — admin ────────────────────────────────

test('GET /api/vapt/stats/quarterly requires admin and returns per-quarter breakdown', async () => {
  const unauth = await requestJson({ port: PORT, urlPath: '/api/vapt/stats/quarterly?year=2030' });
  assert.equal(unauth.status, 401);

  const res = await requestJson({ port: PORT, urlPath: '/api/vapt/stats/quarterly?year=2030', token: adminToken });
  assert.equal(res.status, 200);
  assert.equal(res.json.year, 2030);
  for (const q of ['Q1', 'Q2', 'Q3', 'Q4']) {
    assert.ok(res.json.quarters[q], `quarters must include ${q}`);
    for (const key of ['total', 'valid', 'expired', 'pending', 'revoked']) {
      assert.ok(key in res.json.quarters[q], `${q} must include ${key}`);
    }
  }
});

// ── 5. GET /api/cognito-status — admin ──────────────────────────────────────

test('GET /api/cognito-status requires admin and reports unconfigured Cognito', async () => {
  const unauth = await requestJson({ port: PORT, urlPath: '/api/cognito-status' });
  assert.equal(unauth.status, 401);

  const res = await requestJson({ port: PORT, urlPath: '/api/cognito-status', token: adminToken });
  assert.equal(res.status, 200);
  assert.equal(res.json.configured, false, 'no Cognito env vars set in test env');
  assert.ok(Array.isArray(res.json.missing) && res.json.missing.length > 0);
  assert.ok('ssoEnabled' in res.json);
  assert.ok('syncEnabled' in res.json);
});

// ── 6. GET /api/s3-status — admin ───────────────────────────────────────────

test('GET /api/s3-status requires admin and reports S3 disabled', async () => {
  const unauth = await requestJson({ port: PORT, urlPath: '/api/s3-status' });
  assert.equal(unauth.status, 401);

  const res = await requestJson({ port: PORT, urlPath: '/api/s3-status', token: adminToken });
  assert.equal(res.status, 200);
  assert.equal(res.json.enabled, false, 'no S3 env vars set in test env');
  assert.ok(Array.isArray(res.json.missing));
});

// ── 7. GET /api/ses-status — admin ──────────────────────────────────────────

test('GET /api/ses-status requires admin and returns email config shape', async () => {
  const unauth = await requestJson({ port: PORT, urlPath: '/api/ses-status' });
  assert.equal(unauth.status, 401);

  const res = await requestJson({ port: PORT, urlPath: '/api/ses-status', token: adminToken });
  assert.equal(res.status, 200);
  for (const key of ['enabled', 'region', 'fromCSTSet', 'fromVAPTSet', 'missing']) {
    assert.ok(key in res.json, `ses-status must include ${key}`);
  }
  assert.equal(res.json.enabled, false, 'AWS creds are zeroed out in the spawn env for this test');
  assert.equal(typeof res.json.fromCSTSet, 'boolean', 'must report presence only, never the raw sender address');
  assert.equal(typeof res.json.fromVAPTSet, 'boolean', 'must report presence only, never the raw sender address');
  assert.ok(Array.isArray(res.json.missing));
});

// ── 8. GET /api/vessels/names — admin ───────────────────────────────────────

test('GET /api/vessels/names requires admin and maps IMO to vessel name', async () => {
  const unauth = await requestJson({ port: PORT, urlPath: '/api/vessels/names' });
  assert.equal(unauth.status, 401);

  const certId = `CST-9988776-01-${String(Date.now() % 90 + 10)}`;
  const createRes = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/certs',
    token: adminToken,
    body: {
      id: certId,
      recipientName: 'MV VESSEL NAMES TEST',
      vesselName: 'MV VESSEL NAMES TEST',
      vesselIMO: '9988776',
      chiefEngineer: 'TEST CHIEF',
      complianceDate: '2030-01-12',
      complianceQuarter: 'Q1',
      trainingMode: 'ONLINE',
      recipientEmail: 'recipient@example.com',
    },
  });
  assert.equal(createRes.status, 201);

  try {
    const res = await requestJson({ port: PORT, urlPath: '/api/vessels/names', token: adminToken });
    assert.equal(res.status, 200);
    assert.equal(res.json['9988776'], 'MV VESSEL NAMES TEST');
  } finally {
    await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/certs/${certId}`, token: adminToken });
  }
});

// ── 9. POST /api/admin/cognito-sync — admin ─────────────────────────────────

test('POST /api/admin/cognito-sync requires admin and 503s when Cognito unconfigured', async () => {
  const unauth = await requestJson({ method: 'POST', port: PORT, urlPath: '/api/admin/cognito-sync' });
  assert.equal(unauth.status, 401);

  const res = await requestJson({ method: 'POST', port: PORT, urlPath: '/api/admin/cognito-sync', token: adminToken });
  assert.equal(res.status, 503, 'Cognito is not configured in the test env');
  // server/index.js:3759 — checks COGNITO_ENABLED before IAM creds, so this is the message we expect
  assert.equal(res.json.error, 'Cognito not configured.');
});

// ── 10. Decommissioned superadmin + auth/user routes ────────────────────────

test('superadmin login/verify routes are decommissioned (410)', async () => {
  const login = await requestJson({ method: 'POST', port: PORT, urlPath: '/api/superadmin/login', body: { username: 'x', password: 'y' } });
  assert.equal(login.status, 410);

  const verify = await requestJson({ port: PORT, urlPath: '/api/superadmin/verify' });
  assert.equal(verify.status, 410);
});

test('auth/user login is decommissioned; logout clears cookie; me requires a valid session', async () => {
  const login = await requestJson({ method: 'POST', port: PORT, urlPath: '/api/auth/user/login', body: { email: 'x@example.com', password: 'y' } });
  assert.equal(login.status, 410);

  const logout = await requestJson({ method: 'POST', port: PORT, urlPath: '/api/auth/user/logout' });
  assert.equal(logout.status, 200);
  assert.deepEqual(logout.json, { ok: true });

  const logoutBin = await requestBinary({ method: 'POST', port: PORT, urlPath: '/api/auth/user/logout' });
  assert.equal(logoutBin.status, 200);
  const setCookie = logoutBin.headers['set-cookie'];
  const cookieStr = Array.isArray(setCookie) ? setCookie.join(';') : (setCookie || '');
  assert.match(cookieStr, /suptSession=/);
  assert.match(cookieStr, /Max-Age=0/);

  const meUnauth = await requestJson({ port: PORT, urlPath: '/api/auth/user/me' });
  assert.equal(meUnauth.status, 401);

  const uniqueSuffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const suptEmail = `supt-status-${uniqueSuffix}@example.com`;
  const group = await requestJson({
    method: 'POST', port: PORT, urlPath: '/api/admin/groups', token: adminToken,
    body: { name: `Status Test Group ${uniqueSuffix}`, vesselIMOs: ['9988776'] },
  });
  assert.equal(group.status, 201);
  const user = await requestJson({
    method: 'POST', port: PORT, urlPath: '/api/admin/users', token: adminToken,
    body: { name: 'Status Test Superintendent', email: suptEmail, groupIds: [group.json.id] },
  });
  assert.equal(user.status, 201);

  const session = mintUserSession(user.json.id);
  const me = await requestJson({ port: PORT, urlPath: '/api/auth/user/me', headers: { Authorization: `UserSession ${session}` } });
  assert.equal(me.status, 200);
  assert.equal(me.json.user.id, user.json.id);
  assert.equal(me.json.user.email, suptEmail);
  assert.ok('name' in me.json.user && 'role' in me.json.user && 'groups' in me.json.user);
  assert.deepEqual(me.json.vessels, ['9988776']);
});

// ── 12. GET /api/docs/check-access — decommissioned workflow ───────────────

test('GET /api/docs/check-access reports the decommissioned captain workflow', async () => {
  const res = await requestJson({ port: PORT, urlPath: '/api/docs/check-access' });
  assert.equal(res.status, 200);
  assert.equal(res.json.valid, false);
  assert.match(res.json.message, /decommission/i);
});

// ── 13. docs temp-link + open token round trip ──────────────────────────────

test('docs temp-link + open token round trip serves the file publicly; bad tokens are rejected safely', async () => {
  const dummyPdf = Buffer.from(
    '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n',
    'utf8'
  );
  const upload = await requestMultipart({
    port: PORT,
    urlPath: '/api/docs/upload',
    token: adminToken,
    fields: {
      vesselIMO: '9988776',
      vesselName: 'MV VESSEL NAMES TEST',
      docType: 'TRAINING_REPORT',
      title: 'Temp Link Test Doc',
    },
    files: [{ fieldName: 'file', filename: 'templink.pdf', contentType: 'application/pdf', data: dummyPdf }],
  });
  assert.equal(upload.status, 201);
  const docId = upload.json.id;

  try {
    // Nonexistent doc → 404
    const missing = await requestJson({ port: PORT, urlPath: '/api/docs/temp-link/DOC-999999', token: adminToken });
    assert.equal(missing.status, 404);

    // No auth → 401
    const unauth = await requestJson({ port: PORT, urlPath: `/api/docs/temp-link/${docId}` });
    assert.equal(unauth.status, 401);

    const tempLink = await requestJson({ port: PORT, urlPath: `/api/docs/temp-link/${docId}`, token: adminToken });
    assert.equal(tempLink.status, 200);
    assert.ok(tempLink.json.url);
    assert.equal(tempLink.json.fileName, 'templink.pdf');
    assert.equal(tempLink.json.title, 'Temp Link Test Doc');

    const openPath = tempLink.json.url.replace(/^https?:\/\/[^/]+/, '');
    assert.match(openPath, /^\/api\/docs\/open\//);

    const opened = await requestBinary({ port: PORT, urlPath: openPath });
    assert.equal(opened.status, 200);
    assert.equal(opened.headers['content-type'], 'application/pdf');
    assert.match(opened.headers['content-disposition'], /templink\.pdf/);
    assert.ok(opened.data.length > 0);
    assert.ok(opened.data.toString('utf8').startsWith('%PDF-1.4'));

    // Garbage token → rejected, never 500
    const garbage = await requestJson({ port: PORT, urlPath: '/api/docs/open/garbage.token' });
    assert.ok([400, 403].includes(garbage.status), `expected 400/403 for garbage token, got ${garbage.status}`);
  } finally {
    await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/docs/${docId}`, token: adminToken });
  }
});

// ── 14. GET /api/docs/request-status — claim token verification ────────────

test('GET /api/docs/request-status validates the HMAC claim token', async () => {
  const reqId = `REQ-NONEXISTENT-${Date.now()}`;
  const claimToken = mintDocClaimToken(reqId);

  const notFound = await requestJson({
    port: PORT,
    urlPath: `/api/docs/request-status?reqId=${encodeURIComponent(reqId)}&claimToken=${encodeURIComponent(claimToken)}`,
  });
  assert.equal(notFound.status, 200);
  assert.deepEqual(notFound.json, { status: 'NOT_FOUND' });

  const tampered = tamperToken(claimToken);
  const invalid = await requestJson({
    port: PORT,
    urlPath: `/api/docs/request-status?reqId=${encodeURIComponent(reqId)}&claimToken=${encodeURIComponent(tampered)}`,
  });
  assert.equal(invalid.status, 403);
  assert.equal(invalid.json.error, 'Invalid claim');
});

// ── 15. PUT/DELETE /api/docs/:id lifecycle ──────────────────────────────────

test('PUT/DELETE /api/docs/:id enforce admin auth and correct lifecycle', async () => {
  const dummyPdf = Buffer.from(
    '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n',
    'utf8'
  );
  const upload = await requestMultipart({
    port: PORT,
    urlPath: '/api/docs/upload',
    token: adminToken,
    fields: {
      vesselIMO: '9988776',
      vesselName: 'MV VESSEL NAMES TEST',
      docType: 'TRAINING_REPORT',
      title: 'Lifecycle Test Doc',
    },
    files: [{ fieldName: 'file', filename: 'lifecycle.pdf', contentType: 'application/pdf', data: dummyPdf }],
  });
  assert.equal(upload.status, 201);
  const docId = upload.json.id;

  // PUT without token → 401
  const putUnauth = await requestJson({ method: 'PUT', port: PORT, urlPath: `/api/docs/${docId}`, body: { title: 'x' } });
  assert.equal(putUnauth.status, 401);

  // DELETE without token → 401
  const delUnauth = await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/docs/${docId}` });
  assert.equal(delUnauth.status, 401);

  const putRes = await requestJson({
    method: 'PUT', port: PORT, urlPath: `/api/docs/${docId}`, token: adminToken,
    body: { title: 'Updated Title', description: 'Updated description' },
  });
  assert.equal(putRes.status, 200);
  assert.equal(putRes.json.title, 'Updated Title');
  assert.equal(putRes.json.description, 'Updated description');

  const delRes = await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/docs/${docId}`, token: adminToken });
  assert.equal(delRes.status, 200);
  assert.deepEqual(delRes.json, { ok: true });

  // Second delete of same id → 404
  const delAgain = await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/docs/${docId}`, token: adminToken });
  assert.equal(delAgain.status, 404);
});
