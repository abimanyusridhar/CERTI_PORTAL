'use strict';

// Security/edge-case integration coverage for gaps flagged as "Manual candidate" /
// "Partially automated" in docs/testing-analysis-and-test-plan.md (rows API-003
// through API-007 and SEC-002). Spawns the real server on port 3424 — other
// integration files own 3421/3422/3423, so this port is reserved for this file.
//
// These tests assert CONFIRMED current server behavior read directly out of
// server/index.js. If actual behavior diverges from an assertion here, that is
// a real bug to report, not a reason to loosen the assertion.

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
const PORT = 3424;

// ─── Boilerplate copied verbatim from server/tests/integration.test.js ───────

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

// ─── Shared fixture: one spawned server instance for the whole file ─────────

const tenantId = `tenant_test_secedge_${Date.now()}_${Math.random().toString(16).slice(2)}`;
let child;
let adminToken;
let jwtSecret;
let urlMacKey;
let sec;

const dummyPdf = Buffer.from(
  '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n',
  'utf8'
);

function mintAdminToken(username) {
  return sec.issueToken(username, 'admin');
}

function mintUserSession(userId) {
  const sessionPayload = { kind: 'usersession', sub: userId, iat: Date.now(), exp: Date.now() + 24 * 60 * 60 * 1000 };
  const sessionB64 = Buffer.from(JSON.stringify(sessionPayload)).toString('base64url');
  const sessionSig = crypto.createHmac('sha256', urlMacKey).update(sessionB64).digest('base64url');
  return `${sessionB64}.${sessionSig}`;
}

test.before(async () => {
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
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitForHealth(PORT);

  const keysPath = path.join(ROOT, 'data', tenantId, '.keys.json');
  const keys = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  jwtSecret = keys.jwtSecret;
  urlMacKey = keys.urlMacKey;
  sec = createSecurityService({ keys, cfg: {} });
  adminToken = mintAdminToken('admin_test');
});

test.after(() => {
  if (child) child.kill('SIGTERM');
  for (const dir of [path.join(ROOT, 'data', tenantId), path.join(ROOT, 'uploads', tenantId)]) {
    if (dir.startsWith(ROOT + path.sep)) fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ─── API-003: duplicate certificate ID rejected with 409 ────────────────────

test('SEC-003: cookie-authenticated admin mutations reject hostile Origin', async () => {
  const forged = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/admin/users',
    headers: {
      Cookie: `adminToken=${adminToken}`,
      Origin: 'https://attacker.example',
    },
    body: {
      name: 'CSRF Blocked User',
      email: 'csrf-blocked@example.com',
    },
  });

  assert.equal(forged.status, 403);
  assert.equal(forged.json.error, 'Cross-site request blocked.');

  const users = await requestJson({ port: PORT, urlPath: '/api/admin/users', token: adminToken });
  assert.equal(users.status, 200);
  assert.equal(
    users.json.some(u => u.email === 'csrf-blocked@example.com'),
    false,
    'blocked cross-site request must not create a user'
  );
});

test('API-003: duplicate CST certificate ID is rejected with 409 and original data is preserved', async () => {
  const certId = `CST-DUPTEST-${String(Date.now() % 900000 + 100000)}`;
  // NOTE: recipientName is intentionally given an existing "MV - " prefix here.
  // server/index.js deriveQuarterFields() (~line 2026) unconditionally rewrites
  // recipientName to "<MV|MT> - <vessel>" whenever it doesn't already match that
  // pattern (e.g. if it were left equal to vesselName) — that's pre-existing,
  // unrelated business logic for auto-formatting display names, not a duplicate-
  // POST bug, so the fixture avoids tripping it to keep this test's signal clean.
  const original = {
    id: certId,
    recipientName: 'MV - Original Recipient',
    vesselName: 'MV Dup Original Vessel',
    vesselIMO: '4444401',
    chiefEngineer: 'ORIGINAL CHIEF',
    complianceDate: '2030-01-12',
    complianceQuarter: 'Q1',
    trainingMode: 'ONLINE',
    recipientEmail: 'original@example.com',
  };
  try {
    const first = await requestJson({ method: 'POST', port: PORT, urlPath: '/api/certs', token: adminToken, body: original });
    assert.equal(first.status, 201, 'first creation should succeed');

    const dup = await requestJson({
      method: 'POST',
      port: PORT,
      urlPath: '/api/certs',
      token: adminToken,
      body: { ...original, recipientName: 'MV - Attacker Recipient', chiefEngineer: 'ATTACKER CHIEF' },
    });
    assert.equal(dup.status, 409, 'duplicate cert ID must be rejected with 409');
    assert.equal(dup.json.error, 'Certificate ID already exists');

    const after = await requestJson({ port: PORT, urlPath: `/api/certs/${certId}`, token: adminToken });
    assert.equal(after.status, 200);
    assert.equal(after.json.recipientName, 'MV - Original Recipient', 'original data must survive a rejected duplicate POST');
    assert.equal(after.json.chiefEngineer, 'ORIGINAL CHIEF');
  } finally {
    await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/certs/${certId}`, token: adminToken });
  }
});

test('API-003: duplicate VAPT certificate ID is rejected with 409 and original data is preserved', async () => {
  const vaptId = `VAP-DUPTEST-${String(Date.now() % 900000 + 100000)}`;
  const original = {
    id: vaptId,
    recipientName: 'MV VAPT DUP ORIGINAL',
    vesselName: 'MV VAPT DUP ORIGINAL',
    vesselIMO: '4444402',
    assessmentDate: '2030-01-12',
    recipientEmail: 'vapt-original@example.com',
  };
  try {
    const first = await requestJson({ method: 'POST', port: PORT, urlPath: '/api/vapt/certs', token: adminToken, body: original });
    assert.equal(first.status, 201, 'first VAPT creation should succeed');

    const dup = await requestJson({
      method: 'POST',
      port: PORT,
      urlPath: '/api/vapt/certs',
      token: adminToken,
      body: { ...original, recipientName: 'MV VAPT DUP ATTACKER' },
    });
    assert.equal(dup.status, 409, 'duplicate VAPT cert ID must be rejected with 409');
    assert.equal(dup.json.error, 'Certificate ID already exists');

    const after = await requestJson({ port: PORT, urlPath: `/api/vapt/certs/${vaptId}`, token: adminToken });
    assert.equal(after.status, 200);
    assert.equal(after.json.recipientName, 'MV VAPT DUP ORIGINAL', 'original VAPT data must survive a rejected duplicate POST');
  } finally {
    await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/vapt/certs/${vaptId}`, token: adminToken });
  }
});

// ─── API-004/005: SQLi- and XSS-shaped payloads in cert fields ──────────────

test('DATA-001: PUT /api/certs/:id normalizes vesselIMO the same way POST does (CST)', async () => {
  const certId = `CST-IMOEDIT-${String(Date.now() % 900000 + 100000)}`;
  try {
    const created = await requestJson({
      method: 'POST', port: PORT, urlPath: '/api/certs', token: adminToken,
      body: { id: certId, recipientName: 'MV - Imo Edit', vesselName: 'Imo Edit Vessel', vesselIMO: '5551001', complianceDate: '2030-01-12', complianceQuarter: 'Q1' },
    });
    assert.equal(created.status, 201);

    // A dirty edit input (mixed case, stray space, non-alphanumeric separator) must
    // land normalized — previously sanitiseCertBody() only trimmed/length-capped
    // vesselIMO on PUT, unlike POST, silently orphaning the cert from group-based
    // vessel access and the /api/supt/vessel/:imo/certs filter.
    const edited = await requestJson({
      method: 'PUT', port: PORT, urlPath: `/api/certs/${certId}`, token: adminToken,
      body: { vesselIMO: ' 5551-002 ' },
    });
    assert.equal(edited.status, 200);
    assert.equal(edited.json.vesselIMO, '5551002', 'PUT must normalize vesselIMO exactly like POST does');
  } finally {
    await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/certs/${certId}`, token: adminToken });
  }
});

test('DATA-001: PUT /api/vapt/certs/:id normalizes vesselIMO the same way POST does (VAPT)', async () => {
  const vaptId = `VAP-IMOEDIT-${String(Date.now() % 900000 + 100000)}`;
  try {
    const created = await requestJson({
      method: 'POST', port: PORT, urlPath: '/api/vapt/certs', token: adminToken,
      body: { id: vaptId, recipientName: 'Imo Edit Vessel', vesselName: 'Imo Edit Vessel', vesselIMO: '5552001', assessmentDate: '2030-01-12' },
    });
    assert.equal(created.status, 201);

    const edited = await requestJson({
      method: 'PUT', port: PORT, urlPath: `/api/vapt/certs/${vaptId}`, token: adminToken,
      body: { vesselIMO: ' 5552-002 ' },
    });
    assert.equal(edited.status, 200);
    assert.equal(edited.json.vesselIMO, '5552002', 'PUT must normalize vesselIMO exactly like POST does');
  } finally {
    await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/vapt/certs/${vaptId}`, token: adminToken });
  }
});

test('API-004/005: SQLi- and XSS-shaped field values are stored and returned verbatim by the API', async () => {
  const certId = `CST-XSSTEST-${String(Date.now() % 900000 + 100000)}`;
  const sqliName = "Robert'); DROP TABLE certs;--";
  const xssNotes = '<script>alert(1)</script>';
  const xssVessel = '<img src=x onerror=alert(1)>';
  // recipientName is prefixed with "MV - " for the same reason documented in the
  // duplicate-ID test above: deriveQuarterFields() would otherwise silently
  // rewrite an un-prefixed recipientName using the vesselName, which would mask
  // (not expose) the SQLi-shaped string we're trying to observe round-trip.
  const sqliRecipientName = 'MV - ' + sqliName;
  try {
    const create = await requestJson({
      method: 'POST',
      port: PORT,
      urlPath: '/api/certs',
      token: adminToken,
      body: {
        id: certId,
        recipientName: sqliRecipientName,
        vesselName: xssVessel,
        vesselIMO: '4444403',
        chiefEngineer: 'TEST CHIEF',
        complianceDate: '2030-01-12',
        complianceQuarter: 'Q1',
        trainingMode: 'ONLINE',
        notes: xssNotes,
      },
    });
    // No SQL engine in this app (JSON-file store) — there is no SQL injection
    // surface. Confirm creation just succeeds as ordinary string data.
    assert.equal(create.status, 201, 'creation with SQLi/XSS-shaped strings must succeed like any other string payload');

    const verify = await requestJson({ port: PORT, urlPath: `/api/verify-by-id/${certId}` });
    assert.equal(verify.status, 200);
    // FINDING (informational, not itself a vulnerability): certPublicFields()
    // (server/index.js ~line 1746) and sanitiseCertBody() (~line 1835) never
    // HTML-escape field values — they only strip control characters and
    // truncate length. The public /api/verify-by-id JSON response therefore
    // returns these fields byte-for-byte, including raw `<script>` markup.
    // A JSON API response is not itself executed as HTML, so this is not an
    // XSS vulnerability at the API layer — but any frontend code that renders
    // these fields via innerHTML (rather than textContent/escaping) would be
    // vulnerable to stored XSS. This test documents current API-side behavior;
    // it does not audit the frontend renderer.
    assert.equal(verify.json.recipientName, sqliRecipientName, 'recipientName must come back unescaped/unmodified (documents no output-encoding at API layer)');
    assert.equal(verify.json.notes, xssNotes, 'notes must come back unescaped/unmodified (documents no output-encoding at API layer)');
    assert.equal(verify.json.vesselName, xssVessel, 'vesselName must come back unescaped/unmodified (documents no output-encoding at API layer)');
  } finally {
    await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/certs/${certId}`, token: adminToken });
  }
});

test('API-004: SQLi- and path-traversal-shaped certificate IDs are rejected safely, never 200 or 500', async () => {
  // Built as full, already-request-safe URL paths rather than raw ID strings:
  // Node's http client rejects raw control/space characters in a request path
  // (ERR_UNESCAPED_CHARACTERS) before the request is even sent, so the SQLi
  // variant's space/quote characters are percent-encoded the way a real browser
  // would encode them. The two traversal variants are left as literal strings
  // (one with raw dot-segments, one pre-percent-encoded) since both are valid,
  // unencoded-at-the-client HTTP path bytes.
  const variants = [
    { label: "SQLi-shaped ID with space/quote chars", urlPath: `/api/verify-by-id/${encodeURIComponent("1' OR '1'='1")}` },
    { label: 'literal ../ path traversal', urlPath: '/api/verify-by-id/../../../etc/passwd' },
    { label: 'percent-encoded ../ path traversal', urlPath: '/api/verify-by-id/%2e%2e%2f%2e%2e%2fetc%2fpasswd' },
  ];
  for (const { label, urlPath } of variants) {
    const res = await requestJson({ port: PORT, urlPath });
    assert.ok(
      res.status === 400 || res.status === 404,
      `expected 400 or 404 for ${label} ("${urlPath}"), got ${res.status}`
    );
    assert.notEqual(res.status, 200, `${label} must never return 200`);
    assert.notEqual(res.status, 500, `${label} must never crash the handler (500)`);
  }
});

// ─── API-006: oversized request body ─────────────────────────────────────────

test('API-006: oversized JSON request body is rejected or reset, and the server remains healthy afterward', async () => {
  const hugeNotes = 'x'.repeat(11 * 1024 * 1024); // 11 MB, above the 10 MB getBody() cap
  let outcome;
  try {
    outcome = await requestJson({
      method: 'POST',
      port: PORT,
      urlPath: '/api/certs',
      token: adminToken,
      body: {
        id: `CST-OVERSIZE-${String(Date.now() % 900000 + 100000)}`,
        recipientName: 'MV OVERSIZE',
        vesselName: 'MV OVERSIZE',
        vesselIMO: '4444404',
        chiefEngineer: 'TEST CHIEF',
        complianceDate: '2030-01-12',
        complianceQuarter: 'Q1',
        trainingMode: 'ONLINE',
        notes: hugeNotes,
      },
    });
  } catch (err) {
    outcome = { connectionError: err };
  }

  if (outcome.connectionError) {
    assert.ok(outcome.connectionError instanceof Error, 'oversized body may legitimately reset the connection instead of a clean HTTP response');
  } else {
    assert.equal(outcome.status, 400, 'oversized JSON body that does get a clean response must be rejected with 400');
  }

  // The important assertion: the server must have survived the oversized
  // request and still be healthy, proving getBody()'s 10MB cap (server/index.js
  // ~line 1944) protects the process rather than crashing/hanging it.
  const health = await requestJson({ port: PORT, urlPath: '/api/health' });
  assert.equal(health.status, 200, 'server must remain healthy after an oversized request');
  assert.ok(health.json && health.json.ok);
}, { timeout: 30000 });

test('API-006: oversized multipart text field is rejected on certificate CREATE (symmetry with UPDATE)', async () => {
  const bigField = await requestMultipart({
    method: 'POST',
    port: PORT,
    urlPath: '/api/certs',
    token: adminToken,
    fields: {
      id: `CST-OVERSIZEFIELD-${String(Date.now() % 900000 + 100000)}`,
      notes: 'x'.repeat(65 * 1024), // 65 KB, above parseMultipart's 64 KB per-field cap
    },
  });
  assert.equal(bigField.status, 400, 'oversized text field on cert CREATE must be rejected, mirroring the existing UPDATE coverage');
});

// ─── SEC-002: cross-vessel broken access control ─────────────────────────────

test('SEC-002: cross-vessel broken access control is enforced for superintendent sessions', async () => {
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const imoA = '1111111';
  const imoB = '2222222';
  // sanitiseCertId() uppercases every stored cert ID, so build these already
  // uppercase to keep exact-match assertions against stored records simple.
  const certIdA = `CST-SECA-${suffix}`.slice(0, 64).toUpperCase();
  const certIdB = `CST-SECB-${suffix}`.slice(0, 64).toUpperCase();
  let groupAId, groupBId, userAId, docIdA, docIdB;

  try {
    // Two groups, each scoped to a single vessel
    const groupA = await requestJson({
      method: 'POST', port: PORT, urlPath: '/api/admin/groups', token: adminToken,
      body: { name: `Group A ${suffix}`, vesselIMOs: [imoA] },
    });
    assert.equal(groupA.status, 201);
    groupAId = groupA.json.id;

    const groupB = await requestJson({
      method: 'POST', port: PORT, urlPath: '/api/admin/groups', token: adminToken,
      body: { name: `Group B ${suffix}`, vesselIMOs: [imoB] },
    });
    assert.equal(groupB.status, 201);
    groupBId = groupB.json.id;

    // Two users, each in only their own group
    const userA = await requestJson({
      method: 'POST', port: PORT, urlPath: '/api/admin/users', token: adminToken,
      body: { name: `User A ${suffix}`, email: `usera-${suffix}@example.com`, groupIds: [groupAId] },
    });
    assert.equal(userA.status, 201);
    userAId = userA.json.id;

    const userB = await requestJson({
      method: 'POST', port: PORT, urlPath: '/api/admin/users', token: adminToken,
      body: { name: `User B ${suffix}`, email: `userb-${suffix}@example.com`, groupIds: [groupBId] },
    });
    assert.equal(userB.status, 201);

    // One CST cert per vessel so both vessels have data. Created via /api/import-csv
    // (bucket 'default', much higher ceiling) rather than POST /api/certs: that
    // route shares the SAME 'upload' rate-limit bucket (server/index.js
    // checkRateLimit(ip, 'upload'), only 10 combined requests per 5 min per IP —
    // see finding notes at the end of this file) with POST /api/vapt/certs and
    // POST /api/docs/upload, and this test file's other cases already spend
    // most of that shared budget. Using import-csv here keeps this test's cert
    // fixtures from starving other tests' upload-bucket quota.
    const certImport = await requestJson({
      method: 'POST', port: PORT, urlPath: '/api/import-csv', token: adminToken,
      body: [
        { id: certIdA, vesselIMO: imoA, vesselName: 'MV SEC A', complianceDate: '2030-01-12', complianceQuarter: 'Q1' },
        { id: certIdB, vesselIMO: imoB, vesselName: 'MV SEC B', complianceDate: '2030-01-12', complianceQuarter: 'Q1' },
      ],
    });
    assert.equal(certImport.status, 200);
    assert.equal(certImport.json.added, 2, 'both fixture certs should import cleanly');

    // One training doc per vessel
    const docA = await requestMultipart({
      port: PORT, urlPath: '/api/docs/upload', token: adminToken,
      fields: { vesselIMO: imoA, vesselName: 'MV SEC A', docType: 'TRAINING_REPORT', title: 'Vessel A Training' },
      files: [{ fieldName: 'file', filename: 'a.pdf', contentType: 'application/pdf', data: dummyPdf }],
    });
    assert.equal(docA.status, 201);
    docIdA = docA.json.id;

    const docB = await requestMultipart({
      port: PORT, urlPath: '/api/docs/upload', token: adminToken,
      fields: { vesselIMO: imoB, vesselName: 'MV SEC B', docType: 'TRAINING_REPORT', title: 'Vessel B Training' },
      files: [{ fieldName: 'file', filename: 'b.pdf', contentType: 'application/pdf', data: dummyPdf }],
    });
    assert.equal(docB.status, 201);
    docIdB = docB.json.id;

    const sessionA = mintUserSession(userAId);
    const authHeaders = { Authorization: `UserSession ${sessionA}` };

    // GET /api/supt/vessels — must include own vessel, must NOT include the other vessel
    const vessels = await requestJson({ port: PORT, urlPath: '/api/supt/vessels', headers: authHeaders });
    assert.equal(vessels.status, 200);
    const imos = vessels.json.map(v => v.imo);
    assert.ok(imos.includes(imoA), 'own vessel must appear in supt/vessels');
    assert.ok(!imos.includes(imoB), 'CRITICAL: other group\'s vessel must NOT appear in supt/vessels');

    // GET /api/supt/vessel/:imo/certs — cross-vessel must be 403
    const crossCerts = await requestJson({ port: PORT, urlPath: `/api/supt/vessel/${imoB}/certs`, headers: authHeaders });
    assert.equal(crossCerts.status, 403, 'CRITICAL: cross-vessel cert access must be denied');
    assert.equal(crossCerts.json.error, 'Vessel not in your group.');

    // Positive case: own vessel certs must be reachable
    const ownCerts = await requestJson({ port: PORT, urlPath: `/api/supt/vessel/${imoA}/certs`, headers: authHeaders });
    assert.equal(ownCerts.status, 200, 'own vessel cert access must succeed');
    assert.ok(ownCerts.json.cst.some(c => c.id === certIdA));

    // GET /api/docs/by-vessel/:imo — cross-vessel must be 403
    const crossDocs = await requestJson({ port: PORT, urlPath: `/api/docs/by-vessel/${imoB}`, headers: authHeaders });
    assert.equal(crossDocs.status, 403, 'CRITICAL: cross-vessel document listing must be denied');

    // Positive case: own vessel docs must be reachable
    const ownDocs = await requestJson({ port: PORT, urlPath: `/api/docs/by-vessel/${imoA}`, headers: authHeaders });
    assert.equal(ownDocs.status, 200, 'own vessel document listing must succeed');
    assert.ok(ownDocs.json.some(d => d.id === docIdA));

    // GET /api/docs/download/:id for the OTHER vessel's doc, using a session token
    // (not an admin token, so the admin bypass in this handler does not apply)
    const crossDownload = await requestJson({ port: PORT, urlPath: `/api/docs/download/${docIdB}`, headers: authHeaders });
    assert.equal(crossDownload.status, 403, 'CRITICAL: cross-vessel document download must be denied');
    assert.equal(crossDownload.json.error, 'Access denied.');
  } finally {
    if (certIdA) await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/certs/${certIdA}`, token: adminToken });
    if (certIdB) await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/certs/${certIdB}`, token: adminToken });
    if (docIdA) await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/docs/${docIdA}`, token: adminToken });
    if (docIdB) await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/docs/${docIdB}`, token: adminToken });
    if (userAId) await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/admin/users/${userAId}`, token: adminToken });
    // userB id wasn't retained beyond creation-status assertions; look it up defensively is unnecessary
    // since the whole tenant data dir is wiped in test.after() regardless.
    if (groupAId) await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/admin/groups/${groupAId}`, token: adminToken });
    if (groupBId) await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/admin/groups/${groupBId}`, token: adminToken });
  }
});

// ─── API-007: rate limit burst ───────────────────────────────────────────────

test('API-007: burst of requests to /api/verify-by-id triggers 429 with Retry-After', async () => {
  const requests = [];
  for (let i = 0; i < 35; i++) {
    requests.push(requestBinary({ port: PORT, urlPath: '/api/verify-by-id/NONEXISTENT-RATE-LIMIT-TEST' }));
  }
  const results = await Promise.all(requests);
  const throttled = results.filter(r => r.status === 429);
  assert.ok(throttled.length > 0, 'the "verify" rate-limit bucket (30/min per server/index.js) must engage under a 35-request burst');
  assert.ok(throttled[0].headers['retry-after'], 'a 429 response must include a Retry-After header');
});

// ─── CSP report-only bake-in: POST /api/csp-report ───────────────────────────

test('CSP: enforcing header keeps unsafe-inline while a strict Report-Only header is also sent', async () => {
  const res = await requestBinary({ port: PORT, urlPath: '/CST' });
  assert.match(res.headers['content-security-policy'] || '', /script-src[^;]*'unsafe-inline'/,
    'enforcing CSP must be unchanged (still permissive) during the report-only bake-in');
  assert.match(res.headers['content-security-policy'] || '', /report-uri \/api\/csp-report/);
  const reportOnly = res.headers['content-security-policy-report-only'] || '';
  assert.ok(reportOnly, 'a Content-Security-Policy-Report-Only header must be present during bake-in');
  assert.doesNotMatch(reportOnly, /script-src[^;]*'unsafe-inline'/,
    'the report-only policy must be the strict (no unsafe-inline) target policy');
});

test('CSP: POST /api/csp-report accepts a legacy report-uri payload and responds 204', async () => {
  const res = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/csp-report',
    headers: { 'Content-Type': 'application/csp-report' },
    body: { 'csp-report': { 'document-uri': 'http://example.test/', 'violated-directive': 'script-src-elem', 'blocked-uri': 'inline' } },
  });
  assert.equal(res.status, 204);
});

test('CSP: POST /api/csp-report tolerates a malformed body without erroring', async () => {
  const res = await requestBinary({
    method: 'POST',
    port: PORT,
    urlPath: '/api/csp-report',
    headers: { 'Content-Type': 'application/csp-report' },
    bodyBuffer: Buffer.from('not json at all'),
  });
  assert.equal(res.status, 204, 'a malformed report body must be dropped silently, not surfaced as a server error');
});

test('CSP: POST /api/csp-report is exempt from the CSRF/cross-site-cookie checks', async () => {
  // A same-site request carrying the adminToken cookie but no X-CSRF-Token header
  // and no matching Origin — this would fail csrfCheckFails() for a normal mutating
  // route, but csp-report must be exempt (browsers send these with no CSRF header).
  const res = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/csp-report',
    headers: { Cookie: `adminToken=${adminToken}`, Origin: 'http://evil.test' },
    body: { 'csp-report': { 'document-uri': 'http://example.test/', 'violated-directive': 'style-src-elem', 'blocked-uri': 'inline' } },
  });
  assert.equal(res.status, 204, 'csp-report must not be blocked as a cross-site cookie mutation or CSRF failure');
});
