'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..', '..');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');

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

test('server critical API flows', async () => {
  const port = 3421;
  const tenantId = `tenant_test_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  const child = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      BASE_ORIGIN: `http://127.0.0.1:${port}`,
      ADMIN_USER: 'admin_test',
      ADMIN_PASS: 'Admin@Test_123!',        // meets: 12+ chars, upper, lower, digit, special
      TENANT_ID: tenantId,
      LOG_LEVEL: 'silent',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    await waitForHealth(port);

    // ── Health endpoint: no cert counts exposed publicly ──────────────────
    const healthRes = await requestJson({ port, urlPath: '/api/health' });
    assert.equal(healthRes.status, 200);
    assert.ok(healthRes.json.ok);
    assert.ok(!('certs' in healthRes.json), 'health endpoint must not expose cert counts');

    // ── CORS: unknown origin must not be reflected ────────────────────────
    const corsCheck = await requestBinary({
      port,
      urlPath: '/api/health',
      headers: { Origin: 'https://evil.example.com' },
    });
    assert.ok(
      corsCheck.headers['access-control-allow-origin'] !== 'https://evil.example.com',
      'CORS must not reflect unknown origin',
    );

    // ── Auth: unauthenticated admin endpoint must return 401 ──────────────
    const unauth = await requestJson({ port, urlPath: '/api/certs' });
    assert.equal(unauth.status, 401, 'admin endpoint must require auth');

    // ── Auth: password login is decommissioned — admin panel is SSO-only now ──
    const deadLogin = await requestJson({
      method: 'POST',
      port,
      urlPath: '/api/auth/login',
      body: { username: 'admin_test', password: 'Admin@Test_123!' },
    });
    assert.equal(deadLogin.status, 410, 'password login must be decommissioned');

    // ── Input validation: cert ID with illegal character → 400 ───────────
    // sanitiseCertId rejects chars outside [A-Za-z0-9-_]
    const badId = await requestJson({ port, urlPath: '/api/verify-by-id/CERT!INVALID' });
    assert.equal(badId.status, 400, 'cert ID with illegal characters must return 400');

    // Path traversal resolves at URL layer (/../ → /etc/passwd → no route → 404)
    const traversal = await requestJson({ port, urlPath: '/api/verify-by-id/../../etc/passwd' });
    assert.equal(traversal.status, 404, 'path traversal attempt must not reach any data');

    // Admin login is SSO-only now (password login removed) — mint an admin JWT
    // directly using the spawned instance's own signing key, the same way
    // /auth/sso/callback does, rather than going through a browser-only Cognito
    // round-trip this test harness can't simulate.
    const keysPath = path.join(ROOT, 'data', tenantId, '.keys.json');
    const { jwtSecret, urlMacKey } = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    function mintAdminToken(username) {
      const nowS = Math.floor(Date.now() / 1000);
      const payload = { sub: username, iat: nowS, exp: nowS + 8 * 60 * 60, jti: crypto.randomBytes(16).toString('hex') };
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const sig = crypto.createHmac('sha256', jwtSecret).update(header + '.' + body).digest('base64url');
      return `${header}.${body}.${sig}`;
    }
    const token = mintAdminToken('admin_test');

    // ── Health detailed endpoint: filesystem + memory info present (admin-only) ──
    const healthDetailRes = await requestJson({ port, urlPath: '/api/health-detailed', token });
    assert.equal(healthDetailRes.status, 200);
    assert.ok(healthDetailRes.json.detailed, 'health-detailed must return detailed block');
    assert.ok(healthDetailRes.json.detailed.memory, 'detailed must include memory info');

    // CRUD create
    const certId = `CST-9999999-01-${String(Date.now() % 90 + 10)}`;
    const createRes = await requestJson({
      method: 'POST',
      port,
      urlPath: '/api/certs',
      token,
      body: {
        id: certId,
        recipientName: 'MV TEST',
        vesselName: 'MV TEST',
        vesselIMO: '9999999',
        chiefEngineer: 'TEST CHIEF',
        complianceDate: '2030-01-12',
        complianceQuarter: 'Q1',
        trainingMode: 'ONLINE',
        recipientEmail: 'recipient@example.com',
      },
    });
    assert.equal(createRes.status, 201);

    // Public verify endpoint for created cert
    const verify = await requestJson({ port, urlPath: `/api/verify-by-id/${certId}` });
    assert.equal(verify.status, 200);
    assert.ok(verify.json && verify.json.id === certId);

    // CRUD update
    const updateRes = await requestJson({
      method: 'PUT',
      port,
      urlPath: `/api/certs/${certId}`,
      token,
      body: { notes: 'updated-by-test' },
    });
    assert.equal(updateRes.status, 200);
    assert.equal(updateRes.json.notes, 'updated-by-test');

    // ── Reference documents (PDF attachments) are accepted and email-gated ──
    const dummyPdf = Buffer.from(
      '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n',
      'utf8'
    );

    const attachRes = await requestMultipart({
      method: 'PUT',
      port,
      urlPath: `/api/certs/${certId}`,
      token,
      files: [
        {
          fieldName: 'attachment0',
          filename: 'dummy.pdf',
          contentType: 'application/pdf',
          data: dummyPdf,
        },
      ],
    });
    assert.equal(attachRes.status, 200);
    assert.ok(attachRes.json && Array.isArray(attachRes.json.attachments));
    assert.equal(attachRes.json.attachments.length, 1, 'CST attachment should be stored');

    // ── Input validation: text field > 64 KB must be rejected ────────────
    const bigField = await requestMultipart({
      method: 'PUT',
      port,
      urlPath: `/api/certs/${certId}`,
      token,
      fields: { notes: 'x'.repeat(65 * 1024) },
    });
    assert.equal(bigField.status, 400, 'oversized text field must be rejected');

    const cstGate = await requestJson({
      method: 'POST',
      port,
      urlPath: `/api/verify-email/${certId}`,
      body: { email: 'recipient@example.com' },
    });
    assert.equal(cstGate.status, 200);
    assert.ok(cstGate.json.downloadToken);

    const cstDenied = await requestBinary({ port, urlPath: `/uploads/nonexistent.pdf` });
    assert.equal(cstDenied.status, 404);

    const vaptId = `VAP-PDF-TEST-${String(Date.now() % 900000 + 100000)}`;
    const vaptCreate = await requestJson({
      method: 'POST',
      port,
      urlPath: '/api/vapt/certs',
      token,
      body: {
        id: vaptId,
        recipientName: 'MV VAPT TEST',
        vesselName: 'MV VAPT TEST',
        vesselIMO: '1234567',
        assessmentDate: '2030-01-12',
        recipientEmail: 'vapt-recipient@example.com',
      },
    });
    assert.equal(vaptCreate.status, 201);

    const vaptAttachRes = await requestMultipart({
      method: 'PUT',
      port,
      urlPath: `/api/vapt/certs/${vaptId}`,
      token,
      files: [
        {
          fieldName: 'attachment0',
          filename: 'vapt_dummy.pdf',
          contentType: 'application/pdf',
          data: dummyPdf,
        },
      ],
    });
    assert.equal(vaptAttachRes.status, 200);
    assert.ok(vaptAttachRes.json && Array.isArray(vaptAttachRes.json.attachments));
    assert.equal(vaptAttachRes.json.attachments.length, 1, 'VAPT attachment should be stored');

    const vaptGate = await requestJson({
      method: 'POST',
      port,
      urlPath: `/api/vapt/verify-email/${vaptId}`,
      body: { email: 'vapt-recipient@example.com' },
    });
    assert.equal(vaptGate.status, 200);
    assert.ok(vaptGate.json.downloadToken);

    const vaptDenied = await requestBinary({ port, urlPath: `/uploads/nonexistent.pdf` });
    assert.equal(vaptDenied.status, 404);

    // Relevant document library flow: admin upload -> vessel request -> approval -> captain/supt access.
    const uniqueSuffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const captainEmail = `captain-${uniqueSuffix}@example.com`;
    const suptEmail = `supt-${uniqueSuffix}@example.com`;
    const dummyDocx = Buffer.from('PK\x03\x04 fake docx payload for integration test', 'binary');
    const trainingDoc = await requestMultipart({
      port,
      urlPath: '/api/docs/upload',
      token,
      fields: {
        vesselIMO: '9999999',
        vesselName: 'MV TEST',
        docType: 'TRAINING_REPORT',
        title: 'Q1 Training Record',
        linkedCertId: certId,
      },
      files: [{
        fieldName: 'file',
        filename: 'training-record.pdf',
        contentType: 'application/pdf',
        data: dummyPdf,
      }],
    });
    assert.equal(trainingDoc.status, 201);
    assert.equal(trainingDoc.json.docType, 'TRAINING_REPORT');

    const drillDoc = await requestMultipart({
      port,
      urlPath: '/api/docs/upload',
      token,
      fields: {
        vesselIMO: '9999999',
        vesselName: 'MV TEST',
        docType: 'DRILL_REPORT',
        title: 'Cyber Drill Record',
        linkedCertId: certId,
      },
      files: [{
        fieldName: 'file',
        filename: 'drill-record.docx',
        contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        data: dummyDocx,
      }],
    });
    assert.equal(drillDoc.status, 201);
    assert.equal(drillDoc.json.docType, 'DRILL_REPORT');

    const docReq = await requestJson({
      method: 'POST',
      port,
      urlPath: '/api/docs/request-access',
      body: {
        captainName: 'Test Captain',
        vesselName: 'MV TEST',
        vesselIMO: '9999999',
        emailId: captainEmail,
      },
    });
    assert.equal(docReq.status, 201);
    assert.ok(docReq.json.requestId);

    const approveDocReq = await requestJson({
      method: 'PUT',
      port,
      urlPath: `/api/docs/access-requests/${docReq.json.requestId}`,
      token,
      body: { status: 'APPROVED' },
    });
    assert.equal(approveDocReq.status, 200);
    assert.ok(approveDocReq.json.accessToken);

    const captainDocs = await requestJson({
      port,
      urlPath: '/api/docs/by-vessel/9999999',
      headers: { Authorization: `DocAccess ${approveDocReq.json.accessToken}` },
    });
    assert.equal(captainDocs.status, 200);
    assert.ok(captainDocs.json.some(d => d.id === trainingDoc.json.id && d.docType === 'TRAINING_REPORT'));
    assert.ok(captainDocs.json.some(d => d.id === drillDoc.json.id && d.docType === 'DRILL_REPORT'));
    assert.ok(captainDocs.json.some(d => d.id.startsWith('ATT_CST_') && d.docType === 'CERT_ATTACHMENT'));

    const captainPdf = await requestBinary({
      port,
      urlPath: `/api/docs/download/${trainingDoc.json.id}?docToken=${encodeURIComponent(approveDocReq.json.accessToken)}`,
    });
    assert.equal(captainPdf.status, 200);
    assert.equal(captainPdf.headers['content-type'], 'application/pdf');
    assert.match(captainPdf.headers['content-disposition'], /^inline;/);

    const captainWord = await requestBinary({
      port,
      urlPath: `/api/docs/download/${drillDoc.json.id}?docToken=${encodeURIComponent(approveDocReq.json.accessToken)}`,
    });
    assert.equal(captainWord.status, 200);
    assert.equal(captainWord.headers['content-type'], 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    assert.match(captainWord.headers['content-disposition'], /^attachment;/);

    const group = await requestJson({
      method: 'POST',
      port,
      urlPath: '/api/admin/groups',
      token,
      body: { name: 'Test Group', vesselIMOs: ['9999999'] },
    });
    assert.equal(group.status, 201);

    const user = await requestJson({
      method: 'POST',
      port,
      urlPath: '/api/admin/users',
      token,
      body: {
        name: 'Test Superintendent',
        email: suptEmail,
        groupIds: [group.json.id],
      },
    });
    assert.equal(user.status, 201);

    // Superintendent login is SSO-only now (password login removed) — mint a
    // UserSession token directly the same way the SSO callback does, using the
    // spawned instance's own signing key (already read above), rather than going
    // through a browser-only Cognito round-trip this test harness can't simulate.
    const sessionPayload = { kind: 'usersession', sub: user.json.id, iat: Date.now(), exp: Date.now() + 24 * 60 * 60 * 1000 };
    const sessionB64 = Buffer.from(JSON.stringify(sessionPayload)).toString('base64url');
    const sessionSig = crypto.createHmac('sha256', urlMacKey).update(sessionB64).digest('base64url');
    const userSession = `${sessionB64}.${sessionSig}`;

    const suptVessels = await requestJson({
      port,
      urlPath: '/api/supt/vessels',
      headers: { Authorization: `UserSession ${userSession}` },
    });
    assert.equal(suptVessels.status, 200);
    const suptVessel = suptVessels.json.find(v => v.imo === '9999999');
    assert.ok(suptVessel);
    assert.ok(suptVessel.docCount >= 3);

    const suptDocs = await requestJson({
      port,
      urlPath: '/api/docs/by-vessel/9999999',
      headers: { Authorization: `UserSession ${userSession}` },
    });
    assert.equal(suptDocs.status, 200);
    assert.ok(suptDocs.json.some(d => d.id === trainingDoc.json.id));
    assert.ok(suptDocs.json.some(d => d.id === drillDoc.json.id));

    const suptWord = await requestBinary({
      port,
      urlPath: `/api/docs/download/${drillDoc.json.id}?userSession=${encodeURIComponent(userSession)}`,
    });
    assert.equal(suptWord.status, 200);
    assert.equal(suptWord.headers['content-type'], 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');

    // CSV import
    const importRes = await requestJson({
      method: 'POST',
      port,
      urlPath: '/api/import-csv',
      token,
      body: [
        { id: 'CST-8888888-01-30', vesselIMO: '8888888', vesselName: 'MV CSV-1' },
      ],
    });
    assert.equal(importRes.status, 200);
    assert.ok(importRes.json && importRes.json.added >= 0);

    // Email dispatch (when SES not configured => 503 is valid expected behavior)
    const emailRes = await requestJson({
      method: 'POST',
      port,
      urlPath: `/api/certs/${certId}/send-email`,
      token,
      body: {},
    });
    assert.ok(emailRes.status === 200 || emailRes.status === 503 || emailRes.status === 500);

    // Delete created cert
    const deleteRes = await requestJson({
      method: 'DELETE',
      port,
      urlPath: `/api/certs/${certId}`,
      token,
    });
    assert.equal(deleteRes.status, 200);

    const vaptDeleteRes = await requestJson({
      method: 'DELETE',
      port,
      urlPath: `/api/vapt/certs/${vaptId}`,
      token,
    });
    assert.equal(vaptDeleteRes.status, 200);
  } finally {
    child.kill('SIGTERM');
    for (const dir of [path.join(ROOT, 'data', tenantId), path.join(ROOT, 'uploads', tenantId)]) {
      if (dir.startsWith(ROOT + path.sep)) fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});
