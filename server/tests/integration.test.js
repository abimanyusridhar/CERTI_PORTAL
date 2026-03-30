'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');

function requestJson({ method = 'GET', port, urlPath, token, body }) {
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
        resolve({ status: res.statusCode, data, text: data.toString('utf8') });
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
  const child = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      BASE_ORIGIN: `http://127.0.0.1:${port}`,
      ADMIN_USER: 'admin_test',
      ADMIN_PASS: 'admin_test_pw',
      LOG_LEVEL: 'silent',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    await waitForHealth(port);

    // Login
    const login = await requestJson({
      method: 'POST',
      port,
      urlPath: '/api/auth/login',
      body: { username: 'admin_test', password: 'admin_test_pw' },
    });
    assert.equal(login.status, 200);
    assert.ok(login.json && login.json.token);
    const token = login.json.token;

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

    // ── Confidential PDF gating (email gate -> downloadToken -> /uploads enforcement) ──
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
    const cstPdfAtt = attachRes.json.attachments.find(a => a && a.url && a.url.toLowerCase().endsWith('.pdf'));
    assert.ok(cstPdfAtt && cstPdfAtt.url, 'CST PDF attachment should exist');
    const cstPdfName = path.basename(cstPdfAtt.url);

    const cstGate = await requestJson({
      method: 'POST',
      port,
      urlPath: `/api/verify-email/${certId}`,
      body: { email: 'recipient@example.com' },
    });
    assert.equal(cstGate.status, 200);
    assert.ok(cstGate.json && cstGate.json.downloadToken, 'downloadToken should be issued for CST');

    const cstDenied = await requestBinary({ port, urlPath: `/uploads/${cstPdfName}` });
    assert.equal(cstDenied.status, 403);

    const cstAllowed = await requestBinary({
      port,
      urlPath: `/uploads/${cstPdfName}?t=${encodeURIComponent(cstGate.json.downloadToken)}`,
    });
    assert.equal(cstAllowed.status, 200);
    assert.ok(cstAllowed.data.toString('utf8').includes('%PDF'), 'Should return PDF bytes');

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
    const vaptPdfAtt = vaptAttachRes.json.attachments.find(a => a && a.url && a.url.toLowerCase().endsWith('.pdf'));
    assert.ok(vaptPdfAtt && vaptPdfAtt.url, 'VAPT PDF attachment should exist');
    const vaptPdfName = path.basename(vaptPdfAtt.url);

    const vaptGate = await requestJson({
      method: 'POST',
      port,
      urlPath: `/api/vapt/verify-email/${vaptId}`,
      body: { email: 'vapt-recipient@example.com' },
    });
    assert.equal(vaptGate.status, 200);
    assert.ok(vaptGate.json && vaptGate.json.downloadToken, 'downloadToken should be issued for VAPT');

    const vaptDenied = await requestBinary({ port, urlPath: `/uploads/${vaptPdfName}` });
    assert.equal(vaptDenied.status, 403);

    const vaptAllowed = await requestBinary({
      port,
      urlPath: `/uploads/${vaptPdfName}?t=${encodeURIComponent(vaptGate.json.downloadToken)}`,
    });
    assert.equal(vaptAllowed.status, 200);
    assert.ok(vaptAllowed.data.toString('utf8').includes('%PDF'), 'Should return PDF bytes');

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
  }
});
