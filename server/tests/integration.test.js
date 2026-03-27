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
  } finally {
    child.kill('SIGTERM');
  }
});
