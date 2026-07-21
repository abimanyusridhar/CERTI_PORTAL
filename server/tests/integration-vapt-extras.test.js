'use strict';

// Extra integration coverage for routes NOT exercised by server/tests/integration.test.js:
//   - GET  /api/vapt/certs/:id            (admin single-cert fetch)
//   - GET  /api/vapt/verify-by-id/:id     (public, projected fields)
//   - GET  /api/public-cert-url/:id       + GET /api/cert-url/:id      (CST)
//   - GET  /api/vapt/public-cert-url/:id  + GET /api/vapt/cert-url/:id (VAPT)
//   - GET  /api/verify/:encToken?s=...      + GET /api/vapt/verify/:encToken?s=...
//   - POST /api/vapt/import-csv
//   - GET  /api/certs/:id/engagement       + GET /api/vapt/certs/:id/engagement
//   - POST /api/track-event
//   - GET  /api/track-open/:token          + GET /api/vapt/track-open/:token
//   - DELETE /api/certs/:id/attachments/:idx + DELETE /api/vapt/certs/:id/attachments/:idx
//
// Runs the real server on port 3422 (integration.test.js already owns 3421) so both
// files can run concurrently under `node --test`.

const test = require('node:test');
const { before, after } = test;
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { cleanupTenantS3Data, fetchTenantKeys } = require('./helpers/s3TestHelpers');

const ROOT = path.join(__dirname, '..', '..');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');
const PORT = 3422;

// ── boilerplate copied verbatim from integration.test.js ────────────────────

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
      if (res.status === 200 && res.json && res.json.ok && res.json.status === 'operational') return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('Server did not become healthy in time');
}

// ── shared fixture state (spawned once for the whole file) ──────────────────

let child;
let tenantId;
let jwtSecret;
let urlMacKey;
let token; // admin JWT

const dummyPdf = Buffer.from(
  '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n',
  'utf8'
);

let cstId;
let vaptId;

function mintAdminToken(username) {
  const nowS = Math.floor(Date.now() / 1000);
  const payload = { sub: username, iat: nowS, exp: nowS + 8 * 60 * 60, jti: crypto.randomBytes(16).toString('hex') };
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', jwtSecret).update(header + '.' + body).digest('base64url');
  return `${header}.${body}.${sig}`;
}

// Flips the first character of a base64url string to a different valid
// base64url character, keeping the same length (so length checks don't mask
// the tamper as a "wrong length" case rather than a genuine signature mismatch).
function tamperFirstChar(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const orig = s[0];
  let repl = alphabet[0];
  if (repl === orig) repl = alphabet[1];
  return repl + s.slice(1);
}

before(async () => {
  // NOTE: TENANT_ID must be <= 48 chars (server/index.js sanitiseTenantId) —
  // keep this prefix short so timestamp + random suffix never overflows that.
  tenantId = `tenant_vex_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`;
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

  ({ jwtSecret, urlMacKey } = await fetchTenantKeys(tenantId));
  token = mintAdminToken('admin_test');

  // Fixture certs shared read-only across most tests below.
  cstId = `CST-9999999-01-${String(Date.now() % 90 + 10)}`;
  const cstCreate = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/certs',
    token,
    body: {
      id: cstId,
      recipientName: 'MV EXTRAS TEST',
      vesselName: 'MV EXTRAS TEST',
      vesselIMO: '9999999',
      chiefEngineer: 'TEST CHIEF',
      complianceDate: '2030-01-12',
      complianceQuarter: 'Q1',
      trainingMode: 'ONLINE',
      recipientEmail: 'recipient@example.com',
    },
  });
  assert.equal(cstCreate.status, 201, 'fixture CST cert must be created');

  vaptId = `VAP-9999999-01-${String(Date.now() % 90 + 10)}`;
  const vaptCreate = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/vapt/certs',
    token,
    body: {
      id: vaptId,
      recipientName: 'MV VAPT EXTRAS',
      vesselName: 'MV VAPT EXTRAS',
      vesselIMO: '1234567',
      assessmentDate: '2030-01-12',
      recipientEmail: 'vapt-recipient@example.com',
    },
  });
  assert.equal(vaptCreate.status, 201, 'fixture VAPT cert must be created');
});

after(async () => {
  // Best-effort cleanup of fixture certs before tearing down the process.
  try {
    await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/certs/${cstId}`, token });
    await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/vapt/certs/${vaptId}`, token });
  } catch { /* non-fatal */ }

  if (child) child.kill('SIGTERM');
  for (const dir of [path.join(ROOT, 'data', tenantId), path.join(ROOT, 'uploads', tenantId)]) {
    if (dir.startsWith(ROOT + path.sep)) fs.rmSync(dir, { recursive: true, force: true });
  }
  await cleanupTenantS3Data(tenantId);
});

// ── GET /api/vapt/certs/:id ───────────────────────────────────────────────────

test('GET /api/vapt/certs/:id — auth gating, full object, 404, 400', async () => {
  const unauth = await requestJson({ port: PORT, urlPath: `/api/vapt/certs/${vaptId}` });
  assert.equal(unauth.status, 401, 'single VAPT cert fetch must require auth');

  const ok = await requestJson({ port: PORT, urlPath: `/api/vapt/certs/${vaptId}`, token });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.id, vaptId);
  assert.equal(ok.json.recipientEmail, 'vapt-recipient@example.com', 'admin single-fetch must return full (non-projected) cert');

  const notFound = await requestJson({ port: PORT, urlPath: '/api/vapt/certs/VAP-DOES-NOT-EXIST-00', token });
  assert.equal(notFound.status, 404);

  const badId = await requestJson({ port: PORT, urlPath: '/api/vapt/certs/BAD!ID$$', token });
  assert.equal(badId.status, 400);
});

// ── GET /api/vapt/verify-by-id/:id ────────────────────────────────────────────

test('GET /api/vapt/verify-by-id/:id — public projected fields, 404, 400', async () => {
  const ok = await requestJson({ port: PORT, urlPath: `/api/vapt/verify-by-id/${vaptId}` });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.id, vaptId);
  assert.ok(!('recipientEmail' in ok.json), 'public VAPT verify must not leak recipientEmail');
  assert.ok('effectiveStatus' in ok.json);

  const notFound = await requestJson({ port: PORT, urlPath: '/api/vapt/verify-by-id/VAP-DOES-NOT-EXIST-00' });
  assert.equal(notFound.status, 404);

  const badId = await requestJson({ port: PORT, urlPath: '/api/vapt/verify-by-id/BAD!ID$$' });
  assert.equal(badId.status, 400);
});

// ── VAPT public-cert-url / cert-url / verify token link ───────────────────────

test('VAPT public-cert-url + cert-url + verify/:encToken — happy path and tamper rejection', async () => {
  const pub = await requestJson({ port: PORT, urlPath: `/api/vapt/public-cert-url/${vaptId}` });
  assert.equal(pub.status, 200);
  assert.ok(pub.json && typeof pub.json.url === 'string' && pub.json.url.includes('?s='));

  const pubNotFound = await requestJson({ port: PORT, urlPath: '/api/vapt/public-cert-url/VAP-DOES-NOT-EXIST-00' });
  assert.equal(pubNotFound.status, 404);

  const adminUnauth = await requestJson({ port: PORT, urlPath: `/api/vapt/cert-url/${vaptId}` });
  assert.equal(adminUnauth.status, 401, 'admin cert-url must require auth');

  const adminUrl = await requestJson({ port: PORT, urlPath: `/api/vapt/cert-url/${vaptId}`, token });
  assert.equal(adminUrl.status, 200);
  assert.ok(adminUrl.json && typeof adminUrl.json.url === 'string');

  // Extract token + signature from the returned shareable URL and hit the
  // public verify endpoint directly.
  const parsedUrl = new URL(adminUrl.json.url);
  const segs = parsedUrl.pathname.split('/').filter(Boolean); // ['VAPT'|'CST', 'cert', '<encToken>']
  const encToken = segs[segs.length - 1];
  const sig = parsedUrl.searchParams.get('s');
  assert.ok(encToken && sig, 'shareable URL must carry an encrypted token + signature');

  const verifyOk = await requestJson({ port: PORT, urlPath: `/api/vapt/verify/${encToken}?s=${encodeURIComponent(sig)}` });
  assert.equal(verifyOk.status, 200);
  assert.equal(verifyOk.json.id, vaptId);

  const tamperedSig = tamperFirstChar(sig);
  const verifyTampered = await requestJson({ port: PORT, urlPath: `/api/vapt/verify/${encToken}?s=${encodeURIComponent(tamperedSig)}` });
  assert.equal(verifyTampered.status, 403);
  assert.match(verifyTampered.json.error, /Invalid or tampered verification link/i);
});

// ── CST public-cert-url / cert-url / verify token link (mirror of VAPT) ──────

test('CST public-cert-url + cert-url + verify/:encToken — happy path and tamper rejection', async () => {
  const pub = await requestJson({ port: PORT, urlPath: `/api/public-cert-url/${cstId}` });
  assert.equal(pub.status, 200);
  assert.ok(pub.json && typeof pub.json.url === 'string' && pub.json.url.includes('?s='));

  const pubNotFound = await requestJson({ port: PORT, urlPath: '/api/public-cert-url/CST-DOES-NOT-EXIST-00' });
  assert.equal(pubNotFound.status, 404);

  const adminUnauth = await requestJson({ port: PORT, urlPath: `/api/cert-url/${cstId}` });
  assert.equal(adminUnauth.status, 401, 'admin cert-url must require auth');

  const adminUrl = await requestJson({ port: PORT, urlPath: `/api/cert-url/${cstId}`, token });
  assert.equal(adminUrl.status, 200);

  const parsedUrl = new URL(adminUrl.json.url);
  const segs = parsedUrl.pathname.split('/').filter(Boolean);
  const encToken = segs[segs.length - 1];
  const sig = parsedUrl.searchParams.get('s');
  assert.ok(encToken && sig);

  const verifyOk = await requestJson({ port: PORT, urlPath: `/api/verify/${encToken}?s=${encodeURIComponent(sig)}` });
  assert.equal(verifyOk.status, 200);
  assert.equal(verifyOk.json.id, cstId);

  const tamperedSig = tamperFirstChar(sig);
  const verifyTampered = await requestJson({ port: PORT, urlPath: `/api/verify/${encToken}?s=${encodeURIComponent(tamperedSig)}` });
  assert.equal(verifyTampered.status, 403);
  assert.match(verifyTampered.json.error, /Invalid or tampered verification link/i);
});

// ── Cross-type token rejection ────────────────────────────────────────────────
//
// signCertUrl/verifyCertUrlSignature sign only the token, not the cert type, so a
// CST token+signature pair passes signature verification just as well under
// /vapt/verify/ as it does under /verify/ (same HMAC key, same input). The route
// handlers must independently reject a decrypted ID that doesn't match their own
// cert-type prefix — this is what stops a CST link from being replayed against
// the VAPT verify endpoint (or vice versa) and getting anywhere past a 400.

test('a valid CST verify link is rejected by the VAPT verify endpoint, and vice versa', async () => {
  const cstAdminUrl = await requestJson({ port: PORT, urlPath: `/api/cert-url/${cstId}`, token });
  assert.equal(cstAdminUrl.status, 200);
  const cstParsed = new URL(cstAdminUrl.json.url);
  const cstSegs = cstParsed.pathname.split('/').filter(Boolean);
  const cstEncToken = cstSegs[cstSegs.length - 1];
  const cstSig = cstParsed.searchParams.get('s');

  const vaptAdminUrl = await requestJson({ port: PORT, urlPath: `/api/vapt/cert-url/${vaptId}`, token });
  assert.equal(vaptAdminUrl.status, 200);
  const vaptParsed = new URL(vaptAdminUrl.json.url);
  const vaptSegs = vaptParsed.pathname.split('/').filter(Boolean);
  const vaptEncToken = vaptSegs[vaptSegs.length - 1];
  const vaptSig = vaptParsed.searchParams.get('s');

  // CST token+sig replayed against the VAPT endpoint: signature is valid (same
  // key/input), so this must be rejected by the cert-type prefix guard, not the
  // signature check — confirm it's a 400 (type mismatch), not a 403 (bad sig).
  const cstOnVapt = await requestJson({ port: PORT, urlPath: `/api/vapt/verify/${cstEncToken}?s=${encodeURIComponent(cstSig)}` });
  assert.equal(cstOnVapt.status, 400);
  assert.match(cstOnVapt.json.error, /Invalid verification token/i);

  const vaptOnCst = await requestJson({ port: PORT, urlPath: `/api/verify/${vaptEncToken}?s=${encodeURIComponent(vaptSig)}` });
  assert.equal(vaptOnCst.status, 400);
  assert.match(vaptOnCst.json.error, /Invalid verification token/i);
});

// ── POST /api/vapt/import-csv ─────────────────────────────────────────────────
//
// KNOWN BUG (confirmed, not a test bug): server/index.js:2975-2992 —
//   for (const cert of records) { ... cert.id = certId; cert = sanitiseCertBody(cert); ... }
// `cert` is the `const` loop-binding of the for-of loop, and line 2992
// reassigns it ("cert = sanitiseCertBody(cert)"), which throws
// "TypeError: Assignment to constant variable." for every non-duplicate,
// non-invalid record. The generic request handler's catch-all reports this
// as a bare 500 "Internal server error", so /api/vapt/import-csv is
// completely broken for any real import payload today. The mirror CST route
// (POST /api/import-csv, ~line 2519-2575) does NOT reassign `cert` inside
// its loop and works correctly — this is a VAPT-only regression. The
// assertion below expects the documented/correct 200 + added>=1 contract and
// is intentionally left failing (500) to surface this rather than being
// weakened to match the buggy behavior.

test('POST /api/vapt/import-csv — auth gating + added count', async () => {
  const importId = `VAP-8888888-01-${String(Date.now() % 90 + 10)}`;

  const unauth = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/vapt/import-csv',
    body: [{ id: importId, vesselIMO: '8888888', vesselName: 'MV VAPT CSV-1' }],
  });
  assert.equal(unauth.status, 401);

  const ok = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/vapt/import-csv',
    token,
    body: [{ id: importId, vesselIMO: '8888888', vesselName: 'MV VAPT CSV-1' }],
  });
  assert.equal(ok.status, 200);
  assert.ok(ok.json && typeof ok.json.added === 'number' && ok.json.added >= 1);

  // Cleanup the imported cert.
  await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/vapt/certs/${importId}`, token });
});

// ── engagement endpoints ──────────────────────────────────────────────────────

test('GET /api/certs/:id/engagement + /api/vapt/certs/:id/engagement — auth gating, shape, 404', async () => {
  const cstUnauth = await requestJson({ port: PORT, urlPath: `/api/certs/${cstId}/engagement` });
  assert.equal(cstUnauth.status, 401);

  const cstOk = await requestJson({ port: PORT, urlPath: `/api/certs/${cstId}/engagement`, token });
  assert.equal(cstOk.status, 200);
  assert.equal(cstOk.json.certId, cstId);
  assert.ok(cstOk.json.engagement && typeof cstOk.json.engagement === 'object');

  const cstNotFound = await requestJson({ port: PORT, urlPath: '/api/certs/CST-DOES-NOT-EXIST-00/engagement', token });
  assert.equal(cstNotFound.status, 404);

  const vaptUnauth = await requestJson({ port: PORT, urlPath: `/api/vapt/certs/${vaptId}/engagement` });
  assert.equal(vaptUnauth.status, 401);

  const vaptOk = await requestJson({ port: PORT, urlPath: `/api/vapt/certs/${vaptId}/engagement`, token });
  assert.equal(vaptOk.status, 200);
  assert.equal(vaptOk.json.certId, vaptId);
  assert.ok(vaptOk.json.engagement && typeof vaptOk.json.engagement === 'object');

  const vaptNotFound = await requestJson({ port: PORT, urlPath: '/api/vapt/certs/VAP-DOES-NOT-EXIST-00/engagement', token });
  assert.equal(vaptNotFound.status, 404);
});

// ── POST /api/track-event ─────────────────────────────────────────────────────

test('POST /api/track-event — valid event, invalid event, malformed JSON', async () => {
  const ok = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/track-event',
    body: { certId: cstId, event: 'cert_viewed' },
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.ok, true);

  const badEvent = await requestJson({
    method: 'POST',
    port: PORT,
    urlPath: '/api/track-event',
    body: { certId: cstId, event: 'not_a_real_event' },
  });
  assert.equal(badEvent.status, 400);

  const malformed = await requestBinary({
    method: 'POST',
    port: PORT,
    urlPath: '/api/track-event',
    headers: { 'Content-Type': 'application/json' },
    bodyBuffer: Buffer.from('{not valid json', 'utf8'),
  });
  assert.equal(malformed.status, 400);
});

// ── tracking pixel endpoints ───────────────────────────────────────────────────

test('GET /api/track-open/:token + /api/vapt/track-open/:token — valid signed token and malformed token', async () => {
  // Construct a validly-signed pixel token the same way the server does:
  // payload = base64url(certId), sig = HMAC-SHA256(urlMacKey, 'track:<kind>:' + payload).slice(0,16)
  function buildTrackToken(kind, certId) {
    const payload = Buffer.from(certId, 'utf8').toString('base64url');
    const sig = crypto.createHmac('sha256', urlMacKey).update(`track:${kind}:` + payload).digest('base64url').slice(0, 16);
    return `${payload}.${sig}`;
  }

  const cstToken = buildTrackToken('cst', cstId);
  const cstPixel = await requestBinary({ port: PORT, urlPath: `/api/track-open/${cstToken}` });
  assert.equal(cstPixel.status, 200);
  assert.equal(cstPixel.headers['content-type'], 'image/gif');

  const vaptToken = buildTrackToken('vapt', vaptId);
  const vaptPixel = await requestBinary({ port: PORT, urlPath: `/api/vapt/track-open/${vaptToken}` });
  assert.equal(vaptPixel.status, 200);
  assert.equal(vaptPixel.headers['content-type'], 'image/gif');

  // Garbage / malformed tokens must never crash the server — still serve the pixel gracefully.
  const garbage = await requestBinary({ port: PORT, urlPath: '/api/track-open/not-a-real-token-at-all' });
  assert.equal(garbage.status, 200, 'malformed track-open token must not 500');
  assert.equal(garbage.headers['content-type'], 'image/gif');

  const vaptGarbage = await requestBinary({ port: PORT, urlPath: '/api/vapt/track-open/%%%invalid%%%' });
  assert.ok(vaptGarbage.status < 500, 'malformed vapt track-open token must not 500');
});

// ── attachment deletion ────────────────────────────────────────────────────────
//
// KNOWN BUG (confirmed, not a test bug): server/index.js:2578 and :3145 —
//   if (route.startsWith('/certs/') && method === 'DELETE') { ... }
//   if (route.startsWith('/vapt/certs/') && method === 'DELETE') { ... }
// These generic "delete cert by id" handlers run BEFORE the more specific
// attachment-delete handlers at :3173 (`/certs/:id/attachments/:idx`) and
// :3196 (`/vapt/certs/:id/attachments/:idx`) in the if-chain, and — unlike
// the analogous GET single-cert handlers (:2163, :2849) which explicitly
// guard with a segment-count check (`segments.length === 2/3`) — they use a
// bare `startsWith` with no such guard. So any DELETE to
// `/certs/<id>/attachments/<idx>` also matches `startsWith('/certs/')`,
// and `sanitiseCertId(route.replace('/certs/', ''))` then receives
// "<id>/attachments/<idx>" (contains "/"), fails the ID regex, and the
// handler returns 400 "Invalid certificate ID" and `return`s — so the
// dedicated attachment-delete routes below are dead code, unreachable in
// production. The assertions below expect the documented/correct 200 +
// shrunk-attachments contract and are intentionally left failing (400) to
// surface this rather than being weakened to match the buggy behavior.

test('DELETE /api/certs/:id/attachments/:idx + /api/vapt/certs/:id/attachments/:idx', async () => {
  const cstAttach = await requestMultipart({
    method: 'PUT',
    port: PORT,
    urlPath: `/api/certs/${cstId}`,
    token,
    files: [{ fieldName: 'attachment0', filename: 'extra.pdf', contentType: 'application/pdf', data: dummyPdf }],
  });
  assert.equal(cstAttach.status, 200);
  assert.equal(cstAttach.json.attachments.length, 1, 'fixture attachment must be stored before delete');

  const cstDelUnauth = await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/certs/${cstId}/attachments/0` });
  assert.equal(cstDelUnauth.status, 401, 'attachment delete must require auth');

  const cstDel = await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/certs/${cstId}/attachments/0`, token });
  assert.equal(cstDel.status, 200, 'DELETE /api/certs/:id/attachments/:idx should remove the attachment and return 200');
  assert.equal(cstDel.json.attachments.length, 0, 'attachments array should shrink after delete');

  const vaptAttach = await requestMultipart({
    method: 'PUT',
    port: PORT,
    urlPath: `/api/vapt/certs/${vaptId}`,
    token,
    files: [{ fieldName: 'attachment0', filename: 'vapt_extra.pdf', contentType: 'application/pdf', data: dummyPdf }],
  });
  assert.equal(vaptAttach.status, 200);
  assert.equal(vaptAttach.json.attachments.length, 1, 'fixture VAPT attachment must be stored before delete');

  const vaptDel = await requestJson({ method: 'DELETE', port: PORT, urlPath: `/api/vapt/certs/${vaptId}/attachments/0`, token });
  assert.equal(vaptDel.status, 200, 'DELETE /api/vapt/certs/:id/attachments/:idx should remove the attachment and return 200');
  assert.equal(vaptDel.json.attachments.length, 0, 'VAPT attachments array should shrink after delete');
});
