'use strict';

const { test, expect } = require('@playwright/test');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Adversarial CSRF re-verification (see docs/qa-assessment-report.md, "CSRF protection
// remains architecture-reliant ... not independently re-verified").
//
// authCheck() (server/index.js:1963-1981) authorizes every admin POST/PUT/DELETE route
// from either an `Authorization: Bearer` header OR a same-site `adminToken` cookie
// fallback. No route separately checks Origin/Referer, and CORS (Access-Control-Allow-*)
// is irrelevant to a classic <form> POST — CORS only gates script-readable responses
// (fetch/XHR), never full-page/iframe navigations. So SameSite=Lax on the `adminToken`
// cookie (server/index.js:3936) is the ONLY thing standing between a malicious
// cross-site page and an authenticated admin mutation. This test drives a real second
// origin ("attacker.test", a distinct site from 127.0.0.1 by the SameSite spec) that
// auto-submits a hidden cross-site form at POST /api/admin/users while a real browser
// cookie jar holds a valid adminToken — the same as an admin who is logged into the
// real dashboard in another tab clicking a malicious link.

const ROOT = path.join(__dirname, '..', '..', '..');
const TENANT_ID = 'tenant_e2e_fixed'; // matches playwright.config.js webServer env
const APP_ORIGIN = 'http://127.0.0.1:3425';
let attackerServer;
let attackerPort;

function mintAdminToken(username) {
  const keysPath = path.join(ROOT, 'data', TENANT_ID, '.keys.json');
  const { jwtSecret } = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  const nowS = Math.floor(Date.now() / 1000);
  const payload = { sub: username, iat: nowS, exp: nowS + 8 * 60 * 60, jti: crypto.randomBytes(16).toString('hex') };
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', jwtSecret).update(header + '.' + body).digest('base64url');
  return `${header}.${body}.${sig}`;
}

test.beforeAll(async () => {
  // A tiny attacker-controlled site — a distinct "site" from 127.0.0.1 under the
  // SameSite spec (no shared registrable domain / not the same IP), which is exactly
  // what makes this a genuine cross-site request rather than same-site-different-port.
  attackerServer = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body>
      <iframe name="sink" style="display:none"></iframe>
      <form id="f" method="POST" target="sink" action="${APP_ORIGIN}/api/admin/users">
        <input name="name" value="CSRF Attacker" />
        <input name="email" value="csrf-attacker@evil.example.com" />
      </form>
      <script>document.getElementById('f').submit();</script>
    </body></html>`);
  });
  await new Promise((resolve) => attackerServer.listen(0, '127.0.0.1', resolve));
  attackerPort = attackerServer.address().port;
});

test.afterAll(async () => {
  await new Promise((resolve) => attackerServer.close(resolve));
});

test.describe('CSRF — admin cookie session', () => {
  test('a same-site request with the adminToken cookie IS authenticated (sanity control)', async ({ page, context }) => {
    const token = mintAdminToken('admin_csrf_sanity');
    await context.addCookies([{ name: 'adminToken', value: token, domain: '127.0.0.1', path: '/', httpOnly: true, sameSite: 'Lax' }]);

    await page.goto(`${APP_ORIGIN}/`);
    const res = await page.evaluate(async (origin) => {
      const r = await fetch(origin + '/api/admin/users', { credentials: 'include' });
      return r.status;
    }, APP_ORIGIN);

    expect(res).toBe(200);
  });

  test('a cross-site auto-submitted form to POST /api/admin/users does not carry the adminToken cookie and is rejected', async ({ page, context, request }) => {
    const token = mintAdminToken('admin_csrf_victim');
    await context.addCookies([{ name: 'adminToken', value: token, domain: '127.0.0.1', path: '/', httpOnly: true, sameSite: 'Lax' }]);

    const before = await request.get(`${APP_ORIGIN}/api/admin/users`, { headers: { Authorization: `Bearer ${token}` } });
    const usersBefore = await before.json();

    // Land the victim's browser on the attacker's distinct site — this is what actually
    // makes the form's POST cross-site, not just cross-port — and wait for the forged
    // request's real response (fired inside the hidden sink iframe, not the top frame).
    const [forgedResponse] = await Promise.all([
      page.waitForResponse((r) => r.url() === `${APP_ORIGIN}/api/admin/users`),
      page.goto(`http://localhost:${attackerPort}/`),
    ]);

    expect(forgedResponse.status(), 'the forged request must be rejected, not silently authenticated').toBe(401);
    expect(forgedResponse.request().headers()['cookie'], 'SameSite=Lax must withhold adminToken on a cross-site POST').toBeUndefined();

    const after = await request.get(`${APP_ORIGIN}/api/admin/users`, { headers: { Authorization: `Bearer ${token}` } });
    const usersAfter = await after.json();
    expect(usersAfter.length, 'no user must have been created by the forged request').toBe(usersBefore.length);
  });
});
