'use strict';

const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Regression coverage for a real production bug: dashboard.js/vapt-dashboard.js's
// "already logged in (page reload)" boot path reads the JWT's `iat` claim — seconds
// since epoch, per the JWT spec — directly into `_sessionStart`, but every other use
// of `_sessionStart` (scheduleSessionTimers) does millisecond arithmetic against
// Date.now(). Without converting iat*1000, `elapsed` computes as roughly `Date.now()`
// itself (tens of years), `remaining` clamps to 0, and the 8-hour session timer fires
// doLogout() within moments of every single page refresh — logging the admin out
// immediately after any reload, even though the JWT itself is nowhere near expired.
// This only manifests on reload (the "already logged in" branch), not on the very
// first load after SSO login (which takes a different, timer-free path) — that's why
// it slipped past manual click-testing and only showed up as "every refresh logs me
// out" in real usage.

const ROOT = path.join(__dirname, '..', '..', '..');
const TENANT_ID = 'tenant_e2e_fixed'; // matches playwright.config.js webServer env
const APP_ORIGIN = 'http://127.0.0.1:3425';

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

async function loginAndAssertLoggedIn(page, context, url, token) {
  await context.addCookies([{ name: 'adminToken', value: token, domain: '127.0.0.1', path: '/', httpOnly: true, sameSite: 'Lax' }]);
  await context.addInitScript((t) => { window.sessionStorage.setItem('adminToken', t); }, token);
  await page.goto(url, { waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  await expect(page.locator('#appWrap')).toBeVisible();
  await expect(page.locator('#loginWrap')).toBeHidden();
}

test.describe('Admin session survives a page refresh (regression: iat seconds/ms mix-up)', () => {
  test('CST dashboard stays logged in across two consecutive reloads', async ({ page, context }) => {
    const token = mintAdminToken('e2e_refresh_cst');
    await loginAndAssertLoggedIn(page, context, `${APP_ORIGIN}/console/cst/`, token);

    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForTimeout(800);
    await expect(page.locator('#appWrap'), 'must still be logged in after one refresh').toBeVisible();
    await expect(page.locator('#loginWrap')).toBeHidden();

    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForTimeout(800);
    await expect(page.locator('#appWrap'), 'must still be logged in after a second refresh').toBeVisible();
    await expect(page.locator('#loginWrap')).toBeHidden();
  });

  test('VAPT dashboard stays logged in across two consecutive reloads', async ({ page, context }) => {
    const token = mintAdminToken('e2e_refresh_vapt');
    await loginAndAssertLoggedIn(page, context, `${APP_ORIGIN}/console/vapt/`, token);

    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForTimeout(800);
    await expect(page.locator('#appWrap'), 'must still be logged in after one refresh').toBeVisible();
    await expect(page.locator('#loginWrap')).toBeHidden();

    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForTimeout(800);
    await expect(page.locator('#appWrap'), 'must still be logged in after a second refresh').toBeVisible();
    await expect(page.locator('#loginWrap')).toBeHidden();
  });
});
