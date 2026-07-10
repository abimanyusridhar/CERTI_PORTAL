'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createAuthRoutes } = require('../../routes/auth');

function createRes() {
  return { status: null, body: null, headers: null };
}

function makeRoutes(overrides = {}) {
  const calls = { revoked: [] };
  const routes = createAuthRoutes({
    sendJSON(res, status, body, headers) {
      res.status = status;
      res.body = body;
      res.headers = headers || {};
    },
    authCheck: () => false,
    verifyToken: () => null,
    revokeToken(jti, expMs) {
      calls.revoked.push({ jti, expMs });
    },
    ...overrides,
  });
  return { routes, calls };
}

test('auth routes - login POST is decommissioned with 410', () => {
  const { routes } = makeRoutes();
  const res = createRes();
  const handled = routes.handleLogin({}, res, 'POST', '/auth/login', '127.0.0.1', { 'X-Test': 'cors' });
  assert.equal(handled, true);
  assert.equal(res.status, 410);
  assert.match(res.body.error, /AWS SSO/);
  assert.equal(res.headers['X-Test'], 'cors');
});

test('auth routes - login ignores other methods and paths', () => {
  const { routes } = makeRoutes();
  assert.equal(routes.handleLogin({}, createRes(), 'GET', '/auth/login', '127.0.0.1', {}), false);
  assert.equal(routes.handleLogin({}, createRes(), 'POST', '/auth/verify', '127.0.0.1', {}), false);
});

test('auth routes - verify returns 401 when unauthenticated', () => {
  const { routes } = makeRoutes({ authCheck: () => false });
  const res = createRes();
  const handled = routes.handleVerify({}, res, 'GET', '/auth/verify', { 'X-Cors': 'yes' });
  assert.equal(handled, true);
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'Access denied. Please log in to continue.');
  assert.equal(res.headers['X-Cors'], 'yes');
});

test('auth routes - verify returns ok when authenticated', () => {
  const { routes } = makeRoutes({ authCheck: () => true });
  const res = createRes();
  const handled = routes.handleVerify({}, res, 'GET', '/auth/verify', {});
  assert.equal(handled, true);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { ok: true });
});

test('auth routes - verify ignores non-matching request', () => {
  const { routes } = makeRoutes();
  assert.equal(routes.handleVerify({}, createRes(), 'POST', '/auth/verify', {}), false);
  assert.equal(routes.handleVerify({}, createRes(), 'GET', '/auth/logout', {}), false);
});

test('auth routes - logout revokes bearer token and clears cookies', async () => {
  const { routes, calls } = makeRoutes({
    verifyToken: token => token === 'valid-token' ? { jti: 'jti-1', exp: 123 } : null,
  });
  const res = createRes();
  const handled = await routes.handleLogout(
    { headers: { authorization: 'Bearer valid-token' } },
    res,
    'POST',
    '/auth/logout',
    { 'X-Cors': 'yes' },
  );
  assert.equal(handled, true);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { ok: true });
  assert.deepEqual(calls.revoked, [{ jti: 'jti-1', expMs: 123000 }]);
  assert.ok(Array.isArray(res.headers['Set-Cookie']));
  assert.equal(res.headers['X-Cors'], 'yes');
});

test('auth routes - logout reads token from cookie when bearer is absent', async () => {
  const { routes, calls } = makeRoutes({
    verifyToken: token => token === 'cookie-token' ? { jti: 'jti-cookie', exp: 456 } : null,
  });
  const res = createRes();
  await routes.handleLogout(
    { headers: { cookie: 'other=1; adminToken=cookie-token; theme=dark' } },
    res,
    'POST',
    '/auth/logout',
    {},
  );
  assert.equal(res.status, 200);
  assert.deepEqual(calls.revoked, [{ jti: 'jti-cookie', expMs: 456000 }]);
});

test('auth routes - logout succeeds without token and ignores other routes', async () => {
  const { routes, calls } = makeRoutes();
  const res = createRes();
  assert.equal(await routes.handleLogout({ headers: {} }, res, 'POST', '/auth/logout', {}), true);
  assert.equal(res.status, 200);
  assert.deepEqual(calls.revoked, []);
  assert.equal(await routes.handleLogout({ headers: {} }, createRes(), 'GET', '/auth/logout', {}), false);
});
