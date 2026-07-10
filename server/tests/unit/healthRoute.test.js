'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHealthRoute } = require('../../routes/health');

function createRes() {
  return { status: null, body: null, headers: null };
}

function makeHealth(overrides = {}) {
  const sent = [];
  const route = createHealthRoute({
    sendJSON(res, status, body, headers) {
      res.status = status;
      res.body = body;
      res.headers = headers || {};
      sent.push({ status, body, headers });
    },
    corsHeadersForOrigin: origin => ({ 'Access-Control-Allow-Origin': origin || 'fallback' }),
    cfg: { version: '9.9.9', maintenance: { enabled: false } },
    sesEnabled: false,
    serverStartTime: Date.now() - 5000,
    serverReadyRef: () => true,
    shuttingDownRef: () => false,
    metricsSnapshot: () => ({ counters: { requestsTotal: 3 } }),
    authCheck: () => false,
    checkRateLimit: () => ({ ok: true }),
    ...overrides,
  });
  return { route, sent };
}

test('health route - ignores non-GET and non-health paths', () => {
  const { route } = makeHealth();
  assert.equal(route({}, createRes(), '/health', 'POST', '', '127.0.0.1'), false);
  assert.equal(route({}, createRes(), '/status', 'GET', '', '127.0.0.1'), false);
});

test('health route - returns operational public health without internal details', () => {
  const { route } = makeHealth();
  const res = createRes();
  const handled = route({}, res, '/health', 'GET', 'https://portal.example.com', '127.0.0.1');
  assert.equal(handled, true);
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
  assert.equal(res.body.status, 'operational');
  assert.equal(res.body.version, '9.9.9');
  assert.equal(res.body.maintenance, false);
  assert.ok(!('detailed' in res.body));
  assert.ok(!('metrics' in res.body));
  assert.equal(res.headers['Access-Control-Allow-Origin'], 'https://portal.example.com');
});

test('health route - reports starting and maintenance states', () => {
  const { route } = makeHealth({
    serverReadyRef: () => false,
    cfg: { version: '1.0.0', maintenance: { enabled: true } },
  });
  const res = createRes();
  route({}, res, '/health', 'GET', '', '127.0.0.1');
  assert.equal(res.body.status, 'starting');
  assert.equal(res.body.maintenance, true);
});

test('health route - reports shutting_down before operational', () => {
  const { route } = makeHealth({
    serverReadyRef: () => true,
    shuttingDownRef: () => true,
  });
  const res = createRes();
  route({}, res, '/health', 'GET', '', '127.0.0.1');
  assert.equal(res.body.status, 'shutting_down');
});

test('health route - rate limits public health when limiter rejects', () => {
  const { route } = makeHealth({
    checkRateLimit: () => ({ ok: false }),
  });
  const res = createRes();
  const handled = route({}, res, '/health', 'GET', 'https://portal.example.com', '10.0.0.1');
  assert.equal(handled, true);
  assert.equal(res.status, 429);
  assert.equal(res.body.error, 'Too many requests. Try again later.');
});

test('health route - detailed endpoint requires admin auth', () => {
  const { route } = makeHealth({ authCheck: () => false });
  const res = createRes();
  const handled = route({}, res, '/health-detailed', 'GET', 'https://portal.example.com', '10.0.0.1');
  assert.equal(handled, true);
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'Access denied.');
});

test('health route - detailed endpoint returns SES, memory, and metrics when authenticated', () => {
  const { route } = makeHealth({
    authCheck: () => true,
    sesEnabled: true,
    metricsSnapshot: () => ({ counters: { requestsTotal: 9 }, routes: { 'GET /api/*': { count: 2 } } }),
  });
  const res = createRes();
  const handled = route({}, res, '/health-detailed', 'GET', '', '127.0.0.1');
  assert.equal(handled, true);
  assert.equal(res.status, 200);
  assert.equal(res.body.detailed.ses.configured, true);
  assert.ok(res.body.detailed.memory.heapUsed.endsWith('MB'));
  assert.equal(res.body.metrics.counters.requestsTotal, 9);
});
