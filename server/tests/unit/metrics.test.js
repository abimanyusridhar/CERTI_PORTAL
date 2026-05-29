'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const { createMetrics } = require('../../ops/metrics');

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot shape
// ─────────────────────────────────────────────────────────────────────────────
test('metrics — snapshot has required top-level fields', () => {
  const m = createMetrics();
  const s = m.snapshot();
  assert.ok(typeof s.uptimeSec === 'number');
  assert.ok(typeof s.counters === 'object');
  assert.ok(typeof s.routes === 'object');
});

test('metrics — counters start at zero', () => {
  const m = createMetrics();
  const { counters } = m.snapshot();
  assert.equal(counters.requestsTotal, 0);
  assert.equal(counters.requests2xx,   0);
  assert.equal(counters.requests4xx,   0);
  assert.equal(counters.requests5xx,   0);
  assert.equal(counters.inFlight,      0);
});

// ─────────────────────────────────────────────────────────────────────────────
// begin / end lifecycle
// ─────────────────────────────────────────────────────────────────────────────
test('metrics — begin increments requestsTotal and inFlight', () => {
  const m   = createMetrics();
  const req = { method: 'GET', url: '/api/health' };
  m.begin(req);
  const s = m.snapshot();
  assert.equal(s.counters.requestsTotal, 1);
  assert.equal(s.counters.inFlight, 1);
});

test('metrics — end decrements inFlight and classifies status', () => {
  const m   = createMetrics();
  const req = { method: 'GET', url: '/api/health' };
  m.begin(req);
  m.end(req, 200);
  const s = m.snapshot();
  assert.equal(s.counters.inFlight,    0);
  assert.equal(s.counters.requests2xx, 1);
  assert.equal(s.counters.requests4xx, 0);
  assert.equal(s.counters.requests5xx, 0);
});

test('metrics — end counts 4xx correctly', () => {
  const m   = createMetrics();
  const req = { method: 'GET', url: '/api/verify-by-id/BAD' };
  m.begin(req);
  m.end(req, 404);
  assert.equal(m.snapshot().counters.requests4xx, 1);
});

test('metrics — end counts 5xx correctly', () => {
  const m   = createMetrics();
  const req = { method: 'POST', url: '/api/certs' };
  m.begin(req);
  m.end(req, 500);
  assert.equal(m.snapshot().counters.requests5xx, 1);
});

test('metrics — inFlight never goes below zero', () => {
  const m   = createMetrics();
  const req = { method: 'GET', url: '/' };
  m.end(req, 200); // end without begin
  assert.equal(m.snapshot().counters.inFlight, 0);
});

// ─────────────────────────────────────────────────────────────────────────────
// Route bucketing
// ─────────────────────────────────────────────────────────────────────────────
test('metrics — API routes are bucketed as /api/*', () => {
  const m   = createMetrics();
  const req = { method: 'GET', url: '/api/health' };
  m.begin(req);
  m.end(req, 200);
  const s = m.snapshot();
  assert.ok('GET /api/*' in s.routes, 'API bucket must exist');
  assert.equal(s.routes['GET /api/*'].count, 1);
});

test('metrics — upload routes are bucketed as /uploads/*', () => {
  const m   = createMetrics();
  const req = { method: 'GET', url: '/uploads/tenant1/cert.png' };
  m.begin(req);
  m.end(req, 200);
  const s = m.snapshot();
  assert.ok('GET /uploads/*' in s.routes, 'uploads bucket must exist');
});

test('metrics — non-API routes use exact path', () => {
  const m   = createMetrics();
  const req = { method: 'GET', url: '/CST' };
  m.begin(req);
  m.end(req, 200);
  const s = m.snapshot();
  assert.ok('GET /CST' in s.routes);
});

test('metrics — route stats include count, avgMs, and maxMs', () => {
  const m   = createMetrics();
  const req = { method: 'GET', url: '/api/verify' };
  m.begin(req);
  m.end(req, 200);
  const stats = m.snapshot().routes['GET /api/*'];
  assert.ok(typeof stats.count  === 'number');
  assert.ok(typeof stats.avgMs  === 'number');
  assert.ok(typeof stats.maxMs  === 'number');
  assert.equal(stats.count, 1);
});

test('metrics — multiple requests accumulate in route stats', () => {
  const m   = createMetrics();
  for (let i = 0; i < 5; i++) {
    const req = { method: 'POST', url: '/api/certs' };
    m.begin(req);
    m.end(req, 201);
  }
  assert.equal(m.snapshot().counters.requestsTotal, 5);
  assert.equal(m.snapshot().counters.requests2xx,   5);
  assert.equal(m.snapshot().routes['POST /api/*'].count, 5);
});

test('metrics — uptime increases over time', async () => {
  const m = createMetrics();
  const s1 = m.snapshot().uptimeSec;
  await new Promise(r => setTimeout(r, 1010));
  const s2 = m.snapshot().uptimeSec;
  assert.ok(s2 >= s1 + 1, 'uptime must increase by at least 1 second');
});
