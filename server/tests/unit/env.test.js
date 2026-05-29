'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const { validateRuntimeConfig } = require('../../config/env');

const BASE_CFG = {
  routes: {
    cst:      '/CST',
    vpt:      '/VAPT',
    cstAdmin: '/CST/misecure',
    vptAdmin: '/VAPT/misecure',
  },
};

const STRONG_PASS = 'Admin@Test_123!'; // 16 chars, upper, lower, digit, special

// ─────────────────────────────────────────────────────────────────────────────
// validateRuntimeConfig — passing cases
// ─────────────────────────────────────────────────────────────────────────────
test('validateRuntimeConfig — passes with valid config', () => {
  const result = validateRuntimeConfig({
    port: 3000,
    adminUser: 'admin',
    adminPass: STRONG_PASS,
    cfg: BASE_CFG,
  });
  assert.ok(result.ok);
  assert.equal(result.errors.length, 0);
});

test('validateRuntimeConfig — accepts port 1 and port 65535 (boundary)', () => {
  for (const port of [1, 65535]) {
    const r = validateRuntimeConfig({ port, adminUser: 'admin', adminPass: STRONG_PASS, cfg: BASE_CFG });
    assert.ok(r.ok, `port ${port} should be valid`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// validateRuntimeConfig — failing cases
// ─────────────────────────────────────────────────────────────────────────────
test('validateRuntimeConfig — rejects port 0', () => {
  const r = validateRuntimeConfig({ port: 0, adminUser: 'admin', adminPass: STRONG_PASS, cfg: BASE_CFG });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /PORT/.test(e)));
});

test('validateRuntimeConfig — rejects port 65536', () => {
  const r = validateRuntimeConfig({ port: 65536, adminUser: 'admin', adminPass: STRONG_PASS, cfg: BASE_CFG });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /PORT/.test(e)));
});

test('validateRuntimeConfig — rejects non-integer port', () => {
  const r = validateRuntimeConfig({ port: 3000.5, adminUser: 'admin', adminPass: STRONG_PASS, cfg: BASE_CFG });
  assert.ok(!r.ok);
});

test('validateRuntimeConfig — rejects missing ADMIN_USER', () => {
  const r = validateRuntimeConfig({ port: 3000, adminUser: '', adminPass: STRONG_PASS, cfg: BASE_CFG });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /ADMIN/.test(e)));
});

test('validateRuntimeConfig — rejects missing ADMIN_PASS', () => {
  const r = validateRuntimeConfig({ port: 3000, adminUser: 'admin', adminPass: '', cfg: BASE_CFG });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /ADMIN/.test(e)));
});

test('validateRuntimeConfig — rejects weak password (under 12 chars)', () => {
  const r = validateRuntimeConfig({ port: 3000, adminUser: 'admin', adminPass: 'Short@1!', cfg: BASE_CFG });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /ADMIN_PASS/.test(e)));
});

test('validateRuntimeConfig — rejects password with no uppercase', () => {
  const r = validateRuntimeConfig({ port: 3000, adminUser: 'admin', adminPass: 'nouppercase@123!', cfg: BASE_CFG });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /ADMIN_PASS/.test(e)));
});

test('validateRuntimeConfig — rejects password with no lowercase', () => {
  const r = validateRuntimeConfig({ port: 3000, adminUser: 'admin', adminPass: 'NOLOWERCASE@123!', cfg: BASE_CFG });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /ADMIN_PASS/.test(e)));
});

test('validateRuntimeConfig — rejects password with no digit', () => {
  const r = validateRuntimeConfig({ port: 3000, adminUser: 'admin', adminPass: 'NoDigitInHere@!Xx', cfg: BASE_CFG });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /ADMIN_PASS/.test(e)));
});

test('validateRuntimeConfig — rejects password with no special character', () => {
  const r = validateRuntimeConfig({ port: 3000, adminUser: 'admin', adminPass: 'NoSpecialChar123A', cfg: BASE_CFG });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /ADMIN_PASS/.test(e)));
});

test('validateRuntimeConfig — rejects missing cfg routes', () => {
  const badCfg = { routes: { cst: '/CST' } }; // missing vpt, cstAdmin, vptAdmin
  const r = validateRuntimeConfig({ port: 3000, adminUser: 'admin', adminPass: STRONG_PASS, cfg: badCfg });
  assert.ok(!r.ok);
  assert.ok(r.errors.some(e => /routes/.test(e)));
});

test('validateRuntimeConfig — rejects null cfg', () => {
  const r = validateRuntimeConfig({ port: 3000, adminUser: 'admin', adminPass: STRONG_PASS, cfg: null });
  assert.ok(!r.ok);
});

test('validateRuntimeConfig — accumulates multiple errors', () => {
  const r = validateRuntimeConfig({ port: 0, adminUser: '', adminPass: '', cfg: null });
  assert.ok(!r.ok);
  assert.ok(r.errors.length >= 2);
});
