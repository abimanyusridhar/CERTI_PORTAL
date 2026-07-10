'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadDotEnv, validateRuntimeConfig } = require('../../config/env');

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

test('loadDotEnv - loads key/value pairs from server .env and strips quotes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'synergy-env-test-'));
  const key1 = `SYNERGY_ENV_TEST_${Date.now()}_A`;
  const key2 = `SYNERGY_ENV_TEST_${Date.now()}_B`;
  fs.writeFileSync(path.join(dir, '.env'), [
    '# comment',
    `${key1}=plain-value`,
    `${key2}="quoted value"`,
    'INVALID_LINE',
    '',
  ].join('\n'), 'utf8');

  try {
    delete process.env[key1];
    delete process.env[key2];
    const messages = [];
    loadDotEnv({ info: (...args) => messages.push(args.join(' ')) }, dir);
    assert.equal(process.env[key1], 'plain-value');
    assert.equal(process.env[key2], 'quoted value');
    assert.ok(messages.some(m => m.includes('.env')));
  } finally {
    delete process.env[key1];
    delete process.env[key2];
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('loadDotEnv - does not overwrite existing process env values', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'synergy-env-test-'));
  const key = `SYNERGY_ENV_TEST_${Date.now()}_KEEP`;
  fs.writeFileSync(path.join(dir, '.env'), `${key}=from-file\n`, 'utf8');

  try {
    process.env[key] = 'existing';
    loadDotEnv(null, dir);
    assert.equal(process.env[key], 'existing');
  } finally {
    delete process.env[key];
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('loadDotEnv - searches parent .env when server .env is absent', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'synergy-env-root-'));
  const serverDir = path.join(root, 'server');
  fs.mkdirSync(serverDir);
  const key = `SYNERGY_ENV_TEST_${Date.now()}_PARENT`;
  fs.writeFileSync(path.join(root, '.env'), `${key}=from-parent\n`, 'utf8');

  try {
    delete process.env[key];
    loadDotEnv(null, serverDir);
    assert.equal(process.env[key], 'from-parent');
  } finally {
    delete process.env[key];
    fs.rmSync(root, { recursive: true, force: true });
  }
});
