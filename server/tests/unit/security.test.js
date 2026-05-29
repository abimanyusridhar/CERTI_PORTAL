'use strict';

const test     = require('node:test');
const assert   = require('node:assert/strict');
const crypto   = require('node:crypto');
const {
  createSecurityService,
  validation,
  CircuitBreaker,
  retryWithBackoff,
  createErrorResponse,
} = require('../../services/security');

// ── Shared test fixtures ──────────────────────────────────────────────────────
const KEYS = {
  urlEncKey: crypto.randomBytes(32).toString('hex'),
  urlMacKey: crypto.randomBytes(32).toString('hex'),
  jwtSecret: crypto.randomBytes(48).toString('hex'),
  pwdSalt:   crypto.randomBytes(32).toString('hex'),
};
const CFG  = { routes: { cst: '/CST', vpt: '/VAPT' } };
const sec  = createSecurityService({ keys: KEYS, cfg: CFG });

// ─────────────────────────────────────────────────────────────────────────────
// validation.isValidCertId
// ─────────────────────────────────────────────────────────────────────────────
test('isValidCertId — valid 3-segment CST ID', () => {
  assert.ok(validation.isValidCertId('CST-12345-AB'));
});

test('isValidCertId — valid VAP ID with numeric suffix', () => {
  assert.ok(validation.isValidCertId('VAP-9999999-0126'));
});

test('isValidCertId — accepts long-enough middle and suffix', () => {
  assert.ok(validation.isValidCertId('CST-ABCDE-XY'));
  assert.ok(validation.isValidCertId('VAP-ABCDE12-XYZW'));
});

test('isValidCertId — rejects wrong prefix', () => {
  assert.ok(!validation.isValidCertId('XYZ-12345-AB'));
  assert.ok(!validation.isValidCertId('VAPT-12345-AB'));
});

test('isValidCertId — rejects middle segment under 5 chars', () => {
  assert.ok(!validation.isValidCertId('CST-1234-AB'));
});

test('isValidCertId — rejects suffix under 2 chars', () => {
  assert.ok(!validation.isValidCertId('CST-12345-A'));
});

test('isValidCertId — rejects lowercase letters', () => {
  assert.ok(!validation.isValidCertId('cst-12345-ab'));
});

test('isValidCertId — rejects IDs over 50 chars', () => {
  assert.ok(!validation.isValidCertId('CST-' + 'A'.repeat(48)));
});

test('isValidCertId — rejects null / undefined / empty', () => {
  assert.ok(!validation.isValidCertId(null));
  assert.ok(!validation.isValidCertId(undefined));
  assert.ok(!validation.isValidCertId(''));
  assert.ok(!validation.isValidCertId(123));
});

// ─────────────────────────────────────────────────────────────────────────────
// validation.isValidEmail
// ─────────────────────────────────────────────────────────────────────────────
test('isValidEmail — accepts standard emails', () => {
  assert.ok(validation.isValidEmail('user@example.com'));
  assert.ok(validation.isValidEmail('user+tag@example.co.uk'));
  assert.ok(validation.isValidEmail('a@b.c'));
});

test('isValidEmail — rejects malformed addresses', () => {
  assert.ok(!validation.isValidEmail('notanemail'));
  assert.ok(!validation.isValidEmail('@example.com'));
  assert.ok(!validation.isValidEmail('user@'));
  assert.ok(!validation.isValidEmail('user @example.com'));
  assert.ok(!validation.isValidEmail(''));
});

test('isValidEmail — rejects email over 254 chars', () => {
  assert.ok(!validation.isValidEmail('a'.repeat(245) + '@example.com'));
});

test('isValidEmail — rejects null / non-string', () => {
  assert.ok(!validation.isValidEmail(null));
  assert.ok(!validation.isValidEmail(undefined));
});

// ─────────────────────────────────────────────────────────────────────────────
// validation.isValidPassword  (min 12 chars + upper + lower + digit + special)
// ─────────────────────────────────────────────────────────────────────────────
test('isValidPassword — accepts strong password', () => {
  assert.ok(validation.isValidPassword('Admin@Test_123!'));
  assert.ok(validation.isValidPassword('Sup3r@Adm1n_Sec!'));
});

test('isValidPassword — rejects password under 12 chars', () => {
  assert.ok(!validation.isValidPassword('Short@1!'));
  assert.ok(!validation.isValidPassword('Ab@12345678')); // 11 chars
});

test('isValidPassword — rejects no uppercase', () => {
  assert.ok(!validation.isValidPassword('admin@test_123!'));
});

test('isValidPassword — rejects no lowercase', () => {
  assert.ok(!validation.isValidPassword('ADMIN@TEST_123!'));
});

test('isValidPassword — rejects no digit', () => {
  assert.ok(!validation.isValidPassword('Admin@TestNoDigit!'));
});

test('isValidPassword — rejects no special character', () => {
  assert.ok(!validation.isValidPassword('AdminTest123456'));
});

test('isValidPassword — rejects null / non-string', () => {
  assert.ok(!validation.isValidPassword(null));
  assert.ok(!validation.isValidPassword(123));
  assert.ok(!validation.isValidPassword(undefined));
});

// ─────────────────────────────────────────────────────────────────────────────
// validation.sanitize
// ─────────────────────────────────────────────────────────────────────────────
test('sanitize — escapes all five dangerous HTML characters', () => {
  assert.equal(
    validation.sanitize('<script>alert("xss")</script>'),
    '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;',
  );
  assert.equal(validation.sanitize("it's a & test"), "it&#x27;s a &amp; test");
  assert.equal(validation.sanitize('<>'), '&lt;&gt;');
  assert.equal(validation.sanitize('"quoted"'), '&quot;quoted&quot;');
});

test('sanitize — returns non-string inputs unchanged', () => {
  assert.equal(validation.sanitize(42), 42);
  assert.equal(validation.sanitize(null), null);
  assert.equal(validation.sanitize(undefined), undefined);
});

test('sanitize — leaves safe strings unmodified', () => {
  assert.equal(validation.sanitize('hello world'), 'hello world');
});

// ─────────────────────────────────────────────────────────────────────────────
// validation.isValidUrl
// ─────────────────────────────────────────────────────────────────────────────
test('isValidUrl — accepts valid URLs', () => {
  assert.ok(validation.isValidUrl('https://example.com'));
  assert.ok(validation.isValidUrl('http://localhost:3000/path?q=1'));
  assert.ok(validation.isValidUrl('ftp://files.example.org'));
});

test('isValidUrl — rejects non-URLs', () => {
  assert.ok(!validation.isValidUrl('not a url'));
  assert.ok(!validation.isValidUrl(''));
  assert.ok(!validation.isValidUrl('missing-scheme.com'));
  assert.ok(!validation.isValidUrl(null));
});

// ─────────────────────────────────────────────────────────────────────────────
// CircuitBreaker
// ─────────────────────────────────────────────────────────────────────────────
test('CircuitBreaker — starts in CLOSED state', () => {
  const cb = new CircuitBreaker({ failureThreshold: 2, timeout: 50 });
  assert.equal(cb.getStatus().state, 'CLOSED');
  assert.equal(cb.getStatus().failureCount, 0);
});

test('CircuitBreaker — opens after failureThreshold consecutive failures', async () => {
  const cb = new CircuitBreaker({ failureThreshold: 2, timeout: 100 });
  const fail = () => { throw new Error('boom'); };
  try { await cb.execute(fail, null); } catch { /* expected */ }
  assert.equal(cb.getStatus().state, 'CLOSED'); // still closed after 1 failure
  try { await cb.execute(fail, null); } catch { /* expected */ }
  assert.equal(cb.getStatus().state, 'OPEN');   // opens after threshold
});

test('CircuitBreaker — uses fallback while OPEN without throwing', async () => {
  const cb = new CircuitBreaker({ failureThreshold: 1, timeout: 200 });
  try { await cb.execute(() => { throw new Error(); }, null); } catch { /* expected */ }
  assert.equal(cb.getStatus().state, 'OPEN');
  const result = await cb.execute(() => { throw new Error('still broken'); }, () => 'fallback');
  assert.equal(result, 'fallback');
});

test('CircuitBreaker — throws when OPEN and no fallback provided', async () => {
  const cb = new CircuitBreaker({ failureThreshold: 1, timeout: 200 });
  try { await cb.execute(() => { throw new Error(); }, null); } catch { /* expected */ }
  await assert.rejects(() => cb.execute(() => {}, null), /Circuit breaker is OPEN/);
});

test('CircuitBreaker — transitions OPEN → HALF_OPEN → CLOSED on success', async () => {
  const cb = new CircuitBreaker({ failureThreshold: 1, successThreshold: 1, timeout: 30 });
  try { await cb.execute(() => { throw new Error(); }, null); } catch { /* expected */ }
  assert.equal(cb.getStatus().state, 'OPEN');
  await new Promise(r => setTimeout(r, 40)); // wait past timeout
  await cb.execute(async () => 'ok', null);
  assert.equal(cb.getStatus().state, 'CLOSED');
});

test('CircuitBreaker — success resets failure count when CLOSED', async () => {
  const cb = new CircuitBreaker({ failureThreshold: 3, timeout: 100 });
  try { await cb.execute(() => { throw new Error(); }, null); } catch { /* expected */ }
  assert.equal(cb.getStatus().failureCount, 1);
  await cb.execute(async () => 'ok', null); // success resets
  assert.equal(cb.getStatus().failureCount, 0);
});

// ─────────────────────────────────────────────────────────────────────────────
// createSecurityService — hashPassword
// ─────────────────────────────────────────────────────────────────────────────
test('hashPassword — returns a non-empty hex string', async () => {
  const hash = await sec.hashPassword('Admin@Test_123!');
  assert.match(hash, /^[0-9a-f]+$/);
  assert.ok(hash.length >= 32);
});

test('hashPassword — is deterministic (same key material, same password)', async () => {
  const [h1, h2] = await Promise.all([
    sec.hashPassword('Admin@Test_123!'),
    sec.hashPassword('Admin@Test_123!'),
  ]);
  assert.equal(h1, h2);
});

test('hashPassword — different passwords produce different hashes', async () => {
  const [h1, h2] = await Promise.all([
    sec.hashPassword('Admin@Test_123!'),
    sec.hashPassword('Admin@Other_456!'),
  ]);
  assert.notEqual(h1, h2);
});

// ─────────────────────────────────────────────────────────────────────────────
// createSecurityService — issueToken / verifyToken
// ─────────────────────────────────────────────────────────────────────────────
test('issueToken — returns a 3-part dot-separated string', () => {
  const token = sec.issueToken('admin');
  assert.equal(token.split('.').length, 3);
});

test('verifyToken — returns payload with correct subject for valid token', () => {
  const token = sec.issueToken('test_user');
  const payload = sec.verifyToken(token);
  assert.ok(payload);
  assert.equal(payload.sub, 'test_user');
  assert.ok(typeof payload.jti === 'string');
  assert.ok(payload.exp > Math.floor(Date.now() / 1000));
});

test('verifyToken — returns null for tampered signature', () => {
  const token = sec.issueToken('admin');
  const [h, b, s] = token.split('.');
  const sigBytes = Buffer.from(s, 'base64url');
  sigBytes[0] ^= 0xff; // flip one byte
  const tampered = `${h}.${b}.${sigBytes.toString('base64url')}`;
  assert.equal(sec.verifyToken(tampered), null);
});

test('verifyToken — returns null for expired token', () => {
  const nowS = Math.floor(Date.now() / 1000);
  const payload = { sub: 'admin', iat: nowS - 100, exp: nowS - 1, jti: 'x' };
  const header  = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body    = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig     = crypto.createHmac('sha256', KEYS.jwtSecret).update(`${header}.${body}`).digest('base64url');
  assert.equal(sec.verifyToken(`${header}.${body}.${sig}`), null);
});

test('verifyToken — returns null for malformed / empty inputs', () => {
  assert.equal(sec.verifyToken(null), null);
  assert.equal(sec.verifyToken(''), null);
  assert.equal(sec.verifyToken('only.two'), null);
  assert.equal(sec.verifyToken('a.b.c.d'), null);
});

// ─────────────────────────────────────────────────────────────────────────────
// createSecurityService — encryptCertToken / decryptCertToken
// ─────────────────────────────────────────────────────────────────────────────
test('encryptCertToken + decryptCertToken — full round-trip', () => {
  const certId = 'CST-9999999-0126';
  const token  = sec.encryptCertToken(certId);
  assert.ok(typeof token === 'string' && token.length > 0);
  assert.equal(sec.decryptCertToken(token), certId);
});

test('decryptCertToken — each encrypted token is unique (random IV)', () => {
  const certId = 'CST-12345-AB';
  const t1 = sec.encryptCertToken(certId);
  const t2 = sec.encryptCertToken(certId);
  assert.notEqual(t1, t2);                    // different ciphertext (random IV)
  assert.equal(sec.decryptCertToken(t1), certId);
  assert.equal(sec.decryptCertToken(t2), certId);
});

test('decryptCertToken — returns null for invalid / truncated input', () => {
  assert.equal(sec.decryptCertToken('notvalid'), null);
  assert.equal(sec.decryptCertToken(null), null);
  assert.equal(sec.decryptCertToken(''), null);
  assert.equal(sec.decryptCertToken('AAAA'), null); // too short
});

// ─────────────────────────────────────────────────────────────────────────────
// createSecurityService — signCertUrl / verifyCertUrlSignature
// ─────────────────────────────────────────────────────────────────────────────
test('signCertUrl + verifyCertUrlSignature — valid signature is accepted', () => {
  const token = sec.encryptCertToken('CST-12345-AB');
  const sig   = sec.signCertUrl(token);
  assert.ok(sec.verifyCertUrlSignature(token, sig));
});

test('verifyCertUrlSignature — rejects wrong signature of same length', () => {
  const token = sec.encryptCertToken('CST-12345-AB');
  const sig   = sec.signCertUrl(token);
  // Same length, all-zero bytes
  const wrong = Buffer.alloc(sig.length, 0x41).toString(); // 'AAA...'
  if (wrong !== sig) assert.ok(!sec.verifyCertUrlSignature(token, wrong));
});

test('verifyCertUrlSignature — rejects null / missing signature', () => {
  const token = sec.encryptCertToken('CST-12345-AB');
  assert.ok(!sec.verifyCertUrlSignature(token, null));
  assert.ok(!sec.verifyCertUrlSignature(token, ''));
});

test('buildCertUrl — returns URL containing token and signature', () => {
  const url = sec.buildCertUrl('CST-12345-AB', 'https://example.com');
  assert.ok(url.startsWith('https://example.com'));
  assert.ok(url.includes('/cert/'));
  assert.ok(url.includes('?s='));
});

// ─────────────────────────────────────────────────────────────────────────────
// retryWithBackoff
// ─────────────────────────────────────────────────────────────────────────────
test('retryWithBackoff — succeeds on first attempt', async () => {
  let calls = 0;
  const result = await retryWithBackoff(async () => { calls++; return 'ok'; }, 3, 1);
  assert.equal(result, 'ok');
  assert.equal(calls, 1);
});

test('retryWithBackoff — retries and eventually succeeds', async () => {
  let calls = 0;
  const result = await retryWithBackoff(async () => {
    calls++;
    if (calls < 3) throw new Error('not ready');
    return 'done';
  }, 3, 1);
  assert.equal(result, 'done');
  assert.equal(calls, 3);
});

test('retryWithBackoff — throws original error after max attempts', async () => {
  let calls = 0;
  await assert.rejects(
    () => retryWithBackoff(async () => { calls++; throw new Error('always fails'); }, 3, 1),
    { message: 'always fails' },
  );
  assert.equal(calls, 3);
});

// ─────────────────────────────────────────────────────────────────────────────
// createErrorResponse
// ─────────────────────────────────────────────────────────────────────────────
test('createErrorResponse — returns structured object with status and error', () => {
  const r = createErrorResponse(400, 'INVALID_INPUT', 'Bad request', { field: 'email' });
  assert.equal(r.status, 400);
  assert.equal(r.error.code, 'INVALID_INPUT');
  assert.equal(r.error.message, 'Bad request');
  assert.equal(r.error.field, 'email');
});

test('createErrorResponse — works without extra details', () => {
  const r = createErrorResponse(500, 'SERVER_ERROR', 'Internal error');
  assert.equal(r.status, 500);
  assert.equal(r.error.code, 'SERVER_ERROR');
  assert.equal(r.error.message, 'Internal error');
});
