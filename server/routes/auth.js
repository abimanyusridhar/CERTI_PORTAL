'use strict';

const crypto = require('crypto');

function createAuthRoutes(deps) {
  const {
    sendJSON,
    getBody,
    authCheck,
    checkRateLimit,
    checkLoginLockout,
    recordLoginFailure,
    clearLoginFailures,
    hashPassword,
    issueToken,
    getAdminUser,
    getAdminPassHash,
    serverReadyRef,
  } = deps;

  async function handleLogin(req, res, method, route, ip, corsH) {
    if (!(route === '/auth/login' && method === 'POST')) return false;
    if (!serverReadyRef()) {
      sendJSON(res, 503, { error: 'Server is starting up, please try again in a moment.' }, corsH);
      return true;
    }
    const lockout = checkLoginLockout(ip);
    if (lockout.locked) {
      sendJSON(res, 429, { error: 'Too many failed login attempts. Try again later.' }, { 'Retry-After': String(lockout.retryAfter), ...corsH });
      return true;
    }
    const rl = checkRateLimit(ip, 'login');
    if (!rl.ok) {
      sendJSON(res, 429, { error: 'Too many login attempts. Try again later.' }, { 'Retry-After': String(rl.retryAfter), ...corsH });
      return true;
    }
    let body;
    try {
      body = JSON.parse(await getBody(req));
    } catch {
      sendJSON(res, 400, { error: 'Invalid JSON' }, corsH);
      return true;
    }
    const { username, password } = body;
    const usernameMatch = typeof username === 'string' && username === getAdminUser();
    const passwordHash = await hashPassword(password || '');
    const hashA = Buffer.from(passwordHash);
    const hashB = Buffer.from(getAdminPassHash());
    const passwordMatch = hashA.length === hashB.length && crypto.timingSafeEqual(hashA, hashB);
    if (!usernameMatch || !passwordMatch) {
      recordLoginFailure(ip);
      await new Promise((r) => setTimeout(r, 200 + Math.random() * 200));
      sendJSON(res, 401, { error: 'Invalid credentials' }, corsH);
      return true;
    }
    clearLoginFailures(ip);
    sendJSON(res, 200, { token: issueToken(username) }, corsH);
    return true;
  }

  function handleVerify(req, res, method, route, corsH) {
    if (!(route === '/auth/verify' && method === 'GET')) return false;
    if (!authCheck(req)) {
      sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
      return true;
    }
    sendJSON(res, 200, { ok: true }, corsH);
    return true;
  }

  return {
    handleLogin,
    handleVerify,
  };
}

module.exports = { createAuthRoutes };
