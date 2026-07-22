'use strict';

function createAuthRoutes(deps) {
  const {
    sendJSON,
    authCheck,
    verifyToken,
    revokeToken,
  } = deps;

  // ── POST /api/auth/login ── DECOMMISSIONED (admin panel is SSO-only now)
  function handleLogin(req, res, method, route, ip, corsH) {
    if (!(route === '/auth/login' && method === 'POST')) return false;
    sendJSON(res, 410, { error: 'Password login has been removed. Sign in with AWS SSO.' }, corsH);
    return true;
  }

  // Returns role/exp/iat alongside the liveness check so the client never needs
  // to decode a raw JWT itself — used for the boot-time role check, expiry
  // countdown, and the "Extend Session" button. Bearer-or-cookie extraction
  // mirrors handleLogout below; authCheck() already covers the revocation-list
  // check, so re-decoding the same token here for its fields is race-free.
  function handleVerify(req, res, method, route, corsH) {
    if (!(route === '/auth/verify' && method === 'GET')) return false;
    if (!authCheck(req)) {
      sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
      return true;
    }
    let token = null;
    const auth = req.headers['authorization'] || '';
    if (auth.startsWith('Bearer ')) token = auth.slice(7);
    if (!token) {
      const m = (req.headers.cookie || '').match(/(?:^|;\s*)adminToken=([^;]+)/);
      if (m) token = decodeURIComponent(m[1]);
    }
    const payload = (token && verifyToken(token)) || {};
    sendJSON(res, 200, { ok: true, role: payload.role || 'admin', exp: payload.exp, iat: payload.iat }, corsH);
    return true;
  }

  async function handleLogout(req, res, method, route, corsH) {
    if (!(route === '/auth/logout' && method === 'POST')) return false;
    // Revoke current session token server-side
    let token = null;
    const auth = req.headers['authorization'] || '';
    if (auth.startsWith('Bearer ')) token = auth.slice(7);
    if (!token) {
      const m = (req.headers.cookie || '').match(/(?:^|;\s*)adminToken=([^;]+)/);
      if (m) token = decodeURIComponent(m[1]);
    }
    if (token && revokeToken) {
      const payload = verifyToken(token);
      if (payload && payload.jti) revokeToken(payload.jti, payload.exp * 1000);
    }
    sendJSON(res, 200, { ok: true }, {
      'Set-Cookie': [
        'adminToken=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0',
        'sso_admin_token=; Path=/; SameSite=Lax; Max-Age=0',
        'csrfToken=; SameSite=Lax; Path=/; Max-Age=0',
      ],
      ...corsH,
    });
    return true;
  }

  return { handleLogin, handleVerify, handleLogout };
}

module.exports = { createAuthRoutes };
