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

  function handleVerify(req, res, method, route, corsH) {
    if (!(route === '/auth/verify' && method === 'GET')) return false;
    if (!authCheck(req)) {
      sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
      return true;
    }
    sendJSON(res, 200, { ok: true }, corsH);
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
        'adminToken=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
        'sso_admin_token=; Path=/; SameSite=Strict; Max-Age=0',
      ],
      ...corsH,
    });
    return true;
  }

  return { handleLogin, handleVerify, handleLogout };
}

module.exports = { createAuthRoutes };
