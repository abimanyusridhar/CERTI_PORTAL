'use strict';

(function () {
  var API = '/api';
  // Clear the short-lived SSO handoff cookie if present (hub page may be the
  // landing target after an SSO redirect) — its value is never persisted to
  // sessionStorage; admin auth relies solely on the httpOnly adminToken cookie.
  (function () {
    if (document.cookie.indexOf('sso_admin_token=') !== -1) {
      document.cookie = 'sso_admin_token=; Path=/; Max-Age=0; SameSite=Lax';
    }
  })();
  var TOKEN = sessionStorage.getItem('adminToken') || '';

  function applyConfig() {
    var C = window.APP_CONFIG;
    if (!C) return;
    var bn = document.getElementById('hubBrandName');
    if (bn) bn.textContent = C.brand.name;
    var cstAdminLink = document.getElementById('cstAdminLink');
    if (cstAdminLink) cstAdminLink.href = (C.routes.cstAdmin || '/console/cst') + '/';
    var vaptAdminLink = document.getElementById('vaptAdminLink');
    if (vaptAdminLink) vaptAdminLink.href = (C.routes.vptAdmin || '/console/vapt') + '/';
    var cstPortalLink = document.getElementById('cstPortalLink');
    if (cstPortalLink) cstPortalLink.href = C.routes.cst || '/CST';
    var vaptPortalLink = document.getElementById('vaptPortalLink');
    if (vaptPortalLink) vaptPortalLink.href = C.routes.vpt || '/VAPT';
    var pubCstLink = document.getElementById('pubCstLink');
    if (pubCstLink) pubCstLink.href = C.routes.cst || '/CST';
    var pubVaptLink = document.getElementById('pubVaptLink');
    if (pubVaptLink) pubVaptLink.href = C.routes.vpt || '/VAPT';
    var pubCstUrl = document.getElementById('pubCstUrl');
    if (pubCstUrl) pubCstUrl.textContent = C.routes.cst || '/CST';
    var pubVaptUrl = document.getElementById('pubVaptUrl');
    if (pubVaptUrl) pubVaptUrl.textContent = C.routes.vpt || '/VAPT';
    var ft = document.getElementById('hubFooterText');
    if (ft) ft.innerHTML = C.brand.name + ' &middot; Cyber Security &amp; Compliance Division';
  }

  document.addEventListener('appconfigready', applyConfig);
  if (window.APP_CONFIG) applyConfig();

  function checkHealth() {
    var timeout = typeof AbortSignal !== 'undefined' && AbortSignal.timeout
      ? AbortSignal.timeout(5000) : undefined;

    fetch('/health', { signal: timeout })
      .then(function (r) {
        var dot = document.getElementById('serverDot');
        var lbl = document.getElementById('serverLabel');
        if (dot) dot.style.background = r.ok ? 'var(--teal)' : 'var(--warn)';
        if (lbl) lbl.textContent = r.ok ? 'Online' : 'Degraded';
      })
      .catch(function () {
        var dot = document.getElementById('serverDot');
        var lbl = document.getElementById('serverLabel');
        if (dot) dot.style.background = 'var(--invalid)';
        if (lbl) lbl.textContent = 'Offline';
      });

    var timeout2 = typeof AbortSignal !== 'undefined' && AbortSignal.timeout
      ? AbortSignal.timeout(5000) : undefined;
    fetch('/api/ses-status', { signal: timeout2, headers: TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {} })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var dot = document.getElementById('mailDot');
        var lbl = document.getElementById('mailLabel');
        var ok = d && d.enabled;
        if (dot) dot.style.background = ok ? 'var(--teal)' : 'var(--warn)';
        if (lbl) lbl.textContent = ok ? 'Mail Ready' : 'Mail Unconfigured';
      })
      .catch(function () {
        var dot = document.getElementById('mailDot');
        if (dot) dot.style.background = 'var(--border)';
      });
  }

  function countValid(list) {
    var now = new Date();
    return list.filter(function (c) {
      var st = (c.status || 'VALID').toUpperCase();
      var vu = c.validUntil ? new Date(c.validUntil) : null;
      return st === 'VALID' && (!vu || vu >= now);
    }).length;
  }

  function countExpired(list) {
    var now = new Date();
    return list.filter(function (c) {
      var st = (c.status || 'VALID').toUpperCase();
      var vu = c.validUntil ? new Date(c.validUntil) : null;
      return st === 'EXPIRED' || (st !== 'PENDING' && st !== 'REVOKED' && vu && vu < now);
    }).length;
  }

  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function setStatsFallback() {
    ['statTotalCst','statTotalVapt','statActiveCst','statActiveVapt',
     'cstTotal','cstValid','cstExpired','vaptTotal','vaptValid','vaptExpired'].forEach(function (id) {
      setText(id, '—');
    });
  }

  function redirectToSso() {
    var C = window.APP_CONFIG;
    var next = window.location.pathname + window.location.search.replace(/[?&]sso_error=[^&]*/, '');
    if (!next || next === '/') next = (C && C.routes && C.routes.cstAdmin) ? C.routes.cstAdmin + '/' : '/console/cst/';
    window.location.replace('/auth/sso/login?next=' + encodeURIComponent(next));
  }

  // Same codes the admin dashboards' SSO_MSGS map — keep these in sync.
  var SSO_MSGS = {
    deactivated:     'Your account has been deactivated. Contact your administrator.',
    not_enrolled:    'Your account is not registered in this portal. Ask your administrator to add you.',
    auth_failed:     'Authentication failed. Please try again or contact your administrator.',
    session_expired: 'Your login session expired. Please try again.'
  };
  var _ssoErrorCode = (window.location.search.match(/[?&]sso_error=([^&]*)/) || [])[1];
  var _ssoError = !!_ssoErrorCode;

  function doLogout() {
    // POST /api/auth/logout revokes the session server-side (jti blacklist)
    // and clears the httpOnly adminToken cookie — the actual session
    // credential — not just hidden client-side. Then reload; the page is
    // server-gated (gateAdminPage), so a reload while unauthenticated
    // 302-redirects to the admin login screen on its own.
    fetch('/api/auth/logout', { method: 'POST' }).catch(() => {}).finally(() => {
      window.location.reload();
    });
  }
  window.doLogout = doLogout;

  function loadStats() {
    if (_ssoError) {
      // Show the specific reason without looping back into another SSO attempt
      setStatsFallback();
      var hero = document.querySelector('.hub-hero-sub');
      if (hero) { hero.textContent = SSO_MSGS[_ssoErrorCode] || 'SSO sign-in failed. Please contact your administrator or try again.'; hero.style.color = 'var(--invalid,#FF5C7A)'; }
      return;
    }
    // Session identity/expiry now comes from the server (httpOnly cookie-backed
    // /api/auth/verify) instead of decoding a raw JWT out of sessionStorage —
    // nothing JS-readable holds a valid session credential any more.
    fetch(API + '/auth/verify')
      .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
      .then(function (info) {
        document.documentElement.classList.toggle('role-client', info.role === 'client');
        loadStatsAuthenticated();
      })
      .catch(function () { redirectToSso(); });
  }

  function loadStatsAuthenticated() {
    var headers = TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {};

    Promise.all([
      fetch(API + '/certs', { headers: headers }).then(function (r) { return r.ok ? r.json() : []; }).catch(function () { return []; }),
      fetch(API + '/vapt/certs', { headers: headers }).then(function (r) { return r.ok ? r.json() : []; }).catch(function () { return []; }),
      fetch(API + '/docs', { headers: headers }).then(function (r) { return r.ok ? r.json() : []; }).catch(function () { return []; })
    ]).then(function (results) {
      var cst = results[0], vapt = results[1], docs = results[2];

      setText('statTotalCst', cst.length);
      setText('statTotalVapt', vapt.length);
      setText('statActiveCst', countValid(cst));
      setText('statActiveVapt', countValid(vapt));

      setText('cstTotal',   cst.length);
      setText('cstValid',   countValid(cst));
      setText('cstExpired', countExpired(cst));

      setText('vaptTotal',   vapt.length);
      setText('vaptValid',   countValid(vapt));
      setText('vaptExpired', countExpired(vapt));

      setText('docTotal',    docs.length);
    });
  }

  checkHealth();
  loadStats();
  setInterval(checkHealth, 30000);
})();
