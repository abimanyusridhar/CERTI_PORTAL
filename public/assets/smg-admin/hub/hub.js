'use strict';

(function () {
  var API = '/api';
  // Read SSO cookie if present (hub page may be landing target after SSO redirect)
  (function () {
    var m = document.cookie.match(/(?:^|;\s*)sso_admin_token=([^;]+)/);
    if (m) {
      sessionStorage.setItem('adminToken', decodeURIComponent(m[1]));
      document.cookie = 'sso_admin_token=; Path=/; Max-Age=0; SameSite=Strict';
    }
  })();
  var TOKEN = sessionStorage.getItem('adminToken') || '';

  function applyConfig() {
    var C = window.APP_CONFIG;
    if (!C) return;
    var bn = document.getElementById('hubBrandName');
    if (bn) bn.textContent = C.brand.name;
    var cstAdminLink = document.getElementById('cstAdminLink');
    if (cstAdminLink) cstAdminLink.href = (C.routes.cstAdmin || '/CST/misecure') + '/';
    var vaptAdminLink = document.getElementById('vaptAdminLink');
    if (vaptAdminLink) vaptAdminLink.href = (C.routes.vaptAdmin || '/VAPT/misecure') + '/';
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
    var hubLinkSuperAdmin = document.getElementById('hubLinkSuperAdmin');
    if (hubLinkSuperAdmin) hubLinkSuperAdmin.href = (C.routes.cstAdmin || '/CST/misecure') + '/superadmin/';
    var hubLinkDocsEl = document.getElementById('hubLinkDocs');
    if (hubLinkDocsEl) hubLinkDocsEl.href = (C.routes.cstAdmin || '/CST/misecure') + '/documents/';
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
    fetch('/api/ses-status', { signal: timeout2 })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var dot = document.getElementById('mailDot');
        var lbl = document.getElementById('mailLabel');
        var ok = d && d.configured;
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
    var next = window.location.pathname + window.location.search.replace(/[?&]sso_error=1/, '');
    if (!next || next === '/') next = (C && C.routes && C.routes.cstAdmin) ? C.routes.cstAdmin + '/' : '/CST/misecure/';
    window.location.replace('/auth/sso/login?next=' + encodeURIComponent(next));
  }

  var _ssoError = /[?&]sso_error=1/.test(window.location.search);

  function loadStats() {
    if (!TOKEN) {
      if (_ssoError) {
        // Show error without redirect loop
        setStatsFallback();
        var hero = document.querySelector('.hub-hero-sub');
        if (hero) { hero.textContent = 'SSO sign-in failed. Please contact your administrator or try again.'; hero.style.color = 'var(--invalid,#ff6b8a)'; }
        return;
      }
      redirectToSso();
      return;
    }
    try {
      var parts = TOKEN.split('.');
      if (parts.length !== 3) { sessionStorage.removeItem('adminToken'); TOKEN = ''; redirectToSso(); return; }
      var payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
      if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp * 1000) {
        sessionStorage.removeItem('adminToken');
        TOKEN = '';
        redirectToSso();
        return;
      }
    } catch (e) { sessionStorage.removeItem('adminToken'); TOKEN = ''; redirectToSso(); return; }

    var headers = { Authorization: 'Bearer ' + TOKEN };

    Promise.all([
      fetch(API + '/certs', { headers: headers }).then(function (r) { return r.ok ? r.json() : []; }).catch(function () { return []; }),
      fetch(API + '/vapt/certs', { headers: headers }).then(function (r) { return r.ok ? r.json() : []; }).catch(function () { return []; }),
      fetch(API + '/docs', { headers: headers }).then(function (r) { return r.ok ? r.json() : []; }).catch(function () { return []; }),
      fetch(API + '/docs/access-requests', { headers: headers }).then(function (r) { return r.ok ? r.json() : []; }).catch(function () { return []; })
    ]).then(function (results) {
      var cst = results[0], vapt = results[1], docs = results[2], reqs = results[3];

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
      setText('reqPending',  reqs.filter(function(r) { return r.status === 'PENDING'; }).length);
      setText('reqApproved', reqs.filter(function(r) { return r.status === 'APPROVED'; }).length);
    });

    // User & group stats use the same Bearer admin token
    Promise.all([
      fetch(API + '/admin/users',  { headers: headers }).then(function(r){ return r.ok ? r.json() : []; }).catch(function(){ return []; }),
      fetch(API + '/admin/groups', { headers: headers }).then(function(r){ return r.ok ? r.json() : []; }).catch(function(){ return []; })
    ]).then(function(res) {
      var uArr = Array.isArray(res[0]) ? res[0] : Object.values(res[0] || {});
      var gArr = Array.isArray(res[1]) ? res[1] : Object.values(res[1] || {});
      var vessels = new Set();
      gArr.forEach(function(g) { (g.vesselIMOs || []).forEach(function(i) { vessels.add(i); }); });
      setText('saUserCount',   uArr.length);
      setText('saGroupCount',  gArr.length);
      setText('saVesselCount', vessels.size);
    });
  }

  checkHealth();
  loadStats();
  setInterval(checkHealth, 30000);
})();
