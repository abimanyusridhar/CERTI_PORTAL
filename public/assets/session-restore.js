'use strict';
// Restores a still-valid sessionStorage-held admin session on page load.
// TOKEN and initApp() are globals defined by the page's own dashboard.js,
// already loaded by the time this script runs (script tags execute in order).
(function () {
  var tok = sessionStorage.getItem('adminToken');
  if (!tok) return;
  try {
    var parts = tok.split('.');
    if (parts.length !== 3) return;
    var payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
    if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp * 1000) {
      sessionStorage.removeItem('adminToken'); return;
    }
    document.getElementById('loginWrap').style.display = 'none';
    document.getElementById('appWrap').style.display = 'flex';
    TOKEN = tok;
    initApp();
  } catch (e) { sessionStorage.removeItem('adminToken'); }
})();
