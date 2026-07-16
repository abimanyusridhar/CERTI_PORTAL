'use strict';
// ── SSO: read short-lived cookie set by /auth/sso/callback ─────────────────
(function () {
  var match = document.cookie.match(/(?:^|;\s*)sso_admin_token=([^;]+)/);
  if (match) {
    sessionStorage.setItem('adminToken', decodeURIComponent(match[1]));
    document.cookie = 'sso_admin_token=; Path=/; Max-Age=0; SameSite=Lax';
  }
  var ssoErr = new URLSearchParams(location.search).get('sso_error');
  if (ssoErr) {
    var el = document.getElementById('ssoErrMsg');
    if (el) {
      var SSO_MSGS = {
        deactivated:     'Your account has been deactivated. Contact your administrator.',
        not_enrolled:    'Your account is not registered in this portal. Ask your administrator to add you.',
        auth_failed:     'Authentication failed. Please try again or contact your administrator.',
        session_expired: 'Your login session expired. Please try again.'
      };
      el.textContent = SSO_MSGS[ssoErr] || 'SSO sign-in failed. Please check your AWS account or try again.';
      el.style.display = 'block';
    }
  }
})();
