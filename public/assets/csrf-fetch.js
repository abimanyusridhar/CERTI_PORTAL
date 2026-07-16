'use strict';
/**
 * Patches window.fetch (once) so every same-origin, cookie-authenticated admin
 * mutation automatically carries the X-CSRF-Token header expected by the
 * server-side double-submit check (server/index.js: csrfCheckFails). Centralizing
 * this here means new admin fetch() call sites are protected for free — no
 * per-call-site header wiring needed.
 *
 * Must load before any script that calls fetch() for an admin API mutation
 * (i.e. before shared-utils.js / dashboard.js / hub.js).
 */
(function () {
  if (window.__csrfFetchPatched) return;
  window.__csrfFetchPatched = true;

  const MUTATING = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

  function readCookie(name) {
    const m = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
    return m ? decodeURIComponent(m[1]) : null;
  }

  function isSameOrigin(url) {
    try {
      return new URL(url, window.location.href).origin === window.location.origin;
    } catch {
      return false;
    }
  }

  const originalFetch = window.fetch.bind(window);

  window.fetch = function (input, init) {
    const method = ((init && init.method) || (input instanceof Request ? input.method : 'GET') || 'GET').toUpperCase();
    const url = input instanceof Request ? input.url : input;

    if (MUTATING.has(method) && isSameOrigin(url)) {
      const csrfToken = readCookie('csrfToken');
      if (csrfToken) {
        const headers = new Headers((init && init.headers) || (input instanceof Request ? input.headers : undefined));
        headers.set('X-CSRF-Token', csrfToken);
        init = Object.assign({}, init, { headers });
      }
    }

    return originalFetch(input, init);
  };
})();
