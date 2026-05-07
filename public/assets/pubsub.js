/**
 * PSP — Publisher / Subscriber / Principal
 * Global event bus + identity context for all admin and public pages.
 * Exposed as window.PSP
 */
(function () {
  'use strict';

  const _subs = {};
  let _principal = null;

  const TOPICS = Object.freeze({
    AUTH_LOGIN:        'auth:login',
    AUTH_LOGOUT:       'auth:logout',
    CERTS_REFRESHED:   'certs:refreshed',
    CERT_SAVED:        'cert:saved',
    CERT_DELETED:      'cert:deleted',
    EMAIL_SENT:        'email:sent',
    SESSION_WARN:      'session:warn',
    SESSION_EXPIRED:   'session:expired',
    HEALTH_UPDATED:    'health:updated',
    NAV_PAGE_CHANGED:  'nav:pageChanged',
  });

  function subscribe(topic, fn) {
    if (!_subs[topic]) _subs[topic] = [];
    _subs[topic].push(fn);
    return function unsubscribe() {
      _subs[topic] = (_subs[topic] || []).filter(f => f !== fn);
    };
  }

  function publish(topic, data) {
    (_subs[topic] || []).forEach(fn => {
      try { fn(data, topic); } catch (e) { /* subscriber errors must not break the bus */ }
    });
  }

  function setPrincipal(identity) {
    _principal = identity ? Object.assign({}, identity, { setAt: Date.now() }) : null;
    publish(TOPICS.AUTH_LOGIN, _principal);
    _updatePrincipalBadge();
  }

  function getPrincipal() {
    return _principal ? Object.assign({}, _principal) : null;
  }

  function createPublisher(namespace) {
    return {
      publish: function (event, data) {
        publish(namespace + ':' + event, data);
      },
      subscribe: function (event, fn) {
        return subscribe(namespace + ':' + event, fn);
      },
    };
  }

  function _updatePrincipalBadge() {
    const el = document.getElementById('pspPrincipalBadge');
    if (!el) return;
    if (_principal && _principal.username) {
      el.textContent = _principal.username;
      el.style.display = 'inline-flex';
    } else {
      el.style.display = 'none';
    }
  }

  window.PSP = { TOPICS, subscribe, publish, setPrincipal, getPrincipal, createPublisher };
})();
