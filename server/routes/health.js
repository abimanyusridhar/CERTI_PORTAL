'use strict';

const os = require('os');

function createHealthRoute(deps) {
  const {
    sendJSON,
    corsHeadersForOrigin,
    cfg,
    sesEnabled,
    serverStartTime,
    serverReadyRef,
    shuttingDownRef,
    metricsSnapshot,
    authCheck,
    checkRateLimit,
  } = deps;

  function getMemoryStatus() {
    const mem = process.memoryUsage();
    return {
      rss:       `${Math.round(mem.rss       / 1024 / 1024)}MB`,
      heapUsed:  `${Math.round(mem.heapUsed  / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(mem.heapTotal / 1024 / 1024)}MB`,
    };
  }

  return function handleHealth(req, res, route, method, origin, ip) {
    if (method !== 'GET') return false;
    const isDetailed = route === '/health-detailed';
    if (route !== '/health' && !isDetailed) return false;

    // Rate-limit the public health endpoint
    if (checkRateLimit && ip) {
      const rl = checkRateLimit(ip, 'default');
      if (!rl.ok) {
        sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, corsHeadersForOrigin(origin || ''));
        return true;
      }
    }

    // Detailed endpoint requires admin auth
    if (isDetailed && authCheck && !authCheck(req)) {
      sendJSON(res, 401, { error: 'Access denied.' }, corsHeadersForOrigin(origin || ''));
      return true;
    }

    const corsH       = corsHeadersForOrigin(origin || '');
    const maintenance = cfg.maintenance || {};

    const body = {
      ok:          true,
      status:      shuttingDownRef() ? 'shutting_down' : (serverReadyRef() ? 'operational' : 'starting'),
      uptime:      Math.floor((Date.now() - serverStartTime) / 1000),
      timestamp:   new Date().toISOString(),
      version:     cfg.version || '1.0.0',
      maintenance: maintenance.enabled || false,
    };

    if (isDetailed) {
      const memory = getMemoryStatus();
      body.detailed = {
        ses:    { configured: sesEnabled },
        memory: { heapUsed: memory.heapUsed, heapTotal: memory.heapTotal, heapOk: parseInt(memory.heapUsed) < 500 },
      };
      // Route-level traffic metrics disclose internal route structure and live
      // request volumes — only ever returned on the authenticated detailed view,
      // never on the public /api/health endpoint.
      if (metricsSnapshot) body.metrics = metricsSnapshot();
    }

    sendJSON(res, 200, body, corsH);
    return true;
  };
}

module.exports = { createHealthRoute };
