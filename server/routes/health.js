'use strict';

function createHealthRoute(deps) {
  const {
    sendJSON,
    corsHeadersForOrigin,
    getCstCerts,
    getVaptCerts,
    cfg,
    sesEnabled,
    serverStartTime,
    serverReadyRef,
    shuttingDownRef,
    metricsSnapshot,
  } = deps;

  return function handleHealth(req, res, route, method, origin) {
    if (route !== '/health' || method !== 'GET') return false;
    const corsH = corsHeadersForOrigin(origin || '');
    const cstCerts = Object.values(getCstCerts());
    const vaptCerts = Object.values(getVaptCerts());
    const maintenance = cfg.maintenance || {};

    sendJSON(res, 200, {
      ok: true,
      status: shuttingDownRef() ? 'shutting_down' : (serverReadyRef() ? 'operational' : 'starting'),
      uptime: Math.floor((Date.now() - serverStartTime) / 1000),
      timestamp: new Date().toISOString(),
      version: cfg.version || '1.0.0',
      ses: sesEnabled,
      maintenance: maintenance.enabled || false,
      certs: { cst: cstCerts.length, vapt: vaptCerts.length },
      compliance: {
        standards: (cfg.compliance && cfg.compliance.standards) || '',
        dataRetentionYears: (cfg.compliance && cfg.compliance.dataRetentionYears) || 5,
      },
      metrics: metricsSnapshot ? metricsSnapshot() : undefined,
    }, corsH);
    return true;
  };
}

module.exports = { createHealthRoute };
