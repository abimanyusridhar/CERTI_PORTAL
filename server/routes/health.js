'use strict';

const fs = require('fs');
const os = require('os');

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
    dataFilePath,
    vaptDataFilePath,
  } = deps;

  // Check if a file/directory is readable and writable
  function checkFileSystem(filePath) {
    try {
      if (!filePath) return { ok: false, error: 'Path not provided' };
      if (!fs.existsSync(filePath)) {
        // Try to create parent directory
        const dir = require('path').dirname(filePath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        return { ok: true, writable: true, exists: false };
      }
      const stat = fs.statSync(filePath);
      // Check permissions
      try {
        fs.accessSync(filePath, fs.constants.R_OK | fs.constants.W_OK);
        return { ok: true, writable: true, exists: true, size: stat.isFile() ? stat.size : null };
      } catch {
        return { ok: false, error: 'Permission denied', exists: true };
      }
    } catch (err) {
      return { ok: false, error: err && err.message ? err.message : String(err) };
    }
  }

  // Get memory usage
  function getMemoryStatus() {
    const mem = process.memoryUsage();
    return {
      rss: `${Math.round(mem.rss / 1024 / 1024)}MB`,
      heapUsed: `${Math.round(mem.heapUsed / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(mem.heapTotal / 1024 / 1024)}MB`,
      external: `${Math.round(mem.external / 1024 / 1024)}MB`,
    };
  }

  return function handleHealth(req, res, route, method, origin) {
    if (route !== '/health' || method !== 'GET') return false;
    if (route === '/health-detailed' || method !== 'GET') return false;
    
    const corsH = corsHeadersForOrigin(origin || '');
    const cstCerts = Object.values(getCstCerts());
    const vaptCerts = Object.values(getVaptCerts());
    const maintenance = cfg.maintenance || {};
    const isDetailed = req.url && req.url.includes('detailed');

    const basicHealth = {
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
    };

    // Add detailed information if requested
    if (isDetailed) {
      const cstFilesystem = checkFileSystem(dataFilePath);
      const vaptFilesystem = checkFileSystem(vaptDataFilePath);
      const memory = getMemoryStatus();
      
      basicHealth.detailed = {
        services: {
          database: {
            cst: cstFilesystem,
            vapt: vaptFilesystem,
          },
          ses: {
            configured: sesEnabled,
            status: sesEnabled ? 'ready' : 'not_configured',
          },
        },
        system: {
          memory,
          cpus: os.cpus().length,
          platform: os.platform(),
          nodeVersion: process.version,
        },
        environment: {
          logLevel: process.env.LOG_LEVEL || 'info',
          port: process.env.PORT || '3000',
          tenantMode: process.env.TENANT_ID ? 'enabled' : 'disabled',
        },
        checks: {
          filesystem: cstFilesystem.ok && vaptFilesystem.ok,
          memory: parseInt(memory.heapUsed) < 500, // Alert if > 500MB
          ses: sesEnabled, // Not actually checking AWS connectivity
        },
      };
    }

    if (metricsSnapshot) {
      basicHealth.metrics = metricsSnapshot();
    }

    sendJSON(res, 200, basicHealth, corsH);
    return true;
  };
}

module.exports = { createHealthRoute };
