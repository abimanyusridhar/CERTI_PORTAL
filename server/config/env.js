'use strict';

const fs = require('fs');
const path = require('path');

function loadDotEnv(log, serverDir) {
  const envPaths = [
    path.join(serverDir, '.env'),
    path.join(serverDir, '..', '.env'),
  ];
  for (const envFile of envPaths) {
    if (!fs.existsSync(envFile)) continue;
    const lines = fs.readFileSync(envFile, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx < 1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      let val = trimmed.slice(eqIdx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (process.env[key] === undefined) process.env[key] = val;
    }
    if (log) log.info('Configuration loaded from', envFile);
    break;
  }
}

function validateRuntimeConfig({ port, adminUser, adminPass, cfg }) {
  const errors = [];
  if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push('PORT must be a valid integer between 1 and 65535');
  if (!adminUser || !adminPass) errors.push('ADMIN_USER and ADMIN_PASS must be set');
  if (!cfg || !cfg.routes || !cfg.routes.cst || !cfg.routes.vpt || !cfg.routes.cstAdmin || !cfg.routes.vptAdmin) {
    errors.push('App config routes are missing required values');
  }
  return { ok: errors.length === 0, errors };
}

module.exports = { loadDotEnv, validateRuntimeConfig };
