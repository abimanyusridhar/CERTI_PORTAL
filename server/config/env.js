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
  if (!adminUser || !adminPass) {
    errors.push('ADMIN_USER and ADMIN_PASS must be set');
  } else {
    // Enforce strong admin password: min 12 chars, uppercase, lowercase, digit, special char
    const passOk = adminPass.length >= 12 &&
                   /[A-Z]/.test(adminPass) &&
                   /[a-z]/.test(adminPass) &&
                   /[0-9]/.test(adminPass) &&
                   /[^A-Za-z0-9]/.test(adminPass);
    if (!passOk) errors.push('ADMIN_PASS must be at least 12 characters and include uppercase, lowercase, digit, and special character');
  }
  if (!cfg || !cfg.routes || !cfg.routes.cst || !cfg.routes.vpt || !cfg.routes.cstAdmin || !cfg.routes.vptAdmin) {
    errors.push('App config routes are missing required values');
  }
  return { ok: errors.length === 0, errors };
}

module.exports = { loadDotEnv, validateRuntimeConfig };
