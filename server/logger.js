'use strict';

const fs = require('fs');
const path = require('path');

const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();
const _logLvl = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 }[LOG_LEVEL] ?? 1;
const USE_JSON_LOGS = process.env.LOG_FORMAT === 'json';
const AUDIT_LOG_ENABLED = process.env.AUDIT_LOGGING !== 'false';

// Audit log file path (tenant-aware if needed)
let AUDIT_LOG_FILE = path.join(__dirname, '..', 'data', 'audit.jsonl');

function setAuditLogFile(filePath) {
  AUDIT_LOG_FILE = filePath;
}

function _ts() {
  return new Date().toISOString();
}

function _shortTs() {
  return new Date().toISOString().slice(11, 23);
}

function _formatMessage(level, reqId, args) {
  if (USE_JSON_LOGS) {
    const msg = args.map(a => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ');
    return JSON.stringify({
      ts: _ts(),
      level,
      reqId: reqId || null,
      msg
    });
  } else {
    const reqStr = reqId ? ` [req:${reqId}]` : '';
    return `${_shortTs()} [${level}]${reqStr} ${args.map(a => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ')}`;
  }
}

function withRequest(req, level, ...args) {
  const reqId = (req && req._reqId) || null;
  const formatted = _formatMessage(level, reqId, args);
  
  if (level === 'error') console.error(formatted);
  else if (level === 'warn') console.warn(formatted);
  else console.log(formatted);
}

/**
 * Log audit events (actions, login attempts, email sends, etc.)
 * These are persisted to audit.jsonl for compliance/security
 */
function auditLog(event, details = {}) {
  if (!AUDIT_LOG_ENABLED) return;
  
  const auditEntry = {
    ts: _ts(),
    event,
    ...details
  };
  
  try {
    fs.appendFileSync(AUDIT_LOG_FILE, JSON.stringify(auditEntry) + '\n', { encoding: 'utf8' });
  } catch (err) {
    if (_logLvl <= 3) {
      console.error(`${_shortTs()} [error] Failed to write audit log:`, err && err.message ? err.message : err);
    }
  }
}

/**
 * Log structured error with stack trace
 */
function errorWithStack(req, message, error) {
  const reqId = (req && req._reqId) || null;
  const stack = error && error.stack ? error.stack.split('\n').slice(0, 5).join(' | ') : '';
  const formatted = _formatMessage('error', reqId, [message, stack]);
  console.error(formatted);
}

const log = {
  // Basic logging
  info: (...a) => _logLvl <= 1 && withRequest(null, 'info', ...a),
  warn: (...a) => _logLvl <= 2 && withRequest(null, 'warn', ...a),
  error: (...a) => _logLvl <= 3 && withRequest(null, 'error', ...a),
  debug: (...a) => _logLvl <= 0 && withRequest(null, 'debug', ...a),
  
  // Request-based logging
  reqInfo: (req, ...a) => _logLvl <= 1 && withRequest(req, 'info', ...a),
  reqWarn: (req, ...a) => _logLvl <= 2 && withRequest(req, 'warn', ...a),
  reqError: (req, ...a) => _logLvl <= 3 && withRequest(req, 'error', ...a),
  reqDebug: (req, ...a) => _logLvl <= 0 && withRequest(req, 'debug', ...a),
  
  // Error with stack trace
  errorWithStack,
  
  // Audit logging
  auditLog,
  audit: auditLog,
  
  // Configuration
  setAuditLogFile,
  setJsonFormat: (enabled) => { USE_JSON_LOGS = enabled; },
};

module.exports = { log };
