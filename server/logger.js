'use strict';

const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();
const _logLvl = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 }[LOG_LEVEL] ?? 1;

function _ts() {
  return new Date().toISOString().slice(11, 23);
}

function withRequest(req, level, ...args) {
  const reqId = req && req._reqId ? ` [req:${req._reqId}]` : '';
  const prefix = `${_ts()} [${level}]${reqId}`;
  if (level === 'error') console.error(prefix, ...args);
  else if (level === 'warn') console.warn(prefix, ...args);
  else console.log(prefix, ...args);
}

const log = {
  info: (...a) => _logLvl <= 1 && withRequest(null, 'info', ...a),
  warn: (...a) => _logLvl <= 2 && withRequest(null, 'warn', ...a),
  error: (...a) => _logLvl <= 3 && withRequest(null, 'error', ...a),
  reqInfo: (req, ...a) => _logLvl <= 1 && withRequest(req, 'info', ...a),
  reqWarn: (req, ...a) => _logLvl <= 2 && withRequest(req, 'warn', ...a),
  reqError: (req, ...a) => _logLvl <= 3 && withRequest(req, 'error', ...a),
};

module.exports = { log };
