'use strict';

function createMetrics() {
  const startedAt = Date.now();
  const counters = {
    requestsTotal: 0,
    requests2xx: 0,
    requests4xx: 0,
    requests5xx: 0,
    inFlight: 0,
  };
  const routeStats = new Map();

  function _bucket(pathname) {
    if (!pathname) return 'unknown';
    if (pathname.startsWith('/api')) return '/api/*';
    if (pathname.startsWith('/uploads/')) return '/uploads/*';
    return pathname;
  }

  function begin(req) {
    counters.requestsTotal++;
    counters.inFlight++;
    req._startTs = Date.now();
  }

  function end(req, statusCode) {
    counters.inFlight = Math.max(0, counters.inFlight - 1);
    if (statusCode >= 500) counters.requests5xx++;
    else if (statusCode >= 400) counters.requests4xx++;
    else if (statusCode >= 200) counters.requests2xx++;

    const pathname = req && req.url ? (new URL(req.url, 'http://localhost')).pathname : '';
    const key = `${req.method || 'GET'} ${_bucket(pathname)}`;
    const prev = routeStats.get(key) || { count: 0, totalMs: 0, maxMs: 0 };
    const ms = req && req._startTs ? Date.now() - req._startTs : 0;
    prev.count++;
    prev.totalMs += ms;
    prev.maxMs = Math.max(prev.maxMs, ms);
    routeStats.set(key, prev);
  }

  function snapshot() {
    const routes = {};
    for (const [k, v] of routeStats.entries()) {
      routes[k] = { count: v.count, avgMs: v.count ? Math.round(v.totalMs / v.count) : 0, maxMs: v.maxMs };
    }
    return {
      uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
      counters: { ...counters },
      routes,
    };
  }

  return { begin, end, snapshot };
}

module.exports = { createMetrics };
