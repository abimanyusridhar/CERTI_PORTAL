'use strict';

// Performance smoke test — NOT a full load/stress/soak suite (no k6-style ramping,
// spike, or endurance scenarios). It answers one narrow question automatically on every
// run: "under a short concurrent burst, does the live server stay error-free and fast?"
// See docs/qa-assessment-report.md — Performance testing was previously "20/100, not
// automated, no load/stress tooling exists". This closes the "no tooling at all" gap
// without overclaiming full performance-engineering coverage.
//
// Run: node server/tests/perf/smoke.js  (or `npm run test:perf`)

const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const autocannon = require('autocannon');

const ROOT = path.join(__dirname, '..', '..', '..');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');
const PORT = 3427;
const BASE_URL = `http://127.0.0.1:${PORT}`;

// Every public route in this app is behind a per-IP rate limiter (server/index.js
// RATE_LIMITS: 'verify' 30/min, 'default' 120/min) — a real, deliberate abuse defense,
// already proven to engage under burst by integration-security-edge.test.js. A single
// -source autocannon burst WILL cross those budgets almost immediately, so a flood of
// 429s here is the limiter working correctly, not a performance defect. What a burst
// like this must never do is hang, time out, or 500 — that's what these thresholds
// actually gate; 429 volume is reported for visibility, not treated as failure.
const THRESHOLDS = {
  p99Ms: 500, // generous local-loopback ceiling — catches gross regressions, not tail-latency tuning
};

function waitForHealth(timeoutMs = 12000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    (function poll() {
      const req = http.get(`${BASE_URL}/api/health`, (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve();
        retry();
      });
      req.on('error', retry);
      function retry() {
        if (Date.now() - start > timeoutMs) return reject(new Error('Server did not become healthy in time'));
        setTimeout(poll, 250);
      }
    })();
  });
}

function runScenario(name, url) {
  return autocannon({
    url,
    connections: 10,
    duration: 5,
    title: name,
  });
}

function checkResult(name, result) {
  const failures = [];
  const errorCount = result.errors + result.timeouts;
  if (errorCount > 0) failures.push(`${errorCount} transport errors/timeouts (expected 0 — server must never hang or drop a connection)`);
  if (result['5xx'] > 0) failures.push(`${result['5xx']} 5xx responses (expected 0 — a rate-limited request must 429 cleanly, never crash the handler)`);
  if (result.latency.p99 > THRESHOLDS.p99Ms) {
    failures.push(`p99 latency ${result.latency.p99}ms exceeds ${THRESHOLDS.p99Ms}ms threshold`);
  }

  console.log(`\n[${name}]`);
  console.log(`  requests: ${result.requests.total} (${result.requests.average}/sec avg)`);
  console.log(`  latency:  avg=${result.latency.average}ms p99=${result.latency.p99}ms max=${result.latency.max}ms`);
  console.log(`  status:   2xx=${result['2xx']} 4xx=${result['4xx']} (rate-limited; expected under burst) 5xx=${result['5xx']} transport-errors=${errorCount}`);
  console.log(`  result:   ${failures.length ? 'FAIL' : 'PASS'}`);
  failures.forEach((f) => console.log(`    - ${f}`));

  return failures;
}

async function main() {
  const tenantId = 'tenant_perf_smoke';
  const child = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      BASE_ORIGIN: BASE_URL,
      ADMIN_USER: 'admin_perf',
      ADMIN_PASS: 'Admin@Perf_Test_123!',
      TENANT_ID: tenantId,
      LOG_LEVEL: 'silent',
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  });

  let stderr = '';
  child.stderr.on('data', (d) => { stderr += d.toString(); });

  let exitCode = 0;
  try {
    await waitForHealth();

    const scenarios = [
      ['GET /api/health', `${BASE_URL}/api/health`],
      ['GET /api/verify-by-id/:id (seeded, public)', `${BASE_URL}/api/verify-by-id/CST-9623740-01-26`],
    ];

    for (const [name, url] of scenarios) {
      const result = await runScenario(name, url);
      const failures = checkResult(name, result);
      if (failures.length) exitCode = 1;
    }
  } catch (err) {
    console.error('Performance smoke test errored:', err.message);
    if (stderr) console.error('Server stderr:\n' + stderr);
    exitCode = 1;
  } finally {
    child.kill();
  }

  process.exit(exitCode);
}

main();
