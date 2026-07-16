'use strict';

const path = require('node:path');

const PORT = 3425;
const TENANT_ID = 'tenant_e2e_fixed';

// Playwright's own config loader isn't allowed to use Date.now()/Math.random()-derived
// state across reruns — a fixed tenant id keeps the seeded data (CST-9623740-01-26,
// VAP-9491666-1026) stable and reused between local runs instead of piling up tenant dirs.

module.exports = {
  testDir: path.join(__dirname, 'server', 'tests', 'e2e'),
  timeout: 30000,
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `node "${path.join(__dirname, 'server', 'index.js')}"`,
    cwd: __dirname,
    port: PORT,
    reuseExistingServer: false,
    timeout: 20000,
    env: {
      PORT: String(PORT),
      BASE_ORIGIN: `http://127.0.0.1:${PORT}`,
      ADMIN_USER: 'admin_e2e',
      ADMIN_PASS: 'Admin@E2E_Test_123!',
      TENANT_ID,
      LOG_LEVEL: 'silent',
    },
  },
};
