'use strict';

const { test, expect } = require('@playwright/test');

// Real DOM/form interaction against the CST public verify page (public/index.html),
// driven through an actual browser against the live spawned server (see playwright.config.js).
// Seeded cert: CST-9623740-01-26 (see SEED in server/index.js).

test.describe('CST public verify page', () => {
  test('rejects a malformed certificate number with an inline error', async ({ page }) => {
    await page.goto('/');
    await page.fill('#certInput', 'bad id!!');
    await page.click('#verifyBtn');

    await expect(page.locator('#result')).toContainText('Invalid Format');
  });

  test('reports a well-formed but unknown certificate as not found', async ({ page }) => {
    await page.goto('/');
    await page.fill('#certInput', 'CST-0000000-99-99');
    await page.click('#verifyBtn');

    await expect(page.locator('#result')).toContainText('Certificate Not Found', { timeout: 15000 });
  });

  test('renders a seeded certificate on successful verification', async ({ page }) => {
    await page.goto('/');
    await page.fill('#certInput', 'CST-9623740-01-26');
    await page.click('#verifyBtn');

    const result = page.locator('#result');
    await expect(result).toContainText('NORD KUDU', { timeout: 15000 });
    await expect(result).toContainText('9623740');
  });

  test('Enter key in the search field submits the same as clicking Verify', async ({ page }) => {
    await page.goto('/');
    await page.fill('#certInput', 'CST-9623740-01-26');
    await page.press('#certInput', 'Enter');

    await expect(page.locator('#result')).toContainText('NORD KUDU', { timeout: 15000 });
  });
});
