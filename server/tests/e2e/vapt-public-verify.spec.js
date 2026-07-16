'use strict';

const { test, expect } = require('@playwright/test');

// Real DOM/form interaction against the VAPT public verify page (public/vapt-index.html).
// Seeded cert: VAP-9491666-1026 (see VAPT_SEED in server/index.js).

test.describe('VAPT public verify page', () => {
  test('rejects a malformed certificate number with an inline error', async ({ page }) => {
    await page.goto('/vapt-index.html');
    await page.fill('#certInput', 'bad id!!');
    await page.click('#verifyBtn');

    await expect(page.locator('#result')).toContainText('Invalid Format');
  });

  test('reports a well-formed but unknown certificate as not found', async ({ page }) => {
    await page.goto('/vapt-index.html');
    await page.fill('#certInput', 'VAP-0000000-0000');
    await page.click('#verifyBtn');

    await expect(page.locator('#result')).toContainText('Not Found', { timeout: 15000 });
  });

  test('renders a seeded certificate on successful verification', async ({ page }) => {
    await page.goto('/vapt-index.html');
    await page.fill('#certInput', 'VAP-9491666-1026');
    await page.click('#verifyBtn');

    const result = page.locator('#result');
    await expect(result).toContainText('Efficiency OL', { timeout: 15000 });
    await expect(result).toContainText('9491666');
  });
});
