'use strict';

const { test, expect } = require('@playwright/test');

// Real browser navigation against the admin hub. Unlike dashboard.html/vapt-dashboard.html
// (which embed their own login UI and must stay reachable unauthenticated), admin/index.html
// is server-side gated: server/index.js's gateAdminPage() checks authCheck(req) before ever
// sending the hub file, and 302s an unauthenticated request straight to the CST admin login
// page (server/index.js:4149-4156). This is enforced before any client JS runs.

test.describe('Admin hub — unauthenticated access', () => {
  test('server-side redirects an unauthenticated hub request to the admin login page', async ({ page }) => {
    await page.goto('/CST/misecure/hub');

    expect(new URL(page.url()).pathname).toBe('/CST/misecure/');
    await expect(page.locator('#loginTitle')).toHaveText('Admin Access');
  });

  test('never renders hub content (stats, user table) for an unauthenticated visitor', async ({ page }) => {
    await page.goto('/CST/misecure/hub');

    // The redirected-to page is the login screen, not the hub — hub-only elements
    // (e.g. the live user stats table) must not exist in the DOM at all.
    await expect(page.locator('#uStatTotal')).toHaveCount(0);
    await expect(page.locator('#userTbody')).toHaveCount(0);
  });

  test('the SSO sign-in link on the login page points at the real SSO route', async ({ page }) => {
    await page.goto('/CST/misecure/hub');

    const ssoBtn = page.locator('#ssoBtn');
    await expect(ssoBtn).toBeVisible();
    await expect(ssoBtn).toHaveAttribute('href', /^\/auth\/sso\/login\?next=/);
  });
});
