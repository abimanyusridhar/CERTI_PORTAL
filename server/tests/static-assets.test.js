'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

function assertFile(rel) {
  assert.ok(fs.existsSync(path.join(ROOT, rel)), `${rel} should exist`);
}

function resolveServedRef(rel) {
  if (rel === 'config.js') return 'config/app.config.js';
  if (rel.startsWith('assets/') || rel.startsWith('images/')) return `public/${rel}`;
  return rel;
}

test('static pages - public and admin entrypoints exist with expected app roots', () => {
  for (const rel of [
    'public/index.html',
    'public/vapt-index.html',
    'admin/dashboard.html',
    'admin/vapt-dashboard.html',
    'admin/index.html',
    'admin/portal.html',
  ]) {
    const html = read(rel);
    assert.match(html, /<html/i, `${rel} should be an HTML document`);
    assert.match(html, /<meta\s+name="viewport"/i, `${rel} should define responsive viewport`);
    assert.match(html, /<\/html>/i, `${rel} should close the document`);
  }
});

test('static pages - referenced first-party assets exist', () => {
  const htmlFiles = [
    'public/index.html',
    'public/vapt-index.html',
    'admin/dashboard.html',
    'admin/vapt-dashboard.html',
    'admin/index.html',
    'admin/portal.html',
  ];
  const refs = new Set();
  const attrRe = /\b(?:src|href)=["']([^"']+)["']/gi;

  for (const rel of htmlFiles) {
    const html = read(rel);
    let match;
    while ((match = attrRe.exec(html))) {
      const href = match[1];
      if (href.includes('${')) continue;
      if (/^(?:https?:|mailto:|tel:|#|data:|\/api\/|\/auth\/)/i.test(href)) continue;
      if (/^\/(?:CST|VAPT|VPT|admin|vapt-admin|cert|vapt-cert)(?:\/|$)/i.test(href)) continue;
      if (href.startsWith('/')) refs.add(resolveServedRef(href.slice(1).split('?')[0]));
      else refs.add(path.normalize(path.join(path.dirname(rel), href.split('?')[0])).replace(/\\/g, '/'));
    }
  }

  for (const rel of refs) {
    if (!rel || rel.endsWith('/')) continue;
    assertFile(rel);
  }
});

test('static pages - login and admin forms expose expected controls', () => {
  const cstAdmin = read('admin/dashboard.html');
  const vaptAdmin = read('admin/vapt-dashboard.html');
  const cstAdminJs = read('public/assets/smg-admin/cst/dashboard.js');
  const vaptAdminJs = read('public/assets/smg-admin/vapt/dashboard.js');
  const hub = read('admin/index.html');
  const portal = read('admin/portal.html');

  assert.match(cstAdmin, /api\/auth\/verify|auth\/sso\/login/i);
  assert.match(cstAdminJs, /API\s*\+\s*['"`]\/certs|\/api\/certs/i);
  assert.match(vaptAdminJs, /API\s*\+\s*['"`]\/vapt\/certs|\/api\/vapt\/certs/i);
  assert.match(hub, /admin\/users/i);
  assert.match(hub, /admin\/groups/i);
  assert.match(hub, /docs\/upload/i);
  assert.match(portal, /api\/supt\/vessels/i);
  assert.match(portal, /api\/docs\/by-vessel/i);
});

test('static assets - shared utility scripts define expected browser helpers', () => {
  const utils = read('public/assets/shared-utils.js');
  assert.match(utils, /function\s+isValidEmail/);
  assert.match(utils, /function\s+sanitize/);
  assert.match(utils, /async function\s+fetchWithTimeout/);
  assert.match(utils, /function\s+debounce/);
  assert.match(utils, /function\s+throttle/);

  const pubsub = read('public/assets/pubsub.js');
  assert.match(pubsub, /export function subscribe/);
  assert.match(pubsub, /export function publish/);
  assert.match(pubsub, /export function setPrincipal/);
});

test('static styles - responsive CSS contains mobile breakpoints and focus styles', () => {
  const shared = read('public/assets/shared-styles.css');
  const refinements = read('public/assets/responsive-refinements.css');
  assert.match(shared + refinements, /@media\s*\(/);
  assert.match(shared + refinements, /:focus|focus-visible/);
});
