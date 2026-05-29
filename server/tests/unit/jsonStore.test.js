'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('node:fs');
const os     = require('node:os');
const path   = require('node:path');
const { createJsonStore } = require('../../repositories/jsonStore');

// Use a long debounce so the async timer never fires during tests;
// we always call flush() to write synchronously and cancel the timer.
const DEBOUNCE = 60_000;

function tmpPath() {
  return path.join(os.tmpdir(), `synergy-store-test-${Date.now()}-${Math.random().toString(16).slice(2)}.json`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Seed data fallback
// ─────────────────────────────────────────────────────────────────────────────
test('jsonStore — load returns seedData when file does not exist', () => {
  const fp   = tmpPath();
  const seed = { key: 'seed-value' };
  const store = createJsonStore({ filePath: fp, seedData: seed, debounceMs: DEBOUNCE });
  try {
    const data = store.load();
    assert.deepEqual(data, seed);
  } finally {
    store.flush(); // cancel debounce timer and write synchronously
    try { fs.unlinkSync(fp); } catch { /* ok */ }
  }
});

test('jsonStore — load returns empty object when no seed provided and file missing', () => {
  const fp    = tmpPath();
  const store = createJsonStore({ filePath: fp, debounceMs: DEBOUNCE });
  try {
    const data = store.load();
    assert.deepEqual(data, {});
  } finally {
    store.flush();
    try { fs.unlinkSync(fp); } catch { /* ok */ }
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Save updates in-memory cache
// ─────────────────────────────────────────────────────────────────────────────
test('jsonStore — save updates the in-memory cache immediately', () => {
  const fp    = tmpPath();
  const store = createJsonStore({ filePath: fp, seedData: {}, debounceMs: DEBOUNCE });
  store.load();
  store.save({ updated: true });
  const data = store.load();
  assert.equal(data.updated, true);
  store.flush();
  try { fs.unlinkSync(fp); } catch { /* ok */ }
});

// ─────────────────────────────────────────────────────────────────────────────
// Flush writes synchronously
// ─────────────────────────────────────────────────────────────────────────────
test('jsonStore — flush writes data to disk synchronously', () => {
  const fp    = tmpPath();
  const store = createJsonStore({ filePath: fp, seedData: {}, debounceMs: DEBOUNCE });
  store.load();
  store.save({ persisted: 'yes' });
  store.flush();
  const written = JSON.parse(fs.readFileSync(fp, 'utf8'));
  assert.equal(written.persisted, 'yes');
  fs.unlinkSync(fp);
});

test('jsonStore — flush is a no-op when no pending save', () => {
  const fp    = tmpPath();
  const store = createJsonStore({ filePath: fp, seedData: {}, debounceMs: DEBOUNCE });
  assert.doesNotThrow(() => store.flush()); // no load/save yet — must not throw
  try { fs.unlinkSync(fp); } catch { /* ok */ }
});

// ─────────────────────────────────────────────────────────────────────────────
// Persistence across store instances
// ─────────────────────────────────────────────────────────────────────────────
test('jsonStore — data written by flush is readable by a new store instance', () => {
  const fp     = tmpPath();
  const store1 = createJsonStore({ filePath: fp, seedData: {}, debounceMs: DEBOUNCE });
  store1.load();
  store1.save({ hello: 'world', count: 42 });
  store1.flush(); // writes synchronously, cancels debounce timer

  const store2 = createJsonStore({ filePath: fp, seedData: { fallback: true }, debounceMs: DEBOUNCE });
  const data   = store2.load();
  assert.equal(data.hello, 'world');
  assert.equal(data.count, 42);
  assert.ok(!('fallback' in data), 'seed must not overwrite existing file');
  store2.flush();
  fs.unlinkSync(fp);
});

// ─────────────────────────────────────────────────────────────────────────────
// Caching: load is served from cache after first read
// ─────────────────────────────────────────────────────────────────────────────
test('jsonStore — subsequent load() calls return the cached result without re-reading file', () => {
  const fp = tmpPath();
  fs.writeFileSync(fp, JSON.stringify({ initial: true }), 'utf8');
  const store = createJsonStore({ filePath: fp, seedData: {}, debounceMs: DEBOUNCE });

  const first = store.load();
  assert.equal(first.initial, true);

  // Modify file on disk directly (simulating an external write)
  fs.writeFileSync(fp, JSON.stringify({ changed: true }), 'utf8');

  // Second load must return cached data, not re-read the file
  const second = store.load();
  assert.equal(second.initial, true);
  assert.ok(!second.changed, 'cache must not re-read file after first load');
  fs.unlinkSync(fp);
});

// ─────────────────────────────────────────────────────────────────────────────
// Error handling
// ─────────────────────────────────────────────────────────────────────────────
test('jsonStore — load falls back to seed when file contains invalid JSON', () => {
  const fp    = tmpPath();
  fs.writeFileSync(fp, 'NOT_VALID_JSON!!!', 'utf8');
  const seed  = { fallback: true };
  const store = createJsonStore({ filePath: fp, seedData: seed, debounceMs: DEBOUNCE });
  const data  = store.load();
  assert.equal(data.fallback, true);
  store.flush();
  fs.unlinkSync(fp);
});
