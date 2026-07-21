'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createS3JsonStore } = require('../../repositories/s3JsonStore');

const DEBOUNCE = 60_000;

function tmpPath() {
  return path.join(os.tmpdir(), `synergy-s3-store-test-${Date.now()}-${Math.random().toString(16).slice(2)}.json`);
}

test('s3JsonStore - init uses local disk when present', async () => {
  const fp = tmpPath();
  fs.writeFileSync(fp, JSON.stringify({ fromDisk: true }), 'utf8');
  const store = createS3JsonStore({ filePath: fp, s3Key: 'data/test.json', seedData: { seed: true }, debounceMs: DEBOUNCE });
  await store.init();
  assert.deepEqual(store.load(), { fromDisk: true });
  await store.flush();
  fs.unlinkSync(fp);
});

test('s3JsonStore - init falls back to seed when no disk and S3 disabled', async () => {
  const fp = tmpPath();
  const store = createS3JsonStore({ filePath: fp, s3Key: 'data/test.json', seedData: { seed: true }, debounceMs: DEBOUNCE });
  await store.init();
  assert.deepEqual(store.load(), { seed: true });
  await store.flush();
  assert.deepEqual(JSON.parse(fs.readFileSync(fp, 'utf8')), { seed: true });
  fs.unlinkSync(fp);
});

test('s3JsonStore - load strips UTF-8 BOM from disk JSON', () => {
  const fp = tmpPath();
  fs.writeFileSync(fp, '\uFEFF' + JSON.stringify({ bom: true }), 'utf8');
  const store = createS3JsonStore({ filePath: fp, s3Key: 'data/test.json', seedData: {}, debounceMs: DEBOUNCE });
  assert.deepEqual(store.load(), { bom: true });
  fs.unlinkSync(fp);
});

test('s3JsonStore - save updates cache immediately and flush creates parent directory', async () => {
  const dir = path.join(os.tmpdir(), `synergy-s3-store-dir-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  const fp = path.join(dir, 'nested', 'store.json');
  const store = createS3JsonStore({ filePath: fp, s3Key: 'data/test.json', seedData: {}, debounceMs: DEBOUNCE });
  store.save({ persisted: true });
  assert.deepEqual(store.load(), { persisted: true });
  await store.flush();
  assert.deepEqual(JSON.parse(fs.readFileSync(fp, 'utf8')), { persisted: true });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('s3JsonStore - invalid disk JSON falls back to seed', () => {
  const fp = tmpPath();
  fs.writeFileSync(fp, '{not-json', 'utf8');
  const store = createS3JsonStore({ filePath: fp, s3Key: 'data/test.json', seedData: { fallback: true }, debounceMs: DEBOUNCE });
  assert.deepEqual(store.load(), { fallback: true });
  store.flush();
  fs.unlinkSync(fp);
});

// ─── Background refresh (multi-instance correctness) ─────────────────────────
// s3.getJson/s3.S3_ENABLED are read via property access at call time in
// s3JsonStore.js, so mutating the shared module object here is picked up —
// same technique as dynamoStore.test.js's dynamodb.query mocking.
function withMockedS3Get(impl) {
  const s3 = require('../../services/s3');
  const originalGetJson = s3.getJson;
  const originalEnabled = s3.S3_ENABLED;
  s3.getJson = impl;
  s3.S3_ENABLED = true;
  return {
    restore() { s3.getJson = originalGetJson; s3.S3_ENABLED = originalEnabled; },
  };
}
function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

test('s3JsonStore - background refresh picks up new remote data while idle', async () => {
  const fp = tmpPath();
  // Disk present so init() takes the "fromDisk" branch and never calls S3 —
  // the only way { fromRemote: true } can end up in cache is the background poll.
  fs.writeFileSync(fp, JSON.stringify({ fromDisk: true }), 'utf8');
  const mock = withMockedS3Get(async () => ({ fromRemote: true }));
  try {
    const store = createS3JsonStore({ filePath: fp, s3Key: 'data/test.json', seedData: {}, debounceMs: DEBOUNCE, refreshIntervalMs: 15 });
    await store.init();
    assert.deepEqual(store.load(), { fromDisk: true });
    await wait(40); // let at least one background refresh tick fire
    assert.deepEqual(store.load(), { fromRemote: true });
    store.stopBackgroundRefresh();
  } finally {
    mock.restore();
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  }
});

test('s3JsonStore - background refresh never clobbers a pending local write', async () => {
  const fp = tmpPath();
  const mock = withMockedS3Get(async () => ({ staleRemote: true }));
  try {
    const store = createS3JsonStore({ filePath: fp, s3Key: 'data/test.json', seedData: {}, debounceMs: 500, refreshIntervalMs: 15 });
    await store.init();
    store.save({ localWrite: true }); // dirty=true, debounce pending for 500ms
    await wait(40); // background refresh ticks at least twice while the write is still pending
    assert.deepEqual(store.load(), { localWrite: true }, 'stale remote data must not overwrite a pending local write');
    store.stopBackgroundRefresh();
    await store.flush();
  } finally {
    mock.restore();
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  }
});

test('s3 service - public methods throw clear errors when S3 is disabled', async () => {
  const s3 = require('../../services/s3');
  assert.equal(s3.S3_ENABLED, false);
  await assert.rejects(() => s3.uploadFile('x.txt', Buffer.from('x'), 'text/plain'), /S3 not configured/);
  await assert.rejects(() => s3.downloadFile('x.txt'), /S3 not configured/);
  await assert.rejects(() => s3.deleteFile('x.txt'), /S3 not configured/);
  await assert.rejects(() => s3.putJson('x.json', { ok: true }), /S3 not configured/);
  await assert.rejects(() => s3.getJson('x.json'), /S3 not configured/);
});
