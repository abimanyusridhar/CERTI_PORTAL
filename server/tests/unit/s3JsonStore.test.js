'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createS3JsonStore } = require('../../repositories/s3JsonStore');

const DEBOUNCE = 60_000;

// s3.getJson/putJson/S3_ENABLED are read via property access at call time in
// s3JsonStore.js, so mutating the shared module object here is picked up.
function withMockedS3({ getJson, putJson } = {}) {
  const s3 = require('../../services/s3');
  const originalGetJson = s3.getJson;
  const originalPutJson = s3.putJson;
  const originalEnabled = s3.S3_ENABLED;
  const putCalls = [];
  s3.getJson = getJson || (async () => { throw new Error('NoSuchKey'); });
  s3.putJson = putJson || (async (key, data) => { putCalls.push({ key, data }); });
  s3.S3_ENABLED = true;
  return {
    putCalls,
    restore() { s3.getJson = originalGetJson; s3.putJson = originalPutJson; s3.S3_ENABLED = originalEnabled; },
  };
}
function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

test('s3JsonStore - init pulls the current object from S3 into cache', async () => {
  const mock = withMockedS3({ getJson: async () => ({ fromRemote: true }) });
  try {
    const store = createS3JsonStore({ s3Key: 'data/test.json', seedData: { seed: true }, debounceMs: DEBOUNCE });
    await store.init();
    assert.deepEqual(store.load(), { fromRemote: true });
  } finally {
    mock.restore();
  }
});

test('s3JsonStore - init falls back to seedData when the S3 key does not exist yet', async () => {
  const mock = withMockedS3({ getJson: async () => { throw new Error('NoSuchKey'); } });
  try {
    const store = createS3JsonStore({ s3Key: 'data/test.json', seedData: { seed: true }, debounceMs: DEBOUNCE });
    await store.init();
    assert.deepEqual(store.load(), { seed: true });
  } finally {
    mock.restore();
  }
});

test('s3JsonStore - save updates the in-memory cache immediately, then debounces a PUT to S3', async () => {
  const mock = withMockedS3({ getJson: async () => { throw new Error('NoSuchKey'); } });
  try {
    const store = createS3JsonStore({ s3Key: 'data/test.json', seedData: {}, debounceMs: 20 });
    await store.init();
    store.save({ persisted: true });
    assert.deepEqual(store.load(), { persisted: true }); // cache updates synchronously
    assert.equal(mock.putCalls.length, 0); // PUT not sent yet — still debouncing
    await wait(40);
    assert.equal(mock.putCalls.length, 1);
    assert.deepEqual(mock.putCalls[0], { key: 'data/test.json', data: { persisted: true } });
  } finally {
    mock.restore();
  }
});

test('s3JsonStore - flush forces the pending save immediately and resolves once S3 confirms', async () => {
  const mock = withMockedS3({ getJson: async () => { throw new Error('NoSuchKey'); } });
  try {
    const store = createS3JsonStore({ s3Key: 'data/test.json', seedData: {}, debounceMs: DEBOUNCE });
    await store.init();
    store.save({ persisted: true });
    await store.flush();
    assert.equal(mock.putCalls.length, 1);
    assert.deepEqual(mock.putCalls[0].data, { persisted: true });
  } finally {
    mock.restore();
  }
});

test('s3JsonStore - flush is a no-op when there is no cache yet', async () => {
  const mock = withMockedS3();
  try {
    const store = createS3JsonStore({ s3Key: 'data/test.json', seedData: {}, debounceMs: DEBOUNCE });
    await store.flush();
    assert.equal(mock.putCalls.length, 0);
  } finally {
    mock.restore();
  }
});

test('s3JsonStore - load() before init() returns seed immediately, then self-corrects once the S3 pull resolves', async () => {
  const mock = withMockedS3({ getJson: async () => ({ fromRemote: true }) });
  try {
    const store = createS3JsonStore({ s3Key: 'data/test.json', seedData: { seed: true }, debounceMs: DEBOUNCE });
    assert.deepEqual(store.load(), { seed: true }); // synchronous — no await
    await wait(10); // let the background pullFromS3() promise resolve
    assert.deepEqual(store.load(), { fromRemote: true });
  } finally {
    mock.restore();
  }
});

// ─── Background refresh (multi-instance correctness) ─────────────────────────

test('s3JsonStore - background refresh picks up new remote data while idle', async () => {
  let getCalls = 0;
  const mock = withMockedS3({
    getJson: async () => {
      getCalls += 1;
      // First call is init()'s own pull; subsequent calls are the background refresh.
      return getCalls === 1 ? { fromInit: true } : { fromRemote: true };
    },
  });
  try {
    const store = createS3JsonStore({ s3Key: 'data/test.json', seedData: {}, debounceMs: DEBOUNCE, refreshIntervalMs: 15 });
    await store.init();
    assert.deepEqual(store.load(), { fromInit: true });
    await wait(40); // let at least one background refresh tick fire
    assert.deepEqual(store.load(), { fromRemote: true });
    store.stopBackgroundRefresh();
  } finally {
    mock.restore();
  }
});

test('s3JsonStore - background refresh never clobbers a pending local write', async () => {
  const mock = withMockedS3({ getJson: async () => ({ staleRemote: true }) });
  try {
    const store = createS3JsonStore({ s3Key: 'data/test.json', seedData: {}, debounceMs: 500, refreshIntervalMs: 15 });
    await store.init();
    store.save({ localWrite: true }); // dirty=true, debounce pending for 500ms
    await wait(40); // background refresh ticks at least twice while the write is still pending
    assert.deepEqual(store.load(), { localWrite: true }, 'stale remote data must not overwrite a pending local write');
    store.stopBackgroundRefresh();
    await store.flush();
  } finally {
    mock.restore();
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
