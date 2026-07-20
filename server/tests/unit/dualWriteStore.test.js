'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createDualWriteStore } = require('../../repositories/dualWriteStore');

function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

function fakeStore(initial) {
  let cache = initial;
  const calls = { init: 0, load: 0, save: [], flush: 0 };
  return {
    calls,
    async init() { calls.init += 1; },
    load() { calls.load += 1; return cache; },
    save(data) { calls.save.push(data); cache = data; },
    async flush() { calls.flush += 1; return 'flushed'; },
  };
}

test('dualWriteStore - init() initializes both primary and secondary', async () => {
  const primary = fakeStore({});
  const secondary = fakeStore({});
  const store = createDualWriteStore({ primary, secondary });
  await store.init();
  assert.equal(primary.calls.init, 1);
  assert.equal(secondary.calls.init, 1);
});

test('dualWriteStore - init() reports a secondary init failure via onError without throwing', async () => {
  const primary = fakeStore({});
  const secondary = { init: async () => { throw new Error('secondary down'); } };
  const errors = [];
  const store = createDualWriteStore({ primary, secondary, onError: (e) => errors.push(e.message) });
  await store.init();
  assert.equal(primary.calls.init, 1);
  assert.deepEqual(errors, ['secondary down']);
});

test('dualWriteStore - save() fans out to both stores', () => {
  const primary = fakeStore({});
  const secondary = fakeStore({});
  const store = createDualWriteStore({ primary, secondary });
  store.save({ a: 1 });
  assert.deepEqual(primary.calls.save, [{ a: 1 }]);
  assert.deepEqual(secondary.calls.save, [{ a: 1 }]);
});

test('dualWriteStore - save() reports a synchronous secondary failure via onError, primary still saved', () => {
  const primary = fakeStore({});
  const secondary = { save: () => { throw new Error('secondary write failed'); } };
  const errors = [];
  const store = createDualWriteStore({ primary, secondary, onError: (e) => errors.push(e.message) });
  store.save({ a: 1 });
  assert.deepEqual(primary.calls.save, [{ a: 1 }]);
  assert.deepEqual(errors, ['secondary write failed']);
});

test('dualWriteStore - load() without shadowRead only reads primary', async () => {
  const primary = fakeStore({ from: 'primary' });
  const secondary = fakeStore({ from: 'secondary' });
  const store = createDualWriteStore({ primary, secondary, shadowRead: false });
  const data = store.load();
  assert.deepEqual(data, { from: 'primary' });
  await wait(10);
  assert.equal(secondary.calls.load, 0);
});

test('dualWriteStore - load() with shadowRead background-diffs secondary and reports mismatches', async () => {
  const primary = fakeStore({ from: 'primary' });
  const secondary = fakeStore({ from: 'secondary' });
  const mismatches = [];
  const store = createDualWriteStore({
    primary, secondary, shadowRead: true,
    onMismatch: (m) => mismatches.push(m),
  });
  const data = store.load();
  assert.deepEqual(data, { from: 'primary' }); // caller always gets primary synchronously
  await wait(10);
  assert.equal(secondary.calls.load, 1);
  assert.deepEqual(mismatches, [{ primary: { from: 'primary' }, secondary: { from: 'secondary' } }]);
});

test('dualWriteStore - load() with shadowRead and matching data reports no mismatch', async () => {
  const primary = fakeStore({ same: true });
  const secondary = fakeStore({ same: true });
  const mismatches = [];
  const store = createDualWriteStore({ primary, secondary, shadowRead: true, onMismatch: (m) => mismatches.push(m) });
  store.load();
  await wait(10);
  assert.deepEqual(mismatches, []);
});

test('dualWriteStore - load() with shadowRead reports secondary.load() throwing via onError', async () => {
  const primary = fakeStore({ ok: true });
  const secondary = { load: () => { throw new Error('secondary read failed'); } };
  const errors = [];
  const store = createDualWriteStore({ primary, secondary, shadowRead: true, onError: (e) => errors.push(e.message) });
  store.load();
  await wait(10);
  assert.deepEqual(errors, ['secondary read failed']);
});

test('dualWriteStore - flush() awaits both stores and reports a secondary failure without rejecting', async () => {
  const primary = fakeStore({});
  const secondary = { flush: async () => { throw new Error('secondary flush failed'); } };
  const errors = [];
  const store = createDualWriteStore({ primary, secondary, onError: (e) => errors.push(e.message) });
  await store.flush();
  assert.equal(primary.calls.flush, 1);
  assert.deepEqual(errors, ['secondary flush failed']);
});

test('dualWriteStore - init/flush tolerate stores that omit init/flush entirely', async () => {
  const primary = { load: () => ({}), save: () => {} };
  const secondary = { load: () => ({}), save: () => {} };
  const store = createDualWriteStore({ primary, secondary });
  await store.init();
  await store.flush();
});

// ── readFromSecondary (DYNAMO_PRIMARY_READ) ────────────────────────────────

test('dualWriteStore - readFromSecondary serves secondary once init() has succeeded', async () => {
  const primary = fakeStore({ from: 'primary' });
  const secondary = fakeStore({ from: 'secondary' });
  const store = createDualWriteStore({ primary, secondary, readFromSecondary: true });
  await store.init();
  const data = store.load();
  assert.deepEqual(data, { from: 'secondary' });
});

test('dualWriteStore - readFromSecondary falls back to primary if secondary.init() never succeeded', async () => {
  const primary = fakeStore({ from: 'primary' });
  const secondary = { init: async () => { throw new Error('table not found'); }, load: () => ({ from: 'secondary' }) };
  const errors = [];
  const store = createDualWriteStore({ primary, secondary, readFromSecondary: true, onError: (e) => errors.push(e.message) });
  await store.init();
  const data = store.load();
  assert.deepEqual(data, { from: 'primary' });
  assert.deepEqual(errors, ['table not found']);
});

test('dualWriteStore - readFromSecondary falls back to primary if secondary.load() throws at read time', async () => {
  const primary = fakeStore({ from: 'primary' });
  const secondary = { init: async () => {}, load: () => { throw new Error('read timeout'); } };
  const errors = [];
  const store = createDualWriteStore({ primary, secondary, readFromSecondary: true, onError: (e) => errors.push(e.message) });
  await store.init();
  const data = store.load();
  assert.deepEqual(data, { from: 'primary' });
  assert.deepEqual(errors, ['read timeout']);
});

test('dualWriteStore - readFromSecondary + shadowRead diffs primary against what secondary served', async () => {
  const primary = fakeStore({ from: 'primary' });
  const secondary = fakeStore({ from: 'secondary' });
  const mismatches = [];
  const store = createDualWriteStore({
    primary, secondary, readFromSecondary: true, shadowRead: true,
    onMismatch: (m) => mismatches.push(m),
  });
  await store.init();
  const data = store.load();
  assert.deepEqual(data, { from: 'secondary' }); // caller gets secondary now
  await wait(10);
  assert.deepEqual(mismatches, [{ primary: { from: 'primary' }, secondary: { from: 'secondary' } }]);
});

test('dualWriteStore - readFromSecondary defaults to false, preserving existing primary-read behavior', async () => {
  const primary = fakeStore({ from: 'primary' });
  const secondary = fakeStore({ from: 'secondary' });
  const store = createDualWriteStore({ primary, secondary });
  await store.init();
  const data = store.load();
  assert.deepEqual(data, { from: 'primary' });
});
