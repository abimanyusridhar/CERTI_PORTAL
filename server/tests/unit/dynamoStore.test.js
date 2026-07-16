'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const dynamodb = require('../../services/dynamodb');
const { createDynamoStore } = require('../../repositories/dynamoStore');

function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

function withMockedDynamo({ queryImpl, batchWriteImpl } = {}) {
  const originalQuery = dynamodb.query;
  const originalBatchWrite = dynamodb.batchWrite;
  const batchWriteCalls = [];
  dynamodb.query = queryImpl || (async () => []);
  dynamodb.batchWrite = async (requests) => {
    batchWriteCalls.push(requests);
    if (batchWriteImpl) return batchWriteImpl(requests);
  };
  return {
    batchWriteCalls,
    restore() {
      dynamodb.query = originalQuery;
      dynamodb.batchWrite = originalBatchWrite;
    },
  };
}

function toPlainRequests(requests) {
  return requests.map(r => {
    if (r.PutRequest) return { put: dynamodb.unmarshalItem(r.PutRequest.Item) };
    return { del: dynamodb.unmarshalItem(r.DeleteRequest.Key) };
  });
}

test('dynamoStore - init rebuilds cache from queried items, stripping PK/SK', async () => {
  const mock = withMockedDynamo({
    queryImpl: async (params) => {
      assert.equal(params.ExpressionAttributeValues[':pk'].S, 'TENANT#acme');
      assert.equal(params.ExpressionAttributeValues[':skPrefix'].S, 'USER#');
      return [
        { PK: 'TENANT#acme', SK: 'USER#u1', id: 'u1', name: 'Alice' },
        { PK: 'TENANT#acme', SK: 'USER#u2', id: 'u2', name: 'Bob' },
      ];
    },
  });
  try {
    const store = createDynamoStore({ tenantId: 'acme', entityPrefix: 'USER', seedData: {}, debounceMs: 5 });
    await store.init();
    assert.deepEqual(store.load(), {
      u1: { id: 'u1', name: 'Alice' },
      u2: { id: 'u2', name: 'Bob' },
    });
  } finally {
    mock.restore();
  }
});

test('dynamoStore - load() before init falls back to a copy of seedData', () => {
  const store = createDynamoStore({ tenantId: 'acme', entityPrefix: 'USER', seedData: { seed: 'yes' }, debounceMs: 5 });
  const loaded = store.load();
  assert.deepEqual(loaded, { seed: 'yes' });
  assert.notEqual(loaded, undefined);
});

test('dynamoStore - save() diffs by reference identity: only changed/new/removed keys are written', async () => {
  const mock = withMockedDynamo();
  try {
    const store = createDynamoStore({ tenantId: 'acme', entityPrefix: 'USER', seedData: {}, debounceMs: 5 });
    await store.init();

    const alice = { id: 'u1', name: 'Alice' };
    const bob = { id: 'u2', name: 'Bob' };
    store.save({ u1: alice, u2: bob });
    await wait(30);

    assert.equal(mock.batchWriteCalls.length, 1);
    assert.deepEqual(toPlainRequests(mock.batchWriteCalls[0]).sort((a, b) => (a.put.id > b.put.id ? 1 : -1)), [
      { put: { PK: 'TENANT#acme', SK: 'USER#u1', id: 'u1', name: 'Alice' } },
      { put: { PK: 'TENANT#acme', SK: 'USER#u2', id: 'u2', name: 'Bob' } },
    ]);

    // Second save reuses bob's reference untouched and only changes alice —
    // only alice should appear in the next diff.
    const aliceUpdated = { id: 'u1', name: 'Alice Updated' };
    store.save({ u1: aliceUpdated, u2: bob });
    await wait(30);

    assert.equal(mock.batchWriteCalls.length, 2);
    assert.deepEqual(toPlainRequests(mock.batchWriteCalls[1]), [
      { put: { PK: 'TENANT#acme', SK: 'USER#u1', id: 'u1', name: 'Alice Updated' } },
    ]);

    // Third save removes u2 entirely.
    store.save({ u1: aliceUpdated });
    await wait(30);

    assert.equal(mock.batchWriteCalls.length, 3);
    assert.deepEqual(toPlainRequests(mock.batchWriteCalls[2]), [{ del: { PK: 'TENANT#acme', SK: 'USER#u2' } }]);
  } finally {
    mock.restore();
  }
});

test('dynamoStore - save() with no actual changes produces no batchWrite call', async () => {
  const mock = withMockedDynamo();
  try {
    const store = createDynamoStore({ tenantId: 'acme', entityPrefix: 'USER', seedData: {}, debounceMs: 5 });
    await store.init();
    const same = { u1: { id: 'u1', name: 'Alice' } };
    store.save(same);
    await wait(30);
    assert.equal(mock.batchWriteCalls.length, 1);

    store.save(same); // identical object reference — nothing changed
    await wait(30);
    assert.equal(mock.batchWriteCalls.length, 1);
  } finally {
    mock.restore();
  }
});

test('dynamoStore - flush() forces the pending diff immediately and resolves once confirmed', async () => {
  const mock = withMockedDynamo();
  try {
    const store = createDynamoStore({ tenantId: 'acme', entityPrefix: 'USER', seedData: {}, debounceMs: 60_000 });
    await store.init();
    store.save({ u1: { id: 'u1', name: 'Alice' } });
    await store.flush();
    assert.equal(mock.batchWriteCalls.length, 1);
  } finally {
    mock.restore();
  }
});

test('dynamoStore - overlapping flushes coalesce into one follow-up flush instead of racing', async () => {
  let resolveFirstWrite;
  const firstWriteGate = new Promise(r => { resolveFirstWrite = r; });
  let callCount = 0;
  const mock = withMockedDynamo({
    batchWriteImpl: async () => {
      callCount += 1;
      if (callCount === 1) await firstWriteGate;
    },
  });
  try {
    const store = createDynamoStore({ tenantId: 'acme', entityPrefix: 'USER', seedData: {}, debounceMs: 60_000 });
    await store.init();

    store.save({ u1: { id: 'u1', name: 'Alice' } });
    const firstFlush = store.flush(); // starts the in-flight batchWrite (gated)

    store.save({ u1: { id: 'u1', name: 'Alice V2' } }); // arrives while flush #1 is in flight
    store.flush(); // should coalesce into pendingAgain rather than racing

    await wait(10);
    assert.equal(callCount, 1); // still gated — second flush hasn't started yet

    resolveFirstWrite();
    await firstFlush;
    await wait(10);

    assert.equal(callCount, 2); // coalesced follow-up flush ran after the first resolved
  } finally {
    mock.restore();
  }
});

test('dynamoStore - errors during debounced flush are reported via onError, not thrown', async () => {
  const mock = withMockedDynamo({ batchWriteImpl: async () => { throw new Error('boom'); } });
  const errors = [];
  try {
    const store = createDynamoStore({
      tenantId: 'acme', entityPrefix: 'USER', seedData: {}, debounceMs: 5,
      onError: (err) => errors.push(err.message),
    });
    await store.init();
    store.save({ u1: { id: 'u1', name: 'Alice' } });
    await wait(30);
    assert.deepEqual(errors, ['boom']);
  } finally {
    mock.restore();
  }
});

test('dynamoStore - defaults tenantId to "default" when not provided', async () => {
  const mock = withMockedDynamo({
    queryImpl: async (params) => {
      assert.equal(params.ExpressionAttributeValues[':pk'].S, 'TENANT#default');
      return [];
    },
  });
  try {
    const store = createDynamoStore({ entityPrefix: 'USER', seedData: {}, debounceMs: 5 });
    await store.init();
  } finally {
    mock.restore();
  }
});
