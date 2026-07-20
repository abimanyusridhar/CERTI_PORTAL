'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const https = require('node:https');

const DYNAMO_PATH = require.resolve('../../services/dynamodb');

const ENV_KEYS = [
  'DYNAMO_TABLE_NAME', 'DYNAMO_REGION', 'DYNAMO_ACCESS_KEY', 'DYNAMO_SECRET_KEY',
  'DYNAMODB_TABLE_NAME', 'DYNAMODB_REGION', 'DYNAMODB_ACCESS_KEY', 'DYNAMODB_SECRET_KEY',
  'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'AWS_REGION', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
];

function withFreshDynamo(env) {
  const oldEnv = {};
  for (const key of ENV_KEYS) {
    oldEnv[key] = process.env[key];
    delete process.env[key];
  }
  Object.assign(process.env, env);
  delete require.cache[DYNAMO_PATH];
  const dynamodb = require('../../services/dynamodb');
  return {
    dynamodb,
    restore() {
      delete require.cache[DYNAMO_PATH];
      for (const [key, value] of Object.entries(oldEnv)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    },
  };
}

function mockHttpsRequest(handler) {
  const original = https.request;
  const calls = [];
  https.request = (options, callback) => {
    const req = new EventEmitter();
    const chunks = [];
    req.write = chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    req.end = () => {
      const body = Buffer.concat(chunks);
      calls.push({ options, body });
      const responseSpec = handler({ options, body, callIndex: calls.length - 1 });
      const res = new EventEmitter();
      res.statusCode = responseSpec.statusCode;
      res.headers = responseSpec.headers || {};
      callback(res);
      process.nextTick(() => {
        if (responseSpec.body) res.emit('data', Buffer.from(responseSpec.body));
        res.emit('end');
      });
    };
    req.on = EventEmitter.prototype.on.bind(req);
    return req;
  };
  return {
    calls,
    restore() { https.request = original; },
  };
}

test('dynamodb service - disabled guards reject every public method', async () => {
  const { dynamodb, restore } = withFreshDynamo({});
  try {
    assert.equal(dynamodb.DYNAMO_ENABLED, false);
    await assert.rejects(() => dynamodb.putItem({ id: '1' }), /DynamoDB not configured/);
    await assert.rejects(() => dynamodb.getItem({ PK: 'a', SK: 'b' }), /DynamoDB not configured/);
    await assert.rejects(() => dynamodb.deleteItem({ PK: 'a', SK: 'b' }), /DynamoDB not configured/);
    await assert.rejects(() => dynamodb.query({}), /DynamoDB not configured/);
    await assert.rejects(() => dynamodb.batchWrite([]), /DynamoDB not configured/);
  } finally {
    restore();
  }
});

test('dynamodb service - marshal/unmarshal round-trips every supported type', () => {
  const { dynamodb, restore } = withFreshDynamo({});
  try {
    const input = {
      name: 'Alice',
      empty: '',
      count: 3,
      active: true,
      tags: ['a', 'b'],
      nested: { x: 1, y: null },
      missing: undefined,
      weird: () => {},
    };
    const marshalled = dynamodb.marshalItem(input);
    assert.deepEqual(marshalled.name, { S: 'Alice' });
    // Empty string stays S: '' — DynamoDB has supported empty-string values
    // since 2020, and collapsing '' to NULL would silently corrupt fields
    // like recipientEmail: "" into null on every round-trip.
    assert.deepEqual(marshalled.empty, { S: '' });
    assert.deepEqual(marshalled.count, { N: '3' });
    assert.deepEqual(marshalled.active, { BOOL: true });
    assert.deepEqual(marshalled.tags, { L: [{ S: 'a' }, { S: 'b' }] });
    assert.deepEqual(marshalled.nested, { M: { x: { N: '1' }, y: { NULL: true } } });
    assert.deepEqual(marshalled.missing, { NULL: true });
    assert.deepEqual(marshalled.weird, { NULL: true });

    const roundTripped = dynamodb.unmarshalItem(marshalled);
    assert.equal(roundTripped.name, 'Alice');
    assert.equal(roundTripped.empty, '');
    assert.equal(roundTripped.count, 3);
    assert.equal(roundTripped.active, true);
    assert.deepEqual(roundTripped.tags, ['a', 'b']);
    assert.deepEqual(roundTripped.nested, { x: 1, y: null });

    assert.equal(dynamodb.unmarshal(null), null);
    assert.equal(dynamodb.unmarshalItem(null), null);
  } finally {
    restore();
  }
});

test('dynamodb service - putItem/getItem/deleteItem sign requests with the correct target and table', async () => {
  const { dynamodb, restore: restoreEnv } = withFreshDynamo({
    DYNAMO_TABLE_NAME: 'unit-table',
    DYNAMO_REGION: 'us-east-1',
    DYNAMO_ACCESS_KEY: 'AKIAUNITTEST',
    DYNAMO_SECRET_KEY: 'unit-secret-key',
  });
  const mock = mockHttpsRequest(({ options, body }) => {
    assert.equal(options.hostname, 'dynamodb.us-east-1.amazonaws.com');
    assert.equal(options.headers['content-type'], 'application/x-amz-json-1.0');
    assert.ok(options.headers.authorization.startsWith('AWS4-HMAC-SHA256 Credential=AKIAUNITTEST/'));
    const parsed = JSON.parse(body.toString('utf8'));
    assert.equal(parsed.TableName, 'unit-table');
    if (options.headers['x-amz-target'] === 'DynamoDB_20120810.GetItem') {
      return { statusCode: 200, body: JSON.stringify({ Item: { id: { S: '1' }, name: { S: 'Alice' } } }) };
    }
    return { statusCode: 200, body: '{}' };
  });

  try {
    assert.equal(dynamodb.DYNAMO_ENABLED, true);
    await dynamodb.putItem({ id: '1', name: 'Alice' });
    await dynamodb.deleteItem({ PK: 'a', SK: 'b' });
    const item = await dynamodb.getItem({ PK: 'a', SK: 'b' });
    assert.deepEqual(item, { id: '1', name: 'Alice' });
    assert.deepEqual(mock.calls.map(c => c.options.headers['x-amz-target']), [
      'DynamoDB_20120810.PutItem',
      'DynamoDB_20120810.DeleteItem',
      'DynamoDB_20120810.GetItem',
    ]);
  } finally {
    mock.restore();
    restoreEnv();
  }
});

test('dynamodb service - DYNAMODB_* naming (the "DB" typo) is accepted as an alias for DYNAMO_*', () => {
  const { dynamodb, restore } = withFreshDynamo({
    DYNAMODB_TABLE_NAME: 'unit-table',
    DYNAMODB_REGION: 'us-east-1',
    DYNAMODB_ACCESS_KEY: 'AKIAUNITTEST',
    DYNAMODB_SECRET_KEY: 'unit-secret-key',
  });
  try {
    // A table name set ONLY via the DYNAMODB_* alias must still enable the
    // service — this exact mismatch (DYNAMODB_TABLE_NAME vs. the canonical
    // DYNAMO_TABLE_NAME) was found silently disabling DynamoDB entirely.
    assert.equal(dynamodb.DYNAMO_ENABLED, true);
  } finally {
    restore();
  }
});

test('dynamodb service - DYNAMO_* takes precedence over DYNAMODB_* when both are set', async () => {
  const { dynamodb, restore } = withFreshDynamo({
    DYNAMO_TABLE_NAME: 'canonical-table',
    DYNAMODB_TABLE_NAME: 'alias-table',
    DYNAMO_ACCESS_KEY: 'AKIA', DYNAMO_SECRET_KEY: 'secret',
  });
  const mock = mockHttpsRequest(({ body }) => {
    const parsed = JSON.parse(body.toString('utf8'));
    assert.equal(parsed.TableName, 'canonical-table');
    return { statusCode: 200, body: '{}' };
  });
  try {
    await dynamodb.putItem({ id: '1' });
  } finally {
    mock.restore();
    restore();
  }
});

test('dynamodb service - getItem returns null when no Item is returned', async () => {
  const { dynamodb, restore: restoreEnv } = withFreshDynamo({
    DYNAMO_TABLE_NAME: 'unit-table', DYNAMO_ACCESS_KEY: 'AKIA', DYNAMO_SECRET_KEY: 'secret',
  });
  const mock = mockHttpsRequest(() => ({ statusCode: 200, body: '{}' }));
  try {
    const item = await dynamodb.getItem({ PK: 'a', SK: 'b' });
    assert.equal(item, null);
  } finally {
    mock.restore();
    restoreEnv();
  }
});

test('dynamodb service - query pages through LastEvaluatedKey', async () => {
  const { dynamodb, restore: restoreEnv } = withFreshDynamo({
    DYNAMO_TABLE_NAME: 'unit-table', DYNAMO_ACCESS_KEY: 'AKIA', DYNAMO_SECRET_KEY: 'secret',
  });
  const mock = mockHttpsRequest(({ callIndex }) => {
    if (callIndex === 0) {
      return {
        statusCode: 200,
        body: JSON.stringify({ Items: [{ id: { S: '1' } }], LastEvaluatedKey: { PK: { S: 'a' } } }),
      };
    }
    return { statusCode: 200, body: JSON.stringify({ Items: [{ id: { S: '2' } }] }) };
  });
  try {
    const items = await dynamodb.query({ KeyConditionExpression: 'PK = :pk', ExpressionAttributeValues: { ':pk': { S: 'a' } } });
    assert.deepEqual(items, [{ id: '1' }, { id: '2' }]);
    assert.equal(mock.calls.length, 2);
    assert.ok(JSON.parse(mock.calls[1].body.toString('utf8')).ExclusiveStartKey);
  } finally {
    mock.restore();
    restoreEnv();
  }
});

test('dynamodb service - batchWrite chunks at 25 items and retries UnprocessedItems', async () => {
  const { dynamodb, restore: restoreEnv } = withFreshDynamo({
    DYNAMO_TABLE_NAME: 'unit-table', DYNAMO_ACCESS_KEY: 'AKIA', DYNAMO_SECRET_KEY: 'secret',
  });
  const requests = Array.from({ length: 30 }, (_, i) => ({
    PutRequest: { Item: dynamodb.marshalItem({ PK: 'a', SK: `item${i}` }) },
  }));
  const mock = mockHttpsRequest(({ body, callIndex }) => {
    const parsed = JSON.parse(body.toString('utf8'));
    const sent = parsed.RequestItems['unit-table'];
    // First chunk (25 items) is retried once via UnprocessedItems before it fully drains.
    if (callIndex === 0) {
      assert.equal(sent.length, 25);
      return { statusCode: 200, body: JSON.stringify({ UnprocessedItems: { 'unit-table': sent.slice(0, 2) } }) };
    }
    if (callIndex === 1) {
      assert.equal(sent.length, 2);
      return { statusCode: 200, body: '{}' };
    }
    assert.equal(sent.length, 5);
    return { statusCode: 200, body: '{}' };
  });
  try {
    await dynamodb.batchWrite(requests);
    assert.equal(mock.calls.length, 3);
  } finally {
    mock.restore();
    restoreEnv();
  }
});

test('dynamodb service - rejects non-2xx responses with status and target context', async () => {
  const { dynamodb, restore: restoreEnv } = withFreshDynamo({
    DYNAMO_TABLE_NAME: 'unit-table', DYNAMO_ACCESS_KEY: 'AKIA', DYNAMO_SECRET_KEY: 'secret',
  });
  const mock = mockHttpsRequest(() => ({
    statusCode: 400,
    body: JSON.stringify({ __type: 'ResourceNotFoundException', message: 'no table' }),
  }));
  try {
    await assert.rejects(() => dynamodb.getItem({ PK: 'a', SK: 'b' }), /GetItem.*400.*no table/);
  } finally {
    mock.restore();
    restoreEnv();
  }
});
