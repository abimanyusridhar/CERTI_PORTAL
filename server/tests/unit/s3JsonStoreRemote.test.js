'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const { EventEmitter } = require('node:events');

const S3_PATH = require.resolve('../../services/s3');
const STORE_PATH = require.resolve('../../repositories/s3JsonStore');

function withS3Enabled() {
  const oldEnv = {};
  for (const key of ['S3_BUCKET', 'S3_REGION', 'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'S3_PREFIX']) {
    oldEnv[key] = process.env[key];
  }
  process.env.S3_BUCKET = 'unit-bucket';
  process.env.S3_REGION = 'us-east-1';
  process.env.S3_ACCESS_KEY = 'AKIAUNITTEST';
  process.env.S3_SECRET_KEY = 'unit-secret-key';
  process.env.S3_PREFIX = '';
  delete require.cache[S3_PATH];
  delete require.cache[STORE_PATH];

  return {
    restore() {
      delete require.cache[S3_PATH];
      delete require.cache[STORE_PATH];
      for (const [key, value] of Object.entries(oldEnv)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    },
  };
}

function mockHttps() {
  const original = https.request;
  const calls = [];
  https.request = (options, callback) => {
    const req = new EventEmitter();
    const chunks = [];
    req.write = chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    req.end = () => {
      const body = Buffer.concat(chunks);
      calls.push({ method: options.method, path: options.path, body });
      const res = new EventEmitter();
      res.statusCode = 200;
      res.headers = {};
      callback(res);
      process.nextTick(() => {
        if (options.method === 'GET') res.emit('data', Buffer.from('{"fromRemote":true}'));
        res.emit('end');
      });
    };
    req.on = EventEmitter.prototype.on.bind(req);
    return req;
  };
  return {
    calls,
    restore() {
      https.request = original;
    },
  };
}

test('s3JsonStore - S3-enabled init pulls remote data and save PUTs to S3 (no local disk involved)', async () => {
  const env = withS3Enabled();
  const mock = mockHttps();

  try {
    const { createS3JsonStore } = require('../../repositories/s3JsonStore');
    const store = createS3JsonStore({
      s3Key: 'data/store.json',
      seedData: { seed: true },
      debounceMs: 1,
    });

    await store.init();
    assert.deepEqual(store.load(), { fromRemote: true });

    store.save({ localChange: true });
    await new Promise(resolve => setTimeout(resolve, 25));
    await store.flush();

    assert.ok(mock.calls.some(c => c.method === 'GET' && c.path === '/data/store.json'));
    assert.ok(mock.calls.some(c => c.method === 'PUT' && c.body.toString('utf8').includes('localChange')));
  } finally {
    mock.restore();
    env.restore();
  }
});
