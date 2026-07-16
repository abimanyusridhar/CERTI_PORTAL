'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const https = require('node:https');

const S3_PATH = require.resolve('../../services/s3');

function withFreshS3(env) {
  const oldEnv = {};
  for (const key of ['S3_BUCKET', 'S3_REGION', 'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'S3_PREFIX', 'S3_SSE', 'S3_KMS_KEY_ID', 'AWS_REGION', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']) {
    oldEnv[key] = process.env[key];
    delete process.env[key];
  }
  Object.assign(process.env, env);
  delete require.cache[S3_PATH];
  const s3 = require('../../services/s3');
  return {
    s3,
    restore() {
      delete require.cache[S3_PATH];
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
      const responseSpec = handler({ options, body });
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
    restore() {
      https.request = original;
    },
  };
}

test('s3 service - enabled upload, download, putJson, getJson, and delete sign native HTTPS requests', async () => {
  const { s3, restore: restoreEnv } = withFreshS3({
    S3_BUCKET: 'unit-bucket',
    S3_REGION: 'us-east-1',
    S3_ACCESS_KEY: 'AKIAUNITTEST',
    S3_SECRET_KEY: 'unit-secret-key',
    S3_PREFIX: 'tenant-a/',
  });
  const mock = mockHttpsRequest(({ options, body }) => {
    assert.equal(options.hostname, 'unit-bucket.s3.us-east-1.amazonaws.com');
    assert.ok(options.headers.authorization.startsWith('AWS4-HMAC-SHA256 Credential=AKIAUNITTEST/'));
    assert.ok(options.headers['x-amz-date']);
    assert.ok(options.headers['x-amz-content-sha256']);

    if (options.method === 'GET') return { statusCode: 200, body: options.path.endsWith('.json') ? '{"ok":true}' : 'file-body' };
    if (options.method === 'PUT') {
      assert.ok(body.length > 0);
      return { statusCode: 200, body: '' };
    }
    if (options.method === 'DELETE') return { statusCode: 204, body: '' };
    return { statusCode: 500, body: 'unexpected method' };
  });

  try {
    assert.equal(s3.S3_ENABLED, true);
    assert.equal(s3.BUCKET, 'unit-bucket');
    assert.equal(s3.REGION, 'us-east-1');
    assert.equal(s3.PREFIX, 'tenant-a/');

    const uploadedUrl = await s3.uploadFile('uploads/a b.txt', Buffer.from('hello'), 'text/plain');
    assert.equal(uploadedUrl, 'https://unit-bucket.s3.us-east-1.amazonaws.com/tenant-a/uploads/a b.txt');

    const downloaded = await s3.downloadFile('uploads/a b.txt');
    assert.equal(downloaded.toString('utf8'), 'file-body');

    await s3.putJson('data/app.json', { saved: true });
    const json = await s3.getJson('data/app.json');
    assert.deepEqual(json, { ok: true });

    await s3.deleteFile('uploads/a b.txt');
    assert.deepEqual(mock.calls.map(c => c.options.method), ['PUT', 'GET', 'PUT', 'GET', 'DELETE']);
    assert.ok(mock.calls.every(c => c.options.path.includes('tenant-a/')));
  } finally {
    mock.restore();
    restoreEnv();
  }
});

test('s3 service - adds optional server-side encryption headers on PUT', async () => {
  const { s3, restore: restoreEnv } = withFreshS3({
    S3_BUCKET: 'unit-bucket',
    S3_ACCESS_KEY: 'AKIAUNITTEST',
    S3_SECRET_KEY: 'unit-secret-key',
    S3_SSE: 'aws:kms',
    S3_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123456789012:key/unit-test',
  });
  const mock = mockHttpsRequest(({ options }) => {
    if (options.method === 'PUT') {
      assert.equal(options.headers['x-amz-server-side-encryption'], 'aws:kms');
      assert.equal(options.headers['x-amz-server-side-encryption-aws-kms-key-id'], 'arn:aws:kms:us-east-1:123456789012:key/unit-test');
    }
    return { statusCode: 200, body: '' };
  });

  try {
    await s3.uploadFile('uploads/encrypted.txt', Buffer.from('hello'), 'text/plain');
    await s3.putJson('data/encrypted.json', { ok: true });
    assert.equal(mock.calls.length, 2);
  } finally {
    mock.restore();
    restoreEnv();
  }
});

test('s3 service - rejects non-2xx S3 responses with status context', async () => {
  const { s3, restore: restoreEnv } = withFreshS3({
    S3_BUCKET: 'unit-bucket',
    S3_ACCESS_KEY: 'AKIAUNITTEST',
    S3_SECRET_KEY: 'unit-secret-key',
  });
  const mock = mockHttpsRequest(() => ({ statusCode: 403, body: 'AccessDenied' }));

  try {
    await assert.rejects(() => s3.downloadFile('secret.txt'), /S3 GET secret\.txt.*403/);
  } finally {
    mock.restore();
    restoreEnv();
  }
});

test('s3 service - propagates HTTPS request errors', async () => {
  const { s3, restore: restoreEnv } = withFreshS3({
    S3_BUCKET: 'unit-bucket',
    S3_ACCESS_KEY: 'AKIAUNITTEST',
    S3_SECRET_KEY: 'unit-secret-key',
  });
  const original = https.request;
  https.request = () => {
    const req = new EventEmitter();
    req.write = () => {};
    req.end = () => process.nextTick(() => req.emit('error', new Error('network down')));
    req.on = EventEmitter.prototype.on.bind(req);
    return req;
  };

  try {
    await assert.rejects(() => s3.downloadFile('any.txt'), /network down/);
  } finally {
    https.request = original;
    restoreEnv();
  }
});
