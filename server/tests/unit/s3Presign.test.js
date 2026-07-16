'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { S3Client } = require('@aws-sdk/client-s3');

const S3_PRESIGN_PATH = require.resolve('../../services/s3Presign');

const ENV_KEYS = [
  'S3_BUCKET', 'S3_REGION', 'S3_ACCESS_KEY', 'S3_SECRET_KEY', 'S3_PREFIX', 'S3_SSE', 'S3_KMS_KEY_ID',
  'AWS_REGION', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
];

function withFreshS3Presign(env) {
  const oldEnv = {};
  for (const key of ENV_KEYS) {
    oldEnv[key] = process.env[key];
    delete process.env[key];
  }
  Object.assign(process.env, env);
  delete require.cache[S3_PRESIGN_PATH];
  const s3Presign = require('../../services/s3Presign');
  return {
    s3Presign,
    restore() {
      delete require.cache[S3_PRESIGN_PATH];
      for (const [key, value] of Object.entries(oldEnv)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    },
  };
}

function mockS3Send(handler) {
  const original = S3Client.prototype.send;
  const calls = [];
  S3Client.prototype.send = function (command) {
    calls.push(command);
    return Promise.resolve(handler(command) || {});
  };
  return { calls, restore() { S3Client.prototype.send = original; } };
}

test('s3Presign - disabled guards reject every public method', async () => {
  const { s3Presign, restore } = withFreshS3Presign({});
  try {
    assert.equal(s3Presign.S3_PRESIGN_ENABLED, false);
    await assert.rejects(() => s3Presign.uploadObject('x.txt', Buffer.from('x'), 'text/plain'), /S3 not configured/);
    await assert.rejects(() => s3Presign.getPresignedDownloadUrl('x.txt'), /S3 not configured/);
    await assert.rejects(() => s3Presign.getPresignedUploadUrl('x.txt'), /S3 not configured/);
  } finally {
    restore();
  }
});

test('s3Presign - getPresignedDownloadUrl signs a GET URL with expiry, filename, and prefix', async () => {
  const { s3Presign, restore } = withFreshS3Presign({
    S3_BUCKET: 'unit-bucket',
    S3_REGION: 'us-east-1',
    S3_ACCESS_KEY: 'AKIAUNITTEST',
    S3_SECRET_KEY: 'unit-secret-key',
    S3_PREFIX: 'tenant-a/',
  });
  try {
    assert.equal(s3Presign.S3_PRESIGN_ENABLED, true);
    const url = await s3Presign.getPresignedDownloadUrl('uploads/report.pdf', { expiresIn: 60, filename: 'report.pdf' });
    const parsed = new URL(url);
    assert.equal(parsed.hostname, 'unit-bucket.s3.us-east-1.amazonaws.com');
    assert.equal(parsed.pathname, '/tenant-a/uploads/report.pdf');
    assert.equal(parsed.searchParams.get('X-Amz-Expires'), '60');
    assert.ok(parsed.searchParams.get('X-Amz-Credential').startsWith('AKIAUNITTEST/'));
    assert.ok(parsed.searchParams.get('X-Amz-Signature'));
    assert.equal(parsed.searchParams.get('response-content-disposition'), 'attachment; filename="report.pdf"');
  } finally {
    restore();
  }
});

test('s3Presign - getPresignedUploadUrl signs a PUT URL', async () => {
  const { s3Presign, restore } = withFreshS3Presign({
    S3_BUCKET: 'unit-bucket', S3_ACCESS_KEY: 'AKIA', S3_SECRET_KEY: 'secret',
  });
  try {
    const url = await s3Presign.getPresignedUploadUrl('uploads/new.png', { expiresIn: 120, contentType: 'image/png' });
    const parsed = new URL(url);
    assert.equal(parsed.searchParams.get('X-Amz-Expires'), '120');
    assert.ok(parsed.searchParams.get('X-Amz-Signature'));
  } finally {
    restore();
  }
});

test('s3Presign - uploadObject sends a PutObjectCommand with bucket/key/content-type', async () => {
  const { s3Presign, restore: restoreEnv } = withFreshS3Presign({
    S3_BUCKET: 'unit-bucket', S3_REGION: 'us-east-1', S3_ACCESS_KEY: 'AKIA', S3_SECRET_KEY: 'secret', S3_PREFIX: 'tenant-a/',
  });
  const mock = mockS3Send(() => ({}));
  try {
    const url = await s3Presign.uploadObject('uploads/a.txt', Buffer.from('hi'), 'text/plain');
    assert.equal(url, 'https://unit-bucket.s3.us-east-1.amazonaws.com/tenant-a/uploads/a.txt');
    assert.equal(mock.calls.length, 1);
    const input = mock.calls[0].input;
    assert.equal(input.Bucket, 'unit-bucket');
    assert.equal(input.Key, 'tenant-a/uploads/a.txt');
    assert.equal(input.ContentType, 'text/plain');
    assert.equal(input.Body.toString('utf8'), 'hi');
  } finally {
    mock.restore();
    restoreEnv();
  }
});

test('s3Presign - uploadObject adds SSE-KMS headers when configured', async () => {
  const { s3Presign, restore: restoreEnv } = withFreshS3Presign({
    S3_BUCKET: 'unit-bucket', S3_ACCESS_KEY: 'AKIA', S3_SECRET_KEY: 'secret',
    S3_SSE: 'aws:kms', S3_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123456789012:key/unit-test',
  });
  const mock = mockS3Send(() => ({}));
  try {
    await s3Presign.uploadObject('uploads/b.txt', Buffer.from('hi'), 'text/plain');
    const input = mock.calls[0].input;
    assert.equal(input.ServerSideEncryption, 'aws:kms');
    assert.equal(input.SSEKMSKeyId, 'arn:aws:kms:us-east-1:123456789012:key/unit-test');
  } finally {
    mock.restore();
    restoreEnv();
  }
});
