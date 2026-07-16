'use strict';

/**
 * s3Presign.js — the one AWS-SDK-backed module in this codebase (see
 * package.json: @aws-sdk/client-s3 + @aws-sdk/s3-request-presigner). Kept
 * separate from the zero-dependency services/s3.js by design, per the
 * Phase 1 plan: everything else here stays hand-rolled to minimize
 * supply-chain surface; only presigned-URL generation (query-string SigV4,
 * not header SigV4) pulls in the SDK.
 *
 * Not yet wired into any live route. This module is complete and
 * unit-tested so the actual cutover — in server/index.js's /uploads/* and
 * /api/docs/download/:id handlers, swapping the final byte-serving step for
 * a redirect to a short-lived presigned URL while every existing
 * access-control check stays exactly where it is — can follow as its own,
 * separately-verified change against those already heavily-tested routes.
 *
 * Environment variables (reuses the same names as services/s3.js):
 *   S3_BUCKET, S3_REGION, S3_ACCESS_KEY, S3_SECRET_KEY, S3_PREFIX, S3_SSE, S3_KMS_KEY_ID
 */

const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const REGION     = process.env.S3_REGION      || process.env.AWS_REGION        || 'ap-south-1';
const BUCKET     = process.env.S3_BUCKET      || '';
const ACCESS_KEY = process.env.S3_ACCESS_KEY  || process.env.AWS_ACCESS_KEY_ID || '';
const SECRET_KEY = process.env.S3_SECRET_KEY  || process.env.AWS_SECRET_ACCESS_KEY || '';
const PREFIX     = process.env.S3_PREFIX      || '';
const SSE        = process.env.S3_SSE         || '';
const KMS_KEY_ID = process.env.S3_KMS_KEY_ID  || '';

const S3_PRESIGN_ENABLED = !!(BUCKET && ACCESS_KEY && SECRET_KEY);

let _client = null;
function client() {
  if (_client) return _client;
  _client = new S3Client({
    region: REGION,
    credentials: { accessKeyId: ACCESS_KEY, secretAccessKey: SECRET_KEY },
  });
  return _client;
}

/**
 * Upload via the SDK's PutObjectCommand — an alternative to
 * services/s3.js#uploadFile for whichever call site switches to this
 * module; the hand-rolled version is left untouched for everything else.
 */
async function uploadObject(key, data, contentType) {
  if (!S3_PRESIGN_ENABLED) throw new Error('S3 not configured');
  const fullKey = PREFIX + key;
  await client().send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: fullKey,
    Body: data,
    ContentType: contentType,
    ...(SSE ? { ServerSideEncryption: SSE } : {}),
    ...(SSE === 'aws:kms' && KMS_KEY_ID ? { SSEKMSKeyId: KMS_KEY_ID } : {}),
  }));
  return `https://${BUCKET}.s3.${REGION}.amazonaws.com/${fullKey}`;
}

/**
 * Presigned, time-limited GET URL — the replacement for proxying file
 * bytes through the app process. `expiresIn` is in seconds; the plan calls
 * for a 60s TTL at the actual call site.
 */
async function getPresignedDownloadUrl(key, { expiresIn = 60, filename, contentType } = {}) {
  if (!S3_PRESIGN_ENABLED) throw new Error('S3 not configured');
  const fullKey = PREFIX + key;
  const command = new GetObjectCommand({
    Bucket: BUCKET,
    Key: fullKey,
    ...(filename ? { ResponseContentDisposition: `attachment; filename="${filename}"` } : {}),
    ...(contentType ? { ResponseContentType: contentType } : {}),
  });
  return getSignedUrl(client(), command, { expiresIn });
}

/**
 * Presigned PUT URL for a later phase's client-direct upload flow. Not
 * wired into any route in Phase 1 — uploads still go through server-side
 * multipart parsing + magic-byte validation, which needs the app to see
 * the actual bytes; a true client-direct PUT needs a quarantine-until-
 * scanned pattern first.
 */
async function getPresignedUploadUrl(key, { expiresIn = 60, contentType } = {}) {
  if (!S3_PRESIGN_ENABLED) throw new Error('S3 not configured');
  const fullKey = PREFIX + key;
  const command = new PutObjectCommand({
    Bucket: BUCKET,
    Key: fullKey,
    ...(contentType ? { ContentType: contentType } : {}),
    ...(SSE ? { ServerSideEncryption: SSE } : {}),
    ...(SSE === 'aws:kms' && KMS_KEY_ID ? { SSEKMSKeyId: KMS_KEY_ID } : {}),
  });
  return getSignedUrl(client(), command, { expiresIn });
}

module.exports = {
  S3_PRESIGN_ENABLED,
  BUCKET,
  REGION,
  PREFIX,
  uploadObject,
  getPresignedDownloadUrl,
  getPresignedUploadUrl,
};
