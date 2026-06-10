'use strict';
/**
 * S3-backed file store — replaces local disk writes in uploads/ directory.
 *
 * All files are stored under:
 *   s3://<BUCKET>/<TENANT_ID>/<filename>
 *
 * Public cert images are served via CloudFront or pre-signed URLs.
 * The server can also proxy them inline (see getFileBuffer).
 */

const { S3Client, PutObjectCommand,
        DeleteObjectCommand, GetObjectCommand,
        HeadObjectCommand }   = require('@aws-sdk/client-s3');
const { getSignedUrl }        = require('@aws-sdk/s3-request-presigner');
const path                    = require('path');

const REGION = process.env.AWS_REGION  || 'ap-south-1';
const BUCKET = process.env.S3_BUCKET;   // set in environment

if (!BUCKET) {
  console.warn('[s3-uploads] WARNING: S3_BUCKET env var not set — file uploads will fail');
}

const s3 = new S3Client({ region: REGION });

/**
 * Upload a file buffer to S3.
 * @param {Buffer} buf        Raw file bytes
 * @param {string} key        S3 object key  e.g. "SYNCERT/cert_abc123.png"
 * @param {string} mimeType   e.g. "image/png"
 * @returns {string}          The S3 key (store this in the DB record)
 */
async function uploadFile(buf, key, mimeType) {
  await s3.send(new PutObjectCommand({
    Bucket:      BUCKET,
    Key:         key,
    Body:        buf,
    ContentType: mimeType,
    ServerSideEncryption: 'AES256',
  }));
  return key;
}

/**
 * Delete a file from S3.
 */
async function deleteFile(key) {
  if (!key) return;
  await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
}

/**
 * Download a file from S3 as a Buffer.
 * Used by the server when proxying cert images to the browser.
 */
async function getFileBuffer(key) {
  const resp = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: key }));
  const chunks = [];
  for await (const chunk of resp.Body) chunks.push(chunk);
  return { buf: Buffer.concat(chunks), contentType: resp.ContentType };
}

/**
 * Generate a short-lived pre-signed URL (15 min) for direct browser download.
 * Use this for document/PDF downloads instead of proxying through the server.
 */
async function presignedUrl(key, expiresIn = 900) {
  return getSignedUrl(s3, new GetObjectCommand({ Bucket: BUCKET, Key: key }), { expiresIn });
}

/**
 * Check whether a key exists in S3.
 */
async function fileExists(key) {
  try {
    await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: key }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Build the S3 key for a cert image or attachment.
 * Convention: <tenantId>/<filename>
 */
function buildKey(tenantId, filename) {
  return `${tenantId}/${path.basename(filename)}`;
}

/**
 * Build the S3 key for a document library file.
 * Convention: <tenantId>/documents/<filename>
 */
function buildDocKey(tenantId, filename) {
  return `${tenantId}/documents/${path.basename(filename)}`;
}

module.exports = { uploadFile, deleteFile, getFileBuffer, presignedUrl, fileExists, buildKey, buildDocKey };
