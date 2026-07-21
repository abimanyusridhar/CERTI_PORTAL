'use strict';

/**
 * s3.js — Zero-dependency AWS S3 service using native Node.js https + SigV4.
 *
 * Enabled when S3_BUCKET is set in environment. Degrades gracefully to local
 * filesystem when not configured (S3_ENABLED === false).
 *
 * Environment variables:
 *   S3_BUCKET           — required to enable S3
 *   S3_REGION           — defaults to ap-south-1
 *   S3_ACCESS_KEY       — AWS access key ID  (falls back to AWS_ACCESS_KEY_ID)
 *   S3_SECRET_KEY       — AWS secret key     (falls back to AWS_SECRET_ACCESS_KEY)
 *   S3_PREFIX           — optional key prefix, e.g. "synergy-cert-portal/"
 */

const https  = require('https');
const crypto = require('crypto');

const REGION     = process.env.S3_REGION      || process.env.AWS_REGION        || 'ap-south-1';
const BUCKET     = process.env.S3_BUCKET      || '';
const ACCESS_KEY = process.env.S3_ACCESS_KEY  || process.env.AWS_ACCESS_KEY_ID || '';
const SECRET_KEY = process.env.S3_SECRET_KEY  || process.env.AWS_SECRET_ACCESS_KEY || '';
const PREFIX     = process.env.S3_PREFIX      || '';
const SSE        = process.env.S3_SSE         || '';
const KMS_KEY_ID = process.env.S3_KMS_KEY_ID  || '';

const S3_ENABLED = !!(BUCKET && ACCESS_KEY && SECRET_KEY);

// ── SigV4 signing helpers ─────────────────────────────────────────────────────

function _hmac(key, data, encoding) {
  return crypto.createHmac('sha256', key).update(data).digest(encoding || undefined);
}

function _signingKey(secretKey, dateStamp, region, service) {
  const kDate    = _hmac('AWS4' + secretKey, dateStamp);
  const kRegion  = _hmac(kDate, region);
  const kService = _hmac(kRegion, service);
  return _hmac(kService, 'aws4_request');
}

function _sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function _canonicalQuerystring(params) {
  return Object.keys(params).sort()
    .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
    .join('&');
}

function _sign(method, path, querystring, headers, payload, dateTime) {
  const dateStamp   = dateTime.slice(0, 8);
  const sortedHdrs  = Object.entries(headers)
    .map(([k, v]) => [k.toLowerCase(), v.trim()])
    .sort((a, b) => a[0].localeCompare(b[0]));
  const signedHeaders = sortedHdrs.map(([k]) => k).join(';');
  const canonicalHdrs = sortedHdrs.map(([k, v]) => `${k}:${v}\n`).join('');
  const payloadHash   = _sha256(payload);

  const canonicalReq = [method, path, querystring, canonicalHdrs, signedHeaders, payloadHash].join('\n');
  const credScope     = `${dateStamp}/${REGION}/s3/aws4_request`;
  const stringToSign  = `AWS4-HMAC-SHA256\n${dateTime}\n${credScope}\n${_sha256(canonicalReq)}`;
  const signature     = _hmac(_signingKey(SECRET_KEY, dateStamp, REGION, 's3'), stringToSign, 'hex');

  return `AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

// ── Core S3 request ───────────────────────────────────────────────────────────

function _s3Request({ method, key, body, contentType, extraHeaders, query }) {
  return new Promise((resolve, reject) => {
    const host     = `${BUCKET}.s3.${REGION}.amazonaws.com`;
    // key === null is a bucket-root request (e.g. ListObjectsV2 — GET /?list-type=2&...)
    const path     = key != null ? '/' + encodeURIComponent(key).replace(/%2F/g, '/') : '/';
    const qs       = query ? _canonicalQuerystring(query) : '';
    const payload  = body || Buffer.alloc(0);
    const dateTime = new Date().toISOString().replace(/[:-]/g, '').replace(/\.\d+/, '');
    const hdrs     = {
      'host':             host,
      'x-amz-date':       dateTime,
      'x-amz-content-sha256': _sha256(payload),
      ...(contentType ? { 'content-type': contentType } : {}),
      ...(extraHeaders || {}),
    };
    if (method === 'PUT' && SSE) {
      hdrs['x-amz-server-side-encryption'] = SSE;
      if (SSE === 'aws:kms' && KMS_KEY_ID) hdrs['x-amz-server-side-encryption-aws-kms-key-id'] = KMS_KEY_ID;
    }
    if (method !== 'GET' && method !== 'HEAD' && method !== 'DELETE') {
      hdrs['content-length'] = String(Buffer.byteLength(payload));
    }
    hdrs['authorization'] = _sign(method, path, qs, hdrs, payload, dateTime);

    const reqOpts = { hostname: host, path: qs ? `${path}?${qs}` : path, method, headers: hdrs };
    const req = https.request(reqOpts, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const buf  = Buffer.concat(chunks);
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ ok: true, status: res.statusCode, body: buf, headers: res.headers });
        } else {
          reject(new Error(`S3 ${method} ${key != null ? key : path} → ${res.statusCode}: ${buf.toString().slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    if (method !== 'GET' && method !== 'HEAD' && method !== 'DELETE') req.write(payload);
    req.end();
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Upload a file to S3.
 * @param {string} key          - S3 object key (relative, PREFIX prepended automatically)
 * @param {Buffer} data         - file content
 * @param {string} contentType  - MIME type
 * @returns {Promise<string>}   - S3 URL
 */
async function uploadFile(key, data, contentType) {
  if (!S3_ENABLED) throw new Error('S3 not configured');
  const fullKey = PREFIX + key;
  await _s3Request({ method: 'PUT', key: fullKey, body: data, contentType });
  return `https://${BUCKET}.s3.${REGION}.amazonaws.com/${fullKey}`;
}

/**
 * Download a file from S3.
 * @param {string} key
 * @returns {Promise<Buffer>}
 */
async function downloadFile(key) {
  if (!S3_ENABLED) throw new Error('S3 not configured');
  const result = await _s3Request({ method: 'GET', key: PREFIX + key });
  return result.body;
}

/**
 * Delete a file from S3.
 * @param {string} key
 */
async function deleteFile(key) {
  if (!S3_ENABLED) throw new Error('S3 not configured');
  await _s3Request({ method: 'DELETE', key: PREFIX + key });
}

/**
 * Store a JSON data file (e.g. certificates.json) in S3.
 * @param {string} dataKey  - e.g. "data/certificates.json"
 * @param {object} obj
 */
async function putJson(dataKey, obj) {
  if (!S3_ENABLED) throw new Error('S3 not configured');
  const buf = Buffer.from(JSON.stringify(obj, null, 2), 'utf8');
  await _s3Request({ method: 'PUT', key: PREFIX + dataKey, body: buf, contentType: 'application/json' });
}

/**
 * Retrieve a JSON data file from S3.
 * @param {string} dataKey
 * @returns {Promise<object>}
 */
async function getJson(dataKey) {
  if (!S3_ENABLED) throw new Error('S3 not configured');
  const result = await _s3Request({ method: 'GET', key: PREFIX + dataKey });
  return JSON.parse(result.body.toString('utf8'));
}

/**
 * List object keys under a prefix (ListObjectsV2). Returns keys with S3_PREFIX
 * already stripped, so they're directly comparable to the keys passed to
 * uploadFile/putJson/deleteFile elsewhere in the app. Used for bulk cleanup
 * (e.g. deleting everything under a tenant's data/uploads prefix) where the
 * exact set of object keys isn't known in advance.
 * @param {string} prefix
 * @returns {Promise<string[]>}
 */
async function listObjects(prefix) {
  if (!S3_ENABLED) throw new Error('S3 not configured');
  const result = await _s3Request({ method: 'GET', key: null, query: { 'list-type': '2', prefix: PREFIX + prefix } });
  const xml = result.body.toString('utf8');
  const keys = [];
  const re = /<Key>([^<]*)<\/Key>/g;
  let m;
  while ((m = re.exec(xml))) {
    const k = m[1].replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&apos;/g, "'");
    keys.push(PREFIX && k.startsWith(PREFIX) ? k.slice(PREFIX.length) : k);
  }
  return keys;
}

module.exports = {
  S3_ENABLED,
  BUCKET,
  REGION,
  PREFIX,
  uploadFile,
  downloadFile,
  deleteFile,
  putJson,
  getJson,
  listObjects,
};
