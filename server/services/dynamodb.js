'use strict';

/**
 * dynamodb.js — Zero-dependency AWS DynamoDB service using native Node.js
 * https + SigV4, mirroring services/s3.js (same signing helpers, same
 * static-credential model — no AWS SDK, no IMDS instance-role credential
 * fetching yet, the same gap that already exists for S3 today).
 *
 * Enabled when DYNAMO_TABLE_NAME is set. Degrades gracefully
 * (DYNAMO_ENABLED === false) so callers can fall back to the existing
 * JSON/S3-backed stores unmodified.
 *
 * Environment variables:
 *   DYNAMO_TABLE_NAME   — required to enable DynamoDB (matches Terraform's dynamodb_table_name)
 *   DYNAMO_REGION       — defaults to AWS_REGION, then ap-south-1
 *   DYNAMO_ACCESS_KEY   — falls back to S3_ACCESS_KEY, then AWS_ACCESS_KEY_ID
 *   DYNAMO_SECRET_KEY   — falls back to S3_SECRET_KEY, then AWS_SECRET_ACCESS_KEY
 */

const https  = require('https');
const crypto = require('crypto');

const REGION     = process.env.DYNAMO_REGION     || process.env.AWS_REGION            || 'ap-south-1';
const TABLE      = process.env.DYNAMO_TABLE_NAME  || '';
const ACCESS_KEY = process.env.DYNAMO_ACCESS_KEY  || process.env.S3_ACCESS_KEY  || process.env.AWS_ACCESS_KEY_ID     || '';
const SECRET_KEY = process.env.DYNAMO_SECRET_KEY  || process.env.S3_SECRET_KEY  || process.env.AWS_SECRET_ACCESS_KEY || '';

const DYNAMO_ENABLED = !!(TABLE && ACCESS_KEY && SECRET_KEY);
const HOST = `dynamodb.${REGION}.amazonaws.com`;

// ── SigV4 signing helpers (identical shape to services/s3.js, service="dynamodb") ──

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

function _sign(method, reqPath, headers, payload, dateTime) {
  const dateStamp  = dateTime.slice(0, 8);
  const sortedHdrs = Object.entries(headers)
    .map(([k, v]) => [k.toLowerCase(), v.trim()])
    .sort((a, b) => a[0].localeCompare(b[0]));
  const signedHeaders = sortedHdrs.map(([k]) => k).join(';');
  const canonicalHdrs = sortedHdrs.map(([k, v]) => `${k}:${v}\n`).join('');
  const payloadHash   = _sha256(payload);

  const canonicalReq = [method, reqPath, '', canonicalHdrs, signedHeaders, payloadHash].join('\n');
  const credScope     = `${dateStamp}/${REGION}/dynamodb/aws4_request`;
  const stringToSign  = `AWS4-HMAC-SHA256\n${dateTime}\n${credScope}\n${_sha256(canonicalReq)}`;
  const signature     = _hmac(_signingKey(SECRET_KEY, dateStamp, REGION, 'dynamodb'), stringToSign, 'hex');

  return `AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

// ── Core request (DynamoDB JSON 1.0 protocol — a single POST / per action) ──

function _request(target, params) {
  return new Promise((resolve, reject) => {
    const payload  = Buffer.from(JSON.stringify(params), 'utf8');
    const dateTime = new Date().toISOString().replace(/[:-]/g, '').replace(/\.\d+/, '');
    const hdrs = {
      'host':           HOST,
      'x-amz-date':     dateTime,
      'x-amz-target':   `DynamoDB_20120810.${target}`,
      'content-type':   'application/x-amz-json-1.0',
      'content-length': String(payload.length),
    };
    hdrs['authorization'] = _sign('POST', '/', hdrs, payload, dateTime);

    const req = https.request({ hostname: HOST, path: '/', method: 'POST', headers: hdrs }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        let json;
        try { json = JSON.parse(buf.toString('utf8') || '{}'); } catch { json = {}; }
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(json);
        } else {
          const err = new Error(`DynamoDB ${target} → ${res.statusCode}: ${json.message || buf.toString().slice(0, 200)}`);
          err.code = json.__type || String(res.statusCode);
          reject(err);
        }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ── Attribute-value marshalling — a subset sufficient for JSON-shaped records
//    (string/number/boolean/null/array/object); no Set/Binary support since
//    nothing in this codebase's data model needs them. ─────────────────────

function marshal(value) {
  if (value === null || value === undefined) return { NULL: true };
  // DynamoDB has supported empty-string S values since 2020 — do not collapse
  // '' to NULL. Doing so silently turns e.g. recipientEmail: "" into null on
  // every round-trip, a real drift a shadow-read diff would flag as a
  // mismatch against the JSON-file copy, which keeps '' as-is.
  if (typeof value === 'string') return { S: value };
  if (typeof value === 'number' && Number.isFinite(value)) return { N: String(value) };
  if (typeof value === 'boolean') return { BOOL: value };
  if (Array.isArray(value)) return { L: value.map(marshal) };
  if (typeof value === 'object') {
    const M = {};
    for (const [k, v] of Object.entries(value)) M[k] = marshal(v);
    return { M };
  }
  return { NULL: true };
}

function unmarshal(av) {
  if (!av || typeof av !== 'object') return null;
  if ('S' in av) return av.S;
  if ('N' in av) return Number(av.N);
  if ('BOOL' in av) return av.BOOL;
  if ('NULL' in av) return null;
  if ('L' in av) return av.L.map(unmarshal);
  if ('M' in av) {
    const out = {};
    for (const [k, v] of Object.entries(av.M)) out[k] = unmarshal(v);
    return out;
  }
  return null;
}

function marshalItem(obj) {
  const item = {};
  for (const [k, v] of Object.entries(obj)) item[k] = marshal(v);
  return item;
}

function unmarshalItem(item) {
  if (!item) return null;
  const obj = {};
  for (const [k, v] of Object.entries(item)) obj[k] = unmarshal(v);
  return obj;
}

// ── Public API ────────────────────────────────────────────────────────────

async function putItem(item) {
  if (!DYNAMO_ENABLED) throw new Error('DynamoDB not configured');
  await _request('PutItem', { TableName: TABLE, Item: marshalItem(item) });
}

async function deleteItem(key) {
  if (!DYNAMO_ENABLED) throw new Error('DynamoDB not configured');
  await _request('DeleteItem', { TableName: TABLE, Key: marshalItem(key) });
}

async function getItem(key) {
  if (!DYNAMO_ENABLED) throw new Error('DynamoDB not configured');
  const res = await _request('GetItem', { TableName: TABLE, Key: marshalItem(key) });
  return unmarshalItem(res.Item);
}

// `params` uses already-marshalled AttributeValues (KeyConditionExpression +
// ExpressionAttributeValues), matching the raw DynamoDB wire format. Pages
// through LastEvaluatedKey internally — callers always get every match.
async function query(params) {
  if (!DYNAMO_ENABLED) throw new Error('DynamoDB not configured');
  const items = [];
  let ExclusiveStartKey;
  do {
    const res = await _request('Query', {
      TableName: TABLE,
      ...params,
      ...(ExclusiveStartKey ? { ExclusiveStartKey } : {}),
    });
    (res.Items || []).forEach(i => items.push(unmarshalItem(i)));
    ExclusiveStartKey = res.LastEvaluatedKey;
  } while (ExclusiveStartKey);
  return items;
}

// `writeRequests` is an array of already-marshalled { PutRequest } /
// { DeleteRequest } entries. Chunks into groups of 25 (BatchWriteItem's hard
// limit) and retries UnprocessedItems until each chunk fully drains.
async function batchWrite(writeRequests) {
  if (!DYNAMO_ENABLED) throw new Error('DynamoDB not configured');
  for (let i = 0; i < writeRequests.length; i += 25) {
    let chunk = writeRequests.slice(i, i + 25);
    while (chunk.length) {
      const res = await _request('BatchWriteItem', { RequestItems: { [TABLE]: chunk } });
      chunk = (res.UnprocessedItems && res.UnprocessedItems[TABLE]) || [];
    }
  }
}

module.exports = {
  DYNAMO_ENABLED,
  TABLE,
  REGION,
  putItem,
  deleteItem,
  getItem,
  query,
  batchWrite,
  marshal,
  unmarshal,
  marshalItem,
  unmarshalItem,
};
