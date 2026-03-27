/**
 * Synergy Certificate Verification Portal — Server (MERGED SINGLE PORT)
 * Pure Node.js · Zero npm dependencies
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  SECURITY HARDENING — v3.2 (Bug-Fix & Hardening Release)   ║
 * ║                                                              ║
 * ║  ✦ AES-256-GCM encrypted + HMAC-signed public cert URLs     ║
 * ║  ✦ Random 128-bit token prefix (opaque, non-enumerable)     ║
 * ║  ✦ Signed JWT-style admin tokens with expiry (8h)           ║
 * ║  ✦ Bcrypt-equivalent PBKDF2 password hashing                ║
 * ║  ✦ Rate limiting on all public endpoints (IP-based)         ║
 * ║  ✦ CORS restricted to allowed origins only                  ║
 * ║  ✦ Strict path traversal protection                         ║
 * ║  ✦ Security headers (CSP, HSTS, X-Frame-Options, etc.)      ║
 * ║  ✦ No credentials ever exposed in startup logs              ║
 * ║  ✦ Input sanitisation on all cert ID parameters             ║
 * ║                                                              ║
 * ║  FIXES v3.2                                                  ║
 * ║  • POST /api/verify-email/:id — server-side email gate      ║
 * ║    for CST (replaces broken client-side compare)            ║
 * ║  • POST /api/vapt/verify-email/:id — same for VAPT          ║
 * ║  • Email gate now timing-safe HMAC compare (no PII leak)    ║
 * ║  • Brute-force delay added to email gate endpoints          ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Public Portal  → http://localhost:3000/
 * Admin Panel    → http://localhost:3000/admin
 * API            → http://localhost:3000/api
 */

'use strict';

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ─── LOGGER ──────────────────────────────────────────────────────────────────
const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();
const _logLvl   = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 }[LOG_LEVEL] ?? 1;
function _ts() { return new Date().toISOString().slice(11, 23); }
const log = {
  info:  (...a) => _logLvl <= 1 && console.log( _ts(), '[info] ', ...a),
  warn:  (...a) => _logLvl <= 2 && console.warn( _ts(), '[warn] ', ...a),
  error: (...a) => _logLvl <= 3 && console.error(_ts(), '[error]', ...a),
};

// ─── CENTRALIZED CONFIG ──────────────────────────────────────────────────────
const CFG = require('../config/app.config');

// ─── ENV LOADER ──────────────────────────────────────────────────────────────
(function loadDotEnv() {
  const envPaths = [
    path.join(__dirname, '.env'),
    path.join(__dirname, '..', '.env'),
  ];
  for (const envFile of envPaths) {
    if (!fs.existsSync(envFile)) continue;
    const lines = fs.readFileSync(envFile, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx < 1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      let val   = trimmed.slice(eqIdx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) ||
          (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (process.env[key] === undefined) process.env[key] = val;
    }
    log.info('Configuration loaded from', envFile);
    break;
  }
})();

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const PORT           = parseInt(process.env.PORT || '3000', 10);
const DATA_FILE        = path.join(__dirname, '..', 'data', 'certificates.json');
const VAPT_DATA_FILE   = path.join(__dirname, '..', 'data', 'vapt_certificates.json');
const TRACK_FILE       = path.join(__dirname, '..', 'data', 'tracking_events.jsonl');
const UPLOADS_DIR      = path.join(__dirname, '..', 'uploads');
const KEYS_FILE        = path.join(__dirname, '..', 'data', '.keys.json');

// ─── DEPLOYMENT CONFIG ───────────────────────────────────────────────────────
const BASE_ORIGIN = (process.env.BASE_ORIGIN || `http://localhost:${PORT}`).replace(/\/+$/, '');

// Warn loudly if BASE_ORIGIN is still localhost — tracking pixels embedded in emails
// point to this value. If it's localhost, recipients' email clients hit their own
// machine instead of this server, so email-open events are never recorded.
if (/^https?:\/\/(localhost|127\.0\.0\.1)/.test(BASE_ORIGIN)) {
  log.warn('⚠️  BASE_ORIGIN is set to localhost (' + BASE_ORIGIN + '). ' +
    'Email open tracking will NOT work for external recipients. ' +
    'Set BASE_ORIGIN=https://your-public-domain.com in your .env file.');
}

function _originVariants(origin) {
  if (!origin || /^https?:\/\/(localhost|127\.0\.0\.1)/.test(origin)) return [origin];
  const alt = origin.startsWith('https://')
    ? origin.replace('https://', 'http://')
    : origin.replace('http://', 'https://');
  return [origin, alt];
}

const ALLOWED_ORIGINS = [
  ..._originVariants(BASE_ORIGIN),
  'http://localhost:3000',
  'http://127.0.0.1:3000',
].filter((v, i, a) => Boolean(v) && a.indexOf(v) === i);

[path.dirname(DATA_FILE), UPLOADS_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ─── PERSISTENT CRYPTO KEYS ──────────────────────────────────────────────────
function loadOrCreateKeys() {
  if (fs.existsSync(KEYS_FILE)) {
    try {
      const k = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
      if (k.urlEncKey && k.urlMacKey && k.jwtSecret && k.pwdSalt) return k;
    } catch { /* fall through to create */ }
  }
  const keys = {
    urlEncKey: crypto.randomBytes(32).toString('hex'),
    urlMacKey: crypto.randomBytes(32).toString('hex'),
    jwtSecret: crypto.randomBytes(48).toString('hex'),
    pwdSalt:   crypto.randomBytes(32).toString('hex'),
  };
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2), { encoding: 'utf8', mode: 0o600 });
  log.info('New cryptographic keys generated and persisted.');
  return keys;
}
const KEYS = loadOrCreateKeys();

// ─── ADMIN CREDENTIALS ───────────────────────────────────────────────────────
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

if (!ADMIN_USER || !ADMIN_PASS) {
  log.error('ADMIN_USER and ADMIN_PASS must be set in your .env file before starting the server.');
  process.exit(1);
}

// ─── PASSWORD HASHING ────────────────────────────────────────────────────────
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, KEYS.pwdSalt, 310000, 32, 'sha256', (err, key) => {
      if (err) reject(err);
      else resolve(key.toString('hex'));
    });
  });
}

let ADMIN_PASS_HASH = '';
let serverReady = false;
let isShuttingDown = false;
let _shutdownTimer = null;

async function initialiseRuntimePrerequisites() {
  // Prepare auth hash before accepting requests.
  ADMIN_PASS_HASH = await hashPassword(ADMIN_PASS);

  // Warm caches and ensure writable runtime directories exist.
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.mkdirSync(path.dirname(VAPT_DATA_FILE), { recursive: true });
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  loadData();
  loadVaptData();

  serverReady = true;
  log.info('Runtime initialisation complete.');
}

// ─── JWT-STYLE ADMIN TOKENS ──────────────────────────────────────────────────
const TOKEN_EXPIRY_MS = 8 * 60 * 60 * 1000;

function issueToken(username) {
  const payload = {
    sub: username,
    iat: Date.now(),
    exp: Date.now() + TOKEN_EXPIRY_MS,
    jti: crypto.randomBytes(16).toString('hex'),
  };
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body   = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig    = crypto.createHmac('sha256', KEYS.jwtSecret)
    .update(header + '.' + body).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const expected = crypto.createHmac('sha256', KEYS.jwtSecret)
    .update(header + '.' + body).digest('base64url');
  const sigBuf      = Buffer.from(sig);
  const expectedBuf = Buffer.from(expected);
  if (sigBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ─── ENCRYPTED + SIGNED PUBLIC CERT URLs ─────────────────────────────────────
function encryptCertToken(certId) {
  const key    = Buffer.from(KEYS.urlEncKey, 'hex');
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(certId, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64url');
}

function decryptCertToken(token) {
  try {
    const raw = Buffer.from(token, 'base64url');
    if (raw.length < 29) return null;
    const iv       = raw.subarray(0, 12);
    const tag      = raw.subarray(12, 28);
    const enc      = raw.subarray(28);
    const key      = Buffer.from(KEYS.urlEncKey, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc).toString('utf8') + decipher.final('utf8');
  } catch { return null; }
}

function signCertUrl(encToken) {
  return crypto.createHmac('sha256', KEYS.urlMacKey)
    .update('cert:' + encToken).digest('base64url').slice(0, 22);
}

function verifyCertUrlSignature(encToken, sig) {
  if (!sig) return false;
  const expected = signCertUrl(encToken);
  if (sig.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

function buildCertUrl(certId, baseUrl) {
  const token = encryptCertToken(certId);
  const sig   = signCertUrl(token);
  return `${baseUrl}${CFG.routes.cst}/cert/${token}?s=${sig}`;
}

// ─── RATE LIMITER ─────────────────────────────────────────────────────────────
const rateLimits = new Map();
const RATE_LIMITS = {
  verify:  { max: 30,  window: 60_000  },
  login:   { max: 5,   window: 300_000 },
  default: { max: 120, window: 60_000  },
};
// FIX: cap Map size to prevent memory exhaustion from unique-IP floods
const RATE_LIMIT_MAX_ENTRIES = 50_000;

function checkRateLimit(ip, bucket) {
  const { max, window } = RATE_LIMITS[bucket] || RATE_LIMITS.default;
  const key   = `${bucket}:${ip}`;
  const now   = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || now > entry.resetAt) {
    // If Map is full, evict one stale entry before inserting
    if (!entry && rateLimits.size >= RATE_LIMIT_MAX_ENTRIES) {
      const firstKey = rateLimits.keys().next().value;
      if (firstKey) rateLimits.delete(firstKey);
    }
    rateLimits.set(key, { count: 1, resetAt: now + window });
    return { ok: true, remaining: max - 1 };
  }
  if (entry.count >= max) return { ok: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
  entry.count++;
  return { ok: true, remaining: max - entry.count };
}

const _rlCleanup = setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimits) if (now > v.resetAt) rateLimits.delete(k);
}, 60_000);

// ─── SECURITY HEADERS ────────────────────────────────────────────────────────
const _isHttps = BASE_ORIGIN.startsWith('https://');
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options':        'DENY',
  'X-XSS-Protection':       '1; mode=block',
  'Referrer-Policy':        'strict-origin-when-cross-origin',
  'Permissions-Policy':     'camera=(), microphone=(), geolocation=()',
  ...(_isHttps ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {}),
  'Content-Security-Policy':
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: blob:; " +
    "connect-src 'self'; " +
    "frame-src 'self' blob:; " +
    "frame-ancestors 'none';",
};

// ─── SEED DATA ───────────────────────────────────────────────────────────────
const SEED = {
  "CST-9623740-01-26": {
    id: "CST-9623740-01-26",
    recipientName: "MV - NORD KUDU",
    vesselName: "NORD KUDU",
    vesselIMO: "9623740",
    chiefEngineer: "BARREGA WILLIE PANIAMOGAN",
    trainingTitle: CFG.cst.trainingTitle,
    organizer: CFG.cst.organizer,
    complianceDate: "2026-01-30",
    complianceQuarter: "Q1",
    trainingMode: "ONLINE",
    validFor: "Q2 (APR–JUN)-2026",
    certificateImage: null,
    notes: CFG.cst.notes,
    recipientEmail: "",
    issuerEmail: CFG.cst.issuerEmail,
    emailStatus: "NOT_SENT",
    emailSentAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  "CST-9689536-02-26": {
    id: "CST-9689536-02-26",
    recipientName: "MT - BW CHINOOK",
    vesselName: "BW CHINOOK",
    vesselIMO: "9689536",
    chiefEngineer: "TARAK NATH",
    trainingTitle: CFG.cst.trainingTitle,
    organizer: CFG.cst.organizer,
    complianceDate: "2026-02-12",
    complianceQuarter: "Q1",
    trainingMode: "ONLINE",
    validFor: "Q2 (APR–JUN)-2026",
    certificateImage: null,
    notes: CFG.cst.notes,
    recipientEmail: "",
    issuerEmail: CFG.cst.issuerEmail,
    emailStatus: "NOT_SENT",
    emailSentAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  }
};

// ─── DATA STORE ──────────────────────────────────────────────────────────────
let _certCache = null;
function loadData() {
  if (_certCache) return _certCache;
  try {
    if (fs.existsSync(DATA_FILE)) {
      _certCache = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      return _certCache;
    }
  } catch { }
  _certCache = { ...SEED };
  saveData(_certCache);
  return _certCache;
}
function saveData(data) {
  _certCache = data;
  // Debounced write — coalesces rapid successive saves into one disk write
  clearTimeout(saveData._t);
  saveData._t = setTimeout(() => {
    fs.promises.writeFile(DATA_FILE, JSON.stringify(data, null, 2), 'utf8')
      .catch(err => log.error('Failed to persist certificate data:', err.message));
  }, 50);
}

// ─── VAPT SEED DATA ──────────────────────────────────────────────────────────
const VAPT_SEED = {
  "VAP-9491666-1026": {
    id: "VAP-9491666-1026",
    recipientName: "MV Efficiency OL",
    vesselName: "Efficiency OL",
    vesselIMO: "9491666",
    certificateNumber: "VAP-9491666-1026",
    assessmentDate: "2026-02-10",
    validUntil: "2027-02-10",
    verifiedBy: CFG.vapt.verifiedBy,
    verifierTitle: CFG.vapt.verifierTitle,
    assessingOrg: CFG.vapt.assessingOrg,
    frameworks: CFG.vapt.frameworks,
    scopeItems: CFG.vapt.scopeItems,
    status: "VALID",
    issuedAt: "2026-02-10",
    certificateImage: null,
    recipientEmail: "",
    issuerEmail: CFG.vapt.issuerEmail,
    emailStatus: "NOT_SENT",
    emailSentAt: null,
    notes: "Re-assessment recommended within 2 weeks from date of participation.",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  }
};

// ─── VAPT DATA STORE ─────────────────────────────────────────────────────────
let _vaptCache = null;
function loadVaptData() {
  if (_vaptCache) return _vaptCache;
  try {
    if (fs.existsSync(VAPT_DATA_FILE)) {
      _vaptCache = JSON.parse(fs.readFileSync(VAPT_DATA_FILE, 'utf8'));
      return _vaptCache;
    }
  } catch { }
  _vaptCache = { ...VAPT_SEED };
  saveVaptData(_vaptCache);
  return _vaptCache;
}
function saveVaptData(data) {
  _vaptCache = data;
  clearTimeout(saveVaptData._t);
  saveVaptData._t = setTimeout(() => {
    fs.promises.writeFile(VAPT_DATA_FILE, JSON.stringify(data, null, 2), 'utf8')
      .catch(err => log.error('Failed to persist VAPT certificate data:', err.message));
  }, 50);
}

// ─── VAPT CERT URL BUILDER ───────────────────────────────────────────────────
function buildVaptCertUrl(certId, baseUrl) {
  const token = encryptCertToken(certId);
  const sig   = signCertUrl(token);
  return `${baseUrl}${CFG.routes.vpt}/cert/${token}?s=${sig}`;
}

// ─── EMAIL DISPATCH (AWS SES — pure Node.js, zero npm deps) ────────────────────
// Authenticates with AWS Signature Version 4 and sends via the SES v2 REST API.
// Configure the following in your .env file:
//   AWS_REGION            SES region  (e.g. us-east-1)
//   AWS_ACCESS_KEY_ID     IAM access key with ses:SendEmail permission
//   AWS_SECRET_ACCESS_KEY IAM secret key
//   AWS_SES_FROM_CST      Verified sender address for CST emails
//   AWS_SES_FROM_VAPT     Verified sender address for VAPT emails
// Legacy aliases AWS_SES_REGION / AWS_SES_ACCESS_KEY / AWS_SES_SECRET_KEY are also accepted.
const SES_REGION     = process.env.AWS_REGION             || process.env.AWS_SES_REGION     || '';
const SES_ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID      || process.env.AWS_SES_ACCESS_KEY || '';
const SES_SECRET_KEY = process.env.AWS_SECRET_ACCESS_KEY  || process.env.AWS_SES_SECRET_KEY || '';
const SES_FROM_CST   = process.env.AWS_SES_FROM_CST   || CFG.contact.cstEmail;
const SES_FROM_VAPT  = process.env.AWS_SES_FROM_VAPT  || CFG.contact.vaptEmail;

const SES_ENABLED = Boolean(SES_REGION && SES_ACCESS_KEY && SES_SECRET_KEY);

if (SES_ENABLED) {
  log.info(`Email dispatch ready (${SES_REGION}) — CST: ${SES_FROM_CST} · VAPT: ${SES_FROM_VAPT}`);
} else {
  log.warn('Email dispatch not configured — credential emails will be unavailable until AWS credentials are set in .env.');
}

/**
 * Dispatch a raw RFC-2822 message via the AWS SES v2 REST API.
 * @param {string}   rawMessage   RFC-2822 formatted email string
 * @param {string}   fromAddress  Verified sender address
 * @param {string[]} toAddresses  Recipient address(es)
 * @returns {Promise<{success:boolean, messageId?:string, error?:string}>}
 */
function sesSendRaw(rawMessage, fromAddress, toAddresses) {
  return new Promise((resolve) => {
    if (!SES_ENABLED) {
      resolve({ success: false, error: 'Email service not configured.' });
      return;
    }

    // NOTE: `https` is now required at top-level (no longer re-required per call)
    const region  = SES_REGION;
    const host    = `email.${region}.amazonaws.com`;
    const service = 'ses';
    const method  = 'POST';
    const uri     = '/v2/email/outbound-emails';

    const rawB64   = Buffer.from(rawMessage).toString('base64');
    const bareFrom = (fromAddress.match(/<([^>]+)>/) || [])[1] || fromAddress;
    const bodyObj  = {
      Content:          { Raw: { Data: rawB64 } },
      Destination:      { ToAddresses: toAddresses },
      FromEmailAddress: bareFrom,
    };
    const bodyStr = JSON.stringify(bodyObj);

    // AWS Signature Version 4
    const now       = new Date();
    const date      = now.toISOString().slice(0, 10).replace(/-/g, '');
    const time      = now.toISOString().replace(/[-:.]/g, '').slice(0, 15) + 'Z';
    const credScope = `${date}/${region}/${service}/aws4_request`;

    function hmac(key, data)    { return crypto.createHmac('sha256', key).update(data).digest(); }
    function hmacHex(key, data) { return crypto.createHmac('sha256', key).update(data).digest('hex'); }
    function sha256hex(data)    { return crypto.createHash('sha256').update(data).digest('hex'); }

    const payloadHash      = sha256hex(bodyStr);
    const signedHeaders    = 'content-type;host;x-amz-date';
    const canonicalHeaders = `content-type:application/json\nhost:${host}\nx-amz-date:${time}\n`;
    const canonicalRequest = [method, uri, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
    const strToSign        = ['AWS4-HMAC-SHA256', time, credScope, sha256hex(canonicalRequest)].join('\n');

    const signingKey = hmac(
      hmac(hmac(hmac('AWS4' + SES_SECRET_KEY, date), region), service), 'aws4_request'
    );
    const signature  = hmacHex(signingKey, strToSign);
    const authHeader = `AWS4-HMAC-SHA256 Credential=${SES_ACCESS_KEY}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const options = {
      hostname: host,
      port:     443,
      path:     uri,
      method,
      headers: {
        'Content-Type':  'application/json',
        'Host':           host,
        'X-Amz-Date':     time,
        'Content-Length': Buffer.byteLength(bodyStr),
        'Authorization':  authHeader,
      },
    };

    const httpreq = https.request(options, (httpsRes) => {
      let data = '';
      httpsRes.on('data', c => { data += c; });
      httpsRes.on('end', () => {
        if (httpsRes.statusCode === 200) {
          try {
            const json = JSON.parse(data);
            resolve({ success: true, messageId: json.MessageId || '' });
          } catch {
            resolve({ success: true, messageId: '' });
          }
        } else {
          try {
            const json = JSON.parse(data);
            const msg  = json.message || json.Message || JSON.stringify(json);
            resolve({ success: false, error: msg });
          } catch {
            resolve({ success: false, error: `HTTP ${httpsRes.statusCode}: ${data.slice(0, 200)}` });
          }
        }
      });
    });
    httpreq.setTimeout(15_000, () => { httpreq.destroy(); resolve({ success: false, error: 'Email service did not respond in time.' }); });
    httpreq.on('error', (err) => resolve({ success: false, error: err.message }));
    httpreq.write(bodyStr);
    httpreq.end();
  });
}


/**
 * Build a branded RFC 2822 email with certificate image attachment.
 * Produces multipart/mixed → multipart/alternative (text + HTML) + image attachment.
 * @param {object} opts
 * @param {string}  opts.from
 * @param {string}  opts.to
 * @param {string}  opts.subject
 * @param {string}  opts.body          Plain-text body
 * @param {string}  [opts.replyTo]
 * @param {string}  [opts.trackingPixelUrl]
 * @param {Buffer}  [opts.certImageData]   Raw bytes of certificate image
 * @param {string}  [opts.certImageName]   Filename e.g. "certificate.png"
 * @param {string}  [opts.certImageMime]   MIME type e.g. "image/png"
 */
function buildRawEmail({ from, to, subject, body, replyTo, trackingPixelUrl, certImageData, certImageName, certImageMime }) {
  const b64subject = '=?UTF-8?B?' + Buffer.from(subject).toString('base64') + '?=';
  const msgId      = `<${crypto.randomBytes(16).toString('hex')}.${Date.now()}@${(from.match(/@([^>\s]+)/) || [])[1] || 'mail'}>`;
  const dateStr    = new Date().toUTCString().replace(/GMT$/, '+0000');
  const outerBnd   = 'SYNMIX_' + crypto.randomBytes(8).toString('hex');
  const innerBnd   = 'SYNALT_' + crypto.randomBytes(8).toString('hex');
  const hasImage   = certImageData && certImageData.length > 0;

  // ── Plain-text part ──────────────────────────────────────────────────────
  const plainB64 = Buffer.from(body).toString('base64').replace(/(.{76})/g, '$1\r\n').trimEnd();

  // ── HTML part: branded email template ────────────────────────────────────
  const urlRegex = /(https?:\/\/[^\s\r\n]+)/g;
  const esc = s => s
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const lines = body.split(/\r?\n/);
  let htmlContent = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const hasUrl = urlRegex.test(line);
    urlRegex.lastIndex = 0;

    if (hasUrl) {
      const replaced = esc(line).replace(/(https?:\/\/[^\s&<]+(?:&amp;[^\s<]*)?)/g, (escapedUrl) => {
        const rawUrl = escapedUrl.replace(/&amp;/g, '&');
        return `</p>
          <div style="margin:20px 0;text-align:center">
            <a href="${rawUrl}" target="_blank" rel="noopener"
              style="display:inline-block;padding:14px 32px;
                     background:linear-gradient(135deg,#D4A843,#9E7B0A);
                     color:#0A1628;border-radius:8px;
                     font-family:Arial,Helvetica,sans-serif;font-size:15px;
                     font-weight:700;text-decoration:none;letter-spacing:.04em;
                     mso-padding-alt:14px 32px;line-height:1.2">
              &#128279;&nbsp; View &amp; Verify Certificate
            </a>
            <p style="margin:10px 0 0;font-size:11px;color:#6a7a8a;word-break:break-all">
              Or copy this link:<br>
              <a href="${rawUrl}" style="color:#1a6abf;word-break:break-all;font-size:11px">${rawUrl}</a>
            </p>
          </div>
          <p style="margin:0;font-size:14px;color:#2a3a4a;line-height:1.7">`;
      });
      htmlContent += `<p style="margin:0;font-size:14px;color:#2a3a4a;line-height:1.7">${replaced}</p>`;
    } else if (line.trim() === '') {
      htmlContent += `<p style="margin:0;font-size:7px;line-height:1">&nbsp;</p>`;
    } else {
      const isDataLine = /^[A-Za-z\s]+\s*:\s+\S/.test(line.trim());
      if (isDataLine) {
        const colonIdx = line.indexOf(':');
        const label = esc(line.slice(0, colonIdx + 1));
        const value = esc(line.slice(colonIdx + 1));
        htmlContent += `<p style="margin:3px 0;font-size:13px;color:#2a3a4a;line-height:1.6">
          <span style="color:#5a6a7a;min-width:160px;display:inline-block">${label}</span>${value}
        </p>`;
      } else {
        htmlContent += `<p style="margin:3px 0;font-size:14px;color:#2a3a4a;line-height:1.7">${esc(line)}</p>`;
      }
    }
  }

  const brandName = CFG.brand.name || 'Synergy Marine Group';

  // Logo SVG: shield with check — same icon used across the portal pages
  const logoSvg = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="1.8" style="display:inline-block;vertical-align:middle;margin-right:10px"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>`;

  const certNote = hasImage
    ? `<p style="margin:16px 0 0;font-size:12px;color:#6a7a8a;text-align:center;border-top:1px solid #e8edf4;padding-top:14px">
        📎 Your certificate image is attached to this email.
      </p>`
    : '';

  const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>${esc(subject)}</title>
</head>
<body style="margin:0;padding:0;background:#eef2f7;font-family:Arial,Helvetica,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#eef2f7;padding:32px 16px">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.10)">

        <!-- Header bar with logo -->
        <tr>
          <td style="background:linear-gradient(135deg,#0A1628 0%,#1D3557 100%);padding:28px 32px;text-align:center">
            <div style="margin-bottom:10px">${logoSvg}<span style="font-size:13px;letter-spacing:.18em;text-transform:uppercase;color:#D4A843;font-weight:800;vertical-align:middle">${esc(brandName)}</span></div>
            <p style="margin:4px 0 0;font-size:20px;font-weight:800;color:#ffffff;letter-spacing:.02em">${esc(subject.replace(/^(Subject:\s*)?Your (CST|VAPT) Certificate\s*—\s*/, '').replace(/\s*—\s*.+$/, '') || 'Certificate Notification')}</p>
            <p style="margin:6px 0 0;font-size:10px;color:#8892B0;letter-spacing:.14em;text-transform:uppercase">Cyber Security &amp; Compliance Division</p>
          </td>
        </tr>

        <!-- Body content -->
        <tr>
          <td style="padding:32px 36px 20px">
            ${htmlContent}
            ${certNote}
          </td>
        </tr>

        <!-- Divider -->
        <tr>
          <td style="padding:0 36px">
            <hr style="border:none;border-top:1px solid #e8edf4;margin:0">
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:20px 36px 28px;text-align:center">
            <p style="margin:0;font-size:11px;color:#8892B0;line-height:1.6">
              This is an automated message from the ${esc(brandName)} Cyber Security Certificate Registry.<br>
              Please do not reply directly to this email.
            </p>
            <p style="margin:10px 0 0;font-size:10px;color:#aab4c4">
              &copy; ${new Date().getFullYear()} ${esc(brandName)} &middot; Cyber Security &amp; Compliance Division
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
  ${trackingPixelUrl
    ? `<img src="${trackingPixelUrl}" width="1" height="1" alt="" style="display:none!important;width:1px!important;height:1px!important;min-width:1px;min-height:1px;overflow:hidden;mso-hide:all" />`
    : ''}
</body>
</html>`;

  const htmlB64 = Buffer.from(htmlBody).toString('base64').replace(/(.{76})/g, '$1\r\n').trimEnd();

  // ── Build MIME structure ─────────────────────────────────────────────────
  // With image: multipart/mixed → [multipart/alternative → [text, html]] + [image]
  // Without:    multipart/alternative → [text, html]
  const topType    = hasImage ? `multipart/mixed; boundary="${outerBnd}"` : `multipart/alternative; boundary="${innerBnd}"`;
  const emailLines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${b64subject}`,
    `Message-ID: ${msgId}`,
    `Date: ${dateStr}`,
    `MIME-Version: 1.0`,
    `Content-Type: ${topType}`,
  ];
  if (replyTo && replyTo !== from) emailLines.push(`Reply-To: ${replyTo}`);
  emailLines.push('');

  if (hasImage) {
    // Outer mixed: first part = alternative (text+html)
    emailLines.push(`--${outerBnd}`);
    emailLines.push(`Content-Type: multipart/alternative; boundary="${innerBnd}"`);
    emailLines.push('');
  }

  // Text part
  emailLines.push(`--${innerBnd}`);
  emailLines.push('Content-Type: text/plain; charset=UTF-8');
  emailLines.push('Content-Transfer-Encoding: base64');
  emailLines.push('');
  emailLines.push(plainB64);
  emailLines.push('');

  // HTML part
  emailLines.push(`--${innerBnd}`);
  emailLines.push('Content-Type: text/html; charset=UTF-8');
  emailLines.push('Content-Transfer-Encoding: base64');
  emailLines.push('');
  emailLines.push(htmlB64);
  emailLines.push('');
  emailLines.push(`--${innerBnd}--`);

  if (hasImage) {
    // Certificate image attachment
    const imgMime  = certImageMime || 'image/png';
    const imgName  = certImageName || 'certificate.png';
    const imgB64   = certImageData.toString('base64').replace(/(.{76})/g, '$1\r\n').trimEnd();
    emailLines.push('');
    emailLines.push(`--${outerBnd}`);
    emailLines.push(`Content-Type: ${imgMime}; name="${imgName}"`);
    emailLines.push('Content-Transfer-Encoding: base64');
    emailLines.push(`Content-Disposition: attachment; filename="${imgName}"`);
    emailLines.push('');
    emailLines.push(imgB64);
    emailLines.push('');
    emailLines.push(`--${outerBnd}--`);
  }

  return emailLines.join('\r\n');
}

// ─── EMAIL LOG HELPER// ─── EMAIL LOG HELPER ─────────────────────────────────────────────────────────
function logEmail(logFile, fields, sesResult) {
  const entry = {
    timestamp: new Date().toISOString(),
    ...fields,
    status:    sesResult.success ? 'SENT' : (SES_ENABLED ? 'FAILED' : 'LOGGED_ONLY'),
    messageId: sesResult.messageId || null,
    sesError:  sesResult.error     || null,
  };
  fs.promises.appendFile(logFile, JSON.stringify(entry) + '\n', 'utf8')
    .catch(() => { /* non-fatal */ });
}

// ─── ENGAGEMENT TRACKING ─────────────────────────────────────────────────────
// Events: email_opened | cert_viewed | document_downloaded
// Each cert stores an `engagement` object with timestamped arrays per event.

/**
 * Append a tracking event to the JSONL log file (non-blocking, non-fatal).
 */
function appendTrackEvent(certId, event, meta = {}) {
  const entry = JSON.stringify({
    t:      new Date().toISOString(),
    certId,
    event,
    ...meta,
  }) + '\n';
  fs.promises.appendFile(TRACK_FILE, entry, 'utf8').catch(() => {});
}

/**
 * Record an engagement event on the cert object itself and persist.
 * @param {object} data   - the full data store object (mutated in-place)
 * @param {string} certId
 * @param {'email_opened'|'cert_viewed'|'document_downloaded'} event
 * @param {object} [meta] - optional extra info (e.g. { file: 'cert.pdf' })
 * @param {function} saveFn - saveData or saveVaptData
 */
function recordEngagement(data, certId, event, meta, saveFn) {
  const cert = data[certId];
  if (!cert) return;
  if (!cert.engagement) cert.engagement = {};
  const eng = cert.engagement;
  const ts  = new Date().toISOString();
  switch (event) {
    case 'email_opened':
      if (!eng.emailOpenedAt) eng.emailOpenedAt = ts;
      eng.emailOpenCount = (eng.emailOpenCount || 0) + 1;
      eng.emailLastOpenAt = ts;
      break;
    case 'cert_viewed':
      if (!eng.certFirstViewedAt) eng.certFirstViewedAt = ts;
      eng.certViewCount = (eng.certViewCount || 0) + 1;
      eng.certLastViewedAt = ts;
      break;
    case 'document_downloaded':
      if (!eng.docFirstDownloadAt) eng.docFirstDownloadAt = ts;
      eng.docDownloadCount = (eng.docDownloadCount || 0) + 1;
      eng.docLastDownloadAt = ts;
      if (meta && meta.file) eng.docLastFile = meta.file;
      break;
  }
  data[certId] = cert;
  saveFn(data);
  appendTrackEvent(certId, event, meta);
}

/**
 * Build a signed 1×1 transparent GIF tracking pixel endpoint URL for an email.
 * The token is an HMAC-signed compact string: base64url(certId) + '.' + hmac
 */
function buildTrackingPixelUrl(certId, baseUrl, kind /* 'cst' | 'vapt' */) {
  const payload = Buffer.from(certId).toString('base64url');
  const sig     = crypto.createHmac('sha256', KEYS.urlMacKey)
    .update('track:' + kind + ':' + payload).digest('base64url').slice(0, 16);
  const prefix  = kind === 'vapt' ? '/api/vapt/track-open/' : '/api/track-open/';
  return `${baseUrl}${prefix}${payload}.${sig}`;
}

/** 1×1 transparent GIF bytes */
const TRACKING_PIXEL_GIF = Buffer.from(
  'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'
);

// ─── CST CREDENTIAL EMAIL ─────────────────────────────────────────────────────
async function sendCstEmail({ to, from, cert, verifyUrl, baseUrl }) {
  const body             = CFG.emailTemplates.cst(cert, verifyUrl);
  const subject          = `Your CST Certificate — ${cert.id} — ${CFG.brand.name}`;
  const trackingPixelUrl = buildTrackingPixelUrl(cert.id, BASE_ORIGIN, 'cst');

  // Load certificate image for attachment (if present)
  let certImageData = null, certImageName = null, certImageMime = null;
  if (cert.certificateImage) {
    try {
      const imgPath = path.join(UPLOADS_DIR, path.basename(cert.certificateImage));
      if (fs.existsSync(imgPath)) {
        certImageData = fs.readFileSync(imgPath);
        const ext     = path.extname(imgPath).toLowerCase();
        certImageMime = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp' }[ext] || 'image/png';
        certImageName = `certificate-${cert.id}${ext}`;
      }
    } catch (e) { log.warn('Could not load cert image for email attachment:', e.message); }
  }

  const raw     = buildRawEmail({ from, to, subject, body, replyTo: from, trackingPixelUrl, certImageData, certImageName, certImageMime });
  const result  = await sesSendRaw(raw, from, [to]);
  logEmail(
    path.join(path.dirname(DATA_FILE), 'email_log.jsonl'),
    { to, from, certId: cert.id, recipientName: cert.recipientName, subject, verifyUrl },
    result
  );
  return result;
}

// ─── VAPT CREDENTIAL EMAIL ────────────────────────────────────────────────────
async function sendVaptEmail({ to, from, cert, verifyUrl, baseUrl }) {
  const body  = CFG.emailTemplates.vapt(cert, verifyUrl);
  const lines = body.split('\n');
  let subject   = `Your VAPT Certificate — ${cert.id} — ${CFG.brand.companyShort || CFG.brand.name} Group`;
  let cleanBody = body;
  if (lines[0].startsWith('Subject:')) {
    subject   = lines[0].replace(/^Subject:\s*/, '').trim();
    cleanBody = lines.slice(2).join('\n');
  }
  const trackingPixelUrl = buildTrackingPixelUrl(cert.id, BASE_ORIGIN, 'vapt');

  // Load certificate image for attachment (if present)
  let certImageData = null, certImageName = null, certImageMime = null;
  if (cert.certificateImage) {
    try {
      const imgPath = path.join(UPLOADS_DIR, path.basename(cert.certificateImage));
      if (fs.existsSync(imgPath)) {
        certImageData = fs.readFileSync(imgPath);
        const ext     = path.extname(imgPath).toLowerCase();
        certImageMime = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp' }[ext] || 'image/png';
        certImageName = `certificate-${cert.id}${ext}`;
      }
    } catch (e) { log.warn('Could not load cert image for email attachment:', e.message); }
  }

  const raw    = buildRawEmail({ from, to, subject, body: cleanBody, replyTo: from, trackingPixelUrl, certImageData, certImageName, certImageMime });
  const result = await sesSendRaw(raw, from, [to]);
  logEmail(
    path.join(path.dirname(DATA_FILE), 'vapt_email_log.jsonl'),
    { to, from, certId: cert.id, recipientName: cert.recipientName, subject, verifyUrl },
    result
  );
  return result;
}

// ─── IMAGE SAVE HELPER ───────────────────────────────────────────────────────
const ALLOWED_IMG_EXTS = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
function saveCertImageFile(files, prefix, existingPath) {
  const f = files && files.certificateImage;
  if (!f || !f.data || !f.data.length) return null;
  if (existingPath) {
    const old = path.join(UPLOADS_DIR, path.basename(existingPath));
    if (fs.existsSync(old)) fs.unlinkSync(old);
  }
  const origExt = path.extname(f.filename || '').toLowerCase();
  const ext     = ALLOWED_IMG_EXTS.includes(origExt) ? origExt : '.jpg';
  const fname   = prefix + '_' + crypto.randomBytes(12).toString('hex') + ext;
  fs.writeFileSync(path.join(UPLOADS_DIR, fname), f.data);
  return '/uploads/' + fname;
}

// ─── PUBLIC FIELD PROJECTORS ─────────────────────────────────────────────────
function certPublicFields(cert) {
  const { id, recipientName, vesselName, vesselIMO, chiefEngineer,
    trainingTitle, organizer, complianceDate, complianceQuarter,
    trainingMode, validFor, validUntil, verifiedBy, status,
    issuedAt, certificateImage, notes, attachments } = cert;
  // Compute effectiveStatus: if status=VALID but past validUntil → EXPIRED
  const now = new Date();
  const isExpired = (status || 'VALID').toUpperCase() === 'VALID' && validUntil && new Date(validUntil) < now;
  const effectiveStatus = isExpired ? 'EXPIRED' : (status || 'VALID').toUpperCase();
  return {
    id, recipientName, vesselName, vesselIMO, chiefEngineer,
    trainingTitle, organizer, complianceDate, complianceQuarter,
    trainingMode, validFor, validUntil, verifiedBy, status,
    effectiveStatus,
    issuedAt, certificateImage, notes,
    attachments: Array.isArray(attachments) ? attachments : [],
  };
}

function vaptPublicFields(cert) {
  const { id, recipientName, vesselName, vesselIMO, certificateNumber, assessmentDate,
    validUntil, verifiedBy, verifierTitle, assessingOrg, frameworks,
    scopeItems, status, issuedAt, certificateImage, notes, attachments } = cert;
  // Compute effectiveStatus: if status=VALID but past validUntil → EXPIRED
  const now = new Date();
  const isExpired = (status || 'VALID').toUpperCase() === 'VALID' && validUntil && new Date(validUntil) < now;
  const effectiveStatus = isExpired ? 'EXPIRED' : (status || 'VALID').toUpperCase();
  return {
    id, recipientName, vesselName, vesselIMO, certificateNumber, assessmentDate,
    validUntil, verifiedBy, verifierTitle, assessingOrg, frameworks,
    scopeItems, status, effectiveStatus, issuedAt, certificateImage, notes,
    attachments: Array.isArray(attachments) ? attachments : [],
  };
}

// ─── ATTACHMENT HELPERS ──────────────────────────────────────────────────────
const ALLOWED_ATTACHMENT_EXTS = ['.pdf', '.jpg', '.jpeg', '.png', '.webp'];

function saveAttachmentFile(fileObj, prefix) {
  const origExt = path.extname(fileObj.filename).toLowerCase();
  const ext     = ALLOWED_ATTACHMENT_EXTS.includes(origExt) ? origExt : '.pdf';
  const fname   = prefix + '_' + crypto.randomBytes(12).toString('hex') + ext;
  fs.writeFileSync(path.join(UPLOADS_DIR, fname), fileObj.data);
  return { name: fileObj.filename || fname, url: '/uploads/' + fname };
}

function extractAttachments(fields, files, prefix, existingAttachments = []) {
  let result = existingAttachments.slice();
  if (fields.attachments) {
    try { result = JSON.parse(fields.attachments); } catch { /* ignore */ }
  }
  const fileKeys = Object.keys(files).filter(k => k.startsWith('attachment'));
  for (const key of fileKeys) {
    const f = files[key];
    if (f && f.data && f.data.length > 0) {
      result.push(saveAttachmentFile(f, prefix));
    }
  }
  return result;
}

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.pdf': 'application/pdf'
};

// ─── INPUT SANITISATION ───────────────────────────────────────────────────────
function sanitiseCertId(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const decoded = decodeURIComponent(raw).trim();
  if (!/^[A-Za-z0-9\-_]{1,64}$/.test(decoded)) return null;
  return decoded.toUpperCase();
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

function sendJSON(res, status, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...SECURITY_HEADERS,
    ...extraHeaders,
  });
  res.end(body);
}

function sendFile(res, filePath, req) {
  const ext  = path.extname(filePath).toLowerCase();
  const base = MIME[ext] || 'text/plain';
  const mime = (base.startsWith('text/') || base === 'application/javascript')
    ? base + '; charset=utf-8'
    : base;
  const isHtml = ext === '.html' || ext === '';
  const cacheControl = isHtml
    ? 'no-cache, no-store, must-revalidate'
    : (ext === '.js' || ext === '.css' || ext === '.woff2' || ext === '.woff')
      ? 'public, max-age=86400'
      : 'public, max-age=3600';
  fs.stat(filePath, (statErr, stat) => {
    if (statErr || !stat.isFile()) {
      res.writeHead(404, SECURITY_HEADERS);
      return res.end('Not found');
    }
    // ETag: mtime hex + file size (lightweight, no hashing)
    const etag = `"${stat.mtimeMs.toString(16)}-${stat.size.toString(16)}"`;
    const lastModified = stat.mtime.toUTCString();
    // Conditional GET support — skip body for unchanged static files
    if (!isHtml && req) {
      const ifNoneMatch  = req.headers['if-none-match'];
      const ifModSince   = req.headers['if-modified-since'];
      if ((ifNoneMatch && ifNoneMatch === etag) ||
          (!ifNoneMatch && ifModSince && new Date(ifModSince) >= stat.mtime)) {
        res.writeHead(304, { ETag: etag, 'Last-Modified': lastModified, 'Cache-Control': cacheControl, ...SECURITY_HEADERS });
        return res.end();
      }
    }
    res.writeHead(200, {
      'Content-Type':   mime,
      'Content-Length': stat.size,
      'Cache-Control':  cacheControl,
      'ETag':           etag,
      'Last-Modified':  lastModified,
      ...SECURITY_HEADERS,
    });
    const stream = fs.createReadStream(filePath);
    stream.on('error', () => { if (!res.headersSent) res.end(); else res.destroy(); });
    stream.pipe(res);
  });
}

function getBody(req, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => { req.destroy(); reject(new Error('Request took too long. Please try again.')); }, timeoutMs);
    req.on('data', c => {
      size += c.length;
      if (size > 10 * 1024 * 1024) { clearTimeout(timer); req.destroy(); reject(new Error('File is too large to upload.')); return; }
      chunks.push(c);
    });
    req.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString()); });
    req.on('error', err => { clearTimeout(timer); reject(err); });
  });
}

function authCheck(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return false;
  return verifyToken(auth.slice(7)) !== null;
}

// ─── CORS HELPER ─────────────────────────────────────────────────────────────
function getCorsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age':       '86400',
    'Vary':                         'Origin',
  };
}

// ─── QUARTER HELPER ──────────────────────────────────────────────────────────
const QUARTER_MAP = {
  Q1: { label: 'Q2 (APR–JUN)',  endMonth: 6,  endDay: 30 },
  Q2: { label: 'Q3 (JUL–SEP)',  endMonth: 9,  endDay: 30 },
  Q3: { label: 'Q4 (OCT–DEC)',  endMonth: 12, endDay: 31 },
  Q4: { label: 'Q1 (JAN–MAR)',  endMonth: 3,  endDay: 31, nextYear: true }
};

function deriveQuarterFields(cert) {
  const q    = (cert.complianceQuarter || '').toUpperCase();
  const info = QUARTER_MAP[q];
  if (!info) return;

  const baseYear = cert.complianceDate
    ? new Date(cert.complianceDate).getFullYear()
    : new Date().getFullYear();
  const year = info.nextYear ? baseYear + 1 : baseYear;

  // Set validFor / validUntil only when not already present
  // (callers delete these fields before calling when forcing recalculation)
  if (!cert.validFor)   cert.validFor   = info.label + '-' + year;
  if (!cert.validUntil) {
    const d = new Date(year, info.endMonth - 1, info.endDay);
    cert.validUntil = d.toISOString().slice(0, 10);
  }

  // Normalise recipientName → "<PREFIX> - <VESSEL>" when missing or bare
  if (cert.vesselName) {
    const current = (cert.recipientName || '').trim();
    const bare    = cert.vesselName.replace(/^(MV|MT)\s*[-\u2013]?\s*/i, '').trim();
    const hasPrefix = /^(MV|MT)\s*[-\u2013]\s*/i.test(current);
    if (!current || current === cert.vesselName.trim() || !hasPrefix) {
      const srcForPrefix = current || cert.vesselName;
      const m   = srcForPrefix.match(/^(MV|MT)\b/i);
      const pfx = m ? m[1].toUpperCase() : 'MV';
      cert.recipientName = pfx + ' - ' + bare;
    }
  }
}

// ─── MULTIPART PARSER ────────────────────────────────────────────────────────
function parseMultipart(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;
    req.on('data', c => {
      totalSize += c.length;
      if (totalSize > 10 * 1024 * 1024) { req.destroy(); return reject(new Error('File is too large to upload.')); }
      chunks.push(c);
    });
    req.on('end', () => {
      const body        = Buffer.concat(chunks);
      const rawBoundary = (req.headers['content-type'] || '').split('boundary=')[1] || '';
      const boundary    = rawBoundary.split(';')[0].trim();
      if (!boundary) return resolve({ fields: {}, files: {} });
      const boundaryBuf = Buffer.from('--' + boundary);
      const parts = [];
      let start = body.indexOf(boundaryBuf);
      while (start !== -1) {
        start += boundaryBuf.length + 2;
        const end = body.indexOf(boundaryBuf, start) - 2;
        if (end < start) break;
        parts.push(body.slice(start, end));
        start = body.indexOf(boundaryBuf, start);
      }
      const fields = {}, files = {};
      for (const part of parts) {
        const headerEnd = part.indexOf('\r\n\r\n');
        if (headerEnd === -1) continue;
        const headerStr     = part.slice(0, headerEnd).toString();
        const content       = part.slice(headerEnd + 4);
        const nameMatch     = headerStr.match(/name="([^"]+)"/);
        const filenameMatch = headerStr.match(/filename="([^"]+)"/);
        const ctMatch       = headerStr.match(/Content-Type: (.+)/i);
        if (!nameMatch) continue;
        const fieldName = nameMatch[1];
        if (filenameMatch) {
          files[fieldName] = {
            filename:    path.basename(filenameMatch[1]),
            contentType: ctMatch ? ctMatch[1].trim() : 'application/octet-stream',
            data:        content
          };
        } else {
          fields[fieldName] = content.toString().trim();
        }
      }
      resolve({ fields, files });
    });
    req.on('error', reject);
  });
}

// ─── SERVER STARTUP TIME (for /api/health) ───────────────────────────────────
const SERVER_START_TIME = Date.now();

// ─── API ROUTER ──────────────────────────────────────────────────────────────
async function handleAPI(req, res, parsed) {
  const method = req.method.toUpperCase();
  const route  = parsed.pathname.replace(/^\/api/, '');
  const ip     = getClientIp(req);
  const origin = req.headers.origin || '';
  const corsH  = getCorsHeaders(origin);

  if (method === 'OPTIONS') {
    res.writeHead(204, { ...corsH, ...SECURITY_HEADERS });
    return res.end();
  }

  // ── GET /api/health ── (public — liveness / monitoring probe)
  // Returns uptime, config version, SES status, cert counts, and maintenance state.
  // Intentionally does NOT expose sensitive details.
  if (route === '/health' && method === 'GET') {
    const cstCerts  = Object.values(loadData());
    const vaptCerts = Object.values(loadVaptData());
    const maintenance = CFG.maintenance || {};
    return sendJSON(res, 200, {
      ok:          true,
      status:      'operational',
      uptime:      Math.floor((Date.now() - SERVER_START_TIME) / 1000),
      timestamp:   new Date().toISOString(),
      version:     CFG.version || '1.0.0',
      ses:         SES_ENABLED,
      maintenance: maintenance.enabled || false,
      certs:       { cst: cstCerts.length, vapt: vaptCerts.length },
      compliance: {
        standards: (CFG.compliance && CFG.compliance.standards) || '',
        dataRetentionYears: (CFG.compliance && CFG.compliance.dataRetentionYears) || 5,
      },
    }, corsH);
  }

  // ── POST /api/auth/login ──────────────────────────────────────────────────
  if (route === '/auth/login' && method === 'POST') {
    if (!serverReady)
      return sendJSON(res, 503, { error: 'Server is starting up, please try again in a moment.' }, corsH);
    const rl = checkRateLimit(ip, 'login');
    if (!rl.ok)
      return sendJSON(res, 429, { error: 'Too many login attempts. Try again later.' },
        { 'Retry-After': String(rl.retryAfter), ...corsH });
    let body;
    try { body = JSON.parse(await getBody(req)); } catch {
      return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH);
    }
    const { username, password }  = body;
    const usernameMatch = typeof username === 'string' && username === ADMIN_USER;
    const passwordHash  = await hashPassword(password || '');
    const passwordMatch = crypto.timingSafeEqual(
      Buffer.from(passwordHash), Buffer.from(ADMIN_PASS_HASH)
    );
    if (!usernameMatch || !passwordMatch) {
      await new Promise(r => setTimeout(r, 200 + Math.random() * 200));
      return sendJSON(res, 401, { error: 'Invalid credentials' }, corsH);
    }
    return sendJSON(res, 200, { token: issueToken(username) }, corsH);
  }

  // ── GET /api/auth/verify ──────────────────────────────────────────────────
  if (route === '/auth/verify' && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    return sendJSON(res, 200, { ok: true }, corsH);
  }

  // ── GET /api/certs ── (admin — list all)
  if (route === '/certs' && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    return sendJSON(res, 200, Object.values(loadData()), corsH);
  }

  // ── GET /api/certs/:id ── (admin — single cert)
  // FIX: Use explicit segment count instead of fragile !includes('/verify') guard
  if (route.startsWith('/certs/') && method === 'GET') {
    const segments = route.split('/').filter(Boolean);   // ['certs', '<id>']
    if (segments.length === 2) {
      if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
      const certId = sanitiseCertId(segments[1]);
      if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
      const cert = loadData()[certId];
      if (!cert) return sendJSON(res, 404, { error: 'Not found' }, corsH);
      return sendJSON(res, 200, cert, corsH);
    }
  }

  // ── GET /api/verify-by-id/:certId ── (public — verify training cert by plain ID)
  if (route.startsWith('/verify-by-id/') && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(rl.retryAfter), ...corsH });
    const certId = sanitiseCertId(route.replace('/verify-by-id/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const cert = loadData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Certificate not found' }, corsH);
    // Track cert view
    recordEngagement(loadData(), certId, 'cert_viewed', { src: 'id_lookup' }, saveData);
    return sendJSON(res, 200, certPublicFields(cert), corsH);
  }

  // ── GET /api/track-open/:token ── (public — 1×1 pixel, fires on email open for CST)
  if (route.startsWith('/track-open/') && method === 'GET') {
    const raw     = route.replace('/track-open/', '');
    const dotIdx  = raw.lastIndexOf('.');
    if (dotIdx > 0) {
      const payload  = raw.slice(0, dotIdx);
      const sig      = raw.slice(dotIdx + 1);
      const expected = crypto.createHmac('sha256', KEYS.urlMacKey)
        .update('track:cst:' + payload).digest('base64url').slice(0, 16);
      const sigBuf = Buffer.from(sig.padEnd(expected.length, '=').slice(0, expected.length));
      const expBuf = Buffer.from(expected);
      const valid  = sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
      if (valid) {
        try {
          const certId = Buffer.from(payload, 'base64url').toString('utf8');
          const data   = loadData();
          if (data[certId]) recordEngagement(data, certId, 'email_opened', { ua: req.headers['user-agent'] || '' }, saveData);
        } catch { /* non-fatal */ }
      }
    }
    res.writeHead(200, {
      'Content-Type': 'image/gif',
      'Content-Length': TRACKING_PIXEL_GIF.length,
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache',
    });
    return res.end(TRACKING_PIXEL_GIF);
  }

  // ── GET /api/vapt/track-open/:token ── (public — 1×1 pixel for VAPT email open)
  if (route.startsWith('/vapt/track-open/') && method === 'GET') {
    const raw     = route.replace('/vapt/track-open/', '');
    const dotIdx  = raw.lastIndexOf('.');
    if (dotIdx > 0) {
      const payload  = raw.slice(0, dotIdx);
      const sig      = raw.slice(dotIdx + 1);
      const expected = crypto.createHmac('sha256', KEYS.urlMacKey)
        .update('track:vapt:' + payload).digest('base64url').slice(0, 16);
      const sigBuf = Buffer.from(sig.padEnd(expected.length, '=').slice(0, expected.length));
      const expBuf = Buffer.from(expected);
      const valid  = sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
      if (valid) {
        try {
          const certId = Buffer.from(payload, 'base64url').toString('utf8');
          const data   = loadVaptData();
          if (data[certId]) recordEngagement(data, certId, 'email_opened', { ua: req.headers['user-agent'] || '' }, saveVaptData);
        } catch { /* non-fatal */ }
      }
    }
    res.writeHead(200, {
      'Content-Type': 'image/gif',
      'Content-Length': TRACKING_PIXEL_GIF.length,
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache',
    });
    return res.end(TRACKING_PIXEL_GIF);
  }

  // ── POST /api/track-event ── (public — cert viewed / document downloaded from browser)
  if (route === '/track-event' && method === 'POST') {
    let body;
    try { body = JSON.parse(await getBody(req, 3000)); } catch { return sendJSON(res, 400, {}, corsH); }
    const { certId: rawId, event, file, kind } = body || {};
    const certId = sanitiseCertId(rawId);
    if (!certId || !['cert_viewed', 'document_downloaded'].includes(event)) {
      return sendJSON(res, 400, { error: 'Invalid event' }, corsH);
    }
    const isVapt = kind === 'vapt';
    const data   = isVapt ? loadVaptData() : loadData();
    if (data[certId]) {
      recordEngagement(data, certId, event, file ? { file } : { src: 'portal' }, isVapt ? saveVaptData : saveData);
    }
    return sendJSON(res, 200, { ok: true }, corsH);
  }

  // ── GET /api/certs/:id/engagement ── (admin — fetch engagement stats for one cert)
  if (route.match(/^\/certs\/[^/]+\/engagement$/) && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const certId = sanitiseCertId(route.replace('/certs/', '').replace('/engagement', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid ID' }, corsH);
    const cert = loadData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    return sendJSON(res, 200, { certId, engagement: cert.engagement || {} }, corsH);
  }

  // ── GET /api/vapt/certs/:id/engagement ── (admin — VAPT engagement stats)
  if (route.match(/^\/vapt\/certs\/[^/]+\/engagement$/) && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const certId = sanitiseCertId(route.replace('/vapt/certs/', '').replace('/engagement', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid ID' }, corsH);
    const cert = loadVaptData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    return sendJSON(res, 200, { certId, engagement: cert.engagement || {} }, corsH);
  }

  // ── GET /api/verify/:encToken ── (public — verify cert by encrypted token)
  if (route.startsWith('/verify/') && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok)
      return sendJSON(res, 429, { error: 'Too many requests. Try again later.' },
        { 'Retry-After': String(rl.retryAfter), ...corsH });
    const encToken = route.replace('/verify/', '');
    const sig      = parsed.searchParams.get('s');
    if (!verifyCertUrlSignature(encToken, sig))
      return sendJSON(res, 403, { error: 'Invalid or tampered verification link' }, corsH);
    const certId = decryptCertToken(encToken);
    if (!certId) return sendJSON(res, 400, { error: 'Invalid verification token' }, corsH);
    const cert = loadData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Certificate not found' }, corsH);
    recordEngagement(loadData(), certId, 'cert_viewed', { src: 'token_link' }, saveData);
    return sendJSON(res, 200, certPublicFields(cert), corsH);
  }

  // ── GET /api/public-cert-url/:id ── (public — shareable encrypted cert URL, rate limited)
  if (route.startsWith('/public-cert-url/') && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok)
      return sendJSON(res, 429, { error: 'Too many requests. Try again later.' },
        { 'Retry-After': String(rl.retryAfter), ...corsH });
    const certId = sanitiseCertId(route.replace('/public-cert-url/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const base = parsed.searchParams.get('base') || BASE_ORIGIN;
    return sendJSON(res, 200, { url: buildCertUrl(certId, base) }, corsH);
  }

  // ── GET /api/cert-url/:id ── (admin — generate public cert URL)
  if (route.startsWith('/cert-url/') && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const certId = sanitiseCertId(route.replace('/cert-url/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const base = parsed.searchParams.get('base') || BASE_ORIGIN;
    return sendJSON(res, 200, { url: buildCertUrl(certId, base) }, corsH);
  }

  // ── POST /api/certs ── (admin — create)
  if (route === '/certs' && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const ct = req.headers['content-type'] || '';
    let cert;
    try {
      if (ct.includes('multipart/form-data')) {
        const { fields, files } = await parseMultipart(req);
        cert = { ...fields };
        const imgPath = saveCertImageFile(files, 'cert');
        if (imgPath) cert.certificateImage = imgPath;
        cert.attachments = extractAttachments(fields, files, 'cst_attach');
      } else {
        cert = JSON.parse(await getBody(req));
        if (!Array.isArray(cert.attachments)) cert.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    const certId = sanitiseCertId(cert.id);
    if (!certId) return sendJSON(res, 400, { error: 'Invalid or missing certificate ID' }, corsH);
    cert.id = certId;
    deriveQuarterFields(cert);
    const data = loadData();
    if (data[cert.id]) return sendJSON(res, 409, { error: 'Certificate ID already exists' }, corsH);
    cert.emailStatus = cert.emailStatus || 'NOT_SENT';
    cert.emailSentAt = cert.emailSentAt || null;
    cert.createdAt   = new Date().toISOString();
    cert.updatedAt   = new Date().toISOString();
    // Auto-populate issuedAt from complianceDate if not explicitly supplied
    if (!cert.issuedAt && cert.complianceDate) cert.issuedAt = cert.complianceDate;
    // Normalise whitespace / casing on key fields
    ['recipientName','vesselName','vesselIMO','chiefEngineer','trainingMode','complianceQuarter'].forEach(k => {
      if (typeof cert[k] === 'string') cert[k] = cert[k].trim();
    });
    if (cert.vesselIMO)         cert.vesselIMO         = cert.vesselIMO.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (cert.complianceQuarter) cert.complianceQuarter = cert.complianceQuarter.toUpperCase();
    if (cert.trainingMode)      cert.trainingMode      = cert.trainingMode.toUpperCase();
    // Apply config defaults for empty mandatory text fields
    if (!cert.trainingTitle) cert.trainingTitle = CFG.cst.trainingTitle;
    if (!cert.organizer)     cert.organizer     = CFG.cst.organizer;
    if (!cert.verifiedBy)    cert.verifiedBy    = CFG.cst.verifiedBy;
    if (!cert.notes)         cert.notes         = CFG.cst.notes;
    if (!cert.issuerEmail)   cert.issuerEmail   = CFG.contact.cstEmail;
    // Auto-status: VALID only when all core fields AND recipient email AND image are present
    const _cstCore = !!(cert.vesselIMO && (cert.vesselName || cert.recipientName) && cert.chiefEngineer && cert.complianceDate && cert.complianceQuarter);
    const _cstFull = _cstCore && !!(cert.recipientEmail && cert.certificateImage);
    if (!_cstCore)                                               cert.status = 'PENDING';
    else if (_cstFull && (!cert.status || cert.status === 'PENDING')) cert.status = 'VALID';
    else if (!cert.status)                                       cert.status = 'PENDING';
    data[cert.id]    = cert;
    saveData(data);
    return sendJSON(res, 201, cert, corsH);
  }

  // ── PUT /api/certs/:id ── (admin — update)
  if (route.startsWith('/certs/') && method === 'PUT') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const certId = sanitiseCertId(route.replace('/certs/', '').replace('/send-email', '').split('/')[0]);
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    // Guard: don't match send-email sub-route
    if (route.includes('/send-email')) return sendJSON(res, 404, { error: 'Not found.' }, corsH);
    const data = loadData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const ct = req.headers['content-type'] || '';
    let updates;
    try {
      if (ct.includes('multipart/form-data')) {
        const { fields, files } = await parseMultipart(req);
        updates = { ...fields };
        const imgPath = saveCertImageFile(files, 'cert', data[certId].certificateImage);
        if (imgPath) updates.certificateImage = imgPath;
        updates.attachments = extractAttachments(fields, files, 'cst_attach',
          Array.isArray(data[certId].attachments) ? data[certId].attachments : []);
      } else {
        updates = JSON.parse(await getBody(req));
        if (updates.attachments !== undefined && !Array.isArray(updates.attachments)) updates.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    const updated = { ...data[certId], ...updates, updatedAt: new Date().toISOString() };
    // Enforce: EXPIRED or REVOKED → validUntil must be today (so radar & filters are always accurate)
    if (updated.status === 'EXPIRED' || updated.status === 'REVOKED') {
      updated.validUntil = new Date().toISOString().slice(0, 10);
    }
    // FIX: re-derive quarter fields on update when compliance fields change.
    // Reset derived fields so deriveQuarterFields can recalculate them.
    if (updates.complianceQuarter || updates.complianceDate) {
      if (updates.complianceQuarter) delete updated.validFor;
      if (updates.complianceDate || updates.complianceQuarter) delete updated.validUntil;
      deriveQuarterFields(updated);
    }
    if (updates.id) {
      const newId = sanitiseCertId(updates.id);
      if (!newId) return sendJSON(res, 400, { error: 'Invalid new certificate ID' }, corsH);
      updated.id = newId;
      if (newId !== certId) {
        data[newId] = updated;
        delete data[certId];
      } else {
        data[certId] = updated;
      }
    } else {
      data[certId] = updated;
    }
    saveData(data);
    return sendJSON(res, 200, updated, corsH);
  }

  // ── POST /api/certs/:id/send-email ── (admin — dispatch credential email)
  if (route.match(/^\/certs\/[^/]+\/send-email$/) && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const certId = sanitiseCertId(
      decodeURIComponent(route.replace('/certs/', '').replace('/send-email', ''))
    );
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadData();
    const cert = data[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Certificate not found' }, corsH);

    let body;
    try { body = JSON.parse(await getBody(req)); } catch { body = {}; }

    // Allow the dashboard to supply an updated recipientEmail in the request body
    const overrideEmail = (body && typeof body.recipientEmail === 'string' && body.recipientEmail.trim())
      ? body.recipientEmail.trim().toLowerCase()
      : null;
    if (overrideEmail) {
      cert.recipientEmail = overrideEmail;
      data[certId] = cert;
      // Persist the email update immediately so it survives even if send fails
      saveData(data);
    }

    if (!cert.recipientEmail)
      return sendJSON(res, 400, { error: 'No recipient email on this certificate. Add an email address first.' }, corsH);
    if ((cert.issuerEmail || '').trim().toLowerCase() === (cert.recipientEmail || '').trim().toLowerCase())
      return sendJSON(res, 400, { error: 'Issuer and recipient email cannot be the same' }, corsH);

    // Always use BASE_ORIGIN for the verify URL embedded in the email.
    const verifyUrl = buildCertUrl(cert.id, BASE_ORIGIN);
    const fromAddr  = SES_FROM_CST || cert.issuerEmail || CFG.contact.cstEmail;

    if (!SES_ENABLED) {
      return sendJSON(res, 503, {
        error: 'Email dispatch is not configured on this server. Set SES_ACCESS_KEY, SES_SECRET_KEY and SES_REGION in your .env file.',
        sesEnabled: false,
      }, corsH);
    }

    const result = await sendCstEmail({
      to: cert.recipientEmail, from: fromAddr, cert, verifyUrl, baseUrl: BASE_ORIGIN
    });

    if (result.success) {
      cert.emailStatus = 'SENT';
      cert.emailSentAt = new Date().toISOString();
      if (result.messageId) cert.sesMessageId = result.messageId;
      data[certId] = cert;
      saveData(data);
      return sendJSON(res, 200, {
        success: true, emailStatus: 'SENT',
        emailSentAt: cert.emailSentAt,
        verifyUrl, messageId: result.messageId || null, sesEnabled: true,
        to: cert.recipientEmail,
      }, corsH);
    }

    return sendJSON(res, 500, {
      error: result.error || 'Email could not be delivered. Please verify the recipient address and try again.',
      sesEnabled: true,
    }, corsH);
  }

  // ── POST /api/import-csv ── (admin — bulk import CST certs)
  if (route === '/import-csv' && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const records = Array.isArray(body) ? body : [];
    if (records.length === 0) return sendJSON(res, 400, { error: 'No records provided' }, corsH);
    if (records.length > 500) return sendJSON(res, 400, { error: 'Batch too large (max 500 per import)' }, corsH);
    const data = loadData();
    let added = 0, skipped = 0, failed = 0;
    const results = [];
    const now = new Date().toISOString();
    for (const cert of records) {
      const certId = sanitiseCertId(cert.id);
      if (!certId) {
        results.push({ id: cert.id || '(blank)', status: 'failed', reason: 'Invalid or missing certificate ID' });
        failed++; continue;
      }
      if (data[certId]) {
        results.push({ id: certId, status: 'skipped', reason: 'Already exists' });
        skipped++; continue;
      }
      // Require at minimum a vessel identifier
      if (!cert.vesselIMO && !cert.vesselName && !cert.recipientName) {
        results.push({ id: certId, status: 'failed', reason: 'Missing vesselIMO / vesselName' });
        failed++; continue;
      }
      // Normalise
      cert.id = certId;
      ['recipientName','vesselName','vesselIMO','chiefEngineer','trainingMode','complianceQuarter'].forEach(k => {
        if (typeof cert[k] === 'string') cert[k] = cert[k].trim();
      });
      if (cert.vesselIMO)         cert.vesselIMO         = cert.vesselIMO.toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (cert.complianceQuarter) cert.complianceQuarter = cert.complianceQuarter.toUpperCase();
      if (cert.trainingMode)      cert.trainingMode      = cert.trainingMode.toUpperCase();
      // Apply config defaults
      if (!cert.trainingTitle) cert.trainingTitle = CFG.cst.trainingTitle;
      if (!cert.organizer)     cert.organizer     = CFG.cst.organizer;
      if (!cert.verifiedBy)    cert.verifiedBy    = CFG.cst.verifiedBy;
      if (!cert.notes)         cert.notes         = CFG.cst.notes;
      if (!cert.issuerEmail)   cert.issuerEmail   = CFG.contact.cstEmail;
      // Derive validFor / validUntil from quarter
      deriveQuarterFields(cert);
      // Imported records always start PENDING (no image yet)
      cert.status      = 'PENDING';
      cert.emailStatus = 'NOT_SENT';
      cert.emailSentAt = null;
      cert.attachments = [];
      cert.createdAt   = now;
      cert.updatedAt   = now;
      data[certId] = cert;
      results.push({ id: certId, status: 'created', vessel: cert.vesselName || cert.recipientName || '' });
      added++;
    }
    saveData(data);
    return sendJSON(res, 200, { added, skipped, failed, total: records.length, results }, corsH);
  }

  // ── DELETE /api/certs/:id ── (admin)
  if (route.startsWith('/certs/') && method === 'DELETE') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const certId = sanitiseCertId(route.replace('/certs/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    // Clean up certificate image from disk
    if (data[certId].certificateImage) {
      const imgPath = path.join(UPLOADS_DIR, path.basename(data[certId].certificateImage));
      if (fs.existsSync(imgPath)) { try { fs.unlinkSync(imgPath); } catch { /* non-fatal */ } }
    }
    // Clean up all attachments from disk
    if (Array.isArray(data[certId].attachments)) {
      for (const att of data[certId].attachments) {
        if (att && att.url) {
          const fp = path.join(UPLOADS_DIR, path.basename(att.url));
          if (fs.existsSync(fp)) { try { fs.unlinkSync(fp); } catch { /* non-fatal */ } }
        }
      }
    }
    delete data[certId];
    saveData(data);
    return sendJSON(res, 200, { success: true }, corsH);
  }

  // ── GET /api/stats ── (public — aggregate cert stats for index page)
  if (route === '/stats' && method === 'GET') {
    const data  = loadData();
    const certs = Object.values(data);
    const now   = new Date();
    const total   = certs.length;
    const revoked = certs.filter(c => (c.status || '').toUpperCase() === 'REVOKED').length;
    const pending = certs.filter(c => (c.status || '').toUpperCase() === 'PENDING').length;
    const expired = certs.filter(c => {
      const st = (c.status || 'VALID').toUpperCase();
      return st === 'EXPIRED' || (st === 'VALID' && c.validUntil && new Date(c.validUntil) < now);
    }).length;
    const valid = certs.filter(c => {
      const st = (c.status || 'VALID').toUpperCase();
      return st === 'VALID' && (!c.validUntil || new Date(c.validUntil) >= now);
    }).length;
    const lastIssuedDate = certs.reduce((best, c) => {
      const d = c.createdAt || c.issuedAt || c.complianceDate || '';
      return d > best ? d : best;
    }, '');
    return sendJSON(res, 200, {
      total, valid, expired, pending, revoked,
      lastIssued: lastIssuedDate ? lastIssuedDate.slice(0, 10) : null,
    }, corsH);
  }

  // ── GET /api/ses-status ── (admin — email service status)
  if (route === '/ses-status' && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    return sendJSON(res, 200, {
      enabled:  SES_ENABLED,
      region:   SES_REGION   || null,
      fromCST:  SES_FROM_CST || null,
      fromVAPT: SES_FROM_VAPT || null,
      missing: [
        !SES_REGION     && 'region',
        !SES_ACCESS_KEY && 'access key',
        !SES_SECRET_KEY && 'secret key',
      ].filter(Boolean),
    }, corsH);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // VAPT CERTIFICATE API ROUTES  (/api/vapt/*)
  // ══════════════════════════════════════════════════════════════════════════

  // ── GET /api/vapt/stats ── (public — aggregate VAPT cert stats)
  if (route === '/vapt/stats' && method === 'GET') {
    const data  = loadVaptData();
    const certs = Object.values(data);
    const now   = new Date();
    const total   = certs.length;
    const revoked = certs.filter(c => (c.status || '').toUpperCase() === 'REVOKED').length;
    const pending = certs.filter(c => (c.status || '').toUpperCase() === 'PENDING').length;
    const expired = certs.filter(c => {
      const st = (c.status || 'VALID').toUpperCase();
      return st === 'EXPIRED' || (st === 'VALID' && c.validUntil && new Date(c.validUntil) < now);
    }).length;
    const valid = certs.filter(c => {
      const st = (c.status || 'VALID').toUpperCase();
      return st === 'VALID' && (!c.validUntil || new Date(c.validUntil) >= now);
    }).length;
    const lastIssuedDate = certs.reduce((best, c) => {
      const d = c.createdAt || c.issuedAt || c.assessmentDate || '';
      return d > best ? d : best;
    }, '');
    return sendJSON(res, 200, {
      total, valid, expired, pending, revoked,
      lastIssued: lastIssuedDate ? lastIssuedDate.slice(0, 10) : null,
    }, corsH);
  }

  // ── POST /api/verify-email/:certId ── (public — gate check for CST PDF access)
  // Accepts { email } in JSON body. Returns { ok: true } only when email matches
  // the stored recipientEmail (case-insensitive, timing-safe). Never reveals the email.
  if (route.match(/^\/verify-email\/[^/]+$/) && method === 'POST') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(rl.retryAfter), ...corsH });
    const certId = sanitiseCertId(route.replace('/verify-email/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const entered  = (typeof body.email === 'string' ? body.email : '').trim().toLowerCase();
    if (!entered)  return sendJSON(res, 400, { error: 'Email is required' }, corsH);
    const cert = loadData()[certId];
    if (!cert)     return sendJSON(res, 404, { error: 'Certificate not found' }, corsH);
    const stored   = (cert.recipientEmail || '').trim().toLowerCase();
    // If no email is configured for this cert, deny access (prevents gate bypass on unconfigured certs)
    if (!stored)   return sendJSON(res, 403, { error: 'No registered email for this certificate' }, corsH);
    // Timing-safe compare using fixed-length HMAC to prevent timing attacks
    const hmacEntered = crypto.createHmac('sha256', KEYS.urlMacKey).update(entered).digest('hex');
    const hmacStored  = crypto.createHmac('sha256', KEYS.urlMacKey).update(stored).digest('hex');
    const bufA = Buffer.from(hmacEntered, 'hex');
    const bufB = Buffer.from(hmacStored,  'hex');
    if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
      await new Promise(r => setTimeout(r, 150 + Math.random() * 100)); // delay brute-force
      return sendJSON(res, 403, { error: 'Email does not match' }, corsH);
    }
    return sendJSON(res, 200, { ok: true }, corsH);
  }

  // ── POST /api/vapt/verify-email/:certId ── (public — gate check for VAPT PDF access)
  if (route.match(/^\/vapt\/verify-email\/[^/]+$/) && method === 'POST') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(rl.retryAfter), ...corsH });
    const certId = sanitiseCertId(route.replace('/vapt/verify-email/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const entered  = (typeof body.email === 'string' ? body.email : '').trim().toLowerCase();
    if (!entered)  return sendJSON(res, 400, { error: 'Email is required' }, corsH);
    const cert = loadVaptData()[certId];
    if (!cert)     return sendJSON(res, 404, { error: 'Certificate not found' }, corsH);
    const stored   = (cert.recipientEmail || '').trim().toLowerCase();
    if (!stored)   return sendJSON(res, 403, { error: 'No registered email for this certificate' }, corsH);
    const hmacEntered = crypto.createHmac('sha256', KEYS.urlMacKey).update(entered).digest('hex');
    const hmacStored  = crypto.createHmac('sha256', KEYS.urlMacKey).update(stored).digest('hex');
    const bufA = Buffer.from(hmacEntered, 'hex');
    const bufB = Buffer.from(hmacStored,  'hex');
    if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
      await new Promise(r => setTimeout(r, 150 + Math.random() * 100));
      return sendJSON(res, 403, { error: 'Email does not match' }, corsH);
    }
    return sendJSON(res, 200, { ok: true }, corsH);
  }

  // ── GET /api/vapt/verify-by-id/:certId ── (public)
  if (route.startsWith('/vapt/verify-by-id/') && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(rl.retryAfter), ...corsH });
    const certId = sanitiseCertId(route.replace('/vapt/verify-by-id/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const cert = loadVaptData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'VAPT Certificate not found' }, corsH);
    recordEngagement(loadVaptData(), certId, 'cert_viewed', { src: 'id_lookup' }, saveVaptData);
    return sendJSON(res, 200, vaptPublicFields(cert), corsH);
  }

  // ── GET /api/vapt/certs ── (admin — list all VAPT certs)
  if (route === '/vapt/certs' && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    return sendJSON(res, 200, Object.values(loadVaptData()), corsH);
  }

  // ── GET /api/vapt/certs/:id ── (admin — single VAPT cert)
  if (route.startsWith('/vapt/certs/') && method === 'GET') {
    const segments = route.split('/').filter(Boolean);   // ['vapt', 'certs', '<id>']
    if (segments.length === 3) {
      if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
      const certId = sanitiseCertId(segments[2]);
      if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
      const cert = loadVaptData()[certId];
      if (!cert) return sendJSON(res, 404, { error: 'Not found' }, corsH);
      return sendJSON(res, 200, cert, corsH);
    }
  }

  // ── GET /api/vapt/verify/:encToken ── (public — verify VAPT cert)
  if (route.startsWith('/vapt/verify/') && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(rl.retryAfter), ...corsH });
    const encToken = route.replace('/vapt/verify/', '');
    const sig = parsed.searchParams.get('s');
    if (!verifyCertUrlSignature(encToken, sig))
      return sendJSON(res, 403, { error: 'Invalid or tampered verification link' }, corsH);
    const certId = decryptCertToken(encToken);
    if (!certId) return sendJSON(res, 400, { error: 'Invalid verification token' }, corsH);
    const cert = loadVaptData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'VAPT Certificate not found' }, corsH);
    recordEngagement(loadVaptData(), certId, 'cert_viewed', { src: 'token_link' }, saveVaptData);
    return sendJSON(res, 200, vaptPublicFields(cert), corsH);
  }

  // ── GET /api/vapt/public-cert-url/:id ── (public — shareable encrypted VAPT URL)
  if (route.startsWith('/vapt/public-cert-url/') && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok)
      return sendJSON(res, 429, { error: 'Too many requests. Try again later.' },
        { 'Retry-After': String(rl.retryAfter), ...corsH });
    const certId = sanitiseCertId(route.replace('/vapt/public-cert-url/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadVaptData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const base = parsed.searchParams.get('base') || BASE_ORIGIN;
    return sendJSON(res, 200, { url: buildVaptCertUrl(certId, base) }, corsH);
  }

  // ── GET /api/vapt/cert-url/:id ── (admin — generate public VAPT cert URL)
  if (route.startsWith('/vapt/cert-url/') && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const certId = sanitiseCertId(route.replace('/vapt/cert-url/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadVaptData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const base = parsed.searchParams.get('base') || BASE_ORIGIN;
    return sendJSON(res, 200, { url: buildVaptCertUrl(certId, base) }, corsH);
  }

  // ── POST /api/vapt/certs ── (admin — create VAPT cert)
  if (route === '/vapt/certs' && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const ct = req.headers['content-type'] || '';
    let cert;
    try {
      if (ct.includes('multipart/form-data')) {
        const { fields, files } = await parseMultipart(req);
        cert = { ...fields };
        const imgPath = saveCertImageFile(files, 'vapt');
        if (imgPath) cert.certificateImage = imgPath;
        cert.attachments = extractAttachments(fields, files, 'vpt_attach');
      } else {
        cert = JSON.parse(await getBody(req));
        if (!Array.isArray(cert.attachments)) cert.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    const certId = sanitiseCertId(cert.id);
    if (!certId) return sendJSON(res, 400, { error: 'Invalid or missing certificate ID' }, corsH);
    cert.id = certId;
    const data = loadVaptData();
    if (data[cert.id]) return sendJSON(res, 409, { error: 'Certificate ID already exists' }, corsH);
    cert.emailStatus   = cert.emailStatus   || 'NOT_SENT';
    cert.emailSentAt   = cert.emailSentAt   || null;
    cert.createdAt     = new Date().toISOString();
    cert.updatedAt     = new Date().toISOString();
    // Normalise whitespace / casing
    ['vesselName','recipientName','vesselIMO'].forEach(k => {
      if (typeof cert[k] === 'string') cert[k] = cert[k].trim();
    });
    if (cert.vesselIMO) cert.vesselIMO = cert.vesselIMO.toUpperCase().replace(/[^A-Z0-9]/g, '');
    // Mirror vesselName → recipientName if absent
    if (!cert.recipientName && cert.vesselName) cert.recipientName = cert.vesselName;
    // Apply config defaults
    if (!cert.verifiedBy)    cert.verifiedBy    = CFG.vapt.verifiedBy;
    if (!cert.verifierTitle) cert.verifierTitle = CFG.vapt.verifierTitle;
    if (!cert.assessingOrg)  cert.assessingOrg  = CFG.vapt.assessingOrg;
    if (!cert.frameworks)    cert.frameworks    = CFG.vapt.frameworks;
    if (!cert.scopeItems)    cert.scopeItems    = CFG.vapt.scopeItems;
    if (!cert.issuerEmail)   cert.issuerEmail   = CFG.contact.vaptEmail;
    // Derive validUntil (+1 year) if not supplied
    if (!cert.validUntil && cert.assessmentDate) {
      const d = new Date(cert.assessmentDate);
      if (!isNaN(d)) { d.setFullYear(d.getFullYear() + 1); cert.validUntil = d.toISOString().slice(0, 10); }
    }
    // Auto-status: VALID only when core fields + email + image are all present
    const _vaptCore = !!(cert.vesselIMO && (cert.vesselName || cert.recipientName) && cert.assessmentDate && cert.validUntil);
    const _vaptFull = _vaptCore && !!(cert.recipientEmail && cert.certificateImage);
    if (!_vaptCore)                                               cert.status = 'PENDING';
    else if (_vaptFull && (!cert.status || cert.status === 'PENDING')) cert.status = 'VALID';
    else if (!cert.status)                                       cert.status = 'PENDING';
    data[cert.id] = cert;
    saveVaptData(data);
    return sendJSON(res, 201, cert, corsH);
  }

  // ── POST /api/vapt/import-csv ── (admin — bulk import VAPT certs)
  if (route === '/vapt/import-csv' && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const records = Array.isArray(body) ? body : [];
    if (records.length === 0) return sendJSON(res, 400, { error: 'No records provided' }, corsH);
    if (records.length > 500) return sendJSON(res, 400, { error: 'Batch too large (max 500 per import)' }, corsH);
    const data = loadVaptData();
    let added = 0, skipped = 0, failed = 0;
    const results = [];
    const now = new Date().toISOString();
    for (const cert of records) {
      const certId = sanitiseCertId(cert.id);
      if (!certId) {
        results.push({ id: cert.id || '(blank)', status: 'failed', reason: 'Invalid or missing certificate ID' });
        failed++; continue;
      }
      if (data[certId]) {
        results.push({ id: certId, status: 'skipped', reason: 'Already exists' });
        skipped++; continue;
      }
      // Require at minimum a vessel identifier
      if (!cert.vesselIMO && !cert.vesselName && !cert.recipientName) {
        results.push({ id: certId, status: 'failed', reason: 'Missing vesselIMO / vesselName' });
        failed++; continue;
      }
      // Normalise
      cert.id = certId;
      ['vesselName','recipientName','vesselIMO'].forEach(k => {
        if (typeof cert[k] === 'string') cert[k] = cert[k].trim();
      });
      if (cert.vesselIMO) cert.vesselIMO = cert.vesselIMO.toUpperCase().replace(/[^A-Z0-9]/g, '');
      // Mirror vesselName → recipientName
      if (!cert.recipientName && cert.vesselName) cert.recipientName = cert.vesselName;
      // Apply config defaults
      if (!cert.verifiedBy)    cert.verifiedBy    = CFG.vapt.verifiedBy;
      if (!cert.verifierTitle) cert.verifierTitle = CFG.vapt.verifierTitle;
      if (!cert.assessingOrg)  cert.assessingOrg  = CFG.vapt.assessingOrg;
      if (!cert.frameworks)    cert.frameworks    = CFG.vapt.frameworks;
      if (!cert.scopeItems)    cert.scopeItems    = CFG.vapt.scopeItems;
      if (!cert.issuerEmail)   cert.issuerEmail   = CFG.contact.vaptEmail;
      // Derive validUntil (+1 year from assessmentDate) if absent
      if (!cert.validUntil && cert.assessmentDate) {
        const d = new Date(cert.assessmentDate);
        if (!isNaN(d)) { d.setFullYear(d.getFullYear() + 1); cert.validUntil = d.toISOString().slice(0, 10); }
      }
      // Imported certs always start PENDING (image uploaded separately)
      cert.status      = 'PENDING';
      cert.emailStatus = 'NOT_SENT';
      cert.emailSentAt = null;
      cert.attachments = [];
      cert.createdAt   = now;
      cert.updatedAt   = now;
      data[certId] = cert;
      results.push({ id: certId, status: 'created', vessel: cert.vesselName || cert.recipientName || '' });
      added++;
    }
    saveVaptData(data);
    return sendJSON(res, 200, { added, skipped, failed, total: records.length, results }, corsH);
  }

  // ── PUT /api/vapt/certs/:id ── (admin — update VAPT cert)
  if (route.startsWith('/vapt/certs/') && method === 'PUT') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    if (route.includes('/send-email')) return sendJSON(res, 404, { error: 'Not found.' }, corsH);
    const certId = sanitiseCertId(route.replace('/vapt/certs/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadVaptData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const ct = req.headers['content-type'] || '';
    let updates;
    try {
      if (ct.includes('multipart/form-data')) {
        const { fields, files } = await parseMultipart(req);
        updates = { ...fields };
        const imgPath = saveCertImageFile(files, 'vapt', data[certId].certificateImage);
        if (imgPath) updates.certificateImage = imgPath;
        updates.attachments = extractAttachments(fields, files, 'vpt_attach',
          Array.isArray(data[certId].attachments) ? data[certId].attachments : []);
      } else {
        updates = JSON.parse(await getBody(req));
        if (updates.attachments !== undefined && !Array.isArray(updates.attachments)) updates.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    const updated = { ...data[certId], ...updates, updatedAt: new Date().toISOString() };
    // Enforce: EXPIRED or REVOKED → validUntil must be today (so radar & filters are always accurate)
    if (updated.status === 'EXPIRED' || updated.status === 'REVOKED') {
      updated.validUntil = new Date().toISOString().slice(0, 10);
    }
    // FIX: consistent ID-rename logic (same as CST PUT)
    if (updates.id) {
      const newId = sanitiseCertId(updates.id);
      if (!newId) return sendJSON(res, 400, { error: 'Invalid new certificate ID' }, corsH);
      updated.id = newId;
      if (newId !== certId) {
        data[newId] = updated;
        delete data[certId];
      } else {
        data[certId] = updated;
      }
    } else {
      data[certId] = updated;
    }
    saveVaptData(data);
    return sendJSON(res, 200, updated, corsH);
  }

  // ── POST /api/vapt/certs/:id/send-email ── (admin — dispatch VAPT credential email)
  if (route.match(/^\/vapt\/certs\/[^/]+\/send-email$/) && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const certId = sanitiseCertId(decodeURIComponent(route.replace('/vapt/certs/', '').replace('/send-email', '')));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadVaptData();
    const cert = data[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Certificate not found' }, corsH);

    let body;
    try { body = JSON.parse(await getBody(req)); } catch { body = {}; }

    // Allow the dashboard to supply an updated recipientEmail in the request body
    const overrideEmail = (body && typeof body.recipientEmail === 'string' && body.recipientEmail.trim())
      ? body.recipientEmail.trim().toLowerCase()
      : null;
    if (overrideEmail) {
      cert.recipientEmail = overrideEmail;
      data[certId] = cert;
      saveVaptData(data);
    }

    if (!cert.recipientEmail) return sendJSON(res, 400, { error: 'No recipient email on this certificate. Add an email address first.' }, corsH);
    if ((cert.issuerEmail || '').trim().toLowerCase() === (cert.recipientEmail || '').trim().toLowerCase())
      return sendJSON(res, 400, { error: 'Issuer and recipient email cannot be the same' }, corsH);

    // Always use BASE_ORIGIN for the verify URL embedded in the email.
    const verifyUrl = buildVaptCertUrl(cert.id, BASE_ORIGIN);
    const fromAddr  = SES_FROM_VAPT || cert.issuerEmail || CFG.contact.vaptEmail;

    if (!SES_ENABLED) {
      return sendJSON(res, 503, {
        error: 'Email dispatch is not configured on this server. Set SES_ACCESS_KEY, SES_SECRET_KEY and SES_REGION in your .env file.',
        sesEnabled: false,
      }, corsH);
    }

    const result = await sendVaptEmail({
      to: cert.recipientEmail, from: fromAddr, cert, verifyUrl, baseUrl: BASE_ORIGIN
    });

    if (result.success) {
      cert.emailStatus = 'SENT';
      cert.emailSentAt = new Date().toISOString();
      if (result.messageId) cert.sesMessageId = result.messageId;
      data[certId] = cert;
      saveVaptData(data);
      return sendJSON(res, 200, {
        success: true, emailStatus: 'SENT',
        emailSentAt: cert.emailSentAt,
        verifyUrl, messageId: result.messageId || null, sesEnabled: true,
        to: cert.recipientEmail,
      }, corsH);
    }

    return sendJSON(res, 500, {
      error: result.error || 'Email could not be delivered. Please verify the recipient address and try again.',
      sesEnabled: true,
    }, corsH);
  }

  // ── DELETE /api/vapt/certs/:id ── (admin)
  if (route.startsWith('/vapt/certs/') && method === 'DELETE') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const certId = sanitiseCertId(route.replace('/vapt/certs/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadVaptData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    // Clean up certificate image from disk
    if (data[certId].certificateImage) {
      const imgPath = path.join(UPLOADS_DIR, path.basename(data[certId].certificateImage));
      if (fs.existsSync(imgPath)) { try { fs.unlinkSync(imgPath); } catch { /* non-fatal */ } }
    }
    // Clean up all attachments from disk
    if (Array.isArray(data[certId].attachments)) {
      for (const att of data[certId].attachments) {
        if (att && att.url) {
          const fp = path.join(UPLOADS_DIR, path.basename(att.url));
          if (fs.existsSync(fp)) { try { fs.unlinkSync(fp); } catch { /* non-fatal */ } }
        }
      }
    }
    delete data[certId];
    saveVaptData(data);
    return sendJSON(res, 200, { success: true }, corsH);
  }

  // ── DELETE /api/certs/:id/attachments/:idx ── (admin — remove one attachment)
  if (route.match(/^\/certs\/[^/]+\/attachments\/\d+$/) && method === 'DELETE') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const parts  = route.split('/');
    const certId = sanitiseCertId(parts[2]);
    const idx    = parseInt(parts[4], 10);
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const atts = Array.isArray(data[certId].attachments) ? data[certId].attachments : [];
    if (isNaN(idx) || idx < 0 || idx >= atts.length) return sendJSON(res, 400, { error: 'Invalid attachment index' }, corsH);
    const removed = atts.splice(idx, 1)[0];
    if (removed && removed.url) {
      const fp = path.join(UPLOADS_DIR, path.basename(removed.url));
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    data[certId].attachments = atts;
    data[certId].updatedAt   = new Date().toISOString();
    saveData(data);
    return sendJSON(res, 200, { success: true, attachments: atts }, corsH);
  }

  // ── DELETE /api/vapt/certs/:id/attachments/:idx ── (admin — remove one VAPT attachment)
  if (route.match(/^\/vapt\/certs\/[^/]+\/attachments\/\d+$/) && method === 'DELETE') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const parts  = route.split('/');
    const certId = sanitiseCertId(parts[3]);
    const idx    = parseInt(parts[5], 10);
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadVaptData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const atts = Array.isArray(data[certId].attachments) ? data[certId].attachments : [];
    if (isNaN(idx) || idx < 0 || idx >= atts.length) return sendJSON(res, 400, { error: 'Invalid attachment index' }, corsH);
    const removed = atts.splice(idx, 1)[0];
    if (removed && removed.url) {
      const fp = path.join(UPLOADS_DIR, path.basename(removed.url));
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    data[certId].attachments = atts;
    data[certId].updatedAt   = new Date().toISOString();
    saveVaptData(data);
    return sendJSON(res, 200, { success: true, attachments: atts }, corsH);
  }

  sendJSON(res, 404, { error: 'Not found.' }, corsH);
}

// ─── SINGLE UNIFIED SERVER ────────────────────────────────────────────────────
async function handleRequest(req, res) {
  if (isShuttingDown) {
    const origin = req.headers.origin || '';
    const corsH = getCorsHeaders(origin);
    return sendJSON(
      res,
      503,
      { error: 'Server is shutting down, please retry shortly.' },
      { ...corsH, 'Retry-After': '5' }
    );
  }

  const parsed = new URL(req.url, 'http://localhost');
  const p      = parsed.pathname;

  // ── Uploads (shared) ─────────────────────────────────────────────────────
  if (p.startsWith('/uploads/')) {
    const fname = path.basename(p);
    const fpath = path.resolve(UPLOADS_DIR, fname);

    if (!fpath.startsWith(UPLOADS_DIR + path.sep) && fpath !== UPLOADS_DIR) {
      res.writeHead(403, SECURITY_HEADERS);
      return res.end('Forbidden');
    }

    const ext   = path.extname(fpath).toLowerCase();
    const mime  = MIME[ext] || 'application/octet-stream';
    const isPdf = ext === '.pdf';

    // ── Track document download: only real downloads, not image thumbnail loads ──
    // Rules:
    //  1. Skip image files (jpg/png/webp/gif) — these are cert thumbnails rendered by
    //     the admin dashboard on every page load, NOT recipient downloads. Counting them
    //     would inflate the download counter with admin activity.
    //  2. Skip requests whose Referer header originates from the admin panel — same reason.
    //  3. For PDFs and other attachments, record the engagement against the owning cert.
    const isImageExt = ['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext);
    const referer    = (req.headers['referer'] || req.headers['referrer'] || '').toLowerCase();
    const isAdminReferer = referer.includes('/misecure') || referer.includes('admin');
    if (!isImageExt && !isAdminReferer) {
      try {
        const fileUrl = '/uploads/' + fname;
        // Check CST certs first
        const cstData = loadData();
        for (const [certId, cert] of Object.entries(cstData)) {
          const owns = cert.certificateImage === fileUrl ||
            (Array.isArray(cert.attachments) && cert.attachments.some(a => a.url === fileUrl));
          if (owns) {
            recordEngagement(cstData, certId, 'document_downloaded', { file: fname }, saveData);
            break;
          }
        }
        // Check VAPT certs
        const vaptData = loadVaptData();
        for (const [certId, cert] of Object.entries(vaptData)) {
          const owns = cert.certificateImage === fileUrl ||
            (Array.isArray(cert.attachments) && cert.attachments.some(a => a.url === fileUrl));
          if (owns) {
            recordEngagement(vaptData, certId, 'document_downloaded', { file: fname }, saveVaptData);
            break;
          }
        }
      } catch { /* non-fatal */ }
    }

    try {
      const content = fs.readFileSync(fpath);
      res.writeHead(200, {
        'Content-Type':           mime,
        'Content-Length':         content.length,
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control':          'private, max-age=3600',
        'X-Frame-Options':        'SAMEORIGIN',
        'Content-Disposition':    isPdf ? `inline; filename="${fname}"` : 'inline',
      });
      return res.end(content);
    } catch {
      res.writeHead(404, SECURITY_HEADERS);
      return res.end('Not found');
    }
  }

  // ── Config (browser-side app.config.js) ──────────────────────────────────
  if (p === '/config.js') {
    return sendFile(res, path.join(__dirname, '..', 'config', 'app.config.js'), req);
  }

  // ── API (shared) ──────────────────────────────────────────────────────────
  if (p.startsWith('/api')) {
    return handleAPI(req, res, parsed);
  }

  // ── Root → redirect to /CST ───────────────────────────────────────────────
  if (p === '/') {
    res.writeHead(302, { Location: CFG.routes.cst });
    return res.end();
  }

  const publicDir = path.resolve(__dirname, '..', 'public');
  const adminDir  = path.resolve(__dirname, '..', 'admin');

  // ══════════════════════════════════════════════════════════════════════════
  //  CST — Cyber Security Training routes
  // ══════════════════════════════════════════════════════════════════════════

  if (p === CFG.routes.cstAdmin || p === CFG.routes.cstAdmin + '/') {
    if (p === CFG.routes.cstAdmin) { res.writeHead(301, { Location: CFG.routes.cstAdmin + '/' }); return res.end(); }
    return sendFile(res, path.join(adminDir, 'dashboard.html'), req);
  }
  if (p.startsWith(CFG.routes.cstAdmin + '/')) {
    const relative = p.slice((CFG.routes.cstAdmin + '/').length);
    let filePath = path.resolve(adminDir, relative || 'dashboard.html');
    if (!path.extname(filePath)) filePath = path.join(adminDir, 'dashboard.html');
    if (!filePath.startsWith(adminDir + path.sep) && filePath !== adminDir) {
      res.writeHead(403, SECURITY_HEADERS); return res.end('Forbidden');
    }
    return sendFile(res, filePath, req);
  }

  if (p.startsWith(CFG.routes.cst + '/cert/')) {
    return sendFile(res, path.join(publicDir, 'index.html'), req);
  }

  if (p === CFG.routes.cst || p === CFG.routes.cst + '/') {
    return sendFile(res, path.join(publicDir, 'index.html'), req);
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  VPT — VAPT Assessment routes
  // ══════════════════════════════════════════════════════════════════════════

  if (p === CFG.routes.vptAdmin || p === CFG.routes.vptAdmin + '/') {
    if (p === CFG.routes.vptAdmin) { res.writeHead(301, { Location: CFG.routes.vptAdmin + '/' }); return res.end(); }
    return sendFile(res, path.join(adminDir, 'vapt-dashboard.html'), req);
  }
  if (p.startsWith(CFG.routes.vptAdmin + '/')) {
    const relative = p.slice((CFG.routes.vptAdmin + '/').length);
    let filePath = path.resolve(adminDir, relative || 'vapt-dashboard.html');
    if (!path.extname(filePath)) filePath = path.join(adminDir, 'vapt-dashboard.html');
    if (!filePath.startsWith(adminDir + path.sep) && filePath !== adminDir) {
      res.writeHead(403, SECURITY_HEADERS); return res.end('Forbidden');
    }
    return sendFile(res, filePath, req);
  }

  if (p.startsWith(CFG.routes.vpt + '/cert/')) {
    return sendFile(res, path.join(publicDir, 'vapt-index.html'), req);
  }

  if (p === CFG.routes.vpt || p === CFG.routes.vpt + '/') {
    return sendFile(res, path.join(publicDir, 'vapt-index.html'), req);
  }

  // ── Legacy redirect support ───────────────────────────────────────────────
  if (p.startsWith('/cert/')) {
    res.writeHead(301, { Location: p.replace('/cert/', CFG.routes.cst + '/cert/') + (parsed.search || '') });
    return res.end();
  }
  if (p.startsWith('/vapt-cert/')) {
    res.writeHead(301, { Location: p.replace('/vapt-cert/', CFG.routes.vpt + '/cert/') + (parsed.search || '') });
    return res.end();
  }
  if (p === '/admin' || p.startsWith('/admin/')) {
    res.writeHead(301, { Location: p.replace('/admin', CFG.routes.cstAdmin) });
    return res.end();
  }
  if (p === '/vapt-admin' || p.startsWith('/vapt-admin/')) {
    res.writeHead(301, { Location: p.replace('/vapt-admin', CFG.routes.vptAdmin) });
    return res.end();
  }

  // ── Static files & 404 ────────────────────────────────────────────────────
  let filePath = path.resolve(publicDir, p.slice(1));
  if (!path.extname(filePath)) filePath += '.html';
  if (!filePath.startsWith(publicDir + path.sep) && filePath !== publicDir) {
    res.writeHead(403, SECURITY_HEADERS); return res.end('Forbidden');
  }
  if (fs.existsSync(filePath)) return sendFile(res, filePath, req);

  // 404
  res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>404 — Page Not Found · ${CFG.brand.name}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',system-ui,sans-serif;background:#0A1628;color:#CCD6F6;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 20px}
    .card{max-width:500px;width:100%;text-align:center}
    .code{font-size:6rem;font-weight:800;line-height:1;background:linear-gradient(135deg,#D4A843,#64FFDA);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:12px}
    h1{font-size:1.5rem;color:#E6F1FF;margin-bottom:10px}
    p{font-size:.9rem;color:#8892B0;line-height:1.7;margin-bottom:28px}
    .links{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
    a{display:inline-flex;align-items:center;gap:7px;padding:11px 22px;border-radius:10px;font-size:.8rem;font-weight:600;letter-spacing:.06em;text-decoration:none;transition:opacity .2s}
    .btn-gold{background:linear-gradient(135deg,#D4A843,#9E7B0A);color:#0A1628}
    .btn-teal{background:rgba(100,255,218,0.1);border:1px solid rgba(100,255,218,0.3);color:#64FFDA}
    a:hover{opacity:.85;transform:translateY(-1px)}
  </style>
</head>
<body>
  <div class="card">
    <div class="code">404</div>
    <h1>Page Not Found</h1>
    <p>The page you're looking for doesn't exist.<br>Use the links below to return to a valid portal.</p>
    <div class="links">
      <a href="${CFG.routes.cst}" class="btn-gold">🛡 CST Portal</a>
      <a href="${CFG.routes.vpt}" class="btn-teal">🔍 VAPT Portal</a>
    </div>
  </div>
</body>
</html>`);
}

const server = http.createServer((req, res) => {
  Promise.resolve(handleRequest(req, res)).catch((err) => {
    log.error('Unhandled request error:', err && err.message ? err.message : err);
    if (res.headersSent) return res.end();
    res.writeHead(500, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'Internal server error' }));
  });
});

// ─── START ───────────────────────────────────────────────────────────────────
server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    log.error(`Port ${PORT} is already in use. Set a different PORT in .env or stop the conflicting process.`);
  } else {
    log.error('Server startup error:', err.message);
  }
  process.exit(1);
});

async function startServer() {
  try {
    await initialiseRuntimePrerequisites();
  } catch (err) {
    log.error('Failed to initialise runtime:', err.message || err);
    process.exit(1);
  }

  server.listen(PORT, () => {
    const W = 58;
    const line  = s  => console.log('║  ' + s.padEnd(W - 4) + '║');
    const blank = () => console.log('║' + ' '.repeat(W - 2) + '║');
    console.log('\n╔' + '═'.repeat(W - 2) + '╗');
    line(CFG.brand.companyFull + ' — Certificate Portal');
    console.log('╠' + '═'.repeat(W - 2) + '╣');
    blank();
    line('  CST Portal  →  ' + BASE_ORIGIN + CFG.routes.cst);
    line('  CST Admin   →  ' + BASE_ORIGIN + CFG.routes.cstAdmin + '/');
    line('  VAPT Portal →  ' + BASE_ORIGIN + CFG.routes.vpt);
    line('  VAPT Admin  →  ' + BASE_ORIGIN + CFG.routes.vptAdmin + '/');
    line('  Health      →  ' + BASE_ORIGIN + '/api/health');
    blank();
    line('  Email dispatch: ' + (SES_ENABLED ? 'Active (' + SES_REGION + ')' : 'Not configured'));
    blank();
    console.log('╚' + '═'.repeat(W - 2) + '╝\n');
  });
}
startServer();

// ─── GRACEFUL SHUTDOWN ────────────────────────────────────────────────────────
function flushPendingSaves() {
  // If a debounced save is pending, flush it synchronously before exit
  [
    { timer: saveData._t,     file: DATA_FILE,      cache: () => _certCache },
    { timer: saveVaptData._t, file: VAPT_DATA_FILE,  cache: () => _vaptCache },
  ].forEach(({ timer, file, cache }) => {
    if (timer) {
      clearTimeout(timer);
      const d = cache();
      if (d) {
        try { fs.writeFileSync(file, JSON.stringify(d, null, 2), 'utf8'); }
        catch (e) { log.error('Data flush on shutdown failed:', e.message); }
      }
    }
  });
}

function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  log.info(`${signal} received — shutting down gracefully…`);
  clearInterval(_rlCleanup);
  flushPendingSaves();
  server.close(err => {
    if (err) { log.error('Server close error:', err.message); process.exit(1); }
    if (_shutdownTimer) clearTimeout(_shutdownTimer);
    log.info('Server stopped cleanly.');
    process.exit(0);
  });
  _shutdownTimer = setTimeout(() => {
    log.error('Forced exit — shutdown exceeded 10 s.');
    process.exit(1);
  }, 10_000);
  _shutdownTimer.unref();
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

// ─── SAFETY NETS ─────────────────────────────────────────────────────────────
process.on('unhandledRejection', (reason, promise) => {
  log.error('Unhandled promise rejection:', reason);
});
process.on('uncaughtException', err => {
  log.error('Uncaught exception:', err.message || err);
});