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
hashPassword(ADMIN_PASS).then(hash => {
  ADMIN_PASS_HASH = hash;
  serverReady = true;
  log.info('Authentication ready.');
}).catch(err => {
  log.error('Failed to initialise authentication:', err.message);
  process.exit(1);
});

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
 * Build a minimal RFC 2822 email string with UTF-8 encoded subject.
 */
function buildRawEmail({ from, to, subject, body, replyTo, trackingPixelUrl }) {
  const b64subject = '=?UTF-8?B?' + Buffer.from(subject).toString('base64') + '?=';
  const msgId  = `<${crypto.randomBytes(16).toString('hex')}.${Date.now()}@${(from.match(/@([^>\s]+)/) || [])[1] || 'mail'}>`;
  const dateStr = new Date().toUTCString().replace(/GMT$/, '+0000');
  const boundary = 'SYNBND_' + crypto.randomBytes(8).toString('hex');

  // Plain-text part (base64)
  const plainB64 = Buffer.from(body).toString('base64').replace(/(.{76})/g, '$1\r\n').replace(/\r\n$/, '');

  // HTML part — plain text converted to basic HTML + tracking pixel appended
  const htmlBody = '<html><body><pre style="font-family:Arial,sans-serif;font-size:14px;white-space:pre-wrap">'
    + body.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    + '</pre>'
    + (trackingPixelUrl
        ? `<img src="${trackingPixelUrl}" width="1" height="1" style="display:none" alt="" />`
        : '')
    + '</body></html>';
  const htmlB64  = Buffer.from(htmlBody).toString('base64').replace(/(.{76})/g, '$1\r\n').replace(/\r\n$/, '');

  const lines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${b64subject}`,
    `Message-ID: ${msgId}`,
    `Date: ${dateStr}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
  ];
  if (replyTo && replyTo !== from) lines.push(`Reply-To: ${replyTo}`);
  lines.push('');
  lines.push(`--${boundary}`);
  lines.push('Content-Type: text/plain; charset=UTF-8');
  lines.push('Content-Transfer-Encoding: base64');
  lines.push('');
  lines.push(plainB64);
  lines.push('');
  lines.push(`--${boundary}`);
  lines.push('Content-Type: text/html; charset=UTF-8');
  lines.push('Content-Transfer-Encoding: base64');
  lines.push('');
  lines.push(htmlB64);
  lines.push('');
  lines.push(`--${boundary}--`);
  return lines.join('\r\n');
}

// ─── EMAIL LOG HELPER ─────────────────────────────────────────────────────────
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
  const trackingPixelUrl = buildTrackingPixelUrl(cert.id, baseUrl || BASE_ORIGIN, 'cst');
  const raw              = buildRawEmail({ from, to, subject, body, replyTo: from, trackingPixelUrl });
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
  const trackingPixelUrl = buildTrackingPixelUrl(cert.id, baseUrl || BASE_ORIGIN, 'vapt');
  const raw    = buildRawEmail({ from, to, subject, body: cleanBody, replyTo: from, trackingPixelUrl });
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
  const baseYear = cert.complianceDate ? new Date(cert.complianceDate).getFullYear() : new Date().getFullYear();
  const year     = info.nextYear ? baseYear + 1 : baseYear;
  if (!cert.validFor)   cert.validFor   = info.label + '-' + year;
  if (!cert.validUntil) {
    const d = new Date(year, info.endMonth - 1, info.endDay);
    cert.validUntil = d.toISOString().slice(0, 10);
  }
  if (cert.vesselName && (!cert.recipientName || cert.recipientName === cert.vesselName)) {
    const existingPrefix = (cert.recipientName || '').match(/^(MV|MT)\s*-\s*/i);
    const prefix = existingPrefix ? existingPrefix[1].toUpperCase() : 'MV';
    cert.recipientName = prefix + ' - ' + cert.vesselName;
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
  // NEW: returns uptime, config version, SES status, and cert counts.
  // Intentionally does NOT expose sensitive details.
  if (route === '/health' && method === 'GET') {
    const cstCerts  = Object.values(loadData());
    const vaptCerts = Object.values(loadVaptData());
    return sendJSON(res, 200, {
      ok:        true,
      uptime:    Math.floor((Date.now() - SERVER_START_TIME) / 1000),
      timestamp: new Date().toISOString(),
      version:   CFG.version || '1.0.0',
      ses:       SES_ENABLED,
      certs:     { cst: cstCerts.length, vapt: vaptCerts.length },
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
    // Auto-status: if all 5 required fields present → VALID; otherwise → PENDING
    // (client sends intended status, but we enforce server-side for consistency)
    const _cstRequired = !!(cert.vesselIMO && cert.recipientEmail && cert.chiefEngineer && cert.complianceDate && cert.certificateImage);
    if (!_cstRequired) cert.status = 'PENDING';
    else if (!cert.status || cert.status === 'PENDING') cert.status = 'VALID';
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
    if (!cert.recipientEmail)
      return sendJSON(res, 400, { error: 'No recipient email on this certificate' }, corsH);
    if ((cert.issuerEmail || '').trim().toLowerCase() === (cert.recipientEmail || '').trim().toLowerCase())
      return sendJSON(res, 400, { error: 'Issuer and recipient email cannot be the same' }, corsH);

    let body;
    try { body = JSON.parse(await getBody(req)); } catch { body = {}; }
    const base      = body.baseUrl || BASE_ORIGIN;
    const verifyUrl = buildCertUrl(cert.id, base);
    const fromAddr  = SES_FROM_CST || cert.issuerEmail || CFG.contact.cstEmail;

    if (!SES_ENABLED) {
      return sendJSON(res, 503, {
        error: 'Email dispatch is not available on this server. Contact your system administrator.',
        sesEnabled: false,
      }, corsH);
    }

    const result = await sendCstEmail({
      to: cert.recipientEmail, from: fromAddr, cert, verifyUrl, baseUrl: base
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
      }, corsH);
    }

    return sendJSON(res, 500, {
      error: 'Email could not be delivered. Please verify the recipient address and try again.',
      sesEnabled: true,
    }, corsH);
  }

  // ── POST /api/import-csv ── (admin — bulk import CST certs, mirrors /api/vapt/import-csv)
  if (route === '/import-csv' && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const records = Array.isArray(body) ? body : [];
    const data = loadData();
    let added = 0, skipped = 0, failed = 0;
    const results = [];
    for (const cert of records) {
      const certId = sanitiseCertId(cert.id);
      if (!certId) { results.push({ id: cert.id, status: 'failed', reason: 'Invalid ID' }); failed++; continue; }
      if (data[certId]) { results.push({ id: certId, status: 'skipped', reason: 'Already exists' }); skipped++; continue; }
      cert.id = certId;
      deriveQuarterFields(cert);
      cert.emailStatus = 'NOT_SENT';
      cert.emailSentAt = null;
      cert.attachments = [];
      cert.createdAt = new Date().toISOString();
      cert.updatedAt = new Date().toISOString();
      data[certId] = cert;
      results.push({ id: certId, status: 'created' });
      added++;
    }
    saveData(data);
    return sendJSON(res, 200, { added, skipped, failed, results }, corsH);
  }

  // ── DELETE /api/certs/:id ── (admin)
  if (route.startsWith('/certs/') && method === 'DELETE') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const certId = sanitiseCertId(route.replace('/certs/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    if (data[certId].certificateImage) {
      const imgPath = path.join(UPLOADS_DIR, path.basename(data[certId].certificateImage));
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    }
    delete data[certId];
    saveData(data);
    return sendJSON(res, 200, { success: true }, corsH);
  }

  // ── GET /api/stats ── (public — aggregate cert stats for index page)
  // IMPROVED: now returns lastIssued date for display on the public portal
  if (route === '/stats' && method === 'GET') {
    const data  = loadData();
    const certs = Object.values(data);
    const now   = new Date();
    const total = certs.length;
    const valid = certs.filter(c =>
      (c.status || 'VALID').toUpperCase() === 'VALID' && (!c.validUntil || new Date(c.validUntil) >= now)
    ).length;
    const expired = certs.filter(c =>
      (c.status || 'VALID').toUpperCase() === 'VALID' && c.validUntil && new Date(c.validUntil) < now
    ).length;
    const pending = certs.filter(c =>
      (c.status || '').toUpperCase() === 'PENDING'
    ).length;
    const lastIssuedDate = certs.reduce((best, c) => {
      const d = c.createdAt || c.issuedAt || c.complianceDate || '';
      return d > best ? d : best;
    }, '');
    return sendJSON(res, 200, {
      total, valid, expired, pending,
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
  // IMPROVED: now returns lastIssued date
  if (route === '/vapt/stats' && method === 'GET') {
    const data  = loadVaptData();
    const certs = Object.values(data);
    const now   = new Date();
    const total = certs.length;
    const valid = certs.filter(c =>
      (c.status || 'VALID').toUpperCase() === 'VALID' && (!c.validUntil || new Date(c.validUntil) >= now)
    ).length;
    const expired = certs.filter(c =>
      (c.status || 'VALID').toUpperCase() === 'VALID' && c.validUntil && new Date(c.validUntil) < now
    ).length;
    const pending = certs.filter(c =>
      (c.status || '').toUpperCase() === 'PENDING'
    ).length;
    const lastIssuedDate = certs.reduce((best, c) => {
      const d = c.createdAt || c.issuedAt || c.assessmentDate || '';
      return d > best ? d : best;
    }, '');
    return sendJSON(res, 200, {
      total, valid, expired, pending,
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
    cert.emailStatus = cert.emailStatus || 'NOT_SENT';
    cert.emailSentAt = cert.emailSentAt || null;
    cert.createdAt   = new Date().toISOString();
    cert.updatedAt   = new Date().toISOString();
    // Auto-status: if all 5 required fields present → VALID; otherwise → PENDING
    const _vaptRequired = !!(cert.vesselName && cert.recipientName && cert.assessmentDate && cert.validUntil && cert.recipientEmail && cert.certificateImage);
    if (!_vaptRequired) cert.status = 'PENDING';
    else if (!cert.status || cert.status === 'PENDING') cert.status = 'VALID';
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
    const data = loadVaptData();
    let added = 0, skipped = 0, failed = 0;
    const results = [];
    for (const cert of records) {
      const certId = sanitiseCertId(cert.id);
      if (!certId) { results.push({ id: cert.id, status: 'failed', reason: 'Invalid ID' }); failed++; continue; }
      if (data[certId]) { results.push({ id: certId, status: 'skipped', reason: 'Already exists' }); skipped++; continue; }
      cert.id = certId;
      cert.emailStatus = 'NOT_SENT';
      cert.emailSentAt = null;
      cert.attachments = [];
      cert.createdAt = new Date().toISOString();
      cert.updatedAt = new Date().toISOString();
      data[certId] = cert;
      results.push({ id: certId, status: 'created' });
      added++;
    }
    saveVaptData(data);
    return sendJSON(res, 200, { added, skipped, failed, results }, corsH);
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
    if (!cert.recipientEmail) return sendJSON(res, 400, { error: 'No recipient email on this certificate' }, corsH);
    if ((cert.issuerEmail || '').trim().toLowerCase() === (cert.recipientEmail || '').trim().toLowerCase())
      return sendJSON(res, 400, { error: 'Issuer and recipient email cannot be the same' }, corsH);

    let body;
    try { body = JSON.parse(await getBody(req)); } catch { body = {}; }
    const base      = body.baseUrl || BASE_ORIGIN;
    const verifyUrl = buildVaptCertUrl(cert.id, base);
    const fromAddr  = SES_FROM_VAPT || cert.issuerEmail || CFG.contact.vaptEmail;

    if (!SES_ENABLED) {
      return sendJSON(res, 503, {
        error: 'Email dispatch is not available on this server. Contact your system administrator.',
        sesEnabled: false,
      }, corsH);
    }

    const result = await sendVaptEmail({
      to: cert.recipientEmail, from: fromAddr, cert, verifyUrl, baseUrl: base
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
      }, corsH);
    }

    return sendJSON(res, 500, {
      error: 'Email could not be delivered. Please verify the recipient address and try again.',
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
    if (data[certId].certificateImage) {
      const imgPath = path.join(UPLOADS_DIR, path.basename(data[certId].certificateImage));
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
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
const server = http.createServer(async (req, res) => {
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

    // ── Track document download: find which cert owns this file ──
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
  log.info(`${signal} received — shutting down gracefully…`);
  clearInterval(_rlCleanup);
  flushPendingSaves();
  server.close(err => {
    if (err) { log.error('Server close error:', err.message); process.exit(1); }
    log.info('Server stopped cleanly.');
    process.exit(0);
  });
  setTimeout(() => { log.error('Forced exit — shutdown exceeded 10 s.'); process.exit(1); }, 10_000).unref();
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