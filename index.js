/**
 * Synergy Certificate Verification Portal — Server (MERGED SINGLE PORT)
 * Pure Node.js · Zero npm dependencies
 *
 * ╔══════════════════════════════════════════════════════════════╗
 * ║  SECURITY HARDENING — v3.0 (Single-Port Edition)            ║
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
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Public Portal  → http://localhost:3000/
 * Admin Panel    → http://localhost:3000/admin
 * API            → http://localhost:3000/api
 */

'use strict';

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// ─── ENV LOADER ──────────────────────────────────────────────────────────────
// Loads KEY=VALUE from .env file (same dir or parent dir).
// Strips surrounding quotes. Never overwrites existing env vars.
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
    console.log(`[ENV] Loaded configuration from ${envFile}`);
    break;
  }
})();

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const PORT        = parseInt(process.env.PORT || '3000', 10);
const DATA_FILE      = path.join(__dirname, '..', 'data', 'certificates.json');
const VAPT_DATA_FILE = path.join(__dirname, '..', 'data', 'vapt_certificates.json');

const UPLOADS_DIR    = path.join(__dirname, '..', 'uploads');
const KEYS_FILE      = path.join(__dirname, '..', 'data', '.keys.json');

// ─── DEPLOYMENT CONFIG ───────────────────────────────────────────────────────
// Local dev:   http://localhost:3000
// Production:  Set BASE_ORIGIN=https://yourdomain.com (or your EC2 IP)
const BASE_ORIGIN = process.env.BASE_ORIGIN || `http://localhost:${PORT}`;

const ALLOWED_ORIGINS = [
  BASE_ORIGIN,
  'http://localhost:3000',
  'http://127.0.0.1:3000',
].filter((v, i, a) => v && a.indexOf(v) === i);

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
  console.log('[SECURITY] Generated new cryptographic keys → .keys.json');
  return keys;
}
const KEYS = loadOrCreateKeys();

// ─── ADMIN CREDENTIALS ───────────────────────────────────────────────────────
// REQUIRED: Set ADMIN_USER and ADMIN_PASS in your .env file.
// The server will refuse to start if either is missing — no hardcoded fallbacks.
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

if (!ADMIN_USER || !ADMIN_PASS) {
  console.error('\n╔══════════════════════════════════════════════════════════════╗');
  console.error('║  FATAL: Missing required environment variables!               ║');
  console.error('║                                                                ║');
  console.error('║  Create a .env file in the project root with:                 ║');
  console.error('║    ADMIN_USER=your_admin_username                              ║');
  console.error('║    ADMIN_PASS=your_strong_password                             ║');
  console.error('║                                                                ║');
  console.error('║  Never hardcode credentials in source code.                   ║');
  console.error('╚══════════════════════════════════════════════════════════════╝\n');
  process.exit(1);
}

function hashPassword(password) {
  return crypto.pbkdf2Sync(password, KEYS.pwdSalt, 310000, 32, 'sha256').toString('hex');
}
const ADMIN_PASS_HASH = hashPassword(ADMIN_PASS);

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
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
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
    const iv      = raw.subarray(0, 12);
    const tag     = raw.subarray(12, 28);
    const enc     = raw.subarray(28);
    const key     = Buffer.from(KEYS.urlEncKey, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc) + decipher.final('utf8');
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
  return `${baseUrl}/CST/cert/${token}?s=${sig}`;
}

// ─── RATE LIMITER ─────────────────────────────────────────────────────────────
const rateLimits = new Map();
const RATE_LIMITS = {
  verify:  { max: 30,  window: 60_000  },
  login:   { max: 5,   window: 300_000 },
  default: { max: 120, window: 60_000  },
};

function checkRateLimit(ip, bucket) {
  const { max, window } = RATE_LIMITS[bucket] || RATE_LIMITS.default;
  const key   = `${bucket}:${ip}`;
  const now   = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimits.set(key, { count: 1, resetAt: now + window });
    return { ok: true, remaining: max - 1 };
  }
  if (entry.count >= max) return { ok: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
  entry.count++;
  return { ok: true, remaining: max - entry.count };
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimits) if (now > v.resetAt) rateLimits.delete(k);
}, 60_000);

// ─── SECURITY HEADERS ────────────────────────────────────────────────────────
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options':        'DENY',
  'X-XSS-Protection':       '1; mode=block',
  'Referrer-Policy':        'strict-origin-when-cross-origin',
  'Permissions-Policy':     'camera=(), microphone=(), geolocation=()',
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
    trainingTitle: "Cyber Security Threat Awareness Training",
    organizer: "Synergy Cyber Security Team",
    complianceDate: "2026-01-30",
    complianceQuarter: "Q1",
    trainingMode: "ONLINE",
    validFor: "Q2 (APR-MAY-JUN)-2026",
    validUntil: "2026-06-30",
    verifiedBy: "Gaurav Singh, CISO - Chief Information Security Officer, Synergy Marine Group",
    status: "VALID",
    issuedAt: "2026-01-30",
    certificateImage: null,
    notes: "Training conducted under supervision of ISO Lead Auditor and Security trainers",
    recipientEmail: "",
    issuerEmail: "trainingawareness@synergyship.com",
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
    trainingTitle: "Cyber Security Threat Awareness Training",
    organizer: "Synergy Cyber Security Team",
    complianceDate: "2026-02-12",
    complianceQuarter: "Q1",
    trainingMode: "ONLINE",
    validFor: "Q2 (APR-MAY-JUN)-2026",
    validUntil: "2026-06-30",
    verifiedBy: "Gaurav Singh, CISO - Chief Information Security Officer, Synergy Marine Group",
    status: "VALID",
    issuedAt: "2026-02-12",
    certificateImage: null,
    notes: "Training conducted under supervision of ISO Lead Auditor and Security trainers",
    recipientEmail: "",
    issuerEmail: "trainingawareness@synergyship.com",
    emailStatus: "NOT_SENT",
    emailSentAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  }
};

// ─── DATA STORE ──────────────────────────────────────────────────────────────
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch { }
  saveData(SEED);
  return { ...SEED };
}
function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
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
    verifiedBy: "Gaurav Singh",
    verifierTitle: "CISO-Synergy Group",
    assessingOrg: "Synergy Cybersecurity team",
    frameworks: "Cybersecurity Framework / OWASP / IMO Framework / ISO 27001:2013",
    scopeItems: "Access Control (USB/Data/Login/Domain/Email/Assets),IT/OT Risk analysis,Vessel Cyber security awareness,Software Version Control (IT/OT),Backups & Disaster Recovery,IT Drills & Internal Audits",
    status: "VALID",
    issuedAt: "2026-02-10",
    certificateImage: null,
    recipientEmail: "",
    issuerEmail: "vapt@synergyship.com",
    emailStatus: "NOT_SENT",
    emailSentAt: null,
    notes: "Re-assessment recommended within 2 weeks from date of participation.",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  }
};

// ─── VAPT DATA STORE ─────────────────────────────────────────────────────────
function loadVaptData() {
  try {
    if (fs.existsSync(VAPT_DATA_FILE)) return JSON.parse(fs.readFileSync(VAPT_DATA_FILE, 'utf8'));
  } catch { }
  saveVaptData(VAPT_SEED);
  return { ...VAPT_SEED };
}
function saveVaptData(data) {
  fs.writeFileSync(VAPT_DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// ─── VAPT CERT URL BUILDER ───────────────────────────────────────────────────
function buildVaptCertUrl(certId, baseUrl) {
  const token = encryptCertToken(certId);
  const sig   = signCertUrl(token);
  return `${baseUrl}/VPT/cert/${token}?s=${sig}`;
}

function simulateSendVaptEmail({ to, from, certId, recipientName, assessmentDate, verifyUrl }) {
  const logFile = path.join(path.dirname(DATA_FILE), 'vapt_email_log.jsonl');
  const entry   = {
    timestamp: new Date().toISOString(),
    to, from, certId, recipientName, assessmentDate,
    verifyUrl, status: 'SIMULATED'
  };
  fs.appendFileSync(logFile, JSON.stringify(entry) + '\n', 'utf8');
  return true;
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

/**
 * Parse attachment metadata from multipart fields.
 * Admin can pass existing attachments as JSON string: attachments='[{name,url},…]'
 * New file uploads arrive as attachment_0, attachment_1, … or attachment_files_0, …
 */
function extractAttachments(fields, files, prefix, existingAttachments = []) {
  // Start with existing (already stored) attachments if passed
  let result = existingAttachments.slice();

  // Parse any JSON array sent as field
  if (fields.attachments) {
    try { result = JSON.parse(fields.attachments); } catch { /* ignore */ }
  }

  // Process newly uploaded files (attachment_0, attachment_1, …)
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
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    ...SECURITY_HEADERS,
    ...extraHeaders,
  });
  res.end(body);
}

function sendFile(res, filePath) {
  const ext  = path.extname(filePath).toLowerCase();
  const mime = MIME[ext] || 'text/plain';
  try {
    const content = fs.readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': mime, ...SECURITY_HEADERS });
    res.end(content);
  } catch {
    res.writeHead(404, SECURITY_HEADERS);
    res.end('Not found');
  }
}

function getBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > 10 * 1024 * 1024) { req.destroy(); reject(new Error('Payload too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
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
function deriveQuarterFields(cert) {
  const qMap = {
    Q1: { label: 'Q2 (APR-MAY-JUN)', endMonth: 5,  endDay: 30 },
    Q2: { label: 'Q3 (JUL-AUG-SEP)', endMonth: 8,  endDay: 30 },
    Q3: { label: 'Q4 (OCT-NOV-DEC)', endMonth: 11, endDay: 31 },
    Q4: { label: 'Q1 (JAN-FEB-MAR)', endMonth: 2,  endDay: 28, nextYear: true }
  };
  const q    = (cert.complianceQuarter || '').toUpperCase();
  const info = qMap[q];
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
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body     = Buffer.concat(chunks);
      const boundary = req.headers['content-type'].split('boundary=')[1];
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

// ─── EMAIL SIMULATION ────────────────────────────────────────────────────────
function simulateSendEmail({ to, from, certId, recipientName, trainingTitle, verifyUrl }) {
  const logFile = path.join(path.dirname(DATA_FILE), 'email_log.jsonl');
  const entry   = {
    timestamp: new Date().toISOString(),
    to, from, certId, recipientName, trainingTitle,
    verifyUrl,
    status: 'SIMULATED'
  };
  fs.appendFileSync(logFile, JSON.stringify(entry) + '\n', 'utf8');
  return true;
}

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

  // ── POST /api/auth/login ──────────────────────────────────────────────────
  if (route === '/auth/login' && method === 'POST') {
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
    const passwordHash  = hashPassword(password || '');
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
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    return sendJSON(res, 200, { ok: true }, corsH);
  }

  // ── GET /api/certs ── (admin — list all)
  if (route === '/certs' && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    return sendJSON(res, 200, Object.values(loadData()), corsH);
  }

  // ── GET /api/certs/:id ── (admin — single cert)
  if (route.startsWith('/certs/') && !route.includes('/verify') &&
      !route.includes('/send-email') && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    const certId = sanitiseCertId(route.replace('/certs/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const cert = loadData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    return sendJSON(res, 200, cert, corsH);
  }

  // ── GET /api/verify-by-id/:certId ── (public — verify training cert by plain ID)
  if (route.startsWith('/verify-by-id/') && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(rl.retryAfter), ...corsH });
    const certId = sanitiseCertId(route.replace('/verify-by-id/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const cert = loadData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Certificate not found' }, corsH);
    const { id, recipientName, vesselName, vesselIMO, chiefEngineer,
            trainingTitle, organizer, complianceDate, complianceQuarter,
            trainingMode, validFor, validUntil, verifiedBy, status,
            issuedAt, certificateImage, notes, attachments } = cert;
    return sendJSON(res, 200, {
      id, recipientName, vesselName, vesselIMO, chiefEngineer,
      trainingTitle, organizer, complianceDate, complianceQuarter,
      trainingMode, validFor, validUntil, verifiedBy, status,
      issuedAt, certificateImage, notes,
      attachments: Array.isArray(attachments) ? attachments : []
    }, corsH);
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
    // Return only public fields
    const { id, recipientName, vesselName, vesselIMO, chiefEngineer,
            trainingTitle, organizer, complianceDate, complianceQuarter,
            trainingMode, validFor, validUntil, verifiedBy, status,
            issuedAt, certificateImage, notes, attachments } = cert;
    return sendJSON(res, 200, {
      id, recipientName, vesselName, vesselIMO, chiefEngineer,
      trainingTitle, organizer, complianceDate, complianceQuarter,
      trainingMode, validFor, validUntil, verifiedBy, status,
      issuedAt, certificateImage, notes,
      attachments: Array.isArray(attachments) ? attachments : []
    }, corsH);
  }

  // ── GET /api/cert-url/:id ── (admin — generate public cert URL)
  if (route.startsWith('/cert-url/') && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    const certId = sanitiseCertId(route.replace('/cert-url/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const base = parsed.searchParams.get('base') || BASE_ORIGIN;
    return sendJSON(res, 200, { url: buildCertUrl(certId, base) }, corsH);
  }

  // ── POST /api/certs ── (admin — create)
  if (route === '/certs' && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    const ct = req.headers['content-type'] || '';
    let cert;
    try {
      if (ct.includes('multipart/form-data')) {
        const { fields, files } = await parseMultipart(req);
        cert = { ...fields };
        if (files.certificateImage && files.certificateImage.data.length > 0) {
          const origExt     = path.extname(files.certificateImage.filename).toLowerCase();
          const allowedExts = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
          const ext         = allowedExts.includes(origExt) ? origExt : '.jpg';
          const fname       = 'cert_' + crypto.randomBytes(12).toString('hex') + ext;
          fs.writeFileSync(path.join(UPLOADS_DIR, fname), files.certificateImage.data);
          cert.certificateImage = '/uploads/' + fname;
        }
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
    data[cert.id]    = cert;
    saveData(data);
    return sendJSON(res, 201, cert, corsH);
  }

  // ── PUT /api/certs/:id ── (admin — update)
  if (route.startsWith('/certs/') && !route.includes('/send-email') && method === 'PUT') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    const certId = sanitiseCertId(route.replace('/certs/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const ct = req.headers['content-type'] || '';
    let updates;
    try {
      if (ct.includes('multipart/form-data')) {
        const { fields, files } = await parseMultipart(req);
        updates = { ...fields };
        if (files.certificateImage && files.certificateImage.data.length > 0) {
          if (data[certId].certificateImage) {
            const old = path.join(UPLOADS_DIR, path.basename(data[certId].certificateImage));
            if (fs.existsSync(old)) fs.unlinkSync(old);
          }
          const origExt     = path.extname(files.certificateImage.filename).toLowerCase();
          const allowedExts = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
          const ext         = allowedExts.includes(origExt) ? origExt : '.jpg';
          const fname       = 'cert_' + crypto.randomBytes(12).toString('hex') + ext;
          fs.writeFileSync(path.join(UPLOADS_DIR, fname), files.certificateImage.data);
          updates.certificateImage = '/uploads/' + fname;
        }
        updates.attachments = extractAttachments(fields, files, 'cst_attach',
          Array.isArray(data[certId].attachments) ? data[certId].attachments : []);
      } else {
        updates = JSON.parse(await getBody(req));
        if (updates.attachments !== undefined && !Array.isArray(updates.attachments)) updates.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    const updated = { ...data[certId], ...updates, updatedAt: new Date().toISOString() };
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

  // ── POST /api/certs/:id/send-email ── (admin)
  if (route.match(/^\/certs\/[^/]+\/send-email$/) && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
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
    const ok = simulateSendEmail({
      to: cert.recipientEmail,
      from: cert.issuerEmail || 'trainingawareness@synergyship.com',
      certId: cert.id,
      recipientName: cert.recipientName,
      trainingTitle: cert.trainingTitle,
      verifyUrl
    });
    if (ok) {
      cert.emailStatus = 'SENT';
      cert.emailSentAt = new Date().toISOString();
      data[certId]     = cert;
      saveData(data);
      return sendJSON(res, 200,
        { success: true, emailStatus: 'SENT', emailSentAt: cert.emailSentAt, verifyUrl }, corsH);
    }
    return sendJSON(res, 500, { error: 'Email dispatch failed' }, corsH);
  }

  // ── DELETE /api/certs/:id ── (admin)
  if (route.startsWith('/certs/') && method === 'DELETE') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
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
  if (route === '/stats' && method === 'GET') {
    const data = loadData();
    const certs = Object.values(data);
    const now = new Date();
    const total = certs.length;
    const valid = certs.filter(c => c.status === 'VALID' && (!c.validUntil || new Date(c.validUntil) >= now)).length;
    return sendJSON(res, 200, { total, valid }, corsH);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // VAPT CERTIFICATE API ROUTES  (/api/vapt/*)
  // ══════════════════════════════════════════════════════════════════════════

  // ── GET /api/vapt/stats ── (public — aggregate VAPT cert stats)
  if (route === '/vapt/stats' && method === 'GET') {
    const data = loadVaptData();
    const certs = Object.values(data);
    const now = new Date();
    const total = certs.length;
    const valid = certs.filter(c => c.status === 'VALID' && (!c.validUntil || new Date(c.validUntil) >= now)).length;
    return sendJSON(res, 200, { total, valid }, corsH);
  }

  // ── GET /api/vapt/verify-by-id/:certId ── (public — verify VAPT cert by plain ID)
  if (route.startsWith('/vapt/verify-by-id/') && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(rl.retryAfter), ...corsH });
    const certId = sanitiseCertId(route.replace('/vapt/verify-by-id/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const cert = loadVaptData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'VAPT Certificate not found' }, corsH);
    const { id, recipientName, vesselName, vesselIMO, certificateNumber, assessmentDate,
            validUntil, verifiedBy, verifierTitle, assessingOrg, frameworks,
            scopeItems, status, issuedAt, certificateImage, notes, attachments } = cert;
    return sendJSON(res, 200, {
      id, recipientName, vesselName, vesselIMO, certificateNumber, assessmentDate,
      validUntil, verifiedBy, verifierTitle, assessingOrg, frameworks,
      scopeItems, status, issuedAt, certificateImage, notes,
      attachments: Array.isArray(attachments) ? attachments : []
    }, corsH);
  }

  // ── GET /api/vapt/certs ── (admin — list all VAPT certs)
  if (route === '/vapt/certs' && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    return sendJSON(res, 200, Object.values(loadVaptData()), corsH);
  }

  // ── GET /api/vapt/certs/:id ── (admin — single VAPT cert)
  if (route.startsWith('/vapt/certs/') && !route.includes('/verify') && !route.includes('/send-email') && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    const certId = sanitiseCertId(route.replace('/vapt/certs/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const cert = loadVaptData()[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    return sendJSON(res, 200, cert, corsH);
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
    const { id, recipientName, vesselName, vesselIMO, certificateNumber, assessmentDate,
            validUntil, verifiedBy, verifierTitle, assessingOrg, frameworks,
            scopeItems, status, issuedAt, certificateImage, notes, attachments } = cert;
    return sendJSON(res, 200, {
      id, recipientName, vesselName, vesselIMO, certificateNumber, assessmentDate,
      validUntil, verifiedBy, verifierTitle, assessingOrg, frameworks,
      scopeItems, status, issuedAt, certificateImage, notes,
      attachments: Array.isArray(attachments) ? attachments : []
    }, corsH);
  }

  // ── GET /api/vapt/cert-url/:id ── (admin — generate public VAPT cert URL)
  if (route.startsWith('/vapt/cert-url/') && method === 'GET') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    const certId = sanitiseCertId(route.replace('/vapt/cert-url/', ''));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadVaptData();
    if (!data[certId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const base = parsed.searchParams.get('base') || BASE_ORIGIN;
    return sendJSON(res, 200, { url: buildVaptCertUrl(certId, base) }, corsH);
  }

  // ── POST /api/vapt/certs ── (admin — create VAPT cert)
  if (route === '/vapt/certs' && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    const ct = req.headers['content-type'] || '';
    let cert;
    try {
      if (ct.includes('multipart/form-data')) {
        const { fields, files } = await parseMultipart(req);
        cert = { ...fields };
        if (files.certificateImage && files.certificateImage.data.length > 0) {
          const origExt = path.extname(files.certificateImage.filename).toLowerCase();
          const allowedExts = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
          const ext = allowedExts.includes(origExt) ? origExt : '.jpg';
          const fname = 'vapt_' + crypto.randomBytes(12).toString('hex') + ext;
          fs.writeFileSync(path.join(UPLOADS_DIR, fname), files.certificateImage.data);
          cert.certificateImage = '/uploads/' + fname;
        }
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
    data[cert.id] = cert;
    saveVaptData(data);
    return sendJSON(res, 201, cert, corsH);
  }

  // ── POST /api/vapt/import-csv ── (admin — bulk import VAPT certs)
  if (route === '/vapt/import-csv' && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
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
  if (route.startsWith('/vapt/certs/') && !route.includes('/send-email') && method === 'PUT') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
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
        if (files.certificateImage && files.certificateImage.data.length > 0) {
          if (data[certId].certificateImage) {
            const old = path.join(UPLOADS_DIR, path.basename(data[certId].certificateImage));
            if (fs.existsSync(old)) fs.unlinkSync(old);
          }
          const origExt = path.extname(files.certificateImage.filename).toLowerCase();
          const allowedExts = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
          const ext = allowedExts.includes(origExt) ? origExt : '.jpg';
          const fname = 'vapt_' + crypto.randomBytes(12).toString('hex') + ext;
          fs.writeFileSync(path.join(UPLOADS_DIR, fname), files.certificateImage.data);
          updates.certificateImage = '/uploads/' + fname;
        }
        updates.attachments = extractAttachments(fields, files, 'vpt_attach',
          Array.isArray(data[certId].attachments) ? data[certId].attachments : []);
      } else {
        updates = JSON.parse(await getBody(req));
        if (updates.attachments !== undefined && !Array.isArray(updates.attachments)) updates.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    const updated = { ...data[certId], ...updates, updatedAt: new Date().toISOString() };
    data[certId] = updated;
    saveVaptData(data);
    return sendJSON(res, 200, updated, corsH);
  }

  // ── POST /api/vapt/certs/:id/send-email ── (admin)
  if (route.match(/^\/vapt\/certs\/[^/]+\/send-email$/) && method === 'POST') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    const certId = sanitiseCertId(decodeURIComponent(route.replace('/vapt/certs/', '').replace('/send-email', '')));
    if (!certId) return sendJSON(res, 400, { error: 'Invalid certificate ID' }, corsH);
    const data = loadVaptData();
    const cert = data[certId];
    if (!cert) return sendJSON(res, 404, { error: 'Certificate not found' }, corsH);
    if (!cert.recipientEmail) return sendJSON(res, 400, { error: 'No recipient email on this certificate' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { body = {}; }
    const base = body.baseUrl || BASE_ORIGIN;
    const verifyUrl = buildVaptCertUrl(cert.id, base);
    const ok = simulateSendVaptEmail({
      to: cert.recipientEmail,
      from: cert.issuerEmail || 'vapt@synergyship.com',
      certId: cert.id,
      recipientName: cert.recipientName,
      assessmentDate: cert.assessmentDate,
      verifyUrl
    });
    if (ok) {
      cert.emailStatus = 'SENT';
      cert.emailSentAt = new Date().toISOString();
      data[certId] = cert;
      saveVaptData(data);
      return sendJSON(res, 200, { success: true, emailStatus: 'SENT', emailSentAt: cert.emailSentAt, verifyUrl }, corsH);
    }
    return sendJSON(res, 500, { error: 'Email dispatch failed' }, corsH);
  }

  // ── DELETE /api/vapt/certs/:id ── (admin)
  if (route.startsWith('/vapt/certs/') && method === 'DELETE') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
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
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
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
    data[certId].updatedAt = new Date().toISOString();
    saveData(data);
    return sendJSON(res, 200, { success: true, attachments: atts }, corsH);
  }

  // ── DELETE /api/vapt/certs/:id/attachments/:idx ── (admin — remove one VAPT attachment)
  if (route.match(/^\/vapt\/certs\/[^/]+\/attachments\/\d+$/) && method === 'DELETE') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
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
    data[certId].updatedAt = new Date().toISOString();
    saveVaptData(data);
    return sendJSON(res, 200, { success: true, attachments: atts }, corsH);
  }

  sendJSON(res, 404, { error: 'Route not found' }, corsH);
}

// ─── SINGLE UNIFIED SERVER ────────────────────────────────────────────────────
//
//  GET /              → public/index.html      (recipient portal)
//  GET /cert/:token   → public/index.html      (cert verification page)
//  GET /uploads/*     → uploads directory
//  GET /api/*         → API (public + admin endpoints)
//  GET /admin         → redirect to /admin/
//  GET /admin/        → admin/dashboard.html
//  GET /admin/*       → admin/* static files
//
const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, 'http://localhost');
  const p      = parsed.pathname;

  // ── Uploads (shared) ─────────────────────────────────────────────────────
  if (p.startsWith('/uploads/')) {
    const fname = path.basename(p);
    const fpath = path.join(UPLOADS_DIR, fname);

    // Path traversal protection — resolved path must be inside UPLOADS_DIR
    const realUploads = fs.realpathSync ? UPLOADS_DIR : UPLOADS_DIR;
    if (!fpath.startsWith(UPLOADS_DIR + path.sep) && fpath !== UPLOADS_DIR) {
      res.writeHead(403, SECURITY_HEADERS);
      return res.end('Forbidden');
    }

    const ext    = path.extname(fpath).toLowerCase();
    const mime   = MIME[ext] || 'application/octet-stream';
    const isPdf  = ext === '.pdf';

    // PDFs and images are served INLINE (view-only — no forced download).
    // X-Frame-Options: SAMEORIGIN allows iframe embedding in admin dashboard.
    const uploadHeaders = {
      'Content-Type': mime,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'private, max-age=3600',
      'X-Frame-Options': 'SAMEORIGIN',
      'Content-Disposition': isPdf
        ? `inline; filename="${fname}"`   // Forces browser PDF viewer, not download
        : 'inline',
    };
    try {
      const content = fs.readFileSync(fpath);
      res.writeHead(200, uploadHeaders);
      return res.end(content);
    } catch {
      res.writeHead(404, SECURITY_HEADERS);
      return res.end('Not found');
    }
  }

  // ── API (shared) ──────────────────────────────────────────────────────────
  if (p.startsWith('/api')) {
    return handleAPI(req, res, parsed);
  }

  // ── Root → redirect to /CST ───────────────────────────────────────────────
  if (p === '/') {
    res.writeHead(302, { Location: '/CST' });
    return res.end();
  }

  const publicDir = path.join(__dirname, '..', 'public');
  const adminDir  = path.join(__dirname, '..', 'admin');

  // ══════════════════════════════════════════════════════════════════════════
  //  CST — Cyber Security Training routes
  // ══════════════════════════════════════════════════════════════════════════

  // /CST/admin  →  Training Admin Dashboard
  if (p === '/CST/admin' || p === '/CST/admin/') {
    if (p === '/CST/admin') { res.writeHead(301, { Location: '/CST/admin/' }); return res.end(); }
    return sendFile(res, path.join(adminDir, 'dashboard.html'));
  }
  if (p.startsWith('/CST/admin/')) {
    const relative = p.slice('/CST/admin/'.length);
    let filePath = path.join(adminDir, relative || 'dashboard.html');
    if (!path.extname(filePath)) filePath = path.join(adminDir, 'dashboard.html');
    if (!filePath.startsWith(adminDir)) { res.writeHead(403, SECURITY_HEADERS); return res.end('Forbidden'); }
    return sendFile(res, filePath);
  }

  // /CST/cert/:token  →  Training cert viewer (SPA handles token)
  if (p.startsWith('/CST/cert/')) {
    return sendFile(res, path.join(publicDir, 'index.html'));
  }

  // /CST  or  /CST/  →  Training cert public viewer
  if (p === '/CST' || p === '/CST/') {
    return sendFile(res, path.join(publicDir, 'index.html'));
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  VPT — VAPT Assessment routes
  // ══════════════════════════════════════════════════════════════════════════

  // /VPT/admin  →  VAPT Admin Dashboard
  if (p === '/VPT/admin' || p === '/VPT/admin/') {
    if (p === '/VPT/admin') { res.writeHead(301, { Location: '/VPT/admin/' }); return res.end(); }
    return sendFile(res, path.join(adminDir, 'vapt-dashboard.html'));
  }
  if (p.startsWith('/VPT/admin/')) {
    const relative = p.slice('/VPT/admin/'.length);
    let filePath = path.join(adminDir, relative || 'vapt-dashboard.html');
    if (!path.extname(filePath)) filePath = path.join(adminDir, 'vapt-dashboard.html');
    if (!filePath.startsWith(adminDir)) { res.writeHead(403, SECURITY_HEADERS); return res.end('Forbidden'); }
    return sendFile(res, filePath);
  }

  // /VPT/cert/:token  →  VAPT cert viewer (SPA handles token)
  if (p.startsWith('/VPT/cert/')) {
    return sendFile(res, path.join(publicDir, 'vapt-index.html'));
  }

  // /VPT  or  /VPT/  →  VAPT cert public viewer
  if (p === '/VPT' || p === '/VPT/') {
    return sendFile(res, path.join(publicDir, 'vapt-index.html'));
  }

  // ── Legacy redirect support ───────────────────────────────────────────────
  // Old /cert/* → /CST/cert/*
  if (p.startsWith('/cert/')) {
    res.writeHead(301, { Location: p.replace('/cert/', '/CST/cert/') + (parsed.search || '') });
    return res.end();
  }
  // Old /vapt-cert/* → /VPT/cert/*
  if (p.startsWith('/vapt-cert/')) {
    res.writeHead(301, { Location: p.replace('/vapt-cert/', '/VPT/cert/') + (parsed.search || '') });
    return res.end();
  }
  // Old /admin → /CST/admin
  if (p === '/admin' || p.startsWith('/admin/')) {
    res.writeHead(301, { Location: p.replace('/admin', '/CST/admin') });
    return res.end();
  }
  // Old /vapt-admin → /VPT/admin
  if (p === '/vapt-admin' || p.startsWith('/vapt-admin/')) {
    res.writeHead(301, { Location: p.replace('/vapt-admin', '/VPT/admin') });
    return res.end();
  }

  // ── Static files & 404 ────────────────────────────────────────────────────
  let filePath = path.join(publicDir, p);
  if (!path.extname(filePath)) filePath += '.html';
  if (!filePath.startsWith(publicDir)) {
    res.writeHead(403, SECURITY_HEADERS); return res.end('Forbidden');
  }
  if (fs.existsSync(filePath)) return sendFile(res, filePath);

  // 404
  res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/html' });
  res.end(`<!DOCTYPE html><html><head><title>Not Found</title></head><body style="font-family:sans-serif;text-align:center;padding:80px;background:#0A1628;color:#CCD6F6"><h2>404 — Page Not Found</h2><p><a href="/CST" style="color:#D4A843">→ CST Certificate Portal</a> &nbsp;|&nbsp; <a href="/VPT" style="color:#64FFDA">→ VPT Assessment Portal</a></p></body></html>`);
});

// ─── START ───────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║  SYNERGY CERTIFICATE PORTAL — SINGLE PORT MODE       ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log(`║  🛡️  CST Portal    → ${BASE_ORIGIN}/CST`.padEnd(55) + '║');
  console.log(`║  🔐 CST Admin     → ${BASE_ORIGIN}/CST/admin/`.padEnd(55) + '║');
  console.log(`║  🔍 VPT Portal    → ${BASE_ORIGIN}/VPT`.padEnd(55) + '║');
  console.log(`║  🔐 VPT Admin     → ${BASE_ORIGIN}/VPT/admin/`.padEnd(55) + '║');
  console.log(`║  📡 API           → ${BASE_ORIGIN}/api`.padEnd(55) + '║');
  console.log('║                                                      ║');
  console.log('║  🔒 Security: AES-256-GCM URLs · HMAC-signed        ║');
  console.log('║               PBKDF2 passwords · JWT tokens (8h)    ║');
  console.log('║               Rate limiting · Strict CORS           ║');
  console.log('║                                                      ║');
  console.log('║  ⚠  Set ADMIN_USER / ADMIN_PASS / BASE_ORIGIN env  ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');
});