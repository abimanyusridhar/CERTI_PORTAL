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
const { log } = require('./logger');
const { loadDotEnv, validateRuntimeConfig } = require('./config/env');
const { createJsonStore } = require('./repositories/jsonStore');
const { createSecurityService, validation } = require('./services/security');
const { createMetrics } = require('./ops/metrics');
const { createHealthRoute } = require('./routes/health');
const { createAuthRoutes } = require('./routes/auth');

// ─── CENTRALIZED CONFIG ──────────────────────────────────────────────────────
let CFG = require('../config/app.config');

// ─── ENV LOADER ──────────────────────────────────────────────────────────────
loadDotEnv(log, __dirname);

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const PORT           = parseInt(process.env.PORT || '3000', 10);
let DATA_FILE        = path.join(__dirname, '..', 'data', 'certificates.json');
let VAPT_DATA_FILE   = path.join(__dirname, '..', 'data', 'vapt_certificates.json');
let TRACK_FILE       = path.join(__dirname, '..', 'data', 'tracking_events.jsonl');
let UPLOADS_DIR      = path.join(__dirname, '..', 'uploads');
let KEYS_FILE        = path.join(__dirname, '..', 'data', '.keys.json');
let DOCS_FILE        = path.join(__dirname, '..', 'data', 'documents.json');
let DOC_ACCESS_FILE  = path.join(__dirname, '..', 'data', 'doc_access_requests.json');
let USERS_FILE       = path.join(__dirname, '..', 'data', 'users.json');
let GROUPS_FILE      = path.join(__dirname, '..', 'data', 'groups.json');
let TENANT_CFG_FILE  = null;

// ─── TENANT ISOLATION (SaaS Phase 1) ────────────────────────────────────────
// When TENANT_ID is set, all tenant data (CST/VAPT JSON, tracking JSONL,
// crypto keys, and uploads) are persisted under:
//   data/<TENANT_ID>/...
//   uploads/<TENANT_ID>/...
function sanitiseTenantId(raw) {
  if (!raw && raw !== '') return null;
  if (typeof raw !== 'string') return null;
  const v = raw.trim();
  if (!v) return null;
  // Allow stable filesystem-friendly IDs: letters, digits, _ and -
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$/.test(v)) return null;
  return v;
}
const TENANT_ID_RAW = process.env.TENANT_ID;
const TENANT_ID = sanitiseTenantId(TENANT_ID_RAW);
if (typeof TENANT_ID_RAW === 'string' && TENANT_ID_RAW.trim() !== '' && !TENANT_ID) {
  log.error('Invalid TENANT_ID. Use 1-48 chars: letters/digits/_/- only, starting with alphanumeric.');
  process.exit(1);
}
if (TENANT_ID) {
  const TENANT_DATA_DIR = path.join(__dirname, '..', 'data', TENANT_ID);
  DATA_FILE      = path.join(TENANT_DATA_DIR, 'certificates.json');
  VAPT_DATA_FILE = path.join(TENANT_DATA_DIR, 'vapt_certificates.json');
  TRACK_FILE     = path.join(TENANT_DATA_DIR, 'tracking_events.jsonl');
  UPLOADS_DIR       = path.join(__dirname, '..', 'uploads', TENANT_ID);
  KEYS_FILE         = path.join(TENANT_DATA_DIR, '.keys.json');
  DOCS_FILE         = path.join(TENANT_DATA_DIR, 'documents.json');
  DOC_ACCESS_FILE   = path.join(TENANT_DATA_DIR, 'doc_access_requests.json');
  USERS_FILE        = path.join(TENANT_DATA_DIR, 'users.json');
  GROUPS_FILE       = path.join(TENANT_DATA_DIR, 'groups.json');
  log.info('Tenant isolation enabled:', TENANT_ID);

  // Optional: tenant-specific branding + email templates + route labels
  // File location:
  //   config/tenants/<TENANT_ID>/app.config.js
  TENANT_CFG_FILE = path.join(__dirname, '..', 'config', 'tenants', TENANT_ID, 'app.config.js');
  if (fs.existsSync(TENANT_CFG_FILE)) {
    try {
      CFG = require(TENANT_CFG_FILE);
      log.info('Tenant config loaded:', TENANT_CFG_FILE);
    } catch (e) {
      log.error('Failed to load tenant config, falling back to default:', e && e.message ? e.message : e);
    }
  }
}

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
  if (!origin) return [];
  // Localhost: allow both http and https for dev convenience
  if (/^https?:\/\/(localhost|127\.0\.0\.1)/.test(origin)) return [origin];
  // Production: HTTPS only — never allow HTTP downgrade
  if (origin.startsWith('https://')) return [origin];
  return []; // Reject plain-HTTP production origins
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
const security = createSecurityService({ keys: KEYS, cfg: CFG });
const metrics = createMetrics();
let _reqSeq = 0;

// ─── ADMIN CREDENTIALS ───────────────────────────────────────────────────────
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

// ─── COGNITO SSO CONFIG ──────────────────────────────────────────────────────
const COGNITO_ENABLED       = !!(process.env.COGNITO_USER_POOL_ID && process.env.COGNITO_CLIENT_ID && process.env.COGNITO_DOMAIN);
const COGNITO_REGION        = process.env.COGNITO_REGION || process.env.AWS_REGION || 'ap-south-1';
const COGNITO_USER_POOL_ID  = process.env.COGNITO_USER_POOL_ID  || '';
const COGNITO_CLIENT_ID     = process.env.COGNITO_CLIENT_ID     || '';
const COGNITO_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET || '';
// COGNITO_DOMAIN = just the hostname, e.g. myapp.auth.ap-south-1.amazoncognito.com
const COGNITO_DOMAIN        = (process.env.COGNITO_DOMAIN || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
// Users in this Cognito group are granted admin access (case-sensitive)
const COGNITO_ADMIN_GROUP   = process.env.COGNITO_ADMIN_GROUP || 'Admins';

if (!ADMIN_USER || !ADMIN_PASS) {
  log.error('ADMIN_USER and ADMIN_PASS must be set in your .env file before starting the server.');
  process.exit(1);
}

const _cfgCheck = validateRuntimeConfig({
  port: PORT,
  adminUser: ADMIN_USER,
  adminPass: ADMIN_PASS,
  cfg: CFG,
});
if (!_cfgCheck.ok) {
  for (const e of _cfgCheck.errors) log.error('Config validation:', e);
  process.exit(1);
}

// ─── PASSWORD HASHING ────────────────────────────────────────────────────────
function hashPassword(password) {
  return security.hashPassword(password);
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
  fs.mkdirSync(path.join(UPLOADS_DIR, 'documents'), { recursive: true });
  loadData();
  loadVaptData();
  loadDocs();
  loadDocAccess();
  loadUsers();
  loadGroups();

  serverReady = true;
  log.info('Runtime initialisation complete.');
}

// ─── JWT-STYLE ADMIN TOKENS ──────────────────────────────────────────────────
const TOKEN_EXPIRY_MS = 8 * 60 * 60 * 1000;

function issueToken(username) {
  return security.issueToken(username);
}

function verifyToken(token) {
  return security.verifyToken(token);
}

// ─── ENCRYPTED + SIGNED PUBLIC CERT URLs ─────────────────────────────────────
function encryptCertToken(certId) {
  return security.encryptCertToken(certId);
}

function decryptCertToken(token) {
  return security.decryptCertToken(token);
}

function signCertUrl(encToken) {
  return security.signCertUrl(encToken);
}

function verifyCertUrlSignature(encToken, sig) {
  return security.verifyCertUrlSignature(encToken, sig);
}

// ─── SERVER-ISSUED DOWNLOAD TOKENS (PDF Gating) ──────────────────────────
// Used to gate access to confidential PDF attachments after a successful
// email verification. The token is short-lived and tied to `certId` + kind.
const DOWNLOAD_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes

function issueDownloadToken(certId, kind /* 'cst' | 'vapt' */) {
  const payload = {
    sub: certId,
    kind,
    iat: Date.now(),
    exp: Date.now() + DOWNLOAD_TOKEN_TTL_MS,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', KEYS.urlMacKey).update(payloadB64).digest('base64url');
  return `${payloadB64}.${sig}`;
}

function verifyDownloadToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;

  const expected = crypto.createHmac('sha256', KEYS.urlMacKey).update(payloadB64).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;

  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (!payload || payload.sub == null || !payload.kind) return null;
    if (payload.kind !== 'cst' && payload.kind !== 'vapt') return null;
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return null;
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function buildCertUrl(certId, baseUrl) {
  return security.buildCertUrl(certId, baseUrl);
}

// ─── RATE LIMITER ─────────────────────────────────────────────────────────────
const rateLimits   = new Map();
const loginLockouts = new Map(); // ip → { failCount, lockedUntil }
const RATE_LIMITS = {
  verify:  { max: 30,  window: 60_000  },
  login:   { max: 5,   window: 300_000 },
  track:   { max: 200, window: 60_000  },
  default: { max: 120, window: 60_000  },
};
const RATE_LIMIT_MAX_ENTRIES = 50_000;
// Progressive lockout: each tier applies when failCount reaches threshold
const LOGIN_LOCKOUT_TIERS = [
  { afterFails: 10, lockMs: 60 * 60_000 },  // 10+ → 1 hour
  { afterFails:  5, lockMs: 15 * 60_000 },  // 5+  → 15 min
  { afterFails:  3, lockMs:  5 * 60_000 },  // 3+  → 5 min
];

function _rlEvictOne(now) {
  // Prefer evicting an already-expired entry; otherwise evict a random one
  for (const [k, v] of rateLimits) {
    if (now > v.resetAt) { rateLimits.delete(k); return; }
  }
  const keys = [...rateLimits.keys()];
  rateLimits.delete(keys[Math.floor(Math.random() * keys.length)]);
}

function checkRateLimit(ip, bucket) {
  const { max, window } = RATE_LIMITS[bucket] || RATE_LIMITS.default;
  const key   = `${bucket}:${ip}`;
  const now   = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || now > entry.resetAt) {
    if (!entry && rateLimits.size >= RATE_LIMIT_MAX_ENTRIES) _rlEvictOne(now);
    rateLimits.set(key, { count: 1, resetAt: now + window });
    return { ok: true, remaining: max - 1 };
  }
  if (entry.count >= max) return { ok: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
  entry.count++;
  return { ok: true, remaining: max - entry.count };
}

function checkLoginLockout(ip) {
  const rec = loginLockouts.get(ip);
  if (!rec || Date.now() >= rec.lockedUntil) return { locked: false };
  return { locked: true, retryAfter: Math.ceil((rec.lockedUntil - Date.now()) / 1000) };
}

function recordLoginFailure(ip) {
  const rec = loginLockouts.get(ip) || { failCount: 0, lockedUntil: 0 };
  rec.failCount++;
  const tier = LOGIN_LOCKOUT_TIERS.find(t => rec.failCount >= t.afterFails);
  if (tier) rec.lockedUntil = Date.now() + tier.lockMs;
  loginLockouts.set(ip, rec);
}

function clearLoginFailures(ip) {
  loginLockouts.delete(ip);
}

const _rlCleanup = setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimits)    if (now > v.resetAt)    rateLimits.delete(k);
  for (const [k, v] of loginLockouts) if (now > v.lockedUntil) loginLockouts.delete(k);
}, 60_000);

// ─── SECURITY HEADERS ────────────────────────────────────────────────────────
const _isHttps = BASE_ORIGIN.startsWith('https://');
const SECURITY_HEADERS = {
  'X-Content-Type-Options':           'nosniff',
  'X-Frame-Options':                  'DENY',
  'X-XSS-Protection':                 '0',       // Disabled — modern browsers use CSP; legacy header causes issues
  'Referrer-Policy':                  'strict-origin-when-cross-origin',
  'Permissions-Policy':               'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy':       'same-origin',
  'Cross-Origin-Resource-Policy':     'same-origin',
  'Cross-Origin-Embedder-Policy':     'require-corp',
  ...(_isHttps ? { 'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload' } : {}),
  'Content-Security-Policy':
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: blob:; " +
    "connect-src 'self'; " +
    "frame-src 'self' blob:; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self';",
};

// API-specific headers: no caching, no content-type sniffing on responses
const API_HEADERS = {
  ...SECURITY_HEADERS,
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  'Pragma':        'no-cache',
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
const cstStore = createJsonStore({
  filePath: DATA_FILE,
  seedData: SEED,
  onError: (err) => log.error('Failed to persist certificate data:', err.message),
  debounceMs: 50,
});
function loadData() {
  _certCache = cstStore.load();
  return _certCache;
}
function saveData(data) {
  _certCache = data;
  cstStore.save(data);
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
const vaptStore = createJsonStore({
  filePath: VAPT_DATA_FILE,
  seedData: VAPT_SEED,
  onError: (err) => log.error('Failed to persist VAPT certificate data:', err.message),
  debounceMs: 50,
});
function loadVaptData() {
  _vaptCache = vaptStore.load();
  return _vaptCache;
}
function saveVaptData(data) {
  _vaptCache = data;
  vaptStore.save(data);
}

// ─── VAPT CERT URL BUILDER ───────────────────────────────────────────────────
function buildVaptCertUrl(certId, baseUrl) {
  return security.buildVaptCertUrl(certId, baseUrl);
}

// ─── DOCUMENTS STORE ─────────────────────────────────────────────────────────
let _docsCache = null;
const docsStore = createJsonStore({
  filePath: DOCS_FILE,
  seedData: {},
  onError: (err) => log.error('Failed to persist documents data:', err.message),
  debounceMs: 50,
});
function loadDocs() { _docsCache = docsStore.load(); return _docsCache; }
function saveDocs(data) { _docsCache = data; docsStore.save(data); }

function normalizeVesselIMO(raw) {
  return String(raw || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 20);
}

function nextSequentialId(records, prefix, width = 4) {
  const nums = Object.keys(records || {})
    .map(k => {
      const m = String(k).match(new RegExp('^' + prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '-(\\d+)$'));
      return m ? parseInt(m[1], 10) : 0;
    })
    .filter(Boolean);
  const next = nums.length ? Math.max(...nums) + 1 : 1;
  return `${prefix}-${String(next).padStart(width, '0')}`;
}

function publicDocRecord(doc) {
  return {
    id: doc.id,
    title: doc.title || doc.fileName || doc.id,
    docType: doc.docType || 'OTHER',
    fileName: doc.fileName || '',
    fileSize: doc.fileSize || 0,
    mimeType: doc.mimeType || 'application/octet-stream',
    description: doc.description || '',
    linkedCertId: doc.linkedCertId || null,
    uploadedAt: doc.uploadedAt || doc.updatedAt || '',
  };
}

function getStoredDocsForVessel(imo) {
  const normalized = normalizeVesselIMO(imo);
  return Object.values(loadDocs())
    .filter(d => normalizeVesselIMO(d.vesselIMO) === normalized)
    .map(publicDocRecord);
}

function attachmentMimeFromName(name) {
  return MIME[path.extname(name || '').toLowerCase()] || 'application/octet-stream';
}

function collectCertAttachmentsForVessel(imo) {
  const normalized = normalizeVesselIMO(imo);
  const atts = [];
  const add = (kind, certId, cert, attachment, index) => {
    if (!attachment || !attachment.url || !attachment.name) return;
    atts.push(publicDocRecord({
      id: `ATT_${kind}_${certId}_${index}`,
      title: attachment.name,
      docType: 'CERT_ATTACHMENT',
      fileName: attachment.name,
      fileSize: attachment.size || 0,
      mimeType: attachment.mimeType || attachment.contentType || attachmentMimeFromName(attachment.name),
      description: `${kind === 'CST' ? 'CST' : 'VAPT'} Certificate ${certId}`,
      linkedCertId: certId,
      uploadedAt: cert.updatedAt || cert.createdAt || '',
    }));
  };

  for (const [certId, cert] of Object.entries(loadData())) {
    if (normalizeVesselIMO(cert.vesselIMO) === normalized && Array.isArray(cert.attachments)) {
      cert.attachments.forEach((a, i) => add('CST', certId, cert, a, i));
    }
  }
  for (const [certId, cert] of Object.entries(loadVaptData())) {
    if (normalizeVesselIMO(cert.vesselIMO) === normalized && Array.isArray(cert.attachments)) {
      cert.attachments.forEach((a, i) => add('VAPT', certId, cert, a, i));
    }
  }
  return atts;
}

function allDocumentLibraryRecords() {
  const docs = Object.values(loadDocs()).map(d => ({
    ...publicDocRecord(d),
    vesselIMO: normalizeVesselIMO(d.vesselIMO),
    vesselName: d.vesselName || '',
    filePath: d.filePath || '',
    isLibraryUpload: true,
  }));

  const addCertAttachments = (kind, certs) => {
    for (const [certId, cert] of Object.entries(certs)) {
      if (!Array.isArray(cert.attachments)) continue;
      cert.attachments.forEach((a, i) => {
        if (!a || !a.url || !a.name) return;
        docs.push({
          ...publicDocRecord({
            id: `ATT_${kind}_${certId}_${i}`,
            title: a.name,
            docType: 'CERT_ATTACHMENT',
            fileName: a.name,
            fileSize: a.size || 0,
            mimeType: a.mimeType || a.contentType || attachmentMimeFromName(a.name),
            description: `${kind === 'CST' ? 'CST' : 'VAPT'} Certificate ${certId}`,
            linkedCertId: certId,
            uploadedAt: cert.updatedAt || cert.createdAt || '',
          }),
          vesselIMO: normalizeVesselIMO(cert.vesselIMO),
          vesselName: cert.vesselName || '',
          isCertificateAttachment: true,
        });
      });
    }
  };
  addCertAttachments('CST', loadData());
  addCertAttachments('VAPT', loadVaptData());
  return docs;
}

function resolveCertificateAttachment(attId) {
  const m = String(attId || '').match(/^ATT_(CST|VAPT)_(.+)_(\d+)$/);
  if (!m) return null;
  const [, kind, certId, idxRaw] = m;
  const idx = Number(idxRaw);
  const data = kind === 'VAPT' ? loadVaptData() : loadData();
  const cert = data[certId];
  const attachment = cert && Array.isArray(cert.attachments) ? cert.attachments[idx] : null;
  if (!attachment || !attachment.url) return null;
  const rel = attachment.url.replace(/^\/uploads\//, '');
  const fp = path.resolve(UPLOADS_DIR, rel);
  if (!fp.startsWith(UPLOADS_DIR + path.sep) && fp !== UPLOADS_DIR) return null;
  return {
    id: attId,
    vesselIMO: normalizeVesselIMO(cert.vesselIMO),
    fileName: attachment.name || path.basename(fp),
    mimeType: attachment.mimeType || attachment.contentType || attachmentMimeFromName(attachment.name || fp),
    filePath: fp,
  };
}

// ─── DOC ACCESS REQUESTS STORE ───────────────────────────────────────────────
let _docAccessCache = null;
const docAccessStore = createJsonStore({
  filePath: DOC_ACCESS_FILE,
  seedData: {},
  onError: (err) => log.error('Failed to persist doc access data:', err.message),
  debounceMs: 50,
});
function loadDocAccess() { _docAccessCache = docAccessStore.load(); return _docAccessCache; }
function saveDocAccess(data) { _docAccessCache = data; docAccessStore.save(data); }

// ─── USERS STORE ─────────────────────────────────────────────────────────────
let _usersCache = null;
const usersStore = createJsonStore({
  filePath: USERS_FILE,
  seedData: {},
  onError: (err) => log.error('Failed to persist users data:', err.message),
  debounceMs: 50,
});
function loadUsers()       { _usersCache = usersStore.load(); return _usersCache; }
function saveUsers(data)   { _usersCache = data; usersStore.save(data); }

// ─── COGNITO SSO — JWKS + TOKEN VERIFICATION ─────────────────────────────────
let _cognitoJwksCache = null;
let _cognitoJwksCacheAt = 0;

function getCognitoJWKS() {
  if (_cognitoJwksCache && Date.now() - _cognitoJwksCacheAt < 3600000) return Promise.resolve(_cognitoJwksCache);
  const issuer = `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}`;
  return new Promise((resolve, reject) => {
    require('https').get(`${issuer}/.well-known/jwks.json`, r => {
      let buf = '';
      r.on('data', c => buf += c);
      r.on('end', () => {
        try {
          _cognitoJwksCache = JSON.parse(buf);
          _cognitoJwksCacheAt = Date.now();
          resolve(_cognitoJwksCache);
        } catch { reject(new Error('Invalid JWKS response')); }
      });
    }).on('error', reject);
  });
}

async function verifyCognitoIdToken(idToken) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT structure');
  const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  const issuer  = `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}`;
  if (payload.iss !== issuer)             throw new Error('Invalid token issuer');
  if (payload.aud !== COGNITO_CLIENT_ID)  throw new Error('Invalid token audience');
  if (Date.now() / 1000 > payload.exp)    throw new Error('Token expired');
  if (header.alg !== 'RS256')             throw new Error('Expected RS256 algorithm');
  const jwks = await getCognitoJWKS();
  const jwk  = (jwks.keys || []).find(k => k.kid === header.kid);
  if (!jwk) throw new Error('Unknown signing key');
  const pubKey   = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(parts[0] + '.' + parts[1]);
  if (!verifier.verify(pubKey, Buffer.from(parts[2], 'base64url'))) throw new Error('Signature invalid');
  return payload;
}

function exchangeCognitoCode(code) {
  const redirectUri = BASE_ORIGIN + '/auth/sso/callback';
  const body = `grant_type=authorization_code&client_id=${encodeURIComponent(COGNITO_CLIENT_ID)}&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
  const authHeader = COGNITO_CLIENT_SECRET
    ? 'Basic ' + Buffer.from(`${COGNITO_CLIENT_ID}:${COGNITO_CLIENT_SECRET}`).toString('base64')
    : null;
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: COGNITO_DOMAIN,
      path: '/oauth2/token',
      method: 'POST',
      headers: Object.assign(
        { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
        authHeader ? { Authorization: authHeader } : {}
      ),
    };
    const req = require('https').request(opts, r => {
      let buf = '';
      r.on('data', c => buf += c);
      r.on('end', () => { try { resolve(JSON.parse(buf)); } catch { reject(new Error('Token parse error')); } });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── GROUPS STORE ─────────────────────────────────────────────────────────────
let _groupsCache = null;
const groupsStore = createJsonStore({
  filePath: GROUPS_FILE,
  seedData: {},
  onError: (err) => log.error('Failed to persist groups data:', err.message),
  debounceMs: 50,
});
function loadGroups()      { _groupsCache = groupsStore.load(); return _groupsCache; }
function saveGroups(data)  { _groupsCache = data; groupsStore.save(data); }

// ─── USER PASSWORD HELPERS (per-user PBKDF2 with random salt) ────────────────
async function hashUserPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt + KEYS.pwdSalt, 100000, 32, 'sha256', (err, derived) => {
      if (err) reject(err);
      else resolve(salt + ':' + derived.toString('hex'));
    });
  });
}
async function verifyUserPassword(password, stored) {
  const [salt, hash] = (stored || '').split(':');
  if (!salt || !hash) return false;
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt + KEYS.pwdSalt, 100000, 32, 'sha256', (err, derived) => {
      if (err) reject(err);
      else {
        const a = Buffer.from(derived.toString('hex'));
        const b = Buffer.from(hash);
        resolve(a.length === b.length && crypto.timingSafeEqual(a, b));
      }
    });
  });
}

// ─── SUPER ADMIN TOKEN ────────────────────────────────────────────────────────
const SUPER_ADMIN_TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
function issueSuperAdminToken() {
  const payload = { kind: 'superadmin', iat: Date.now(), exp: Date.now() + SUPER_ADMIN_TOKEN_TTL_MS };
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
  return b64 + '.' + sig;
}
function verifySuperAdminToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expected = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
  const sBuf = Buffer.from(sig), eBuf = Buffer.from(expected);
  if (sBuf.length !== eBuf.length || !crypto.timingSafeEqual(sBuf, eBuf)) return null;
  try {
    const p = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    if (!p || p.kind !== 'superadmin') return null;
    if (Date.now() > p.exp) return null;
    return p;
  } catch { return null; }
}
function superAdminCheck(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('SuperAdmin ')) return false;
  return verifySuperAdminToken(auth.slice(11)) !== null;
}

// ─── USER SESSION TOKEN (24-hour, for superintendents on public pages) ────────
const USER_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
function issueUserSessionToken(userId) {
  const payload = { kind: 'usersession', sub: userId, iat: Date.now(), exp: Date.now() + USER_SESSION_TTL_MS };
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
  return b64 + '.' + sig;
}
function verifyUserSessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expected = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
  const sBuf = Buffer.from(sig), eBuf = Buffer.from(expected);
  if (sBuf.length !== eBuf.length || !crypto.timingSafeEqual(sBuf, eBuf)) return null;
  try {
    const p = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    if (!p || p.kind !== 'usersession' || !p.sub) return null;
    if (Date.now() > p.exp) return null;
    return p;
  } catch { return null; }
}
// Returns the active user object if the request carries a valid UserSession token, else null
function getUserFromSession(req) {
  const auth  = req.headers['authorization'] || '';
  const token = auth.startsWith('UserSession ') ? auth.slice(12) : '';
  const payload = verifyUserSessionToken(token);
  if (!payload) return null;
  const users = loadUsers();
  const user = users[payload.sub];
  if (!user || !user.active) return null;
  return user;
}
// Returns Set of vessel IMOs accessible by a user (from all their groups)
function getUserVesselIMOs(user) {
  const groups = loadGroups();
  const imoSet = new Set();
  (user.groupIds || []).forEach(gid => {
    const g = groups[gid];
    if (g) (g.vesselIMOs || []).forEach(i => imoSet.add(normalizeVesselIMO(i)));
  });
  return imoSet;
}

// ─── DOC ACCESS TOKEN (vessel-level, 30-day) ─────────────────────────────────
const DOC_ACCESS_TOKEN_TTL_MS = 365 * 24 * 60 * 60 * 1000; // 1-year TTL — permanent grants auto-renew

function issueDocAccessToken(vesselIMO, requestId) {
  const payload = { sub: normalizeVesselIMO(vesselIMO), kind: 'docaccess', reqId: requestId, iat: Date.now(), exp: Date.now() + DOC_ACCESS_TOKEN_TTL_MS };
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}

function verifyDocAccessToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expected = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
  const sBuf = Buffer.from(sig), eBuf = Buffer.from(expected);
  if (sBuf.length !== eBuf.length || !crypto.timingSafeEqual(sBuf, eBuf)) return null;
  try {
    const p = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    if (!p || p.kind !== 'docaccess' || !p.sub) return null;
    if (typeof p.exp !== 'number' || Date.now() > p.exp) return null;
    return p;
  } catch { return null; }
}

// Relaxed variant — verifies HMAC signature but ignores expiry.
// Used only for permanent-grant auto-renewal in /api/docs/check-access.
function verifyDocAccessTokenRelaxed(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expected = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
  const sBuf = Buffer.from(sig), eBuf = Buffer.from(expected);
  if (sBuf.length !== eBuf.length || !crypto.timingSafeEqual(sBuf, eBuf)) return null;
  try {
    const p = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    if (!p || p.kind !== 'docaccess' || !p.sub) return null;
    return p; // No expiry check — for permanent-grant renewal only
  } catch { return null; }
}

// Issue a short-lived claim token so the submitting browser can poll request status without auth.
function issueDocClaimToken(reqId) {
  const b64 = Buffer.from(JSON.stringify({ kind: 'docclaim', reqId, iat: Date.now() })).toString('base64url');
  const sig  = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
  return b64 + '.' + sig;
}
function verifyDocClaimToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  const expected = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
  const sBuf = Buffer.from(sig), eBuf = Buffer.from(expected);
  if (sBuf.length !== eBuf.length || !crypto.timingSafeEqual(sBuf, eBuf)) return null;
  try {
    const p = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    if (!p || p.kind !== 'docclaim' || !p.reqId) return null;
    return p;
  } catch { return null; }
}

// Send document access approval email — no token in body, vessel just returns to the cert page.
async function sendDocAccessEmail(docReq, certPageUrl) {
  if (!SES_ENABLED) return { success: false, error: 'Email not configured' };
  const captain    = docReq.captainName || 'Captain';
  const vesselName = docReq.vesselName  || '';
  const vesselIMO  = docReq.vesselIMO   || '';
  const to         = docReq.emailId;
  const from       = SES_FROM_CST;
  const subject    = `Document Access Approved — ${vesselName || vesselIMO} — ${CFG.brand.companyShort || CFG.brand.name}`;
  const body =
    `Dear Captain ${captain},\n\n` +
    `Your request to access compliance documents for vessel ${vesselName}${vesselIMO ? ' (IMO: ' + vesselIMO + ')' : ''} ` +
    `has been approved by the ${CFG.brand.name} Cyber Security Team.\n\n` +
    `Return to the certificate verification page — your documents will load automatically:\n\n` +
    `${certPageUrl}\n\n` +
    `No token or extra steps are required. Documents will be available on every future visit from this device.\n\n` +
    `If you have any questions, contact us at ${CFG.contact.cstEmail}.\n\n` +
    `Regards,\n${CFG.brand.cstTeam}\n${CFG.contact.cstEmail}`;
  const raw = buildRawEmail({ from, to, subject, body, replyTo: from });
  return sesSendRaw(raw, from, [to]);
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

  const brandName  = CFG.brand.name || 'Synergy Marine Group';
  const division   = (CFG.brand.division || 'Cyber Security & Compliance Division').replace(brandName, '').replace(/^\s*·?\s*/, '');
  const logoImgUrl = BASE_ORIGIN + '/images/SYN.png';
  const aftImgUrl  = BASE_ORIGIN + '/images/AFT.png';
  const year       = new Date().getFullYear();

  const certNote = hasImage
    ? `<tr><td style="padding:0 36px 4px">
        <p style="margin:0;font-size:12px;color:#6a7a8a;text-align:center;border-top:1px solid #e8edf4;padding-top:14px">
          &#128206; Your certificate image is attached to this email.
        </p>
      </td></tr>`
    : '';

  const htmlBody = `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="x-apple-disable-message-reformatting">
  <title>${esc(subject)}</title>
  <!--[if mso]><noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript><![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#EEF2F7;font-family:Arial,Helvetica,sans-serif;-webkit-font-smoothing:antialiased">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#EEF2F7;padding:32px 16px">
  <tr><td align="center">
    <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 4px 28px rgba(0,0,0,0.12)">

      <!-- ── HEADER ── -->
      <tr>
        <td style="background:linear-gradient(135deg,#0A1628 0%,#1A3050 100%);padding:26px 32px 22px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="width:52px;vertical-align:middle;padding-right:14px">
                <img src="${logoImgUrl}" width="48" height="48"
                  alt="${esc(brandName)} Logo"
                  style="display:block;border-radius:50%;border:2px solid rgba(212,168,67,0.45);background:rgba(212,168,67,0.08)">
              </td>
              <td style="vertical-align:middle;padding-right:10px">
                <p style="margin:0;font-size:7px;letter-spacing:.22em;text-transform:uppercase;color:#8892B0;font-weight:700">OFFICIAL CORRESPONDENCE</p>
                <p style="margin:3px 0 1px;font-size:15px;font-weight:800;color:#D4A843;letter-spacing:.04em">${esc(brandName)}</p>
                <p style="margin:0;font-size:8px;color:#8892B0;letter-spacing:.1em;text-transform:uppercase">${esc(division)}</p>
              </td>
              <td style="width:44px;vertical-align:middle;text-align:right">
                <img src="${aftImgUrl}" width="38" height="38"
                  alt="AFT"
                  style="display:block;border-radius:50%;border:1px solid rgba(255,255,255,0.15);margin-left:auto">
              </td>
            </tr>
          </table>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:18px;border-top:1px solid rgba(255,255,255,0.08);padding-top:16px">
            <tr>
              <td>
                <p style="margin:0;font-size:18px;font-weight:800;color:#ffffff;letter-spacing:.01em;line-height:1.25">${esc(subject.replace(/^Subject:\s*/i,'').replace(/\s*—\s*Synergy.*$/,'').replace(/^Your\s+(CST|VAPT)\s+Certificate\s*[—-]\s*/i,''))}</p>
                <p style="margin:6px 0 0;font-size:9px;color:#8892B0;letter-spacing:.16em;text-transform:uppercase">Certificate Notification &nbsp;·&nbsp; Do not reply to this email</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- ── BODY CONTENT ── -->
      <tr>
        <td style="padding:30px 36px 22px">
          ${htmlContent}
        </td>
      </tr>

      ${certNote}

      <!-- ── DIVIDER ── -->
      <tr><td style="padding:0 36px"><hr style="border:none;border-top:1px solid #E8EDF4;margin:0"></td></tr>

      <!-- ── FOOTER ── -->
      <tr>
        <td style="padding:20px 36px 28px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="text-align:center;padding-bottom:14px">
                <img src="${logoImgUrl}" width="32" height="32"
                  alt="${esc(brandName)}"
                  style="display:inline-block;border-radius:50%;border:1px solid rgba(181,134,10,0.3);margin-bottom:10px">
                <p style="margin:0;font-size:11px;color:#8892B0;line-height:1.7">
                  This is an automated message from the <strong style="color:#5a6a7a">${esc(brandName)}</strong><br>
                  Cyber Security Certificate Registry. Please do not reply to this email.
                </p>
                <p style="margin:10px 0 0;font-size:10px;color:#aab4c4">
                  &copy; ${year} ${esc(brandName)} &nbsp;&middot;&nbsp; ${esc(division)}<br>
                  <a href="${BASE_ORIGIN}" style="color:#aab4c4;text-decoration:none">${BASE_ORIGIN}</a>
                </p>
                <p style="margin:8px 0 0;font-size:9px;color:#c4ccd8;letter-spacing:.06em;text-transform:uppercase">
                  Data Classification: RESTRICTED &nbsp;·&nbsp; Maritime Personnel &amp; Vessel Security Records
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
${trackingPixelUrl
  ? `<img src="${trackingPixelUrl}" width="1" height="1" alt="" style="display:none!important;width:1px!important;height:1px!important;min-width:1px;min-height:1px;overflow:hidden;mso-hide:all">`
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
const ALLOWED_ATTACHMENT_EXTS = ['.pdf', '.jpg', '.jpeg', '.png', '.webp', '.doc', '.docx', '.xls', '.xlsx'];

function saveAttachmentFile(fileObj, prefix) {
  const origExt = path.extname(fileObj.filename).toLowerCase();
  const ext     = ALLOWED_ATTACHMENT_EXTS.includes(origExt) ? origExt : '.pdf';
  const fname   = prefix + '_' + crypto.randomBytes(12).toString('hex') + ext;
  fs.writeFileSync(path.join(UPLOADS_DIR, fname), fileObj.data);
  return { name: fileObj.filename || fname, url: '/uploads/' + fname, size: fileObj.data.length };
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
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
};

// ─── INPUT SANITISATION ───────────────────────────────────────────────────────
function sanitiseCertId(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const decoded = decodeURIComponent(raw).trim();
  if (!/^[A-Za-z0-9\-_]{1,64}$/.test(decoded)) return null;
  return decoded.toUpperCase();
}

function sanitiseCertBody(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const LIMITS = {
    recipientName: 200, vesselName: 200, vesselIMO: 20,
    chiefEngineer: 200, trainingTitle: 300, organizer: 200,
    notes: 1000, recipientEmail: 255, issuerEmail: 255,
    complianceQuarter: 10, trainingMode: 20, status: 20,
    certificateNumber: 60, assessmentDate: 30, validUntil: 30,
    complianceDate: 30, verifiedBy: 200, verifierTitle: 200,
    assessingOrg: 200, riskLevel: 50,
  };
  const CTRL = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
  const out = { ...obj };
  for (const [field, maxLen] of Object.entries(LIMITS)) {
    if (out[field] != null) {
      out[field] = String(out[field]).replace(CTRL, '').trim().slice(0, maxLen);
    }
  }
  if (out.recipientEmail && !validation.isValidEmail(out.recipientEmail)) out.recipientEmail = '';
  if (out.issuerEmail    && !validation.isValidEmail(out.issuerEmail))    out.issuerEmail    = '';
  return out;
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
    ...API_HEADERS,
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
    : (ext === '.js' || ext === '.css')
      ? 'no-cache, must-revalidate'
      : (ext === '.woff2' || ext === '.woff')
        ? 'public, max-age=604800'
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
      if (totalSize > 20 * 1024 * 1024) { req.destroy(); return reject(new Error('File is too large to upload. Maximum size is 20 MB.')); }
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
const healthRoute = createHealthRoute({
  sendJSON,
  corsHeadersForOrigin: getCorsHeaders,
  getCstCerts: loadData,
  getVaptCerts: loadVaptData,
  cfg: CFG,
  sesEnabled: SES_ENABLED,
  serverStartTime: SERVER_START_TIME,
  serverReadyRef: () => serverReady,
  shuttingDownRef: () => isShuttingDown,
  metricsSnapshot: () => metrics.snapshot(),
});
const authRoutes = createAuthRoutes({
  sendJSON,
  getBody,
  authCheck,
  checkRateLimit,
  checkLoginLockout,
  recordLoginFailure,
  clearLoginFailures,
  hashPassword,
  issueToken,
  getAdminUser: () => ADMIN_USER,
  getAdminPassHash: () => ADMIN_PASS_HASH,
  serverReadyRef: () => serverReady,
});

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

  if (healthRoute(req, res, route, method, origin)) return;
  if (await authRoutes.handleLogin(req, res, method, route, ip, corsH)) return;
  if (authRoutes.handleVerify(req, res, method, route, corsH)) return;

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
    const lockout = checkLoginLockout(ip);
    if (lockout.locked)
      return sendJSON(res, 429, { error: 'Too many failed login attempts. Try again later.' },
        { 'Retry-After': String(lockout.retryAfter), ...corsH });
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
      recordLoginFailure(ip);
      await new Promise(r => setTimeout(r, 200 + Math.random() * 200));
      return sendJSON(res, 401, { error: 'Invalid credentials' }, corsH);
    }
    clearLoginFailures(ip);
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
    const rl = checkRateLimit(ip, 'track');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, { 'Retry-After': String(rl.retryAfter), ...corsH });
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
        cert.attachments = extractAttachments(fields, files, 'cert');
      } else {
        cert = JSON.parse(await getBody(req));
        if (!Array.isArray(cert.attachments)) cert.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    const certId = sanitiseCertId(cert.id);
    if (!certId) return sendJSON(res, 400, { error: 'Invalid or missing certificate ID' }, corsH);
    cert.id = certId;
    cert = sanitiseCertBody(cert);
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
        updates.attachments = extractAttachments(fields, files, 'cert', data[certId].attachments || []);
      } else {
        updates = JSON.parse(await getBody(req));
        if (updates.attachments !== undefined && !Array.isArray(updates.attachments)) updates.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    updates = sanitiseCertBody(updates);
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
    const force = Boolean(body && body.force === true);

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

    if ((cert.emailStatus || '').toUpperCase() === 'SENT' && !force) {
      return sendJSON(res, 409, {
        error: 'Email has already been sent for this certificate.',
        emailStatus: 'SENT',
        emailSentAt: cert.emailSentAt || null,
      }, corsH);
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

    log.error('CST send-email failed:', result.error);
    return sendJSON(res, 500, {
      error: 'Email could not be delivered. Please verify the recipient address and try again.',
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
  // Accepts { email } in JSON body.
  // Returns { ok: true, downloadToken } only when email matches the stored recipientEmail
  // (case-insensitive, timing-safe). Never reveals the email.
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
    return sendJSON(res, 200, { ok: true, downloadToken: issueDownloadToken(certId, 'cst') }, corsH);
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
    return sendJSON(res, 200, { ok: true, downloadToken: issueDownloadToken(certId, 'vapt') }, corsH);
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
        cert.attachments = extractAttachments(fields, files, 'vapt');
      } else {
        cert = JSON.parse(await getBody(req));
        if (!Array.isArray(cert.attachments)) cert.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    const certId = sanitiseCertId(cert.id);
    if (!certId) return sendJSON(res, 400, { error: 'Invalid or missing certificate ID' }, corsH);
    cert.id = certId;
    cert = sanitiseCertBody(cert);
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
      cert = sanitiseCertBody(cert);
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
        updates.attachments = extractAttachments(fields, files, 'vapt', data[certId].attachments || []);
      } else {
        updates = JSON.parse(await getBody(req));
        if (updates.attachments !== undefined && !Array.isArray(updates.attachments)) updates.attachments = [];
      }
    } catch { return sendJSON(res, 400, { error: 'Invalid request body' }, corsH); }
    updates = sanitiseCertBody(updates);
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

    const force = body && body.force === true;

    // Allow the dashboard to supply an updated recipientEmail in the request body
    const overrideEmail = (body && typeof body.recipientEmail === 'string' && body.recipientEmail.trim())
      ? body.recipientEmail.trim().toLowerCase()
      : null;
    if (overrideEmail) {
      cert.recipientEmail = overrideEmail;
      data[certId] = cert;
      saveVaptData(data);
    }

    if ((cert.emailStatus || '').toUpperCase() === 'SENT' && !force) {
      return sendJSON(res, 409, {
        error: 'Email has already been sent for this certificate.',
        emailStatus: 'SENT',
        emailSentAt: cert.emailSentAt || null,
      }, corsH);
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

    log.error('VAPT send-email failed:', result.error);
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

  // ════════════════════════════════════════════════════════════════════════════
  //  RELEVANT DOCUMENTS — vessel-level documents with access-token gating
  // ════════════════════════════════════════════════════════════════════════════

  // ── GET /api/docs ── (admin — list all documents)
  if (route === '/docs' && method === 'GET') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    return sendJSON(res, 200, allDocumentLibraryRecords(), corsH);
  }

  // ── POST /api/docs/upload ── (admin — upload a document for a vessel)
  if (route === '/docs/upload' && method === 'POST') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied. Please log in to continue.' }, corsH);
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('multipart/form-data')) return sendJSON(res, 400, { error: 'multipart/form-data required' }, corsH);
    let fields, files;
    try { ({ fields, files } = await parseMultipart(req)); } catch (e) { return sendJSON(res, 400, { error: e.message || 'Upload failed' }, corsH); }
    const vesselIMO  = normalizeVesselIMO(fields.vesselIMO);
    const vesselName = (fields.vesselName || '').trim().slice(0, 120);
    const docType    = ['TRAINING_REPORT','DRILL_REPORT','AUDIT_REPORT','OTHER'].includes((fields.docType||'').toUpperCase()) ? fields.docType.toUpperCase() : 'OTHER';
    const title      = (fields.title || '').trim().slice(0, 200) || 'Untitled Document';
    const description = (fields.description || '').trim().slice(0, 500);
    const linkedCertId = (fields.linkedCertId || '').trim().slice(0, 60);
    const fileObj = files.file;
    if (!vesselIMO) return sendJSON(res, 400, { error: 'Vessel IMO is required' }, corsH);
    if (!fileObj || !fileObj.data || !fileObj.data.length) return sendJSON(res, 400, { error: 'No file provided' }, corsH);
    const ALLOWED_MIME = ['application/pdf','image/jpeg','image/png','image/gif','image/webp','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
    if (!ALLOWED_MIME.includes(fileObj.contentType)) return sendJSON(res, 400, { error: 'File type not allowed' }, corsH);
    const safeOrig = path.basename(fileObj.filename || 'upload').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80);
    const uid = crypto.randomBytes(8).toString('hex');
    const fname = `DOC-${vesselIMO}-${uid}-${safeOrig}`;
    const docsUploadDir = path.join(UPLOADS_DIR, 'documents');
    fs.mkdirSync(docsUploadDir, { recursive: true });
    const fpath = path.join(docsUploadDir, fname);
    fs.writeFileSync(fpath, fileObj.data);
    const docs = loadDocs();
    const docId = nextSequentialId(docs, 'DOC');
    const doc = {
      id: docId, vesselIMO, vesselName, docType, title, description,
      linkedCertId: linkedCertId || null,
      fileName: safeOrig,
      filePath: `/uploads/documents/${fname}`,
      fileSize: fileObj.data.length,
      mimeType: fileObj.contentType,
      uploadedAt: new Date().toISOString(),
    };
    docs[docId] = doc;
    saveDocs(docs);
    return sendJSON(res, 201, doc, corsH);
  }

  // ── PUT /api/docs/:id ── (admin — update doc metadata)
  if (route.match(/^\/docs\/DOC-\d+$/) && method === 'PUT') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const docId = route.replace('/docs/', '');
    const docs = loadDocs();
    if (!docs[docId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    let updates;
    try { updates = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const allowed = ['title','description','docType','vesselName','linkedCertId'];
    for (const k of allowed) {
      if (updates[k] !== undefined) docs[docId][k] = String(updates[k]).trim().slice(0, 500);
    }
    docs[docId].updatedAt = new Date().toISOString();
    saveDocs(docs);
    return sendJSON(res, 200, docs[docId], corsH);
  }

  // ── DELETE /api/docs/:id ── (admin — delete document + file)
  if (route.match(/^\/docs\/DOC-\d+$/) && method === 'DELETE') {
    if (!authCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const docId = route.replace('/docs/', '');
    const docs = loadDocs();
    if (!docs[docId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    const fp = docs[docId].filePath ? path.join(UPLOADS_DIR, 'documents', path.basename(docs[docId].filePath)) : null;
    if (fp && fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch { /* ignore */ }
    delete docs[docId];
    saveDocs(docs);
    return sendJSON(res, 200, { ok: true }, corsH);
  }

  // ── GET /api/docs/by-vessel/:imo ── (vessel — list docs; accepts DocAccess token or UserSession)
  if (route.match(/^\/docs\/by-vessel\/[A-Z0-9]{1,20}$/) && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, corsH);
    const imo = normalizeVesselIMO(route.replace('/docs/by-vessel/', ''));
    const authHdr = req.headers['authorization'] || '';

    // Path A: UserSession (superintendent)
    const sessUser = getUserFromSession(req);
    if (sessUser) {
      const imoSet = getUserVesselIMOs(sessUser);
      if (!imoSet.has(imo)) return sendJSON(res, 403, { error: 'Access denied. Vessel not in your group.' }, corsH);
      return sendJSON(res, 200, [...getStoredDocsForVessel(imo), ...collectCertAttachmentsForVessel(imo)], corsH);
    }

    // Path B: DocAccess token (captain / vessel user)
    const token = authHdr.startsWith('DocAccess ') ? authHdr.slice(10) : (parsed.searchParams.get('docToken') || '');
    const payload = verifyDocAccessToken(token);
    if (!payload || payload.sub !== imo) return sendJSON(res, 403, { error: 'Access denied. Valid document access token required.' }, corsH);
    // Verify the grant hasn't been revoked
    if (payload.reqId) {
      const ac = loadDocAccess();
      const gr = ac[payload.reqId];
      if (!gr || !gr.permanentGrant || gr.status !== 'APPROVED') {
        return sendJSON(res, 403, { error: 'Access revoked.' }, corsH);
      }
    }
    return sendJSON(res, 200, [...getStoredDocsForVessel(imo), ...collectCertAttachmentsForVessel(imo)], corsH);
  }

  // ── GET /api/docs/download/:id ── (vessel — download; accepts DocAccess token, UserSession, or admin)
  if (route.match(/^\/docs\/download\/(?:DOC-\d+|ATT_(?:CST|VAPT)_.+_\d+)$/) && method === 'GET') {
    const rl = checkRateLimit(ip, 'default');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests.' }, corsH);
    const docId = route.replace('/docs/download/', '');
    const docs = loadDocs();
    const certAttachment = resolveCertificateAttachment(docId);
    const doc = docs[docId] || certAttachment;
    if (!doc) return sendJSON(res, 404, { error: 'Document not found' }, corsH);
    const authHdr = req.headers['authorization'] || '';

    let accessGranted = false;
    // Admin direct access
    if (authCheck(req) || superAdminCheck(req)) { accessGranted = true; }
    // Superintendent session (also via query param for <a> download links)
    if (!accessGranted) {
      const qSession = parsed.searchParams.get('userSession') || '';
      const sessToken = authHdr.startsWith('UserSession ') ? authHdr.slice(12) : qSession;
      const sessPay = verifyUserSessionToken(sessToken);
      if (sessPay) {
        const users = loadUsers();
        const u = users[sessPay.sub];
        if (u && u.active) {
          const imoSet = getUserVesselIMOs(u);
          if (imoSet.has(normalizeVesselIMO(doc.vesselIMO))) accessGranted = true;
        }
      }
    }
    // DocAccess token
    if (!accessGranted) {
      const token = authHdr.startsWith('DocAccess ') ? authHdr.slice(10) : (parsed.searchParams.get('docToken') || '');
      const payload = verifyDocAccessToken(token);
      if (payload && payload.sub === normalizeVesselIMO(doc.vesselIMO)) {
        // Verify not revoked
        let grantOk = true;
        if (payload.reqId) {
          const ac = loadDocAccess();
          const gr = ac[payload.reqId];
          if (!gr || !gr.permanentGrant || gr.status !== 'APPROVED') grantOk = false;
        }
        if (grantOk) accessGranted = true;
      }
    }
    if (!accessGranted) return sendJSON(res, 403, { error: 'Access denied.' }, corsH);
    const fp = certAttachment
      ? certAttachment.filePath
      : path.resolve(UPLOADS_DIR, 'documents', path.basename(doc.filePath || ''));
    const allowedRoot = certAttachment ? UPLOADS_DIR : path.join(UPLOADS_DIR, 'documents');
    if ((!fp.startsWith(allowedRoot + path.sep) && fp !== allowedRoot) || !fs.existsSync(fp)) return sendJSON(res, 404, { error: 'File not found' }, corsH);
    const data = fs.readFileSync(fp);
    const mime = doc.mimeType || 'application/octet-stream';
    const isViewable = mime === 'application/pdf' || mime.startsWith('image/');
    const disposition = isViewable
      ? `inline; filename="${doc.fileName.replace(/"/g, '_')}"`
      : `attachment; filename="${doc.fileName.replace(/"/g, '_')}"`;
    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Disposition': disposition,
      'Content-Length': data.length,
      'Cache-Control': 'private, no-store',
      ...SECURITY_HEADERS,
    });
    return res.end(data);
  }

  // ── POST /api/docs/request-access ── (public — vessel requests document access)
  if (route === '/docs/request-access' && method === 'POST') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests. Try again later.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req, 5000)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const captainName = (body.captainName || body.vesselName || '').trim().slice(0, 120); // captain's name
    const vesselName  = (body.vesselName  || '').trim().slice(0, 120);                    // vessel name from cert
    const vesselIMO   = normalizeVesselIMO(body.vesselIMO);
    const emailId     = (body.emailId     || '').trim().toLowerCase().slice(0, 200);
    if (!emailId) return sendJSON(res, 400, { error: 'emailId is required' }, corsH);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailId)) return sendJSON(res, 400, { error: 'Invalid email address' }, corsH);
    const access = loadDocAccess();
    // If already permanently approved — return a fresh claim token so the browser can auto-retrieve access
    const approved = Object.values(access).find(r => r.emailId === emailId && r.vesselIMO === vesselIMO && r.permanentGrant);
    if (approved) {
      const claimToken = issueDocClaimToken(approved.id);
      return sendJSON(res, 200, { ok: true, requestId: approved.id, claimToken, alreadyApproved: true }, corsH);
    }
    // If already pending — return existing reqId + fresh claim token
    const dup = Object.values(access).find(r => r.emailId === emailId && r.vesselIMO === vesselIMO && r.status === 'PENDING');
    if (dup) {
      const claimToken = issueDocClaimToken(dup.id);
      return sendJSON(res, 200, { ok: true, requestId: dup.id, claimToken, alreadyPending: true }, corsH);
    }
    const reqId = nextSequentialId(access, 'REQ');
    const req_ = { id: reqId, captainName, vesselName, vesselIMO, emailId, requestedAt: new Date().toISOString(), status: 'PENDING', permanentGrant: false, accessToken: null, tokenExpiry: null, approvedAt: null, notes: '' };
    access[reqId] = req_;
    saveDocAccess(access);
    const claimToken = issueDocClaimToken(reqId);
    return sendJSON(res, 201, { ok: true, requestId: reqId, claimToken, message: 'Access request submitted.' }, corsH);
  }

  // ── GET /api/docs/access-requests ── (admin — list all access requests)
  if (route === '/docs/access-requests' && method === 'GET') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const access = loadDocAccess();
    return sendJSON(res, 200, Object.values(access).sort((a, b) => (b.requestedAt || '').localeCompare(a.requestedAt || '')), corsH);
  }

  // ── PUT /api/docs/access-requests/:id ── (admin — approve or deny)
  if (route.match(/^\/docs\/access-requests\/REQ-\d+$/) && method === 'PUT') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const reqId = route.replace('/docs/access-requests/', '');
    const access = loadDocAccess();
    if (!access[reqId]) return sendJSON(res, 404, { error: 'Request not found' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const action = (body.status || '').toUpperCase();
    if (!['APPROVED', 'DENIED'].includes(action)) return sendJSON(res, 400, { error: 'status must be APPROVED or DENIED' }, corsH);
    access[reqId].status = action;
    access[reqId].notes  = (body.notes || '').trim().slice(0, 300);
    if (action === 'APPROVED') {
      const token = issueDocAccessToken(access[reqId].vesselIMO, reqId);
      access[reqId].accessToken    = token;
      access[reqId].tokenExpiry    = new Date(Date.now() + DOC_ACCESS_TOKEN_TTL_MS).toISOString();
      access[reqId].approvedAt     = new Date().toISOString();
      access[reqId].permanentGrant = true; // One-time approval — auto-renews forever
      saveDocAccess(access);
      // Auto-send approval email — vessel just returns to the cert page, no token link needed
      const certPageUrl = BASE_ORIGIN + (CFG.routes.cst || '/CST') + '/';
      let emailSent = false;
      try {
        const mailResult = await sendDocAccessEmail(access[reqId], certPageUrl);
        emailSent = mailResult.success;
        if (!mailResult.success) log.warn('Doc access email failed:', mailResult.error);
      } catch (e) { log.warn('Doc access email error:', e.message); }
      access[reqId].emailSent   = emailSent;
      access[reqId].emailSentAt = emailSent ? new Date().toISOString() : null;
      saveDocAccess(access);
      return sendJSON(res, 200, { ...access[reqId], emailSent }, corsH);
    } else {
      access[reqId].accessToken    = null;
      access[reqId].tokenExpiry    = null;
      access[reqId].permanentGrant = false;
      saveDocAccess(access);
      return sendJSON(res, 200, access[reqId], corsH);
    }
  }

  // ── DELETE /api/docs/access-requests/:id ── (admin — remove request)
  if (route.match(/^\/docs\/access-requests\/REQ-\d+$/) && method === 'DELETE') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const reqId = route.replace('/docs/access-requests/', '');
    const access = loadDocAccess();
    if (!access[reqId]) return sendJSON(res, 404, { error: 'Not found' }, corsH);
    delete access[reqId];
    saveDocAccess(access);
    return sendJSON(res, 200, { ok: true }, corsH);
  }

  // ── GET /api/docs/check-access ── (public — verify token; auto-renews permanent grants)
  if (route === '/docs/check-access' && method === 'GET') {
    const token = parsed.searchParams.get('token') || '';
    const imo   = (parsed.searchParams.get('imo') || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    // Fast path — token still valid
    const payload = verifyDocAccessToken(token);
    if (payload && (!imo || payload.sub === imo)) {
      // Verify the grant hasn't been revoked since this token was issued
      if (payload.reqId) {
        const ac = loadDocAccess();
        const gr = ac[payload.reqId];
        if (!gr || !gr.permanentGrant || gr.status !== 'APPROVED') {
          return sendJSON(res, 200, { valid: false }, corsH);
        }
      }
      return sendJSON(res, 200, { valid: true, vesselIMO: payload.sub, exp: payload.exp }, corsH);
    }
    // Slow path — token expired or missing; check for permanent grant and auto-renew
    if (token) {
      const relaxed = verifyDocAccessTokenRelaxed(token);
      if (relaxed && relaxed.reqId && (!imo || relaxed.sub === imo)) {
        const access = loadDocAccess();
        const grant  = access[relaxed.reqId];
        if (grant && grant.permanentGrant && grant.status === 'APPROVED' && grant.vesselIMO === relaxed.sub) {
          const newToken = issueDocAccessToken(grant.vesselIMO, relaxed.reqId);
          grant.accessToken    = newToken;
          grant.tokenExpiry    = new Date(Date.now() + DOC_ACCESS_TOKEN_TTL_MS).toISOString();
          grant.lastRenewedAt  = new Date().toISOString();
          saveDocAccess(access);
          return sendJSON(res, 200, { valid: true, vesselIMO: grant.vesselIMO, newToken, renewed: true }, corsH);
        }
      }
    }
    return sendJSON(res, 200, { valid: false }, corsH);
  }

  // ── GET /api/docs/temp-link/:id ── (admin — generates 24-hour signed URL; no auth needed to open it)
  if (route.match(/^\/docs\/temp-link\/(?:DOC-\d+|ATT_(?:CST|VAPT)_.+_\d+)$/) && method === 'GET') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Unauthorized' }, corsH);
    const docId = route.replace('/docs/temp-link/', '');
    const docs = loadDocs();
    const certAttachment = resolveCertificateAttachment(docId);
    const doc = docs[docId] || certAttachment;
    if (!doc) return sendJSON(res, 404, { error: 'Document not found' }, corsH);
    const payload = { id: docId, exp: Date.now() + 24 * 60 * 60 * 1000 };
    const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
    const token = `${b64}.${sig}`;
    const url = `${BASE_ORIGIN}/api/docs/open/${encodeURIComponent(token)}`;
    return sendJSON(res, 200, { url, fileName: doc.fileName, title: doc.title || doc.fileName }, corsH);
  }

  // ── GET /api/docs/open/:token ── (public — serves document via signed temp link; no login required)
  if (route.startsWith('/docs/open/') && method === 'GET') {
    const rl = checkRateLimit(ip, 'default');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests.' }, corsH);
    let rawToken;
    try { rawToken = decodeURIComponent(route.replace('/docs/open/', '')); } catch { return sendJSON(res, 400, { error: 'Bad token encoding' }, corsH); }
    const parts = rawToken.split('.');
    if (parts.length !== 2) return sendJSON(res, 400, { error: 'Invalid token format' }, corsH);
    const [b64, sig] = parts;
    const expected = crypto.createHmac('sha256', KEYS.urlMacKey).update(b64).digest('base64url');
    const sigBuf = Buffer.from(sig, 'base64url');
    const expBuf = Buffer.from(expected, 'base64url');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return sendJSON(res, 403, { error: 'Invalid or tampered link' }, corsH);
    let payload;
    try { payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8')); } catch { return sendJSON(res, 400, { error: 'Malformed token' }, corsH); }
    if (!payload || !payload.id || !payload.exp || Date.now() > payload.exp) return sendJSON(res, 403, { error: 'Link has expired. Ask your admin to generate a new one.' }, corsH);
    const docs = loadDocs();
    const certAttachment = resolveCertificateAttachment(payload.id);
    const doc = docs[payload.id] || certAttachment;
    if (!doc) return sendJSON(res, 404, { error: 'Document not found' }, corsH);
    const fp = certAttachment
      ? certAttachment.filePath
      : path.resolve(UPLOADS_DIR, 'documents', path.basename(doc.filePath || ''));
    const allowedRoot = certAttachment ? UPLOADS_DIR : path.join(UPLOADS_DIR, 'documents');
    if ((!fp.startsWith(allowedRoot + path.sep) && fp !== allowedRoot) || !fs.existsSync(fp)) return sendJSON(res, 404, { error: 'File not found on disk' }, corsH);
    const data = fs.readFileSync(fp);
    const mime = doc.mimeType || 'application/octet-stream';
    const isViewable = mime === 'application/pdf' || mime.startsWith('image/');
    const disp = isViewable ? `inline; filename="${doc.fileName.replace(/"/g,'_')}"` : `attachment; filename="${doc.fileName.replace(/"/g,'_')}"`;
    res.writeHead(200, { 'Content-Type': mime, 'Content-Disposition': disp, 'Content-Length': data.length, 'Cache-Control': 'private, max-age=3600', ...SECURITY_HEADERS });
    return res.end(data);
  }

  // ── GET /api/docs/request-status ── (public — vessel polls approval via claim token; no auth needed)
  if (route === '/docs/request-status' && method === 'GET') {
    const rl = checkRateLimit(ip, 'verify');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many requests.' }, corsH);
    const reqId      = (parsed.searchParams.get('reqId')      || '').trim();
    const claimToken = (parsed.searchParams.get('claimToken') || '').trim();
    const imo        = (parsed.searchParams.get('imo')        || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const claim = verifyDocClaimToken(claimToken);
    if (!claim || claim.reqId !== reqId) return sendJSON(res, 403, { error: 'Invalid claim' }, corsH);
    const access = loadDocAccess();
    const req_   = access[reqId];
    if (!req_ || (imo && req_.vesselIMO !== imo)) return sendJSON(res, 200, { status: 'NOT_FOUND' }, corsH);
    if (req_.status === 'APPROVED' && req_.permanentGrant) {
      const valid = req_.accessToken && verifyDocAccessToken(req_.accessToken);
      const activeToken = valid ? req_.accessToken : (() => {
        const t = issueDocAccessToken(req_.vesselIMO, reqId);
        req_.accessToken   = t;
        req_.tokenExpiry   = new Date(Date.now() + DOC_ACCESS_TOKEN_TTL_MS).toISOString();
        req_.lastRenewedAt = new Date().toISOString();
        saveDocAccess(access);
        return t;
      })();
      return sendJSON(res, 200, { status: 'APPROVED', accessToken: activeToken, vesselIMO: req_.vesselIMO }, corsH);
    }
    return sendJSON(res, 200, { status: req_.status }, corsH);
  }

  // ── POST /api/superadmin/login ── (super admin login — separate from regular admin)
  if (route === '/superadmin/login' && method === 'POST') {
    const SUPER_ADMIN_PASS = process.env.SUPER_ADMIN_PASS;
    if (!SUPER_ADMIN_PASS) return sendJSON(res, 503, { error: 'Super admin not configured on this server.' }, corsH);
    const rl = checkRateLimit(ip, 'login');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many attempts.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const entered = (body.password || '').trim();
    const hEntered  = crypto.createHmac('sha256', KEYS.urlMacKey).update(entered).digest('hex');
    const hExpected = crypto.createHmac('sha256', KEYS.urlMacKey).update(SUPER_ADMIN_PASS).digest('hex');
    const eA = Buffer.from(hEntered), eB = Buffer.from(hExpected);
    const match = eA.length === eB.length && crypto.timingSafeEqual(eA, eB);
    if (!match) { await new Promise(r => setTimeout(r, 200 + Math.random() * 200)); return sendJSON(res, 401, { error: 'Invalid credentials.' }, corsH); }
    return sendJSON(res, 200, { token: issueSuperAdminToken() }, corsH);
  }

  // ── GET /api/superadmin/verify ── (check super admin token)
  if (route === '/superadmin/verify' && method === 'GET') {
    if (!superAdminCheck(req)) return sendJSON(res, 401, { error: 'Invalid or expired super admin token.' }, corsH);
    return sendJSON(res, 200, { ok: true }, corsH);
  }

  // ── POST /api/auth/user/login ── (superintendent public login)
  if (route === '/auth/user/login' && method === 'POST') {
    const rl = checkRateLimit(ip, 'login');
    if (!rl.ok) return sendJSON(res, 429, { error: 'Too many attempts.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const email    = (body.email    || '').trim().toLowerCase();
    const password = (body.password || '').trim();
    if (!email || !password) return sendJSON(res, 400, { error: 'Email and password are required.' }, corsH);
    const users = loadUsers();
    const user = Object.values(users).find(u => u.email.toLowerCase() === email && u.active);
    if (!user) {
      await new Promise(r => setTimeout(r, 200 + Math.random() * 200));
      return sendJSON(res, 401, { error: 'Invalid credentials.' }, corsH);
    }
    const ok = await verifyUserPassword(password, user.passwordHash);
    if (!ok) {
      await new Promise(r => setTimeout(r, 200 + Math.random() * 200));
      return sendJSON(res, 401, { error: 'Invalid credentials.' }, corsH);
    }
    const sessionToken = issueUserSessionToken(user.id);
    const groups = loadGroups();
    const userGroups = (user.groupIds || []).map(gid => groups[gid]).filter(Boolean).map(g => ({
      id: g.id, name: g.name, vesselIMOs: g.vesselIMOs || [],
    }));
    return sendJSON(res, 200, {
      sessionToken,
      user: { id: user.id, name: user.name, email: user.email, role: user.role, groups: userGroups },
    }, corsH);
  }

  // ── GET /api/auth/user/me ── (verify session + return user info)
  if (route === '/auth/user/me' && method === 'GET') {
    const sessUser = getUserFromSession(req);
    if (!sessUser) return sendJSON(res, 401, { error: 'Session expired or invalid.' }, corsH);
    const groups = loadGroups();
    const userGroups = (sessUser.groupIds || []).map(gid => groups[gid]).filter(Boolean).map(g => ({
      id: g.id, name: g.name, vesselIMOs: g.vesselIMOs || [],
    }));
    const vessels = getUserVesselIMOs(sessUser);
    return sendJSON(res, 200, {
      user: { id: sessUser.id, name: sessUser.name, email: sessUser.email, role: sessUser.role, groups: userGroups },
      vessels: Array.from(vessels),
    }, corsH);
  }

  // ── GET /api/admin/users ── (admin read-only, super admin full)
  if (route === '/admin/users' && method === 'GET') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const users = loadUsers();
    const safe = Object.values(users).map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, groupIds: u.groupIds, active: u.active, createdAt: u.createdAt }));
    return sendJSON(res, 200, safe, corsH);
  }

  // ── POST /api/admin/users ── (super admin — create superintendent)
  if (route === '/admin/users' && method === 'POST') {
    if (!superAdminCheck(req)) return sendJSON(res, 401, { error: 'Super admin access required.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const name     = (body.name     || '').trim().slice(0, 120);
    const email    = (body.email    || '').trim().toLowerCase().slice(0, 200);
    const password = (body.password || '').trim();
    const role     = (body.role     || 'superintendent').trim();
    const groupIds = Array.isArray(body.groupIds) ? body.groupIds.filter(g => typeof g === 'string') : [];
    if (!name || !email || !password) return sendJSON(res, 400, { error: 'name, email, password are required.' }, corsH);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return sendJSON(res, 400, { error: 'Invalid email.' }, corsH);
    if (password.length < 8) return sendJSON(res, 400, { error: 'Password must be at least 8 characters.' }, corsH);
    const users = loadUsers();
    if (Object.values(users).some(u => u.email.toLowerCase() === email)) return sendJSON(res, 409, { error: 'Email already registered.' }, corsH);
    const id = nextSequentialId(users, 'USR');
    const passwordHash = await hashUserPassword(password);
    users[id] = { id, name, email, passwordHash, role, groupIds, active: true, createdAt: new Date().toISOString() };
    saveUsers(users);
    const { passwordHash: _ph, ...safeUser } = users[id];
    return sendJSON(res, 201, safeUser, corsH);
  }

  // ── PUT /api/admin/users/:id ── (super admin — update user)
  if (route.match(/^\/admin\/users\/USR-\d+$/) && method === 'PUT') {
    if (!superAdminCheck(req)) return sendJSON(res, 401, { error: 'Super admin access required.' }, corsH);
    const userId = route.replace('/admin/users/', '');
    const users = loadUsers();
    if (!users[userId]) return sendJSON(res, 404, { error: 'User not found.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    if (body.name     !== undefined) users[userId].name     = String(body.name).trim().slice(0, 120);
    if (body.email    !== undefined) {
      const newEmail = String(body.email).trim().toLowerCase();
      if (Object.values(users).some(u => u.id !== userId && u.email.toLowerCase() === newEmail)) return sendJSON(res, 409, { error: 'Email already in use.' }, corsH);
      users[userId].email = newEmail;
    }
    if (body.groupIds !== undefined) users[userId].groupIds = Array.isArray(body.groupIds) ? body.groupIds : [];
    if (body.active   !== undefined) users[userId].active   = Boolean(body.active);
    if (body.password) {
      if (body.password.length < 8) return sendJSON(res, 400, { error: 'Password must be at least 8 characters.' }, corsH);
      users[userId].passwordHash = await hashUserPassword(body.password);
    }
    users[userId].updatedAt = new Date().toISOString();
    saveUsers(users);
    const { passwordHash: _ph, ...safeUser } = users[userId];
    return sendJSON(res, 200, safeUser, corsH);
  }

  // ── DELETE /api/admin/users/:id ── (super admin — remove user)
  if (route.match(/^\/admin\/users\/USR-\d+$/) && method === 'DELETE') {
    if (!superAdminCheck(req)) return sendJSON(res, 401, { error: 'Super admin access required.' }, corsH);
    const userId = route.replace('/admin/users/', '');
    const users = loadUsers();
    if (!users[userId]) return sendJSON(res, 404, { error: 'User not found.' }, corsH);
    delete users[userId];
    saveUsers(users);
    return sendJSON(res, 200, { ok: true }, corsH);
  }

  // ── GET /api/supt/vessels ── (superintendent — list all accessible vessels with cert counts)
  if (route === '/supt/vessels' && method === 'GET') {
    const sessUser = getUserFromSession(req);
    if (!sessUser) return sendJSON(res, 401, { error: 'Session expired or invalid.' }, corsH);
    const imoSet   = getUserVesselIMOs(sessUser);
    const cstAll   = loadData();
    const vaptAll  = loadVaptData();
    const docsAll  = loadDocs();
    const vessels  = Array.from(imoSet).map(imo => {
      const cstCerts  = Object.values(cstAll).filter(c => (c.vesselIMO || '').toUpperCase() === imo);
      const vaptCerts = Object.values(vaptAll).filter(c => (c.vesselIMO || '').toUpperCase() === imo);
      const docs      = Object.values(docsAll).filter(d => normalizeVesselIMO(d.vesselIMO) === imo);
      const certDocs  = collectCertAttachmentsForVessel(imo);
      const vesselName = (cstCerts[0] || vaptCerts[0] || {}).vesselName || imo;
      const now = Date.now();
      const cstValid  = cstCerts.filter(c  => c.status === 'VALID' && (!c.validUntil  || new Date(c.validUntil).getTime()  > now)).length;
      const vaptValid = vaptCerts.filter(c => c.status === 'VALID' && (!c.validUntil || new Date(c.validUntil).getTime() > now)).length;
      return { imo, vesselName, cstCount: cstCerts.length, vaptCount: vaptCerts.length, docCount: docs.length + certDocs.length, cstValid, vaptValid };
    }).sort((a, b) => a.vesselName.localeCompare(b.vesselName));
    return sendJSON(res, 200, vessels, corsH);
  }

  // ── GET /api/supt/vessel/:imo/certs ── (superintendent — CST+VAPT cert records for one vessel)
  if (route.match(/^\/supt\/vessel\/[A-Z0-9]{1,20}\/certs$/) && method === 'GET') {
    const sessUser = getUserFromSession(req);
    if (!sessUser) return sendJSON(res, 401, { error: 'Session expired or invalid.' }, corsH);
    const imo = route.replace('/supt/vessel/', '').replace('/certs', '').toUpperCase();
    const imoSet = getUserVesselIMOs(sessUser);
    if (!imoSet.has(imo)) return sendJSON(res, 403, { error: 'Vessel not in your group.' }, corsH);
    const cstAll  = loadData();
    const vaptAll = loadVaptData();
    const cstCerts = Object.values(cstAll).filter(c => (c.vesselIMO || '').toUpperCase() === imo).map(c => ({
      id: c.id, certId: c.certId, vesselName: c.vesselName, vesselIMO: c.vesselIMO,
      recipientName: c.recipientName, chiefEngineer: c.chiefEngineer,
      rank: c.rank, courseType: c.courseType, trainingMode: c.trainingMode,
      trainingProvider: c.trainingProvider, complianceQuarter: c.complianceQuarter,
      complianceDate: c.complianceDate, issuedDate: c.issuedDate || c.issuedAt,
      validUntil: c.validUntil, status: c.status,
    }));
    const vaptCerts = Object.values(vaptAll).filter(c => (c.vesselIMO || '').toUpperCase() === imo).map(c => ({
      id: c.id, certId: c.certId, vesselName: c.vesselName, vesselIMO: c.vesselIMO,
      assessmentType: c.assessmentType, riskLevel: c.riskLevel,
      complianceQuarter: c.complianceQuarter, trainingMode: c.trainingMode,
      issuedDate: c.issuedDate || c.issuedAt, validUntil: c.validUntil, status: c.status,
    }));
    return sendJSON(res, 200, { cst: cstCerts, vapt: vaptCerts }, corsH);
  }

  // ── GET /api/vessels/names ── (admin or superadmin — IMO→name map from both CST+VAPT cert data)
  if (route === '/vessels/names' && method === 'GET') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const cstCerts  = loadData();
    const vaptCerts = loadVaptData();
    const nameMap = {};
    Object.values(cstCerts).forEach(c  => { if (c.vesselIMO && c.vesselName) nameMap[c.vesselIMO.toUpperCase()]  = c.vesselName; });
    Object.values(vaptCerts).forEach(c => { if (c.vesselIMO && c.vesselName) nameMap[c.vesselIMO.toUpperCase()] = c.vesselName; });
    return sendJSON(res, 200, nameMap, corsH);
  }

  // ── GET /api/admin/groups ── (admin — list groups)
  if (route === '/admin/groups' && method === 'GET') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const groups = loadGroups();
    return sendJSON(res, 200, Object.values(groups), corsH);
  }

  // ── POST /api/admin/groups ── (admin — create group)
  if (route === '/admin/groups' && method === 'POST') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    const name       = (body.name || '').trim().slice(0, 120);
    const vesselIMOs = Array.isArray(body.vesselIMOs) ? body.vesselIMOs.map(i => String(i).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 20)).filter(Boolean) : [];
    const notes      = (body.notes || '').trim().slice(0, 500);
    if (!name) return sendJSON(res, 400, { error: 'Group name is required.' }, corsH);
    const groups = loadGroups();
    const id = nextSequentialId(groups, 'GRP');
    groups[id] = { id, name, vesselIMOs, notes, createdAt: new Date().toISOString() };
    saveGroups(groups);
    return sendJSON(res, 201, groups[id], corsH);
  }

  // ── PUT /api/admin/groups/:id ── (admin — update group)
  if (route.match(/^\/admin\/groups\/GRP-\d+$/) && method === 'PUT') {
    if (!authCheck(req) && !superAdminCheck(req)) return sendJSON(res, 401, { error: 'Access denied.' }, corsH);
    const groupId = route.replace('/admin/groups/', '');
    const groups = loadGroups();
    if (!groups[groupId]) return sendJSON(res, 404, { error: 'Group not found.' }, corsH);
    let body;
    try { body = JSON.parse(await getBody(req)); } catch { return sendJSON(res, 400, { error: 'Invalid JSON' }, corsH); }
    if (body.name       !== undefined) groups[groupId].name       = String(body.name).trim().slice(0, 120);
    if (body.vesselIMOs !== undefined) groups[groupId].vesselIMOs = Array.isArray(body.vesselIMOs) ? body.vesselIMOs.map(i => String(i).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 20)).filter(Boolean) : [];
    if (body.notes      !== undefined) groups[groupId].notes      = String(body.notes).trim().slice(0, 500);
    groups[groupId].updatedAt = new Date().toISOString();
    saveGroups(groups);
    return sendJSON(res, 200, groups[groupId], corsH);
  }

  // ── DELETE /api/admin/groups/:id ── (super admin — remove group)
  if (route.match(/^\/admin\/groups\/GRP-\d+$/) && method === 'DELETE') {
    if (!superAdminCheck(req)) return sendJSON(res, 401, { error: 'Super admin access required.' }, corsH);
    const groupId = route.replace('/admin/groups/', '');
    const groups = loadGroups();
    if (!groups[groupId]) return sendJSON(res, 404, { error: 'Group not found.' }, corsH);
    delete groups[groupId];
    saveGroups(groups);
    return sendJSON(res, 200, { ok: true }, corsH);
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

  // ── SSO: GET /auth/sso/login ─────────────────────────────────────────────
  if (p === '/auth/sso/login' && method === 'GET') {
    if (!COGNITO_ENABLED) { res.writeHead(302, { Location: '/' }); return res.end(); }
    const next  = (parsed.searchParams.get('next') || '/').replace(/[<>"'`]/g, '');
    const state = Buffer.from(JSON.stringify({ next, ts: Date.now() })).toString('base64url');
    const loginUrl = `https://${COGNITO_DOMAIN}/login?response_type=code`
      + `&client_id=${encodeURIComponent(COGNITO_CLIENT_ID)}`
      + `&redirect_uri=${encodeURIComponent(BASE_ORIGIN + '/auth/sso/callback')}`
      + `&scope=openid+email+profile`
      + `&state=${state}`;
    res.writeHead(302, { ...SECURITY_HEADERS, Location: loginUrl });
    return res.end();
  }

  // ── SSO: GET /auth/sso/callback ──────────────────────────────────────────
  if (p === '/auth/sso/callback' && method === 'GET') {
    const code  = parsed.searchParams.get('code')  || '';
    const state = parsed.searchParams.get('state') || '';
    let next = '/';
    try { const s = JSON.parse(Buffer.from(state, 'base64url').toString('utf8')); next = (s.next || '/').replace(/[<>"'`]/g, ''); } catch { /* default */ }
    if (!code || !COGNITO_ENABLED) {
      res.writeHead(302, { Location: next + (next.includes('?') ? '&' : '?') + 'sso_error=1' });
      return res.end();
    }
    try {
      const tokens    = await exchangeCognitoCode(code);
      if (tokens.error) throw new Error(tokens.error_description || tokens.error);
      const idPayload = await verifyCognitoIdToken(tokens.id_token);
      const email     = (idPayload.email || '').toLowerCase();
      const cogGroups = idPayload['cognito:groups'] || [];
      // Primary: Cognito group membership. Fallback: email matches ADMIN_USER.
      const isAdmin   = cogGroups.includes(COGNITO_ADMIN_GROUP)
                        || email === (ADMIN_USER || '').toLowerCase();
      log.info('SSO login:', email, '| groups:', cogGroups, '| admin:', isAdmin);
      let sessionToken, cookieName;
      if (isAdmin) {
        sessionToken = issueToken(ADMIN_USER);
        cookieName   = 'sso_admin_token';
      } else {
        const users = loadUsers();
        let user = Object.values(users).find(u => (u.email || '').toLowerCase() === email && u.active);
        if (!user) {
          const newId = 'usr_' + crypto.randomBytes(8).toString('hex');
          user = { id: newId, name: idPayload.name || idPayload.email || email, email,
                   role: 'user', active: true, groupIds: [], passwordHash: '',
                   createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), ssoSub: idPayload.sub };
          users[newId] = user;
          saveUsers(users);
          log.info('SSO auto-provisioned superintendent:', email);
        }
        sessionToken = issueUserSessionToken(user.id);
        cookieName   = 'sso_user_token';
      }
      const secure = BASE_ORIGIN.startsWith('https') ? '; Secure' : '';
      res.writeHead(302, {
        ...SECURITY_HEADERS,
        'Set-Cookie': `${cookieName}=${sessionToken}; Path=/; Max-Age=30; SameSite=Strict${secure}`,
        Location: next,
      });
      return res.end();
    } catch (err) {
      log.error('SSO callback error:', err.message);
      res.writeHead(302, { Location: '/?sso_error=1' });
      return res.end();
    }
  }

  // ── SSO: GET /auth/sso/logout ────────────────────────────────────────────
  if (p === '/auth/sso/logout' && method === 'GET') {
    const logoutUri = encodeURIComponent(BASE_ORIGIN + '/');
    const location  = COGNITO_ENABLED
      ? `https://${COGNITO_DOMAIN}/logout?client_id=${encodeURIComponent(COGNITO_CLIENT_ID)}&logout_uri=${logoutUri}`
      : '/';
    const clr = '; Path=/; Max-Age=0; SameSite=Strict';
    res.writeHead(302, {
      ...SECURITY_HEADERS,
      'Set-Cookie': [`sso_admin_token=${clr}`, `sso_user_token=${clr}`],
      Location: location,
    });
    return res.end();
  }

  // ── Uploads (shared) ─────────────────────────────────────────────────────
  if (p.startsWith('/uploads/')) {
    // Extract relative path while protecting against traversal attacks
    const relPath = p.slice('/uploads/'.length);
    
    // Reject path traversal attempts
    if (relPath.includes('..') || relPath.startsWith('/')) {
      res.writeHead(403, SECURITY_HEADERS);
      return res.end('Forbidden');
    }
    
    // Resolve the full path
    const fpath = path.resolve(UPLOADS_DIR, relPath);

    // Verify the resolved path is within UPLOADS_DIR (another traversal check)
    if (!fpath.startsWith(UPLOADS_DIR + path.sep) && fpath !== UPLOADS_DIR) {
      res.writeHead(403, SECURITY_HEADERS);
      return res.end('Forbidden');
    }
    if (!fs.existsSync(fpath)) {
      res.writeHead(404, SECURITY_HEADERS);
      return res.end('Not found');
    }

    const ext   = path.extname(fpath).toLowerCase();
    const mime  = MIME[ext] || 'application/octet-stream';
    const isPdf = ext === '.pdf';
    const fname = path.basename(fpath);

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
        const fileUrl = '/uploads/' + relPath;
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

    // Confidential PDF attachments are gated by a short-lived, server-issued token.
    // Admin panel requests are temporarily allowed via referer allowance to avoid
    // forcing token plumbing in legacy dashboard flows.
    if (isPdf && !isAdminReferer) {
      const downloadToken = parsed.searchParams.get('t') || '';
      const payload = verifyDownloadToken(downloadToken);
      if (!payload) {
        res.writeHead(403, SECURITY_HEADERS);
        return res.end('Forbidden');
      }

      const fileUrl = '/uploads/' + relPath;
      const data = payload.kind === 'vapt' ? loadVaptData() : loadData();
      const cert = data && payload.sub ? data[payload.sub] : null;
      const owns = cert && (
        cert.certificateImage === fileUrl ||
        (Array.isArray(cert.attachments) && cert.attachments.some(a => a.url === fileUrl))
      );
      if (!owns) {
        res.writeHead(403, SECURITY_HEADERS);
        return res.end('Forbidden');
      }
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
    const cfgPath = (TENANT_CFG_FILE && fs.existsSync(TENANT_CFG_FILE))
      ? TENANT_CFG_FILE
      : path.join(__dirname, '..', 'config', 'app.config.js');
    return sendFile(res, cfgPath, req);
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
    const relative = p.slice((CFG.routes.cstAdmin + '/').length).replace(/\/$/, '');
    // Known named admin pages — extensionless sub-paths resolved here.
    const PAGE_MAP = { documents: 'documents.html', hub: 'index.html', access: 'access.html', users: 'users.html', groups: 'groups.html', portal: 'portal.html', superadmin: 'super-admin.html' };
    let filePath;
    if (!relative) {
      filePath = path.join(adminDir, 'dashboard.html');
    } else if (PAGE_MAP[relative]) {
      filePath = path.join(adminDir, PAGE_MAP[relative]);
    } else {
      filePath = path.resolve(adminDir, relative);
      if (!path.extname(filePath)) filePath = path.join(adminDir, 'dashboard.html');
    }
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
  req._reqId = (++_reqSeq).toString(36) + Date.now().toString(36).slice(-4);
  metrics.begin(req);
  res.on('finish', () => {
    metrics.end(req, res.statusCode || 0);
    const p = (() => { try { return new URL(req.url, 'http://localhost').pathname; } catch { return req.url || ''; } })();
    if ((res.statusCode || 0) >= 500) {
      log.reqError(req, req.method, p, res.statusCode);
    } else if ((res.statusCode || 0) >= 400) {
      log.reqWarn(req, req.method, p, res.statusCode);
    } else {
      log.reqInfo(req, req.method, p, res.statusCode);
    }
  });
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
    const D = '─'.repeat(64);
    const cstA = BASE_ORIGIN + CFG.routes.cstAdmin;
    const vptA = BASE_ORIGIN + CFG.routes.vptAdmin;
    const u = (label, url) => console.log('    ' + label.padEnd(18) + url);
    console.log('\n' + D);
    console.log('  ' + CFG.brand.companyFull + ' — Certificate Portal  (port ' + PORT + ')');
    console.log(D);
    console.log('');
    console.log('  PUBLIC PORTALS');
    u('CST Portal',   BASE_ORIGIN + CFG.routes.cst);
    u('VAPT Portal',  BASE_ORIGIN + CFG.routes.vpt);
    console.log('');
    console.log('  CST ADMIN');
    u('Dashboard',    cstA + '/');
    u('Documents',    cstA + '/documents/');
    u('Access Ctrl',  cstA + '/access/');
    console.log('');
    console.log('  VAPT ADMIN');
    u('Dashboard',    vptA + '/');
    console.log('');
    console.log('  SUPER ADMIN');
    u('Users',        cstA + '/users/');
    u('Groups',       cstA + '/groups/');
    u('Supt Portal',  cstA + '/portal/');
    console.log('');
    console.log('  HEALTH / STATUS');
    u('Health',       BASE_ORIGIN + '/api/health');
    u('Email',        SES_ENABLED ? 'Active (' + SES_REGION + ')' : 'Not configured');
    console.log('');
    console.log(D + '\n');
  });
}
startServer();

// ─── GRACEFUL SHUTDOWN ────────────────────────────────────────────────────────
function flushPendingSaves() {
  try { cstStore.flush(); } catch (e) { log.error('Data flush on shutdown failed:', e.message); }
  try { vaptStore.flush(); } catch (e) { log.error('Data flush on shutdown failed:', e.message); }
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
