'use strict';

const crypto = require('crypto');

/**
 * Circuit Breaker Pattern for handling external service failures
 * States: CLOSED (working) → OPEN (failing) → HALF_OPEN (testing)
 */
class CircuitBreaker {
  constructor(options = {}) {
    this.failureThreshold = options.failureThreshold || 5;
    this.successThreshold = options.successThreshold || 2;
    this.timeout = options.timeout || 30000; // 30s
    this.monitoredFunction = options.fn || null;
    
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.nextAttemptTime = null;
    this.lastError = null;
  }

  async execute(fn, fallback) {
    // If open and not time to try yet, use fallback
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttemptTime) {
        if (fallback) return fallback();
        throw new Error('Circuit breaker is OPEN. Service unavailable.');
      }
      this.state = 'HALF_OPEN';
    }

    try {
      const result = await fn();
      this._onSuccess();
      return result;
    } catch (err) {
      this._onFailure(err);
      if (fallback) return fallback();
      throw err;
    }
  }

  _onSuccess() {
    this.failureCount = 0;
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= this.successThreshold) {
        this.state = 'CLOSED';
        this.successCount = 0;
      }
    }
  }

  _onFailure(err) {
    this.failureCount++;
    this.lastError = err;
    if (this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttemptTime = Date.now() + this.timeout;
    }
  }

  getStatus() {
    return {
      state: this.state,
      failureCount: this.failureCount,
      lastError: this.lastError ? this.lastError.message : null,
      nextAttemptTime: this.nextAttemptTime,
    };
  }
}

/**
 * Input validation utilities
 */
const validation = {
  isValidCertId(id) {
    if (!id || typeof id !== 'string') return false;
    // Allow CST/VAPT format: CST-XXXXXXX-XX-XX, VAP-XXXXXXX-XXXX
    return /^(CST|VAP)-[A-Z0-9]{5,}-[A-Z0-9]{2,}$/.test(id) && id.length <= 50;
  },

  isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
  },

  isValidUsername(username) {
    if (!username || typeof username !== 'string') return false;
    return /^[a-zA-Z0-9._-]{3,32}$/.test(username);
  },

  isValidPassword(password) {
    if (!password || typeof password !== 'string') return false;
    // Minimum 8 chars, at least one uppercase, one lowercase, one digit
    return password.length >= 8 &&
           /[A-Z]/.test(password) &&
           /[a-z]/.test(password) &&
           /[0-9]/.test(password);
  },

  sanitize(input) {
    if (typeof input !== 'string') return input;
    // Basic HTML escape
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  },

  isValidUrl(url) {
    if (!url || typeof url !== 'string') return false;
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }
};

/**
 * Exponential backoff retry utility
 */
async function retryWithBackoff(fn, maxAttempts = 3, baseDelay = 100) {
  let lastError = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (attempt < maxAttempts) {
        const delay = baseDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  throw lastError;
}

/**
 * Standardized error response builder
 */
function createErrorResponse(statusCode, errorCode, message, details = {}) {
  return {
    status: statusCode,
    error: {
      code: errorCode,
      message,
      ...details
    }
  };
}

function createSecurityService({ keys, cfg }) {
  const TOKEN_EXPIRY_S = 8 * 60 * 60; // 8 hours in seconds (standard JWT uses seconds)

  function hashPassword(password) {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, keys.pwdSalt, 310000, 32, 'sha256', (err, key) => {
        if (err) reject(err);
        else resolve(key.toString('hex'));
      });
    });
  }

  function issueToken(username) {
    const nowS = Math.floor(Date.now() / 1000); // Unix seconds (standard JWT)
    const payload = {
      sub: username,
      iat: nowS,
      exp: nowS + TOKEN_EXPIRY_S,
      jti: crypto.randomBytes(16).toString('hex'),
    };
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', keys.jwtSecret).update(header + '.' + body).digest('base64url');
    return `${header}.${body}.${sig}`;
  }

  function verifyToken(token) {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const expected = crypto.createHmac('sha256', keys.jwtSecret).update(header + '.' + body).digest('base64url');
    const sigBuf = Buffer.from(sig);
    const expectedBuf = Buffer.from(expected);
    if (sigBuf.length !== expectedBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
    try {
      const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
      // exp is Unix seconds; multiply by 1000 to compare with Date.now() (ms)
      if (!payload.exp || Date.now() > payload.exp * 1000) return null;
      return payload;
    } catch {
      return null;
    }
  }

  function encryptCertToken(certId) {
    const key = Buffer.from(keys.urlEncKey, 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(certId, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString('base64url');
  }

  function decryptCertToken(token) {
    try {
      const raw = Buffer.from(token, 'base64url');
      if (raw.length < 29) return null;
      const iv = raw.subarray(0, 12);
      const tag = raw.subarray(12, 28);
      const enc = raw.subarray(28);
      const key = Buffer.from(keys.urlEncKey, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      return decipher.update(enc).toString('utf8') + decipher.final('utf8');
    } catch {
      return null;
    }
  }

  function signCertUrl(encToken) {
    return crypto.createHmac('sha256', keys.urlMacKey).update('cert:' + encToken).digest('base64url').slice(0, 22);
  }

  function verifyCertUrlSignature(encToken, sig) {
    if (!sig) return false;
    const expected = signCertUrl(encToken);
    if (sig.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  }

  function buildCertUrl(certId, baseUrl) {
    const token = encryptCertToken(certId);
    const sig = signCertUrl(token);
    return `${baseUrl}${cfg.routes.cst}/cert/${token}?s=${sig}`;
  }

  function buildVaptCertUrl(certId, baseUrl) {
    const token = encryptCertToken(certId);
    const sig = signCertUrl(token);
    return `${baseUrl}${cfg.routes.vpt}/cert/${token}?s=${sig}`;
  }

  return {
    hashPassword,
    issueToken,
    verifyToken,
    encryptCertToken,
    decryptCertToken,
    signCertUrl,
    verifyCertUrlSignature,
    buildCertUrl,
    buildVaptCertUrl,
  };
}

module.exports = {
  createSecurityService,
  CircuitBreaker,
  validation,
  retryWithBackoff,
  createErrorResponse,
};
