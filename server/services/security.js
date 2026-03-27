'use strict';

const crypto = require('crypto');

function createSecurityService({ keys, cfg }) {
  const TOKEN_EXPIRY_MS = 8 * 60 * 60 * 1000;

  function hashPassword(password) {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, keys.pwdSalt, 310000, 32, 'sha256', (err, key) => {
        if (err) reject(err);
        else resolve(key.toString('hex'));
      });
    });
  }

  function issueToken(username) {
    const payload = {
      sub: username,
      iat: Date.now(),
      exp: Date.now() + TOKEN_EXPIRY_MS,
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
      if (Date.now() > payload.exp) return null;
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

module.exports = { createSecurityService };
