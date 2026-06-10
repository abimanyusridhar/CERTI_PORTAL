'use strict';
/**
 * s3JsonStore — S3-backed drop-in replacement for createJsonStore.
 *
 * Strategy:
 *   LOAD  → try local disk cache first (fast); if missing, pull from S3;
 *            if S3 also missing, fall back to seedData.
 *   SAVE  → write local disk immediately (debounced) AND mirror to S3 async.
 *
 * This means:
 *   - Reads are fast (local disk cache, no S3 latency per request)
 *   - Writes are durable (both disk AND S3 — data survives instance replacement)
 *   - On fresh EC2 launch: data is pulled from S3 automatically on first load
 *
 * Activated automatically when s3.S3_ENABLED === true (S3_BUCKET + keys set).
 */

const fs = require('fs');
const s3 = require('../services/s3');

function createS3JsonStore({ filePath, s3Key, seedData, onError, debounceMs = 50 }) {
  let cache = null;
  let timer = null;

  // ── Local disk helpers ────────────────────────────────────────────────────
  function readFromDisk() {
    try {
      if (fs.existsSync(filePath)) {
        let raw = fs.readFileSync(filePath, 'utf8');
        if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
        return JSON.parse(raw);
      }
    } catch { /* fall through */ }
    return null;
  }

  function writeToDisk(data) {
    try {
      const dir = require('path').dirname(filePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) {
      if (onError) onError(e);
    }
  }

  // ── S3 helpers ────────────────────────────────────────────────────────────
  async function pullFromS3() {
    try {
      const data = await s3.getJson(s3Key);
      // Cache locally so next restart is fast
      writeToDisk(data);
      return data;
    } catch {
      return null; // S3 key doesn't exist yet — normal on first run
    }
  }

  function pushToS3(data) {
    s3.putJson(s3Key, data).catch(err => {
      if (onError) onError(new Error('S3 sync failed for ' + s3Key + ': ' + err.message));
    });
  }

  // ── Public API (matches createJsonStore interface) ────────────────────────
  function load() {
    if (cache) return cache;

    // Try local disk first (fast path)
    const fromDisk = readFromDisk();
    if (fromDisk) {
      cache = fromDisk;
      // Silently mirror to S3 if not there yet (first-time sync)
      pushToS3(cache);
      return cache;
    }

    // No local file — try S3 synchronously via async init trick
    // We return seed data immediately and trigger async S3 pull.
    // On the next load() call (after init completes), real data will be returned.
    cache = { ...(seedData || {}) };
    pullFromS3().then(remote => {
      if (remote && Object.keys(remote).length > 0) {
        cache = remote;
      }
    }).catch(() => {});
    return cache;
  }

  function save(data) {
    cache = data;
    // Write to disk (debounced)
    clearTimeout(timer);
    timer = setTimeout(() => {
      fs.promises.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8')
        .then(() => { if (s3.S3_ENABLED) pushToS3(data); })
        .catch(err => onError && onError(err));
    }, debounceMs);
  }

  function flush() {
    if (!timer) return;
    clearTimeout(timer);
    timer = null;
    if (!cache) return;
    writeToDisk(cache);
    if (s3.S3_ENABLED) pushToS3(cache);
  }

  return { load, save, flush };
}

module.exports = { createS3JsonStore };
