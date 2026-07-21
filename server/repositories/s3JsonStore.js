'use strict';
/**
 * s3JsonStore — S3-backed drop-in replacement for createJsonStore.
 *
 * Strategy:
 *   LOAD  → use in-memory cache (no I/O per request); on cold start, try local
 *            disk first, then pull from S3 if disk is empty.
 *   SAVE  → update in-memory cache immediately, then debounce disk + S3 writes
 *            in PARALLEL — a disk failure does NOT block the S3 write.
 *   FLUSH → writes synchronously to disk and returns a Promise that resolves
 *            once S3 confirms the write (used during graceful shutdown).
 *
 * On fresh EC2 launch (empty ephemeral disk):
 *   init() pulls the latest data from S3 and caches it locally, so the first
 *   request sees the correct data without hitting S3 again.
 *
 * Multi-instance correctness (refreshIntervalMs):
 *   Without this, the in-memory cache is populated once at cold start and
 *   NEVER refreshed afterwards except by this same process's own save()
 *   calls. Run more than one instance behind a load balancer and instance
 *   A's writes become permanently invisible to instance B until B restarts
 *   — a silent, unbounded data-divergence bug. Passing refreshIntervalMs > 0
 *   starts a background poll that re-pulls from S3 on that interval, bounding
 *   cross-instance staleness to roughly that window. It always skips a cycle
 *   while a local write is pending/in-flight (the `dirty` flag) so a slightly
 *   stale remote read can never clobber this instance's own uncommitted
 *   change. Default 0 (disabled) — existing callers/tests are unaffected
 *   unless they opt in.
 */

const fs   = require('fs');
const path = require('path');
const s3   = require('../services/s3');

function writeFileAtomicSync(filePath, data) {
  const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmpPath, data, 'utf8');
  fs.renameSync(tmpPath, filePath);
}

async function writeFileAtomic(filePath, data) {
  const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await fs.promises.writeFile(tmpPath, data, 'utf8');
  await fs.promises.rename(tmpPath, filePath);
}

function createS3JsonStore({ filePath, s3Key, seedData, onError, debounceMs = 50, refreshIntervalMs = 0 }) {
  let cache = null;
  let timer = null;
  let dirty = false;       // true while a local write is pending or in-flight
  let refreshTimer = null;

  // ── Local disk helpers ────────────────────────────────────────────────────
  function readFromDisk() {
    try {
      if (fs.existsSync(filePath)) {
        let raw = fs.readFileSync(filePath, 'utf8');
        if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1); // strip UTF-8 BOM
        return JSON.parse(raw);
      }
    } catch { /* fall through */ }
    return null;
  }

  function writeToDisk(data) {
    try {
      const dir = path.dirname(filePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      writeFileAtomicSync(filePath, JSON.stringify(data, null, 2));
    } catch (e) {
      if (onError) onError(e);
    }
  }

  // ── S3 helpers ────────────────────────────────────────────────────────────
  async function pullFromS3() {
    try {
      const data = await s3.getJson(s3Key);
      writeToDisk(data); // cache locally so next restart is fast
      return data;
    } catch {
      return null; // key doesn't exist yet — normal on first deploy
    }
  }

  // Returns a Promise so callers can await durable S3 confirmation.
  function pushToS3(data) {
    return s3.putJson(s3Key, data).catch(err => {
      if (onError) onError(new Error('S3 sync failed for ' + s3Key + ': ' + err.message));
    });
  }

  // ── Startup pre-load ─────────────────────────────────────────────────────
  // Call before server.listen() to ensure cache is warm before the first request.
  async function init() {
    if (cache) { startBackgroundRefresh(); return; } // already warmed (e.g. called twice)
    const fromDisk = readFromDisk();
    if (fromDisk) {
      cache = fromDisk;
      startBackgroundRefresh();
      return;
    }
    // Fresh instance — no local data, pull authoritative copy from S3
    const remote = await pullFromS3();
    cache = (remote && Object.keys(remote).length > 0) ? remote : { ...(seedData || {}) };
    startBackgroundRefresh();
  }

  // ── Background refresh (multi-instance correctness — see file header) ────
  async function backgroundRefresh() {
    if (dirty || timer) return; // a local write is pending/in-flight — never clobber it
    const remote = await pullFromS3();
    if (remote && !dirty && !timer) cache = remote; // re-check: a write may have started mid-fetch
  }
  function startBackgroundRefresh() {
    if (!refreshIntervalMs || refreshTimer) return;
    refreshTimer = setInterval(() => { backgroundRefresh().catch(() => {}); }, refreshIntervalMs);
    refreshTimer.unref(); // background polling must never keep the process alive on its own
  }
  function stopBackgroundRefresh() {
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  }

  // ── Public API (matches createJsonStore interface + init) ─────────────────
  function load() {
    if (cache) return cache;

    // Cold-start fallback (init() was not awaited — should not occur in normal flow)
    const fromDisk = readFromDisk();
    if (fromDisk) {
      cache = fromDisk;
      pushToS3(cache); // mirror to S3 in background
      return cache;
    }

    // Return seed immediately; overwrite if/when S3 pull succeeds
    cache = { ...(seedData || {}) };
    pullFromS3().then(remote => {
      if (remote && Object.keys(remote).length > 0) cache = remote;
    }).catch(() => {});
    return cache;
  }

  function save(data) {
    cache = data;
    dirty = true;
    clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      const serialized = JSON.stringify(data, null, 2);
      // Disk and S3 writes are INDEPENDENT — disk failure does NOT block S3 sync.
      const diskWrite = writeFileAtomic(filePath, serialized).catch(err => onError && onError(err));
      const s3Write = s3.S3_ENABLED ? pushToS3(data) : Promise.resolve();
      Promise.all([diskWrite, s3Write]).finally(() => { dirty = false; });
    }, debounceMs);
  }

  // Flush any pending debounced save to disk (sync) and S3 (async, awaitable).
  // Returns a Promise that resolves once S3 confirms the write — used during
  // graceful shutdown to avoid losing the last few mutations.
  function flush() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (!cache) return Promise.resolve();
    dirty = true;
    writeToDisk(cache);
    return (s3.S3_ENABLED ? pushToS3(cache) : Promise.resolve()).finally(() => { dirty = false; });
  }

  return { init, load, save, flush, stopBackgroundRefresh };
}

module.exports = { createS3JsonStore };
