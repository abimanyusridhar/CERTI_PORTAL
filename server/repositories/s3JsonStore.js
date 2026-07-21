'use strict';
/**
 * s3JsonStore — S3-only JSON collection store. No local filesystem is ever
 * touched (no cache file, no temp file, nothing) — this process's memory and
 * the S3 object are the only two copies of the data that exist.
 *
 * Strategy:
 *   INIT  → pull the current object from S3 into the in-memory cache. If the
 *            key doesn't exist yet (first deploy), seed with seedData.
 *   LOAD  → return the in-memory cache (no I/O per request).
 *   SAVE  → update the in-memory cache immediately, then debounce a single
 *            PUT to S3.
 *   FLUSH → forces the pending debounced PUT now, returning a Promise that
 *            resolves once S3 confirms the write (used during graceful
 *            shutdown, so the last few mutations aren't lost).
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

const s3 = require('../services/s3');

function createS3JsonStore({ s3Key, seedData, onError, debounceMs = 50, refreshIntervalMs = 0 }) {
  let cache = null;
  let timer = null;
  let dirty = false;       // true while a local write is pending or in-flight
  let refreshTimer = null;

  // Returns a Promise so callers can await durable S3 confirmation.
  function pushToS3(data) {
    return s3.putJson(s3Key, data).catch(err => {
      if (onError) onError(new Error('S3 sync failed for ' + s3Key + ': ' + err.message));
    });
  }

  async function pullFromS3() {
    try {
      return await s3.getJson(s3Key);
    } catch {
      return null; // key doesn't exist yet — normal on first deploy
    }
  }

  // ── Startup pre-load ─────────────────────────────────────────────────────
  // Call before server.listen() to ensure cache is warm before the first request.
  async function init() {
    if (cache) { startBackgroundRefresh(); return; } // already warmed (e.g. called twice)
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

  // ── Public API ──────────────────────────────────────────────────────────
  function load() {
    if (cache) return cache;

    // Cold-start fallback (init() was not awaited — should not occur in normal flow).
    // Return seed immediately; overwrite if/when the S3 pull succeeds.
    cache = { ...(seedData || {}) };
    pullFromS3().then(remote => {
      if (remote && Object.keys(remote).length > 0 && !dirty && !timer) cache = remote;
    }).catch(() => {});
    return cache;
  }

  function save(data) {
    cache = data;
    dirty = true;
    clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      pushToS3(data).finally(() => { dirty = false; });
    }, debounceMs);
  }

  // Forces the pending debounced save to S3 now. Returns a Promise that
  // resolves once S3 confirms the write — used during graceful shutdown.
  function flush() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (!cache) return Promise.resolve();
    dirty = true;
    return pushToS3(cache).finally(() => { dirty = false; });
  }

  return { init, load, save, flush, stopBackgroundRefresh };
}

module.exports = { createS3JsonStore };
