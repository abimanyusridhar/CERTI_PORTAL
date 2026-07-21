'use strict';

/**
 * dynamoStore — DynamoDB-backed drop-in replacement for createJsonStore,
 * matching the same flat `{ [id]: record }` cache shape the app already
 * uses for certStore/usersStore/groupsStore/docsStore/etc, mapped onto the
 * Phase 1 single-table schema: PK=TENANT#<tenantId>, SK=<entityPrefix>#<id>
 * (see docs/data-structure-migration-plan.md and terraform/dynamodb.tf).
 *
 * Strategy mirrors s3JsonStore.js:
 *   INIT  → Query every item under this PK+SK-prefix, rebuild the
 *            in-memory cache from them.
 *   LOAD  → return the in-memory cache (no I/O per request).
 *   SAVE  → update the cache immediately; debounce a diff against the last
 *            confirmed-persisted snapshot into batched PutItem/DeleteItem
 *            calls. The diff is a reference-identity check per top-level
 *            key — callers only replace the object for a record they
 *            actually changed (e.g. `users[id] = {...}`), leaving every
 *            other key's reference untouched, so `before[id] !== after[id]`
 *            is a cheap and correct dirty check.
 *   FLUSH → force the pending diff to run now, returning a Promise that
 *            resolves once DynamoDB confirms it (used during graceful
 *            shutdown).
 *
 * Errors surface via onError (matching jsonStore/s3JsonStore) — writes are
 * fire-and-forget from the caller's point of view, never thrown back into
 * the request path that called save().
 *
 * Multi-instance correctness (refreshIntervalMs):
 *   Same gap as s3JsonStore.js: the cache is built once at init() and never
 *   refreshed afterwards except by this process's own save() calls, so a
 *   second instance's writes stay invisible here until this instance
 *   restarts. Passing refreshIntervalMs > 0 starts a background re-query on
 *   that interval, skipped whenever a local write is pending/in-flight (via
 *   the `dirty` flag) so a stale re-query can never clobber this instance's
 *   own uncommitted change. Default 0 (disabled) — existing callers/tests
 *   are unaffected unless they opt in.
 */

const dynamodb = require('../services/dynamodb');

function createDynamoStore({ tenantId, entityPrefix, seedData, onError, debounceMs = 50, refreshIntervalMs = 0 }) {
  const pk = `TENANT#${tenantId || 'default'}`;
  const skPrefix = `${entityPrefix}#`;

  let cache = null;     // current in-memory state, keyed by entity id
  let persisted = null; // last state confirmed written to DynamoDB
  let timer = null;
  let flushing = null;      // in-flight batchWrite Promise, or null
  let pendingAgain = false; // a save() arrived while a flush was in flight
  let dirty = false;        // true while a local write is pending or in-flight
  let refreshTimer = null;

  function skFor(id) { return `${skPrefix}${id}`; }

  async function queryAll() {
    const items = await dynamodb.query({
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :skPrefix)',
      ExpressionAttributeValues: {
        ':pk':       { S: pk },
        ':skPrefix': { S: skPrefix },
      },
    });
    const loaded = {};
    for (const item of items) {
      const { PK, SK, ...record } = item;
      if (record.id) loaded[record.id] = record;
    }
    return loaded;
  }

  async function init() {
    if (cache) { startBackgroundRefresh(); return; }
    const loaded = await queryAll();
    cache = loaded;
    persisted = { ...loaded };
    startBackgroundRefresh();
  }

  // ── Background refresh (multi-instance correctness — see file header) ────
  async function backgroundRefresh() {
    if (dirty || timer || flushing) return; // local write pending/in-flight — never clobber it
    const loaded = await queryAll();
    if (dirty || timer || flushing) return; // re-check: a write may have started mid-query
    cache = loaded;
    persisted = { ...loaded };
  }
  function startBackgroundRefresh() {
    if (!refreshIntervalMs || refreshTimer) return;
    refreshTimer = setInterval(() => { backgroundRefresh().catch(() => {}); }, refreshIntervalMs);
    refreshTimer.unref(); // background polling must never keep the process alive on its own
  }
  function stopBackgroundRefresh() {
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  }

  function load() {
    if (cache) return cache;
    // Cold-start fallback (init() was not awaited — should not occur in normal flow).
    cache = { ...(seedData || {}) };
    persisted = {};
    return cache;
  }

  function save(data) {
    cache = data;
    dirty = true;
    clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      scheduleFlush();
    }, debounceMs);
  }

  async function _flushDiff() {
    const before = persisted || {};
    const after  = cache || {};
    const ids = new Set([...Object.keys(before), ...Object.keys(after)]);

    const writeRequests = [];
    for (const id of ids) {
      if (!(id in after)) {
        writeRequests.push({ DeleteRequest: { Key: dynamodb.marshalItem({ PK: pk, SK: skFor(id) }) } });
      } else if (before[id] !== after[id]) {
        writeRequests.push({ PutRequest: { Item: dynamodb.marshalItem({ ...after[id], PK: pk, SK: skFor(id) }) } });
      }
    }
    if (writeRequests.length) await dynamodb.batchWrite(writeRequests);
    persisted = { ...after }; // only mark persisted once the write actually succeeded
  }

  // Serializes overlapping flushes: if one is already in flight when another
  // is requested, that request is coalesced into a single follow-up flush
  // (picking up whatever `cache` holds by then) rather than racing two
  // concurrent batchWrite calls against the same diff baseline.
  function scheduleFlush() {
    if (flushing) { pendingAgain = true; return flushing; }
    flushing = _flushDiff()
      .catch(err => { if (onError) onError(err); })
      .then(() => {
        flushing = null;
        if (pendingAgain) { pendingAgain = false; return scheduleFlush(); }
        dirty = false; // no more follow-up work queued — safe for background refresh again
      });
    return flushing;
  }

  function flush() {
    if (timer) { clearTimeout(timer); timer = null; }
    return scheduleFlush();
  }

  return { init, load, save, flush, stopBackgroundRefresh };
}

module.exports = { createDynamoStore };
