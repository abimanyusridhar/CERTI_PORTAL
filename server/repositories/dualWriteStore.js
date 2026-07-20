'use strict';

/**
 * dualWriteStore — wraps two stores sharing the { init, load, save, flush }
 * interface (e.g. the existing s3JsonStore as `primary` and the new
 * dynamoStore as `secondary`) for the migration rollout described in the
 * Phase 1 plan:
 *
 *   DUAL_WRITE_DYNAMO=true   → save() fans out to both; reads stay on primary.
 *   SHADOW_READ_DYNAMO=true  → additionally background-diffs secondary
 *                              against primary on every load(), without ever
 *                              serving the shadow copy to a request.
 *   DYNAMO_PRIMARY_READ=true → reads are served from secondary (DynamoDB)
 *                              instead of primary (JSON/S3). Writes still go
 *                              to both (dual-write must also be on — see the
 *                              validation in server/index.js), so primary
 *                              stays a live, current fallback rather than a
 *                              stale snapshot.
 *
 * The secondary write is always fire-and-forget: a secondary write failure
 * is reported via onError but never blocks, delays, or rolls back the
 * primary path (mirrors the existing disk-doesn't-block-S3 split in
 * s3JsonStore.save). Secondary READS, once readFromSecondary is on, are the
 * one exception to "secondary never affects what a request sees" — but even
 * then, any read failure (or the secondary never having finished init())
 * falls straight back to primary rather than surfacing an error or serving
 * stale/seed data, so a DynamoDB outage degrades to "reads come from JSON",
 * not "the app breaks".
 */

function createDualWriteStore({ primary, secondary, onError, onMismatch, shadowRead = false, readFromSecondary = false }) {
  let secondaryReady = false;

  async function init() {
    if (primary.init) await primary.init();
    if (secondary.init) {
      try { await secondary.init(); secondaryReady = true; } catch (err) { if (onError) onError(err); }
    } else {
      secondaryReady = true;
    }
  }

  function load() {
    if (readFromSecondary && secondaryReady && secondary.load) {
      try {
        const data = secondary.load();
        if (shadowRead) {
          // Still diff against primary — catches primary falling behind
          // (e.g. a write that failed on the JSON side but not DynamoDB)
          // exactly like the normal shadow-read direction does.
          setImmediate(() => {
            try {
              const primaryData = primary.load();
              if (JSON.stringify(primaryData) !== JSON.stringify(data)) {
                if (onMismatch) onMismatch({ primary: primaryData, secondary: data });
              }
            } catch (err) {
              if (onError) onError(err);
            }
          });
        }
        return data;
      } catch (err) {
        if (onError) onError(err);
        return primary.load(); // DynamoDB read failed — fall back, don't throw
      }
    }

    const data = primary.load();
    if (shadowRead && secondary.load) {
      setImmediate(() => {
        try {
          const shadow = secondary.load();
          if (JSON.stringify(shadow) !== JSON.stringify(data)) {
            if (onMismatch) onMismatch({ primary: data, secondary: shadow });
          }
        } catch (err) {
          if (onError) onError(err);
        }
      });
    }
    return data;
  }

  function save(data) {
    primary.save(data);
    try {
      secondary.save(data);
    } catch (err) {
      if (onError) onError(err);
    }
  }

  function flush() {
    const primaryFlush = Promise.resolve(primary.flush ? primary.flush() : undefined);
    const secondaryFlush = Promise.resolve()
      .then(() => (secondary.flush ? secondary.flush() : undefined))
      .catch(err => { if (onError) onError(err); });
    return Promise.all([primaryFlush, secondaryFlush]);
  }

  return { init, load, save, flush };
}

module.exports = { createDualWriteStore };
