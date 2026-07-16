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
 *
 * The secondary write/read is always fire-and-forget: a secondary failure
 * is reported via onError/onMismatch but never blocks, delays, or rolls
 * back the primary path (mirrors the existing disk-doesn't-block-S3 split
 * in s3JsonStore.save).
 */

function createDualWriteStore({ primary, secondary, onError, onMismatch, shadowRead = false }) {
  async function init() {
    if (primary.init) await primary.init();
    if (secondary.init) {
      try { await secondary.init(); } catch (err) { if (onError) onError(err); }
    }
  }

  function load() {
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
