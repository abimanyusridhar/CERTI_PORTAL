'use strict';

const fs = require('fs');

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

function createJsonStore({ filePath, seedData, onError, debounceMs = 50 }) {
  let cache = null;
  let timer = null;

  function load() {
    if (cache) return cache;
    try {
      if (fs.existsSync(filePath)) {
        let raw = fs.readFileSync(filePath, 'utf8');
        if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1); // strip UTF-8 BOM
        cache = JSON.parse(raw);
        return cache;
      }
    } catch {
      // fall through to seed
    }
    cache = { ...seedData };
    save(cache);
    return cache;
  }

  function save(data) {
    cache = data;
    clearTimeout(timer);
    timer = setTimeout(() => {
      writeFileAtomic(filePath, JSON.stringify(data, null, 2))
        .catch((err) => onError && onError(err));
    }, debounceMs);
  }

  function flush() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (!cache) return Promise.resolve();
    try { writeFileAtomicSync(filePath, JSON.stringify(cache, null, 2)); } catch (e) { if (onError) onError(e); }
    return Promise.resolve();
  }

  return { load, save, flush };
}

module.exports = { createJsonStore };
