'use strict';

const fs = require('fs');

function createJsonStore({ filePath, seedData, onError, debounceMs = 50 }) {
  let cache = null;
  let timer = null;

  function load() {
    if (cache) return cache;
    try {
      if (fs.existsSync(filePath)) {
        cache = JSON.parse(fs.readFileSync(filePath, 'utf8'));
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
      fs.promises.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8')
        .catch((err) => onError && onError(err));
    }, debounceMs);
  }

  function flush() {
    if (!timer) return;
    clearTimeout(timer);
    timer = null;
    if (!cache) return;
    fs.writeFileSync(filePath, JSON.stringify(cache, null, 2), 'utf8');
  }

  return { load, save, flush };
}

module.exports = { createJsonStore };
