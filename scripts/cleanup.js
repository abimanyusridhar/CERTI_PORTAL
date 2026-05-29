#!/usr/bin/env node
/**
 * scripts/cleanup.js — Production maintenance utility
 *
 * Usage:
 *   node scripts/cleanup.js            — dry-run (shows what would be removed)
 *   node scripts/cleanup.js --fix      — actually delete orphaned uploads
 *   node scripts/cleanup.js --logs 30  — trim log files older than 30 days
 *   node scripts/cleanup.js --fix --logs 30  — do both
 *
 * What it does:
 *   1. Finds upload files (cert_*.pdf/png, vapt_*.pdf, cst_attach_*, DOC-*)
 *      that are not referenced by any certificate or document in data/
 *   2. Flags 64-byte or 0-byte "dummy" files regardless of reference status
 *   3. Optionally trims tracking_events.jsonl and email_log.jsonl to a
 *      rolling window (default 90 days)
 *
 * Safety rules:
 *   • Never deletes anything from data/  (only log trimming with --logs)
 *   • Never deletes uploads/.gitkeep
 *   • Requires --fix to actually change anything (default is dry-run)
 *   • Prints every action before taking it
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const ROOT       = path.join(__dirname, '..');
const DATA_DIR   = path.join(ROOT, 'data');
const UPLOADS    = path.join(ROOT, 'uploads');
const FIX        = process.argv.includes('--fix');
const LOGS_IDX   = process.argv.indexOf('--logs');
const LOG_DAYS   = LOGS_IDX >= 0 ? parseInt(process.argv[LOGS_IDX + 1] || '90', 10) : null;
const TENANT_ID  = process.env.TENANT_ID || null;

// ── Helpers ──────────────────────────────────────────────────────────────────
function colour(code, s) { return `\x1b[${code}m${s}\x1b[0m`; }
const red    = s => colour(31, s);
const yellow = s => colour(33, s);
const green  = s => colour(32, s);
const dim    = s => colour(2,  s);

let deleted = 0, skipped = 0, trimmed = 0;

function safeDelete(fp) {
  if (!fp.startsWith(UPLOADS + path.sep)) {
    console.error(red('BLOCKED: will not delete outside uploads/: ' + fp));
    return;
  }
  if (FIX) {
    try { fs.unlinkSync(fp); deleted++; console.log(red('  DELETED ') + fp); }
    catch (e) { console.error(red('  ERROR   ') + fp + ' — ' + e.message); }
  } else {
    skipped++;
    console.log(yellow('  DRY-RUN ') + fp);
  }
}

function walkUploads(dir, rel = '') {
  const result = [];
  for (const f of fs.readdirSync(dir)) {
    const abs  = path.join(dir, f);
    const relF = rel ? rel + '/' + f : f;
    if (fs.statSync(abs).isDirectory()) { result.push(...walkUploads(abs, relF)); continue; }
    if (f === '.gitkeep') continue;
    result.push({ abs, rel: relF, size: fs.statSync(abs).size });
  }
  return result;
}

function loadRefs() {
  const refs = new Set();

  function addFromCerts(filePath) {
    if (!fs.existsSync(filePath)) return;
    try {
      const certs = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      for (const c of Object.values(certs)) {
        if (c.certificateImage) refs.add(c.certificateImage.replace(/^\/uploads\//, ''));
        for (const a of (c.attachments || [])) {
          if (a.url) refs.add(a.url.replace(/^\/uploads\//, ''));
        }
      }
    } catch { /* skip unreadable */ }
  }

  function addFromDocs(filePath) {
    if (!fs.existsSync(filePath)) return;
    try {
      const docs = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      for (const d of Object.values(docs)) {
        if (d.fileUrl) refs.add(d.fileUrl.replace(/^\/uploads\//, ''));
      }
    } catch { /* skip unreadable */ }
  }

  // Default (no tenant) data
  addFromCerts(path.join(DATA_DIR, 'certificates.json'));
  addFromCerts(path.join(DATA_DIR, 'vapt_certificates.json'));
  addFromDocs(path.join(DATA_DIR, 'documents.json'));

  // All tenant sub-directories
  if (fs.existsSync(DATA_DIR)) {
    for (const entry of fs.readdirSync(DATA_DIR)) {
      const sub = path.join(DATA_DIR, entry);
      if (!fs.statSync(sub).isDirectory()) continue;
      const tid = entry;
      addFromCerts(path.join(sub, 'certificates.json'));
      addFromCerts(path.join(sub, 'vapt_certificates.json'));
      addFromDocs(path.join(sub, 'documents.json'));

      // Tenant uploads live under uploads/<TENANT_ID>/
      // Refs stored as relative to their own uploads dir — rebase them
      // (the server stores e.g. "/uploads/SYNCERT/cert_xxx.pdf")
      // so the ref is already "SYNCERT/cert_xxx.pdf" after strip
    }
  }

  return refs;
}

// ── Phase 1: orphaned upload files ───────────────────────────────────────────
console.log('\n' + colour(1, '=== Orphaned Upload Files ==='));
console.log(dim(FIX ? '(--fix mode: will delete)' : '(dry-run: pass --fix to delete)\n'));

const refs  = loadRefs();
const files = walkUploads(UPLOADS);

const orphans  = [];
const dummies  = [];

for (const f of files) {
  const isDummy   = f.size <= 100; // 64-byte test files; real certs are 400KB+
  const isOrphan  = !refs.has(f.rel);

  if (isDummy && isOrphan) {
    dummies.push(f);
  } else if (isOrphan) {
    orphans.push(f);
  }
}

if (dummies.length === 0 && orphans.length === 0) {
  console.log(green('  ✔ No orphaned uploads found.'));
} else {
  if (dummies.length) {
    console.log(colour(1, '\nDummy / stub files (≤100 B, not in any certificate):'));
    for (const f of dummies) {
      console.log(dim(`  ${String(f.size).padStart(6)}B`) + '  ' + f.rel);
      safeDelete(f.abs);
    }
  }
  if (orphans.length) {
    console.log(colour(1, '\nOrphaned uploads (not referenced by any certificate or document):'));
    for (const f of orphans) {
      const kb = (f.size / 1024).toFixed(0);
      console.log(yellow(`  ${kb.padStart(7)}KB`) + '  ' + f.rel);
      safeDelete(f.abs);
    }
  }
}

// ── Phase 2: log trimming ─────────────────────────────────────────────────────
if (LOG_DAYS !== null) {
  console.log('\n' + colour(1, `=== Log Trimming (keeping last ${LOG_DAYS} days) ===`));
  const cutoff = Date.now() - LOG_DAYS * 24 * 60 * 60 * 1000;

  const logFiles = [
    path.join(DATA_DIR, 'tracking_events.jsonl'),
    path.join(DATA_DIR, 'email_log.jsonl'),
    ...(TENANT_ID ? [
      path.join(DATA_DIR, TENANT_ID, 'tracking_events.jsonl'),
      path.join(DATA_DIR, TENANT_ID, 'email_log.jsonl'),
    ] : []),
  ];

  for (const lf of logFiles) {
    if (!fs.existsSync(lf)) continue;
    const lines  = fs.readFileSync(lf, 'utf8').trim().split('\n').filter(Boolean);
    const before = lines.length;
    const kept   = lines.filter(l => {
      try { const ts = JSON.parse(l).ts || JSON.parse(l).timestamp || JSON.parse(l).t; return !ts || new Date(ts).getTime() >= cutoff; }
      catch { return true; } // keep unparseable lines
    });
    const removed = before - kept.length;
    if (removed === 0) {
      console.log(green('  ✔ Nothing to trim: ') + path.relative(ROOT, lf));
      continue;
    }
    console.log(yellow(`  ${removed} old entries → `) + path.relative(ROOT, lf));
    if (FIX) {
      fs.writeFileSync(lf, kept.join('\n') + '\n', 'utf8');
      trimmed += removed;
      console.log(green('    Written: ') + kept.length + ' entries kept');
    } else {
      console.log(dim('    (dry-run — pass --fix to write)'));
    }
  }
}

// ── Summary ───────────────────────────────────────────────────────────────────
console.log('\n' + colour(1, '=== Summary ==='));
if (FIX) {
  console.log(green(`  Deleted:  ${deleted} file(s)`));
  if (LOG_DAYS !== null) console.log(green(`  Trimmed:  ${trimmed} log entries`));
} else {
  console.log(yellow(`  Would delete: ${skipped} file(s) (run with --fix to proceed)`));
  if (LOG_DAYS !== null) console.log(dim('  Log trim: add --fix to apply'));
}
console.log();
