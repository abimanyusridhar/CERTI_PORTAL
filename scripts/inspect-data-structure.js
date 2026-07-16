#!/usr/bin/env node
'use strict';

/**
 * Read-only migration readiness inspector.
 *
 * Reports collection sizes, observed fields, basic ID quality, and target-table
 * estimates without printing certificate, user, email, or vessel record values.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TENANT_ID = process.env.TENANT_ID || '';

const COLLECTIONS = [
  { file: 'certificates.json', label: 'cstCertificates', target: 'certificates(type=CST)' },
  { file: 'vapt_certificates.json', label: 'vaptCertificates', target: 'certificates(type=VAPT)' },
  { file: 'documents.json', label: 'documents', target: 'documents' },
  { file: 'users.json', label: 'users', target: 'users' },
  { file: 'groups.json', label: 'groups', target: 'groups' },
  { file: 'doc_access_requests.json', label: 'docAccessRequests', target: 'legacy_doc_access_requests' },
  { file: 'tracking_events.json', label: 'trackingEvents', target: 'audit_events/source=tracking' },
];

function candidatePath(file) {
  const tenantPath = TENANT_ID ? path.join(ROOT, 'data', TENANT_ID, file) : null;
  if (tenantPath && fs.existsSync(tenantPath)) return tenantPath;
  const rootPath = path.join(ROOT, 'data', file);
  if (fs.existsSync(rootPath)) return rootPath;
  return tenantPath || rootPath;
}

function readJson(filePath) {
  if (!fs.existsSync(filePath)) return { ok: false, missing: true, records: [], raw: null };
  try {
    const raw = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
    const parsed = JSON.parse(raw);
    const records = Array.isArray(parsed) ? parsed : Object.values(parsed || {});
    return { ok: true, missing: false, records, raw: parsed };
  } catch (err) {
    return { ok: false, missing: false, error: err.message, records: [], raw: null };
  }
}

function uniqueSorted(values) {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function summarizeCollection(def) {
  const filePath = candidatePath(def.file);
  const result = readJson(filePath);
  const records = result.records.filter(v => v && typeof v === 'object');
  const fields = uniqueSorted(records.flatMap(record => Object.keys(record)));
  const ids = records.map(record => record.id).filter(Boolean);
  const uniqueIds = new Set(ids);

  return {
    label: def.label,
    file: path.relative(ROOT, filePath).replace(/\\/g, '/'),
    target: def.target,
    status: result.missing ? 'missing' : result.ok ? 'ok' : 'invalid_json',
    records: records.length,
    fields,
    idQuality: {
      missingId: records.length - ids.length,
      duplicateId: ids.length - uniqueIds.size,
    },
  };
}

function countNested(records, field) {
  return records.reduce((total, record) => total + (Array.isArray(record[field]) ? record[field].length : 0), 0);
}

function loadRecords(file) {
  return readJson(candidatePath(file)).records.filter(v => v && typeof v === 'object');
}

function buildTargetEstimate() {
  const cst = loadRecords('certificates.json');
  const vapt = loadRecords('vapt_certificates.json');
  const docs = loadRecords('documents.json');
  const users = loadRecords('users.json');
  const groups = loadRecords('groups.json');
  const accessRequests = loadRecords('doc_access_requests.json');
  const trackingEvents = loadRecords('tracking_events.json');

  return {
    tenants: TENANT_ID ? 1 : 0,
    certificates: cst.length + vapt.length,
    certificateAttachments: countNested(cst, 'attachments') + countNested(vapt, 'attachments'),
    certificateEngagementEvents: countNested(cst, 'engagement') + countNested(vapt, 'engagement'),
    documents: docs.length,
    users: users.length,
    groups: groups.length,
    groupVessels: countNested(groups, 'vesselIMOs'),
    legacyDocAccessRequests: accessRequests.length,
    trackingEvents: trackingEvents.length,
  };
}

function main() {
  const summaries = COLLECTIONS.map(summarizeCollection);
  const output = {
    generatedAt: new Date().toISOString(),
    tenantId: TENANT_ID || null,
    sourceRoot: path.relative(process.cwd(), path.join(ROOT, 'data')) || 'data',
    collections: summaries,
    targetEstimate: buildTargetEstimate(),
    notes: [
      'Read-only report. No source files were changed.',
      'Field names are reported, but record values are intentionally omitted.',
      'Use this before database migration dry-runs to detect shape drift.',
    ],
  };

  console.log(JSON.stringify(output, null, 2));
}

main();
