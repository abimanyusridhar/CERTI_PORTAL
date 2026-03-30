/* eslint-disable no-console */
const fs = require('fs');
const path = require('path');

const htmlPath = path.join(__dirname, '..', 'admin', 'dashboard.html');
let html = fs.readFileSync(htmlPath, 'utf8');

const cssOutRel = path.join('public', 'assets', 'smg-admin', 'cst', 'dashboard.css');
const jsOutRel = path.join('public', 'assets', 'smg-admin', 'cst', 'dashboard.js');
const cssOutPath = path.join(__dirname, '..', cssOutRel);
const jsOutPath = path.join(__dirname, '..', jsOutRel);

fs.mkdirSync(path.dirname(cssOutPath), { recursive: true });
fs.mkdirSync(path.dirname(jsOutPath), { recursive: true });

// 1) Extract first <style>...</style>
const cssMatch = html.match(/<style>([\s\S]*?)<\/style>/);
if (!cssMatch) throw new Error('Admin CST CSS <style> block not found');
const css = cssMatch[1];
fs.writeFileSync(cssOutPath, css, 'utf8');

// 2) Replace <style>...</style> with <link>
html = html.replace(
  /<style>[\s\S]*?<\/style>/,
  '<link rel="stylesheet" href="/assets/smg-admin/cst/dashboard.css" />',
);

// 3) Merge all inline (no-src) <script>...</script> blocks at the end.
// We intentionally only capture <script> blocks with *no attributes* (i.e., literal "<script>").
const inlineMatches = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
if (inlineMatches.length === 0) throw new Error('No inline <script> blocks found to extract');

const js = inlineMatches.map(m => m[1]).join('\n');
fs.writeFileSync(jsOutPath, js, 'utf8');

// 4) Replace the entire region from first inline <script> to the end of last inline <script>
// with a single <script src> tag.
const first = inlineMatches[0];
const last = inlineMatches[inlineMatches.length - 1];
const start = first.index;
const end = last.index + last[0].length;

html = html.slice(0, start) + `<script src="/assets/smg-admin/cst/dashboard.js"></script>` + html.slice(end);
fs.writeFileSync(htmlPath, html, 'utf8');

console.log('Extracted admin CST assets', { cssOutRel, jsOutRel });

