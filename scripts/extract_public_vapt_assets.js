/* eslint-disable no-console */
const fs = require('fs');
const path = require('path');

const htmlPath = path.join(__dirname, '..', 'public', 'vapt-index.html');
let html = fs.readFileSync(htmlPath, 'utf8');

const cssOutRel = path.join('public', 'assets', 'smg-public', 'vapt', 'index.css');
const jsOutRel = path.join('public', 'assets', 'smg-public', 'vapt', 'index.js');
const cssOutPath = path.join(__dirname, '..', cssOutRel);
const jsOutPath = path.join(__dirname, '..', jsOutRel);

fs.mkdirSync(path.dirname(cssOutPath), { recursive: true });
fs.mkdirSync(path.dirname(jsOutPath), { recursive: true });

// 1) Extract first <style>...</style>
const cssMatch = html.match(/<style>([\s\S]*?)<\/style>/);
if (!cssMatch) throw new Error('CSS <style> block not found in public/vapt-index.html');
const css = cssMatch[1];
fs.writeFileSync(cssOutPath, css, 'utf8');

// 2) Replace <style>...</style> with <link>
html = html.replace(
  /<style>[\s\S]*?<\/style>/,
  '<link rel="stylesheet" href="/assets/smg-public/vapt/index.css" />',
);

// 3) Extract main inline <script> immediately after the Cloudflare email-decode script.
const emailScriptMatch = html.match(
  /(<script[^>]*data-cfasync="false"[^>]*email-decode\.min\.js[^>]*><\/script>)(?:\s*|\n|\r)*<script>([\s\S]*?)<\/script>/,
);
if (!emailScriptMatch) {
  throw new Error('Email-decode script + following inline <script> not found in public/vapt-index.html');
}

const emailTag = emailScriptMatch[1];
const js = emailScriptMatch[2];
fs.writeFileSync(jsOutPath, js, 'utf8');

// 4) Replace the email-decode + inline script pair with email-decode + external script
html = html.replace(
  /<script[^>]*data-cfasync="false"[^>]*email-decode\.min\.js[^>]*><\/script>\s*<script>[\s\S]*?<\/script>/,
  `${emailTag}<script src="/assets/smg-public/vapt/index.js"></script>`,
);

fs.writeFileSync(htmlPath, html, 'utf8');
console.log('Extracted VAPT assets', { cssOutRel, jsOutRel });

