'use strict';
(function() {
  const API = '/api';
  let TOKEN = sessionStorage.getItem('adminToken') || '';
  let allDocs = [];
  let _confirmCb = null;

  // ── SESSION MANAGEMENT (page-wide idle/expiry banners) ──────────────
  const SESSION_MAX_MS   = 8 * 60 * 60 * 1000;
  const SESSION_WARN_MS  = 5 * 60 * 1000;
  const IDLE_WARN_MS     = 28 * 60 * 1000;
  const IDLE_OUT_MS      = 30 * 60 * 1000;
  let _sessionStart = Date.now();
  let _lastActivity = Date.now();

  function resetIdle() {
    _lastActivity = Date.now();
    document.getElementById('idleWarningBanner').style.display = 'none';
  }
  function refreshSession() {
    _sessionStart = Date.now();
    document.getElementById('sessionWarningBanner').style.display = 'none';
  }
  window.resetIdle = resetIdle;
  window.refreshSession = refreshSession;
  ['click','keydown','mousemove','touchstart'].forEach(e => document.addEventListener(e, resetIdle, { passive: true }));

  function tickSession() {
    const remaining = SESSION_MAX_MS - (Date.now() - _sessionStart);
    const idle      = Date.now() - _lastActivity;
    const swb = document.getElementById('sessionWarningBanner');
    const iwb = document.getElementById('idleWarningBanner');
    const sc  = document.getElementById('sessionCountdown');
    const ic  = document.getElementById('idleCountdown');
    if (remaining <= 0 || idle >= IDLE_OUT_MS) { window.doLogout(); return; }
    if (remaining <= SESSION_WARN_MS) {
      swb.style.display = 'block';
      const m = Math.ceil(remaining / 60000);
      if (sc) sc.textContent = m + ' minute' + (m !== 1 ? 's' : '');
    } else { swb.style.display = 'none'; }
    if (idle >= IDLE_WARN_MS) {
      iwb.style.display = 'block';
      const m = Math.ceil((IDLE_OUT_MS - idle) / 60000);
      if (ic) ic.textContent = m + ' minute' + (m !== 1 ? 's' : '');
    } else { iwb.style.display = 'none'; }
  }
  setInterval(tickSession, 30000);

  const authHdr = () => ({ Authorization: 'Bearer ' + TOKEN });
  function checkUnauth(r) { if (r.status === 401) { window.doLogout(); return true; } return false; }

  async function loadDocsData() {
    const loadingHtml = '<div style="text-align:center;padding:40px;color:var(--text-sec);font-size:.78rem">Loading…</div>';
    document.getElementById('docsTableBody').innerHTML = loadingHtml;
    try {
      const docsRes = await fetch(API + '/docs', { headers: authHdr() });
      if (checkUnauth(docsRes)) return;
      if (docsRes.ok) allDocs = await docsRes.json();
    } catch { toast('Failed to load data', true); }
    renderDocs();
    updateBadges();
    updateDocStats();
  }
  window.loadDocsData = loadDocsData;

  function updateBadges() {
    const b = document.getElementById('badgeDocsTab');
    if (b) b.textContent = allDocs.length;
  }

  function updateDocStats() {
    const totalEl = document.getElementById('dStatTotal');
    const vesselsEl = document.getElementById('dStatVessels');
    const sizeEl = document.getElementById('dStatSize');
    if (!totalEl) return;
    totalEl.textContent = allDocs.length;
    vesselsEl.textContent = new Set(allDocs.map(d => d.vesselIMO).filter(Boolean)).size;
    const totalBytes = allDocs.reduce((sum, d) => sum + (d.fileSize || 0), 0);
    sizeEl.textContent = totalBytes > 1048576 ? (totalBytes / 1048576).toFixed(1) + ' MB' : (totalBytes / 1024).toFixed(0) + ' KB';
  }

  function onFileSelect(input) {
    const f = input.files[0];
    const sel = document.getElementById('fileSelected');
    sel.textContent = f ? `${f.name} (${(f.size / 1024).toFixed(1)} KB)` : '';
  }
  window.onFileSelect = onFileSelect;

  const drop = document.getElementById('fileDrop');
  if (drop) {
    drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('drag-over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('drag-over'));
    drop.addEventListener('drop', e => {
      e.preventDefault();
      drop.classList.remove('drag-over');
      const fi = document.getElementById('fileInput');
      fi.files = e.dataTransfer.files;
      onFileSelect(fi);
    });
  }

  async function uploadDoc() {
    const imo    = document.getElementById('uImo').value.trim();
    const vessel = document.getElementById('uVessel').value.trim();
    const type   = document.getElementById('uTypeValue').value;
    const certId = document.getElementById('uCertId').value.trim();
    const title  = document.getElementById('uTitle').value.trim();
    const desc   = document.getElementById('uDesc').value.trim();
    const fi     = document.getElementById('fileInput');
    const msg    = document.getElementById('uploadMsg');
    const btn    = document.getElementById('btnUpload');

    if (!imo || !vessel || !title) { toast('Vessel IMO, Vessel Name and Title are required', true); return; }
    if (!fi.files.length) { toast('Please select a file to upload', true); return; }

    const fd = new FormData();
    fd.append('vesselIMO', imo);
    fd.append('vesselName', vessel);
    fd.append('docType', type);
    fd.append('title', title);
    fd.append('description', desc);
    fd.append('linkedCertId', certId);
    fd.append('file', fi.files[0]);

    btn.disabled = true;
    msg.textContent = 'Uploading…';

    try {
      const r = await fetch(API + '/docs/upload', { method: 'POST', headers: authHdr(), body: fd });
      const d = await r.json();
      if (!r.ok) { toast(d.error || 'Upload failed', true); msg.textContent = ''; btn.disabled = false; return; }
      toast('Document uploaded successfully');
      msg.textContent = '';
      ['uImo','uVessel','uCertId','uTitle','uDesc'].forEach(id => document.getElementById(id).value = '');
      document.getElementById('fileInput').value = '';
      document.getElementById('fileSelected').textContent = '';
      await loadDocsData();
    } catch { toast('Network error', true); msg.textContent = ''; }
    btn.disabled = false;
  }
  window.uploadDoc = uploadDoc;

  function renderDocs() {
    const q    = (document.getElementById('docSearch').value || '').toLowerCase();
    const tf   = document.getElementById('docTypeFilter').value;
    const body = document.getElementById('docsTableBody');
    const IMAGE_EXTS = /\.(png|jpg|jpeg|gif|bmp|webp|tiff|svg)$/i;
    let filtered = allDocs.filter(d => {
      const mime = (d.mimeType || '').toLowerCase();
      const fname = (d.fileName || d.title || '').toLowerCase();
      if (mime.startsWith('image/') || IMAGE_EXTS.test(fname)) return false;
      const match = !q || (d.vesselName||'').toLowerCase().includes(q) || (d.vesselIMO||'').toLowerCase().includes(q) || (d.title||'').toLowerCase().includes(q);
      const tMatch = !tf || d.docType === tf;
      return match && tMatch;
    });
    document.getElementById('docsCount').textContent = filtered.length + ' document' + (filtered.length !== 1 ? 's' : '');
    if (!filtered.length) {
      const hasFilters = q || tf;
      const emptyMsg = hasFilters ? 'No documents match the current filter.' : 'No documents uploaded yet. Use the form above to upload the first document.';
      body.innerHTML = `<div class="empty-state"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg><p style="margin-top:10px">${emptyMsg}</p></div>`;
      return;
    }
    const escH = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
    const typeBadge = t => {
      const m = { TRAINING_REPORT: ['badge-training','Training Report'], DRILL_REPORT: ['badge-drill','Drill Report'], AUDIT_REPORT: ['badge-audit','Audit Report'], CERT_ATTACHMENT: ['badge-audit','Certificate Attachment'], OTHER: ['badge-other','Other'] };
      const [cls, lbl] = m[t] || m.OTHER;
      return `<span class="doc-type-badge ${cls}">${lbl}</span>`;
    };
    const fmtSize = b => b > 1048576 ? (b/1048576).toFixed(1)+' MB' : (b/1024).toFixed(0)+' KB';
    const fmtDt = s => s ? new Date(s).toLocaleDateString('en-GB', {day:'2-digit',month:'short',year:'numeric'}) : '—';
    const docIcon = (mime, name) => {
      const m = (mime||'').toLowerCase(); const n = (name||'').toLowerCase();
      if (m === 'application/pdf' || n.endsWith('.pdf')) return ['pdf', `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>`];
      if (m.startsWith('image/')) return ['img', `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>`];
      if (m.includes('excel') || m.includes('spreadsheet') || n.match(/\.xlsx?$/)) return ['xls', `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>`];
      if (m.includes('word') || n.match(/\.docx?$/)) return ['doc', `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>`];
      return ['other', `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"/></svg>`];
    };
    body.innerHTML = `<div class="doc-card-grid">${filtered.map(d => {
      const safeId = escH(d.id);
      const [iconCls, iconSvg] = docIcon(d.mimeType, d.fileName);
      const canDelete = !d.isCertificateAttachment;
      return `<div class="doc-card">
        <div class="doc-card-top">
          <div class="doc-icon ${iconCls}">${iconSvg}</div>
          <div class="doc-card-info">
            <div class="doc-card-title" title="${escH(d.title)}">${escH(d.title)}</div>
            <div class="doc-card-vessel">
              <span>${escH(d.vesselName||'—')}</span>
              ${d.vesselIMO ? `<span class="imo-chip">${escH(d.vesselIMO)}</span>` : ''}
            </div>
            <div class="doc-card-meta">
              ${typeBadge(d.docType)}
              <span style="font-size:.62rem;color:var(--text-sec)">${fmtSize(d.fileSize||0)}</span>
              <span style="font-size:.62rem;color:var(--text-sec)">${fmtDt(d.uploadedAt)}</span>
              ${d.linkedCertId ? `<span style="font-family:'JetBrains Mono',monospace;font-size:.58rem;color:var(--gold);background:rgba(212,168,67,.08);padding:1px 6px;border-radius:4px;border:1px solid rgba(212,168,67,.25)">${escH(d.linkedCertId)}</span>` : ''}
            </div>
          </div>
        </div>
        ${d.description ? `<div style="font-size:.72rem;color:var(--text-sec);line-height:1.55;padding:0 2px">${escH(d.description)}</div>` : ''}
        <div class="doc-card-actions">
          <button class="btn-open" id="btnOpen_${safeId}" data-action="openDocDirect" data-id="${safeId}">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
            Open
          </button>
          <button class="btn-sm teal" data-action="copyDocLink" data-id="${safeId}" title="Copy shareable link for superintendents">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"/></svg>
            Share Link
          </button>
          ${canDelete ? `<button class="btn-sm danger" data-action="deleteDoc" data-id="${safeId}" data-title="${escH(d.title)}" style="margin-left:auto">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            Delete
          </button>` : `<span style="margin-left:auto;font-size:.62rem;color:var(--text-sec)">Managed from certificate</span>`}
        </div>
      </div>`;
    }).join('')}</div>`;
  }
  window.renderDocs = renderDocs;

  async function openDocDirect(id, btn) {
    const orig = btn ? btn.innerHTML : '';
    if (btn) { btn.disabled = true; btn.textContent = '…'; }
    try {
      const r = await fetch(`/api/docs/temp-link/${id}`, { headers: authHdr() });
      if (!r.ok) { toast('Could not generate link: ' + ((await r.json()).error || r.status), true); return; }
      const { url } = await r.json();
      window.open(url, '_blank');
    } catch { toast('Open failed — check connection', true); }
    if (btn) { btn.disabled = false; btn.innerHTML = orig; }
  }
  window.openDocDirect = openDocDirect;

  async function copyDocLink(id, btn) {
    const orig = btn ? btn.innerHTML : '';
    if (btn) { btn.disabled = true; }
    try {
      const r = await fetch(`/api/docs/temp-link/${id}`, { headers: authHdr() });
      if (!r.ok) { toast('Could not generate link', true); return; }
      const { url } = await r.json();
      await navigator.clipboard.writeText(url);
      toast('Shareable link copied — valid for 24 hours. Send to superintendent.');
    } catch { toast('Copy failed', true); }
    if (btn) { btn.disabled = false; btn.innerHTML = orig; }
  }
  window.copyDocLink = copyDocLink;

  async function deleteDoc(id, title) {
    openConfirm(`Delete "${title}"?`, 'This will permanently delete the document file. This action cannot be undone.', async () => {
      try {
        const r = await fetch(API + '/docs/' + id, { method: 'DELETE', headers: authHdr() });
        if (!r.ok) { toast((await r.json()).error || 'Delete failed', true); return; }
        toast('Document deleted');
        await loadDocsData();
      } catch { toast('Network error', true); }
    });
  }
  window.deleteDoc = deleteDoc;

  function openConfirm(title, body, cb) {
    document.getElementById('confirmTitle').textContent = title;
    document.getElementById('confirmBody').textContent = body;
    _confirmCb = cb;
    document.getElementById('confirmModal').classList.add('show');
  }
  function closeConfirm() { document.getElementById('confirmModal').classList.remove('show'); _confirmCb = null; }
  window.closeConfirm = closeConfirm;
  document.getElementById('confirmOk').addEventListener('click', () => { if (_confirmCb) _confirmCb(); closeConfirm(); });
  document.getElementById('confirmModal').addEventListener('click', e => { if (e.target === document.getElementById('confirmModal')) closeConfirm(); });

  function toast(msg, isErr) {
    const el = document.createElement('div');
    el.className = 'toast-msg ' + (isErr ? 'err' : 'ok');
    el.textContent = msg;
    document.getElementById('toast').appendChild(el);
    setTimeout(() => el.remove(), 3500);
  }

  (function initFromUrl() {
    const sp = new URLSearchParams(window.location.search);
    const imo    = sp.get('imo')    || '';
    const vessel = sp.get('vessel') || '';
    if (imo)    { const el = document.getElementById('uImo');    if (el) el.value = imo;    }
    if (vessel) { const el = document.getElementById('uVessel'); if (el) el.value = vessel; }
  })();

  if (TOKEN) loadDocsData();
})();
