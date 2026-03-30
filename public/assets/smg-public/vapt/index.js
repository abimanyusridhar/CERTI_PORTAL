
  'use strict';
  const API = '/api';

  // HTML-escape helper — prevents XSS when inserting server data into innerHTML
  function escH(s) {
    if (s == null) return '—';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  // Stats — initial fetch + auto-refresh every 60 s
  function animateNum(el, to) {
    if (!el) return;
    const from = parseInt(el.textContent) || 0;
    if (from === to) return;
    el.classList.add('updating');
    const dur = 600, start = performance.now();
    const ease = t => t < .5 ? 2*t*t : -1+(4-2*t)*t;
    const tick = now => {
      const p = Math.min((now - start) / dur, 1);
      el.textContent = Math.round(from + (to - from) * ease(p));
      if (p < 1) requestAnimationFrame(tick);
      else { el.textContent = to; setTimeout(() => el.classList.remove('updating'), 200); }
    };
    requestAnimationFrame(tick);
  }

  function hideDesc() { const d = document.getElementById('descBlock'); if (d) d.style.display = 'none'; }
  function showDesc() { const d = document.getElementById('descBlock'); if (d) d.style.display = ''; }

  function fmt(d) {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  }
  function fmtLong(d) {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
  }

  function scroll() { document.getElementById('result').scrollIntoView({ behavior: 'smooth', block: 'start' }); }

  // Cached shareable URL for the last-verified cert (populated after each verify)
  let _lastShareUrl = null;
  let _verifying = false; // debounce guard

  async function verify() {
    if (_verifying) return;
    const raw = document.getElementById('certInput').value.trim().toUpperCase();
    if (!raw) return;
    if (!/^[A-Za-z0-9\-_]{1,64}$/.test(raw)) {
      document.getElementById('result').innerHTML = '<div class="not-found"><svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.5" style="margin:0 auto 10px"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg><h3 style="color:var(--warn)">Invalid Format</h3><p>Certificate IDs may only contain letters, numbers, and hyphens (e.g. <code style="font-family:\'JetBrains Mono\',monospace;color:var(--teal)">VAP-9491666-1026</code>).</p></div>';
      hideDesc(); scroll(); return;
    }
    const btn = document.getElementById('verifyBtn');
    const input = document.getElementById('certInput');
    _verifying = true;
    btn.disabled = true;
    input.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Verifying&hellip;';
    _lastShareUrl = null;
    const ctrl = new AbortController();
    const _timeout = setTimeout(() => ctrl.abort(), 12_000);
    try {
      const res = await fetch(API + '/vapt/verify-by-id/' + encodeURIComponent(raw), { signal: ctrl.signal });
      clearTimeout(_timeout);
      if (res.status === 429) {
        const retryAfter = parseInt(res.headers.get('Retry-After') || '60', 10);
        renderRateLimit(retryAfter);
        hideDesc(); scroll();
      } else {
        // Safe JSON parse — a reverse proxy (Nginx/Cloudflare) returning an HTML
        // error page on 502/503/504 would cause res.json() to throw a SyntaxError,
        // which the outer catch turns into "Server Unavailable" even when Node is
        // healthy and the certificate number is valid. Parse separately first.
        let data = {};
        try { data = await res.json(); } catch { /* non-JSON proxy response */ }
        hideDesc();
        if (res.status === 404) {
          renderNotFound();
          history.pushState(null, '', (window.APP_CONFIG ? window.APP_CONFIG.routes.vpt : '/VPT'));
        } else if (!res.ok) {
          renderError(data.error);
          history.pushState(null, '', (window.APP_CONFIG ? window.APP_CONFIG.routes.vpt : '/VPT'));
        } else {
          // Fetch the encrypted, shareable verification URL from the server
          let shareUrl = window.location.href;
          try {
            const urlCtrl = new AbortController();
            const _urlTimeout = setTimeout(() => urlCtrl.abort(), 8_000);
            const ur = await fetch(API + '/vapt/public-cert-url/' + encodeURIComponent(raw), { signal: urlCtrl.signal });
            clearTimeout(_urlTimeout);
            if (ur.ok) { const ud = await ur.json(); if (ud.url) shareUrl = ud.url; }
          } catch { /* fallback to current URL */ }
          _lastShareUrl = shareUrl;
          renderCert(data);
          history.replaceState({ certId: raw }, '', shareUrl);
        }
      }
    } catch (e) { clearTimeout(_timeout); renderError(e && e.name === 'AbortError' ? 'Request timed out. Please try again.' : undefined); }
    _verifying = false;
    btn.disabled = false;
    input.disabled = false;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg> Verify';
  }

  // Rate limit countdown
  let _rlTimer = null;
  function renderRateLimit(seconds) {
    if (_rlTimer) clearInterval(_rlTimer);
    let remaining = seconds || 60;
    const _email = (window.APP_CONFIG && window.APP_CONFIG.contact) ? window.APP_CONFIG.contact.vaptEmail : '';
    function update() {
      document.getElementById('result').innerHTML = `
      <div style="display:flex;align-items:center;gap:14px;padding:20px 24px;background:rgba(255,179,71,0.05);border:1px solid rgba(255,179,71,0.28);border-radius:14px;animation:fadeUp .4s ease" role="alert">
        <div style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;font-weight:700;color:var(--warn);line-height:1;min-width:36px;text-align:center" aria-live="polite" aria-atomic="true">${remaining}</div>
        <div>
          <div style="font-size:.82rem;font-weight:700;color:var(--warn);margin-bottom:3px">Too Many Requests</div>
          <div style="font-size:.74rem;color:var(--text-sec);line-height:1.6">Verification limit reached. You can retry in <strong>${remaining} second${remaining===1?'':'s'}</strong>.${_email ? ` For urgent queries contact <strong style="color:var(--teal)">${_email}</strong>` : ''}</div>
        </div>
      </div>`;
    }
    update();
    scroll();
    _rlTimer = setInterval(() => {
      remaining--;
      if (remaining <= 0) { clearInterval(_rlTimer); update(); } else { update(); }
    }, 1000);
  }

  function renderNotFound() {
    const _vaptEmail = (window.APP_CONFIG&&window.APP_CONFIG.contact)?window.APP_CONFIG.contact.vaptEmail:'';
    const _brandName = (window.APP_CONFIG&&window.APP_CONFIG.brand)?window.APP_CONFIG.brand.name:'Synergy';
    document.getElementById('result').innerHTML = `
    <div class="not-found" role="alert">
      <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="var(--invalid)" stroke-width="1.5" style="margin:0 auto" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
      <h3>Certificate Not Found</h3>
      <p>No VAPT certificate matching this ID exists in the <strong>${_brandName}</strong> registry.<br>
      Check the number carefully — IDs are case-insensitive.<br>
      For assistance contact <strong style="color:var(--teal)">${_vaptEmail || 'the VAPT team'}</strong></p>
      <div style="margin-top:16px;padding:10px 16px;background:var(--surface);border:1px solid var(--border);border-radius:10px;font-size:.72rem;color:var(--text-sec);line-height:1.7">
        <strong style="color:var(--text)">Expected format:</strong>
        <code style="font-family:'JetBrains Mono',monospace;color:var(--teal);margin-left:6px">VAP-{XXXXXX}-{XXXX}</code>
        &nbsp;·&nbsp;
        <code style="font-family:'JetBrains Mono',monospace;color:var(--teal)">VAP-XXXXX-XXXX</code>
      </div>
    </div>`;
    scroll();
  }

  function renderError(serverMsg) {
    const _vaptErrEmail = (window.APP_CONFIG && window.APP_CONFIG.contact)
      ? window.APP_CONFIG.contact.vaptEmail
      : '';
    const detail = serverMsg ? `<br><code style="font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--warn);opacity:.75">${serverMsg}</code>` : '';
    document.getElementById('result').innerHTML = `
    <div class="not-found" style="background:rgba(255,179,71,0.04);border-color:rgba(255,179,71,0.2)" role="alert">
      <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.5" style="margin:0 auto" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
      <h3 style="color:var(--warn)">Service Unavailable</h3>
      <p>Could not reach the VAPT verification service. Please try again in a moment.${detail}<br>
      If the issue persists, contact <strong style="color:var(--teal)">${_vaptErrEmail || 'the VAPT team'}</strong></p>
      <button onclick="verify()" style="margin-top:14px;padding:9px 22px;background:rgba(255,179,71,0.08);border:1px solid rgba(255,179,71,0.3);border-radius:20px;color:var(--warn);font-size:.72rem;font-weight:600;letter-spacing:.08em;cursor:pointer;text-transform:uppercase">↺ Retry</button>
    </div>`;
    scroll();
  }

  function renderCert(c) {
    // Reset email gate for new cert
    _currentCertId = c.id || '';
    _emailGateVerified = false;
    const now  = new Date(); now.setHours(0,0,0,0);
    const vu   = c.validUntil ? new Date(c.validUntil) : null;
    if (vu) vu.setHours(0,0,0,0);
    // Use server-computed effectiveStatus if available, else derive client-side
    const effectiveSt = (c.effectiveStatus || c.status || '').toUpperCase();
    const isV     = effectiveSt === 'VALID';
    const isExp   = effectiveSt === 'EXPIRED' || (!isV && (c.status || '').toUpperCase() === 'VALID' && vu && vu < now);
    const isPend  = effectiveSt === 'PENDING';
    const accent  = isV ? 'var(--teal)' : isPend ? '#7EB8F7' : isExp ? 'var(--warn)' : 'var(--invalid)';
    const badgeCls = isV ? 'badge-valid' : isPend ? 'badge-pending' : isExp ? 'badge-expired' : 'badge-invalid';
    const copyCls  = isV ? 'btn-copy-valid' : isPend ? 'btn-copy-pending' : 'btn-copy-invalid';
    const valCls   = isV ? 'val-valid' : isPend ? 'val-pending' : 'val-invalid';
    const daysLeft = vu ? Math.round((vu - now) / 86400000) : null;
    const statusLabel = isV ? 'VERIFIED &amp; VALID' : isPend ? 'PENDING' : isExp ? 'EXPIRED' : escH(effectiveSt);

    const nearExpiry = (isV && daysLeft !== null && daysLeft >= 0 && daysLeft <= 30) ? `
    <div class="near-exp">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="2" style="flex-shrink:0"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
      <div><strong>Assessment expiring ${daysLeft===0?'today':`in ${daysLeft} day${daysLeft===1?'':'s'}`}</strong> — Re-assessment recommended promptly.</div>
    </div>` : '';

    const validMsg = isV
      ? `Assessment is <strong style="color:var(--teal)">current and verified</strong> — valid until ${fmtLong(c.validUntil)}${daysLeft!==null&&daysLeft>0?` · <strong>${daysLeft} day${daysLeft===1?'':'s'}</strong> remaining`:''}`
      : isPend
      ? `This assessment is <strong style="color:#7EB8F7">registered but not yet activated</strong>. Contact the VAPT team for status updates.`
      : isExp
      ? `This assessment <strong style="color:var(--warn)">expired on ${fmtLong(c.validUntil)}</strong> and is no longer valid for compliance. Please contact the issuer for re-assessment.`
      : `This assessment is <strong style="color:var(--invalid)">${effectiveSt.toLowerCase()}</strong> and not currently valid for compliance purposes.`;

    const valIconPath = isV
      ? 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'
      : isPend
      ? 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z'
      : isExp
      ? 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z'
      : 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z';

    const valTitle = isV ? 'ASSESSMENT IS VALID &amp; AUTHENTIC' : isPend ? 'ASSESSMENT PENDING ACTIVATION' : isExp ? 'ASSESSMENT HAS EXPIRED' : 'ASSESSMENT IS NOT VALID';

    const imgBlock = c.certificateImage ? `
    <div class="cert-img-card">
      <div class="cert-img-topbar">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
        Original VAPT Certificate &mdash; Click to enlarge
      </div>
      <img src="${c.certificateImage}" alt="VAPT Certificate" data-cert-img="true" onclick="openLB(this.src)" />
    </div>` : '';

    const scopeList = (c.scopeItems || '').split(',').map(s => s.trim()).filter(Boolean);

    // Admin-attached docs only, no defaults
    const atts = Array.isArray(c.attachments) ? c.attachments : [];
    const docsBlock = buildDocsBlock(atts, c.recipientEmail || '');

    document.getElementById('result').innerHTML = `
    <div class="recipient-banner">
      <div class="recipient-banner-left">
        <div class="recipient-banner-icon">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>
        </div>
        <div>
          <div class="recipient-banner-title">VAPT Assessment Recipient View</div>
          <div class="recipient-banner-sub">${(window.APP_CONFIG&&window.APP_CONFIG.vapt)?window.APP_CONFIG.vapt.readOnlyNote:"This record is read-only · verified directly from the Synergy VAPT registry"}</div>
        </div>
      </div>
      <div class="recipient-ts">Queried: ${new Date().toUTCString()}</div>
    </div>
    <div class="cred-layout">

      <!-- SIDEBAR -->
      <div class="cred-sidebar">
        <div class="sidebar-card">
          <div class="sdlabel">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>
            Issued To
          </div>
          <div class="sdname">${escH(c.recipientName)}</div>
          <div class="sdsub">${escH(c.vesselName || '')}${c.vesselIMO ? ' · IMO ' + escH(c.vesselIMO) : ''}</div>
          <button class="btn-dl" id="dlBtn" onclick="downloadCertificate('${c.id}', this)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            Download Certificate
          </button>
          <div class="sd-contact">Want to report an error? <a href="mailto:${(window.APP_CONFIG&&window.APP_CONFIG.contact)?window.APP_CONFIG.contact.vaptEmail:''}">Contact Issuer</a></div>
        </div>

        <div class="verify-card">
          <div class="vc-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${accent}" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="${valIconPath}"/></svg>
            <span class="vc-title" style="color:${accent}">Credential Verification</span>
          </div>
          <div class="vrow">
            <div class="vrow-lbl">Assessment Date</div>
            <div class="vrow-val">${fmtLong(c.assessmentDate || c.issuedAt)}</div>
          </div>
          <div class="vrow">
            <div class="vrow-lbl">Expiration Date</div>
            <div class="vrow-val" style="${isExp ? 'color:var(--warn)' : !isV && !isPend ? 'color:var(--invalid)' : ''}">${fmtLong(c.validUntil)}</div>
          </div>
          <div class="vrow">
            <div class="vrow-lbl">Status</div>
            <span class="status-badge ${badgeCls}">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="${valIconPath}"/></svg>
              ${statusLabel}
            </span>
          </div>
          <button class="btn-copy ${copyCls}" onclick="copyVerifyLink(this)">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
            Copy Verification Link
          </button>
          <div class="vrow-lbl">Certificate ID</div>
          <div class="cert-id-mono">${c.id}</div>
        </div>
      </div>

      <!-- MAIN -->
      <div class="cred-main">
        ${imgBlock}

        <!-- Validity -->
        <div class="val-banner ${valCls} ${isV ? 'val-valid-glow' : 'val-invalid-glow'}">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="${accent}" stroke-width="1.8" style="flex-shrink:0"><path stroke-linecap="round" stroke-linejoin="round" d="${valIconPath}"/></svg>
          <div class="val-text">
            <h4 style="color:${accent}">${valTitle}</h4>
            <p>${validMsg}</p>
          </div>
        </div>

        ${nearExpiry}

        <!-- Issued By -->
        <div class="issued-card">
          <div>
            <div class="ib-label">Assessed By</div>
            <div class="ib-name">${escH(c.assessingOrg || (window.APP_CONFIG?window.APP_CONFIG.brand.vaptTeam:'Synergy Cybersecurity Team'))}</div>
            <div class="ib-sub">${escH(c.verifiedBy || (window.APP_CONFIG?window.APP_CONFIG.vapt.verifiedBy:'Gaurav Singh'))}${c.verifierTitle ? ' · ' + c.verifierTitle : ' · ' + (window.APP_CONFIG?window.APP_CONFIG.vapt.cisoDisplay:'CISO, Synergy Group')}</div>
          </div>
          <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="rgba(100,255,218,0.15)" stroke-width="1.1"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
        </div>

        <!-- Meta -->
        <div class="meta-row">
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg></div><div class="meta-lbl">Type</div><div class="meta-val">VAPT</div></div>
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"/></svg></div><div class="meta-lbl">Level</div><div class="meta-val">Advanced</div></div>
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path stroke-linecap="round" stroke-linejoin="round" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1"/></svg></div><div class="meta-lbl">Location</div><div class="meta-val">On-Vessel</div></div>
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="10"/><path stroke-linecap="round" d="M12 6v6l4 2"/></svg></div><div class="meta-lbl">Validity</div><div class="meta-val">1 Year</div></div>
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg></div><div class="meta-lbl">IMO</div><div class="meta-val" style="color:var(--teal)">${c.vesselIMO || '—'}</div></div>
        </div>

        <!-- Certificate Details -->
        <div class="info-card">
          <div class="sect-title">Assessment Details</div>
          <div class="info-grid">
            <div class="ii"><span class="ilbl">Vessel Name</span><span class="ival">${c.vesselName || '—'}</span></div>
            <div class="ii"><span class="ilbl">Vessel IMO</span><span class="ival mono">${c.vesselIMO || '—'}</span></div>
            <div class="ii"><span class="ilbl">Assessment Date</span><span class="ival">${fmtLong(c.assessmentDate)}</span></div>
            <div class="ii"><span class="ilbl">Valid Until</span><span class="ival ${isExp ? '' : !isV && !isPend ? 'red' : ''}" style="${isExp ? 'color:var(--warn)' : ''}">${fmtLong(c.validUntil)}</span></div>
            <div class="ii fw"><span class="ilbl">Frameworks / Standards</span><span class="ival">${c.frameworks || 'Cybersecurity Framework / OWASP / IMO Framework / ISO 27001:2013'}</span></div>
            ${scopeList.length ? `<div class="ii fw">
              <span class="ilbl">Assessment Scope</span>
              <div class="scope-tags">${scopeList.map(s => `<span class="scope-tag">${s}</span>`).join('')}</div>
            </div>` : ''}
          </div>
          ${c.notes ? `<div class="cert-notes">* ${c.notes}</div>` : ''}
        </div>

        <!-- VAPT Scope & Skills -->
        <div class="info-card">
          <div class="sect-title">Validated Skills &amp; Standards</div>
          <div class="skills-wrap">
            <span class="skill-tag">IMO MSC-FAL.1/Circ.3</span><span class="skill-tag">ISO 27001:2013</span><span class="skill-tag">OWASP Framework</span><span class="skill-tag">OT Security</span><span class="skill-tag">Access Control Review</span><span class="skill-tag">Penetration Testing</span><span class="skill-tag">Cyber Risk Analysis</span><span class="skill-tag">Backup &amp; Recovery</span><span class="skill-tag">Crew Awareness</span>
          </div>
        </div>

        ${docsBlock}

        <div class="sec-footer">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
          ${(window.APP_CONFIG&&window.APP_CONFIG.vapt)?window.APP_CONFIG.vapt.registryBanner:"Synergy VAPT Certificate Registry"} &nbsp;&middot;&nbsp; ${new Date().toUTCString()}
        </div>
      </div>
    </div>`;
    scroll();
  }

  async function downloadCertificate(certId, btn) {
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Preparing…'; }
    try {
      const imgEl = document.querySelector('#result img[data-cert-img="true"]');
      if (imgEl && imgEl.src && !imgEl.src.includes('undefined') && !imgEl.src.includes('null')) {
        const res  = await fetch(imgEl.src);
        const blob = await res.blob();
        const ext  = blob.type.includes('png') ? '.png' : blob.type.includes('webp') ? '.webp' : '.jpg';
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = 'VAPT-Certificate-' + certId + ext;
        document.body.appendChild(a); a.click();
        document.body.removeChild(a); URL.revokeObjectURL(url);
        // Fire download tracking — blob fetch bypasses the server /uploads/ handler
        // so we must explicitly notify the server of this engagement event.
        const fname = imgEl.src.split('/').pop().split('?')[0];
        fetch('/api/track-event', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ certId, event: 'document_downloaded', file: fname, kind: 'vapt' })
        }).catch(() => {});
      } else {
        if (navigator.clipboard) {
          await navigator.clipboard.writeText(window.location.href);
          if (btn) { btn.textContent = '✓ Link Copied!'; setTimeout(() => { if(btn){btn.disabled=false;btn.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg> Download Certificate';} }, 2000); return; }
        }
      }
    } catch { alert('Download unavailable. Please contact ' + (window.APP_CONFIG?window.APP_CONFIG.contact.vaptEmail:'')); }
    if (btn) { setTimeout(() => { btn.disabled=false; btn.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg> Download Certificate'; }, 1800); }
  }

  function copyVerifyLink(btn) {
    if (!navigator.clipboard) return;
    // Use the server-generated encrypted URL if available (works for recipients too),
    // falling back to the current URL when loaded directly via a cert token.
    const shareUrl = _lastShareUrl || window.location.href;
    navigator.clipboard.writeText(shareUrl).then(() => {
      if (btn) { const orig = btn.innerHTML; btn.textContent = '✓ Copied!'; setTimeout(() => btn.innerHTML = orig, 2000); }
    });
  }

  // Handle back/forward navigation
  window.addEventListener('popstate', function() {
    if (!window.location.pathname.includes('/cert/') && !new URLSearchParams(window.location.search).get('s')) {
      document.getElementById('result').innerHTML = '';
      _lastShareUrl = null;
      showDesc();
    }
  });

  /* ── DOCS BLOCK BUILDER ──────────────────────────────────────────── */
  function buildDocsBlock(atts, recipEmail) {
    if (!atts || !atts.length) return '';

    var hasPdfs = atts.some(function(a) {
      var uL = (a.url || '').toLowerCase(), nL = (a.name || '').toLowerCase();
      return uL.endsWith('.pdf') || nL.endsWith('.pdf');
    });

    // Masked email: first 2 chars + **** + last char @ domain
    var maskedEmail = '';
    if (recipEmail) {
      var at = recipEmail.indexOf('@');
      if (at >= 2) {
        var local = recipEmail.slice(0, at);
        var domain = recipEmail.slice(at);
        maskedEmail = local.slice(0, 2) + '****' + local.slice(-1) + domain;
      } else {
        maskedEmail = recipEmail.replace(/./g, '*');
      }
    }

    // Confidential notice shown only when PDFs are present
    var confidentialNotice = '';
    if (hasPdfs) {
      confidentialNotice =
        '<div style="margin-bottom:14px;border:1px solid rgba(212,168,67,.35);border-radius:11px;overflow:hidden">' +
          '<div style="display:flex;align-items:center;gap:9px;padding:11px 14px;background:rgba(212,168,67,.07);border-bottom:1px solid rgba(212,168,67,.18)">' +
            '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>' +
            '<span style="font-size:.72rem;font-weight:700;color:#D4A843;letter-spacing:.05em">&#x1F512; CONFIDENTIAL DOCUMENTS — PASSWORD PROTECTED</span>' +
          '</div>' +
          '<div style="padding:12px 14px;background:rgba(212,168,67,.03)">' +
            '<p style="font-size:.73rem;color:var(--text-sec);line-height:1.65;margin-bottom:10px">' +
              'These documents were sent directly to your registered email address. Each PDF attachment is protected with a personal password.' +
            '</p>' +
            '<div style="display:flex;align-items:center;gap:8px;padding:9px 12px;background:rgba(212,168,67,.06);border:1px solid rgba(212,168,67,.2);border-radius:8px">' +
              '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>' +
              '<div>' +
                '<div style="font-size:.62rem;color:#8892B0;margin-bottom:2px;letter-spacing:.05em">PDF PASSWORD</div>' +
                '<div style="font-size:.74rem;font-weight:700;color:#D4A843;font-family:\'JetBrains Mono\',monospace">Your registered email address</div>' +
                (maskedEmail ? '<div style="font-size:.64rem;color:#8892B0;margin-top:2px">Sent to: ' + maskedEmail + '</div>' : '') +
              '</div>' +
            '</div>' +
          '</div>' +
        '</div>';
    }

    var items = '';
    for (var i = 0; i < atts.length; i++) {
      var a = atts[i];
      var url  = a.url  || '';
      var name = a.name || ('Document ' + (i + 1));
      var uL   = url.toLowerCase();
      var nL   = name.toLowerCase();
      var isPdf = uL.endsWith('.pdf') || nL.endsWith('.pdf');
      var isImg = /\.(jpg|jpeg|png|webp|gif)$/.test(uL) || /\.(jpg|jpeg|png|webp|gif)$/.test(nL);
      var ext  = name.split('.').pop().toUpperCase() || 'FILE';

      var iconPath = isPdf
        ? 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z'
        : isImg
          ? 'M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z'
          : 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z';

      var iconColor = isPdf ? '#D4A843' : isImg ? '#64FFDA' : '#8892B0';
      var safeUrl  = url.replace(/"/g, '&quot;');
      var safeName = name.replace(/"/g, '&quot;');

      if (isPdf) {
        items +=
          '<div style="border:1px solid rgba(212,168,67,.2);border-radius:11px;overflow:hidden;background:rgba(212,168,67,.03)">' +
            '<button class="doc-item" onclick="requestPdfAccess(\'' + safeUrl + '\',\'' + safeName + '\')" style="display:flex;align-items:center;gap:10px;padding:10px 15px;width:100%;text-align:left;background:rgba(212,168,67,.04);border:none;border-radius:11px;color:#D4A843;font-size:.76rem;cursor:pointer;transition:background .2s" onmouseover="this.style.background=\'rgba(212,168,67,.09)\'" onmouseout="this.style.background=\'rgba(212,168,67,.04)\'">' +
              '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="' + iconColor + '" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="' + iconPath + '"/></svg>' +
              '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + safeName + '">' + name + '</span>' +
              '<span style="font-size:.54rem;letter-spacing:.1em;color:#D4A843;text-transform:uppercase;flex-shrink:0;background:rgba(212,168,67,.08);border:1px solid rgba(212,168,67,.25);border-radius:4px;padding:2px 7px">' + ext + '</span>' +
              '<span style="display:inline-flex;align-items:center;gap:4px;font-size:.6rem;color:#D4A843;font-weight:700;letter-spacing:.06em;flex-shrink:0;margin-left:4px;padding:2px 7px;background:rgba(212,168,67,.1);border:1px solid rgba(212,168,67,.25);border-radius:6px"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg> Password Protected</span>' +
            '</button>' +
          '</div>';
      } else if (isImg) {
        items +=
          '<div style="border:1px solid rgba(255,255,255,.08);border-radius:11px;overflow:hidden;background:rgba(255,255,255,.03)">' +
            '<button class="doc-item" onclick="openLB(\'' + safeUrl + '\')" style="display:flex;align-items:center;gap:10px;padding:10px 15px;width:100%;text-align:left;background:rgba(255,255,255,.03);border:none;border-radius:11px;color:#64FFDA;font-size:.76rem;cursor:pointer;transition:background .2s" onmouseover="this.style.background=\'rgba(100,255,218,.04)\'" onmouseout="this.style.background=\'rgba(255,255,255,.03)\'">' +
              '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="' + iconColor + '" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="' + iconPath + '"/></svg>' +
              '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + safeName + '">' + name + '</span>' +
              '<span style="font-size:.54rem;letter-spacing:.1em;color:#8892B0;text-transform:uppercase;flex-shrink:0;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:4px;padding:2px 7px">' + ext + '</span>' +
              '<span style="font-size:.62rem;color:#64FFDA;font-weight:700;letter-spacing:.06em;flex-shrink:0;margin-left:4px">&#128269; Zoom</span>' +
            '</button>' +
            '<img src="' + safeUrl + '" class="att-img-thumb" onclick="openLB(\'' + safeUrl + '\')" />' +
          '</div>';
      } else {
        items +=
          '<a href="' + safeUrl + '" target="_blank" class="doc-item" download="' + safeName + '" style="display:flex;align-items:center;gap:10px;padding:10px 15px;border:1px solid rgba(255,255,255,.08);border-radius:11px;background:rgba(255,255,255,.03);color:#8892B0;font-size:.76rem;text-decoration:none;transition:border-color .2s,background .2s" onmouseover="this.style.borderColor=\'rgba(212,168,67,.3)\';this.style.background=\'rgba(212,168,67,.04)\'" onmouseout="this.style.borderColor=\'rgba(255,255,255,.08)\';this.style.background=\'rgba(255,255,255,.03)\'">' +
            '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="' + iconColor + '" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="' + iconPath + '"/></svg>' +
            '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + safeName + '">' + name + '</span>' +
            '<span style="font-size:.54rem;letter-spacing:.1em;color:#8892B0;text-transform:uppercase;flex-shrink:0;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:4px;padding:2px 7px">' + ext + '</span>' +
            '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;opacity:.4"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>' +
          '</a>';
      }
    }

    return '<div class="info-card">' +
      '<div class="sect-title" style="display:flex;align-items:center;gap:7px"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg> Relevant Documents</div>' +
      confidentialNotice +
      '<div class="docs-list">' + items + '</div>' +
    '</div>';
  }

  /* ── LIGHTBOX ── */
  // ── TOAST HELPER ─────────────────────────────────────────────────────
  let _toastTimer = null;
  function showToast(msg) {
    const t = document.getElementById('copyToast');
    if (!t) return;
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
  }

  // ── CERT ID COPY ──────────────────────────────────────────────────────
  function copyId(el) {
    const text = el.dataset.certid || el.textContent.trim();
    navigator.clipboard.writeText(text).then(() => showToast('✓ Certificate ID copied')).catch(() => {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); showToast('✓ Certificate ID copied'); } catch (_) {}
      document.body.removeChild(ta);
    });
  }

  // ── LIGHTBOX — with focus trap + ARIA ─────────────────────────────────
  let _lbPreviousFocus = null;
  function openLB(src) {
    _lbPreviousFocus = document.activeElement;
    const lb = document.getElementById('lightbox');
    document.getElementById('lbImg').src = src;
    lb.setAttribute('aria-hidden', 'false');
    lb.style.display = 'flex';
    const xBtn = lb.querySelector('.lb-x');
    if (xBtn) xBtn.focus();
    document.body.style.overflow = 'hidden';
  }
  function closeLB() {
    const lb = document.getElementById('lightbox');
    lb.setAttribute('aria-hidden', 'true');
    lb.style.display = 'none';
    document.getElementById('lbImg').src = '';
    document.body.style.overflow = '';
    if (_lbPreviousFocus) { try { _lbPreviousFocus.focus(); } catch(_) {} }
  }

  /* ── EMAIL GATE ── */
  let _pendingPdfUrl = null, _pendingPdfName = null, _currentCertId = '', _emailGateVerified = false;

  function requestPdfAccess(url, name) {
    if (_emailGateVerified) { _doPdfOpen(url, name); return; }
    _pendingPdfUrl = url; _pendingPdfName = name;
    const ov = document.getElementById('emailGateOverlay');
    ov.style.display = 'flex'; ov.setAttribute('aria-hidden','false');
    document.getElementById('gateEmailInput').value = '';
    document.getElementById('gateErr').style.display = 'none';
    document.body.style.overflow = 'hidden';
    setTimeout(() => { try { document.getElementById('gateEmailInput').focus(); } catch(_) {} }, 80);
  }

  async function verifyEmailGate() {
    const entered = (document.getElementById('gateEmailInput').value || '').trim();
    const errEl   = document.getElementById('gateErr');
    if (!entered) { errEl.textContent = 'Please enter your email address.'; errEl.style.display = 'block'; return; }
    if (!_currentCertId) { errEl.textContent = 'No certificate loaded. Please search again.'; errEl.style.display = 'block'; return; }
    const btn = document.getElementById('gateProceedBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Verifying…'; }
    errEl.style.display = 'none';
    try {
      const res = await fetch('/api/vapt/verify-email/' + encodeURIComponent(_currentCertId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: entered })
      });
      if (res.ok) {
        _emailGateVerified = true;
        if (btn) { btn.textContent = '✓ Verified — Opening…'; }
        setTimeout(() => {
          closeEmailGate();
          if (_pendingPdfUrl) _doPdfOpen(_pendingPdfUrl, _pendingPdfName);
          _pendingPdfUrl = null; _pendingPdfName = null;
        }, 700);
      } else if (res.status === 403) {
        errEl.textContent = 'Email does not match our records. Please try again.';
        errEl.style.display = 'block';
        if (btn) { btn.disabled = false; btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;vertical-align:middle;margin-right:6px"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg> Access Document'; }
      } else if (res.status === 429) {
        errEl.textContent = 'Too many attempts. Please wait before trying again.';
        errEl.style.display = 'block';
        if (btn) { btn.disabled = false; btn.textContent = 'Access Document'; }
      } else {
        errEl.textContent = 'Verification service unavailable. Please try again.';
        errEl.style.display = 'block';
        if (btn) { btn.disabled = false; btn.textContent = 'Access Document'; }
      }
    } catch {
      errEl.textContent = 'Network error. Please check your connection and try again.';
      errEl.style.display = 'block';
      if (btn) { btn.disabled = false; btn.textContent = 'Access Document'; }
    }
  }

  function closeEmailGate() {
    const ov = document.getElementById('emailGateOverlay');
    ov.style.display = 'none'; ov.setAttribute('aria-hidden','true');
    document.body.style.overflow = '';
    const btn = document.getElementById('gateProceedBtn');
    if (btn) { btn.disabled = false; btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;vertical-align:middle;margin-right:6px"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg> Access Document'; }
  }

  function _doPdfOpen(url, name) {
    window.open(url, '_blank', 'noopener,noreferrer');
  }

  /* ── PDF VIEWER MODAL — with focus trap + ARIA ── */
  let _pdfPreviousFocus = null;
  function openPdfModal(url, name) {
    // Route through email gate (same as CST) — verifies recipient identity before opening
    requestPdfAccess(url, name);
  }
  function closePdfModal() {
    const ov = document.getElementById('pdfViewerOverlay');
    ov.setAttribute('aria-hidden', 'true');
    ov.style.display = 'none';
    document.getElementById('pdfModalFrame').src = '';
    document.body.style.overflow = '';
    if (_pdfPreviousFocus) { try { _pdfPreviousFocus.focus(); } catch(_) {} }
  }

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') { closeLB(); closePdfModal(); closeEmailGate(); }
    if (e.key === 'Tab') {
      const lb = document.getElementById('lightbox');
      if (lb && lb.getAttribute('aria-hidden') === 'false') { e.preventDefault(); lb.querySelector('.lb-x').focus(); }
    }
  });


  // Auto-load from URL token
  async function verifyByToken(token, sig) {
    const result = document.getElementById('result');
    result.innerHTML = '<div class="scanning"><div class="scan-ring"></div><p>Decrypting &amp; verifying VAPT certificate&hellip;</p></div>';
    hideDesc();
    const sigParam = sig ? `?s=${encodeURIComponent(sig)}` : '';
    try {
      const r = await fetch(`${API}/vapt/verify/${encodeURIComponent(token)}${sigParam}`);
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        if (r.status === 403) {
          result.innerHTML = `<div class="not-found"><svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="var(--invalid)" stroke-width="1.5" style="margin:0 auto"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><h3>Invalid Verification Link</h3><p>${err.error || 'This link is invalid or has been tampered with. Please use the original link from the VAPT certificate.'}</p></div>`;
        } else if (r.status === 404) {
          renderNotFound();
        } else {
          renderError();
        }
        return;
      }
      const data = await r.json().catch(() => null);
      if (!data) { renderError(); return; }
      // Ensure the cert number input is populated when opening /cert/<token>?s=...
      // (admin "View" links use the encrypted route, not the legacy ?id= route).
      try {
        const inp = document.getElementById('certInput');
        if (inp && data.id) inp.value = String(data.id);
      } catch (_) {}
      renderCert(data);
    } catch { renderError(); }
  }

  async function checkUrl() {
    // Case 1: Encrypted cert token in path — e.g. /VPT/cert/<token>?s=<sig>
    const _vptBase = (window.APP_CONFIG ? window.APP_CONFIG.routes.vpt : '/VPT');
    const pathMatch = window.location.pathname.match(new RegExp('^' + _vptBase.replace('/', '\\/') + '\\/cert\\/(.+)'));
    if (pathMatch) {
      const token = pathMatch[1];
      const sig   = new URLSearchParams(window.location.search).get('s') || '';
      document.getElementById('certInput').value = '';
      await verifyByToken(token, sig);
      return;
    }
    // Case 2: Legacy ?id= param (plain cert ID — still supported for back-compat)
    const _vid = new URLSearchParams(window.location.search).get('id');
    if (_vid) {
      document.getElementById('certInput').value = _vid;
      await verify();
    }
  }

  checkUrl();

  let _lastAppliedConfig = null;
  function applyConfig() {
    var C = window.APP_CONFIG;
    if (!C || C === _lastAppliedConfig) return;
    _lastAppliedConfig = C;
    document.title = C.titles.vaptPortal;
    var el;
    if ((el=document.getElementById("navBrandName"))) el.textContent = C.brand.name;
    if ((el=document.getElementById("navBrandSub")))  el.textContent = C.nav.vaptBrandSub;
    if ((el=document.getElementById("heroSub")))      el.innerHTML   = C.vapt.heroSub;
    if ((el=document.getElementById("searchHint")))   el.innerHTML   = C.vapt.searchHint || 'Enter your VAPT certificate number as provided in your assessment report';
    if ((el=document.getElementById("footerCredit"))) el.innerHTML   = C.vapt.footerCredit;
    if ((el=document.getElementById("footerEmail")))  el.textContent = C.contact.vaptEmail;
    // Description block
    if ((el=document.getElementById("descVaptTeam"))) el.textContent = C.brand.vaptTeam;
    var t=document.getElementById("navTabCST"); if(t) t.href=C.routes.cst;
    var v=document.getElementById("navTabVPT"); if(v) v.href=C.routes.vpt;
    var cl=document.getElementById("cstTabLabel"); if(cl) cl.textContent=C.nav.cstTabLabel;
    var vl=document.getElementById("vptTabLabel"); if(vl) vl.textContent=C.nav.vptTabLabel;
    var inp=document.getElementById("certInput"); if(inp) inp.placeholder=(C.vapt&&C.vapt.certPlaceholder)||'Enter VAPT certificate number';
  }
  // Call immediately (fast path if config.js already loaded synchronously)
  applyConfig();
  // Fallback: fire again once all deferred scripts finish loading
  if (document.readyState !== 'complete') {
    window.addEventListener('load', applyConfig);
  }
  // Also call applyConfig when config.js (deferred) finishes loading
  document.addEventListener('appconfigready', applyConfig);

  // ── OFFLINE DETECTION ──────────────────────────────────────────────────────
  (function () {
    const banner  = document.getElementById('offlineBanner');
    let pollTimer = null;
    async function healthCheck() {
      try { const r = await fetch('/api/health', { cache: 'no-store' }); if (r.ok) { if (banner) banner.style.display = 'none'; clearInterval(pollTimer); pollTimer = null; } } catch { }
    }
    window.addEventListener('offline', () => { if (banner) banner.style.display = 'block'; if (!pollTimer) pollTimer = setInterval(healthCheck, (window.APP_CONFIG&&window.APP_CONFIG.resilience&&window.APP_CONFIG.resilience.offlinePollMs)||8000); });
    window.addEventListener('online',  () => healthCheck());
    if (!navigator.onLine && banner) { banner.style.display = 'block'; pollTimer = setInterval(healthCheck, 8000); }
  })();

  // ── MAINTENANCE BANNER ────────────────────────────────────────────────────
  (function () {
    function checkMaintenance() {
      const C = window.APP_CONFIG;
      const mb = document.getElementById('maintenanceBanner');
      const mg = document.getElementById('maintenanceBannerMsg');
      if (C && C.maintenance && C.maintenance.enabled && mb && mg) {
        let text = C.maintenance.message || 'Scheduled maintenance in progress.';
        if (C.maintenance.eta) text += ' Expected: ' + C.maintenance.eta;
        mg.textContent = text; mb.style.display = 'block';
      }
    }
    checkMaintenance();
    document.addEventListener('appconfigready', checkMaintenance);
  })();

  // ── VAPT COMPLIANCE FOOTER BINDING ────────────────────────────────────────
  function applyVaptComplianceFooter() {
    const C = window.APP_CONFIG;
    if (!C) return;
    var el;
    if (C.compliance) {
      if ((el=document.getElementById('vaptComplianceStandards')))   el.textContent = C.compliance.standards || el.textContent;
      if ((el=document.getElementById('vaptComplianceJurisdiction'))) el.textContent = C.compliance.jurisdiction || 'Singapore MPA';
      if ((el=document.getElementById('vaptCompliancePrivacy')))      { el.href = 'mailto:' + (C.compliance.privacyContact||''); el.textContent = 'Privacy / DPO (' + (C.compliance.privacyContact||'') + ')'; }
    }
    var fEmail = document.getElementById('footerEmail');
    if (fEmail && C.contact && C.contact.vaptEmail) { fEmail.textContent = C.contact.vaptEmail; fEmail.href = 'mailto:' + C.contact.vaptEmail; }
  }
  applyVaptComplianceFooter();
  document.addEventListener('appconfigready', applyVaptComplianceFooter);
