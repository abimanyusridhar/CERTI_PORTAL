
  'use strict';
  const API = '/api';

  // HTML-escape helper — prevents XSS when inserting server data into innerHTML
  function escH(s) {
    if (s == null) return '—';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  // Animated counter helper
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

  function isCertValid(c) {
    const es = (c.effectiveStatus || c.status || '').toUpperCase();
    return es === 'VALID';
  }
  function isCertExpired(c) {
    const es = (c.effectiveStatus || c.status || '').toUpperCase();
    if (es === 'EXPIRED') return true;
    // Fallback client-side check if effectiveStatus not yet present
    return (c.status || 'VALID').toUpperCase() === 'VALID' && c.validUntil && new Date(c.validUntil) < new Date();
  }
  function isCertPending(c) {
    return (c.effectiveStatus || c.status || '').toUpperCase() === 'PENDING';
  }

  function scroll() { document.getElementById('result').scrollIntoView({ behavior: 'smooth', block: 'start' }); }

  // Cached shareable URL for the last-verified cert (populated after each verify)
  let _lastShareUrl = null;

  // In-flight guard: prevents concurrent verify() calls
  let _verifying = false;
  let _rlCountdown = null;

  function startRateLimitCountdown(seconds) {
    clearInterval(_rlCountdown);
    const btn = document.getElementById('verifyBtn');
    let remaining = seconds;
    function update() {
      if (btn) { btn.disabled = true; btn.textContent = `Wait ${remaining}s`; }
    }
    update();
    _rlCountdown = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(_rlCountdown);
        if (btn) { btn.disabled = false; btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg> Verify'; }
      } else { update(); }
    }, 1000);
  }

  async function verify() {
    if (_verifying) return;
    const raw = document.getElementById('certInput').value.trim();
    if (!raw) return;
    if (!/^[A-Za-z0-9\-_]{1,64}$/.test(raw)) {
      document.getElementById('result').innerHTML = '<div class="not-found"><h3 style="color:var(--warn)">Invalid Format</h3><p>Certificate IDs may only contain letters, numbers, and hyphens.</p></div>';
      hideDesc(); scroll(); return;
    }
    const btn = document.getElementById('verifyBtn');
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Verifying&hellip;';
    _verifying = true;
    _lastShareUrl = null;
    // Abort after 12 seconds to prevent UI from hanging on network issues
    const ctrl = new AbortController();
    const _timeout = setTimeout(() => ctrl.abort(), 12_000);
    try {
      const res = await fetch(API + '/verify-by-id/' + encodeURIComponent(raw), { signal: ctrl.signal });
      clearTimeout(_timeout);
      if (res.status === 429) {
        const retryAfter = parseInt(res.headers.get('Retry-After') || '30', 10);
        document.getElementById('result').innerHTML = `<div class="not-found" style="border-color:rgba(255,179,71,.3)"><svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.5" style="margin:0 auto"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg><h3 style="color:var(--warn)">Too Many Requests</h3><p>You have exceeded the verification rate limit.<br>Please wait <strong style="color:var(--warn)">${retryAfter} seconds</strong> before trying again.</p></div>`;
        hideDesc(); scroll();
        startRateLimitCountdown(retryAfter);
        _verifying = false;
        return;
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
          history.pushState(null, '', (window.APP_CONFIG ? window.APP_CONFIG.routes.cst : '/CST'));
        } else if (!res.ok) {
          renderError();
        } else {
          // Fetch the encrypted, shareable verification URL from the server
          let shareUrl = window.location.href;
          try {
            const urlCtrl = new AbortController();
            const _urlTimeout = setTimeout(() => urlCtrl.abort(), 8_000);
            const ur = await fetch(API + '/public-cert-url/' + encodeURIComponent(raw), { signal: urlCtrl.signal });
            clearTimeout(_urlTimeout);
            if (ur.ok) { const ud = await ur.json(); if (ud.url) shareUrl = ud.url; }
          } catch { /* fallback to current URL */ }
          _lastShareUrl = shareUrl;
          renderCert(data);
          history.replaceState({ certId: raw }, '', shareUrl);
        }
      }
    } catch (e) { clearTimeout(_timeout); renderError(e && e.name === 'AbortError' ? 'timeout' : undefined); }
    _verifying = false;
    btn.disabled = false;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg> Verify';
  }

  function renderNotFound() {
    const _email = (window.APP_CONFIG && window.APP_CONFIG.contact)
      ? window.APP_CONFIG.contact.cstEmail
      : '';
    document.getElementById('result').innerHTML = `<div class="not-found"><svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="var(--invalid)" stroke-width="1.5" style="margin:0 auto"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><h3>Certificate Not Found</h3><p>No certificate matches this number in the ${(window.APP_CONFIG&&window.APP_CONFIG.brand)?window.APP_CONFIG.brand.name:'Synergy'} registry.<br>Please verify the number carefully or contact <strong style="color:var(--gold)">${_email}</strong></p></div>`;
    scroll();
  }

  function renderError(reason) {
    const _errEmail = (window.APP_CONFIG && window.APP_CONFIG.contact)
      ? window.APP_CONFIG.contact.cstEmail
      : '';
    const msg = reason === 'timeout'
      ? 'The verification request timed out. Please check your connection and try again.'
      : 'Could not reach the verification service. Please try again in a moment.';
    document.getElementById('result').innerHTML = `<div class="not-found" style="background:rgba(255,179,71,0.04);border-color:rgba(255,179,71,0.2)"><svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.5" style="margin:0 auto"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg><h3 style="color:var(--warn)">Service Unavailable</h3><p>${msg}<br>If the issue persists, contact <strong style="color:var(--gold)">${_errEmail}</strong></p></div>`;
    scroll();
  }

  function renderCert(cert) {
    // Reset email gate for new cert lookup
    _currentCertId = cert.id || '';
    _emailGateVerified = false;
    _downloadToken = null;
    const valid   = isCertValid(cert);
    const expired = !valid && isCertExpired(cert);
    const pending = !valid && !expired && isCertPending(cert);
    const accent  = valid ? 'var(--teal)' : pending ? '#7EB8F7' : expired ? 'var(--warn)' : 'var(--invalid)';
    const badgeCls = valid ? 'badge-valid' : pending ? 'badge-pending' : expired ? 'badge-expired' : 'badge-invalid';
    const copyCls  = valid ? 'btn-copy-valid' : pending ? 'btn-copy-pending' : 'btn-copy-invalid';
    const valCls   = valid ? 'val-valid' : pending ? 'val-pending' : expired ? 'val-invalid' : 'val-invalid';
    const effectiveSt = (cert.effectiveStatus || cert.status || 'UNKNOWN').toUpperCase();
    const statusTxt = valid ? 'VERIFIED &amp; VALID' : pending ? 'PENDING ACTIVATION' : expired ? 'EXPIRED' : effectiveSt;

    // Days left
    const dLeft = cert.validUntil
      ? Math.round((new Date(cert.validUntil).setHours(0,0,0,0) - new Date().setHours(0,0,0,0)) / 86400000)
      : null;

    const nearExpiry = (valid && dLeft !== null && dLeft >= 0 && dLeft <= 30) ? `
    <div class="near-exp">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="2" style="flex-shrink:0"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
      <div><strong>Certificate expiring ${dLeft===0?'today':`in ${dLeft} day${dLeft===1?'':'s'}`}</strong> — Please ensure renewal is initiated promptly.</div>
    </div>` : '';

    const validMsg = valid
      ? `Certificate is <strong style="color:var(--teal)">active and accepted</strong> — valid until ${fmt(cert.validUntil)}${dLeft!==null && dLeft>0 ? ` · <strong>${dLeft} day${dLeft===1?'':'s'}</strong> remaining` : ''}`
      : pending
      ? `This certificate is <strong style="color:#7EB8F7">registered but not yet activated</strong>. ${(window.APP_CONFIG&&window.APP_CONFIG.cst)?window.APP_CONFIG.cst.pendingNote:'Contact the Synergy Cyber Security Team for status updates.'}`
      : expired
      ? `This certificate <strong style="color:var(--warn)">expired on ${fmt(cert.validUntil)}</strong> and is no longer valid for compliance. Please contact the issuer for renewal.`
      : `This certificate is <strong style="color:var(--invalid)">${effectiveSt.toLowerCase()}</strong> and not currently accepted for compliance.`;

    const valIconPath = valid
      ? 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'
      : pending
      ? 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z'
      : expired
      ? 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z'
      : 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z';

    const valTitle = valid ? 'CERTIFICATE IS VALID &amp; AUTHENTIC' : pending ? 'CERTIFICATE PENDING ACTIVATION' : expired ? 'CERTIFICATE HAS EXPIRED' : 'CERTIFICATE IS NOT VALID';

    // Cert image
    const imgBlock = cert.certificateImage ? `
    <div class="cert-img-card">
      <div class="cert-img-topbar">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
        Original Certificate Document &mdash; Click to enlarge
      </div>
      <img src="${cert.certificateImage}" alt="Certificate Document" data-cert-img="true" onclick="openLB(this.src)" />
    </div>` : '';

    // ── RELEVANT DOCUMENTS — access-token gated, loaded async after render ──
    const _certImo        = cert.vesselIMO  || '';
    const _certVesselName = cert.vesselName || cert.recipientName || '';
    const docsBlock = _certImo
      ? '<div id="relevantDocsSection" class="info-card" style="margin-top:14px"></div>'
      : '';

    document.getElementById('result').innerHTML = `
    <div class="recipient-banner">
      <div class="recipient-banner-left">
        <div class="recipient-banner-icon">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--gold)" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
        </div>
        <div>
          <div class="recipient-banner-title">Certificate Recipient View</div>
          <div class="recipient-banner-sub">${(window.APP_CONFIG||{cst:{readOnlyNote:"This record is read-only · verified directly from the Synergy registry"}}).cst.readOnlyNote}</div>
        </div>
      </div>
      <div class="recipient-ts">Queried: ${new Date().toUTCString()}</div>
    </div>
    <div class="cred-layout">

      <!-- SIDEBAR -->
      <div class="cred-sidebar">
        <div class="sidebar-card">
          <div class="sdlabel">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
            Issued To
          </div>
          <div class="sdname">${escH(cert.recipientName)}</div>
          <div class="sdsub">${escH(cert.vesselName)}${cert.vesselIMO ? ' · IMO ' + escH(cert.vesselIMO) : ''}${cert.chiefEngineer ? '<br>' + escH(cert.chiefEngineer) : ''}</div>
          <button class="btn-dl" id="dlBtn" onclick="downloadCertificate('${cert.id}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            Download Certificate
          </button>
          <div class="sd-contact">Want to report an error? <a href="mailto:${(window.APP_CONFIG&&window.APP_CONFIG.contact)?window.APP_CONFIG.contact.cstEmail:''}">Contact Issuer</a></div>
        </div>

        <div class="verify-card">
          <div class="vc-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${accent}" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
            <span class="vc-title" style="color:${accent}">Credential Verification</span>
          </div>
          <div class="vrow">
            <div class="vrow-lbl">Issue Date</div>
            <div class="vrow-val">${fmt(cert.issuedAt || cert.complianceDate)}</div>
          </div>
          <div class="vrow">
            <div class="vrow-lbl">Expiration Date</div>
            <div class="vrow-val" style="${expired ? 'color:var(--warn)' : !valid && !pending ? 'color:var(--invalid)' : ''}">${fmt(cert.validUntil)}</div>
          </div>
          <div class="vrow">
            <div class="vrow-lbl">Status</div>
            <span class="status-badge ${badgeCls}">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="${valIconPath}"/></svg>
              ${statusTxt}
            </span>
          </div>
          <button class="btn-copy ${copyCls}" onclick="copyVerifyLink(this)">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
            Copy Verification Link
          </button>
          <div class="vrow-lbl">Certificate ID <span style="font-size:.5rem;letter-spacing:.1em;color:var(--teal);margin-left:6px;cursor:pointer;opacity:.7" onclick="copyCertId('${cert.id}',this)" title="Click to copy">⧉ COPY</span></div>
          <div class="cert-id-mono" onclick="copyCertId('${cert.id}',this)" title="Click to copy certificate ID" style="cursor:pointer" role="button" tabindex="0" onkeydown="if(event.key==='Enter'||event.key===' ')copyCertId('${cert.id}',this)">${cert.id}</div>
        </div>
      </div>

      <!-- MAIN -->
      <div class="cred-main">
        ${imgBlock}

        <!-- Validity -->
        <div class="val-banner ${valCls} ${valid ? 'val-valid-glow' : 'val-invalid-glow'}">
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
            <div class="ib-label">Issued By</div>
            <div class="ib-name">${escH(cert.organizer || (window.APP_CONFIG?window.APP_CONFIG.brand.cstTeam:'Synergy Cyber Security Team'))}</div>
            <div class="ib-sub">${escH(cert.verifiedBy || (window.APP_CONFIG?window.APP_CONFIG.cst.verifiedBy:'CISO, Synergy Marine Group'))}</div>
          </div>
          <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="var(--border-gold)" stroke-width="1.1"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
        </div>

        <!-- Meta Row -->
        <div class="meta-row">
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg></div><div class="meta-lbl">Type</div><div class="meta-val">Training</div></div>
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"/></svg></div><div class="meta-lbl">Level</div><div class="meta-val">Intermediate</div></div>
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path stroke-linecap="round" stroke-linejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg></div><div class="meta-lbl">Format</div><div class="meta-val">${escH(cert.trainingMode || 'Online')}</div></div>
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="10"/><path stroke-linecap="round" d="M12 6v6l4 2"/></svg></div><div class="meta-lbl">Duration</div><div class="meta-val">50 Min</div></div>
          <div class="meta-card"><div class="meta-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path stroke-linecap="round" stroke-linejoin="round" d="M8 7V3m8 4V3M3 11h18M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg></div><div class="meta-lbl">Quarter</div><div class="meta-val" style="color:var(--gold)">${escH(cert.complianceQuarter)}</div></div>
        </div>

        <!-- Certificate Details -->
        <div class="info-card">
          <div class="sect-title">Certificate Details</div>
          <div class="info-grid">
            <div class="ii"><span class="ilbl">Vessel Name</span><span class="ival">${escH(cert.vesselName)}</span></div>
            <div class="ii"><span class="ilbl">Vessel IMO</span><span class="ival mono">${escH(cert.vesselIMO)}</span></div>
            <div class="ii"><span class="ilbl">Chief Engineer</span><span class="ival">${escH(cert.chiefEngineer)}</span></div>
            <div class="ii"><span class="ilbl">Compliance Date</span><span class="ival">${fmt(cert.complianceDate)}</span></div>
            <div class="ii"><span class="ilbl">Valid For Period</span><span class="ival">${escH(cert.validFor)}</span></div>
            <div class="ii"><span class="ilbl">Valid Until</span><span class="ival ${!valid && !pending ? 'red' : ''}">${fmt(cert.validUntil)}</span></div>
          </div>
          ${cert.notes ? `<div class="cert-notes">* ${escH(cert.notes)}</div>` : ''}
        </div>

        <!-- Competencies -->
        <div class="info-card">
          <div class="sect-title">Validated Competencies</div>
          <div class="comp-list">
            <div class="comp-item"><div class="comp-lbl">Regulatory Frameworks</div><div class="comp-desc">Proficiency in navigating ISM Code, ISPS, and NIS2 compliance requirements.</div></div>
            <div class="comp-item"><div class="comp-lbl">Threat Intelligence</div><div class="comp-desc">Ability to identify maritime-specific risks, including AIS/GPS manipulation and OT-targeted ransomware.</div></div>
            <div class="comp-item"><div class="comp-lbl">Operational Security</div><div class="comp-desc">Mastery of maritime cyber hygiene, including secure media handling and social engineering defense.</div></div>
            <div class="comp-item"><div class="comp-lbl">Emergency Preparedness</div><div class="comp-desc">Knowledge of incident response and recovery protocols to ensure vessel safety and operational continuity.</div></div>
          </div>
        </div>

        <!-- Skills -->
        <div class="info-card">
          <div class="sect-title">Skills</div>
          <div class="skills-wrap">
            <span class="skill-tag">Cybersecurity Compliance</span><span class="skill-tag">Cyber Hygiene</span><span class="skill-tag">Cyber Incident Response</span><span class="skill-tag">Cyber Safety</span><span class="skill-tag">Cyber Security Assessment</span><span class="skill-tag">Cyber Security Management</span><span class="skill-tag">Cyber Threat Intelligence</span><span class="skill-tag">Social Engineering Defense</span><span class="skill-tag">ISM / ISPS Compliance</span>
          </div>
        </div>

        ${docsBlock}

        <div class="sec-footer">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
          ${(window.APP_CONFIG&&window.APP_CONFIG.cst)?window.APP_CONFIG.cst.registryBanner:"Synergy Cyber Security Registry"} &nbsp;&middot;&nbsp; ${new Date().toUTCString()}
        </div>
      </div>
    </div>`;
    scroll();
    if (_certImo) loadRelevantDocs(_certImo, _certVesselName);
  }

  // ── RELEVANT DOCUMENTS — async loader ────────────────────────────────────────
  // Capture docToken from the URL immediately on load — before verify() can change the URL.
  const _initialDocToken = (function() {
    try { return new URLSearchParams(window.location.search).get('docToken') || ''; } catch { return ''; }
  })();

  // Per-vessel access token (internal — never shown to user)
  function _docToken(imo)       { try { return localStorage.getItem('docAccessToken_' + imo) || ''; } catch { return ''; } }
  function _saveDocToken(imo,t) { try { localStorage.setItem('docAccessToken_' + imo, t); } catch {} }
  function _clearDocToken(imo)  { try { localStorage.removeItem('docAccessToken_' + imo); } catch {} }

  // Per-vessel request tracking (claim token lets browser poll status without auth)
  function _docReqId(imo)           { try { return localStorage.getItem('docReqId_' + imo) || ''; } catch { return ''; } }
  function _saveDocReqId(imo, id)   { try { localStorage.setItem('docReqId_' + imo, id); } catch {} }
  function _clearDocReqId(imo)      { try { localStorage.removeItem('docReqId_' + imo); } catch {} }
  function _docClaimTok(imo)        { try { return localStorage.getItem('docClaimTok_' + imo) || ''; } catch { return ''; } }
  function _saveDocClaimTok(imo, t) { try { localStorage.setItem('docClaimTok_' + imo, t); } catch {} }
  function _clearDocClaimTok(imo)   { try { localStorage.removeItem('docClaimTok_' + imo); } catch {} }

  // Superintendent session helpers
  function _userSession()         { try { return localStorage.getItem('userSessionToken') || ''; } catch { return ''; } }
  function _saveUserSession(t)    { try { localStorage.setItem('userSessionToken', t); } catch {} }
  function _clearUserSession()    { try { localStorage.removeItem('userSessionToken'); localStorage.removeItem('userSessionName'); } catch {} }
  function _userSessionName()     { try { return localStorage.getItem('userSessionName') || ''; } catch { return ''; } }
  function _saveUserSessionName(n){ try { localStorage.setItem('userSessionName', n); } catch {} }

  async function loadRelevantDocs(imo, vesselName) {
    const el = document.getElementById('relevantDocsSection');
    if (!el) return;
    vesselName = vesselName || '';

    el.innerHTML = '<div class="sect-title" style="display:flex;align-items:center;gap:7px;margin-bottom:10px">'
      + '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>'
      + ' Relevant Documents</div>'
      + '<div style="font-size:.74rem;color:var(--text-sec);padding:8px 2px">Checking access…</div>';

    // 0. Superintendent session — direct access if vessel is in their group
    const storedSession = _userSession();
    if (storedSession) {
      try {
        const me = await fetch('/api/auth/user/me', { headers: { Authorization: 'UserSession ' + storedSession } });
        if (me.ok) {
          const md = await me.json();
          if (md.vessels && md.vessels.includes(imo)) {
            const userName = (md.user && md.user.name) ? md.user.name : _userSessionName();
            if (userName) _saveUserSessionName(userName);
            const r = await fetch(`/api/docs/by-vessel/${encodeURIComponent(imo)}`, { headers: { Authorization: 'UserSession ' + storedSession } });
            if (r.ok) { renderDocList(el, await r.json(), storedSession, imo, 'userSession', userName); return; }
          }
          // Vessel not in their groups — fall through to captain flow
        } else if (me.status === 401) { _clearUserSession(); }
      } catch { /* fall through */ }
    }

    // 1. Already-granted access token in localStorage
    const storedToken = _docToken(imo);
    if (storedToken) {
      try {
        const chk = await fetch(`/api/docs/check-access?token=${encodeURIComponent(storedToken)}&imo=${encodeURIComponent(imo)}`);
        const d   = await chk.json();
        if (d.valid) {
          const activeToken = d.newToken ? (_saveDocToken(imo, d.newToken), d.newToken) : storedToken;
          const r = await fetch(`/api/docs/by-vessel/${encodeURIComponent(imo)}`, { headers: { Authorization: 'DocAccess ' + activeToken } });
          if (r.ok) { renderDocList(el, await r.json(), activeToken, imo); return; }
          if (r.status === 403) _clearDocToken(imo);
        } else { _clearDocToken(imo); }
      } catch { /* fall through */ }
    }

    // 2. Legacy URL token (email links from before claim-token flow)
    if (_initialDocToken) {
      try {
        const chk = await fetch(`/api/docs/check-access?token=${encodeURIComponent(_initialDocToken)}&imo=${encodeURIComponent(imo)}`);
        const d   = await chk.json();
        if (d.valid) {
          const activeToken = d.newToken || _initialDocToken;
          _saveDocToken(imo, activeToken);
          const r = await fetch(`/api/docs/by-vessel/${encodeURIComponent(imo)}`, { headers: { Authorization: 'DocAccess ' + activeToken } });
          if (r.ok) { renderDocList(el, await r.json(), activeToken, imo); return; }
        }
      } catch { /* fall through */ }
    }

    // 3. Tracked request — poll status silently using stored claim token
    const storedReqId = _docReqId(imo);
    const storedClaim = _docClaimTok(imo);
    if (storedReqId && storedClaim) {
      try {
        const chk = await fetch(`/api/docs/request-status?reqId=${encodeURIComponent(storedReqId)}&claimToken=${encodeURIComponent(storedClaim)}&imo=${encodeURIComponent(imo)}`);
        const d   = await chk.json();
        if (d.status === 'APPROVED' && d.accessToken) {
          _saveDocToken(imo, d.accessToken);
          const r = await fetch(`/api/docs/by-vessel/${encodeURIComponent(imo)}`, { headers: { Authorization: 'DocAccess ' + d.accessToken } });
          if (r.ok) { renderDocList(el, await r.json(), d.accessToken, imo); return; }
        }
        if (d.status === 'PENDING') { renderPendingState(el, imo, vesselName); return; }
        if (d.status === 'DENIED')  { _clearDocReqId(imo); _clearDocClaimTok(imo); renderDeniedState(el, imo, vesselName); return; }
        // NOT_FOUND or error — clear stale claim and show form
        _clearDocReqId(imo); _clearDocClaimTok(imo);
      } catch { /* fall through */ }
    }

    // 4. No state — show fresh request form
    renderDocRequestForm(el, imo, vesselName);
  }

  function renderDocList(el, docs, token, imo, tokenType, userName) {
    const fmtSize = b => b > 1048576 ? (b/1048576).toFixed(1)+' MB' : (b/1024).toFixed(0)+' KB';
    const typeLbl = { TRAINING_REPORT: 'Training Report', DRILL_REPORT: 'Drill Report', AUDIT_REPORT: 'Audit Report', CERT_ATTACHMENT: 'Certificate Attachment', OTHER: 'Document' };
    const isSuperintendent = tokenType === 'userSession';
    const resolvedName = userName || _userSessionName();
    const accessLabel = isSuperintendent
      ? (resolvedName ? 'Supt · ' + resolvedName : 'Superintendent Access')
      : 'Access Granted';
    el.innerHTML = '<div class="sect-title" style="display:flex;align-items:center;gap:7px;margin-bottom:12px">'
      + '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>'
      + ' Relevant Documents'
      + '<span style="margin-left:auto;font-size:.6rem;color:var(--gold);display:flex;align-items:center;gap:4px"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg> ' + escH(accessLabel) + '</span>'
      + '</div>'
      + (docs.length ? '' : '<div style="font-size:.76rem;color:var(--text-sec);text-align:center;padding:16px 0">No documents uploaded for this vessel yet.</div>')
      + '<div class="docs-list">'
      + docs.map(d => {
          const ext  = (d.fileName || '').split('.').pop().toUpperCase() || 'FILE';
          const lbl  = typeLbl[d.docType] || 'Document';
          const size = fmtSize(d.fileSize || 0);
          const escT = escH(d.title);
          const mime = (d.mimeType || '').toLowerCase();
          const canView = mime === 'application/pdf' || mime.startsWith('image/');
          const actionLabel = canView ? 'View' : 'Download';
          const actionIcon = canView
            ? '<path stroke-linecap="round" stroke-linejoin="round" d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'
            : '<path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>';
          const dlHref = d.directUrl
            ? d.directUrl
            : (isSuperintendent
                ? '/api/docs/download/' + escH(d.id) + '?userSession=' + encodeURIComponent(token)
                : '/api/docs/download/' + escH(d.id) + '?docToken=' + encodeURIComponent(token));
          return '<div style="border:1px solid rgba(212,168,67,.2);border-radius:11px;margin-bottom:8px;background:rgba(212,168,67,.03)">'
            + '<div style="display:flex;align-items:center;gap:10px;padding:11px 14px">'
            + '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>'
            + '<div style="flex:1;min-width:0">'
            + '<div style="font-size:.78rem;color:var(--text-bright);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escT + '">' + escT + '</div>'
            + '<div style="font-size:.63rem;color:var(--text-sec);margin-top:2px">' + escH(lbl) + ' &bull; ' + escH(ext) + ' &bull; ' + escH(size) + '</div>'
            + '</div>'
            + '<a href="' + dlHref + '" target="_blank" style="display:inline-flex;align-items:center;gap:5px;padding:6px 13px;border-radius:7px;background:rgba(212,168,67,.1);border:1px solid rgba(212,168,67,.3);color:#D4A843;font-size:.67rem;font-weight:700;text-decoration:none;white-space:nowrap;letter-spacing:.05em;transition:all .2s" onmouseover="this.style.background=\'rgba(212,168,67,.18)\'" onmouseout="this.style.background=\'rgba(212,168,67,.10)\'">'
            + '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' + actionIcon + '</svg>'
            + ' ' + actionLabel + '</a>'
            + '</div>'
            + '</div>';
        }).join('')
      + '</div>'
      + '<div style="margin-top:10px;font-size:.64rem;color:var(--text-sec);display:flex;align-items:center;justify-content:space-between">'
      + '<span>Access is vessel-specific and authorised by Synergy Marine Group.</span>'
      + (isSuperintendent
          ? '<button onclick="_clearUserSession();loadRelevantDocs(\'' + escH(imo) + '\',\'\')" style="background:none;border:none;color:var(--text-sec);font-size:.62rem;cursor:pointer;text-decoration:underline">Clear access</button>'
          : '<button onclick="_clearDocToken(\'' + escH(imo) + '\');_clearDocReqId(\'' + escH(imo) + '\');_clearDocClaimTok(\'' + escH(imo) + '\');loadRelevantDocs(\'' + escH(imo) + '\')" style="background:none;border:none;color:var(--text-sec);font-size:.62rem;cursor:pointer;text-decoration:underline">Clear access</button>'
        )
      + '</div>';
  }

  function renderDocRequestForm(el, imo, vesselName) {
    vesselName = vesselName || '';
    el.innerHTML = '<div class="sect-title" style="display:flex;align-items:center;gap:7px;margin-bottom:12px">'
      + '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>'
      + ' Relevant Documents'
      + '</div>'
      + '<div style="border:1px solid rgba(212,168,67,.2);border-radius:11px;overflow:hidden">'
      + '<div style="padding:12px 16px;background:rgba(212,168,67,.04);border-bottom:1px solid rgba(212,168,67,.12);display:flex;align-items:center;gap:9px">'
      + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>'
      + '<div>'
      + '<div style="font-size:.74rem;font-weight:700;color:#D4A843;letter-spacing:.04em">Access Required</div>'
      + '<div style="font-size:.65rem;color:var(--text-sec);margin-top:1px">Enter the captain\'s name and email to request access</div>'
      + '</div>'
      + '</div>'
      + '<div style="padding:16px">'
      + '<p style="font-size:.76rem;color:var(--text-sec);line-height:1.65;margin-bottom:14px">Training reports, drill reports and compliance documents for this vessel are available to authorised personnel. Once approved your documents will appear here automatically on every future visit.</p>'
      + '<div style="margin-bottom:12px"><label style="font-size:.62rem;color:var(--text-sec);letter-spacing:.08em;text-transform:uppercase;font-weight:600;display:block;margin-bottom:4px">Captain\'s Name</label>'
      + '<input id="_docReqCaptain" type="text" placeholder="Enter captain\'s full name" style="width:100%;background:var(--navy);border:1px solid var(--border);border-radius:8px;padding:9px 12px;font-size:.8rem;color:var(--text-bright);font-family:\'DM Sans\',sans-serif;box-sizing:border-box;transition:border-color .2s" onfocus="this.style.borderColor=\'var(--gold)\'" onblur="this.style.borderColor=\'var(--border)\'" /></div>'
      + '<div style="margin-bottom:14px"><label style="font-size:.62rem;color:var(--text-sec);letter-spacing:.08em;text-transform:uppercase;font-weight:600;display:block;margin-bottom:4px">Email Address</label>'
      + '<input id="_docReqEmail" type="email" placeholder="vessel@company.com" style="width:100%;background:var(--navy);border:1px solid var(--border);border-radius:8px;padding:9px 12px;font-size:.8rem;color:var(--text-bright);font-family:\'DM Sans\',sans-serif;box-sizing:border-box;transition:border-color .2s" onfocus="this.style.borderColor=\'var(--gold)\'" onblur="this.style.borderColor=\'var(--border)\'" /></div>'
      + '<button onclick="submitDocAccessRequest(\'' + escH(imo) + '\',\'' + escH(vesselName) + '\')" style="display:inline-flex;align-items:center;gap:7px;padding:9px 18px;border-radius:8px;background:rgba(212,168,67,.1);border:1px solid rgba(212,168,67,.3);color:#D4A843;font-size:.73rem;font-weight:700;cursor:pointer;letter-spacing:.05em;transition:all .2s;font-family:\'DM Sans\',sans-serif">'
      + '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>'
      + 'Request Access</button>'
      + '<div id="_docReqMsg" style="margin-top:10px;font-size:.73rem"></div>'
      + '<div style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px">'
      + '<button onclick="document.getElementById(\'_saLoginPanel\').style.display=document.getElementById(\'_saLoginPanel\').style.display===\'none\'?\'block\':\'none\'" style="background:none;border:none;color:var(--text-sec);font-size:.68rem;cursor:pointer;text-decoration:underline;font-family:\'DM Sans\',sans-serif;padding:0">Superintendent? Sign in for direct access</button>'
      + '<div id="_saLoginPanel" style="display:none;margin-top:12px">'
      + '<div style="margin-bottom:10px"><label style="font-size:.62rem;color:var(--text-sec);letter-spacing:.08em;text-transform:uppercase;font-weight:600;display:block;margin-bottom:4px">Email</label>'
      + '<input id="_saEmail" type="email" placeholder="superintendent@company.com" style="width:100%;background:var(--navy);border:1px solid var(--border);border-radius:8px;padding:9px 12px;font-size:.8rem;color:var(--text-bright);font-family:\'DM Sans\',sans-serif;box-sizing:border-box;transition:border-color .2s" onfocus="this.style.borderColor=\'var(--gold)\'" onblur="this.style.borderColor=\'var(--border)\'" /></div>'
      + '<div style="margin-bottom:12px"><label style="font-size:.62rem;color:var(--text-sec);letter-spacing:.08em;text-transform:uppercase;font-weight:600;display:block;margin-bottom:4px">Password</label>'
      + '<input id="_saPwd" type="password" placeholder="••••••••" style="width:100%;background:var(--navy);border:1px solid var(--border);border-radius:8px;padding:9px 12px;font-size:.8rem;color:var(--text-bright);font-family:\'DM Sans\',sans-serif;box-sizing:border-box;transition:border-color .2s" onfocus="this.style.borderColor=\'var(--gold)\'" onblur="this.style.borderColor=\'var(--border)\'" onkeydown="if(event.key===\'Enter\')submitSuperintendentLogin(\'' + escH(imo) + '\',\'' + escH(vesselName) + '\')" /></div>'
      + '<button onclick="submitSuperintendentLogin(\'' + escH(imo) + '\',\'' + escH(vesselName) + '\')" style="display:inline-flex;align-items:center;gap:7px;padding:8px 16px;border-radius:8px;background:rgba(212,168,67,.1);border:1px solid rgba(212,168,67,.3);color:#D4A843;font-size:.72rem;font-weight:700;cursor:pointer;font-family:\'DM Sans\',sans-serif">'
      + '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/></svg>'
      + 'Sign In</button>'
      + '<div id="_saLoginMsg" style="margin-top:8px;font-size:.72rem"></div>'
      + '</div>'
      + '</div>'
      + '</div>'
      + '</div>';
  }

  function renderPendingState(el, imo, vesselName) {
    vesselName = vesselName || '';
    el.innerHTML = '<div class="sect-title" style="display:flex;align-items:center;gap:7px;margin-bottom:12px">'
      + '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>'
      + ' Relevant Documents'
      + '</div>'
      + '<div style="border:1px solid rgba(212,168,67,.2);border-radius:11px;overflow:hidden">'
      + '<div style="padding:12px 16px;background:rgba(212,168,67,.04);border-bottom:1px solid rgba(212,168,67,.12);display:flex;align-items:center;gap:9px">'
      + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
      + '<div>'
      + '<div style="font-size:.74rem;font-weight:700;color:#D4A843;letter-spacing:.04em">Approval Pending</div>'
      + '<div style="font-size:.65rem;color:var(--text-sec);margin-top:1px">Your request is under review by the admin team</div>'
      + '</div>'
      + '</div>'
      + '<div style="padding:16px">'
      + '<p style="font-size:.76rem;color:var(--text-sec);line-height:1.65;margin-bottom:16px">Your document access request has been submitted and is awaiting approval. Once approved, your documents will appear here automatically — no token or extra steps required.</p>'
      + '<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">'
      + '<button id="_checkApprovalBtn" onclick="checkApprovalStatus(\'' + escH(imo) + '\',\'' + escH(vesselName) + '\')" style="display:inline-flex;align-items:center;gap:7px;padding:9px 18px;border-radius:8px;background:rgba(212,168,67,.1);border:1px solid rgba(212,168,67,.3);color:#D4A843;font-size:.73rem;font-weight:700;cursor:pointer;transition:all .2s;font-family:\'DM Sans\',sans-serif">'
      + '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>'
      + 'Check Approval Status</button>'
      + '<button onclick="_clearDocReqId(\'' + escH(imo) + '\');_clearDocClaimTok(\'' + escH(imo) + '\');renderDocRequestForm(document.getElementById(\'relevantDocsSection\'),\'' + escH(imo) + '\',\'' + escH(vesselName) + '\')" style="background:none;border:none;color:var(--text-sec);font-size:.7rem;cursor:pointer;text-decoration:underline;font-family:\'DM Sans\',sans-serif">Submit a different request</button>'
      + '</div>'
      + '<div id="_statusMsg" style="margin-top:10px;font-size:.73rem"></div>'
      + '</div>'
      + '</div>';
  }

  function renderDeniedState(el, imo, vesselName) {
    vesselName = vesselName || '';
    el.innerHTML = '<div class="sect-title" style="display:flex;align-items:center;gap:7px;margin-bottom:12px">'
      + '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#D4A843" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>'
      + ' Relevant Documents'
      + '</div>'
      + '<div style="border:1px solid rgba(255,107,138,.25);border-radius:11px;overflow:hidden">'
      + '<div style="padding:12px 16px;background:rgba(255,107,138,.04);border-bottom:1px solid rgba(255,107,138,.12);display:flex;align-items:center;gap:9px">'
      + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#FF6B8A" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>'
      + '<div>'
      + '<div style="font-size:.74rem;font-weight:700;color:#FF6B8A;letter-spacing:.04em">Access Not Approved</div>'
      + '<div style="font-size:.65rem;color:var(--text-sec);margin-top:1px">Your previous request was not approved</div>'
      + '</div>'
      + '</div>'
      + '<div style="padding:16px">'
      + '<p style="font-size:.76rem;color:var(--text-sec);line-height:1.65;margin-bottom:16px">Your access request was not approved. Please contact the admin team or submit a new request below.</p>'
      + '<button onclick="renderDocRequestForm(document.getElementById(\'relevantDocsSection\'),\'' + escH(imo) + '\',\'' + escH(vesselName) + '\')" style="display:inline-flex;align-items:center;gap:7px;padding:9px 18px;border-radius:8px;background:rgba(212,168,67,.1);border:1px solid rgba(212,168,67,.3);color:#D4A843;font-size:.73rem;font-weight:700;cursor:pointer;font-family:\'DM Sans\',sans-serif">'
      + '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>'
      + 'Submit New Request</button>'
      + '</div>'
      + '</div>';
  }

  async function checkApprovalStatus(imo, vesselName) {
    const btn = document.getElementById('_checkApprovalBtn');
    const msg = document.getElementById('_statusMsg');
    const storedReqId = _docReqId(imo);
    const storedClaim = _docClaimTok(imo);
    if (!storedReqId || !storedClaim) {
      const el = document.getElementById('relevantDocsSection');
      if (el) renderDocRequestForm(el, imo, vesselName);
      return;
    }
    if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
    if (msg) { msg.textContent = ''; }
    try {
      const chk = await fetch(`/api/docs/request-status?reqId=${encodeURIComponent(storedReqId)}&claimToken=${encodeURIComponent(storedClaim)}&imo=${encodeURIComponent(imo)}`);
      const d   = await chk.json();
      if (d.status === 'APPROVED' && d.accessToken) {
        _saveDocToken(imo, d.accessToken);
        if (msg) { msg.style.color='#64FFDA'; msg.textContent='Access approved — loading your documents…'; }
        setTimeout(() => loadRelevantDocs(imo, vesselName), 700);
        return;
      }
      if (d.status === 'DENIED') {
        _clearDocReqId(imo); _clearDocClaimTok(imo);
        const el = document.getElementById('relevantDocsSection');
        if (el) renderDeniedState(el, imo, vesselName);
        return;
      }
      // Still pending
      if (msg) { msg.style.color='var(--text-sec)'; msg.textContent='Still pending — you\'ll be notified once approved.'; }
      if (btn) { btn.disabled = false; btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>Check Approval Status'; }
    } catch {
      if (btn) { btn.disabled = false; btn.textContent = 'Check Approval Status'; }
      if (msg) { msg.style.color='var(--invalid,#FF6B8A)'; msg.textContent='Connection failed. Check your internet and try again.'; }
    }
  }

  async function submitDocAccessRequest(imo, vesselName) {
    vesselName = vesselName || '';
    const captainName = ((document.getElementById('_docReqCaptain') || {}).value || '').trim();
    const email       = ((document.getElementById('_docReqEmail')   || {}).value || '').trim();
    const msg         = document.getElementById('_docReqMsg');
    if (!captainName) { if (msg) { msg.style.color='var(--invalid,#FF6B8A)'; msg.textContent="Please enter the captain's name."; } return; }
    if (!email)       { if (msg) { msg.style.color='var(--invalid,#FF6B8A)'; msg.textContent='Please enter your email address.';  } return; }
    if (msg) { msg.style.color='var(--text-sec)'; msg.textContent='Submitting…'; }
    try {
      const r = await fetch('/api/docs/request-access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ captainName, vesselName, vesselIMO: imo, emailId: email }),
      });
      const d = await r.json();
      if (!r.ok) { if (msg) { msg.style.color='var(--invalid,#FF6B8A)'; msg.textContent=d.error||'Request could not be submitted. Please try again.'; } return; }
      // Save claim token — browser uses this to silently poll status without auth
      _saveDocReqId(imo, d.requestId);
      _saveDocClaimTok(imo, d.claimToken);
      const el = document.getElementById('relevantDocsSection');
      if (d.alreadyApproved) {
        // Was already approved — silently fetch access and load docs
        if (msg) { msg.style.color='var(--text-sec)'; msg.textContent='Checking access…'; }
        await checkApprovalStatus(imo, vesselName);
      } else {
        if (el) renderPendingState(el, imo, vesselName);
      }
    } catch { if (msg) { msg.style.color='var(--invalid,#FF6B8A)'; msg.textContent='Connection failed. Check your internet and try again.'; } }
  }

  async function submitSuperintendentLogin(imo, vesselName) {
    vesselName = vesselName || '';
    const email = ((document.getElementById('_saEmail')   || {}).value || '').trim();
    const pwd   = ((document.getElementById('_saPwd')     || {}).value || '').trim();
    const msg   = document.getElementById('_saLoginMsg');
    if (!email || !pwd) { if (msg) { msg.style.color='var(--invalid,#FF6B8A)'; msg.textContent='Please enter your email and password.'; } return; }
    if (msg) { msg.style.color='var(--text-sec)'; msg.textContent='Signing in…'; }
    try {
      const r = await fetch('/api/auth/user/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: pwd }),
      });
      const d = await r.json();
      if (!r.ok) { if (msg) { msg.style.color='var(--invalid,#FF6B8A)'; msg.textContent = d.error || 'Sign-in failed. Check your email and password.'; } return; }
      _saveUserSession(d.sessionToken);
      if (d.user && d.user.name) _saveUserSessionName(d.user.name);
      if (msg) { msg.style.color='var(--teal,#64FFDA)'; msg.textContent='Signed in — loading your documents…'; }
      setTimeout(() => loadRelevantDocs(imo, vesselName), 600);
    } catch { if (msg) { msg.style.color='var(--invalid,#FF6B8A)'; msg.textContent='Connection failed. Check your internet and try again.'; } }
  }

  window.loadRelevantDocs    = loadRelevantDocs;
  window.renderDocRequestForm = renderDocRequestForm;
  window.checkApprovalStatus  = checkApprovalStatus;
  window.submitDocAccessRequest = submitDocAccessRequest;
  window.submitSuperintendentLogin = submitSuperintendentLogin;
  window._clearDocToken     = _clearDocToken;
  window._clearDocReqId     = _clearDocReqId;
  window._clearDocClaimTok  = _clearDocClaimTok;
  window._clearUserSession   = _clearUserSession;
  window._saveUserSession    = _saveUserSession;
  window._saveUserSessionName = _saveUserSessionName;

  async function downloadCertificate(certId) {
    const btn = document.getElementById('dlBtn');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Preparing…'; }
    try {
      const imgEl = document.querySelector('#result img[data-cert-img="true"]');
      if (imgEl && imgEl.src && !imgEl.src.includes('undefined') && !imgEl.src.includes('null')) {
        const res  = await fetch(imgEl.src);
        const blob = await res.blob();
        const ext  = blob.type.includes('png') ? '.png' : blob.type.includes('webp') ? '.webp' : '.jpg';
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = 'Certificate-' + certId + ext;
        document.body.appendChild(a); a.click();
        document.body.removeChild(a); URL.revokeObjectURL(url);
        // Fire download tracking — blob fetch bypasses the server /uploads/ handler
        // so we must explicitly notify the server of this engagement event.
        const fname = imgEl.src.split('/').pop().split('?')[0];
        fetch('/api/track-event', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ certId, event: 'document_downloaded', file: fname, kind: 'cst' })
        }).catch(() => {});
      } else {
        if (navigator.clipboard) {
          await navigator.clipboard.writeText(window.location.href);
          if (btn) {
            btn.textContent = '✓ Link Copied!';
            setTimeout(() => { if (btn) { btn.disabled=false; btn.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg> Download Certificate'; } }, 2000);
            return;
          }
        }
      }
    } catch { alert('Download failed. Please try again or contact the issuing authority.'); }
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

  function copyCertId(id, el) {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(id).then(() => {
      const orig = el.textContent;
      el.textContent = '✓ Copied!';
      el.style.color = 'var(--teal)';
      setTimeout(() => { el.textContent = orig; el.style.color = ''; }, 1800);
    });
  }

  window.addEventListener('popstate', function() {
    const p = new URLSearchParams(window.location.search);
    if (!p.get('s') && !window.location.pathname.includes('/cert/')) {
      document.getElementById('result').innerHTML = '';
      _lastShareUrl = null;
      showDesc();
    }
  });

  function openLB(src) {
    const lb = document.getElementById('lightbox');
    lb.querySelector('img').src = src;
    lb.style.display = 'flex';
    // Focus trap
    const closer = lb.querySelector('.lb-x');
    if (closer) setTimeout(() => closer.focus(), 50);
  }
  function closeLB()  {
    document.getElementById('lightbox').style.display = 'none';
    // Return focus to the element that triggered the lightbox
    const triggerEl = document.querySelector('#result img[data-cert-img="true"]');
    if (triggerEl) triggerEl.focus();
  }

  /* ── EMAIL GATE (CST) ───────────────────────────────────────────── */
  let _pendingPdfUrl = null, _pendingPdfName = null, _currentCertId = '', _emailGateVerified = false, _downloadToken = null;

  function openPdfModal(url, name) {
    requestPdfAccess(url, name);
  }

  function requestPdfAccess(url, name) {
    if (_emailGateVerified) { _doPdfOpen(url, name); return; }
    _pendingPdfUrl = url; _pendingPdfName = name;
    const ov = document.getElementById('emailGateOverlay');
    ov.style.display = 'flex'; ov.setAttribute('aria-hidden', 'false');
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
      const res = await fetch('/api/verify-email/' + encodeURIComponent(_currentCertId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: entered })
      });
      if (res.ok) {
        const d = await res.json().catch(() => ({}));
        _downloadToken = d && d.downloadToken ? d.downloadToken : null;
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
    ov.style.display = 'none'; ov.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    const btn = document.getElementById('gateProceedBtn');
    if (btn) { btn.disabled = false; btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;vertical-align:middle;margin-right:6px"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg> Access Document'; }
  }

  function _doPdfOpen(url, name) {
    // Append the short-lived server token so `/uploads/:file` can validate access.
    if (_downloadToken && url && url.indexOf('?t=') === -1) {
      const sep = url.includes('?') ? '&' : '?';
      url = url + sep + 't=' + encodeURIComponent(_downloadToken);
    }
    window.open(url, '_blank', 'noopener,noreferrer');
  }

  function closePdfModal() {
    document.getElementById('pdfViewerOverlay').style.display = 'none';
    document.getElementById('pdfModalFrame').src = '';
  }

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') { closeLB(); closePdfModal(); closeEmailGate(); }
  });

  // Auto-load from URL token
  async function verifyByToken(token, sig) {
    const result = document.getElementById('result');
    result.innerHTML = '<div class="scanning"><div class="scan-ring"></div><p>Decrypting &amp; verifying certificate&hellip;</p></div>';
    hideDesc();
    const sigParam = sig ? `?s=${encodeURIComponent(sig)}` : '';
    try {
      const r = await fetch(`/api/verify/${encodeURIComponent(token)}${sigParam}`);
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        if (r.status === 403) {
          result.innerHTML = `<div class="not-found"><svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="var(--invalid)" stroke-width="1.5" style="margin:0 auto"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><h3>Invalid Verification Link</h3><p>${err.error || 'This link is invalid or has been tampered with. Please use the original link from the certificate.'}</p></div>`;
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

  async function checkHash() {
    const _cstBase = (window.APP_CONFIG ? window.APP_CONFIG.routes.cst : '/CST');
    // Case 1: Encrypted cert token in path — e.g. /CST/cert/<token>?s=<sig>
    const pathMatch = window.location.pathname.match(new RegExp('^' + _cstBase.replace('/', '\\/') + '\\/cert\\/(.+)'));
    if (pathMatch) {
      const token = pathMatch[1];
      const sig   = new URLSearchParams(window.location.search).get('s') || '';
      document.getElementById('certInput').value = '';
      await verifyByToken(token, sig);
      return;
    }
    // Case 2: Legacy ?id= param (plain cert ID in URL — still supported for back-compat)
    const _id = new URLSearchParams(window.location.search).get('id');
    if (_id) { document.getElementById('certInput').value = _id; await verify(); }
  }

  checkHash();

  // Apply centralized config to static DOM elements
  let _configApplied = false;
  function applyConfig() {
    if (_configApplied) return;
    var C = window.APP_CONFIG;
    if (!C) return;
    _configApplied = true;
    document.title = C.titles.cstPortal;
    // Update meta description dynamically so social crawlers get the right text
    var metaDesc = document.querySelector('meta[name="description"]');
    if (metaDesc) metaDesc.content = 'Verify ' + C.brand.name + ' Cyber Security Training certificates in real-time.';
    var el;
    if ((el=document.getElementById('navBrandName'))) el.textContent = C.brand.name;
    if ((el=document.getElementById('navBrandSub')))  el.textContent = C.nav.cstBrandSub;
    if ((el=document.getElementById('heroSub')))      el.innerHTML   = C.cst.heroSub;
    if ((el=document.getElementById('searchHint')))   el.innerHTML   = C.cst.searchHint;
    if ((el=document.getElementById('footerCredit'))) el.innerHTML   = C.cst.footerCredit;
    if ((el=document.getElementById('footerEmail')))  el.textContent = C.contact.cstEmail;
    if ((el=document.getElementById('notFoundEmail'))) el.textContent= C.contact.cstEmail;
    // Description block brand names
    if ((el=document.getElementById('descCstTeam')))    el.textContent = C.brand.cstTeam;
    if ((el=document.getElementById('descCompanyName'))) el.textContent = C.brand.name;
    var t=document.getElementById('navTabCST'); if(t) t.href=C.routes.cst;
    var v=document.getElementById('navTabVPT'); if(v) v.href=C.routes.vpt;
    var cl=document.getElementById('cstTabLabel'); if(cl) cl.textContent=C.nav.cstTabLabel;
    var vl=document.getElementById('vptTabLabel'); if(vl) vl.textContent=C.nav.vptTabLabel;
    var inp=document.getElementById('certInput');
    if(inp) inp.placeholder = C.cst.searchPlaceholder;
  }
  // Call immediately (fast path if config.js already loaded synchronously)
  applyConfig();
  // config.js is deferred — also wire up the custom event it dispatches
  document.addEventListener('appconfigready', applyConfig);
  // Belt-and-suspenders: run once more after full page load
  window.addEventListener('load', applyConfig);

  // ── OFFLINE DETECTION & RESILIENCE ───────────────────────────────────────────
  (function () {
    const banner   = document.getElementById('offlineBanner');
    const CFG_RES  = () => (window.APP_CONFIG && window.APP_CONFIG.resilience) || {};
    let pollTimer  = null;

    function showOffline()  { if (banner) banner.style.display = 'block'; }
    function hideOffline()  { if (banner) banner.style.display = 'none'; clearInterval(pollTimer); pollTimer = null; }

    async function healthCheck() {
      try {
        const r = await fetch('/api/health', { cache: 'no-store' });
        if (r.ok) hideOffline();
      } catch { /* still offline */ }
    }

    window.addEventListener('offline', () => {
      showOffline();
      const interval = CFG_RES().offlinePollMs || 8000;
      if (!pollTimer) pollTimer = setInterval(healthCheck, interval);
    });
    window.addEventListener('online',  () => healthCheck());

    // Initial health check
    if (!navigator.onLine) {
      showOffline();
      const interval = CFG_RES().offlinePollMs || 8000;
      pollTimer = setInterval(healthCheck, interval);
    }
  })();

  // ── MAINTENANCE MODE BANNER ───────────────────────────────────────────────────
  (function () {
    const mb  = document.getElementById('maintenanceBanner');
    const msg = document.getElementById('maintenanceBannerMsg');
    function checkMaintenance() {
      const C = window.APP_CONFIG;
      if (C && C.maintenance && C.maintenance.enabled && mb && msg) {
        let text = C.maintenance.message || 'Scheduled maintenance in progress.';
        if (C.maintenance.eta) text += ' Expected: ' + C.maintenance.eta;
        msg.textContent = text;
        mb.style.display = 'block';
      }
    }
    checkMaintenance();
    document.addEventListener('appconfigready', checkMaintenance);
  })();

  // ── COMPLIANCE FOOTER BINDING ─────────────────────────────────────────────────
  function applyComplianceFooter() {
    const C = window.APP_CONFIG;
    if (!C || !C.compliance) return;
    var el;
    if ((el=document.getElementById('complianceStandards')))  el.textContent = C.compliance.standards || el.textContent;
    if ((el=document.getElementById('complianceDataClass')))  el.textContent = 'Data Classification: ' + (C.compliance.dataClassification || 'RESTRICTED');
    if ((el=document.getElementById('complianceJurisdiction'))) el.textContent = C.compliance.jurisdiction || 'Singapore MPA';
    if ((el=document.getElementById('compliancePrivacy')))    { el.href = 'mailto:' + (C.compliance.privacyContact || ''); el.textContent = 'Privacy / DPO (' + (C.compliance.privacyContact || '') + ')'; }
    if ((el=document.getElementById('complianceRetention'))) el.textContent = 'Records retained ' + (C.compliance.dataRetentionYears || 5) + ' years per maritime compliance obligations';
    // Update footer email as mailto link
    var fEmail = document.getElementById('footerEmail');
    if (fEmail && C.contact && C.contact.cstEmail) {
      fEmail.textContent = C.contact.cstEmail;
      fEmail.href = 'mailto:' + C.contact.cstEmail;
    }
  }
  applyComplianceFooter();
  document.addEventListener('appconfigready', applyComplianceFooter);
