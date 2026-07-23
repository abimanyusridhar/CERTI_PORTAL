'use strict';
/**
 * Combined CST + VAPT vessel view embedded in the CST/VAPT dashboards' own
 * Dashboard tab, for the read-only "client" role only — shown/hidden and
 * loaded by each dashboard.js's own role check (see scheduleTokenExpiryWarning
 * in vapt/dashboard.js and the equivalent boot-time /api/auth/verify call in
 * cst/dashboard.js). Normal admins never see this section; their Dashboard
 * tab is unchanged.
 *
 * Shared verbatim between admin/dashboard.html and admin/vapt-dashboard.html
 * — both pages use identical modal markup conventions (.overlay + inline
 * style.display, .modal-hdr/.modal-foot, data-action="closeXBackdrop"
 * wired into dashboard-actions.js's BACKDROP_HANDLERS), so one file covers
 * both. Uses the element ids below, expected to exist inside
 * #clientCombinedSection on whichever page includes this script.
 *
 * Does its OWN /api/auth/verify check rather than relying on the host
 * page's dashboard.js to call in — dashboard.js's own verify call and this
 * script's load are two independent network requests with no ordering
 * guarantee (this script's <script> tag can still be loading when
 * dashboard.js's fetch resolves), so a "let dashboard.js call us" design
 * would race and silently no-op. Self-checking removes that race entirely.
 */
(function() {
  const API = '/api';
  let TOKEN = sessionStorage.getItem('adminToken') || '';
  let vesselIndex = new Map();

  const authHdr = () => ({ Authorization: 'Bearer ' + TOKEN });
  function checkUnauth(r) { if (r.status === 401) { window.doLogout(); return true; } return false; }

  const RISK_STYLE = {
    CRITICAL: { emoji: '🔴', color: 'var(--invalid)' },
    HIGH:     { emoji: '🟠', color: 'var(--warn)' },
    MEDIUM:   { emoji: '🟡', color: 'var(--warn)' },
    LOW:      { emoji: '🟢', color: 'var(--teal)' },
  };
  const Q_COLORS = { Q1: '#64FFDA', Q2: '#D4A843', Q3: '#B47EFF', Q4: '#FF5C7A' };

  const escH  = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  const fmtDt = s => s ? new Date(s).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
  const isValid = r => (r.status || '').toUpperCase() === 'VALID';

  function vesselKey(r) { return (r.vesselIMO || r.vesselName || 'unknown').toString().toUpperCase(); }

  function buildVesselIndex(cst, vapt) {
    const idx = new Map();
    [...cst, ...vapt].forEach(r => {
      const key = vesselKey(r);
      if (!idx.has(key)) idx.set(key, { imo: r.vesselIMO || '', vesselName: r.vesselName || r.vesselIMO || 'Unknown Vessel', cst: [], vapt: [] });
      const entry = idx.get(key);
      if (!entry.imo && r.vesselIMO) entry.imo = r.vesselIMO;
      (r._type === 'CST' ? entry.cst : entry.vapt).push(r);
    });
    return idx;
  }

  async function loadCcrRecords() {
    const grid = document.getElementById('ccrVesselGrid');
    if (!grid) return;
    try {
      const [rC, rV] = await Promise.all([
        fetch(API + '/certs',      { headers: authHdr() }),
        fetch(API + '/vapt/certs', { headers: authHdr() }),
      ]);
      if (checkUnauth(rC) || checkUnauth(rV)) return;
      if (!rC.ok || !rV.ok) return;
      const cst  = (await rC.json()).map(c => Object.assign({ _type: 'CST' },  c));
      const vapt = (await rV.json()).map(c => Object.assign({ _type: 'VAPT' }, c));
      vesselIndex = buildVesselIndex(cst, vapt);
      renderCcrRecords();
    } catch { /* section stays as-is; the page's own dashboard still loaded fine */ }
  }
  window.loadCcrRecords = loadCcrRecords;

  function renderCcrRecords() {
    const searchEl = document.getElementById('ccrSearch');
    const q = (searchEl && searchEl.value || '').toLowerCase();
    const vessels = [...vesselIndex.entries()]
      .filter(([key, v]) => !q || v.vesselName.toLowerCase().includes(q) || (v.imo || '').toLowerCase().includes(q))
      .sort((a, b) => a[1].vesselName.localeCompare(b[1].vesselName));

    const grid  = document.getElementById('ccrVesselGrid');
    const empty = document.getElementById('ccrEmpty');
    if (!grid) return;
    if (!vessels.length) {
      grid.innerHTML = '';
      if (empty) {
        document.getElementById('ccrEmptyMsg').textContent = vesselIndex.size
          ? 'No vessels match your search.'
          : 'No certificate records yet.';
        empty.style.display = 'block';
      }
      return;
    }
    if (empty) empty.style.display = 'none';

    grid.innerHTML = vessels.map(([key, v]) => {
      const validCount = v.cst.filter(isValid).length + v.vapt.filter(isValid).length;
      const totalCount = v.cst.length + v.vapt.length;
      return `<div class="ccr-vessel-card" data-action="openCcrModal" data-imo="${escH(key)}">
        <div class="ccr-vessel-head">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--gold)" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 21h18M5 21V10l7-7 7 7v11M9 21v-6h6v6"/></svg>
          <span class="ccr-vessel-name">${escH(v.vesselName)}</span>
          <span class="ccr-vessel-count">${totalCount} record${totalCount !== 1 ? 's' : ''}</span>
        </div>
        <div class="ccr-vessel-imo">${v.imo ? 'IMO ' + escH(v.imo) : 'IMO unavailable'}</div>
        <div class="ccr-vessel-pills">
          <span class="ccr-pill ccr-pill-cst">CST ${v.cst.length}</span>
          <span class="ccr-pill ccr-pill-vapt">VAPT ${v.vapt.length}</span>
          <span class="ccr-pill ccr-pill-valid">${validCount} valid</span>
        </div>
      </div>`;
    }).join('');
  }
  window.renderCcrRecords = renderCcrRecords;

  function certRow(r, isCst) {
    let badge;
    if (isCst && r.complianceQuarter) {
      const qc = Q_COLORS[r.complianceQuarter.toUpperCase()] || 'var(--text-sec)';
      badge = `<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:.62rem;font-weight:700;letter-spacing:.06em;background:${qc}1F;border:1px solid ${qc};color:${qc}">${escH(r.complianceQuarter)}</span>`;
    } else if (!isCst && r.riskLevel) {
      const ri = RISK_STYLE[r.riskLevel.toUpperCase()] || { emoji: '', color: 'var(--text-sec)' };
      badge = `<span style="font-size:.72rem;color:${ri.color}">${ri.emoji} ${escH(r.riskLevel)}</span>`;
    } else {
      badge = '<span style="color:var(--text-sec);font-size:.7rem">—</span>';
    }
    const st = (r.status || 'PENDING').toUpperCase();
    const stColor = st === 'VALID' ? 'var(--teal)' : st === 'REVOKED' ? 'var(--invalid)' : st === 'EXPIRED' ? 'var(--warn)' : 'var(--text-sec)';
    const stBg    = st === 'VALID' ? 'rgba(100,255,218,.1)' : st === 'REVOKED' ? 'rgba(255,107,138,.1)' : st === 'EXPIRED' ? 'rgba(255,170,46,.1)' : 'rgba(255,255,255,.05)';
    return `<div style="display:flex;align-items:center;gap:10px;padding:10px 4px;border-bottom:1px solid var(--border)">
      <div style="flex:1;min-width:0">
        <div style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:${isCst ? 'var(--gold)' : 'var(--teal)'}">${escH(r.id)}</div>
        <div style="font-size:.72rem;color:var(--text-sec);margin-top:2px">${escH(r.recipientName || '—')}</div>
      </div>
      ${badge}
      <span style="display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;font-size:.62rem;font-weight:700;letter-spacing:.05em;background:${stBg};border:1px solid ${stColor}66;color:${stColor}">${st}</span>
      <span style="font-size:.68rem;color:var(--text-sec);min-width:78px;text-align:right">${fmtDt(r.validUntil)}</span>
    </div>`;
  }

  function certSection(title, color, list, isCst) {
    const rows = list.length
      ? list.map(r => certRow(r, isCst)).join('')
      : `<div style="padding:12px 4px;font-size:.72rem;color:var(--text-sec)">No ${escH(title)} records for this vessel.</div>`;
    return `<div style="margin-bottom:16px">
      <div style="font-size:.66rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:${color};margin-bottom:6px">${escH(title)} (${list.length})</div>
      ${rows}
    </div>`;
  }

  function openCcrModal(key) {
    const v = vesselIndex.get(key);
    if (!v) return;
    const overlay = document.getElementById('ccrModal');
    if (!overlay) return;
    document.getElementById('ccrModalTitle').textContent = v.vesselName + (v.imo ? ' — IMO ' + v.imo : '');
    document.getElementById('ccrModalBody').innerHTML =
      certSection('CST Training', 'var(--gold)', v.cst, true) +
      certSection('VAPT Assessment', 'var(--teal)', v.vapt, false);
    overlay.style.display = 'flex';
  }
  window.openCcrModal = openCcrModal;

  function closeCcrModal() {
    const overlay = document.getElementById('ccrModal');
    if (overlay) overlay.style.display = 'none';
  }
  window.closeCcrModal = closeCcrModal;

  // Section is hidden by default in the page's own markup — reveal + load
  // only for the client role, independent of the host page's own boot logic.
  fetch(API + '/auth/verify').then(r => r.ok ? r.json() : null).then(info => {
    if (!info || info.role !== 'client') return;
    const sec = document.getElementById('clientCombinedSection');
    if (sec) sec.style.display = 'block';
    loadCcrRecords();
  }).catch(() => {});
})();
