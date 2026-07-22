'use strict';
(function() {
  const API = '/api';
  let TOKEN = sessionStorage.getItem('adminToken') || '';
  let allRecords  = [];
  let vesselIndex = new Map(); // imo -> { imo, vesselName, cst:[], vapt:[] }

  const authHdr = () => ({ Authorization: 'Bearer ' + TOKEN });
  function checkUnauth(r) { if (r.status === 401) { window.doLogout(); return true; } return false; }

  const RISK_STYLE = {
    CRITICAL: { emoji: '🔴', color: 'var(--invalid)' },
    HIGH:     { emoji: '🟠', color: 'var(--warn)' },
    MEDIUM:   { emoji: '🟡', color: 'var(--warn)' },
    LOW:      { emoji: '🟢', color: 'var(--teal)' },
  };
  // Same palette as the CST certificate list's per-quarter badge (dashboard.js)
  // and the superintendent portal (portal.js) — Q3 is purple rather than
  // orange so it isn't confused with Q2's gold at a glance.
  const Q_COLORS = { Q1: '#64FFDA', Q2: '#D4A843', Q3: '#B47EFF', Q4: '#FF5C7A' };

  const escH  = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  const fmtDt = s => s ? new Date(s).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';

  async function loadRecordsData() {
    try {
      const [rC, rV] = await Promise.all([
        fetch(API + '/certs',      { headers: authHdr() }),
        fetch(API + '/vapt/certs', { headers: authHdr() }),
      ]);
      if (checkUnauth(rC) || checkUnauth(rV)) return;
      if (!rC.ok || !rV.ok) { toast('Failed to load records', true); return; }
      const cst  = (await rC.json()).map(c => Object.assign({ _type: 'CST' },  c));
      const vapt = (await rV.json()).map(c => Object.assign({ _type: 'VAPT' }, c));
      allRecords = cst.concat(vapt);
      buildVesselIndex();
      updateStats();
      renderRecords();
    } catch { toast('Connection failed. Check your internet and try again.', true); }
  }
  window.loadRecordsData = loadRecordsData;

  function buildVesselIndex() {
    vesselIndex = new Map();
    allRecords.forEach(r => {
      const key = (r.vesselIMO || r.vesselName || 'unknown').toUpperCase();
      if (!vesselIndex.has(key)) vesselIndex.set(key, { imo: r.vesselIMO || '', vesselName: r.vesselName || 'Unknown Vessel', cst: [], vapt: [] });
      const v = vesselIndex.get(key);
      if (r._type === 'CST') v.cst.push(r); else v.vapt.push(r);
      // Prefer whichever record actually has a vessel name, in case an
      // early record for this IMO was missing it.
      if (!v.vesselName || v.vesselName === 'Unknown Vessel') v.vesselName = r.vesselName || v.vesselName;
    });
  }

  function updateStats() {
    document.getElementById('recStatVessels').textContent = vesselIndex.size;
    document.getElementById('recStatCst').textContent     = allRecords.filter(r => r._type === 'CST').length;
    document.getElementById('recStatVapt').textContent    = allRecords.filter(r => r._type === 'VAPT').length;
    document.getElementById('recStatValid').textContent   = allRecords.filter(r => (r.status || '').toUpperCase() === 'VALID').length;
  }

  function renderRecords() {
    const q = (document.getElementById('recSearch').value || '').toLowerCase();
    const vessels = Array.from(vesselIndex.values()).filter(v => {
      if (!q) return true;
      return v.vesselName.toLowerCase().includes(q) || (v.imo || '').toLowerCase().includes(q);
    });
    vessels.sort((a, b) => a.vesselName.localeCompare(b.vesselName));

    const grid  = document.getElementById('recVesselGrid');
    const empty = document.getElementById('recEmpty');
    if (!vessels.length) {
      grid.innerHTML = '';
      document.getElementById('recEmptyMsg').textContent = vesselIndex.size
        ? 'No vessels match your search.'
        : 'No certificate records yet.';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';

    grid.innerHTML = vessels.map(v => {
      const total = v.cst.length + v.vapt.length;
      const validCount = v.cst.concat(v.vapt).filter(r => (r.status || '').toUpperCase() === 'VALID').length;
      return `<div class="group-card" style="cursor:pointer" data-action="openVesselRecords" data-imo="${escH(v.imo || v.vesselName)}">
        <div class="group-card-head">
          <div class="group-name">${escH(v.vesselName)}</div>
          <span class="vessel-count">${total} record${total !== 1 ? 's' : ''}</span>
        </div>
        <div class="group-card-body">
          ${v.imo ? `<div class="imo-chips"><span class="imo-chip">IMO ${escH(v.imo)}</span></div>` : ''}
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:${v.imo ? '10px' : '0'}">
            <span class="role-badge" style="background:rgba(212,168,67,.1);border-color:rgba(212,168,67,.25);color:var(--gold)">CST ${v.cst.length}</span>
            <span class="role-badge" style="background:rgba(100,255,218,.1);border-color:rgba(100,255,218,.25);color:var(--teal)">VAPT ${v.vapt.length}</span>
            ${validCount ? `<span class="active-pill on">${validCount} Valid</span>` : ''}
          </div>
        </div>
      </div>`;
    }).join('');
  }
  window.renderRecords = renderRecords;

  function certSection(title, color, list, isVapt) {
    if (!list.length) return '';
    const rows = list.map(r => {
      const st = (r.status || 'PENDING').toUpperCase();
      const stColor = st === 'VALID' ? 'var(--teal)' : st === 'REVOKED' ? 'var(--invalid)' : st === 'EXPIRED' ? 'var(--warn)' : 'var(--text-sec)';
      const stBg    = st === 'VALID' ? 'rgba(100,255,218,.1)' : st === 'REVOKED' ? 'rgba(255,107,138,.1)' : st === 'EXPIRED' ? 'rgba(255,170,46,.1)' : 'rgba(255,255,255,.05)';
      let tagCell = '<span style="color:var(--text-sec);font-size:.7rem">—</span>';
      if (!isVapt && r.complianceQuarter) {
        const qc = Q_COLORS[r.complianceQuarter.toUpperCase()] || 'var(--text-sec)';
        tagCell = `<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:.6rem;font-weight:700;letter-spacing:.06em;background:${qc}1F;border:1px solid ${qc};color:${qc}">${escH(r.complianceQuarter)}</span>`;
      } else if (isVapt && r.riskLevel) {
        const ri = RISK_STYLE[r.riskLevel.toUpperCase()] || { emoji: '', color: 'var(--text-sec)' };
        tagCell = `<span style="font-size:.7rem;color:${ri.color}">${ri.emoji} ${escH(r.riskLevel)}</span>`;
      }
      return `<div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)">
        <div style="flex:1;min-width:0">
          <div style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:${color}">${escH(r.id)}</div>
          <div style="font-size:.76rem;color:var(--text-bright);margin-top:2px">${escH(r.recipientName || '—')}</div>
        </div>
        <div style="flex-shrink:0">${tagCell}</div>
        <div style="flex-shrink:0"><span class="active-pill" style="background:${stBg};border:1px solid ${stColor}66;color:${stColor}">${st}</span></div>
        <div style="flex-shrink:0;font-size:.7rem;color:var(--text-sec);min-width:80px;text-align:right">${fmtDt(r.validUntil)}</div>
      </div>`;
    }).join('');
    return `<div style="margin-bottom:18px">
      <div style="font-size:.68rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:${color};margin-bottom:8px">${title} (${list.length})</div>
      ${rows}
    </div>`;
  }

  function openVesselRecords(imoKey) {
    const v = vesselIndex.get(String(imoKey).toUpperCase()) ||
              Array.from(vesselIndex.values()).find(x => x.imo === imoKey || x.vesselName === imoKey);
    if (!v) return;
    document.getElementById('vesselModalTitle').textContent = v.vesselName + (v.imo ? ` · IMO ${v.imo}` : '');
    const cstHtml  = certSection('CST Training Certificates', 'var(--gold)', v.cst, false);
    const vaptHtml = certSection('VAPT Assessments', 'var(--teal)', v.vapt, true);
    document.getElementById('vesselModalBody').innerHTML = (cstHtml + vaptHtml) ||
      '<div style="padding:24px;text-align:center;color:var(--text-sec);font-size:.8rem">No records for this vessel.</div>';
    document.getElementById('vesselRecordsModal').classList.add('open', 'show');
  }
  window.openVesselRecords = openVesselRecords;

  function closeVesselRecords() {
    document.getElementById('vesselRecordsModal').classList.remove('open', 'show');
  }
  window.closeVesselRecords = closeVesselRecords;

  // Backdrop click-to-close — a direct listener scoped to this one element,
  // not routed through the shared hub-actions.js dispatcher (which has no
  // "only the overlay itself, not its children" guard). The modal markup is
  // already parsed by the time this (non-deferred) script tag runs.
  const _vesselOverlay = document.getElementById('vesselRecordsModal');
  if (_vesselOverlay) _vesselOverlay.addEventListener('click', (e) => { if (e.target === _vesselOverlay) closeVesselRecords(); });

  function toast(msg, isErr) {
    const el = document.createElement('div');
    el.className = 'toast-msg ' + (isErr ? 'err' : 'ok');
    el.textContent = msg;
    document.getElementById('toast').appendChild(el);
    setTimeout(() => el.remove(), 3200);
  }

  // This tab only loads on the already server-gated hub page (unauthenticated
  // requests never reach here), so no client-side token check is needed.
  loadRecordsData();
})();
