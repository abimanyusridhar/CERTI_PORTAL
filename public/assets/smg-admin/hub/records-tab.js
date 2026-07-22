'use strict';
(function() {
  const API = '/api';
  let TOKEN = sessionStorage.getItem('adminToken') || '';
  let vesselIndex = new Map(); // key -> { imo, vesselName, cst: [], vapt: [] }

  const authHdr = () => ({ Authorization: 'Bearer ' + TOKEN });
  function checkUnauth(r) { if (r.status === 401) { window.doLogout(); return true; } return false; }

  const RISK_STYLE = {
    CRITICAL: { emoji: '🔴', color: 'var(--invalid)' },
    HIGH:     { emoji: '🟠', color: 'var(--warn)' },
    MEDIUM:   { emoji: '🟡', color: 'var(--warn)' },
    LOW:      { emoji: '🟢', color: 'var(--teal)' },
  };
  // Same palette as the CST certificate list's per-quarter badge (dashboard.js) —
  // Q3 uses purple rather than orange so it isn't confused with Q2's gold at a glance.
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
      vesselIndex = buildVesselIndex(cst, vapt);
      updateStats(cst, vapt);
      renderRecords();
    } catch { toast('Connection failed. Check your internet and try again.', true); }
  }
  window.loadRecordsData = loadRecordsData;

  function updateStats(cst, vapt) {
    const validCount = cst.filter(isValid).length + vapt.filter(isValid).length;
    document.getElementById('recStatVessels').textContent = vesselIndex.size;
    document.getElementById('recStatCst').textContent     = cst.length;
    document.getElementById('recStatVapt').textContent    = vapt.length;
    document.getElementById('recStatValid').textContent   = validCount;
  }

  function renderRecords() {
    const q = (document.getElementById('recSearch').value || '').toLowerCase();
    const vessels = [...vesselIndex.entries()]
      .filter(([key, v]) => !q || v.vesselName.toLowerCase().includes(q) || (v.imo || '').toLowerCase().includes(q))
      .sort((a, b) => a[1].vesselName.localeCompare(b[1].vesselName));

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

    grid.innerHTML = vessels.map(([key, v]) => {
      const validCount = v.cst.filter(isValid).length + v.vapt.filter(isValid).length;
      const totalCount = v.cst.length + v.vapt.length;
      return `<div class="group-card" style="cursor:pointer" data-action="openVesselRecModal" data-imo="${escH(key)}">
        <div class="group-card-head">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--gold)" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 21h18M5 21V10l7-7 7 7v11M9 21v-6h6v6"/></svg>
          <span class="group-name">${escH(v.vesselName)}</span>
          <span class="vessel-count">${totalCount} record${totalCount !== 1 ? 's' : ''}</span>
        </div>
        <div class="group-card-body">
          <div style="font-family:'JetBrains Mono',monospace;font-size:.68rem;color:var(--text-sec);margin-bottom:10px">${v.imo ? 'IMO ' + escH(v.imo) : 'IMO unavailable'}</div>
          <div class="imo-chips">
            <span class="imo-chip" style="background:rgba(212,168,67,.13);border-color:rgba(212,168,67,.32);color:var(--gold)">CST ${v.cst.length}</span>
            <span class="imo-chip">VAPT ${v.vapt.length}</span>
            <span class="imo-chip" style="background:rgba(100,255,218,.08);border-color:rgba(100,255,218,.22);color:var(--teal)">${validCount} valid</span>
          </div>
        </div>
      </div>`;
    }).join('');
  }
  window.renderRecords = renderRecords;

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
      <span class="active-pill" style="background:${stBg};border:1px solid ${stColor}66;color:${stColor}">${st}</span>
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

  function openVesselRecModal(key) {
    const v = vesselIndex.get(key);
    if (!v) return;
    document.getElementById('vesselRecModalTitle').textContent = v.vesselName + (v.imo ? ' — IMO ' + v.imo : '');
    document.getElementById('vesselRecModalBody').innerHTML =
      certSection('CST Training', 'var(--gold)', v.cst, true) +
      certSection('VAPT Assessment', 'var(--teal)', v.vapt, false);
    document.getElementById('vesselRecModal').classList.add('open');
  }
  window.openVesselRecModal = openVesselRecModal;

  function closeVesselRecModal() { document.getElementById('vesselRecModal').classList.remove('open'); }
  window.closeVesselRecModal = closeVesselRecModal;

  const _vrModal = document.getElementById('vesselRecModal');
  if (_vrModal) _vrModal.addEventListener('click', e => { if (e.target === _vrModal) closeVesselRecModal(); });

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
