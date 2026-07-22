'use strict';
(function() {
  const API = '/api';
  let TOKEN = sessionStorage.getItem('adminToken') || '';
  let allRecords = [];

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
      updateStats();
      renderRecords();
    } catch { toast('Connection failed. Check your internet and try again.', true); }
  }
  window.loadRecordsData = loadRecordsData;

  function updateStats() {
    document.getElementById('recStatTotal').textContent = allRecords.length;
    document.getElementById('recStatCst').textContent   = allRecords.filter(r => r._type === 'CST').length;
    document.getElementById('recStatVapt').textContent  = allRecords.filter(r => r._type === 'VAPT').length;
    document.getElementById('recStatValid').textContent = allRecords.filter(r => (r.status || '').toUpperCase() === 'VALID').length;
  }

  function renderRecords() {
    const q      = (document.getElementById('recSearch').value || '').toLowerCase();
    const type   = document.getElementById('recTypeFilter').value;
    const status = document.getElementById('recStatusFilter').value;
    const list = allRecords.filter(r => {
      if (type && r._type !== type) return false;
      if (status && (r.status || '').toUpperCase() !== status) return false;
      if (q) {
        const haystack = [r.id, r.recipientName, r.vesselName, r.vesselIMO].join(' ').toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
    const tbody = document.getElementById('recTbody');
    const empty = document.getElementById('recEmpty');
    if (!list.length) {
      tbody.innerHTML = '';
      document.getElementById('recEmptyMsg').textContent = allRecords.length
        ? 'No records match your search or filters.'
        : 'No certificate records yet.';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    const escH  = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
    const fmtDt = s => s ? new Date(s).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';

    // Most recently issued first, mixing CST and VAPT together by date rather
    // than grouping by type — the point of this view is to see both at once.
    list.sort((a, b) => new Date(b.complianceDate || b.issuedAt || 0) - new Date(a.complianceDate || a.issuedAt || 0));

    tbody.innerHTML = list.map(r => {
      const isCst = r._type === 'CST';
      const typeBadge = isCst
        ? `<span class="role-badge" style="background:rgba(212,168,67,.1);border-color:rgba(212,168,67,.25);color:var(--gold)">CST</span>`
        : `<span class="role-badge">VAPT</span>`;
      let qrCell = '<span style="color:var(--text-sec);font-size:.7rem">—</span>';
      if (isCst && r.complianceQuarter) {
        const qc = Q_COLORS[r.complianceQuarter.toUpperCase()] || 'var(--text-sec)';
        qrCell = `<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:.62rem;font-weight:700;letter-spacing:.06em;background:${qc}1F;border:1px solid ${qc};color:${qc}">${escH(r.complianceQuarter)}</span>`;
      } else if (!isCst && r.riskLevel) {
        const ri = RISK_STYLE[r.riskLevel.toUpperCase()] || { emoji: '', color: 'var(--text-sec)' };
        qrCell = `<span style="font-size:.72rem;color:${ri.color}">${ri.emoji} ${escH(r.riskLevel)}</span>`;
      }
      const st = (r.status || 'PENDING').toUpperCase();
      const stColor = st === 'VALID' ? 'var(--teal)' : st === 'REVOKED' ? 'var(--invalid)' : st === 'EXPIRED' ? 'var(--warn)' : 'var(--text-sec)';
      const stBg    = st === 'VALID' ? 'rgba(100,255,218,.1)' : st === 'REVOKED' ? 'rgba(255,107,138,.1)' : st === 'EXPIRED' ? 'rgba(255,170,46,.1)' : 'rgba(255,255,255,.05)';
      return `<tr>
        <td>${typeBadge}</td>
        <td><span style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:${isCst ? 'var(--gold)' : 'var(--teal)'}">${escH(r.id)}</span></td>
        <td><div class="user-name">${escH(r.recipientName || '—')}</div><div class="user-email">${escH(r.vesselName || '')}</div></td>
        <td><span style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text-sec)">${escH(r.vesselIMO || '—')}</span></td>
        <td>${qrCell}</td>
        <td><span class="active-pill" style="background:${stBg};border:1px solid ${stColor}66;color:${stColor}">${st}</span></td>
        <td style="font-size:.7rem;color:var(--text-sec)">${fmtDt(r.validUntil)}</td>
      </tr>`;
    }).join('');
  }
  window.renderRecords = renderRecords;

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
