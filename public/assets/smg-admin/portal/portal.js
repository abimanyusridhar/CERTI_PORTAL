'use strict';
// ─── SESSION (server-side httpOnly cookie is the source of truth; only the
// display name — not a credential — is cached client-side for instant render) ──
const LS_NAME = 'suptSessionName';
function getName()      { return localStorage.getItem(LS_NAME) || ''; }
function saveSession(n) { if (n) localStorage.setItem(LS_NAME, n); }
function clearSession() { localStorage.removeItem(LS_NAME); }

function applyPortalConfig() {
  const C = window.APP_CONFIG;
  if (!C) return;
  const portalPath = ((C.routes && C.routes.cstAdmin) || '/CST/misecure') + '/portal/';
  const btn = document.getElementById('ssoLoginBtn');
  if (btn) btn.href = '/auth/sso/login?next=' + encodeURIComponent(portalPath);
  const ssoErr = new URLSearchParams(location.search).get('sso_error');
  if (ssoErr) {
    const el = document.getElementById('ssoErrMsg');
    if (el) {
      const SSO_MSGS = {
        deactivated:     'Your account has been deactivated. Contact your administrator.',
        not_enrolled:    'Your account is not registered in this portal. Ask your administrator to add you.',
        auth_failed:     'Authentication failed. Please try again or contact your administrator.',
        session_expired: 'Your login session expired. Please try again.'
      };
      el.textContent = SSO_MSGS[ssoErr] || 'SSO login failed. Please check your account or contact your administrator.';
      el.style.display = 'block';
    }
  }
}
function showLogin() {
  document.getElementById('loginWrap').style.display = 'flex';
  applyPortalConfig();
  document.addEventListener('appconfigready', applyPortalConfig);
}

// ─── INIT ──────────────────────────────────────────────────────────────────────
// Session lives in an httpOnly cookie set by the SSO callback — the browser sends
// it automatically, so a single check here covers the SSO-login case with no
// client-readable token. SSO is the only login path; there is no password form.
window.addEventListener('DOMContentLoaded', () => {
  fetch('/api/auth/user/me')
    .then(r => r.ok ? r.json() : null)
    .then(d => {
      if (d && d.user) {
        saveSession(d.user.name || d.user.email || '');
        enterApp(d.user.name || d.user.email || '');
        loadDashboard();
      } else {
        showLogin();
      }
    })
    .catch(() => showLogin());
});

function enterApp(name) {
  document.getElementById('loginWrap').style.display = 'none';
  document.getElementById('appWrap').style.display = 'flex';
  document.getElementById('sbUserName').textContent = name || 'Superintendent';
}

function doLogout() {
  fetch('/api/auth/user/logout', { method: 'POST' }).catch(() => {}).finally(() => {
    clearSession();
    location.reload();
  });
}

// ─── HELPERS ───────────────────────────────────────────────────────────────────
function fmtDate(d)    { if (!d) return '—'; try { return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }); } catch { return d; } }
function statusPill(s) {
  const v = (s || '').toUpperCase();
  if (v === 'VALID')   return `<span class="status-pill valid">● VALID</span>`;
  if (v === 'EXPIRED') return `<span class="status-pill expired">● EXPIRED</span>`;
  return `<span class="status-pill pending">● ${v || 'PENDING'}</span>`;
}
function riskPill(r) {
  const v = (r || '').toUpperCase();
  const cls = v === 'CRITICAL' ? 'critical' : v === 'HIGH' ? 'high' : v === 'MEDIUM' ? 'medium' : 'low';
  return `<span class="risk-pill ${cls}">${v || 'N/A'}</span>`;
}

// ─── DASHBOARD ─────────────────────────────────────────────────────────────────
let _vessels = [];
let _imoToGroups = {};
let _chartCstStatus = null;
let _chartVaptStatus = null;
let _chartVesselValidity = null;

async function loadDashboard() {
  const grid = document.getElementById('vesselGrid');
  grid.innerHTML = '<div class="loading-center"><div class="spinner"></div> Loading vessels…</div>';
  showView('dashboard');
  try {
    const [rVessels, rMe] = await Promise.all([
      fetch('/api/supt/vessels'),
      fetch('/api/auth/user/me'),
    ]);
    if (rVessels.status === 401) { clearSession(); location.reload(); return; }
    if (!rVessels.ok) throw new Error('Failed to load vessels');
    _vessels = await rVessels.json();
    // Build IMO → group names map from /me response
    _imoToGroups = {};
    if (rMe.ok) {
      const me = await rMe.json();
      ((me.user && me.user.groups) || []).forEach(g => {
        (g.vesselIMOs || []).forEach(imo => {
          const key = imo.toUpperCase();
          if (!_imoToGroups[key]) _imoToGroups[key] = [];
          if (!_imoToGroups[key].includes(g.name)) _imoToGroups[key].push(g.name);
        });
      });
    }
    renderDashboard(_vessels);
  } catch (e) {
    grid.innerHTML = `<div class="loading-center" style="color:var(--invalid)">Failed to load vessels. ${e.message}</div>`;
  }
}

function renderDashboard(vessels) {
  const grid = document.getElementById('vesselGrid');
  const sub  = document.getElementById('dashSub');
  const now  = Date.now();
  const d30  = now + 30 * 864e5;
  const d90  = now + 90 * 864e5;

  // Aggregate fleet-wide stats
  const totCst      = vessels.reduce((a, v) => a + (v.cstCount  || 0), 0);
  const totVapt     = vessels.reduce((a, v) => a + (v.vaptCount || 0), 0);
  const totDocs     = vessels.reduce((a, v) => a + (v.docCount  || 0), 0);
  const cstValid    = vessels.reduce((a, v) => a + (v.cstValid   || 0), 0);
  const cstExpired  = vessels.reduce((a, v) => a + (v.cstExpired || 0), 0);
  const cstPending  = vessels.reduce((a, v) => a + (v.cstPending || 0), 0);
  const cstExp90    = vessels.reduce((a, v) => a + (v.cstExpiring || 0), 0);
  const cstVesselsExpiring = vessels.filter(v => (v.cstExpiring || 0) > 0).length;
  const vaptValid   = vessels.reduce((a, v) => a + (v.vaptValid   || 0), 0);
  const vaptExpired = vessels.reduce((a, v) => a + (v.vaptExpired || 0), 0);
  const vaptPending = vessels.reduce((a, v) => a + (v.vaptPending || 0), 0);
  const vaptVessels = vessels.filter(v => (v.vaptCount || 0) > 0).length;
  const coverage    = vessels.length ? Math.round((vaptVessels / vessels.length) * 100) : 0;

  // Populate overview cards
  document.getElementById('statVessels').textContent   = vessels.length;
  document.getElementById('statCstCerts').textContent  = totCst;
  document.getElementById('statVaptCerts').textContent = totVapt;
  document.getElementById('statDocs').textContent      = totDocs;

  // Populate CST detail cards
  const el = id => document.getElementById(id);
  if (el('statCstValid'))    el('statCstValid').textContent    = cstValid;
  if (el('statCstExpired'))  el('statCstExpired').textContent  = cstExpired;
  if (el('statCstPending'))  el('statCstPending').textContent  = cstPending;
  if (el('statCstExp30'))    el('statCstExp30').textContent    = cstVesselsExpiring;
  if (el('statCstExp90'))    el('statCstExp90').textContent    = cstExp90;

  // Populate VAPT detail cards
  if (el('statVaptValid'))     el('statVaptValid').textContent     = vaptValid;
  if (el('statVaptExpired'))   el('statVaptExpired').textContent   = vaptExpired;
  if (el('statVaptPending'))   el('statVaptPending').textContent   = vaptPending;
  if (el('statVaptVessels'))   el('statVaptVessels').textContent   = vaptVessels;
  if (el('statVaptCoverage'))  el('statVaptCoverage').textContent  = coverage + '%';

  sub.textContent = `${vessels.length} vessel${vessels.length !== 1 ? 's' : ''} · ${cstValid} valid CST · ${vaptValid} valid VAPT · ${cstPending + vaptPending} pending`;

  // Build charts after DOM settles
  setTimeout(() => buildAnalyticsCharts(vessels, totCst, cstValid, cstExpired, cstPending, cstExp90, totVapt, vaptValid, vaptExpired, vaptPending, cstVesselsExpiring), 50);
  renderExpiryPanel(vessels);
  // Sidebar list
  const sbList = document.getElementById('sbVesselList');
  sbList.innerHTML = vessels.map(v => `
    <div class="sb-vessel-item" id="sb-${v.imo}" data-action="openVessel" data-imo="${escHtml(v.imo)}">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 17l3-9 4 5 3-7 5 11H3z"/></svg>
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(v.vesselName)}</span>
    </div>`).join('');
  // Grid cards
  if (!vessels.length) {
    grid.innerHTML = `<div class="loading-center" style="grid-column:1/-1">
      <div style="text-align:center">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" style="opacity:.2;display:block;margin:0 auto 12px"><path d="M3 17l3-9 4 5 3-7 5 11H3z"/></svg>
        <div style="font-size:.85rem;color:var(--text-sec)">No vessels assigned to your account</div>
        <div style="font-size:.72rem;color:var(--text-sec);opacity:.6;margin-top:4px">Contact your administrator to request vessel access</div>
      </div></div>`;
    return;
  }
  grid.innerHTML = vessels.map(v => {
    const groups = _imoToGroups[v.imo] || [];
    const groupBadges = groups.map(g => `<span class="group-badge"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>${escHtml(g)}</span>`).join('');
    return `<div class="vessel-card" data-action="openVessel" data-imo="${escHtml(v.imo)}">
      <div class="vc-header">
        <div class="vc-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#64FFDA" stroke-width="1.8"><path d="M3 17l3-9 4 5 3-7 5 11H3z"/></svg>
        </div>
        <div style="flex:1;min-width:0">
          <div class="vc-name">${escHtml(v.vesselName)}</div>
          <div class="vc-imo">IMO ${escHtml(v.imo)}</div>
        </div>
      </div>
      ${groups.length ? `<div class="vc-groups">${groupBadges}</div>` : ''}
      <div class="vc-counts" style="margin-top:${groups.length ? '8' : '0'}px">
        <span class="vc-pill cst">${v.cstCount} CST</span>
        <span class="vc-pill vapt">${v.vaptCount} VAPT</span>
        <span class="vc-pill doc">${v.docCount} Docs</span>
      </div>
      <div class="vc-footer">
        <div class="vc-valid">${v.cstValid + v.vaptValid} valid cert${(v.cstValid + v.vaptValid) !== 1 ? 's' : ''} active
          ${v.cstExpiring ? `<span style="margin-left:6px;display:inline-flex;align-items:center;gap:3px;padding:2px 7px;border-radius:20px;font-size:.6rem;font-weight:700;background:rgba(255,170,46,.1);border:1px solid rgba(255,170,46,.3);color:#FFAA2E">&#9651; ${v.cstExpiring} expiring</span>` : ''}
        </div>
        <svg class="vc-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
      </div>
    </div>`;
  }).join('');
}

// ─── ANALYTICS CHARTS ─────────────────────────────────────────────────────────
function _chartDefaults() {
  return {
    plugins: { legend: { display: false }, tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed}` } } },
    animation: { duration: 600 },
  };
}

function buildAnalyticsCharts(vessels, totCst, cstValid, cstExpired, cstPending, cstExp90, totVapt, vaptValid, vaptExpired, vaptPending, cstVesselsExpiring) {
  if (typeof Chart === 'undefined') return;

  const isLight = document.documentElement.classList.contains('light');
  const TEAL  = isLight ? 'rgba(10,124,110,0.80)'  : 'rgba(100,255,218,0.85)';
  const RED   = isLight ? 'rgba(220,38,38,0.75)'   : 'rgba(255,107,138,0.85)';
  const GOLD  = isLight ? 'rgba(212,168,67,0.80)'  : 'rgba(212,168,67,0.85)';
  const AMBER = isLight ? 'rgba(217,119,6,0.80)'   : 'rgba(255,170,46,0.80)';
  const BLUE  = isLight ? 'rgba(37,99,235,0.75)'   : 'rgba(118,137,174,0.85)';
  const GREY  = isLight ? 'rgba(30,60,120,0.08)'   : 'rgba(255,255,255,0.08)';
  const tickColor  = isLight ? 'rgba(10,22,40,.45)' : 'rgba(255,255,255,.45)';
  const gridColor  = isLight ? 'rgba(30,60,120,.06)' : 'rgba(255,255,255,.05)';
  const legendColor = isLight ? 'rgba(10,22,40,.6)'  : 'rgba(255,255,255,.6)';

  // ── CST Status Donut ──────────────────────────────────────────────────────────
  const cstCtx = document.getElementById('cstStatusChart');
  if (cstCtx) {
    if (_chartCstStatus) _chartCstStatus.destroy();
    _chartCstStatus = new Chart(cstCtx, {
      type: 'doughnut',
      data: {
        labels: ['Valid', 'Expiring ≤90d', 'Expired', 'Pending'],
        datasets: [{ data: [Math.max(0, cstValid - cstExp90), cstExp90, cstExpired, cstPending],
          backgroundColor: [TEAL, AMBER, RED, BLUE], borderWidth: 0, hoverOffset: 4 }]
      },
      options: { ..._chartDefaults(), cutout: '68%', maintainAspectRatio: false }
    });
    const leg = document.getElementById('cstStatusLegend');
    if (leg) leg.innerHTML = [
      [TEAL,  'Valid (stable)',    Math.max(0, cstValid - cstExp90)],
      [AMBER, 'Expiring ≤90 days', cstExp90],
      [RED,   'Expired',           cstExpired],
      [BLUE,  'Pending',           cstPending],
    ].map(([c, l, n]) =>
      `<div class="chart-legend-item"><span class="chart-legend-dot" style="background:${c}"></span>${l}<span class="chart-legend-val">${n}</span></div>`
    ).join('');
  }

  // ── VAPT Status Donut ─────────────────────────────────────────────────────────
  const vaptCtx = document.getElementById('vaptStatusChart');
  if (vaptCtx) {
    if (_chartVaptStatus) _chartVaptStatus.destroy();
    const noVapt = Math.max(0, vessels.length - vessels.filter(v => v.vaptCount > 0).length);
    _chartVaptStatus = new Chart(vaptCtx, {
      type: 'doughnut',
      data: {
        labels: ['Valid', 'Expired', 'Pending', 'No VAPT'],
        datasets: [{ data: [vaptValid, vaptExpired, vaptPending, noVapt],
          backgroundColor: [GOLD, RED, BLUE, GREY], borderWidth: 0, hoverOffset: 4 }]
      },
      options: { ..._chartDefaults(), cutout: '68%', maintainAspectRatio: false }
    });
    const leg = document.getElementById('vaptStatusLegend');
    if (leg) leg.innerHTML = [
      [GOLD, 'Valid',    vaptValid],
      [RED,  'Expired',  vaptExpired],
      [BLUE, 'Pending',  vaptPending],
      [GREY, 'No VAPT',  noVapt],
    ].map(([c, l, n]) =>
      `<div class="chart-legend-item"><span class="chart-legend-dot" style="background:${c}"></span>${l}<span class="chart-legend-val">${n}</span></div>`
    ).join('');
  }

  // ── Per-vessel validity bar chart ─────────────────────────────────────────────
  const vvCtx = document.getElementById('vesselValidityChart');
  if (vvCtx && vessels.length) {
    const top = vessels.slice().sort((a, b) => (b.cstCount + b.vaptCount) - (a.cstCount + a.vaptCount)).slice(0, 10);
    if (_chartVesselValidity) _chartVesselValidity.destroy();
    _chartVesselValidity = new Chart(vvCtx, {
      type: 'bar',
      data: {
        labels: top.map(v => v.vesselName.length > 14 ? v.vesselName.slice(0, 13) + '…' : v.vesselName),
        datasets: [
          { label: 'CST Valid',   data: top.map(v => v.cstValid   || 0), backgroundColor: TEAL, borderRadius: 3 },
          { label: 'CST Expired', data: top.map(v => v.cstExpired || 0), backgroundColor: RED,  borderRadius: 3 },
          { label: 'CST Pending', data: top.map(v => v.cstPending || 0), backgroundColor: BLUE, borderRadius: 3 },
          { label: 'VAPT Valid',  data: top.map(v => v.vaptValid  || 0), backgroundColor: GOLD, borderRadius: 3 },
        ]
      },
      options: {
        ..._chartDefaults(),
        maintainAspectRatio: false,
        scales: {
          x: { stacked: false, ticks: { color: tickColor, font: { size: 10 } }, grid: { display: false } },
          y: { ticks: { color: tickColor, font: { size: 10 }, precision: 0 }, grid: { color: gridColor } }
        },
        plugins: { legend: { display: true, position: 'top', labels: { color: legendColor, font: { size: 10 }, boxWidth: 10, padding: 12 } }, tooltip: {} }
      }
    });
  }
}

// ─── EXPIRY ALERT PANEL ────────────────────────────────────────────────────────
function renderExpiryPanel(vessels) {
  const panel = document.getElementById('expiryAlertPanel');
  if (!panel) return;

  const sorted = vessels.slice().sort((a, b) => {
    const aScore = (a.cstExpiring || 0) * 10 + (a.cstExpired || 0);
    const bScore = (b.cstExpiring || 0) * 10 + (b.cstExpired || 0);
    return bScore - aScore;
  });

  const withExpiry = sorted.filter(v => (v.cstExpiring || 0) > 0);
  const count = withExpiry.length;

  panel.innerHTML =
    `<div class="alert-panel-hdr">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#FFAA2E" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
      <span class="alert-panel-title">Vessel Certificate Summary</span>
      ${count ? `<span class="alert-badge amber">⚠ ${count} vessel${count > 1 ? 's' : ''} expiring soon</span>` : '<span class="alert-badge ok">✓ No imminent expiries</span>'}
    </div>`
    + sorted.map(v => {
      const cstTotal   = v.cstCount   || 0;
      const cstValid   = v.cstValid   || 0;
      const cstExpired = v.cstExpired || 0;
      const cstExpiring= v.cstExpiring || 0;
      const vaptTotal  = v.vaptCount || 0;
      const vaptValid  = v.vaptValid || 0;
      const fillPct    = cstTotal ? Math.round((cstValid / cstTotal) * 100) : 0;
      const fillColor  = fillPct >= 80 ? '#64FFDA' : fillPct >= 50 ? '#FFAA2E' : '#FF5C7A';
      return `<div class="alert-row" data-action="openVessel" data-imo="${escHtml(v.imo)}">
        <div style="min-width:0;flex:1">
          <div class="alert-vessel">${escHtml(v.vesselName)}</div>
          <div class="alert-imo">IMO ${escHtml(v.imo)}</div>
        </div>
        <div class="alert-bar-wrap">
          <div style="font-size:.57rem;color:var(--text-sec);margin-bottom:3px;display:flex;justify-content:space-between"><span>CST validity</span><span>${fillPct}%</span></div>
          <div class="alert-bar-bg"><div class="alert-bar-fill" style="width:${fillPct}%;background:${fillColor}"></div></div>
        </div>
        <div class="alert-counts">
          <span class="alert-pill ok" title="CST Valid">${cstValid} valid</span>
          ${cstExpiring ? `<span class="alert-pill warn" title="CST Expiring ≤90d">⚠ ${cstExpiring} exp.</span>` : ''}
          ${cstExpired  ? `<span class="alert-pill bad" title="CST Expired">${cstExpired} exp'd</span>` : ''}
          ${vaptTotal   ? `<span class="vapt-badge" title="VAPT">${vaptValid}/${vaptTotal} VAPT</span>` : '<span style="font-size:.6rem;color:var(--text-sec)">No VAPT</span>'}
        </div>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--text-sec)" stroke-width="2" style="flex-shrink:0"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
      </div>`;
    }).join('');
}

// ─── VESSEL DETAIL ─────────────────────────────────────────────────────────────
let _currentIMO = null;
let _certCache  = {};
let _docCache   = {};

async function openVessel(imo) {
  _currentIMO = imo;
  const vessel = _vessels.find(v => v.imo === imo) || { vesselName: imo, imo };
  document.getElementById('vdName').textContent = vessel.vesselName;
  // Show IMO + group names in detail header
  const groups = _imoToGroups[imo] || [];
  const groupBadgesHtml = groups.length
    ? ' &nbsp;' + groups.map(g => `<span class="group-badge"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>${escHtml(g)}</span>`).join(' ')
    : '';
  document.getElementById('vdImo').innerHTML = 'IMO ' + escHtml(imo) + groupBadgesHtml;
  // Reset analytics while loading
  ['vaTotal','vaValid','vaExpiring','vaVapt','vaVaptValid','vaDocs'].forEach(id => {
    const el = document.getElementById(id); if (el) el.textContent = '—';
  });
  // Reset quarter filter to All on each vessel open
  _activeQuarter = null;
  ['qAll','qQ1','qQ2','qQ3','qQ4'].forEach((id, i) => {
    const el = document.getElementById(id); if (!el) return;
    el.className = 'q-btn' + (i === 0 ? ' all active' : '');
  });
  // Sidebar highlight
  document.querySelectorAll('.sb-vessel-item').forEach(el => el.classList.toggle('active', el.id === 'sb-' + imo));
  document.getElementById('btnBackToDash').style.display = 'flex';
  showView('vessel');
  switchTab('cst');
  // Load certs if not cached
  if (!_certCache[imo]) {
    document.getElementById('cstContent').innerHTML  = '<div class="loading-center"><div class="spinner"></div> Loading…</div>';
    document.getElementById('vaptContent').innerHTML = '<div class="loading-center"><div class="spinner"></div> Loading…</div>';
    try {
      const r = await fetch(`/api/supt/vessel/${encodeURIComponent(imo)}/certs`);
      if (r.status === 401) { clearSession(); location.reload(); return; }
      if (!r.ok) throw new Error('Failed to load cert data');
      _certCache[imo] = await r.json();
    } catch (e) {
      const errHtml = `<div class="loading-center" style="color:var(--invalid)">Failed to load. ${e.message}</div>`;
      document.getElementById('cstContent').innerHTML  = errHtml;
      document.getElementById('vaptContent').innerHTML = errHtml;
      return;
    }
  }
  const cstList  = _certCache[imo].cst  || [];
  const vaptList = _certCache[imo].vapt || [];
  renderCstTable(cstList);
  renderVaptTable(vaptList);
  // Populate vessel analytics bar
  const now  = Date.now();
  const soon = now + 90 * 24 * 60 * 60 * 1000;
  const _st = c => (c.status || '').toUpperCase();
  const _ts = c => c.validUntil ? new Date(c.validUntil).getTime() : Infinity;
  document.getElementById('vaTotal').textContent     = cstList.length;
  document.getElementById('vaValid').textContent     = cstList.filter(c => _st(c) === 'VALID' && _ts(c) > now).length;
  document.getElementById('vaExpiring').textContent  = cstList.filter(c => _st(c) === 'VALID' && _ts(c) > now && _ts(c) <= soon).length;
  document.getElementById('vaVapt').textContent      = vaptList.length;
  document.getElementById('vaVaptValid').textContent = vaptList.filter(c => _st(c) === 'VALID' && _ts(c) > now).length;
  // Load docs if not cached
  if (!_docCache[imo]) loadDocs(imo);
  else { renderDocList(_docCache[imo]); document.getElementById('vaDocs').textContent = _docCache[imo].length; }
}

function qBadge(q) {
  const v = (q || '').toUpperCase();
  const color = { Q1:'#7689AE', Q2:'#64FFDA', Q3:'#FFAA2E', Q4:'#FF5C7A' }[v] || 'var(--text-sec)';
  const bg    = { Q1:'rgba(118,137,174,0.12)', Q2:'rgba(100,255,218,0.10)', Q3:'rgba(255,170,46,0.12)', Q4:'rgba(255,107,138,0.12)' }[v] || 'transparent';
  return v ? `<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:.6rem;font-weight:700;letter-spacing:.1em;background:${bg};border:1px solid ${color};color:${color}">${v}</span>`
           : `<span style="color:var(--text-sec);font-size:.7rem">—</span>`;
}
function modeBadge(m) {
  const v = (m || '').toUpperCase();
  const c = { ONLINE:'var(--sp-accent)', OFFLINE:'var(--sp-gold)', HYBRID:'#B47EFF' }[v] || 'var(--text-sec)';
  return v ? `<span style="font-size:.6rem;font-weight:700;color:${c}">${v}</span>` : `<span style="color:var(--text-sec);font-size:.7rem">—</span>`;
}

function renderCstTable(certs) {
  const filtered = filterByQuarter(certs, 'issuedDate');
  const el = document.getElementById('cstContent');
  if (!filtered.length) {
    const sub = _activeQuarter
      ? `No CST certificates found in Q${_activeQuarter} — try a different quarter or All`
      : 'No Cyber Security Training certificates found for this vessel';
    el.innerHTML = `<div class="empty-state">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
      <div class="empty-title">No CST Certificates</div>
      <div class="empty-sub">${sub}</div>
    </div>`;
    return;
  }
  el.innerHTML = `<div class="table-wrap" style="overflow-x:auto">
    <table class="data-table" style="min-width:900px">
      <thead><tr>
        <th>Certificate ID</th>
        <th>Vessel / Recipient</th>
        <th>IMO</th>
        <th>Chief Engineer</th>
        <th>Quarter</th>
        <th>Mode</th>
        <th>Status</th>
        <th>Valid Until</th>
        <th>Open</th>
      </tr></thead>
      <tbody>${filtered.map(c => {
        const now = new Date(), vu = c.validUntil ? new Date(c.validUntil) : null;
        const isExpired = c.status === 'VALID' && vu && vu < now;
        const effStatus = isExpired ? 'EXPIRED' : (c.status || 'PENDING');
        const daysLeft  = vu ? Math.ceil((vu - now) / 86400000) : null;
        const validStr  = vu ? `${fmtDate(c.validUntil)}${daysLeft !== null && daysLeft > 0 ? ` <span style="font-size:.6rem;color:var(--text-sec);opacity:.8">· ${daysLeft}d</span>` : ''}` : '—';
        return `<tr>
        <td class="mono" style="font-size:.72rem">${escHtml(c.certId || c.id || '—')}</td>
        <td><div style="font-weight:600;color:var(--text-bright);font-size:.8rem">${escHtml(c.recipientName || c.vesselName || '—')}</div>${c.vesselName && c.recipientName ? `<div style="font-size:.65rem;color:var(--text-sec)">${escHtml(c.vesselName)}</div>` : ''}</td>
        <td class="mono" style="font-size:.7rem;color:var(--text-sec)">${escHtml(c.vesselIMO || '—')}</td>
        <td style="font-size:.76rem;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(c.chiefEngineer || '')}">${escHtml(c.chiefEngineer || '—')}</td>
        <td>${qBadge(c.complianceQuarter)}</td>
        <td>${modeBadge(c.trainingMode)}</td>
        <td>${statusPill(effStatus)}</td>
        <td style="white-space:nowrap;font-size:.73rem">${validStr}</td>
        <td><button class="btn-view" data-action="viewCertPublic" data-id="${escHtml(c.id)}" data-type="cst">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          View
        </button></td>
      </tr>`;
      }).join('')}</tbody>
    </table>
  </div>`;
}

function renderVaptTable(certs) {
  const el = document.getElementById('vaptContent');
  if (!certs.length) {
    el.innerHTML = `<div class="empty-state">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <div class="empty-title">No VAPT Assessments</div>
      <div class="empty-sub">No VAPT assessment records found for this vessel</div>
    </div>`;
    return;
  }
  el.innerHTML = `<div class="table-wrap" style="overflow-x:auto">
    <table class="data-table" style="min-width:800px">
      <thead><tr>
        <th>Certificate ID</th>
        <th>Vessel / Recipient</th>
        <th>IMO</th>
        <th>Assessed</th>
        <th>Risk Level</th>
        <th>Status</th>
        <th>Valid Until</th>
        <th>Open</th>
      </tr></thead>
      <tbody>${certs.map(c => {
        const now = new Date(), vu = c.validUntil ? new Date(c.validUntil) : null;
        const isExpired = c.status === 'VALID' && vu && vu < now;
        const effStatus = isExpired ? 'EXPIRED' : (c.status || 'PENDING');
        const daysLeft  = vu ? Math.ceil((vu - now) / 86400000) : null;
        const validStr  = vu ? `${fmtDate(c.validUntil)}${daysLeft !== null && daysLeft > 0 ? ` <span style="font-size:.6rem;color:var(--text-sec);opacity:.8">· ${daysLeft}d</span>` : ''}` : '—';
        return `<tr>
        <td class="mono" style="font-size:.72rem">${escHtml(c.certId || c.id || '—')}</td>
        <td><div style="font-weight:600;color:var(--text-bright);font-size:.8rem">${escHtml(c.recipientName || c.vesselName || '—')}</div>${c.vesselName && c.recipientName ? `<div style="font-size:.65rem;color:var(--text-sec)">${escHtml(c.vesselName)}</div>` : ''}</td>
        <td class="mono" style="font-size:.7rem;color:var(--text-sec)">${escHtml(c.vesselIMO || '—')}</td>
        <td style="font-size:.73rem;color:var(--text-sec)">${fmtDate(c.assessmentDate || c.issuedDate)}</td>
        <td>${riskPill(c.riskLevel)}</td>
        <td>${statusPill(effStatus)}</td>
        <td style="white-space:nowrap;font-size:.73rem">${validStr}</td>
        <td><button class="btn-view vapt" data-action="viewCertPublic" data-id="${escHtml(c.id)}" data-type="vapt">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          View
        </button></td>
      </tr>`;
      }).join('')}</tbody>
    </table>
  </div>`;
}

async function loadDocs(imo) {
  document.getElementById('docsContent').innerHTML = '<div class="loading-center"><div class="spinner"></div> Loading documents…</div>';
  try {
    const r = await fetch(`/api/docs/by-vessel/${encodeURIComponent(imo)}`);
    if (r.status === 401) { clearSession(); location.reload(); return; }
    if (!r.ok) throw new Error('Failed to load documents');
    _docCache[imo] = await r.json();
    if (_currentIMO === imo) {
      renderDocList(_docCache[imo]);
      document.getElementById('vaDocs').textContent = _docCache[imo].length;
    }
  } catch (e) {
    if (_currentIMO === imo)
      document.getElementById('docsContent').innerHTML = `<div class="loading-center" style="color:var(--invalid)">Failed to load documents. ${e.message}</div>`;
  }
}

function renderDocList(docs) {
  const el = document.getElementById('docsContent');
  if (!docs || !docs.length) {
    el.innerHTML = `<div class="empty-state">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      <div class="empty-title">No Documents</div>
      <div class="empty-sub">No documents have been uploaded for this vessel</div>
    </div>`;
    return;
  }
  el.innerHTML = `<div class="doc-list">${docs.map(d => {
    const isPdf  = (d.mimeType || '').includes('pdf');
    const isImg  = (d.mimeType || '').startsWith('image/');
    const isView = isPdf || isImg;
    // Auth is via the httpOnly suptSession cookie, sent automatically on this
    // same-origin navigation — no token needs to be (or can be) put in the URL.
    const url    = `/api/docs/download/${encodeURIComponent(d.id)}`;
    const icon   = isPdf
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FF5C7A" stroke-width="1.8"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`
      : isImg
        ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#64FFDA" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`
        : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#6495ED" stroke-width="1.8"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
    return `<div class="doc-item">
      <div class="doc-icon">${icon}</div>
      <div class="doc-info">
        <div class="doc-title">${escHtml(d.title || d.originalName || d.id)}</div>
        <div class="doc-meta">${escHtml(d.docType || 'Document')} · ${fmtDate(d.uploadedAt)}${d.fileName ? ' · ' + escHtml(d.fileName) : ''}</div>
      </div>
      <a class="doc-dl" href="${url}" target="_blank" rel="noopener">
        ${isView
          ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> View`
          : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg> Download`}
      </a>
    </div>`;
  }).join('')}
  </div>`;
}

// ─── QUARTER FILTER ────────────────────────────────────────────────────────────
let _activeQuarter = null;

function setQuarter(q) {
  _activeQuarter = q;
  ['qAll','qQ1','qQ2','qQ3','qQ4'].forEach((id, i) => {
    const el = document.getElementById(id);
    if (!el) return;
    const qVal = i === 0 ? null : i;
    el.className = 'q-btn' + (i === 0 ? ' all' : '') + (qVal === q ? ' active' : '');
  });
  if (_currentIMO && _certCache[_currentIMO]) {
    renderCstTable(_certCache[_currentIMO].cst || []);
    renderVaptTable(_certCache[_currentIMO].vapt || []);
  }
}
window.setQuarter = setQuarter;

function filterByQuarter(certs, dateField) {
  if (!_activeQuarter) return certs;
  return certs.filter(c => {
    if (c.complianceQuarter) return c.complianceQuarter === 'Q' + _activeQuarter;
    const d = c[dateField] || c.complianceDate || c.issuedDate;
    if (!d) return false;
    const month = new Date(d).getMonth() + 1;
    return (month <= 3 ? 1 : month <= 6 ? 2 : month <= 9 ? 3 : 4) === _activeQuarter;
  });
}

// ─── TABS ──────────────────────────────────────────────────────────────────────
function switchTab(tab) {
  const tabs  = { cst: 'tabCst',  vapt: 'tabVapt',  docs: 'tabDocs'  };
  const panes = { cst: 'paneCst', vapt: 'paneVapt', docs: 'paneDocs' };
  const classes = { cst: 'active-cst', vapt: 'active-vapt', docs: 'active-docs' };
  Object.entries(tabs).forEach(([key, id]) => {
    const btn  = document.getElementById(id);
    const pane = document.getElementById(panes[key]);
    btn.className  = 'tab-btn' + (key === tab ? ' ' + classes[key] : '');
    pane.className = 'tab-pane' + (key === tab ? ' active' : '');
  });
  const qbar = document.getElementById('quarterFilterBar');
  if (qbar) qbar.style.display = (tab === 'docs' || tab === 'vapt') ? 'none' : 'flex';
}

// ─── VIEWS ─────────────────────────────────────────────────────────────────────
function showView(view) {
  document.getElementById('viewDashboard').className = view === 'dashboard' ? 'active' : '';
  document.getElementById('viewVessel').className    = view === 'vessel'    ? 'active' : '';
}

function showDashboard() {
  _currentIMO = null;
  document.querySelectorAll('.sb-vessel-item').forEach(el => el.classList.remove('active'));
  document.getElementById('btnBackToDash').style.display = 'none';
  showView('dashboard');
}

// ─── VIEW CERT IN PUBLIC PORTAL ────────────────────────────────────────────────
function viewCertPublic(certId, type) {
  const cfg     = window.APP_CONFIG && window.APP_CONFIG.routes;
  const cstBase = (cfg && cfg.cst) || '/CST';
  const vptBase = (cfg && cfg.vpt) || '/VAPT';
  const base    = (type === 'vapt') ? vptBase : cstBase;
  window.open(base + '?id=' + encodeURIComponent(certId), '_blank', 'noopener,noreferrer');
}
window.viewCertPublic = viewCertPublic;

// ─── XSS GUARD ─────────────────────────────────────────────────────────────────
function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

// ─── DELEGATED CLICK HANDLER ───────────────────────────────────────────────────
// Replaces the onclick="" attributes previously inline in this page and in the
// HTML template strings above. A single listener covers both static markup and
// dynamically-rendered rows — the fix that a hash-based CSP (which only covers
// static script content) could not provide (see admin/dashboard.html history).
const ACTION_HANDLERS = {
  showDashboard:   () => showDashboard(),
  toggleTheme:     () => window.toggleTheme && window.toggleTheme(),
  doLogout:        () => doLogout(),
  switchTab:       (el) => switchTab(el.dataset.tab),
  setQuarter:      (el) => setQuarter(el.dataset.quarter ? Number(el.dataset.quarter) : null),
  openVessel:      (el) => openVessel(el.dataset.imo),
  viewCertPublic:  (el) => viewCertPublic(el.dataset.id, el.dataset.type),
};

document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const handler = ACTION_HANDLERS[el.dataset.action];
  if (handler) handler(el, e);
});
