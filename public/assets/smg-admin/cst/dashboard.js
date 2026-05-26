
    // ════════════════════════════════════════════════════
    // MODULE: Security — HTML escape (XSS prevention)
    // ════════════════════════════════════════════════════
    function escHtml(s) {
      if (s == null) return '';
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
    }

    // ════════════════════════════════════════════════════
    // MODULE: State
    // ════════════════════════════════════════════════════
    const API = '/api';  // Relative — works on any hostname/port (single server)
    let TOKEN = sessionStorage.getItem('adminToken') || '';

    // ── Image URL helper ──────────────────────────────────────
    // The admin server (port 3001) ALREADY serves /uploads/ directly,
    // so we just use relative paths — no port or subdomain logic needed.
    function imgUrl(src) {
      if (!src) return '';
      if (src.startsWith('data:') || src.startsWith('http://') || src.startsWith('https://')) return src;
      // /uploads/cert_xxx.jpg  → served by whichever server this page is on
      return src;
    }
    let CERTS = [];
    let STATUS_CHART = null, EXPIRY_CHART = null, EMAIL_CHART = null;
    let editingId = null, imgFile = null, deleteId = null;
    let issuanceMode = false;
    let selectedIssueCertId = null;
    let dupCheckTimer = null;
    // Attachment state — var (not let) so onclick handlers in dynamic HTML can access them
    var pendingPdfs = [];
    var savedAttachments = [];

    // ════════════════════════════════════════════════════
    // MODULE: Auth
    // ════════════════════════════════════════════════════
    async function doLogin() {
      const u = document.getElementById('lUser').value.trim();
      const p = document.getElementById('lPass').value;
      document.getElementById('lBtnTxt').textContent = 'Authenticating…';
      try {
        const r = await fetch(API + '/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) });
        const d = await r.json();
        if (!r.ok) {
          const errEl = document.getElementById('loginErr');
          errEl.textContent = r.status === 429
            ? 'Too many attempts. Please wait a few minutes and try again.'
            : 'Invalid credentials. Please try again.';
          errEl.style.display = 'block';
          return;
        }
        TOKEN = d.token;
        sessionStorage.setItem('adminToken', TOKEN);
        document.getElementById('loginWrap').style.display = 'none';
        document.getElementById('appWrap').style.display = 'flex';
        if (window.syncButtons) window.syncButtons();
        if (window.PSP) PSP.setPrincipal({ username: u, certType: 'CST' });
        scheduleTokenExpiryWarning();
        // Start session expiry + idle timeout monitoring
        if (window._startSessionTimers) window._startSessionTimers(Date.now());
        initApp();
      } catch {
        document.getElementById('loginErr').textContent = 'Login failed. Check your connection and try again.';
        document.getElementById('loginErr').style.display = 'block';
      }
      document.getElementById('lBtnTxt').textContent = 'Login to Admin Panel';
    }
    function doLogout() {
      if (window.PSP) { PSP.publish(PSP.TOPICS.AUTH_LOGOUT, { certType: 'CST' }); PSP.setPrincipal(null); }
      sessionStorage.removeItem('adminToken'); TOKEN = '';
      if (_autoRefreshInterval) { clearInterval(_autoRefreshInterval); _autoRefreshInterval = null; }
      document.getElementById('loginWrap').style.display = 'flex';
      document.getElementById('appWrap').style.display = 'none';
      if (window.syncButtons) window.syncButtons();
    }

    // ════════════════════════════════════════════════════
    // MODULE: Init
    // ════════════════════════════════════════════════════
    let _autoRefreshInterval = null;

    // Helper: returns true if any blocking modal/overlay is currently visible
    function _isModalOpen() {
      const modals = ['addMod', 'viewMod', 'delMod'];
      return modals.some(id => {
        const el = document.getElementById(id);
        return el && el.style.display !== 'none' && el.style.display !== '';
      });
    }

    async function initApp() {
      await refreshStats();
      await loadGroupsMap();
      renderTbl('dashTbl', '');
      updateRealTimeBadge();
      checkSesStatus();  // Check email service status
      checkHealth();     // Check server health endpoint
      // ── Real-time auto-refresh: poll every 30 seconds ──
      if (_autoRefreshInterval) clearInterval(_autoRefreshInterval);
      _autoRefreshInterval = setInterval(async () => {
        // Skip background refresh when a modal is open — prevents clobbering live edits
        if (_isModalOpen()) return;
        await refreshStats();
        const dashPage  = document.getElementById('page-dashboard');
        const certsPage = document.getElementById('page-certs');
        const issuePage = document.getElementById('page-issue');
        if (dashPage  && dashPage.style.display  !== 'none') renderTbl('dashTbl', '');
        if (certsPage && certsPage.style.display !== 'none') renderTbl('allTbl', document.getElementById('allQ')?.value || '');
        if (issuePage && issuePage.style.display !== 'none') {
          renderIssueList(document.getElementById('issueSearch')?.value || '');
          renderSentLog();
        }
        updateRealTimeBadge();
      }, 30000);
    }

    function updateRealTimeBadge() {
      const el = document.getElementById('realtimeBadge');
      if (el) {
        const now = new Date();
        el.textContent = 'Live · ' + now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      }
    }
    async function refreshStats() {
      try {
        const ctrl = new AbortController();
        const _t = setTimeout(() => ctrl.abort(), 15_000);
        const r = await fetch(API + '/certs', { headers: { Authorization: 'Bearer ' + TOKEN }, signal: ctrl.signal });
        clearTimeout(_t);
        if (r.status === 401) { toast('Session expired. Please log in again.', 'err'); doLogout(); return; }
        CERTS = await r.json();
        checkNearExpiryBanner(CERTS); // Proactive near-expiry banner on dashboard
        const a = computeAnalytics(CERTS);
        document.getElementById('stTotal').textContent = a.total;
        document.getElementById('stValid').textContent = a.valid;
        document.getElementById('stRevoked').textContent = a.revoked;
        document.getElementById('stExpired').textContent = a.expired;
        document.getElementById('stEmailSent').textContent = a.emailSent;
        document.getElementById('stPending').textContent = a.pending || 0;
        document.getElementById('stMailNotSent').textContent = a.emailPending;
        document.getElementById('stNearExpiry').textContent = a.buckets.expSoon30;
        // Sub-labels with live percentages
        const _vp = a.total > 0 ? Math.round(a.valid / a.total * 100) : 0;
        const _ep = a.total > 0 ? Math.round(a.emailSent / a.total * 100) : 0;
        const _sub = document.getElementById('stTotalSub'); if (_sub) _sub.textContent = a.total > 0 ? `${a.valid} valid · ${a.expired} expired` : '—';
        const _vps = document.getElementById('stValidPct'); if (_vps) _vps.textContent = `${_vp}% of total`;
        const _eps = document.getElementById('stEmailPct'); if (_eps) _eps.textContent = `${_ep}% dispatch rate`;
        const _ess = document.getElementById('stEmailSentSub'); if (_ess) _ess.textContent = `${a.emailSent} sent successfully`;
        document.getElementById('nbTotal').textContent = a.total;
        document.getElementById('svValid').textContent = a.valid;
        document.getElementById('svRevoked').textContent = a.revoked;
        document.getElementById('svExpired').textContent = a.expired;
        document.getElementById('svEmailSent').textContent = a.emailSent;
        document.getElementById('svEmailPending').textContent = a.emailPending;
        document.getElementById('dispatchSent').textContent = a.emailSent;
        document.getElementById('dispatchPending').textContent = a.emailPending;
        updateCharts(a);
        updateInsights(a);
        renderAlertPanels(a);
        renderSentLog();
        // Update Internal Validity alert badge
        const ivBadge = document.getElementById('nbValidityAlert');
        if (ivBadge && typeof computeIVStats === 'function') {
          const ivS = computeIVStats(CERTS);
          const alertCount = ivS.expiring + ivS.expired;
          ivBadge.textContent = alertCount;
          ivBadge.style.background = alertCount > 0 ? 'rgba(255,107,138,.18)' : 'rgba(255,179,71,.12)';
          ivBadge.style.color = alertCount > 0 ? 'var(--invalid)' : 'var(--warn)';
          ivBadge.style.borderColor = alertCount > 0 ? 'rgba(255,107,138,.3)' : 'rgba(255,179,71,.25)';
        }
        if (window.PSP) PSP.publish(PSP.TOPICS.CERTS_REFRESHED, { count: CERTS.length, certType: 'CST' });
      } catch { }
    }

    // ════════════════════════════════════════════════════
    // MODULE: Analytics
    // ════════════════════════════════════════════════════
    function daysUntil(d) {
      if (!d) return null;
      const t = new Date(d), now = new Date();
      return Math.round((t.setHours(0, 0, 0, 0) - now.setHours(0, 0, 0, 0)) / 86400000);
    }
    function fmt(d) {
      if (!d) return '—';
      return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
    }
    function fmtDt(d) {
      if (!d) return '—';
      const dt = new Date(d);
      return dt.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
        + ' · ' + dt.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    }
    function computeAnalytics(certs) {
      const now = new Date();
      let valid = 0, revoked = 0, expired = 0, pending = 0, expSoon30 = 0, expSoon90 = 0, expiredPast = 0, noExpiry = 0, emailSent = 0, emailPending = 0, earliestIssued = null;
      const qC = { Q1: 0, Q2: 0, Q3: 0, Q4: 0 }, mC = { ONLINE: 0, OFFLINE: 0, HYBRID: 0 };
      const nearExpiry = [];
      certs.forEach(c => {
        const st = (c.status || 'VALID').toUpperCase();
        const vu = c.validUntil ? new Date(c.validUntil) : null;
        const isV = st === 'VALID' && (!vu || vu >= now);
        if (st === 'REVOKED') revoked++;
        else if (st === 'PENDING') pending++;
        else if (!isV) expired++;
        else valid++;
        const dl = daysUntil(c.validUntil);
        const isTerminated = st === 'EXPIRED' || st === 'REVOKED';
        if (isTerminated || (dl !== null && dl < 0)) expiredPast++;
        else if (dl === null) noExpiry++;
        else if (dl <= 30) { expSoon30++; nearExpiry.push({ ...c, daysLeft: dl }); }
        else if (dl <= 90) { expSoon90++; if (dl <= 45) nearExpiry.push({ ...c, daysLeft: dl }); }
        if (c.issuedAt) { const ii = new Date(c.issuedAt); if (!earliestIssued || ii < earliestIssued) earliestIssued = ii; }
        if (qC[(c.complianceQuarter || '').toUpperCase()] !== undefined) qC[c.complianceQuarter.toUpperCase()]++;
        if (mC[(c.trainingMode || '').toUpperCase()] !== undefined) mC[c.trainingMode.toUpperCase()]++;
        if (c.emailStatus === 'SENT') emailSent++;
        else emailPending++;
      });
      nearExpiry.sort((a, b) => a.daysLeft - b.daysLeft);
      // Non-overlapping buckets for expiry radar
      let exp7=0, exp8to30=0, exp31to90=0, healthyBucket=0;
      certs.forEach(c => {
        const st2 = (c.status || 'VALID').toUpperCase();
        // EXPIRED and REVOKED by status are already counted in expiredPast — exclude from future buckets
        if (st2 === 'EXPIRED' || st2 === 'REVOKED') return;
        const dl2 = daysUntil(c.validUntil);
        if (dl2 === null || dl2 < 0) return;
        if (dl2 <= 7) exp7++;
        else if (dl2 <= 30) exp8to30++;
        else if (dl2 <= 90) exp31to90++;
        else healthyBucket++;
      });
      return {
        total: certs.length, valid, revoked, expired, pending, emailSent, emailPending,
        buckets: { expiredPast, expSoon30, expSoon90, noExpiry, exp7, exp8to30, exp31to90, healthy: healthyBucket }, earliestIssued,
        nearExpiry,
        mostCommonQuarter: Object.entries(qC).sort((a, b) => b[1] - a[1])[0],
        topMode: Object.entries(mC).sort((a, b) => b[1] - a[1])[0]
      };
    }

    // ════════════════════════════════════════════════════
    // MODULE: Charts  —  update-in-place (no flicker)
    // ════════════════════════════════════════════════════
    const _CHART_LEGEND = { display: true, position: 'right', labels: { color: '#8892B0', boxWidth: 10, font: { size: 10 }, padding: 10 } };

    function _buildStatusChart(a) {
      return new Chart(document.getElementById('statusChart').getContext('2d'), {
        type: 'doughnut',
        data: {
          labels: ['Valid', 'Expired', 'Revoked', 'Pending'],
          datasets: [{ data: [a.valid, a.expired, a.revoked, a.pending || 0],
            backgroundColor: ['rgba(100,255,218,.55)', 'rgba(255,179,71,.5)', 'rgba(255,107,138,.5)', 'rgba(126,184,247,.45)'],
            borderColor: ['#64FFDA', '#FFB347', '#FF6B8A', '#7EB8F7'], borderWidth: 1.5, hoverOffset: 6 }]
        },
        options: { responsive: true, maintainAspectRatio: false, cutout: '62%',
          plugins: { legend: _CHART_LEGEND, tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw} (${a.total > 0 ? Math.round(ctx.raw / a.total * 100) : 0}%)` } } } }
      });
    }

    function _buildEmailChart(a) {
      return new Chart(document.getElementById('emailChart').getContext('2d'), {
        type: 'doughnut',
        data: {
          labels: ['Sent ✓', 'Not Sent', 'Pending Certs'],
          datasets: [{ data: [a.emailSent, a.emailPending, a.pending || 0],
            backgroundColor: ['rgba(100,255,218,.55)', 'rgba(255,107,138,.5)', 'rgba(126,184,247,.4)'],
            borderColor: ['#64FFDA', '#FF6B8A', '#7EB8F7'], borderWidth: 1.5, hoverOffset: 6 }]
        },
        options: { responsive: true, maintainAspectRatio: false, cutout: '62%',
          plugins: { legend: _CHART_LEGEND, tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw}` } } } }
      });
    }

    function _buildExpiryChart(a) {
      const bk = a.buckets || {};
      return new Chart(document.getElementById('expiryChart').getContext('2d'), {
        type: 'bar',
        data: {
          labels: ['Expired', '≤7d', '8–30d', '31–90d', '>90d', 'No Expiry'],
          datasets: [{
            label: 'Certificates',
            data: [bk.expiredPast || 0, bk.exp7 || 0, bk.exp8to30 || 0, bk.exp31to90 || 0, bk.healthy || 0, bk.noExpiry || 0],
            backgroundColor: ['rgba(255,107,138,.65)', 'rgba(255,107,138,.45)', 'rgba(212,168,67,.55)', 'rgba(255,179,71,.45)', 'rgba(100,255,218,.48)', 'rgba(136,146,176,.38)'],
            borderColor: ['#FF6B8A', '#FF6B8A', '#D4A843', '#FFB347', '#64FFDA', '#8892B0'],
            borderWidth: 1.5, borderRadius: 5
          }]
        },
        options: { responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false }, tooltip: { callbacks: { label: ctx => ` ${ctx.raw} cert${ctx.raw !== 1 ? 's' : ''}` } } },
          scales: {
            x: { ticks: { color: '#8892B0', font: { size: 11 }, maxRotation: 0 }, grid: { display: false } },
            y: { ticks: { color: '#8892B0', font: { size: 10 }, callback: v => Number.isInteger(v) ? v : '' }, grid: { color: 'rgba(136,146,176,.12)' }, beginAtZero: true }
          }
        }
      });
    }

    function updateCharts(a) {
      if (!window.Chart) return;
      // ── Status Doughnut: update data in-place, rebuild only on first load ──
      if (STATUS_CHART) {
        STATUS_CHART.data.datasets[0].data = [a.valid, a.expired, a.revoked, a.pending || 0];
        STATUS_CHART.options.plugins.tooltip.callbacks.label = ctx => ` ${ctx.label}: ${ctx.raw} (${a.total > 0 ? Math.round(ctx.raw / a.total * 100) : 0}%)`;
        STATUS_CHART.update('none');
      } else {
        STATUS_CHART = _buildStatusChart(a);
      }
      // ── Email Doughnut ──
      if (EMAIL_CHART) {
        EMAIL_CHART.data.datasets[0].data = [a.emailSent, a.emailPending, a.pending || 0];
        EMAIL_CHART.update('none');
      } else {
        EMAIL_CHART = _buildEmailChart(a);
      }
      // ── Expiry Radar Bar ──
      if (EXPIRY_CHART) {
        const bk = a.buckets || {};
        EXPIRY_CHART.data.datasets[0].data = [bk.expiredPast || 0, bk.exp7 || 0, bk.exp8to30 || 0, bk.exp31to90 || 0, bk.healthy || 0, bk.noExpiry || 0];
        EXPIRY_CHART.update('none');
      } else {
        EXPIRY_CHART = _buildExpiryChart(a);
      }
    }

    function updateInsights(a) {
      const chips = document.getElementById('insightChips');
      const list = document.getElementById('insightList');
      if (!chips || !list) return;
      const t = a.total || 1;
      const vp = Math.round(a.valid / t * 100);
      const ep = Math.round(a.emailSent / t * 100);
      // Update expiry radar subtitle
      const erSub = document.getElementById('expiryRadarSub');
      if (erSub) {
        const urgentCount = (a.buckets.exp7 || 0) + (a.buckets.expiredPast || 0);
        erSub.textContent = urgentCount > 0
          ? `⚠ ${urgentCount} cert${urgentCount !== 1 ? 's' : ''} need attention · ${a.total} total`
          : `All ${a.total} certificates tracked · ${a.buckets.healthy || 0} healthy`;
      }
      // Status chips — colour-coded by severity
      chips.innerHTML = [
        `<span class="analytics-chip" style="background:rgba(100,255,218,.1);color:var(--teal);border:1px solid rgba(100,255,218,.2)"><strong>${vp}%</strong> valid</span>`,
        `<span class="analytics-chip" style="background:rgba(100,255,218,.07);color:var(--teal);border:1px solid rgba(100,255,218,.15)"><strong>${ep}%</strong> emailed</span>`,
        a.pending > 0 ? `<span class="analytics-chip" style="background:rgba(126,184,247,.1);color:#7EB8F7;border:1px solid rgba(126,184,247,.25)">⏳ <strong>${a.pending}</strong> pending</span>` : '',
        a.emailPending > 0 ? `<span class="analytics-chip" style="background:rgba(255,107,138,.08);color:var(--invalid);border:1px solid rgba(255,107,138,.2)">✉ <strong>${a.emailPending}</strong> unsent</span>` : '',
        a.buckets.expSoon30 > 0 ? `<span class="analytics-chip" style="background:rgba(255,179,71,.08);color:var(--warn);border:1px solid rgba(255,179,71,.2)">⚠ <strong>${a.buckets.expSoon30}</strong> exp ≤30d</span>` : '',
      ].filter(Boolean).join('');
      // Action items — priority ordered
      const items = [];
      if (a.pending > 0) items.push(`<li style="color:#7EB8F7;border-left:2px solid #7EB8F7;padding-left:8px;margin-bottom:6px"><strong>${a.pending}</strong> cert(s) awaiting activation — open ⏳ panel below to activate.</li>`);
      if (a.emailPending > 0) items.push(`<li style="color:var(--invalid);border-left:2px solid var(--invalid);padding-left:8px;margin-bottom:6px"><strong>${a.emailPending}</strong> recipient(s) have not received their credential yet.</li>`);
      if ((a.nearExpiry||[]).filter(x=>x.daysLeft<=7).length > 0) items.push(`<li style="color:var(--invalid);border-left:2px solid var(--invalid);padding-left:8px;margin-bottom:6px"><strong>${(a.nearExpiry||[]).filter(x=>x.daysLeft<=7).length}</strong> cert(s) expire within <strong>7 days</strong> — urgent renewal required.</li>`);
      if (a.buckets.expSoon30 > 0) items.push(`<li style="color:var(--warn);border-left:2px solid var(--warn);padding-left:8px;margin-bottom:6px"><strong>${a.buckets.expSoon30}</strong> cert(s) expire within <strong>30 days</strong>.</li>`);
      if (a.buckets.expiredPast > 0) items.push(`<li style="border-left:2px solid var(--border);padding-left:8px;margin-bottom:6px"><strong>${a.buckets.expiredPast}</strong> cert(s) already expired — consider archiving or renewing.</li>`);
      if (items.length === 0) items.push(`<li style="color:var(--teal);border-left:2px solid var(--teal);padding-left:8px">✓ Registry healthy — no action items.</li>`);
      list.innerHTML = items.join('');
      // ── Training & Quarter Breakdown panel ──
      const bp = document.getElementById('breakdownPanel');
      if (bp) {
        const qC = { Q1: 0, Q2: 0, Q3: 0, Q4: 0 };
        const mC = { ONLINE: 0, OFFLINE: 0, HYBRID: 0 };
        CERTS.forEach(c => {
          if (c.complianceQuarter && qC[c.complianceQuarter.toUpperCase()] !== undefined) qC[c.complianceQuarter.toUpperCase()]++;
          if (c.trainingMode && mC[c.trainingMode.toUpperCase()] !== undefined) mC[c.trainingMode.toUpperCase()]++;
        });
        const qTotal = Object.values(qC).reduce((s,v) => s+v, 0) || 1;
        const mTotal = Object.values(mC).reduce((s,v) => s+v, 0) || 1;
        bp.innerHTML = `
          <div style="font-size:.56rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:10px">Compliance Quarter</div>
          ${Object.entries(qC).map(([q,n]) => `
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
              <div style="font-size:.7rem;font-weight:600;color:var(--gold);min-width:24px">${q}</div>
              <div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden">
                <div style="height:100%;width:${Math.round(n/qTotal*100)}%;background:linear-gradient(90deg,var(--gold),rgba(212,168,67,.4));border-radius:3px;transition:width .4s ease"></div>
              </div>
              <div style="font-size:.68rem;color:var(--text-sec);min-width:26px;text-align:right">${n}</div>
            </div>`).join('')}
          <div style="font-size:.56rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin:12px 0 10px">Training Mode</div>
          ${Object.entries(mC).map(([m,n]) => {
            const col = m==='ONLINE' ? 'var(--teal)' : m==='OFFLINE' ? 'var(--warn)' : '#7EB8F7';
            return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
              <div style="font-size:.65rem;font-weight:600;color:${col};min-width:50px">${m}</div>
              <div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden">
                <div style="height:100%;width:${Math.round(n/mTotal*100)}%;background:${col};opacity:.6;border-radius:3px;transition:width .4s ease"></div>
              </div>
              <div style="font-size:.68rem;color:var(--text-sec);min-width:26px;text-align:right">${n}</div>
            </div>`;
          }).join('')}`;
      }
    }

    function renderAlertPanels(a) {
      // ── Near Expiry ──
      const neEl = document.getElementById('nearExpiryList');
      const neCountEl = document.getElementById('neCountBadge');
      if (neEl && neCountEl) {
        neCountEl.textContent = a.nearExpiry.length;
        if (a.nearExpiry.length === 0) {
          neEl.innerHTML = '<div style="padding:28px;text-align:center;color:var(--text-sec);font-size:.78rem">✓ All certificates healthy — no urgent expiries</div>';
        } else {
          neEl.innerHTML = a.nearExpiry.map(c => {
            const dl = c.daysLeft;
            const badgeCls = dl <= 7 ? 'crit' : dl <= 20 ? 'warn' : 'ok';
            const badgeLabel = dl === 0 ? 'TODAY' : dl + 'd';
            const sId = escHtml(c.id), sName = escHtml(c.recipientName), sVessel = escHtml(c.vesselName);
            return `<div class="ne-item" onclick="editCert('${sId}')">
              <div class="ne-days-badge ${badgeCls}">${badgeLabel}</div>
              <div style="flex:1;min-width:0">
                <div style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--gold)">${sId}</div>
                <div style="font-size:.76rem;color:var(--text-bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${sName || '—'}${sVessel ? ' · ' + sVessel : ''}</div>
                <div style="font-size:.62rem;color:var(--text-sec)">Valid until ${fmt(c.validUntil)} · ${dl === 0 ? 'expires today' : dl + ' day' + (dl===1?'':'s') + ' left'}</div>
              </div>
              <div style="display:flex;gap:5px">
                <button class="btn btn-ghost btn-sm" style="font-size:.58rem;padding:3px 7px" onclick="event.stopPropagation();editCert('${sId}')">Edit</button>
              </div>
            </div>`;
          }).join('');
        }
      }

      // ── Pending Activation ──
      const pendEl = document.getElementById('pendingCertList');
      const pendCountEl = document.getElementById('pendingCountBadge');
      if (pendEl && pendCountEl) {
        const pendingCerts = CERTS.filter(c => (c.status || '').toUpperCase() === 'PENDING');
        pendCountEl.textContent = pendingCerts.length;
        if (pendingCerts.length === 0) {
          pendEl.innerHTML = '<div style="padding:28px;text-align:center;color:var(--text-sec);font-size:.78rem">✓ No pending certificates</div>';
        } else {
          pendEl.innerHTML = pendingCerts.map(c => {
            const sId = escHtml(c.id), sName = escHtml(c.recipientName), sVessel = escHtml(c.vesselName);
            return `<div class="ne-item" onclick="editCert('${sId}')">
              <div style="flex-shrink:0;width:30px;height:30px;border-radius:8px;background:rgba(126,184,247,.1);border:1px solid rgba(126,184,247,.25);display:flex;align-items:center;justify-content:center;font-size:.9rem">⏳</div>
              <div style="flex:1;min-width:0">
                <div style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--gold)">${sId}</div>
                <div style="font-size:.76rem;color:var(--text-bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${sName || '—'}${sVessel ? ' · ' + sVessel : ''}</div>
                <div style="font-size:.62rem;color:#7EB8F7">Not yet publicly verifiable — activate to enable</div>
              </div>
              <div style="display:flex;gap:5px">
                <button class="btn btn-sm" style="font-size:.58rem;padding:3px 7px;background:rgba(100,255,218,.08);border:1px solid rgba(100,255,218,.22);color:var(--teal)" onclick="event.stopPropagation();activateCert('${sId}')">✓ Activate</button>
                <button class="btn btn-ghost btn-sm" style="font-size:.58rem;padding:3px 7px" onclick="event.stopPropagation();editCert('${sId}')">Edit</button>
              </div>
            </div>`;
          }).join('');
        }
      }

      // ── Emails Not Sent ──
      const epEl = document.getElementById('emailPendingList');
      const epCountEl = document.getElementById('emailPendingCountBadge');
      if (epEl && epCountEl) {
        const unsent = CERTS.filter(c => c.recipientEmail && c.emailStatus !== 'SENT');
        const noEmail = CERTS.filter(c => !c.recipientEmail && c.emailStatus !== 'SENT' && (c.status||'').toUpperCase() !== 'PENDING');
        epCountEl.textContent = unsent.length + noEmail.length;
        const allMissing = [...unsent, ...noEmail];
        if (allMissing.length === 0) {
          epEl.innerHTML = '<div style="padding:28px;text-align:center;color:var(--text-sec);font-size:.78rem">✓ All credentials dispatched</div>';
        } else {
          epEl.innerHTML = allMissing.map(c => {
            const isPending = (c.status||'').toUpperCase() === 'PENDING';
            const hasEmail  = !!c.recipientEmail;
            const sId = escHtml(c.id), sName = escHtml(c.recipientName), sEmail = escHtml(c.recipientEmail);
            const subColor  = isPending ? '#7EB8F7' : hasEmail ? 'var(--invalid)' : 'var(--warn)';
            const subText   = isPending ? '⏳ Cert pending — activate first' : hasEmail ? sEmail : '⚠ No email address on record';
            return `<div class="ne-item" style="gap:10px;cursor:${(!isPending&&hasEmail)?'pointer':'default'}" ${(!isPending&&hasEmail)?`onclick="quickSend('${sId}')"`:''}>
              <div style="flex-shrink:0;width:30px;height:30px;border-radius:8px;background:rgba(255,107,138,.08);border:1px solid rgba(255,107,138,.2);display:flex;align-items:center;justify-content:center">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--invalid)" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
              </div>
              <div style="flex:1;min-width:0">
                <div style="font-family:'JetBrains Mono',monospace;font-size:.64rem;color:var(--gold)">${sId}</div>
                <div style="font-size:.76rem;color:var(--text-bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${sName || '—'}</div>
                <div style="font-size:.61rem;color:${subColor};margin-top:1px">${subText}</div>
              </div>
              <div style="display:flex;gap:5px;flex-shrink:0">
                ${!isPending && hasEmail
                  ? `<button class="btn btn-issue btn-sm" style="font-size:.58rem;padding:4px 9px;white-space:nowrap;border-radius:7px" onclick="event.stopPropagation();quickSend('${sId}')">
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg>
                      Send
                    </button>`
                  : !isPending && !hasEmail
                  ? `<button class="btn btn-ghost btn-sm" style="font-size:.58rem;padding:4px 9px" onclick="event.stopPropagation();editCert('${sId}')">+ Email</button>`
                  : `<button class="btn btn-sm" style="font-size:.58rem;padding:4px 9px;background:rgba(100,255,218,.08);border:1px solid rgba(100,255,218,.22);color:var(--teal)" onclick="event.stopPropagation();activateCert('${sId}')">Activate</button>`
                }
              </div>
            </div>`;
          }).join('');
        }
      }
    }

    // ── QUICK STATUS CHANGE (inline table dropdown) ──
    async function quickStatusChange(id, newStatus, selEl) {
      const c = CERTS.find(x => x.id === id); if (!c) return;
      const oldStatus = c.status;
      if (oldStatus === newStatus) return;
      // Optimistic UI
      c.status = newStatus;
      if (selEl) { selEl.className = 'inline-status-sel status-' + newStatus.toLowerCase(); }
      try {
        const fd = new FormData();
        fd.append('status', newStatus);
        // If activating from PENDING and no validUntil set, auto-set 1 year from today
        if (newStatus === 'VALID' && !c.validUntil) {
          const d = new Date(); d.setFullYear(d.getFullYear() + 1);
          fd.append('validUntil', d.toISOString().slice(0, 10));
          c.validUntil = d.toISOString().slice(0, 10);
        }
        // When marking EXPIRED or REVOKED → set validUntil to today so radar + filters are accurate
        if (newStatus === 'EXPIRED' || newStatus === 'REVOKED') {
          const today = new Date().toISOString().slice(0, 10);
          fd.append('validUntil', today);
          c.validUntil = today;
        }
        const r = await fetch(API + '/certs/' + encodeURIComponent(id), {
          method: 'PUT', headers: { Authorization: 'Bearer ' + TOKEN }, body: fd
        });
        if (r.ok) {
          toast('Status updated successfully.', 'ok');
          await refreshStats();
          renderTbl('dashTbl', '');
          renderTbl('allTbl', document.getElementById('allQ')?.value || '', document.getElementById('allStatus')?.value || '', document.getElementById('allQtr')?.value || '', document.getElementById('allMode')?.value || '', document.getElementById('allEmail')?.value || '');
        } else {
          c.status = oldStatus;
          if (selEl) { selEl.value = oldStatus; selEl.className = 'inline-status-sel status-' + oldStatus.toLowerCase(); }
          toast('Could not update status. Please try again.', 'err');
        }
      } catch {
        c.status = oldStatus;
        if (selEl) { selEl.value = oldStatus; selEl.className = 'inline-status-sel status-' + oldStatus.toLowerCase(); }
        toast('Connection error. Please check your network.', 'err');
      }
    }

    async function activateCert(id) {
      const c = CERTS.find(x => x.id === id);
      if (!c) return;
      if (!confirm(`Activate certificate ${id}? This will set status to VALID.`)) return;
      try {
        const fd = new FormData();
        fd.append('status', 'VALID');
        const r = await fetch(API + '/certs/' + encodeURIComponent(id), { method: 'PUT', headers: { Authorization: 'Bearer ' + TOKEN }, body: fd });
        if (r.ok) {
          toast('Certificate activated successfully.', 'ok');
          await refreshStats();
          renderTbl('dashTbl', '');
        } else { toast('Could not activate certificate. Please try again.', 'err'); }
      } catch { toast('Something went wrong. Please try again.', 'err'); }
    }

    // ════════════════════════════════════════════════════
    // MODULE: Table rendering
    // ════════════════════════════════════════════════════
    function clearAllFilters() {
      ['allQ','allStatus','allQtr','allMode','allEmail'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
      renderTbl('allTbl', '', '', '', '', '');
      const cb = document.getElementById('allClearFilters');
      if (cb) cb.style.display = 'none';
    }
    function renderTbl(id, q, statusFilter, quarterFilter, modeFilter, emailFilter) {
      const el = document.getElementById(id);
      if (!el) {
        console.warn('[WARNING] renderTbl: Element not found with id=' + id);
        return;
      }
      
      // Force visibility and proper display
      el.style.display = 'block';
      el.style.visibility = 'visible';
      el.style.minHeight = 'auto';
      
      let list = CERTS || [];
      if (q) { const ql = q.toLowerCase(); list = list.filter(c => c.id.toLowerCase().includes(ql) || (c.recipientName || '').toLowerCase().includes(ql) || (c.vesselIMO || '').includes(ql) || (c.vesselName || '').toLowerCase().includes(ql) || (c.chiefEngineer || '').toLowerCase().includes(ql)); }
      if (statusFilter) {
        if (statusFilter === 'EXPIRED') {
          // EXPIRED = stored VALID but past validUntil
          const _now = new Date();
          list = list.filter(c => (c.status === 'VALID' || c.status === 'EXPIRED') && c.validUntil && new Date(c.validUntil) < _now || c.status === 'EXPIRED');
        } else if (statusFilter === 'VALID') {
          const _now = new Date();
          list = list.filter(c => c.status === 'VALID' && (!c.validUntil || new Date(c.validUntil) >= _now));
        } else {
          list = list.filter(c => c.status === statusFilter);
        }
      }
      if (quarterFilter) list = list.filter(c => (c.complianceQuarter || '').toUpperCase() === quarterFilter);
      if (modeFilter) list = list.filter(c => (c.trainingMode || '').toUpperCase() === modeFilter);
      if (emailFilter === 'SENT') list = list.filter(c => c.emailStatus === 'SENT');
      else if (emailFilter === 'NOT_SENT') list = list.filter(c => c.emailStatus !== 'SENT');
      // Update count badge
      const countEl = document.getElementById('allCertCount');
      if (countEl) countEl.innerHTML = `<strong>${list.length}</strong> records`;
      // Show/hide clear filter button
      const cb = document.getElementById('allClearFilters');
      if (cb) cb.style.display = (q || statusFilter || quarterFilter || modeFilter || emailFilter) ? '' : 'none';
      if (!list.length) { el.innerHTML = `<div class="empty-state"><svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" style="margin:0 auto;opacity:.3"><path stroke-linecap="round" stroke-linejoin="round" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><h3>No certificates match these filters</h3><p style="font-size:.8rem;color:var(--text-sec);margin-top:6px">Try adjusting your search or clearing filters</p></div>`; return; }
      const isDash = id === 'dashTbl';
      const tableHTML = `<div class="tbl-scroll-wrap" style="display:block!important;visibility:visible!important;height:auto!important;min-height:200px!important;overflow-x:auto!important"><table style="display:table!important;visibility:visible!important;min-width:1200px;width:100%!important;border-collapse:collapse!important"><colgroup>
    <col style="width:36px"><!-- Select -->
    <col style="width:160px"><!-- Cert ID -->
    <col style="width:200px"><!-- Vessel/Recipient -->
    <col style="width:88px"> <!-- IMO -->
    <col style="width:145px"><!-- Chief Engineer -->
    <col style="width:68px"> <!-- Quarter -->
    <col style="width:80px"> <!-- Mode -->
    <col style="width:118px"><!-- Status -->
    <col style="width:145px"><!-- Valid Until -->
    <col style="width:78px"> <!-- Email -->
    <col style="width:140px"><!-- Engagement -->
    ${!isDash ? '<col style="width:72px">' : ''}<!-- Image -->
    <col style="min-width:180px"><!-- Actions (fill rest) -->
  </colgroup><thead style="display:table-header-group!important;visibility:visible!important"><tr style="display:table-row!important;visibility:visible!important">
    <th style="padding:8px 6px;width:36px;text-align:center"><input type="checkbox" id="selAllCb_${id}" onchange="toggleSelectAll(this,'${id}')" style="accent-color:#64FFDA;width:14px;height:14px" title="Select all"></th><th>Certificate ID</th><th>Vessel / Recipient</th><th>IMO</th><th>Chief Engineer</th><th>Quarter</th><th>Mode</th><th>Status</th><th>Valid Until</th><th>Email</th><th>Engagement</th>${!isDash ? '<th>Image</th>' : ''}<th>Actions</th>
  </tr></thead><tbody style="display:table-row-group!important;visibility:visible!important">`+ (isDash ? list.slice(0, 10) : list).map(c => {
        const now = new Date(), vu = c.validUntil ? new Date(c.validUntil) : null;
        const isV = c.status === 'VALID' && (!vu || vu >= now);
        const pillCls = c.status === 'PENDING' ? 'pending' : c.status === 'VALID' ? (isV ? 'valid' : 'expired') : (c.status || 'unknown').toLowerCase();
        const dl = daysUntil(c.validUntil);
        let vl = fmt(c.validUntil);
        let vlColor = 'var(--text-sec)';
        if (dl !== null) {
          if (dl < 0) { vl += ` · ${Math.abs(dl)}d ago`; vlColor = 'var(--invalid)'; }
          else if (dl === 0) { vl += ' · today'; vlColor = 'var(--warn)'; }
          else if (dl <= 30) { vl += ` · ${dl}d`; vlColor = 'var(--warn)'; }
          else { vl += ` · ${dl}d`; vlColor = isV ? 'var(--teal)' : 'var(--text-sec)'; }
        }
        const imgSrc = imgUrl(c.certificateImage);
        const imgEl = c.certificateImage
          ? `<img class="thumb" src="${imgSrc}" loading="lazy" data-haserr="1" onclick="openLB(this.src)" /><div class="no-img" style="display:none">—</div>`
          : `<div class="no-img">—</div>`;
        const emailCls = c.emailStatus === 'SENT' ? 'sent' : 'not-sent';
        const emailLabel = c.emailStatus === 'SENT' ? '✓ Sent' : '—';
        const canSend = !!(c.recipientEmail && c.emailStatus !== 'SENT');
        // ── Engagement badges ──
        const eng = c.engagement || {};
        const emailSent = c.emailStatus === 'SENT';
        const engParts = [];
        if (eng.emailOpenCount)
          engParts.push(`<span class="eng-badge eng-open" title="Email opened ${eng.emailOpenCount}× · First: ${fmtDt(eng.emailOpenedAt)} · Last: ${fmtDt(eng.emailLastOpenAt)}">📧 <strong>${eng.emailOpenCount}</strong></span>`);
        else if (emailSent)
          engParts.push(`<span class="eng-badge" style="opacity:.45;font-size:.58rem" title="Email sent but not yet opened">📧 0</span>`);
        if (eng.certViewCount)
          engParts.push(`<span class="eng-badge eng-view" title="Cert viewed ${eng.certViewCount}× · First: ${fmtDt(eng.certFirstViewedAt)} · Last: ${fmtDt(eng.certLastViewedAt)}">👁 <strong>${eng.certViewCount}</strong></span>`);
        if (eng.docDownloadCount)
          engParts.push(`<span class="eng-badge eng-dl" title="Downloaded ${eng.docDownloadCount}× · Last: ${fmtDt(eng.docLastDownloadAt)}${eng.docLastFile?' · '+eng.docLastFile:''}">⬇ <strong>${eng.docDownloadCount}</strong></span>`);
        const engCell = engParts.length
          ? `<div style="display:flex;flex-wrap:wrap;gap:3px">${engParts.join('')}</div>`
          : (emailSent
          ? `<span class="eng-badge" style="background:rgba(255,179,71,.08);border:1px solid rgba(255,179,71,.22);color:var(--warn);font-size:.57rem;opacity:.85" title="Email sent — awaiting recipient interaction">⏳ Awaiting</span>`
          : `<span style="color:var(--text-sec);font-size:.6rem;font-style:italic;opacity:.6">No activity</span>`);
        const qVal = (c.complianceQuarter || '').toUpperCase();
        const qColors = { Q1: '#4A9EFF', Q2: '#64FFDA', Q3: '#FFB347', Q4: '#FF6B8A' };
        const qBg    = { Q1: 'rgba(74,158,255,0.12)', Q2: 'rgba(100,255,218,0.10)', Q3: 'rgba(255,179,71,0.12)', Q4: 'rgba(255,107,138,0.12)' };
        const qBadge = qVal
          ? `<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:.6rem;font-weight:700;letter-spacing:.1em;background:${qBg[qVal]||'rgba(255,255,255,.06)'};border:1px solid ${qColors[qVal]||'var(--border)'};color:${qColors[qVal]||'var(--text-sec)'};">${qVal}</span>`
          : `<span style="color:var(--text-sec);font-size:.7rem">—</span>`;
        const modeVal = (c.trainingMode || '').toUpperCase();
        const modeColors = { ONLINE:'var(--teal)', OFFLINE:'var(--gold)', HYBRID:'#B47EFF' };
        const modeBadge = modeVal
          ? `<span style="font-size:.6rem;font-weight:600;color:${modeColors[modeVal]||'var(--text-sec)'};">${modeVal}</span>`
          : `<span style="color:var(--text-sec);font-size:.7rem">—</span>`;
        const safeId   = escHtml(c.id);
        const safeName = escHtml(c.recipientName);
        const safeVessel = escHtml(c.vesselName);
        const safeIMO  = escHtml(c.vesselIMO);
        const safeCE   = escHtml(c.chiefEngineer);
        const safeEmail = escHtml(c.recipientEmail);
        const groupName = _imoGroupMap[(c.vesselIMO||'').toUpperCase()] || '';
        const groupBadge = groupName ? `<div style="display:inline-flex;align-items:center;gap:4px;margin-top:3px;padding:1px 7px;border-radius:20px;background:rgba(100,255,218,.1);border:1px solid rgba(100,255,218,.25);font-size:.58rem;color:var(--teal);font-weight:600;letter-spacing:.06em"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2h5M12 12a4 4 0 100-8 4 4 0 000 8z"/></svg>${escHtml(groupName)}</div>` : '';
        const selCell = `<td style="padding:6px 6px;text-align:center;vertical-align:middle;display:table-cell!important;visibility:visible!important"><input type="checkbox" class="row-sel-cb" data-imo="${safeIMO}" data-tbl="${id}" onchange="toggleRowSelect(this)" style="accent-color:#64FFDA;width:14px;height:14px" ${_selectedRows.has(c.vesselIMO||'')?'checked':''}></td>`;
        return `<tr style="display:table-row!important;visibility:visible!important;border-bottom:1px solid var(--border)!important">${selCell}
      <td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important"><span class="cid" title="${safeId}">${safeId}</span></td>
      <td class="name-cell" style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important;cursor:pointer" title="View in public portal" onclick="viewCertNewTab('${safeId}',null)"><div style="color:var(--text-bright);font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${safeName || '—'}</div>${safeVessel && c.vesselName !== c.recipientName ? `<div style="font-size:.68rem;color:var(--text-sec)">${safeVessel}</div>` : ''} ${groupBadge}</td>
      <td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important"><span style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--text-sec)">${safeIMO || '—'}</span></td>
      <td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important;font-size:.76rem;color:var(--text-sec);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${safeCE || '—'}</td>
      <td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important">${qBadge}</td>
      <td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important">${modeBadge}</td>
      <td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important"><select class="inline-status-sel status-${(c.status||'pending').toLowerCase()}" data-id="${safeId}" onchange="quickStatusChange('${safeId}',this.value,this)" title="Change status">
        <option value="VALID" ${c.status==='VALID'?'selected':''}>✓ VALID</option>
        <option value="PENDING" ${c.status==='PENDING'?'selected':''}>⏳ PENDING</option>
        <option value="EXPIRED" ${c.status==='EXPIRED'?'selected':''}>⏰ EXPIRED</option>
        <option value="REVOKED" ${c.status==='REVOKED'?'selected':''}>🚫 REVOKED</option>
      </select></td>
      <td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important;color:${vlColor};font-size:.76rem;white-space:nowrap">${vl}</td>
      <td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important"><span class="pill ${emailCls}" title="${safeEmail || 'no email'}">${emailLabel}</span></td>
      <td class="eng-cell" style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important">${engCell}</td>
      ${!isDash ? `<td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important">${imgEl}</td>` : ''}
      <td style="display:table-cell!important;visibility:visible!important;padding:8px 10px!important"><div class="act-grp">
        <button class="btn btn-ghost btn-sm" onclick="viewCertNewTab('${safeId}',this)">View</button>
        <button class="btn btn-teal btn-sm" onclick="editCert('${safeId}')">Edit</button>
        <button class="btn btn-ghost btn-sm" title="Copy encrypted verification URL" onclick="copyEncUrl('${safeId}',this)" style="font-size:.58rem">🔒</button>
        ${canSend ? `<button class="btn btn-issue btn-sm" onclick="quickSend('${safeId}')">✉</button>` : ''}
        <button class="btn btn-ghost btn-sm" title="Assign vessel to group" onclick="openAssignGroup('${safeIMO}','${safeVessel||safeName}')">👥</button>
        <button class="btn btn-danger btn-sm" onclick="askDelete('${safeId}')">Delete</button>
      </div></td>
    </tr>`;
      }).join('') + `</tbody></table></div>`;

      try {
        el.innerHTML = tableHTML;
      } catch (htmlErr) {
        console.error('[renderTbl] innerHTML error:', htmlErr);
        el.innerHTML = '<div class="empty-state"><h3>Table render error</h3><p style="font-size:.8rem;color:var(--text-sec)">Check browser console for details.</p></div>';
        return;
      }
      
      // Ensure table wrapper and table are visible
      setTimeout(() => {
        const tblWrapper = el.querySelector('.tbl-scroll-wrap');
        const tbl = el.querySelector('table');
        if (tblWrapper) {
          tblWrapper.style.display = 'block';
          tblWrapper.style.visibility = 'visible';
          tblWrapper.style.minHeight = '200px';
        }
        if (tbl) {
          tbl.style.display = 'table';
          tbl.style.visibility = 'visible';
        }
      }, 0);
      
      el.querySelectorAll('img.thumb[data-haserr]').forEach(img => {
        img.addEventListener('error', function() {
          this.style.display = 'none';
          const placeholder = this.nextElementSibling;
          if (placeholder) placeholder.style.display = 'inline-flex';
        }, { once: true });
      });
    }

    // ════════════════════════════════════════════════════
    // MODULE: Pages
    // ════════════════════════════════════════════════════
    function showPage(name, el) {
      try {
        ['dashboard', 'certs', 'add', 'issue', 'csv', 'validity'].forEach(p => {
          const pageEl = document.getElementById('page-' + p);
          if (pageEl) {
            if (p === name) {
              pageEl.style.display = '';
              pageEl.style.visibility = 'visible';
              pageEl.style.opacity = '1';
            } else {
              pageEl.style.display = 'none';
              pageEl.style.visibility = 'hidden';
            }
          }
        });
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        if (el) el.classList.add('active');
        const titles = { dashboard: ['Dashboard', 'Admin › Overview'], certs: ['All Certificates', 'Admin › Certificates'], add: [editingId ? 'Edit Certificate' : 'Add Certificate', 'Admin › ' + (editingId ? 'Edit' : 'Add')], issue: ['Issue Credentials', 'Admin › Issue'], csv: ['Import CSV', 'Admin › CSV Import'], validity: ['Internal Validity', 'Admin › Internal Validity'] };
        const [t, b] = titles[name] || ['', ''];
        const titleEl = document.getElementById('pageTitle');
        const breadEl = document.getElementById('pageBread');
        if (titleEl) titleEl.textContent = t;
        if (breadEl) breadEl.textContent = b;
        if (name === 'certs') {
          const alltblEl = document.getElementById('allTbl');
          if (!alltblEl) console.warn('[WARNING] page-certs: #allTbl element not found');
          // Ensure the table container is visible
          if (alltblEl) {
            alltblEl.style.display = 'block';
            alltblEl.style.visibility = 'visible';
          }
          renderTbl('allTbl', '');
        } else {
          if (typeof clearSelections === 'function') clearSelections();
        }
        if (name === 'issue') { renderIssueList(''); refreshStats(); }
        if (name === 'validity') renderValidityPage();
      } catch (err) {
        console.error('[ERROR] showPage() error:', err);
      }
    }
    function startAdd() {
      issuanceMode = false; editingId = null; resetForm();
      showPage('add', document.getElementById('nav-add'));
    }

    // ════════════════════════════════════════════════════
    // MODULE: Duplicate check
    // ════════════════════════════════════════════════════
    function checkDuplicate() {
      clearTimeout(dupCheckTimer);
      const id = document.getElementById('fId').value.trim().toUpperCase();
      const hint = document.getElementById('dupHint');
      const inp = document.getElementById('fId');
      if (!id || editingId) { hint.textContent = ''; inp.classList.remove('duplicate-warn', 'duplicate-ok'); return; }
      dupCheckTimer = setTimeout(async () => {
        try {
          const r = await fetch(API + '/certs/' + encodeURIComponent(id), { headers: { Authorization: 'Bearer ' + TOKEN } });
          const d = r.status === 404 ? { exists: false } : { exists: true };
          if (d.exists) {
            hint.textContent = '⚠ This ID already exists in the registry'; hint.className = 'field-hint warn';
            inp.classList.add('duplicate-warn'); inp.classList.remove('duplicate-ok');
          } else {
            hint.textContent = '✓ ID is available'; hint.className = 'field-hint ok';
            inp.classList.add('duplicate-ok'); inp.classList.remove('duplicate-warn');
          }
        } catch { }
      }, 500);
    }

    // ════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════
    // MODULE: Quarter Logic — auto-derive validFor, validUntil, recipientName
    // ════════════════════════════════════════════════════
    // Quarter the training was DONE in → valid until END of the NEXT quarter
    // Q1 (Jan-Mar) done → expires end of Q2 (Jun 30)
    // Q2 (Apr-Jun) done → expires end of Q3 (Sep 30)
    // Q3 (Jul-Sep) done → expires end of Q4 (Dec 31)
    // Q4 (Oct-Dec) done → expires end of Q1 next year (Mar 31)
    const QUARTER_MAP = {
      Q1: { label: 'Q2 (APR–JUN)',  endMonth: 6,  endDay: 30 },
      Q2: { label: 'Q3 (JUL–SEP)',  endMonth: 9,  endDay: 30 },
      Q3: { label: 'Q4 (OCT–DEC)',  endMonth: 12, endDay: 31 },
      Q4: { label: 'Q1 (JAN–MAR)',  endMonth: 3,  endDay: 31, nextYear: true }
    };
    function onQuarterChange() {
      const q = document.getElementById('fQuarter').value;
      const compDate = document.getElementById('fCompDate').value;
      const baseYear = compDate ? new Date(compDate).getFullYear() : new Date().getFullYear();
      const info = QUARTER_MAP[q];
      if (!info) return;
      const year = info.nextYear ? baseYear + 1 : baseYear;
      document.getElementById('fValidFor').value = info.label + '-' + year;
      const until = new Date(year, info.endMonth - 1, info.endDay);
      document.getElementById('fUntil').value = until.toISOString().slice(0, 10);
      livePreview();
    }
    function onVesselNameInput() {
      const vn = document.getElementById('fVesselName').value.trim();
      const recip = document.getElementById('fRecip');
      if (vn && (!recip.value || recip.value.startsWith('MV - '))) {
        recip.value = 'MV - ' + vn;
      }
      livePreview();
    }

    function onStatusChange() {
      const s = document.getElementById('fStatus').value;
      const hint = document.getElementById('statusHint');
      if (s === 'PENDING') {
        hint.style.display = 'block';
      } else {
        hint.style.display = 'none';
      }
      livePreview();
      updateCompletionChecklist();
    }

    function validateIssueDate(input) {
      livePreview();
    }

    // ── URL helpers ──────────────────────────────────────────
    // The server returns the full public URL in /api/cert-url.
    // We never need to guess the public origin in the browser.

    // Sync fallback: plain cert path (used only when no token available yet)
    function getCertHashUrl(certId) {
      var base = (window.APP_CONFIG ? window.APP_CONFIG.routes.cst : '/CST');
      return base + '/cert/' + encodeURIComponent(certId);
    }
    // Async: fetch encrypted+signed URL from server (server knows PUBLIC_ORIGIN)
    async function getCertEncryptedUrl(certId) {
      var base = (window.APP_CONFIG ? window.APP_CONFIG.routes.cst : '/CST');
      try {
        const r = await fetch(API + '/cert-url/' + encodeURIComponent(certId), {
          headers: { Authorization: 'Bearer ' + TOKEN }
        });
        if (!r.ok) return window.location.origin + base + '/cert/' + encodeURIComponent(certId);
        const d = await r.json();
        // Server returns the full absolute URL with correct public origin
        return d.url;
      } catch { return window.location.origin + base + '/cert/' + encodeURIComponent(certId); }
    }
    function copyUrl(url, btn) {
      navigator.clipboard.writeText(url).then(() => {
        const orig = btn.textContent; btn.textContent = '✓ Copied!';
        setTimeout(() => { btn.textContent = orig; }, 2000);
      }).catch(() => {});
    }
    // Copy AES-256-GCM encrypted + HMAC-signed URL
    async function copyEncUrl(certId, btn) {
      const orig = btn.textContent;
      btn.textContent = '⏳'; btn.disabled = true;
      const url = await getCertEncryptedUrl(certId);
      await navigator.clipboard.writeText(url).catch(() => {});
      btn.textContent = '✓'; setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 1800);
    }
    // Token expiry check — warn admin 30 min before expiry
    function scheduleTokenExpiryWarning() {
      try {
        const parts = TOKEN.split('.');
        if (parts.length !== 3) return;
        const payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
        const msLeft = payload.exp * 1000 - Date.now();
        if (msLeft <= 0) { doLogout(); return; }
        // Auto-logout at expiry
        setTimeout(doLogout, msLeft);
        // Warn at 30 min before expiry
        const warnAt = msLeft - 30 * 60 * 1000;
        if (warnAt > 0) setTimeout(() => toast('⚠ Session expires in 30 minutes. Save your work.', 'warn'), warnAt);
      } catch { }
    }

    // ════════════════════════════════════════════════════
    // MODULE: Completion Checklist
    // ════════════════════════════════════════════════════
    const COMPLETION_FIELDS = [
      { id: 'imo',       label: 'Vessel IMO Number',       tagId: 'imoRequiredTag',   check: () => !!document.getElementById('fIMO').value.trim() },
      { id: 'email',     label: 'Recipient Email',         tagId: 'emailRequiredTag', check: () => { const v = document.getElementById('fEmail'); return !!(v && v.value.trim()); } },
      { id: 'eng',       label: 'Chief Engineer Name',     tagId: 'engRequiredTag',   check: () => !!document.getElementById('fEng').value.trim() },
      { id: 'compDate',  label: 'Compliance Date',         tagId: 'dateRequiredTag',  check: () => !!document.getElementById('fCompDate').value },
      { id: 'img',       label: 'Certificate Image (PNG)', tagId: 'imgRequiredTag',   check: () => !!(imgFile || (document.getElementById('prevImg') && document.getElementById('prevImg').src && !document.getElementById('prevImg').src.endsWith('/') && document.getElementById('prevImg').src !== window.location.href)) },
    ];

    function updateCompletionChecklistFull() {
      const isEdit = !!editingId;
      const fields = COMPLETION_FIELDS.map(f => ({ ...f, ok: f.check() }));
      const total = fields.length;
      const done = fields.filter(f => f.ok).length;
      const allDone = done === total;
      const pct = Math.round(done / total * 100);

      // Elements
      const headerTitle = document.getElementById('cpHeaderTitle');
      const headerSub   = document.getElementById('cpHeaderSub');
      const headerIcon  = document.getElementById('cpHeaderIcon');
      const bar         = document.getElementById('cpBar');
      const badge       = document.getElementById('cpProgressBadge');
      const cpHeader    = document.getElementById('cpHeader');
      const actionText  = document.getElementById('cpActionText');
      const saveBtn     = document.getElementById('saveBtn');
      const saveTxt     = document.getElementById('saveTxt');
      const statusSel   = document.getElementById('fStatus');
      const statusHint  = document.getElementById('statusHint');

      if (!headerTitle) return; // not on add page

      // Update progress bar
      bar.style.width = pct + '%';
      badge.textContent = done + '/' + total;

      // Render checklist items
      const itemsEl = document.getElementById('cpItems');
      if (itemsEl) {
        itemsEl.innerHTML = fields.map(f => {
          const cls = f.ok ? 'done' : 'missing';
          const tag = f.ok ? 'Done' : 'Required';
          return `<div class="cp-item ${cls}">
            <div class="cp-check">${f.ok ? '✓' : ''}</div>
            <span class="cp-label">${f.label}</span>
            <span class="cp-tag">${tag}</span>
          </div>`;
        }).join('');
      }

      // Update inline field tags
      fields.forEach(f => {
        if (!f.tagId) return;
        const tag = document.getElementById(f.tagId);
        if (!tag) return;
        if (f.ok) {
          tag.style.background = 'rgba(100,255,218,.08)';
          tag.style.color = 'var(--teal)';
          tag.style.borderColor = 'rgba(100,255,218,.2)';
          tag.textContent = '✓ Done';
        } else {
          tag.style.background = 'rgba(255,107,138,.06)';
          tag.style.color = 'var(--invalid)';
          tag.style.borderColor = 'rgba(255,107,138,.15)';
          tag.textContent = 'Required';
        }
      });

      if (allDone) {
        // ── ALL COMPLETE ──
        headerTitle.textContent = isEdit ? 'Ready to Update' : 'Ready to Activate';
        headerTitle.style.color = 'var(--teal)';
        headerSub.textContent = isEdit ? 'All required fields complete' : 'All fields complete — auto-set to VALID';
        headerIcon.style.cssText = 'width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.65rem;flex-shrink:0;background:rgba(100,255,218,.12);border:1px solid rgba(100,255,218,.3);color:var(--teal)';
        headerIcon.textContent = '✓';
        bar.style.background = 'var(--teal)';
        badge.style.cssText = 'margin-left:auto;font-size:.6rem;font-weight:700;padding:3px 9px;border-radius:8px;background:rgba(100,255,218,.1);border:1px solid rgba(100,255,218,.25);color:var(--teal)';
        cpHeader.style.background = 'rgba(100,255,218,.04)';
        // New cert → auto-set VALID; edit → leave existing status as-is but unlock
        if (!isEdit) {
          statusSel.value = 'VALID';
          actionText.innerHTML = '· All required fields completed ✓<br>· Status automatically set to <strong style="color:var(--teal)">VALID</strong> — certificate is publicly verifiable<br>· You can change the status above if needed';
        } else {
          actionText.innerHTML = '· All required fields completed ✓<br>· Update the certificate to apply changes';
        }
        statusSel.disabled = false;
        statusSel.style.opacity = '';
        saveBtn.setAttribute('style', 'flex:1;justify-content:center;padding:12px');
        saveBtn.className = 'btn btn-primary';
        saveTxt.textContent = isEdit ? 'Update Certificate' : 'Save & Activate';
        statusHint.style.display = statusSel.value === 'PENDING' ? 'block' : 'none';
      } else {
        // ── INCOMPLETE ──
        const missing = fields.filter(f => !f.ok).length;
        headerTitle.textContent = 'Pending Activation';
        headerTitle.style.color = done === 0 ? 'var(--text-sec)' : 'var(--warn)';
        headerSub.textContent = missing + ' required field' + (missing === 1 ? '' : 's') + ' missing — will save as PENDING';
        headerIcon.style.cssText = 'width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.65rem;flex-shrink:0;' + (done === 0 ? 'background:var(--surface);border:1px solid var(--border);color:var(--text-sec)' : 'background:rgba(255,179,71,.12);border:1px solid rgba(255,179,71,.3);color:var(--warn)');
        headerIcon.textContent = done === 0 ? '○' : '!';
        bar.style.background = pct > 60 ? 'var(--warn)' : 'var(--invalid)';
        badge.style.cssText = 'margin-left:auto;font-size:.6rem;font-weight:700;padding:3px 9px;border-radius:8px;background:rgba(255,179,71,.1);border:1px solid rgba(255,179,71,.25);color:var(--warn)';
        cpHeader.style.background = '';
        actionText.innerHTML = '· Fill missing fields above to auto-activate<br>· Will be saved as <strong style="color:#7EB8F7">PENDING</strong> — not publicly verifiable until all fields filled<br>· All 5 fields required: IMO, Email, Chief Engineer, Date, Image';
        // Force PENDING and lock dropdown (new certs only — don't override existing cert status on edit)
        if (!isEdit) {
          statusSel.value = 'PENDING';
          statusSel.disabled = true;
          statusSel.style.opacity = '0.5';
          statusHint.style.display = 'block';
          saveBtn.setAttribute('style', 'flex:1;justify-content:center;padding:12px;background:rgba(126,184,247,.15);border-color:rgba(126,184,247,.35);color:#7EB8F7');
          saveBtn.className = 'btn btn-primary';
          saveTxt.textContent = 'Save as Pending';
        }
      }
    }

    // Alias for backward compat calls
    const updateCompletionChecklist = updateCompletionChecklistFull;

        // ════════════════════════════════════════════════════
    function livePreview() {
      const id = document.getElementById('fId').value || '—';
      const name = document.getElementById('fRecip').value || 'Recipient Name';
      const title = document.getElementById('fTitle').value || 'Training Title';
      const vessel = document.getElementById('fVesselName').value || '—';
      const imo = document.getElementById('fIMO').value || '—';
      const q = document.getElementById('fQuarter').value;
      const mode = document.getElementById('fMode').value;
      const until = document.getElementById('fUntil').value;
      const verif = document.getElementById('fVerifier').value;
      const status = document.getElementById('fStatus').value;
      document.getElementById('pv-id').textContent = id;
      document.getElementById('pv-name').textContent = name;
      document.getElementById('pv-title').textContent = title;
      document.getElementById('pv-vessel').textContent = vessel;
      document.getElementById('pv-imo').textContent = imo;
      document.getElementById('pv-quarter').textContent = q;
      document.getElementById('pv-mode').textContent = mode;
      document.getElementById('pv-until').textContent = until ? new Date(until).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
      document.getElementById('pv-verifier').textContent = verif.split(',')[0] || verif;
      document.getElementById('pv-watermark').textContent = status === 'VALID' ? 'VALID' : status;
      const wmColors = { VALID: 'rgba(212,168,67,.04)', PENDING: 'rgba(126,184,247,.06)', REVOKED: 'rgba(255,107,138,.05)', EXPIRED: 'rgba(255,107,138,.05)' };
      document.getElementById('pv-watermark').style.color = wmColors[status] || 'rgba(255,107,138,.05)';
      // Trigger checklist update
      updateCompletionChecklistFull();
    }

    // ════════════════════════════════════════════════════
    // MODULE: Issue Credentials
    // ════════════════════════════════════════════════════
    function renderIssueList(q) {
      const el = document.getElementById('issueCertList');
      const filter = document.getElementById('issueFilter').value;
      let list = CERTS;
      if (q) { const ql = q.toLowerCase(); list = list.filter(c => c.id.toLowerCase().includes(ql) || (c.recipientName || '').toLowerCase().includes(ql) || (c.vesselIMO || '').includes(ql)); }
      if (filter) list = list.filter(c => (c.emailStatus || 'NOT_SENT') === filter);
      // Sort: pending first, then by vessel name
      list = [...list].sort((a, b) => {
        const aP = a.emailStatus === 'SENT' ? 1 : 0;
        const bP = b.emailStatus === 'SENT' ? 1 : 0;
        if (aP !== bP) return aP - bP;
        return (a.recipientName || '').localeCompare(b.recipientName || '');
      });
      if (!list.length) { el.innerHTML = `<div style="text-align:center;padding:24px;color:var(--text-sec);font-size:.78rem">No certificates match</div>`; return; }
      const sentCount = list.filter(c => c.emailStatus === 'SENT').length;
      const pendingCount = list.length - sentCount;
      el.innerHTML = `
        <div style="display:flex;gap:8px;margin-bottom:12px;padding:10px 12px;background:var(--navy-mid);border-radius:9px;border:1px solid var(--border)">
          <div style="flex:1;text-align:center">
            <div style="font-family:'Playfair Display',serif;font-size:1.2rem;font-weight:700;color:var(--invalid)">${pendingCount}</div>
            <div style="font-size:.56rem;letter-spacing:.1em;color:var(--text-sec);text-transform:uppercase">Pending</div>
          </div>
          <div style="width:1px;background:var(--border)"></div>
          <div style="flex:1;text-align:center">
            <div style="font-family:'Playfair Display',serif;font-size:1.2rem;font-weight:700;color:var(--teal)">${sentCount}</div>
            <div style="font-size:.56rem;letter-spacing:.1em;color:var(--text-sec);text-transform:uppercase">Sent ✓</div>
          </div>
          <div style="width:1px;background:var(--border)"></div>
          <div style="flex:1;text-align:center">
            <div style="font-family:'Playfair Display',serif;font-size:1.2rem;font-weight:700;color:var(--gold)">${list.length}</div>
            <div style="font-size:.56rem;letter-spacing:.1em;color:var(--text-sec);text-transform:uppercase">Total</div>
          </div>
        </div>
      ` + list.slice(0, 50).map(c => {
        const isSent = c.emailStatus === 'SENT';
        const isSelected = c.id === selectedIssueCertId;
        const hasEmail = !!c.recipientEmail;
        const rowCls = isSelected ? 'selected' : isSent ? 'done' : '';
        const checkContent = isSelected ? '●' : isSent ? '✓' : '';
        return `<div class="issue-cert-row ${rowCls}" onclick="selectIssueCert('${c.id}')">
          <div class="issue-cert-check">${checkContent}</div>
          <div class="issue-cert-meta" style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px">
              <span style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--gold)">${c.id}</span>
              ${c.status === 'PENDING' ? `<span style="font-size:.52rem;background:rgba(126,184,247,.12);color:#7EB8F7;border:1px solid rgba(126,184,247,.25);border-radius:5px;padding:1px 5px">PENDING</span>` : ''}
            </div>
            <div style="font-size:.78rem;color:var(--text-bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${c.recipientName || '—'}</div>
            <div style="font-size:.63rem;color:var(--text-sec);margin-top:1px;display:flex;align-items:center;gap:6px">
              <span>IMO ${c.vesselIMO || '—'}</span>
              ${hasEmail ? `<span style="color:var(--teal)">· ${c.recipientEmail}</span>` : `<span style="color:var(--warn)">· no email set</span>`}
            </div>
            ${isSent && c.emailSentAt ? `<div style="font-size:.58rem;color:var(--teal);margin-top:2px">✓ Sent ${new Date(c.emailSentAt).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'})}</div>` : ''}
          </div>
          <span class="email-status-badge ${isSent ? 'sent' : 'not-sent'}">${isSent ? '✓ Done' : '⏳ Pending'}</span>
        </div>`;
      }).join('');
    }

    function selectIssueCert(id) {
      selectedIssueCertId = id;
      const c = CERTS.find(x => x.id === id);
      if (!c) return;
      renderIssueList(document.getElementById('issueSearch').value);
      document.getElementById('issueSelectPrompt').style.display = 'none';
      document.getElementById('issueComposeForm').style.display = 'block';
      document.getElementById('issueSelectedId').textContent = c.id;
      document.getElementById('issueSelectedName').textContent = (c.recipientName || '') + (c.vesselIMO ? '  ·  IMO ' + c.vesselIMO : '');
      document.getElementById('issueRecipEmail').value = c.recipientEmail || '';
      // Always keep both buttons available — Mark Sent shows prior status but stays clickable
      const markBtn = document.getElementById('markSentBtn');
      const sendBtn = document.getElementById('sendSesBtn');
      markBtn.disabled = false;
      markBtn.style.background = ''; markBtn.style.borderColor = ''; markBtn.style.color = '';
      sendBtn.disabled = false;
      sendBtn.style.background = ''; sendBtn.style.borderColor = ''; sendBtn.style.color = '';
      document.getElementById('markSentTxt').textContent = c.emailStatus === 'SENT' ? '✓ Re-Mark Sent' : 'Mark Sent';
      document.getElementById('sendSesTxt').textContent = c.emailStatus === 'SENT' ? 'Re-Send via AWS' : 'Send via AWS SES';
      updateIssueEmailPreview();
    }

    function clearIssueSelection() {
      selectedIssueCertId = null;
      document.getElementById('issueSelectPrompt').style.display = 'block';
      document.getElementById('issueComposeForm').style.display = 'none';
      renderIssueList(document.getElementById('issueSearch').value);
    }

    async function updateIssueEmailPreview() {
      if (!selectedIssueCertId) return;
      const c = CERTS.find(x => x.id === selectedIssueCertId);
      if (!c) return;
      const verifyUrl = await getCertEncryptedUrl(c.id);

      // Use config template if available, else inline fallback
      const plainText = (window.APP_CONFIG && window.APP_CONFIG.emailTemplates && window.APP_CONFIG.emailTemplates.cst)
        ? window.APP_CONFIG.emailTemplates.cst(c, verifyUrl)
        : (() => {
            const d = c.complianceDate ? new Date(c.complianceDate).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) : '—';
            const team = window.APP_CONFIG ? window.APP_CONFIG.brand.cstTeam : 'Synergy Cyber Security Team';
            const email = window.APP_CONFIG ? window.APP_CONFIG.contact.cstEmail : 'trainingawareness@synergyship.com';
            return `Dear ${c.recipientName || 'Sir / Madam'},\n\nPlease find below the Cyber Security Threat Awareness Training certificate details for your records.\n\nVessel            : ${c.recipientName||'—'}\nVessel IMO        : ${c.vesselIMO||'—'}\nChief Engineer    : ${c.chiefEngineer||'—'}\nCertificate No.   : ${c.id}\nCompliance Date   : ${d}\nCompliance Quarter: ${c.complianceQuarter||'—'}\nTraining Mode     : ${c.trainingMode||'—'}\nValid For         : ${c.validFor||'—'}\n\nYour certificate image is attached to this email for your records.\n\nTo verify the authenticity of this certificate at any time, visit the link below\nor enter Certificate No. ${c.id} at the verification portal:\n\n${verifyUrl}\n\nThis training was organized by the ${team} and conducted\nunder supervision of ISO Lead Auditor and Security trainers.\n\nRegards,\n${team}\n${email}`;
          })();

      const previewEl = document.getElementById('issueEmailPreview');
      const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

      // Split the body around the verify URL to inject the CTA button
      const bodyBeforeUrl = plainText.split(verifyUrl)[0] || '';
      const bodyAfterUrl  = (plainText.split(verifyUrl)[1] || '').trim();

      previewEl.innerHTML = `
        <div style="white-space:pre-wrap;font-size:.75rem;color:var(--text);line-height:1.9;font-family:'DM Sans',sans-serif">${esc(bodyBeforeUrl)}</div>

        <!-- Cert image note -->
        <div style="margin:10px 0;padding:10px 14px;background:rgba(100,255,218,.04);border:1px solid rgba(100,255,218,.18);border-radius:9px;font-size:.72rem;color:var(--teal);display:flex;align-items:center;gap:7px">
          <span>📎</span><span>Certificate image is attached to this email.</span>
        </div>

        <!-- CTA Block -->
        <div style="margin:14px 0 10px;padding:14px 16px;background:rgba(212,168,67,.06);border:1px solid rgba(212,168,67,.2);border-radius:10px">
          <div style="font-size:.6rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:10px;display:flex;align-items:center;gap:5px">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
            Verification Link
          </div>
          <a href="${esc(verifyUrl)}" target="_blank" rel="noopener"
            style="display:inline-flex;align-items:center;gap:8px;padding:11px 22px;
                   background:linear-gradient(135deg,#D4A843,#9E7B0A);color:#0A1628;
                   border-radius:9px;font-weight:700;font-size:.78rem;text-decoration:none;
                   letter-spacing:.04em;font-family:'DM Sans',sans-serif;
                   box-shadow:0 3px 12px rgba(212,168,67,.4);margin-bottom:10px;display:block;text-align:center">
            🔗 &nbsp;Click Here to View &amp; Verify Certificate
          </a>
          <div style="font-size:.6rem;color:var(--text-sec);word-break:break-all;display:flex;align-items:flex-start;gap:5px;padding:8px 10px;background:var(--navy);border-radius:7px;border:1px solid var(--border)">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2" style="flex-shrink:0;margin-top:1px"><path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
            <span style="font-family:'JetBrains Mono',monospace;color:var(--teal);font-size:.6rem">${esc(verifyUrl)}</span>
          </div>
        </div>

        <div style="white-space:pre-wrap;font-size:.75rem;color:var(--text-sec);line-height:1.9;border-top:1px solid var(--border);padding-top:10px;margin-top:6px">${esc(bodyAfterUrl)}</div>
      `;

      previewEl._plainText = plainText;
    }

    function copyMailBody() {
      const el = document.getElementById('issueEmailPreview');
      const body = el._plainText || el.textContent;
      if (!body) return;
      navigator.clipboard.writeText(body).then(() => {
        const btn = document.getElementById('copyBtnTxt');
        const orig = btn ? btn.textContent : 'Copy Body';
        if (btn) btn.textContent = '✓ Copied!';
        setTimeout(() => { if (btn) btn.textContent = orig; }, 2000);
      }).catch(() => {});
    }

    // ── Email service status check (runs once on load) ──────────────────
    async function checkSesStatus() {
      try {
        const r = await fetch(API + '/ses-status', { headers: { Authorization: 'Bearer ' + TOKEN } });
        const d = r.ok ? await r.json() : {};
        const badge = document.getElementById('sesBadgeCst');
        const dot   = document.getElementById('sesBadgeCstDot');
        const txt   = document.getElementById('sesBadgeCstTxt');
        const sbDot = document.getElementById('sesSbDot');
        const lbl   = document.getElementById('sesSbLabel');
        if (d.enabled) {
          if (badge) {
            badge.style.background  = 'rgba(100,255,218,.08)';
            badge.style.color       = 'var(--teal)';
            badge.style.borderColor = 'rgba(100,255,218,.25)';
          }
          if (dot)  { dot.style.background = 'var(--teal)'; dot.style.animation = 'pulse 2s ease-in-out infinite'; }
          if (txt)  txt.textContent = 'Email Dispatch Active';
          if (sbDot) sbDot.style.background = 'var(--teal)';
          if (lbl)  lbl.textContent = 'Mail On';
        } else {
          if (badge) {
            badge.style.background  = 'rgba(255,107,138,.08)';
            badge.style.color       = '#ff6b8a';
            badge.style.borderColor = 'rgba(255,107,138,.2)';
          }
          if (dot)  { dot.style.background = 'var(--invalid)'; dot.style.animation = ''; }
          if (txt)  txt.textContent = 'Email Offline';
          if (sbDot) sbDot.style.background = 'var(--invalid)';
          if (lbl)  lbl.textContent = 'Mail Off';
        }
      } catch {
        const dot = document.getElementById('sesSbDot');
        const lbl = document.getElementById('sesSbLabel');
        if (dot) dot.style.background = 'var(--invalid)';
        if (lbl) lbl.textContent      = 'Mail Err';
      }
    }

    // ── Server health check (runs once on load, no auth required) ───────
    async function checkHealth() {
      const dot = document.getElementById('healthDot');
      const lbl = document.getElementById('healthLabel');
      try {
        const r = await fetch(API + '/health');
        const d = r.ok ? await r.json() : {};
        if (r.ok && d.ok) {
          if (dot) dot.style.background = 'var(--teal)';
          const up = d.uptime != null ? Math.floor(d.uptime / 3600) + 'h' : '';
          if (lbl) lbl.textContent = up ? 'Up · ' + up : 'Online';
        } else {
          if (dot) dot.style.background = 'var(--warn)';
          if (lbl) lbl.textContent = 'Degraded';
        }
      } catch {
        if (dot) dot.style.background = 'var(--invalid)';
        if (lbl) lbl.textContent = 'Offline';
      }
    }

    // ── Send credential email ───────────────────────────────────────────
    async function sendViaSES() {
      if (!selectedIssueCertId) { toast('Select a certificate first.', 'warn'); return; }
      const recipEmail = (document.getElementById('issueRecipEmail').value || '').trim();
      if (!recipEmail) { toast('Enter a recipient email address first.', 'warn'); return; }
      const issueCert = CERTS.find(x => x.id === selectedIssueCertId);
      const force = issueCert && (issueCert.emailStatus || '').toUpperCase() === 'SENT';

      const btn = document.getElementById('sendSesBtn');
      btn.disabled = true;
      document.getElementById('sendSesTxt').textContent = 'Sending…';
      const resultEl = document.getElementById('sesSendResult');
      resultEl.style.display = 'none';

      try {
        // Pass recipientEmail in the request body — server will persist it AND use it to send
        const r = await fetch(API + '/certs/' + encodeURIComponent(selectedIssueCertId) + '/send-email', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
          body: JSON.stringify({ recipientEmail: recipEmail, baseUrl: window.location.origin, force })
        });
        const d = await r.json();

        if (r.ok && d.success) {
          const sentAt = d.emailSentAt ? new Date(d.emailSentAt).toLocaleString('en-GB', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }) : new Date().toLocaleString();
          resultEl.style.display = 'block';
          resultEl.style.background = 'rgba(100,255,218,.07)';
          resultEl.style.border     = '1px solid rgba(100,255,218,.22)';
          resultEl.style.color      = 'var(--teal)';
          resultEl.innerHTML = `
            <div style="display:flex;align-items:flex-start;gap:10px">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-top:1px"><path stroke-linecap="round" stroke-linejoin="round" d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg>
              <div>
                <div style="font-weight:700;font-size:.78rem">Dispatched via AWS SES</div>
                <div style="font-size:.65rem;opacity:.85;margin-top:3px;line-height:1.6">
                  To: <strong>${recipEmail}</strong><br>
                  Sent: ${sentAt}${d.messageId ? '<br>Message ID: <code style="font-size:.6rem;opacity:.7">' + d.messageId + '</code>' : ''}
                </div>
              </div>
            </div>`;
          toast('✓ Credential email sent successfully.', 'ok');
          const c = CERTS.find(x => x.id === selectedIssueCertId);
          if (c) { c.emailStatus = 'SENT'; c.emailSentAt = d.emailSentAt || new Date().toISOString(); c.recipientEmail = recipEmail; }
          await refreshStats();
          renderIssueList(document.getElementById('issueSearch').value);
          renderSentLog();
          btn.disabled = false;
          btn.style.background = ''; btn.style.borderColor = ''; btn.style.color = '';
          document.getElementById('sendSesTxt').textContent = 'Re-Send via AWS';
          document.getElementById('markSentTxt').textContent = '✓ Re-Mark Sent';
          return;
        } else {
          let errMsg;
          if (r.status === 409) {
            errMsg = d.error || 'Email has already been sent for this certificate.';
          } else if (r.status === 503 || d.sesEnabled === false) {
            errMsg = 'Email dispatch (AWS SES) is not configured on this server. Set SES_ACCESS_KEY, SES_SECRET_KEY and SES_REGION in your .env file.';
          } else {
            errMsg = d.error || d.sesError || ('Server error — HTTP ' + r.status);
          }
          resultEl.style.display    = 'block';
          resultEl.style.background = 'rgba(255,107,138,.07)';
          resultEl.style.border     = '1px solid rgba(255,107,138,.2)';
          resultEl.style.color      = 'var(--invalid)';
          resultEl.innerHTML = `<div style="display:flex;align-items:flex-start;gap:8px"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-top:1px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>${errMsg}</span></div>`;
          toast('✗ ' + (d.error || 'Send failed'), 'err');
        }
      } catch (e) {
        resultEl.style.display = 'block';
        resultEl.style.background = 'rgba(255,107,138,.07)';
        resultEl.style.border     = '1px solid rgba(255,107,138,.2)';
        resultEl.style.color      = 'var(--invalid)';
        resultEl.innerHTML = `<div style="display:flex;align-items:flex-start;gap:8px"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-top:1px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>Could not reach the server. Check your network connection and try again.</span></div>`;
        toast('Connection error. Please try again.', 'err');
      }
      btn.disabled = false;
      btn.style.background = ''; btn.style.borderColor = ''; btn.style.color = '';
      document.getElementById('sendSesTxt').textContent = 'Send via AWS SES';
    }

    async function markAsSent() {
      if (!selectedIssueCertId) { toast('Select a certificate first.', 'warn'); return; }
      const recipEmail = (document.getElementById('issueRecipEmail').value || '').trim();
      const btn = document.getElementById('markSentBtn');
      btn.disabled = true;
      document.getElementById('markSentTxt').textContent = 'Saving…';
      try {
        const fd = new FormData();
        fd.append('emailStatus', 'SENT');
        fd.append('emailSentAt', new Date().toISOString());
        if (recipEmail) fd.append('recipientEmail', recipEmail);
        const r = await fetch(API + '/certs/' + encodeURIComponent(selectedIssueCertId), {
          method: 'PUT', headers: { Authorization: 'Bearer ' + TOKEN }, body: fd
        });
        if (!r.ok) { toast('Could not record dispatch status. Please try again.', 'err'); btn.disabled = false; document.getElementById('markSentTxt').textContent = 'Mark as Sent'; return; }
        toast('✓ Marked as sent!', 'ok');
        const c = CERTS.find(x => x.id === selectedIssueCertId);
        if (c) { c.emailStatus = 'SENT'; c.emailSentAt = new Date().toISOString(); if (recipEmail) c.recipientEmail = recipEmail; }
        await refreshStats();
        renderIssueList(document.getElementById('issueSearch').value);
        renderSentLog();
        // Re-enable — keep both options available
        btn.disabled = false;
        btn.style.background = ''; btn.style.borderColor = ''; btn.style.color = '';
        document.getElementById('markSentTxt').textContent = '✓ Re-Mark Sent';
        document.getElementById('sendSesTxt').textContent = 'Re-Send via AWS';
      } catch { toast('Something went wrong. Please try again.', 'err'); btn.disabled = false; document.getElementById('markSentTxt').textContent = 'Mark as Sent'; }
    }

    async function quickSend(id) {
      selectedIssueCertId = id;
      showPage('issue', document.getElementById('nav-issue'));
      await refreshStats();
      renderIssueList('');
      selectIssueCert(id);
    }

    function renderSentLog() {
      const el = document.getElementById('sentLogList');
      const sent = CERTS.filter(c => c.emailStatus === 'SENT').sort((a, b) => new Date(b.emailSentAt) - new Date(a.emailSentAt));
      // Update badge count
      const badge = document.getElementById('sentLogCount');
      if (badge) badge.textContent = sent.length + ' sent';
      if (!sent.length) { el.innerHTML = `<div style="text-align:center;padding:28px;color:var(--text-sec);font-size:.78rem">No credentials dispatched yet</div>`; return; }
      el.innerHTML = sent.map(c => {
        const eng = c.engagement || {};
        const engBadges = [];
        if (eng.emailOpenCount)
          engBadges.push(`<span class="eng-badge eng-open" title="Opened ${eng.emailOpenCount}× · Last: ${fmtDt(eng.emailLastOpenAt)}">📧 ${eng.emailOpenCount}</span>`);
        else
          engBadges.push(`<span class="eng-badge" style="opacity:.35;font-size:.57rem" title="Not yet opened">📧 0</span>`);
        if (eng.certViewCount)
          engBadges.push(`<span class="eng-badge eng-view" title="Viewed ${eng.certViewCount}× · Last: ${fmtDt(eng.certLastViewedAt)}">👁 ${eng.certViewCount}</span>`);
        if (eng.docDownloadCount)
          engBadges.push(`<span class="eng-badge eng-dl" title="Downloaded ${eng.docDownloadCount}×">⬇ ${eng.docDownloadCount}</span>`);
        return `
        <div style="padding:12px 14px;border-radius:10px;background:var(--navy-mid);border:1px solid var(--border);margin-bottom:8px;transition:border-color .15s" onmouseover="this.style.borderColor='var(--border-gold)'" onmouseout="this.style.borderColor='var(--border)'">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">
            <span style="font-family:'JetBrains Mono',monospace;font-size:.68rem;color:var(--gold)">${c.id}</span>
            <div style="display:flex;align-items:center;gap:4px">${engBadges.join('')}</div>
          </div>
          <div style="font-size:.78rem;color:var(--text-bright);font-weight:500">${c.recipientName || '—'}</div>
          <div style="font-size:.64rem;color:var(--text-sec);margin-top:2px">IMO: ${c.vesselIMO || '—'}</div>
          ${c.recipientEmail ? `<div style="font-size:.64rem;color:var(--teal);margin-top:2px;display:flex;align-items:center;gap:4px">
            <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
            ${c.recipientEmail}</div>` : ''}
          <div style="font-size:.6rem;color:var(--text-sec);margin-top:7px;padding-top:7px;border-top:1px solid var(--border);display:flex;align-items:center;gap:6px">
            <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            <span style="color:var(--teal);font-weight:600">Sent</span>
            ${c.emailSentAt ? '· ' + new Date(c.emailSentAt).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) + ' · ' + new Date(c.emailSentAt).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'}) : '—'}
          </div>
        </div>`;
      }).join('');
    }

    // ════════════════════════════════════════════════════
    // MODULE: View / Edit / Delete
    // ════════════════════════════════════════════════════
    // Open certificate directly in a new tab (avoids CSP frame-ancestors block)
    async function viewCertNewTab(id, btn) {
      const orig = btn ? btn.textContent : '';
      if (btn) { btn.textContent = '…'; btn.disabled = true; }
      // Open blank tab synchronously so popup-blocker won't block it
      const tab = window.open('', '_blank');
      if (!tab) { if (btn) { btn.textContent = orig; btn.disabled = false; } return; }
      tab.document.write('<html><head><title>Loading…</title></head><body style="margin:0;background:#0A1628;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:#CCD6F6"><div style="text-align:center"><div style="font-size:1.1rem;margin-bottom:8px">🔒 Generating secure link…</div><div style="font-size:.8rem;opacity:.5">Please wait</div></div></body></html>');
      try {
        const url = await getCertEncryptedUrl(id);
        tab.location.href = url;
      } catch(e) {
        const base = (window.APP_CONFIG ? window.APP_CONFIG.routes.cst : '/CST');
        tab.location.href = window.location.origin + base + '/cert/' + encodeURIComponent(id);
      }
      if (btn) { btn.textContent = orig; btn.disabled = false; }
    }

    function viewCert(id) {
      const c = CERTS.find(x => x.id === id); if (!c) return;
      const now = new Date(), vu = c.validUntil ? new Date(c.validUntil) : null;
      const isV = c.status === 'VALID' && (!vu || vu >= now);
      const isPending = (c.status || '').toUpperCase() === 'PENDING';
      const statusColor = isV ? 'var(--teal)' : isPending ? '#7EB8F7' : 'var(--invalid)';
      const statusBg = isV ? 'rgba(100,255,218,.08)' : isPending ? 'rgba(126,184,247,.08)' : 'rgba(255,107,138,.08)';
      const statusBorder = isV ? 'rgba(100,255,218,.25)' : isPending ? 'rgba(126,184,247,.25)' : 'rgba(255,107,138,.25)';
      const dl = vu ? Math.round((vu.setHours(0,0,0,0) - now.setHours(0,0,0,0)) / 86400000) : null;
      let dlText = '';
      if (dl !== null) { if (dl > 0) dlText = `${dl} days remaining`; else if (dl === 0) dlText = 'Expires today'; else dlText = `Expired ${Math.abs(dl)} days ago`; }
      // URL will be loaded async after modal renders (avoids broken inline onerror HTML)
      const publicUrl = (window.APP_CONFIG ? window.APP_CONFIG.routes.cst : '/CST') + '/cert/' + encodeURIComponent(c.id); // placeholder — replaced async below

      document.getElementById('viewBody').innerHTML = `
        <!-- Status Banner -->
        <div style="background:${statusBg};border:1px solid ${statusBorder};border-radius:12px;padding:14px 18px;margin-bottom:18px;display:flex;align-items:center;gap:14px">
          <div style="width:36px;height:36px;border-radius:50%;background:${statusBg};border:1.5px solid ${statusBorder};display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${statusColor}" stroke-width="2">
              ${isV ? '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>' : isPending ? '<circle cx="12" cy="12" r="10"/><path stroke-linecap="round" d="M12 6v6l4 2"/>' : '<path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/>'}
            </svg>
          </div>
          <div style="flex:1">
            <div style="font-size:.72rem;font-weight:700;color:${statusColor};letter-spacing:.08em;text-transform:uppercase">${isV ? 'Valid & Active' : isPending ? 'Pending Activation' : c.status}</div>
            <div style="font-size:.7rem;color:var(--text-sec);margin-top:2px">${dlText || (isPending ? 'Not yet assigned a validity window' : 'No expiry date set')}</div>
          </div>
          <span style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--gold);background:var(--gold-dim);border:1px solid var(--border-gold);padding:4px 10px;border-radius:20px">${c.id}</span>
        </div>

        <!-- Recipient Hero Block -->
        <div style="background:linear-gradient(135deg,rgba(212,168,67,.06),rgba(10,22,40,.4));border:1px solid var(--border-gold);border-radius:12px;padding:16px 20px;margin-bottom:18px;text-align:center">
          <div style="font-size:.52rem;letter-spacing:.22em;color:var(--text-sec);text-transform:uppercase;margin-bottom:6px">Certificate Awarded To</div>
          <div style="font-family:'Playfair Display',serif;font-size:1.25rem;font-weight:800;color:var(--text-bright);margin-bottom:4px">${c.recipientName || '—'}</div>
          ${c.vesselName ? `<div style="font-size:.72rem;color:var(--gold)">Vessel: ${c.vesselName}${c.vesselIMO ? ' &nbsp;·&nbsp; IMO ' + c.vesselIMO : ''}</div>` : ''}
        </div>

        <!-- Two Column Info Grid -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:18px">
          ${[
            ['Training Program', c.trainingTitle || '—', false],
            ['Organizer', c.organizer || '—', false],
            ['Chief Engineer', c.chiefEngineer || '—', false],
            ['Training Mode', c.trainingMode || '—', false],
            ['Compliance Date', fmt(c.complianceDate), false],
            ['Compliance Quarter', c.complianceQuarter || '—', false],
            ['Valid For Period', c.validFor || (isPending ? '— (Pending)' : '—'), false],
            ['Valid Until', c.validUntil ? fmt(c.validUntil) : (isPending ? 'Not assigned' : '—'), false],
            ['Issued Date', fmt(c.issuedAt), false],
            ['Email Status', (c.emailStatus || 'NOT_SENT'), false],
          ].map(([lbl, val, mono]) => `
            <div style="background:var(--navy-mid);border:1px solid var(--border);border-radius:9px;padding:10px 14px">
              <div style="font-size:.5rem;letter-spacing:.16em;color:var(--text-sec);text-transform:uppercase;margin-bottom:4px">${lbl}</div>
              <div style="font-size:.8rem;color:var(--text-bright);font-weight:500;font-family:${mono ? 'JetBrains Mono,monospace' : 'inherit'};word-break:break-word">${val}</div>
            </div>`).join('')}
        </div>

        <!-- Verified By - full width -->
        <div style="background:var(--navy-mid);border:1px solid var(--border-gold);border-radius:9px;padding:10px 14px;margin-bottom:18px">
          <div style="font-size:.5rem;letter-spacing:.16em;color:var(--gold);text-transform:uppercase;margin-bottom:4px">Verified By</div>
          <div style="font-size:.8rem;color:var(--text-bright);font-weight:500">${c.verifiedBy || '—'}</div>
        </div>

        ${c.recipientEmail ? `
        <div style="background:var(--navy-mid);border:1px solid var(--border);border-radius:9px;padding:10px 14px;margin-bottom:18px;display:flex;align-items:center;gap:10px">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
          <div style="flex:1">
            <div style="font-size:.5rem;letter-spacing:.15em;color:var(--text-sec);text-transform:uppercase;margin-bottom:2px">Recipient Email</div>
            <div style="font-size:.78rem;font-family:'JetBrains Mono',monospace;color:var(--teal)">${c.recipientEmail}</div>
          </div>
          <span style="font-size:.58rem;font-weight:700;padding:3px 8px;border-radius:8px;background:${c.emailStatus==='SENT'?'rgba(100,255,218,.1)':'rgba(255,107,138,.08)'};color:${c.emailStatus==='SENT'?'var(--teal)':'var(--invalid)'};border:1px solid ${c.emailStatus==='SENT'?'rgba(100,255,218,.25)':'rgba(255,107,138,.2)'}">${c.emailStatus==='SENT'?'✓ Sent':'Pending'}</span>
        </div>` : ''}

        <!-- Unique Verification URL -->
        <div style="background:rgba(100,255,218,.04);border:1px solid rgba(100,255,218,.18);border-radius:10px;padding:12px 16px;margin-bottom:${c.certificateImage ? '18px' : '4px'}">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <div style="font-size:.5rem;letter-spacing:.16em;color:var(--teal);text-transform:uppercase;display:flex;align-items:center;gap:6px">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
              Unique Verification URL
            </div>
            <button id="viewCopyUrlBtn" onclick="copyViewUrl(this)" style="background:var(--gold-dim);border:1px solid var(--border-gold);color:var(--gold);border-radius:7px;padding:4px 12px;font-size:.6rem;cursor:pointer;font-family:'DM Sans',sans-serif;font-weight:600;letter-spacing:.08em;transition:background .15s">⎘ Copy Link</button>
          </div>
          <div id="viewPublicUrl" style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--text);word-break:break-all;background:var(--navy);border:1px solid var(--border);border-radius:7px;padding:8px 12px;user-select:all">${publicUrl}</div>
          <div style="margin-top:8px;font-size:.62rem;color:var(--text-sec)">Share this URL with recipients, auditors, or inspectors for instant certificate verification.</div>
        </div>

        ${c.certificateImage ? `<div style="margin-top:2px;text-align:center" id="viewImgWrap">
          <div style="font-size:.55rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:8px">Certificate Document</div>
          <img id="viewCertImg" src="${imgUrl(c.certificateImage)}" style="max-height:220px;border-radius:10px;border:1px solid var(--border-gold);cursor:zoom-in;box-shadow:0 8px 32px rgba(0,0,0,.3)" loading="lazy" onclick="openLB(this.src)" />
        </div>` : ''}

        ${false ? `
        <div style="display:none">
          <div></div>
          <div>
            ${(c.attachments||[]).map((a, i) => {
              const uL = (a.url || '').toLowerCase(), nL = (a.name || '').toLowerCase();
              const isPdf = uL.endsWith('.pdf') || nL.endsWith('.pdf');
              const isImg = /\.(jpg|jpeg|png|webp|gif)$/.test(uL) || /\.(jpg|jpeg|png|webp|gif)$/.test(nL);
              const ext = (a.name || '').split('.').pop().toUpperCase() || 'FILE';
              const dn = a.name || ('Document ' + (i + 1));
              const safeUrl = (a.url || '').replace(/'/g, "\\'");
              const safeName = dn.replace(/'/g, "\\'");
              if (isPdf) {
                return `<div style="border:1px solid var(--border);border-radius:8px;overflow:hidden;background:var(--navy-mid);display:flex;align-items:stretch">
                  <button onclick="event.preventDefault();event.stopPropagation();window.open('${safeUrl}','_blank')" style="display:flex;align-items:center;gap:8px;padding:8px 12px;flex:1;text-align:left;background:transparent;border:none;border-radius:8px 0 0 8px;color:var(--gold);font-size:.76rem;cursor:pointer">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                    <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${dn}</span>
                    <span style="font-size:.6rem;color:var(--gold);letter-spacing:.06em">${ext}</span>
                    <span style="font-size:.6rem;color:var(--teal);font-weight:600">👁 View</span>
                  </button>
                  <a href="${safeUrl}" download="${safeName}" onclick="event.stopPropagation()" title="Download" style="display:flex;align-items:center;justify-content:center;padding:0 12px;background:rgba(100,255,218,.05);border-left:1px solid rgba(100,255,218,.12);border-radius:0 8px 8px 0;color:var(--teal);text-decoration:none;transition:background .18s;flex-shrink:0" onmouseover="this.style.background='rgba(100,255,218,.13)'" onmouseout="this.style.background='rgba(100,255,218,.05)'">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                  </a>
                </div>`;
              } else if (isImg) {
                return `<div>
                  <button onclick="openLB('${safeUrl}')" style="display:flex;align-items:center;gap:8px;padding:8px 12px;border:1px solid var(--border);border-radius:8px 8px 0 0;background:var(--navy-mid);color:var(--teal);font-size:.76rem;cursor:pointer;text-align:left;width:100%;border-bottom:none">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                    <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${dn}</span>
                    <span style="font-size:.6rem;color:var(--text-sec);letter-spacing:.06em">${ext}</span>
                    <span style="font-size:.6rem;color:var(--teal);font-weight:600">🔍 Zoom</span>
                  </button>
                  <img src="${a.url}" onclick="openLB('${safeUrl}')" style="width:100%;max-height:140px;object-fit:cover;cursor:zoom-in;border:1px solid var(--border);border-radius:0 0 8px 8px;display:block" />
                </div>`;
              } else {
                return `<a href="${a.url}" target="_blank" download="${dn}" style="display:flex;align-items:center;gap:8px;padding:8px 12px;border:1px solid var(--border);border-radius:8px;background:var(--navy-mid);color:var(--gold);font-size:.76rem;text-decoration:none">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                  <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${dn}</span>
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="opacity:.5"><path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
                </a>`;
              }
            }).join('')}
          </div>
        </div>` : ''}

        <!-- ── Engagement / Activity Log ── -->
        ${(function() {
          const eng = c.engagement || {};
          const hasAnyEngagement = eng.emailOpenedAt || eng.certFirstViewedAt || eng.docFirstDownloadAt;
          const emailSent        = c.emailStatus === 'SENT';

          // Build rich event entries
          const events = [];
          if (c.emailSentAt)
            events.push({ ts: c.emailSentAt, icon: '📤', label: 'Email dispatched', color: 'var(--text-sec)',
              sub: c.recipientEmail ? 'To: ' + c.recipientEmail : null });
          if (eng.emailOpenedAt)
            events.push({ ts: eng.emailOpenedAt, icon: '📧', label: 'Email opened',
              sub: eng.emailOpenCount > 1 ? `${eng.emailOpenCount} times · most recently ${fmtDt(eng.emailLastOpenAt)}` : 'Once',
              color: '#4A9EFF', count: eng.emailOpenCount });
          if (eng.certFirstViewedAt)
            events.push({ ts: eng.certFirstViewedAt, icon: '👁', label: 'Certificate viewed',
              sub: eng.certViewCount > 1 ? `${eng.certViewCount} times · last: ${fmtDt(eng.certLastViewedAt)}` : 'Once',
              color: 'var(--teal)', count: eng.certViewCount });
          if (eng.docFirstDownloadAt)
            events.push({ ts: eng.docFirstDownloadAt, icon: '⬇', label: 'Document downloaded',
              sub: (eng.docDownloadCount > 1 ? eng.docDownloadCount + ' times · ' : '') + (eng.docLastFile || ''),
              color: 'var(--gold)', count: eng.docDownloadCount });

          events.sort((a, b) => a.ts < b.ts ? -1 : 1);

          // Always render the wrapper so async live-refresh can find it
          // Engagement summary chips
          const chips = [];
          if (eng.emailOpenCount)    chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(74,158,255,.12);border:1px solid rgba(74,158,255,.3);color:#4A9EFF;font-size:.58rem;font-weight:700">📧 ${eng.emailOpenCount} open${eng.emailOpenCount>1?'s':''}</span>`);
          if (eng.certViewCount)     chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(100,255,218,.10);border:1px solid rgba(100,255,218,.3);color:var(--teal);font-size:.58rem;font-weight:700">👁 ${eng.certViewCount} view${eng.certViewCount>1?'s':''}</span>`);
          if (eng.docDownloadCount)  chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(212,168,67,.10);border:1px solid rgba(212,168,67,.3);color:var(--gold);font-size:.58rem;font-weight:700">⬇ ${eng.docDownloadCount} download${eng.docDownloadCount>1?'s':''}</span>`);
          if (!hasAnyEngagement && emailSent)
            chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(255,179,71,.07);border:1px solid rgba(255,179,71,.2);color:var(--warn);font-size:.58rem">⏳ Awaiting recipient</span>`);

          return `
        <div id="viewEngagementSection" data-certid="${c.id}" style="margin-top:16px;border-top:1px solid var(--border);padding-top:16px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px">
            <div style="font-size:.58rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;display:flex;align-items:center;gap:6px;font-weight:600">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              Recipient Activity
            </div>
            ${chips.length ? `<div style="display:flex;flex-wrap:wrap;gap:4px">${chips.join('')}</div>` : ''}
          </div>
          ${events.length === 0
            ? `<div style="font-size:.72rem;color:var(--text-sec);font-style:italic;padding:6px 0">No recipient activity recorded yet.</div>`
            : `<div style="position:relative;padding-left:22px">
                <div style="position:absolute;left:7px;top:6px;bottom:6px;width:1px;background:linear-gradient(to bottom,var(--border),transparent)"></div>
                ${events.map((ev, i) => `
                <div style="position:relative;margin-bottom:${i < events.length-1 ? '13px' : '0'}">
                  <div style="position:absolute;left:-18px;top:3px;width:8px;height:8px;border-radius:50%;background:${ev.color};box-shadow:0 0 6px ${ev.color}55;border:1.5px solid var(--bg)"></div>
                  <div style="display:flex;align-items:center;gap:6px">
                    <span style="font-size:.72rem;color:${ev.color};font-weight:700">${ev.icon} ${ev.label}</span>
                    ${ev.count > 1 ? `<span style="padding:1px 6px;border-radius:10px;background:${ev.color}20;color:${ev.color};font-size:.56rem;font-weight:700">×${ev.count}</span>` : ''}
                  </div>
                  <div style="font-size:.63rem;color:var(--text-sec);margin-top:2px">${fmtDt(ev.ts)}${ev.sub ? ' · ' + ev.sub : ''}</div>
                </div>`).join('')}
              </div>`
          }
        </div>`;
        })()}
      `;
      const viewFoot = document.querySelector('#viewMod .modal-foot');
      // Remove any previous activate btn
      const prevAct = viewFoot && viewFoot.querySelector('#viewActivateBtn');
      if (prevAct) prevAct.remove();
      if (isPending && viewFoot) {
        const actBtn = document.createElement('button');
        actBtn.id = 'viewActivateBtn';
        actBtn.className = 'btn';
        actBtn.style.cssText = 'background:rgba(100,255,218,.1);border:1px solid rgba(100,255,218,.3);color:var(--teal);display:flex;align-items:center;gap:7px;';
        actBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg> Activate Certificate';
        actBtn.onclick = () => { closeView(); activateCert(c.id); };
        viewFoot.prepend(actBtn);
      }

      document.getElementById('viewMod').style.display = 'flex';

      // ── Async: refresh engagement data live when modal opens ──
      (async function loadViewEngagement(certId) {
        try {
          const r = await fetch(API + '/certs/' + encodeURIComponent(certId) + '/engagement', {
            headers: { Authorization: 'Bearer ' + TOKEN }
          });
          if (!r.ok) return;
          const { engagement } = await r.json();
          // Update cached cert
          const cached = CERTS.find(x => x.id === certId);
          if (cached) cached.engagement = engagement;
          // Guard: only update if this modal is still showing the same cert (race-condition fix)
          const actDiv = document.getElementById('viewEngagementSection');
          if (!actDiv || actDiv.dataset.certid !== certId) return;
          const eng = engagement || {};
          const hasAnyEngagement = eng.emailOpenedAt || eng.certFirstViewedAt || eng.docFirstDownloadAt;
          const emailSent = cached ? cached.emailStatus === 'SENT' : false;
          const events = [];
          const cachedC = cached || {};
          if (cachedC.emailSentAt)
            events.push({ ts: cachedC.emailSentAt, icon: '📤', label: 'Email dispatched', color: 'var(--text-sec)', sub: cachedC.recipientEmail ? 'To: ' + cachedC.recipientEmail : null });
          if (eng.emailOpenedAt)
            events.push({ ts: eng.emailOpenedAt, icon: '📧', label: 'Email opened', sub: eng.emailOpenCount > 1 ? eng.emailOpenCount + ' times · most recently ' + fmtDt(eng.emailLastOpenAt) : 'Once', color: '#4A9EFF', count: eng.emailOpenCount });
          if (eng.certFirstViewedAt)
            events.push({ ts: eng.certFirstViewedAt, icon: '👁', label: 'Certificate viewed', sub: eng.certViewCount > 1 ? eng.certViewCount + ' times · last: ' + fmtDt(eng.certLastViewedAt) : 'Once', color: 'var(--teal)', count: eng.certViewCount });
          if (eng.docFirstDownloadAt)
            events.push({ ts: eng.docFirstDownloadAt, icon: '⬇', label: 'Document downloaded', sub: (eng.docDownloadCount > 1 ? eng.docDownloadCount + ' times · ' : '') + (eng.docLastFile || ''), color: 'var(--gold)', count: eng.docDownloadCount });
          events.sort((a, b) => a.ts < b.ts ? -1 : 1);
          const chips = [];
          if (eng.emailOpenCount)   chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(74,158,255,.12);border:1px solid rgba(74,158,255,.3);color:#4A9EFF;font-size:.58rem;font-weight:700">📧 ${eng.emailOpenCount} open${eng.emailOpenCount>1?'s':''}</span>`);
          if (eng.certViewCount)    chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(100,255,218,.10);border:1px solid rgba(100,255,218,.3);color:var(--teal);font-size:.58rem;font-weight:700">👁 ${eng.certViewCount} view${eng.certViewCount>1?'s':''}</span>`);
          if (eng.docDownloadCount) chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(212,168,67,.10);border:1px solid rgba(212,168,67,.3);color:var(--gold);font-size:.58rem;font-weight:700">⬇ ${eng.docDownloadCount} download${eng.docDownloadCount>1?'s':''}</span>`);
          if (!hasAnyEngagement && emailSent)
            chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(255,179,71,.07);border:1px solid rgba(255,179,71,.2);color:var(--warn);font-size:.58rem">⏳ Awaiting recipient</span>`);
          actDiv.innerHTML = `
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px">
                <div style="font-size:.58rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;display:flex;align-items:center;gap:6px;font-weight:600">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                  Recipient Activity
                </div>
                ${chips.length ? '<div style="display:flex;flex-wrap:wrap;gap:4px">'+chips.join('')+'</div>' : ''}
              </div>
              ${events.length === 0
                ? '<div style="font-size:.72rem;color:var(--text-sec);font-style:italic;padding:6px 0">No recipient activity recorded yet.</div>'
                : '<div style="position:relative;padding-left:22px">'
                  + '<div style="position:absolute;left:7px;top:6px;bottom:6px;width:1px;background:linear-gradient(to bottom,var(--border),transparent)"></div>'
                  + events.map((ev, i) =>
                    '<div style="position:relative;margin-bottom:' + (i < events.length-1 ? '13px' : '0') + '">'
                    + '<div style="position:absolute;left:-18px;top:3px;width:8px;height:8px;border-radius:50%;background:' + ev.color + ';box-shadow:0 0 6px ' + ev.color + '55;border:1.5px solid var(--bg)"></div>'
                    + '<div style="display:flex;align-items:center;gap:6px">'
                    + '<span style="font-size:.72rem;color:' + ev.color + ';font-weight:700">' + ev.icon + ' ' + ev.label + '</span>'
                    + (ev.count > 1 ? '<span style="padding:1px 6px;border-radius:10px;background:' + ev.color + '20;color:' + ev.color + ';font-size:.56rem;font-weight:700">×' + ev.count + '</span>' : '')
                    + '</div>'
                    + '<div style="font-size:.63rem;color:var(--text-sec);margin-top:2px">' + fmtDt(ev.ts) + (ev.sub ? ' · ' + ev.sub : '') + '</div>'
                    + '</div>'
                  ).join('')
                  + '</div>'
              }`;
        } catch(e) { /* silent — stale data from cache is fine */ }
      })(id);

      // ── Async: attach image error handler (safe, no inline HTML injection) ──
      const viewImg = document.getElementById('viewCertImg');
      if (viewImg) {
        viewImg.addEventListener('error', function onImgError() {
          viewImg.removeEventListener('error', onImgError);
          const wrap = document.getElementById('viewImgWrap');
          if (wrap) {
            wrap.innerHTML =
              '<div style="padding:14px 18px;background:rgba(255,179,71,.06);border:1px dashed rgba(255,179,71,.3);' +
              'border-radius:10px;text-align:center;color:var(--warn);font-size:.78rem">' +
              '⚠ Certificate image could not be loaded.<br>' +
              '<span style="font-size:.68rem;color:var(--text-sec)">Ensure the server is running and the image file exists.</span></div>';
          }
        });
      }

      // ── Async: fetch encrypted URL and update URL display ──
      (async function loadViewUrl(certId) {
        const urlEl  = document.getElementById('viewPublicUrl');
        const copyEl = document.getElementById('viewCopyUrlBtn');
        if (!urlEl) return;
        urlEl.style.color = 'var(--text-sec)';
        urlEl.textContent = 'Generating secure link…';
        const url = await getCertEncryptedUrl(certId);
        urlEl.textContent = url;
        urlEl.style.color = '';
        // Store URL on copy button for copyViewUrl()
        if (copyEl) copyEl.dataset.url = url;
      })(c.id);
    }

    function copyViewUrl(btn) {
      const url = btn.dataset.url || document.getElementById('viewPublicUrl').textContent;
      if (!url || url === 'Generating secure link…') { return; }
      navigator.clipboard.writeText(url).catch(() => {});
      const orig = btn.textContent; btn.textContent = '✓ Copied!';
      setTimeout(() => { btn.textContent = orig; }, 2000);
    }

    function openViewInTab() {
      const urlEl = document.getElementById('viewPublicUrl');
      const url = (urlEl && urlEl.textContent && urlEl.textContent !== 'Generating secure link…') ? urlEl.textContent : null;
      if (url) { window.open(url, '_blank'); }
    }
    function closeView() { document.getElementById('viewMod').style.display = 'none'; }

    function editCert(id) {
      const c = CERTS.find(x => x.id === id); if (!c) return;
      editingId = id;
      document.getElementById('fId').value = c.id || '';
      document.getElementById('fRecip').value = c.recipientName || '';
      document.getElementById('fVesselName').value = c.vesselName || '';
      document.getElementById('fIMO').value = c.vesselIMO || '';
      document.getElementById('fEng').value = c.chiefEngineer || '';
      document.getElementById('fTitle').value = c.trainingTitle || '';
      document.getElementById('fOrg').value = c.organizer || '';
      document.getElementById('fMode').value = c.trainingMode || 'ONLINE';
      document.getElementById('fCompDate').value = c.complianceDate ? c.complianceDate.slice(0, 10) : '';
      document.getElementById('fQuarter').value = c.complianceQuarter || 'Q1';
      document.getElementById('fValidFor').value = c.validFor || '';
      document.getElementById('fUntil').value = c.validUntil ? c.validUntil.slice(0, 10) : '';
      document.getElementById('fIssued').value = c.issuedAt ? c.issuedAt.slice(0, 10) : '';
      // Allow any date in edit mode
      document.getElementById('fIssued').removeAttribute('min');
      document.getElementById('fVerifier').value = c.verifiedBy || '';
      document.getElementById('fNotes').value = c.notes || '';
      document.getElementById('fStatus').value = c.status || 'VALID';
      if (document.getElementById('fEmail')) document.getElementById('fEmail').value = c.recipientEmail || '';
      document.getElementById('formHead').textContent = 'Edit Certificate';
      document.getElementById('saveTxt').textContent = 'Update Certificate';
      if (c.certificateImage) {
        document.getElementById('prevImg').src = imgUrl(c.certificateImage);
        document.getElementById('uploadDefault').style.display = 'none';
        document.getElementById('uploadPrev').style.display = 'block';
        document.getElementById('prevName').textContent = 'Existing image';
        const tag = document.getElementById('imgRequiredTag');
        if (tag) { tag.style.background = 'rgba(100,255,218,.08)'; tag.style.color = 'var(--teal)'; tag.style.borderColor = 'rgba(100,255,218,.2)'; tag.textContent = '✓ Attached'; }
      }
      // Load existing attachments
      pendingPdfs = []; savedAttachments = Array.isArray(c.attachments) ? c.attachments : []; renderAttachList();
      document.getElementById('dupHint').textContent = ''; document.getElementById('fId').classList.remove('duplicate-warn', 'duplicate-ok');
      // Re-enable status select for editing
      document.getElementById('fStatus').disabled = false;
      document.getElementById('fStatus').style.opacity = '';
      livePreview();
      updateCompletionChecklistFull();
      showPage('add', document.getElementById('nav-add'));
    }

    async function saveCert() {
      const id = document.getElementById('fId').value.trim().toUpperCase();
      const recip = document.getElementById('fRecip').value.trim();
      if (!id || !recip) { toast('Certificate ID and Recipient are required.', 'err'); return; }
      const fd = new FormData();
      const fields = { id, recipientName: recip, recipientEmail: (document.getElementById('fEmail') ? document.getElementById('fEmail').value.trim() : ''), vesselName: document.getElementById('fVesselName').value, vesselIMO: document.getElementById('fIMO').value, chiefEngineer: document.getElementById('fEng').value, trainingTitle: document.getElementById('fTitle').value, organizer: document.getElementById('fOrg').value, trainingMode: document.getElementById('fMode').value, complianceDate: document.getElementById('fCompDate').value, complianceQuarter: document.getElementById('fQuarter').value, validFor: document.getElementById('fValidFor').value, validUntil: document.getElementById('fUntil').value, issuedAt: document.getElementById('fIssued').value, verifiedBy: document.getElementById('fVerifier').value, notes: document.getElementById('fNotes').value, status: document.getElementById('fStatus').value };
      Object.entries(fields).forEach(([k, v]) => fd.append(k, v));
      if (imgFile) fd.append('certificateImage', imgFile);
      // Existing attachments (tell server which ones to keep)
      fd.append('attachments', JSON.stringify(savedAttachments));
      // New PDF files
      pendingPdfs.forEach((p, i) => fd.append(`attachment${i}`, p.file, p.name));
      try {
        const url = editingId ? API + '/certs/' + encodeURIComponent(editingId) : API + '/certs';
        const mth = editingId ? 'PUT' : 'POST';
        const r = await fetch(url, { method: mth, headers: { Authorization: 'Bearer ' + TOKEN }, body: fd });
        if (!r.ok) { let msg = 'Could not save certificate. Please try again.'; try { const e = await r.json(); msg = e.error || msg; } catch {} toast(msg, 'err'); return; }
        const saved = await r.json();
        savedAttachments = Array.isArray(saved.attachments) ? saved.attachments : [];
        pendingPdfs = [];
        renderAttachList();
        toast(editingId ? 'Certificate updated!' : 'Certificate added!', 'ok');
        editingId = null; imgFile = null; resetForm();
        await refreshStats();
        showPage('certs', document.getElementById('nav-certs'));
      } catch (e) { toast(e.message || 'Something went wrong. Please try again.', 'err'); }
    }

    function resetForm() {
      ['fId', 'fRecip', 'fVesselName', 'fIMO', 'fEng', 'fCompDate', 'fEmail'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
      document.getElementById('fTitle').value = (window.APP_CONFIG?window.APP_CONFIG.cst.trainingTitle:'Cyber Security Threat Awareness Training');
      document.getElementById('fOrg').value = (window.APP_CONFIG?window.APP_CONFIG.cst.organizer:'Synergy Cyber Security Team');
      document.getElementById('fVerifier').value = (window.APP_CONFIG?window.APP_CONFIG.cst.verifiedBy:'Gaurav Singh, CISO - Chief Information Security Officer, Synergy Marine Group');
      document.getElementById('fNotes').value = (window.APP_CONFIG?window.APP_CONFIG.cst.notes:'Training conducted under supervision of ISO Lead Auditor and Security trainers');
      document.getElementById('fMode').value = 'ONLINE';
      document.getElementById('fStatus').value = 'VALID';
      onStatusChange();
      document.getElementById('fQuarter').value = 'Q1';
      document.getElementById('fIssued').value = new Date().toISOString().slice(0, 10);
      document.getElementById('fIssued').removeAttribute('min');
      onQuarterChange();
      document.getElementById('dupHint').textContent = ''; document.getElementById('fId').classList.remove('duplicate-warn', 'duplicate-ok');
      clearImgSilent();
      editingId = null; imgFile = null;
      pendingPdfs = []; savedAttachments = []; renderAttachList();
      document.getElementById('formHead').textContent = 'Add New Certificate';
      document.getElementById('saveTxt').textContent = 'Save Certificate';
      livePreview();
      updateCompletionChecklistFull();
    }

    function openDocLibraryForVessel() {
      const imo = (document.getElementById('fIMO') || {}).value || '';
      const vessel = (document.getElementById('fVesselName') || {}).value || '';
      const base = (window.APP_CONFIG && window.APP_CONFIG.routes && window.APP_CONFIG.routes.cstAdmin) || '/CST/misecure';
      let url = base + '/documents/';
      if (imo) url += '?imo=' + encodeURIComponent(imo.trim().toUpperCase()) + '&vessel=' + encodeURIComponent(vessel.trim());
      window.open(url, '_blank');
    }

    function askDelete(id) { deleteId = id; document.getElementById('delId').textContent = id; document.getElementById('delMod').style.display = 'flex'; }
    function closeDel() { document.getElementById('delMod').style.display = 'none'; deleteId = null; }
    async function doDelete() {
      try {
        const r = await fetch(API + '/certs/' + encodeURIComponent(deleteId), { method: 'DELETE', headers: { Authorization: 'Bearer ' + TOKEN } });
        if (!r.ok) { toast('Could not delete certificate. Please try again.', 'err'); return; }
        closeDel(); await refreshStats(); renderTbl('dashTbl', ''); renderTbl('allTbl', '');
        toast('Certificate removed successfully.', 'ok');
      } catch { toast('Something went wrong. Please try again.', 'err'); }
    }

    // ════════════════════════════════════════════════════
    // MODULE: Image upload
    // ════════════════════════════════════════════════════
    function onFileSelect(input) {
      const file = input.files[0]; if (!file) return;
      if (file.size > 5 * 1024 * 1024) { toast('File exceeds the 5 MB limit. Please choose a smaller file.', 'err'); return; }
      imgFile = file;
      const r = new FileReader();
      r.onload = e => {
        document.getElementById('prevImg').src = e.target.result;
        document.getElementById('uploadDefault').style.display = 'none';
        document.getElementById('uploadPrev').style.display = 'block';
        document.getElementById('prevName').textContent = file.name + ' (' + Math.round(file.size / 1024) + ' KB)';
        const tag = document.getElementById('imgRequiredTag');
        if (tag) { tag.style.background = 'rgba(100,255,218,.08)'; tag.style.color = 'var(--teal)'; tag.style.borderColor = 'rgba(100,255,218,.2)'; tag.textContent = '✓ Attached'; }
        updateCompletionChecklistFull();
      };
      r.readAsDataURL(file);
    }
    function onDragOver(e) { e.preventDefault(); document.getElementById('dropZone').classList.add('drag-over'); }
    function onDragLeave() { document.getElementById('dropZone').classList.remove('drag-over'); }
    function onDrop(e) { e.preventDefault(); document.getElementById('dropZone').classList.remove('drag-over'); const f = e.dataTransfer.files[0]; if (f && f.type.startsWith('image/')) onFileSelect({ files: [f] }); }
    function clearImg(e) { e.stopPropagation(); clearImgSilent(); }
    // ── PDF / DOCUMENT ATTACHMENTS ──
    function _he(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
    function renderAttachList() {
      const el = document.getElementById('attachList');
      if (!el) return;
      const all = [
        ...savedAttachments.map((a, i) => ({ ...a, saved: true, idx: i })),
        ...pendingPdfs.map((p, i) => ({ name: p.name, pending: true, idx: i }))
      ];
      if (!all.length) {
        el.innerHTML = '<div style="font-size:.72rem;color:var(--text-sec);padding:6px 2px">No documents attached. Click "+ Attach" to add PDF, Word or Excel files.</div>';
        return;
      }
      el.innerHTML = all.map(a => {
        const fn = (a.name || '').toLowerCase();
        const icon = fn.endsWith('.pdf') ? '📋' : (fn.endsWith('.xls') || fn.endsWith('.xlsx')) ? '📊' : (fn.endsWith('.doc') || fn.endsWith('.docx')) ? '📝' : '📄';
        const badge = a.pending ? '<span style="font-size:.56rem;background:rgba(255,179,71,.09);color:var(--gold);border:1px solid rgba(255,179,71,.2);padding:1px 5px;border-radius:4px;margin-left:5px">pending</span>' : '';
        const openBtn = (!a.pending && a.url) ? `<a href="${_he(a.url)}" target="_blank" style="font-size:.62rem;color:var(--teal);padding:3px 8px;border-radius:5px;background:rgba(100,255,218,.07);border:1px solid rgba(100,255,218,.2);text-decoration:none">Open</a>` : '';
        const rmBtn = a.saved
          ? `<button type="button" onclick="removeSavedAttach(${a.idx})" style="font-size:.6rem;color:var(--invalid);padding:3px 8px;border-radius:5px;border:1px solid rgba(255,107,138,.18);background:rgba(255,107,138,.05);cursor:pointer;font-family:'DM Sans',sans-serif">Remove</button>`
          : `<button type="button" onclick="removePendingAttach(${a.idx})" style="font-size:.6rem;color:var(--invalid);padding:3px 8px;border-radius:5px;border:1px solid rgba(255,107,138,.18);background:rgba(255,107,138,.05);cursor:pointer;font-family:'DM Sans',sans-serif">Remove</button>`;
        return `<div style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:.88rem;flex-shrink:0">${icon}</span>
          <span style="flex:1;font-size:.73rem;color:var(--text-bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_he(a.name || 'Document')}${badge}</span>
          <div style="display:flex;gap:5px;flex-shrink:0">${openBtn}${rmBtn}</div>
        </div>`;
      }).join('');
    }
    function pdfFileSelect(input) {
      if (!input || !input.files || !input.files.length) return;
      Array.from(input.files).forEach(f => {
        if (f.size > 20 * 1024 * 1024) { toast('File "' + f.name + '" exceeds 20 MB.', 'err'); return; }
        pendingPdfs.push({ file: f, name: f.name });
      });
      input.value = '';
      renderAttachList();
    }
    function removeSavedAttach(idx) { savedAttachments.splice(idx, 1); renderAttachList(); }
    function removePendingAttach(idx) { pendingPdfs.splice(idx, 1); renderAttachList(); }
    function pdfDragOver(e) { e.preventDefault(); }
    function pdfDragLeave() {}
    function pdfDrop(e) { e.preventDefault(); }
    function removePendingPdf() {}
    async function removeServerAttachment() {}

    function clearImgSilent() {
      imgFile = null;
      document.getElementById('prevImg').src = '';
      document.getElementById('uploadDefault').style.display = 'block';
      document.getElementById('uploadPrev').style.display = 'none';
      const tag = document.getElementById('imgRequiredTag');
      if (tag) { tag.style.background = 'rgba(255,107,138,.06)'; tag.style.color = 'var(--invalid)'; tag.style.borderColor = 'rgba(255,107,138,.15)'; tag.textContent = 'Required'; }
      updateCompletionChecklistFull();
    }

    // ════════════════════════════════════════════════════
    // ════════════════════════════════════════════════════
    // MODULE: CSV IMPORT  (v2 — flexible column mapping)
    // ════════════════════════════════════════════════════
    let csvParsedRows   = [];
    let csvRawHeaders   = [];   // original headers from file
    let csvColMap       = {};   // { logicalField: detectedColumnIndex }

    // ── Canonical field aliases (lower-cased, trimmed) ──
    const CSV_FIELD_ALIASES = {
      vesselIMO:      ['imo number','imo_number','imo no','imo','vessel imo','vessel_imo','imonumber'],
      complianceDate: ['issues_dates','issue date','issue_date','compliance date','compliance_date','issueddate','issued date','issued_date','training date','date'],
      chiefEngineer:  ['chif name','chief name','chief_engineer','chief engineer','chief eng','chiefofficer','chief','ce name','master'],
      recipientName:  ['vessel_name','vessel name','(mv/mt) - vessel name','vessel','ship name','ship_name','full vessel name','mv/mt vessel name'],
      recipientEmail: ['recipient email','recipient_email','email','email address','master email','contact email'],
      notes:          ['notes','remarks','comment','comments'],
      certId:         ['cert number','cert_number','certificate number','certificate_number','cert no','cert id'],
    };

    function matchHeader(header) {
      const h = header.toLowerCase().trim().replace(/['"]/g,'');
      for (const [field, aliases] of Object.entries(CSV_FIELD_ALIASES)) {
        if (aliases.includes(h)) return field;
      }
      return null;
    }

    function autoDetectMapping(headers) {
      const map = {};
      headers.forEach((h, idx) => {
        const field = matchHeader(h);
        if (field && !(field in map)) map[field] = idx;
      });
      return map;
    }

    function csvDragOver(e) { e.preventDefault(); document.getElementById('csvDropZone').classList.add('drag-over'); }
    function csvDragLeave() { document.getElementById('csvDropZone').classList.remove('drag-over'); }
    function csvDrop(e) { e.preventDefault(); document.getElementById('csvDropZone').classList.remove('drag-over'); const f = e.dataTransfer.files[0]; if (f) handleCsvFile({ files: [f] }); }

    function handleCsvFile(input) {
      // accept both <input> element and drag-and-drop file reference
      const file = input.files ? input.files[0] : input; if (!file) return;
      const r = new FileReader();
      r.onload = e => {
        const text = e.target.result;
        const parsed = parseCsv(text);
        csvParsedRows = parsed.rows;
        csvRawHeaders = parsed.headers;
        csvColMap     = autoDetectMapping(parsed.rawHeaders);

        if (csvParsedRows.length === 0) { toast('No data rows found. Check that your CSV has a header row and at least one data row.', 'err'); return; }

        // Warn if key fields not detected
        const missing = ['vesselIMO','complianceDate','recipientName'].filter(f => !(f in csvColMap));
        const hintsEl = document.getElementById('csvHint');
        if (missing.length > 0) {
          hintsEl.style.color = 'var(--warn)';
          hintsEl.textContent = '⚠ Could not auto-detect: ' + missing.join(', ') + ' — check column names';
        } else {
          hintsEl.style.color = 'var(--teal)';
          hintsEl.textContent = '✓ All required columns detected';
        }

        document.getElementById('csvUploadDefault').style.display = 'none';
        document.getElementById('csvUploadLoaded').style.display = 'block';
        document.getElementById('csvFileName').textContent = file.name;
        document.getElementById('csvRowCount').textContent = csvParsedRows.length + ' data row(s) · ' + csvRawHeaders.length + ' column(s)';
        renderCsvPreview();
      };
      r.readAsText(file);
    }

    function parseCsv(text) {
      const lines = text.split(/\r?\n/);
      if (lines.length < 2) return { headers: [], rawHeaders: [], rows: [] };

      function splitLine(line) {
        const result = []; let cur = ''; let inQ = false;
        for (let i = 0; i < line.length; i++) {
          const ch = line[i];
          if (ch === '"') { inQ = !inQ; }
          else if ((ch === ',' || ch === '\t') && !inQ) { result.push(cur.trim()); cur = ''; }
          else { cur += ch; }
        }
        result.push(cur.trim());
        return result;
      }

      // Find first non-empty line as header
      let headerIdx = 0;
      while (headerIdx < lines.length && !lines[headerIdx].trim()) headerIdx++;
      if (headerIdx >= lines.length) return { headers: [], rawHeaders: [], rows: [] };

      const rawHeaders = splitLine(lines[headerIdx]).map(h => h.replace(/^"|"$/g, '').trim());
      const headers    = rawHeaders.map(h => h.toLowerCase());
      const rows = [];

      for (let i = headerIdx + 1; i < lines.length; i++) {
        const line = lines[i];
        if (!line.trim()) continue;
        const vals = splitLine(line).map(v => v.replace(/^"|"$/g, '').trim());
        // Skip completely empty rows
        if (vals.every(v => !v)) continue;
        const obj = {};
        rawHeaders.forEach((h, idx) => { obj[h] = vals[idx] || ''; obj[h.toLowerCase()] = vals[idx] || ''; });
        rows.push(obj);
      }
      return { headers, rawHeaders, rows };
    }

    function parseCsvDate(raw) {
      if (!raw) return '';
      raw = raw.trim();
      // DD-Mon-YY or DD-Mon-YYYY  e.g. 18-Feb-26 or 18-Feb-2026
      const m1 = raw.match(/^(\d{1,2})[-\/\s](Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-\/\s](\d{2,4})$/i);
      if (m1) {
        const yr  = m1[3].length === 2 ? (parseInt(m1[3]) < 50 ? '20' + m1[3] : '19' + m1[3]) : m1[3];
        const MON = { jan:'01',feb:'02',mar:'03',apr:'04',may:'05',jun:'06',jul:'07',aug:'08',sep:'09',oct:'10',nov:'11',dec:'12' };
        return `${yr}-${MON[m1[2].toLowerCase()]}-${m1[1].padStart(2,'0')}`;
      }
      // DD/MM/YYYY or DD-MM-YYYY
      const m2 = raw.match(/^(\d{1,2})[-\/](\d{1,2})[-\/](\d{2,4})$/);
      if (m2) {
        const yr = m2[3].length === 2 ? (parseInt(m2[3]) < 50 ? '20' + m2[3] : '19' + m2[3]) : m2[3];
        return `${yr}-${m2[2].padStart(2,'0')}-${m2[1].padStart(2,'0')}`;
      }
      // YYYY-MM-DD passthrough
      if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return raw;
      try { const d = new Date(raw); if (!isNaN(d)) return d.toISOString().slice(0,10); } catch {}
      return '';
    }

    function getRowVal(row, field) {
      // Use auto-detected column map index, then fall back to alias scan on row keys
      if (csvColMap && field in csvColMap) {
        // row keys include both original and lowercased headers
        const colIdx = csvColMap[field];
        const keys   = csvRawHeaders;
        if (keys && keys[colIdx]) return (row[keys[colIdx]] || row[keys[colIdx].toLowerCase()] || '').trim();
      }
      // Fallback: scan all known aliases directly on row
      const aliases = CSV_FIELD_ALIASES[field] || [];
      for (const alias of aliases) {
        const v = row[alias] || row[alias.replace(/_/g,' ')] || '';
        if (v) return v.trim();
      }
      return '';
    }

    function buildCertFromRow(row, quarter, mode) {
      const imo          = getRowVal(row, 'vesselIMO');
      const rawDate      = getRowVal(row, 'complianceDate');
      const chiefName    = getRowVal(row, 'chiefEngineer');
      const recipientName= getRowVal(row, 'recipientName');
      const email        = getRowVal(row, 'recipientEmail');
      const notes        = getRowVal(row, 'notes');
      const manualId     = getRowVal(row, 'certId');

      // vesselName = clean name without type prefix
      const vesselName   = recipientName.replace(/^(MV|MT)\s*[-–]\s*/i, '').trim() || recipientName;

      const complianceDate = parseCsvDate(rawDate);

      var _cstPfx = (window.APP_CONFIG&&window.APP_CONFIG.certFormats)?window.APP_CONFIG.certFormats.cstPrefix:'CST';
      let certId = manualId || '';
      // Auto-generate cert ID if not supplied in CSV
      if (!certId) {
        if (imo && complianceDate) {
          const parts = complianceDate.split('-');
          certId = `${_cstPfx}-${imo}-${parts[1]}-${parts[0].slice(-2)}`;
        } else if (imo) {
          const now = new Date();
          certId = `${_cstPfx}-${imo}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getFullYear()).slice(-2)}`;
        }
      }

      const qMap = { Q1:{label:'Q2 (APR–JUN)',end:'06-30'}, Q2:{label:'Q3 (JUL–SEP)',end:'09-30'}, Q3:{label:'Q4 (OCT–DEC)',end:'12-31'}, Q4:{label:'Q1 (JAN–MAR)',end:'03-31',nextYear:true} };
      const qi = qMap[quarter] || qMap['Q1'];
      const baseYear = complianceDate ? parseInt(complianceDate.slice(0,4)) : new Date().getFullYear();
      const validYear = qi.nextYear ? baseYear + 1 : baseYear;

      const CFG = window.APP_CONFIG || {};
      return {
        id: (certId||'').toUpperCase(),
        recipientName, vesselName, vesselIMO: imo, chiefEngineer: chiefName,
        trainingTitle: (CFG.cst||{}).trainingTitle || 'Cyber Security Threat Intelligence Awareness Training',
        organizer:     (CFG.cst||{}).organizer     || 'Synergy Marine Group Cyber Security Team',
        complianceDate, complianceQuarter: quarter, trainingMode: mode,
        validFor:      qi.label + '-' + validYear,
        validUntil:    validYear + '-' + qi.end,
        issuedAt:      complianceDate,
        verifiedBy:    (CFG.cst||{}).verifiedBy    || 'Gaurav Singh, CISO - Chief Information Security Officer, Synergy Marine Group',
        status: 'PENDING', certificateImage: null,
        notes:         notes || (CFG.cst||{}).notes || 'Training conducted under supervision of ISO Lead Auditor and Security trainers',
        recipientEmail: email,
        issuerEmail:   (CFG.contact||{}).cstEmail  || 'trainingawareness@synergyship.com',
        emailStatus: 'NOT_SENT', emailSentAt: null,
      };
    }

    function renderCsvPreview() {
      const quarter = document.getElementById('csvQuarter').value;
      const mode    = document.getElementById('csvMode').value;
      const records = csvParsedRows.map(r => buildCertFromRow(r, quarter, mode));
      const dups = [], noId = [], noImo = [];

      document.getElementById('csvPreviewWrap').style.display = 'block';
      document.getElementById('csvPreviewCount').textContent = records.length;
      document.getElementById('csvImportBtn').disabled = false;

      let html = '<table style="width:100%;border-collapse:collapse"><thead><tr style="position:sticky;top:0;background:var(--navy-mid);z-index:1">';
      ['#','Cert ID','Vessel','IMO','Chief Engineer','Date','Email','Status'].forEach(h =>
        html += `<th style="padding:8px 10px;text-align:left;font-size:.6rem;letter-spacing:.1em;color:var(--text-sec);text-transform:uppercase;border-bottom:1px solid var(--border);white-space:nowrap">${h}</th>`
      );
      html += '</tr></thead><tbody>';

      records.forEach((c, i) => {
        const existing   = CERTS.find(x => x.id === c.id);
        const hasId      = !!c.id;
        const hasImo     = !!c.vesselIMO;
        const rowBg      = existing ? 'background:rgba(255,179,71,.05)' : !hasId ? 'background:rgba(255,107,138,.05)' : '';
        const idColor    = existing ? 'var(--warn)' : !hasId ? 'var(--invalid)' : 'var(--teal)';
        const statusTxt  = existing ? '⚠ Exists' : !hasId ? '✗ No ID' : '✓ New';
        const statusColor= existing ? 'var(--warn)' : !hasId ? 'var(--invalid)' : 'var(--teal)';
        const emailChip  = c.recipientEmail
          ? `<span style="color:var(--teal);font-size:.6rem">✓</span>`
          : `<span style="color:var(--text-sec);font-size:.6rem">—</span>`;
        if (existing) dups.push(c.id);
        if (!hasId)   noId.push(i+1);
        if (!hasImo)  noImo.push(i+1);
        html += `<tr style="${rowBg};border-bottom:1px solid var(--border)">
          <td style="padding:6px 10px;color:var(--text-sec);font-size:.63rem">${i+1}</td>
          <td style="padding:6px 10px;font-family:'JetBrains Mono',monospace;font-size:.61rem;color:${idColor}">${c.id||'—'}</td>
          <td style="padding:6px 10px;font-size:.65rem;color:var(--text-bright);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${c.recipientName}">${c.recipientName||'—'}</td>
          <td style="padding:6px 10px;font-size:.65rem">${c.vesselIMO||'—'}</td>
          <td style="padding:6px 10px;font-size:.63rem;color:var(--text-sec);max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${c.chiefEngineer}">${c.chiefEngineer||'—'}</td>
          <td style="padding:6px 10px;font-size:.63rem">${c.complianceDate||'—'}</td>
          <td style="padding:6px 10px;text-align:center">${emailChip}</td>
          <td style="padding:6px 10px;font-size:.63rem;color:${statusColor};white-space:nowrap">${statusTxt}</td></tr>`;
      });
      html += '</tbody></table>';
      document.getElementById('csvPreviewTable').innerHTML = html;

      // Build warning messages
      const warnBox = document.getElementById('csvWarnBox');
      const warns = [];
      if (dups.length)  warns.push(`⚠ ${dups.length} duplicate(s) will be skipped: ${dups.slice(0,3).join(', ')}${dups.length>3?'…':''}`);
      if (noId.length)  warns.push(`✗ ${noId.length} row(s) missing IMO/date (cannot generate ID): rows ${noId.slice(0,5).join(', ')}`);
      if (noImo.length && !noId.length) warns.push(`⚠ ${noImo.length} row(s) have no IMO number`);
      if (warns.length) { warnBox.style.display = 'block'; warnBox.innerHTML = warns.map(w => `<div>${w}</div>`).join(''); }
      else              { warnBox.style.display = 'none'; }
      // warnings already set above
    }

    async function doImportCsv() {
      if (csvParsedRows.length === 0) { toast('Please upload a CSV file before importing.', 'err'); return; }
      const quarter = document.getElementById('csvQuarter').value;
      const mode = document.getElementById('csvMode').value;
      const records = csvParsedRows.map(r => buildCertFromRow(r, quarter, mode));
      const btn = document.getElementById('csvImportBtn');
      btn.disabled = true;
      document.getElementById('csvImportTxt').textContent = 'Importing\u2026';
      const log = document.getElementById('csvResultLog');
      log.style.display = 'block'; log.innerHTML = '';
      const CHUNK_SIZE = 500; // server contract: max 500 per batch
      let added = 0, skipped = 0, failed = 0;
      const total = records.length;
      for (let off = 0; off < records.length; off += CHUNK_SIZE) {
        const chunk = records.slice(off, off + CHUNK_SIZE);
        try {
          const r = await fetch(API + '/import-csv', {
            method: 'POST',
            headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
            body: JSON.stringify(chunk),
          });
          const d = await r.json().catch(() => ({}));
          if (r.ok) {
            added += d.added || 0;
            skipped += d.skipped || 0;
            failed += d.failed || 0;
            if (Array.isArray(d.results)) {
              d.results.forEach(res => {
                if (res.status === 'created') log.innerHTML += `<div style="color:var(--teal)">✓ Created ${res.id} \u2014 ${res.vessel || ''}</div>`;
                else if (res.status === 'skipped') log.innerHTML += `<div style="color:var(--warn)">⚠ Skipped ${res.id} \u2014 ${res.reason || 'already exists'}</div>`;
                else log.innerHTML += `<div style="color:var(--invalid)">✗ Failed ${res.id}: ${res.reason || 'Unknown error'}</div>`;
              });
            }
          } else {
            const msg = d.error || 'Unknown error';
            failed += chunk.length;
            log.innerHTML += `<div style="color:var(--invalid)">✗ Import batch failed: ${msg}</div>`;
          }
        } catch {
          failed += chunk.length;
          log.innerHTML += `<div style="color:var(--invalid)">✗ Import batch interrupted \u2014 connection error.</div>`;
        }
        log.scrollTop = log.scrollHeight;
      }
      log.innerHTML += `<div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border);color:var(--gold)">Done \u2014 ✓ ${added} created \u00b7 ⚠ ${skipped} skipped \u00b7 ✗ ${failed} failed (from ${total} record(s))</div>`;
      document.getElementById('csvImportTxt').textContent = 'Import All Records';
      btn.disabled = false;
      await refreshStats();
      renderTbl('dashTbl', ''); renderTbl('allTbl', '');
      if (added > 0) toast(`${added} certificate(s) imported!`, 'ok');
    }

    document.getElementById('csvQuarter').addEventListener('change', () => { if (csvParsedRows.length > 0) renderCsvPreview(); });
    document.getElementById('csvMode').addEventListener('change', () => { if (csvParsedRows.length > 0) renderCsvPreview(); });

    function downloadSampleCsv() {
      // Headers match all supported aliases — use the canonical Synergy format
      const rows = [
        'IMO Number,VESSEL_NAME,Chif Name,ISSUES_DATES,recipient_email,notes',
        '9623740,MV - NORD KUDU,BARREGA WILLIE PANIAMOGAN,30-Jan-26,master@nordkudu.com,',
        '9689536,MT - BW CHINOOK,TARAK NATH,12-Feb-26,master@bwchinook.com,',
        '9491666,MV - EFFICIENCY OL,JOHN A SMITH,10-Mar-26,chief@efficiencyol.com,Attended online session',
      ].join('\n');
      const blob = new Blob([rows], { type: 'text/csv' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'cst_import_sample.csv';
      a.click();
      URL.revokeObjectURL(a.href);
    }

    function clearCsvFile(e) { e.stopPropagation(); clearCsvFileSilent(); }
    function clearCsvFileSilent() {
      csvParsedRows = [];
      document.getElementById('csvFileInput').value = '';
      document.getElementById('csvUploadDefault').style.display = 'block';
      document.getElementById('csvUploadLoaded').style.display = 'none';
      document.getElementById('csvPreviewWrap').style.display = 'none';
      document.getElementById('csvResultLog').style.display = 'none';
      document.getElementById('csvImportBtn').disabled = true;
    }

        // ════════════════════════════════════════════════════
    // MODULE: Lightbox / Toast / Keyboard
    // ════════════════════════════════════════════════════
    function openLB(src) { document.getElementById('lbImg').src = src; document.getElementById('lightbox').style.display = 'flex'; }
    function closeLB() { document.getElementById('lightbox').style.display = 'none'; }

    function openPdfModal(url, name) {
      document.getElementById('pdfModalTitle').textContent = name || 'Document';
      document.getElementById('pdfModalLink').href = url;
      document.getElementById('pdfViewerOverlay').style.display = 'flex';
      const noSupport = document.getElementById('pdfNoSupport');
      const frame = document.getElementById('pdfModalFrame');
      noSupport.style.display = 'none';
      frame.style.display = 'block';

      // For PDFs: try loading directly; on error show fallback UI
      frame.onerror = function() { showPdfFallback(); };
      frame.src = url;

      // Detect if PDF failed to render after a short delay (CSP/X-Frame block)
      const loadTimeout = setTimeout(() => {
        // If frame contentDocument is inaccessible or blank, show fallback
        try {
          const doc = frame.contentDocument || frame.contentWindow.document;
          if (!doc || doc.body.innerHTML === '') showPdfFallback();
        } catch(e) {
          // Cross-origin block — the iframe has something, probably fine
        }
      }, 3000);
      frame.onload = function() { clearTimeout(loadTimeout); };
    }
    function showPdfFallback() {
      document.getElementById('pdfModalFrame').style.display = 'none';
      document.getElementById('pdfNoSupport').style.display = 'flex';
    }
    function closePdfModal() {
      document.getElementById('pdfViewerOverlay').style.display = 'none';
      const frame = document.getElementById('pdfModalFrame');
      frame.src = '';
      frame.style.display = 'block';
      document.getElementById('pdfNoSupport').style.display = 'none';
    }
    function toast(msg, type = 'ok') { const t = document.getElementById('toast'); t.textContent = msg; t.className = 'show ' + type; setTimeout(() => t.className = '', 3500); }
    document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeLB(); closeView(); closeDel(); closePdfModal(); } });

    // ════════════════════════════════════════════════════
    // MODULE: Boot
    // ════════════════════════════════════════════════════
    if (TOKEN) {
      // Validate token hasn't expired before restoring session
      try {
        const parts = TOKEN.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
          if (Date.now() > payload.exp * 1000) {
            sessionStorage.removeItem('adminToken'); TOKEN = '';
          }
        } else { sessionStorage.removeItem('adminToken'); TOKEN = ''; }
      } catch { sessionStorage.removeItem('adminToken'); TOKEN = ''; }
    }
    if (TOKEN) {
      document.getElementById('loginWrap').style.display = 'none';
      document.getElementById('appWrap').style.display = 'flex';
      scheduleTokenExpiryWarning();
      initApp();
    } else {
      document.getElementById('appWrap').style.display = 'none';
    }
    livePreview();
    updateCompletionChecklistFull();
  

// Near-expiry proactive banner — shown on Dashboard page when any cert expires within 30 days
function checkNearExpiryBanner(certs) {
  const now = new Date();
  const nearExpiry = (certs || []).filter(c => {
    if (!c.validUntil || (c.status||'').toUpperCase() !== 'VALID') return false;
    const dLeft = Math.round((new Date(c.validUntil).setHours(0,0,0,0) - now.setHours(0,0,0,0)) / 86400000);
    return dLeft >= 0 && dLeft <= 30;
  });
  const banner = document.getElementById('nearExpiryBanner');
  if (!banner) return;
  if (!nearExpiry.length) { banner.style.display = 'none'; return; }
  banner.style.display = 'flex';
  banner.innerHTML = `
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
    <div>
      <strong>${nearExpiry.length} certificate${nearExpiry.length===1?'':'s'} expiring within 30 days</strong> —
      ${nearExpiry.slice(0,3).map(c => {
        const d = Math.round((new Date(c.validUntil).setHours(0,0,0,0) - new Date().setHours(0,0,0,0)) / 86400000);
        return `<span style="font-family:'JetBrains Mono',monospace;font-size:.75em">${c.id}</span> (${d}d)`;
      }).join(', ')}${nearExpiry.length > 3 ? ' …' : ''}
    </div>
    <button onclick="this.parentElement.style.display='none'" style="margin-left:auto;background:none;border:none;color:currentColor;cursor:pointer;opacity:.6;font-size:1rem;padding:0 4px;line-height:1" aria-label="Dismiss">✕</button>
  `;
}

let _lastAppliedConfig = null;
// ── MOBILE SIDEBAR TOGGLE ────────────────────────────────────────────────
function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  const ov = document.getElementById('sidebarOverlay');
  const btn = document.getElementById('hamburgerBtn');
  const isOpen = sb && sb.classList.contains('open');
  if (isOpen) { closeSidebar(); } else {
    if (sb) sb.classList.add('open');
    if (ov) ov.classList.add('open');
    if (btn) btn.setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
  }
}
function closeSidebar() {
  const sb = document.getElementById('sidebar');
  const ov = document.getElementById('sidebarOverlay');
  const btn = document.getElementById('hamburgerBtn');
  if (sb) sb.classList.remove('open');
  if (ov) ov.classList.remove('open');
  if (btn) btn.setAttribute('aria-expanded', 'false');
  document.body.style.overflow = '';
}
// Close sidebar when a nav item is clicked on mobile
document.addEventListener('click', function(e) {
  if (e.target.closest('.nav-item') && window.innerWidth <= 900) { closeSidebar(); }
});
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') { closeSidebar(); } });

function applyConfig() {

  var C = window.APP_CONFIG;
  if (!C || C === _lastAppliedConfig) return;
  _lastAppliedConfig = C;
  document.title = C.titles.cstAdmin;
  var el;
  if ((el=document.getElementById("loginSub")))    el.textContent = C.nav.cstLoginSub;
  if ((el=document.getElementById("sbName")))      el.textContent = C.nav.cstSidebarName;
  if ((el=document.getElementById("adminRole")))   el.textContent = C.brand.adminRole;
  if ((el=document.getElementById("csvHint")))     el.textContent = C.cst.csvFormatHint;
  if ((el=document.getElementById("pvOrgName")))   el.textContent = C.cst.previewOrgName;
  if ((el=document.getElementById("pv-title")))    el.textContent = C.cst.trainingTitle;
  if ((el=document.getElementById("pv-verifier"))) el.textContent = C.cst.previewSigName;
  // Form field defaults
  if ((el=document.getElementById("fTitle")))    el.value = C.cst.trainingTitle;
  if ((el=document.getElementById("fOrg")))      el.value = C.cst.organizer;
  if ((el=document.getElementById("fVerifier"))) el.value = C.cst.verifiedBy;
  if ((el=document.getElementById("fNotes")))    el.value = C.cst.notes;
  // Sidebar nav links
  var sbCST = document.getElementById("sbLinkCST");      if (sbCST)      sbCST.href      = C.routes.cst;
  var sbVPT = document.getElementById("sbLinkVPTAdmin"); if (sbVPT)      sbVPT.href      = C.routes.vptAdmin;
  // Admin data notice from compliance config
  if (C.compliance && C.compliance.adminDataNotice) {
    var notice = document.getElementById("adminDataNotice");
    if (notice) notice.lastChild.textContent = ' ' + C.compliance.adminDataNotice;
  }
}
  // Call immediately (fast path if config.js already loaded)
  applyConfig();
  // Fallback: also call after DOM + scripts are fully ready
  if (document.readyState !== 'complete') {
    window.addEventListener('load', applyConfig);
  }
  // Also call applyConfig when config.js (deferred) finishes loading
  document.addEventListener('appconfigready', applyConfig);

// ── SESSION EXPIRY & IDLE TIMEOUT MANAGEMENT ─────────────────────────────────
(function () {
  'use strict';

  // Read timing from config or use safe defaults
  function getCfg() {
    return (window.APP_CONFIG && window.APP_CONFIG.session) || {};
  }

  var _sessionStart    = null;
  var _sessionTimer    = null;
  var _idleTimer       = null;
  var _idleWarnTimer   = null;
  var _sessionWarnTimer= null;
  var _idleCountdownInterval = null;
  var _sessionCountdownInterval = null;

  // Format mm:ss for countdown displays
  function fmtMs(ms) {
    var s   = Math.max(0, Math.ceil(ms / 1000));
    var m   = Math.floor(s / 60);
    var sec = s % 60;
    return m + ':' + (sec < 10 ? '0' : '') + sec;
  }

  function showSessionWarn(msLeft) {
    var banner = document.getElementById('sessionWarningBanner');
    var el     = document.getElementById('sessionCountdown');
    if (!banner) return;
    banner.style.display = 'block';
    if (el) el.textContent = fmtMs(msLeft);
    clearInterval(_sessionCountdownInterval);
    var remaining = msLeft;
    _sessionCountdownInterval = setInterval(function () {
      remaining -= 1000;
      if (el) el.textContent = fmtMs(remaining);
      if (remaining <= 0) { clearInterval(_sessionCountdownInterval); }
    }, 1000);
  }

  function hideSessionWarn() {
    var b = document.getElementById('sessionWarningBanner');
    if (b) b.style.display = 'none';
    clearInterval(_sessionCountdownInterval);
  }

  function showIdleWarn(msLeft) {
    var banner = document.getElementById('idleWarningBanner');
    var el     = document.getElementById('idleCountdown');
    if (!banner) return;
    banner.style.display = 'block';
    if (el) el.textContent = fmtMs(msLeft);
    clearInterval(_idleCountdownInterval);
    var remaining = msLeft;
    _idleCountdownInterval = setInterval(function () {
      remaining -= 1000;
      if (el) el.textContent = fmtMs(remaining);
      if (remaining <= 0) { clearInterval(_idleCountdownInterval); }
    }, 1000);
  }

  function hideIdleWarn() {
    var b = document.getElementById('idleWarningBanner');
    if (b) b.style.display = 'none';
    clearInterval(_idleCountdownInterval);
  }

  // Called by "I'm still here" button
  window.resetIdle = function () {
    hideIdleWarn();
    startIdleTimeout();
  };

  // Called by "Extend Session" button — re-verify token with server
  window.refreshSession = function () {
    const tok = sessionStorage.getItem('adminToken') || '';
    if (!tok) return;
    fetch('/api/auth/verify', { headers: { Authorization: 'Bearer ' + tok } })
      .then(function (r) {
        if (r.ok) {
          hideSessionWarn();
          // Restart session timer from now
          if (_sessionStart) _sessionStart = Date.now();
          scheduleSessionTimers();
        } else {
          doLogout();
        }
      })
      .catch(function () { /* network error — just dismiss */ hideSessionWarn(); });
  };

  function scheduleSessionTimers() {
    clearTimeout(_sessionTimer);
    clearTimeout(_sessionWarnTimer);
    var cfg        = getCfg();
    var maxMs      = cfg.maxDurationMs      || 8 * 60 * 60 * 1000;
    var warnBefore = cfg.warningBeforeMs    || 5 * 60 * 1000;
    var now        = Date.now();
    var elapsed    = _sessionStart ? (now - _sessionStart) : 0;
    var remaining  = Math.max(0, maxMs - elapsed);
    var warnAt     = Math.max(0, remaining - warnBefore);

    _sessionWarnTimer = setTimeout(function () { showSessionWarn(warnBefore); }, warnAt);
    _sessionTimer     = setTimeout(function () {
      clearInterval(_sessionCountdownInterval);
      doLogout();
    }, remaining);
  }

  function startIdleTimeout() {
    clearTimeout(_idleTimer);
    clearTimeout(_idleWarnTimer);
    var cfg        = getCfg();
    var idleMs     = cfg.idleTimeoutMs       || 30 * 60 * 1000;
    var warnBefore = cfg.idleWarningBeforeMs || 2  * 60 * 1000;
    var warnAt     = idleMs - warnBefore;

    _idleWarnTimer = setTimeout(function () { showIdleWarn(warnBefore); }, warnAt);
    _idleTimer     = setTimeout(function () {
      clearInterval(_idleCountdownInterval);
      doLogout();
    }, idleMs);
  }

  // Reset idle on user activity
  var _actThrottle = null;
  function onActivity() {
    if (_actThrottle) return;
    _actThrottle = setTimeout(function () { _actThrottle = null; }, 10000);
    hideIdleWarn();
    startIdleTimeout();
  }
  ['mousemove', 'keydown', 'pointerdown', 'scroll', 'touchstart'].forEach(function (ev) {
    document.addEventListener(ev, onActivity, { passive: true });
  });

  // Hook into the existing post-login flow — expose start function globally
  window._startSessionTimers = function (sessionStartMs) {
    _sessionStart = sessionStartMs || Date.now();
    scheduleSessionTimers();
    startIdleTimeout();
  };

  // If already logged in (page reload), start timers with token issue time if available
  var _tok = sessionStorage.getItem('adminToken') || '';
  if (_tok) {
    // Parse JWT payload to get iat (issued-at)
    try {
      var parts = _tok.split('.');
      if (parts.length === 3) {
        var payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        if (payload && payload.iat) { _sessionStart = payload.iat; }
      }
    } catch (e) { /* use now */ }
    if (!_sessionStart) _sessionStart = Date.now();
    scheduleSessionTimers();
    startIdleTimeout();
  }
})();



// ════════════════════════════════════════════════════
// MODULE: Internal Validity (90-Day Window)
// Logic: Issue Date (issuedAt or complianceDate) + 90 days
// ════════════════════════════════════════════════════

function ivDeadline(cert) {
  const base = cert.issuedAt || cert.complianceDate;
  if (!base) return null;
  const d = new Date(base);
  if (isNaN(d)) return null;
  d.setDate(d.getDate() + 90);
  return d;
}

function ivDaysLeft(cert) {
  const dl = ivDeadline(cert);
  if (!dl) return null;
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  dl.setHours(0, 0, 0, 0);
  return Math.round((dl - now) / 86400000);
}

function ivStatus(cert) {
  const d = ivDaysLeft(cert);
  if (d === null) return 'nodate';
  if (d < 0) return 'expired';
  if (d <= 30) return 'expiring';
  return 'valid';
}

function computeIVStats(certs) {
  let valid = 0, expiring = 0, expired = 0, nodate = 0;
  certs.forEach(c => {
    const s = ivStatus(c);
    if (s === 'valid') valid++;
    else if (s === 'expiring') expiring++;
    else if (s === 'expired') expired++;
    else nodate++;
  });
  return { valid, expiring, expired, nodate, total: certs.length };
}

function renderValidityPage(q) {
  const filterSel = document.getElementById('ivFilterSel');
  const filter = filterSel ? filterSel.value : '';
  const search = (q || (document.getElementById('ivSearchQ') ? document.getElementById('ivSearchQ').value : '')).toLowerCase();

  const certs = (typeof CERTS !== 'undefined' ? CERTS : []);
  const stats = computeIVStats(certs);

  // KPI cards
  const kpiRow = document.getElementById('ivKpiRow');
  if (kpiRow) {
    kpiRow.innerHTML = [
      { label: 'Within Window', count: stats.valid, color: 'var(--teal)', bg: 'rgba(100,255,218,.08)', border: 'rgba(100,255,218,.2)', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
      { label: 'Expiring ≤ 30d', count: stats.expiring, color: 'var(--warn)', bg: 'rgba(255,179,71,.08)', border: 'rgba(255,179,71,.22)', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' },
      { label: 'Passed 90-Day Window', count: stats.expired, color: 'var(--invalid)', bg: 'rgba(255,107,138,.07)', border: 'rgba(255,107,138,.2)', icon: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z' },
      { label: 'No Issue Date', count: stats.nodate, color: '#8892B0', bg: 'rgba(136,146,176,.06)', border: 'rgba(136,146,176,.18)', icon: 'M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' }
    ].map(k => `
      <div class="stat-card" style="border-color:${k.border};background:${k.bg}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
          <div class="slabel" style="margin:0;color:${k.color}">${k.label}</div>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${k.color}" stroke-width="1.5" opacity=".5"><path stroke-linecap="round" stroke-linejoin="round" d="${k.icon}"/></svg>
        </div>
        <div class="snum" style="color:${k.color}">${k.count}</div>
        <div style="font-size:.57rem;color:var(--text-sec);margin-top:4px">of ${stats.total} total certificates</div>
      </div>`).join('');
  }

  // Filter + search certs
  let rows = certs.filter(c => {
    const s = ivStatus(c);
    if (filter && s !== filter) return false;
    if (search) {
      const haystack = [c.id, c.recipientName, c.vesselName, c.vesselIMO].join(' ').toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  // Sort: expired first, then expiring, then valid, then nodate
  const order = { expired: 0, expiring: 1, valid: 2, nodate: 3 };
  rows.sort((a, b) => {
    const sa = order[ivStatus(a)], sb = order[ivStatus(b)];
    if (sa !== sb) return sa - sb;
    const da = ivDaysLeft(a), db = ivDaysLeft(b);
    if (da === null && db === null) return 0;
    if (da === null) return 1;
    if (db === null) return -1;
    return da - db;
  });

  const wrap = document.getElementById('ivTableWrap');
  if (!wrap) return;

  if (rows.length === 0) {
    wrap.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-sec);font-size:.82rem">No certificates match the current filter.</div>';
    return;
  }

  const statusLabel = { valid: ['Within Window', 'var(--teal)', 'rgba(100,255,218,.12)'], expiring: ['Expiring Soon', 'var(--warn)', 'rgba(255,179,71,.12)'], expired: ['Passed Window', 'var(--invalid)', 'rgba(255,107,138,.12)'], nodate: ['No Date', '#8892B0', 'rgba(136,146,176,.1)'] };

  const fmtD = d => d ? new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';

  wrap.innerHTML = `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.75rem">
    <thead><tr style="border-bottom:1px solid var(--border)">
      ${['Cert ID','Recipient / Vessel','Issue Date','90-Day Deadline','Days Left','Internal Status','Cert Status'].map(h =>
        `<th style="padding:9px 12px;text-align:left;color:var(--text-sec);font-weight:600;font-size:.68rem;letter-spacing:.04em;white-space:nowrap">${h}</th>`
      ).join('')}
    </tr></thead>
    <tbody>
    ${rows.map(c => {
      const ivSt = ivStatus(c);
      const [stLabel, stColor, stBg] = statusLabel[ivSt];
      const dl = ivDaysLeft(c);
      const deadline = ivDeadline(c);
      const daysStr = dl === null ? '—' : dl < 0 ? `${Math.abs(dl)}d overdue` : `${dl}d left`;
      const daysColor = dl === null ? '#8892B0' : dl < 0 ? 'var(--invalid)' : dl <= 30 ? 'var(--warn)' : 'var(--teal)';
      const certSt = (c.status || 'VALID').toUpperCase();
      const csBg = certSt === 'VALID' ? 'rgba(100,255,218,.1)' : certSt === 'REVOKED' ? 'rgba(255,107,138,.1)' : 'rgba(255,179,71,.1)';
      const csColor = certSt === 'VALID' ? 'var(--teal)' : certSt === 'REVOKED' ? 'var(--invalid)' : 'var(--warn)';
      return `<tr style="border-bottom:1px solid var(--border);transition:background .15s" onmouseover="this.style.background='var(--surface-hover)'" onmouseout="this.style.background=''">
        <td style="padding:9px 12px;font-family:'JetBrains Mono',monospace;color:var(--gold);font-size:.68rem">${c.id}</td>
        <td style="padding:9px 12px">
          <div style="color:var(--text-bright);font-weight:500">${c.recipientName || '—'}</div>
          <div style="font-size:.64rem;color:var(--text-sec);margin-top:1px">${c.vesselName || ''}${c.vesselIMO ? ' · IMO ' + c.vesselIMO : ''}</div>
        </td>
        <td style="padding:9px 12px;color:var(--text-sec)">${fmtD(c.issuedAt || c.complianceDate)}</td>
        <td style="padding:9px 12px;color:var(--text-sec)">${deadline ? fmtD(deadline.toISOString()) : '—'}</td>
        <td style="padding:9px 12px;font-weight:600;color:${daysColor}">${daysStr}</td>
        <td style="padding:9px 12px">
          <span style="display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:20px;font-size:.63rem;font-weight:700;letter-spacing:.04em;background:${stBg};color:${stColor};border:1px solid ${stColor}40">
            ${stLabel}
          </span>
        </td>
        <td style="padding:9px 12px">
          <span style="display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:20px;font-size:.63rem;font-weight:700;letter-spacing:.04em;background:${csBg};color:${csColor};border:1px solid ${csColor}40">
            ${certSt}
          </span>
        </td>
      </tr>`;
    }).join('')}
    </tbody>
  </table></div>`;
}

function exportValidityCSV() {
  const certs = (typeof CERTS !== 'undefined' ? CERTS : []);
  const fmtD = d => d ? new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '';
  const rows = [['Cert ID','Recipient','Vessel','Vessel IMO','Issue Date','90-Day Deadline','Days Left','Internal Status','Cert Status']];
  certs.forEach(c => {
    const dl = ivDaysLeft(c);
    const deadline = ivDeadline(c);
    rows.push([
      c.id, c.recipientName || '', c.vesselName || '', c.vesselIMO || '',
      fmtD(c.issuedAt || c.complianceDate),
      deadline ? fmtD(deadline.toISOString()) : '',
      dl === null ? '' : dl < 0 ? `${Math.abs(dl)}d overdue` : `${dl}d left`,
      ivStatus(c).toUpperCase(),
      (c.status || 'VALID').toUpperCase()
    ]);
  });
  const csv = rows.map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = 'internal-validity-' + new Date().toISOString().slice(0,10) + '.csv';
  a.click();
}

// ════════════════════════════════════════════════════
// MODULE: Assign Vessel to Group
// ════════════════════════════════════════════════════
let _assignGroupIMO = '', _assignGroupName = '', _allGroupsForAssign = [], _bulkAssignIMOs = [];
let _selectedRows = new Set();
let _imoGroupMap = {};

async function loadGroupsMap() {
  try {
    const r = await fetch(API + '/admin/groups', { headers: { Authorization: 'Bearer ' + TOKEN } });
    if (!r.ok) return;
    const groups = await r.json();
    _imoGroupMap = {};
    groups.forEach(g => { (g.vesselIMOs || []).forEach(imo => { _imoGroupMap[imo.toUpperCase()] = g.name; }); });
  } catch { }
}

async function openAssignGroup(vesselIMO, vesselName) {
  if (!vesselIMO) return;
  _bulkAssignIMOs = [];
  _assignGroupIMO = vesselIMO;
  _assignGroupName = vesselName;
  const label = document.getElementById('assignGroupVesselLabel');
  if (label) label.textContent = (vesselName ? vesselName + ' · ' : '') + 'IMO ' + vesselIMO;
  const mod = document.getElementById('assignGroupMod');
  if (mod) mod.style.display = 'flex';
  const listEl = document.getElementById('assignGroupList');
  if (!listEl) return;
  listEl.innerHTML = '<div style="padding:14px;font-size:.75rem;color:var(--text-sec)">Loading groups…</div>';
  try {
    const r = await fetch(API + '/admin/groups', { headers: { Authorization: 'Bearer ' + TOKEN } });
    if (!r.ok) throw new Error('Could not load groups (' + r.status + ')');
    _allGroupsForAssign = await r.json();
    if (!_allGroupsForAssign.length) {
      listEl.innerHTML = '<div style="padding:14px;font-size:.75rem;color:var(--text-sec)">No groups found. Create groups first in the Groups page.</div>';
      return;
    }
    listEl.innerHTML = _allGroupsForAssign.map(g => {
      const already = (g.vesselIMOs || []).some(i => i.toUpperCase() === vesselIMO.toUpperCase());
      return `<label style="display:flex;align-items:center;gap:10px;padding:9px 13px;border-bottom:1px solid rgba(100,255,218,.06);cursor:${already?'default':'pointer'};font-size:.78rem;color:var(--text-sec)">
        <input type="radio" name="assignGroupRadio" value="${escHtml(g.id)}" ${already ? 'disabled' : ''}
          style="accent-color:#64FFDA;flex-shrink:0" />
        <span>
          <strong style="color:var(--text-bright)">${escHtml(g.name)}</strong>
          <span style="color:var(--text-sec);font-size:.65rem;margin-left:7px">${(g.vesselIMOs || []).length} vessel${(g.vesselIMOs || []).length !== 1 ? 's' : ''}</span>
          ${already ? '<span style="font-size:.6rem;color:var(--teal);margin-left:7px">✓ Already assigned</span>' : ''}
        </span>
      </label>`;
    }).join('');
  } catch (e) {
    listEl.innerHTML = `<div style="padding:14px;font-size:.73rem;color:var(--invalid)">${escHtml(e.message)}</div>`;
  }
}

function closeAssignGroup() {
  const mod = document.getElementById('assignGroupMod');
  if (mod) mod.style.display = 'none';
  _assignGroupIMO = ''; _assignGroupName = ''; _bulkAssignIMOs = [];
}

async function confirmAssignGroup() {
  const sel = document.querySelector('#assignGroupList input[name="assignGroupRadio"]:checked');
  if (!sel) { toast('Please select a group.', 'err'); return; }
  const groupId = sel.value;
  const group = _allGroupsForAssign.find(g => g.id === groupId);
  if (!group) return;
  const imosToAssign = _bulkAssignIMOs.length > 0 ? _bulkAssignIMOs : (_assignGroupIMO ? [_assignGroupIMO] : []);
  if (!imosToAssign.length) { toast('No vessel selected.', 'err'); return; }
  const existing = (group.vesselIMOs || []).map(i => i.toUpperCase());
  const newIMOs = imosToAssign.filter(imo => !existing.includes(imo.toUpperCase()));
  if (!newIMOs.length) { toast('All selected vessels are already in this group.', 'warn'); return; }
  const updated = [...(group.vesselIMOs || []), ...newIMOs];
  const btn = document.getElementById('btnConfirmAssign');
  if (btn) { btn.disabled = true; btn.textContent = 'Assigning…'; }
  try {
    const r = await fetch(API + '/admin/groups/' + encodeURIComponent(groupId), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + TOKEN },
      body: JSON.stringify({ vesselIMOs: updated }),
    });
    if (!r.ok) throw new Error('Server returned ' + r.status);
    const n = newIMOs.length;
    const wasBulk = _bulkAssignIMOs.length > 0;
    toast(n + ' vessel' + (n !== 1 ? 's' : '') + ' assigned to group "' + group.name + '"', 'ok');
    closeAssignGroup();
    if (wasBulk) clearSelections();
    await loadGroupsMap();
    const dashPage  = document.getElementById('page-dashboard');
    const certsPage = document.getElementById('page-certs');
    if (dashPage  && dashPage.style.display  !== 'none') renderTbl('dashTbl', '');
    if (certsPage && certsPage.style.display !== 'none') renderTbl('allTbl', document.getElementById('allQ')?.value||'', document.getElementById('allStatusSel')?.value||'');
  } catch (e) {
    toast('Assign failed: ' + e.message, 'err');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Assign to Group'; }
  }
}

// ── Row selection (multi-select / bulk assign) ──
function toggleRowSelect(cb) {
  const imo = cb.dataset.imo;
  if (!imo) return;
  if (cb.checked) _selectedRows.add(imo);
  else _selectedRows.delete(imo);
  updateSelToolbar();
}

function toggleSelectAll(cb, tblId) {
  const scope = tblId ? document.getElementById(tblId) : document;
  (scope || document).querySelectorAll('input.row-sel-cb').forEach(c => {
    c.checked = cb.checked;
    if (cb.checked) _selectedRows.add(c.dataset.imo);
    else _selectedRows.delete(c.dataset.imo);
  });
  updateSelToolbar();
}

function updateSelToolbar() {
  const bar = document.getElementById('certSelBar');
  const countEl = document.getElementById('certSelCount');
  const n = _selectedRows.size;
  if (bar) bar.style.display = n > 0 ? 'flex' : 'none';
  if (countEl) countEl.textContent = n + ' vessel' + (n !== 1 ? 's' : '') + ' selected';
}

function clearSelections() {
  _selectedRows.clear();
  document.querySelectorAll('#allTbl input.row-sel-cb').forEach(c => c.checked = false);
  const allCb = document.getElementById('selAllCb');
  if (allCb) allCb.checked = false;
  updateSelToolbar();
}

async function openBulkAssign() {
  if (!_selectedRows.size) { toast('Select at least one vessel first.', 'warn'); return; }
  const imoList = [..._selectedRows];
  _bulkAssignIMOs = imoList;
  _assignGroupIMO = '';
  const label = document.getElementById('assignGroupVesselLabel');
  if (label) {
    label.innerHTML = imoList.length === 1
      ? 'IMO ' + escHtml(imoList[0])
      : '<strong>' + imoList.length + ' vessels selected</strong>: ' + imoList.map(escHtml).join(', ');
  }
  const mod = document.getElementById('assignGroupMod');
  if (mod) mod.style.display = 'flex';
  const listEl = document.getElementById('assignGroupList');
  if (!listEl) return;
  listEl.innerHTML = '<div style="padding:14px;font-size:.75rem;color:var(--text-sec)">Loading groups…</div>';
  try {
    const r = await fetch(API + '/admin/groups', { headers: { Authorization: 'Bearer ' + TOKEN } });
    if (!r.ok) throw new Error('Could not load groups (' + r.status + ')');
    _allGroupsForAssign = await r.json();
    if (!_allGroupsForAssign.length) {
      listEl.innerHTML = '<div style="padding:14px;font-size:.75rem;color:var(--text-sec)">No groups found. Create groups first in the Groups page.</div>';
      return;
    }
    listEl.innerHTML = _allGroupsForAssign.map(g => {
      const assignedCount = imoList.filter(imo => (g.vesselIMOs || []).some(i => i.toUpperCase() === imo.toUpperCase())).length;
      const allAlready = assignedCount === imoList.length;
      return `<label style="display:flex;align-items:center;gap:10px;padding:9px 13px;border-bottom:1px solid rgba(100,255,218,.06);cursor:${allAlready?'default':'pointer'};font-size:.78rem;color:var(--text-sec)">
        <input type="radio" name="assignGroupRadio" value="${escHtml(g.id)}" ${allAlready ? 'disabled' : ''}
          style="accent-color:#64FFDA;flex-shrink:0" />
        <span>
          <strong style="color:var(--text-bright)">${escHtml(g.name)}</strong>
          <span style="color:var(--text-sec);font-size:.65rem;margin-left:7px">${(g.vesselIMOs||[]).length} vessel${(g.vesselIMOs||[]).length!==1?'s':''}</span>
          ${assignedCount > 0 && !allAlready ? `<span style="font-size:.6rem;color:var(--warn);margin-left:7px">${assignedCount} already assigned</span>` : ''}
          ${allAlready ? '<span style="font-size:.6rem;color:var(--teal);margin-left:7px">✓ All already assigned</span>' : ''}
        </span>
      </label>`;
    }).join('');
  } catch (e) {
    listEl.innerHTML = `<div style="padding:14px;font-size:.73rem;color:var(--invalid)">${escHtml(e.message)}</div>`;
  }
}
