
  // ── Security: HTML escape (XSS prevention) ──
  function escHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  const API = '/api';
  let TOKEN = sessionStorage.getItem('adminToken') || '';
  let CERTS = [];
  let STATUS_CHART = null, EXPIRY_CHART = null, EMAIL_CHART = null;
  let editingId = null, imgFile = null, deleteTargetId = null;
  let autoRecipFrom = ''; // tracks the vessel name we last auto-mirrored into fRecipientName, so a manual edit isn't clobbered
  let filterStatus = '';
  let csvParsedRows = [];
  let selectedIssueCertId = null;
  // Attachment state — var so onclick handlers in dynamic HTML can access them
  var pendingPdfs = [];
  var savedAttachments = [];

  // ── AUTH ──
  function doLogout() {
    import('/assets/pubsub.js').then(PSP => {
      PSP.publish(PSP.TOPICS.AUTH_LOGOUT, { certType: 'VAPT' });
      PSP.setPrincipal(null);
    }).catch(() => {});
    sessionStorage.removeItem('adminToken'); TOKEN = '';
    if (_autoRefreshInterval) { clearInterval(_autoRefreshInterval); _autoRefreshInterval = null; }
    // POST /api/auth/logout revokes the session server-side (jti blacklist)
    // and clears the httpOnly adminToken cookie — the actual session
    // credential — not just hidden client-side. Then reload to re-render
    // the (now unauthenticated) login shell.
    fetch('/api/auth/logout', { method: 'POST' }).catch(() => {}).finally(() => {
      window.location.reload();
    });
  }

  // ── INIT ──
  let _autoRefreshInterval = null;

  // Warn admin 30 min before token expiry; auto-logout when expired
  // Role/expiry/session-start now come from the server (httpOnly-cookie-backed
  // /api/auth/verify) instead of decoding a raw JWT client-side — nothing
  // JS-readable holds a valid session credential any more.
  function scheduleTokenExpiryWarning() {
    fetch(API + '/auth/verify').then(r => r.ok ? r.json() : null).then(info => {
      if (!info) return;
      const isClient = info.role === 'client';
      document.documentElement.classList.toggle('role-client', isClient);
      if (isClient) {
        loadClientOtherCerts().then(() => {
          const certsPage = document.getElementById('page-certs');
          if (certsPage && certsPage.style.display !== 'none') {
            renderTbl('allTbl', document.getElementById('allQ')?.value || '');
          }
        });
      }
      if (window._startSessionTimers && typeof info.iat === 'number') window._startSessionTimers(info.iat * 1000);
      const msLeft = info.exp * 1000 - Date.now();
      if (msLeft <= 0) { doLogout(); return; }
      setTimeout(doLogout, msLeft);
      const warnAt = msLeft - 30 * 60 * 1000;
      if (warnAt > 0) setTimeout(() => toast('⚠ Session expires in 30 minutes. Save your work.', 'warn'), warnAt);
    }).catch(() => {});
  }

  async function initApp() {
    scheduleTokenExpiryWarning();
    await refreshStats();
    await loadGroupsMap();
    renderTbl('dashTbl', '');
    updateRealTimeBadge();
    checkSesStatus();
    checkHealth();
    if (_autoRefreshInterval) clearInterval(_autoRefreshInterval);
    _autoRefreshInterval = setInterval(async () => {
      // Skip background refresh when a modal/overlay is open
      const viewOpen  = document.getElementById('viewOverlay');
      const delOpen   = document.getElementById('delOverlay');
      const groupOpen = document.getElementById('assignGroupMod');
      const addPage   = document.getElementById('page-add');
      if ((viewOpen  && viewOpen.style.display  === 'flex') ||
          (delOpen   && delOpen.style.display   !== 'none') ||
          (groupOpen && groupOpen.style.display !== 'none') ||
          (addPage   && addPage.style.display   !== 'none')) return;
      await refreshStats();
      const dashPage  = document.getElementById('page-dashboard');
      const certsPage = document.getElementById('page-certs');
      const issuePage = document.getElementById('page-issue');
      if (dashPage  && dashPage.style.display  !== 'none') renderTbl('dashTbl', '');
      if (certsPage && certsPage.style.display !== 'none') renderTbl('allTbl', document.getElementById('allQ')?.value || '', document.getElementById('allStatusSel')?.value || '', document.getElementById('allEmailSel')?.value || '', document.getElementById('allRiskSel')?.value || '', document.getElementById('allQuarterSel')?.value || '');
      if (issuePage && issuePage.style.display !== 'none') {
        renderIssueList(document.getElementById('issueSearch')?.value || '');
        renderSentLog();
      }
      updateRealTimeBadge();
    }, 30000);
  }

  function updateRealTimeBadge() {
    const el = document.getElementById('realtimeBadge');
    if (el) el.textContent = 'Live · ' + new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  async function refreshStats() {
    try {
      const ctrl = new AbortController();
      const _t = setTimeout(() => ctrl.abort(), 15_000);
      const r = await fetch(API + '/vapt/certs', { headers:{ Authorization:'Bearer '+TOKEN }, signal: ctrl.signal });
      clearTimeout(_t);
      if (r.status === 401) { toast('Session expired.','err'); doLogout(); return; }
      CERTS = await r.json();
      checkNearExpiryBanner(CERTS); // Proactive near-expiry banner
      const now = new Date();
      let valid=0,expired=0,pending=0,revoked=0,emailSent=0,emailPending=0,nearExpiry=[];
      let expiredPastCount=0, expSoon90Count=0, noExpiryCount=0;
      CERTS.forEach(c => {
        const vu = c.validUntil ? new Date(c.validUntil) : null;
        const isV = c.status==='VALID' && (!vu || vu>=now);
        const st = (c.status||'').toUpperCase();
        if (st==='REVOKED') revoked++;
        else if (st==='PENDING') pending++;
        else if (!isV) expired++;
        else valid++;
        if (c.emailStatus==='SENT') emailSent++; else emailPending++;
        const dl = daysUntil(c.validUntil);
        const isTerminated = st === 'EXPIRED' || st === 'REVOKED';
        if (isTerminated || (dl !== null && dl < 0)) expiredPastCount++;
        else if (dl === null) noExpiryCount++;
        else if (dl <= 90) expSoon90Count++;
        if (!isTerminated && dl!==null && dl>=0 && dl<=45) nearExpiry.push({...c,daysLeft:dl});
      });
      nearExpiry.sort((a,b)=>a.daysLeft-b.daysLeft);
      const total = CERTS.length;
      const vp = total > 0 ? Math.round(valid/total*100) : 0;
      const ep = total > 0 ? Math.round(emailSent/total*100) : 0;
      // Update stat cards
      document.getElementById('stTotal').textContent = total;
      document.getElementById('stValid').textContent = valid;
      document.getElementById('stExpired').textContent = expired;
      document.getElementById('stPending').textContent = pending;
      document.getElementById('stNearExpiry').textContent = nearExpiry.filter(x=>x.daysLeft<=30).length;
      document.getElementById('stEmailSent').textContent = emailSent;
      document.getElementById('stMailNotSent').textContent = emailPending;
      const _sr = document.getElementById('stRevoked'); if (_sr) _sr.textContent = revoked;
      // Sub-labels
      const _sub = document.getElementById('stTotalSub'); if (_sub) _sub.textContent = total > 0 ? `${valid} valid · ${expired} expired` : '—';
      const _vps = document.getElementById('stValidPct'); if (_vps) _vps.textContent = `${vp}% of total`;
      const _eps = document.getElementById('stEmailPct'); if (_eps) _eps.textContent = `${ep}% dispatch rate`;
      const _ess = document.getElementById('stEmailSentSub'); if (_ess) _ess.textContent = `${emailSent} sent successfully`;
      document.getElementById('nbTotal').textContent = total;
      // Sidebar
      document.getElementById('svValid').textContent = valid;
      document.getElementById('svExpired').textContent = expired;
      document.getElementById('svNearExpiry').textContent = nearExpiry.filter(x=>x.daysLeft<=30).length;
      document.getElementById('svEmailSent').textContent = emailSent;
      document.getElementById('svEmailPending').textContent = emailPending;
      // Issue page
      document.getElementById('dispatchSent').textContent = emailSent;
      document.getElementById('dispatchPending').textContent = emailPending;
      // Alert panels
      const now2 = new Date(); now2.setHours(0,0,0,0);
      let exp7=0, exp8to30=0, exp31to90=0, healthyCount=0;
      CERTS.forEach(c => {
        const st2 = (c.status || 'VALID').toUpperCase();
        // EXPIRED and REVOKED by status already counted in expiredPastCount — skip from future buckets
        if (st2 === 'EXPIRED' || st2 === 'REVOKED') return;
        if (!c.validUntil) return;
        const dl2 = Math.round((new Date(c.validUntil).setHours(0,0,0,0) - now2.getTime()) / 86400000);
        if (dl2 < 0) return; // already counted in expiredPastCount
        else if (dl2 <= 7) exp7++;
        else if (dl2 <= 30) exp8to30++;
        else if (dl2 <= 90) exp31to90++;
        else healthyCount++;
      });
      document.getElementById('neCountBadge').textContent = nearExpiry.filter(x=>x.daysLeft<=30).length;
      const expBuckets = {
        expiredPast: expiredPastCount,
        exp7,
        exp8to30,
        exp31to90,
        healthy: healthyCount,
        noExpiry: noExpiryCount
      };
      renderAlertPanels({nearExpiry:nearExpiry.filter(x=>x.daysLeft<=30), pending, emailPending});
      updateCharts({valid,expired,pending,revoked,emailSent,emailPending,nearExpiry:nearExpiry.filter(x=>x.daysLeft<=30),total,buckets:expBuckets});
      updateInsights({valid,expired,pending,emailSent,emailPending,nearExpiry:nearExpiry.filter(x=>x.daysLeft<=30),total,buckets:expBuckets});
      updateRealTimeBadge();
      import('/assets/pubsub.js').then(PSP => PSP.publish(PSP.TOPICS.CERTS_REFRESHED, { count: CERTS.length, certType: 'VAPT' })).catch(() => {});
    } catch {}
  }

  function daysUntil(d) {
    if (!d) return null;
    const t=new Date(d),now=new Date();
    return Math.round((t.setHours(0,0,0,0)-now.setHours(0,0,0,0))/86400000);
  }
  function fmt(d) {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});
  }
  function fmtDt(d) {
    if (!d) return '—';
    const dt = new Date(d);
    return dt.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'})
      + ' · ' + dt.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});
  }
  function fmtTiny(d) {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-GB',{day:'2-digit',month:'short'});
  }

  // ── Recipient Activity timeline — shared by the initial view-modal render
  // and the async live-refresh that follows it, so both stay in sync instead
  // of drifting apart as two hand-copied blocks. emailInfo = the subset of
  // cert fields the timeline needs (emailSentAt/recipientEmail/emailStatus);
  // engagement = the tracked-activity object (emailOpenedAt/certFirstViewedAt/etc).
  function buildEngagementActivityHtml(emailInfo, engagement) {
    const eng = engagement || {};
    const hasAnyEngagement = eng.emailOpenedAt || eng.certFirstViewedAt || eng.docFirstDownloadAt;
    const emailSent = emailInfo.emailStatus === 'SENT';
    const events = [];
    if (emailInfo.emailSentAt)
      events.push({ ts: emailInfo.emailSentAt, icon: '📤', label: 'Email dispatched', color: 'var(--text-sec)',
        sub: emailInfo.recipientEmail ? 'To: ' + emailInfo.recipientEmail : null });
    if (eng.emailOpenedAt)
      events.push({ ts: eng.emailOpenedAt, icon: '📧', label: 'Email opened',
        sub: eng.emailOpenCount > 1 ? eng.emailOpenCount + ' times · most recently ' + fmtDt(eng.emailLastOpenAt) : 'Once',
        color: '#64FFDA', count: eng.emailOpenCount });
    if (eng.certFirstViewedAt)
      events.push({ ts: eng.certFirstViewedAt, icon: '👁', label: 'Certificate viewed',
        sub: eng.certViewCount > 1 ? eng.certViewCount + ' times · last: ' + fmtDt(eng.certLastViewedAt) : 'Once',
        color: 'var(--teal)', count: eng.certViewCount });
    if (eng.docFirstDownloadAt)
      events.push({ ts: eng.docFirstDownloadAt, icon: '⬇', label: 'Document downloaded',
        sub: (eng.docDownloadCount > 1 ? eng.docDownloadCount + ' times · ' : '') + (eng.docLastFile || ''),
        color: 'var(--gold)', count: eng.docDownloadCount });
    events.sort((a, b) => a.ts < b.ts ? -1 : 1);

    const chips = [];
    if (eng.emailOpenCount)   chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(100,255,218,.12);border:1px solid rgba(100,255,218,.3);color:#64FFDA;font-size:.58rem;font-weight:700">📧 ${eng.emailOpenCount} open${eng.emailOpenCount>1?'s':''}</span>`);
    if (eng.certViewCount)    chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(100,255,218,.10);border:1px solid rgba(100,255,218,.3);color:var(--teal);font-size:.58rem;font-weight:700">👁 ${eng.certViewCount} view${eng.certViewCount>1?'s':''}</span>`);
    if (eng.docDownloadCount) chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(212,168,67,.10);border:1px solid rgba(212,168,67,.3);color:var(--gold);font-size:.58rem;font-weight:700">⬇ ${eng.docDownloadCount} download${eng.docDownloadCount>1?'s':''}</span>`);
    if (!hasAnyEngagement && emailSent)
      chips.push(`<span style="padding:3px 9px;border-radius:20px;background:rgba(255,170,46,.07);border:1px solid rgba(255,170,46,.2);color:var(--warn);font-size:.58rem">⏳ Awaiting recipient</span>`);

    return `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px">
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
  }

  function goIssue(id) {
    showPage('issue',document.getElementById('nav-issue'));
    setTimeout(() => { selectIssueCert(id); },100);
  }

  // ── CHARTS  —  update-in-place, no flicker ──
  const _CHART_LEGEND = { display:true, position:'right', labels:{ color:'#7689AE', font:{ size:10 }, boxWidth:10, padding:8 } };

  function _buildStatusChart(a) {
    return new Chart(document.getElementById('statusChart').getContext('2d'), {
      type:'doughnut',
      data:{ labels:['Valid','Expired','Pending','Revoked'], datasets:[{ data:[a.valid,a.expired,a.pending||0,a.revoked||0],
        backgroundColor:['rgba(100,255,218,.55)','rgba(255,170,46,.5)','rgba(255,170,46,.45)','rgba(255,107,138,.5)'],
        borderColor:['#64FFDA','#FFAA2E','#FFAA2E','#FF5C7A'], borderWidth:1.5, hoverOffset:6 }] },
      options:{ responsive:true, maintainAspectRatio:false, cutout:'62%',
        plugins:{ legend:_CHART_LEGEND, tooltip:{ callbacks:{ label:ctx=>` ${ctx.label}: ${ctx.raw} (${a.total>0?Math.round(ctx.raw/a.total*100):0}%)` } } } }
    });
  }
  function _buildEmailChart(a) {
    return new Chart(document.getElementById('emailChart').getContext('2d'), {
      type:'doughnut',
      data:{ labels:['Sent ✓','Not Sent','Pending Certs'], datasets:[{ data:[a.emailSent,a.emailPending,a.pending||0],
        backgroundColor:['rgba(100,255,218,.55)','rgba(255,107,138,.5)','rgba(255,170,46,.4)'],
        borderColor:['#64FFDA','#FF5C7A','#FFAA2E'], borderWidth:1.5, hoverOffset:6 }] },
      options:{ responsive:true, maintainAspectRatio:false, cutout:'62%',
        plugins:{ legend:_CHART_LEGEND, tooltip:{ callbacks:{ label:ctx=>` ${ctx.label}: ${ctx.raw}` } } } }
    });
  }
  function _buildExpiryChart(a) {
    const bk = a.buckets || {};
    return new Chart(document.getElementById('expiryChart').getContext('2d'), {
      type:'bar',
      data:{
        labels:['Expired','≤7d','8–30d','31–90d','>90d','No Expiry'],
        datasets:[{ label:'Certificates',
          data:[bk.expiredPast||0, bk.exp7||0, bk.exp8to30||0, bk.exp31to90||0, bk.healthy||0, bk.noExpiry||0],
          backgroundColor:['rgba(255,107,138,.65)','rgba(255,107,138,.45)','rgba(212,168,67,.55)','rgba(255,170,46,.45)','rgba(100,255,218,.48)','rgba(118,137,174,.38)'],
          borderColor:['#FF5C7A','#FF5C7A','#D4A843','#FFAA2E','#64FFDA','#7689AE'],
          borderWidth:1.5, borderRadius:5 }]
      },
      options:{ responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ display:false }, tooltip:{ callbacks:{ label:ctx=>` ${ctx.raw} cert${ctx.raw!==1?'s':''}` } } },
        scales:{
          x:{ ticks:{ color:'#7689AE', font:{ size:11 }, maxRotation:0 }, grid:{ display:false } },
          y:{ ticks:{ color:'#7689AE', font:{ size:10 }, callback: v => Number.isInteger(v) ? v : '' }, grid:{ color:'rgba(118,137,174,.12)' }, beginAtZero:true }
        }
      }
    });
  }

  function updateCharts(a) {
    if (!window.Chart) return;
    // Status Doughnut — update in-place
    if (STATUS_CHART) {
      STATUS_CHART.data.datasets[0].data = [a.valid,a.expired,a.pending||0,a.revoked||0];
      STATUS_CHART.options.plugins.tooltip.callbacks.label = ctx=>` ${ctx.label}: ${ctx.raw} (${a.total>0?Math.round(ctx.raw/a.total*100):0}%)`;
      STATUS_CHART.update('none');
    } else { STATUS_CHART = _buildStatusChart(a); }
    // Email Doughnut
    if (EMAIL_CHART) {
      EMAIL_CHART.data.datasets[0].data = [a.emailSent,a.emailPending,a.pending||0];
      EMAIL_CHART.update('none');
    } else { EMAIL_CHART = _buildEmailChart(a); }
    // Expiry Bar
    if (EXPIRY_CHART) {
      const bk = a.buckets||{};
      EXPIRY_CHART.data.datasets[0].data = [bk.expiredPast||0,bk.exp7||0,bk.exp8to30||0,bk.exp31to90||0,bk.healthy||0,bk.noExpiry||0];
      EXPIRY_CHART.update('none');
    } else { EXPIRY_CHART = _buildExpiryChart(a); }
  }

  function updateInsights(a) {
    const chips = document.getElementById('insightChips');
    const list = document.getElementById('insightList');
    if (!chips || !list) return;
    const t = a.total || 1;
    const vp = Math.round(a.valid/t*100);
    const ep = Math.round(a.emailSent/t*100);
    // Update expiry radar subtitle
    const erSub = document.getElementById('expiryRadarSub');
    if (erSub) {
      const urgentCount = ((a.buckets||{}).exp7 || 0) + ((a.buckets||{}).expiredPast || 0);
      erSub.textContent = urgentCount > 0
        ? `⚠ ${urgentCount} cert${urgentCount !== 1 ? 's' : ''} need attention · ${a.total} total`
        : `All ${a.total} VAPT certificates tracked · ${(a.buckets||{}).healthy || 0} healthy`;
    }
    chips.innerHTML = [
      `<span class="analytics-chip" style="background:rgba(100,255,218,.1);color:var(--teal);border:1px solid rgba(100,255,218,.2)"><strong>${vp}%</strong> valid</span>`,
      `<span class="analytics-chip" style="background:rgba(100,255,218,.07);color:var(--teal);border:1px solid rgba(100,255,218,.15)"><strong>${ep}%</strong> emailed</span>`,
      (a.pending||0) > 0 ? `<span class="analytics-chip" style="background:rgba(255,170,46,.1);color:#FFAA2E;border:1px solid rgba(255,170,46,.25)">⏳ <strong>${a.pending}</strong> pending</span>` : '',
      a.emailPending > 0 ? `<span class="analytics-chip" style="background:rgba(255,107,138,.08);color:var(--invalid);border:1px solid rgba(255,107,138,.2)">✉ <strong>${a.emailPending}</strong> unsent</span>` : '',
      (a.nearExpiry||[]).length > 0 ? `<span class="analytics-chip" style="background:rgba(255,170,46,.08);color:var(--warn);border:1px solid rgba(255,170,46,.2)">⚠ <strong>${a.nearExpiry.length}</strong> exp ≤30d</span>` : '',
    ].filter(Boolean).join('');
    const items = [];
    if ((a.pending||0) > 0) items.push(`<li style="color:#FFAA2E;border-left:2px solid #FFAA2E;padding-left:8px;margin-bottom:6px"><strong>${a.pending}</strong> VAPT cert(s) awaiting activation — open ⏳ panel below.</li>`);
    if (a.emailPending > 0) items.push(`<li style="color:var(--invalid);border-left:2px solid var(--invalid);padding-left:8px;margin-bottom:6px"><strong>${a.emailPending}</strong> recipient(s) have not received their VAPT credential yet.</li>`);
    if ((a.nearExpiry||[]).filter(x=>x.daysLeft<=7).length > 0) items.push(`<li style="color:var(--invalid);border-left:2px solid var(--invalid);padding-left:8px;margin-bottom:6px"><strong>${a.nearExpiry.filter(x=>x.daysLeft<=7).length}</strong> VAPT cert(s) expire within <strong>7 days</strong>.</li>`);
    if ((a.nearExpiry||[]).length > 0) items.push(`<li style="color:var(--warn);border-left:2px solid var(--warn);padding-left:8px;margin-bottom:6px"><strong>${a.nearExpiry.length}</strong> cert(s) expire within 30 days.</li>`);
    if (a.expired > 0) items.push(`<li style="border-left:2px solid var(--border);padding-left:8px;margin-bottom:6px"><strong>${a.expired}</strong> VAPT cert(s) already expired.</li>`);
    if (items.length === 0) items.push(`<li style="color:var(--teal);border-left:2px solid var(--teal);padding-left:8px">✓ VAPT registry healthy — no action items.</li>`);
    list.innerHTML = items.join('');
    // ── Assessment Activity Breakdown ──
    const bp = document.getElementById('breakdownPanel');
    if (bp) {
      const byMonth = {};
      const byYear = {};
      CERTS.forEach(c => {
        const d = c.assessmentDate || c.issuedAt;
        if (d) {
          const dt = new Date(d);
          const mo = dt.toLocaleString('en-GB',{month:'short',year:'numeric'});
          const yr = dt.getFullYear().toString();
          byMonth[mo] = (byMonth[mo]||0) + 1;
          byYear[yr] = (byYear[yr]||0) + 1;
        }
      });
      const recent = Object.entries(byMonth).slice(-6);
      const rTotal = recent.reduce((s,[,v])=>s+v,0) || 1;
      const yearEntries = Object.entries(byYear).sort((a,b)=>b[0].localeCompare(a[0])).slice(0,4);
      const yTotal = yearEntries.reduce((s,[,v])=>s+v,0) || 1;
      bp.innerHTML = `
        <div style="font-size:.56rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:10px">Assessments by Year</div>
        ${yearEntries.map(([yr,n])=>`
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            <div style="font-size:.7rem;font-weight:600;color:var(--gold);min-width:36px">${yr}</div>
            <div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden">
              <div style="height:100%;width:${Math.round(n/yTotal*100)}%;background:linear-gradient(90deg,var(--gold),rgba(212,168,67,.4));border-radius:3px;transition:width .4s ease"></div>
            </div>
            <div style="font-size:.68rem;color:var(--text-sec);min-width:26px;text-align:right">${n}</div>
          </div>`).join('')}
        <div style="font-size:.56rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin:12px 0 10px">Recent Months (last 6)</div>
        ${recent.length === 0 ? '<div style="font-size:.72rem;color:var(--text-sec)">No assessment date data</div>' :
          recent.map(([mo,n])=>`
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
              <div style="font-size:.65rem;color:var(--teal);min-width:64px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${mo}</div>
              <div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden">
                <div style="height:100%;width:${Math.round(n/rTotal*100)}%;background:var(--teal);opacity:.55;border-radius:3px;transition:width .4s ease"></div>
              </div>
              <div style="font-size:.68rem;color:var(--text-sec);min-width:22px;text-align:right">${n}</div>
            </div>`).join('')}
      `;
    }
  }

  function renderAlertPanels(a) {
    // ── Near Expiry ──
    const neEl = document.getElementById('nearExpiryList');
    if (neEl) {
      if (!a.nearExpiry.length) {
        neEl.innerHTML = '<div style="padding:28px;text-align:center;color:var(--text-sec);font-size:.78rem">✓ All VAPT certificates healthy</div>';
      } else {
        neEl.innerHTML = a.nearExpiry.map(c => {
          const dl=c.daysLeft, bc=dl<=7?'crit':dl<=20?'warn':'ok', label=dl===0?'TODAY':dl+'d';
          const sId=escHtml(c.id), sName=escHtml(c.recipientName);
          return `<div class="ne-item" data-action="editCert" data-id="${sId}">
            <div class="ne-days-badge ${bc}">${label}</div>
            <div style="flex:1;min-width:0">
              <div style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--gold)">${sId}</div>
              <div style="font-size:.76rem;color:var(--text-bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${sName||'—'}</div>
              <div style="font-size:.62rem;color:var(--text-sec)">Valid until ${fmt(c.validUntil)} · ${dl===0?'expires today':dl+' day'+(dl===1?'':'s')+' left'}</div>
            </div>
            <button class="btn btn-ghost btn-sm" style="font-size:.58rem;padding:3px 7px" data-action="editCert" data-id="${sId}">Edit</button>
          </div>`;
        }).join('');
      }
    }
    // ── Pending Activation ──
    const pendEl = document.getElementById('pendingCertList');
    const pendCountEl = document.getElementById('pendingCountBadge');
    if (pendEl && pendCountEl) {
      const pendingCerts = CERTS.filter(c=>(c.status||'').toUpperCase()==='PENDING');
      pendCountEl.textContent = pendingCerts.length;
      if (!pendingCerts.length) {
        pendEl.innerHTML = '<div style="padding:28px;text-align:center;color:var(--text-sec);font-size:.78rem">✓ No pending certificates</div>';
      } else {
        pendEl.innerHTML = pendingCerts.map(c=>{
          const sId=escHtml(c.id), sName=escHtml(c.recipientName), sIMO=escHtml(c.vesselIMO);
          return `<div class="ne-item" data-action="editCert" data-id="${sId}">
            <div style="flex-shrink:0;width:30px;height:30px;border-radius:8px;background:rgba(255,170,46,.1);border:1px solid rgba(255,170,46,.25);display:flex;align-items:center;justify-content:center;font-size:.9rem">⏳</div>
            <div style="flex:1;min-width:0">
              <div style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--gold)">${sId}</div>
              <div style="font-size:.76rem;color:var(--text-bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${sName||'—'}${sIMO?' · IMO '+sIMO:''}</div>
              <div style="font-size:.62rem;color:#FFAA2E">Not yet publicly verifiable — activate to enable</div>
            </div>
            <div style="display:flex;gap:5px">
              <button class="btn btn-sm" style="font-size:.58rem;padding:3px 7px;background:rgba(100,255,218,.08);border:1px solid rgba(100,255,218,.22);color:var(--teal)" data-action="activateCert" data-id="${sId}">✓ Activate</button>
              <button class="btn btn-ghost btn-sm" style="font-size:.58rem;padding:3px 7px" data-action="editCert" data-id="${sId}">Edit</button>
            </div>
          </div>`;
        }).join('');
      }
    }
    // ── Emails Not Sent ──
    const epEl = document.getElementById('emailPendingList');
    const epCountEl = document.getElementById('emailPendingCountBadge');
    if (epEl && epCountEl) {
      const unsent  = CERTS.filter(c => c.recipientEmail && c.emailStatus !== 'SENT');
      const noEmail = CERTS.filter(c => !c.recipientEmail && c.emailStatus !== 'SENT' && (c.status||'').toUpperCase() !== 'PENDING');
      const allMissing = [...unsent, ...noEmail];
      epCountEl.textContent = allMissing.length;
      if (!allMissing.length) {
        epEl.innerHTML = '<div style="padding:28px;text-align:center;color:var(--text-sec);font-size:.78rem">✓ All credentials dispatched</div>';
      } else {
        epEl.innerHTML = allMissing.map(c => {
          const isPending = (c.status||'').toUpperCase() === 'PENDING';
          const hasEmail  = !!c.recipientEmail;
          const sId=escHtml(c.id), sName=escHtml(c.recipientName), sEmail=escHtml(c.recipientEmail);
          const subColor  = isPending ? '#FFAA2E' : hasEmail ? 'var(--invalid)' : 'var(--warn)';
          const subText   = isPending ? '⏳ Cert pending — activate first' : hasEmail ? sEmail : '⚠ No email address on record';
          return `<div class="ne-item" style="gap:10px;cursor:${(!isPending&&hasEmail)?'pointer':'default'}" ${(!isPending&&hasEmail)?`data-action="goIssue" data-id="${sId}"`:''}>
            <div style="flex-shrink:0;width:30px;height:30px;border-radius:8px;background:rgba(255,107,138,.08);border:1px solid rgba(255,107,138,.2);display:flex;align-items:center;justify-content:center">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--invalid)" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
            </div>
            <div style="flex:1;min-width:0">
              <div style="font-family:'JetBrains Mono',monospace;font-size:.64rem;color:var(--gold)">${sId}</div>
              <div style="font-size:.76rem;color:var(--text-bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${sName||'—'}</div>
              <div style="font-size:.61rem;color:${subColor};margin-top:1px">${subText}</div>
            </div>
            <div style="display:flex;gap:5px;flex-shrink:0">
              ${!isPending && hasEmail
                ? `<button class="btn btn-issue btn-sm" style="font-size:.58rem;padding:4px 9px;white-space:nowrap;border-radius:7px" data-action="goIssue" data-id="${sId}">
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg>
                    Send
                  </button>`
                : !isPending && !hasEmail
                ? `<button class="btn btn-ghost btn-sm" style="font-size:.58rem;padding:4px 9px" data-action="editCert" data-id="${sId}">+ Email</button>`
                : `<button class="btn btn-sm" style="font-size:.58rem;padding:4px 9px;background:rgba(100,255,218,.08);border:1px solid rgba(100,255,218,.22);color:var(--teal)" data-action="activateCert" data-id="${sId}">Activate</button>`
              }
            </div>
          </div>`;
        }).join('');
      }
    }
  }

  // ── TABLE ──
  function clearAllFilters() {
    ['allQ','allStatusSel','allEmailSel','allRiskSel','allQuarterSel'].forEach(id => {
      const el=document.getElementById(id); if(el) el.value='';
    });
    renderTbl('allTbl','','','','','');
    const cb=document.getElementById('allClearFilters'); if(cb) cb.style.display='none';
  }
  function renderTbl(id, q, statusFilter, emailFilter, riskFilter, quarterFilter) {
    const el = document.getElementById(id);
    // Client role sees All Certificates grouped by vessel (CST + VAPT nested
    // together, expand-in-place) instead of the flat per-cert admin table —
    // avoids switching to the CST dashboard just to see the other cert type.
    // Admins are completely unaffected; only 'allTbl' branches here.
    if (id === 'allTbl' && document.documentElement.classList.contains('role-client')) {
      renderClientVesselTbl(q, statusFilter, emailFilter, riskFilter, quarterFilter);
      return;
    }
    let list = CERTS;
    if (q) { const ql=q.toLowerCase(); list=list.filter(c=>c.id.toLowerCase().includes(ql)||(c.recipientName||'').toLowerCase().includes(ql)||(c.vesselIMO||'').includes(ql)||(c.vesselName||'').toLowerCase().includes(ql)); }
    if (statusFilter) {
      if (statusFilter === 'EXPIRED') {
        const _now = new Date();
        list = list.filter(c => (c.status === 'VALID' && c.validUntil && new Date(c.validUntil) < _now) || c.status === 'EXPIRED');
      } else if (statusFilter === 'VALID') {
        const _now = new Date();
        list = list.filter(c => c.status === 'VALID' && (!c.validUntil || new Date(c.validUntil) >= _now));
      } else {
        list = list.filter(c => c.status === statusFilter);
      }
    } else if (filterStatus) list=list.filter(c=>c.status===filterStatus);
    if (emailFilter==='SENT') list=list.filter(c=>c.emailStatus==='SENT');
    else if (emailFilter==='NOT_SENT') list=list.filter(c=>c.emailStatus!=='SENT');
    if (riskFilter) list=list.filter(c=>(c.riskLevel||'').toUpperCase()===riskFilter.toUpperCase());
    if (quarterFilter) {
      const qNum = parseInt(quarterFilter, 10);
      list = list.filter(c => {
        const d = c.assessmentDate || c.issuedAt;
        if (!d) return false;
        const month = new Date(d).getMonth() + 1;
        const cq = month <= 3 ? 1 : month <= 6 ? 2 : month <= 9 ? 3 : 4;
        return cq === qNum;
      });
    }
    // Update count badge
    const countEl=document.getElementById('allCertCount');
    if(countEl) countEl.innerHTML=`<strong>${list.length}</strong> records`;
    const cb=document.getElementById('allClearFilters');
    if(cb) cb.style.display=(q||statusFilter||emailFilter||riskFilter||quarterFilter)?'':'none';
    if (!list.length) { el.innerHTML='<div class="empty-state"><h3>No VAPT certificates match these filters</h3><p style="font-size:.8rem;color:var(--text-sec);margin-top:4px">Try adjusting your search or clearing filters.</p></div>'; return; }
    const isDash=id==='dashTbl';
    el.innerHTML = `<div class="tbl-scroll-wrap" style="overflow-x:auto"><table style="min-width:1000px;width:100%;border-collapse:collapse"><colgroup>
      <col style="width:36px"><!-- Select -->
      <col style="width:148px"><!-- Cert ID -->
      <col style="width:175px"><!-- Vessel -->
      <col style="width:80px"> <!-- IMO -->
      <col style="width:110px"><!-- Assessment Date -->
      <col style="width:110px"><!-- Status -->
      <col style="width:90px"> <!-- Risk -->
      <col style="width:120px"><!-- Valid Until -->
      <col style="width:70px"> <!-- Email -->
      <col style="width:130px"><!-- Engagement -->
      <col style="width:68px"> <!-- Image -->
      <col style="min-width:180px"><!-- Actions (fill rest) -->
    </colgroup><thead><tr>
      <th style="padding:8px 6px;width:36px;text-align:center"><input type="checkbox" id="selAllCb_${id}" data-change-action="toggleSelectAll" data-tbl="${id}" style="accent-color:#64FFDA;width:14px;height:14px" title="Select all"></th><th>Cert ID</th><th>Vessel</th><th>IMO</th><th>Assessment Date</th><th>Status</th><th>Risk</th><th>Valid Until</th><th>Email</th><th>Engagement</th><th>Image</th><th>Actions</th>
    </tr></thead><tbody>` + (isDash?list.slice(0,10):list).map(c => {
      const now=new Date(),vu=c.validUntil?new Date(c.validUntil):null;
      const isV=c.status==='VALID'&&(!vu||vu>=now);
      const pillCls=c.status==='PENDING'?'pending':(c.status==='REVOKED'?'revoked':isV?'valid':'expired');
      const dl=daysUntil(c.validUntil);
      let vlStr=fmt(c.validUntil);
      let vlColor='var(--text-sec)';
      if(dl!==null){if(dl<0){vlStr+=` · ${Math.abs(dl)}d ago`;vlColor='var(--invalid)';}else if(dl===0){vlStr+=' · today';vlColor='var(--warn)';}else if(dl<=30){vlStr+=` · ${dl}d`;vlColor='var(--warn)';}else{vlStr+=` · ${dl}d`;vlColor=isV?'var(--teal)':'var(--text-sec)';}}
      const imgEl = c.certificateImage
        ? `<img class="thumb" src="${c.certificateImage}" loading="lazy" data-action="openLB" data-onerror-action="hideImgShowSibling" /><div class="no-img" style="display:none">—</div>`
        : '<div class="no-img">—</div>';
      const emailCls=c.emailStatus==='SENT'?'sent':'not-sent';
      const canSend=c.recipientEmail&&c.emailStatus!=='SENT'&&c.status==='VALID';
      const eng = c.engagement || {};
      const emailSentV = c.emailStatus === 'SENT';
      const engPartsV = [];
      if (eng.emailOpenCount)
        engPartsV.push(`<span class="eng-badge eng-open" title="Email opened ${eng.emailOpenCount}× · First: ${fmtDt(eng.emailOpenedAt)} · Last: ${fmtDt(eng.emailLastOpenAt)}">📧 <strong>${eng.emailOpenCount}</strong></span>`);
      else if (emailSentV)
        engPartsV.push(`<span class="eng-badge" style="opacity:.4;font-size:.58rem" title="Sent, not yet opened">📧 0</span>`);
      if (eng.certViewCount)
        engPartsV.push(`<span class="eng-badge eng-view" title="Viewed ${eng.certViewCount}× · First: ${fmtDt(eng.certFirstViewedAt)} · Last: ${fmtDt(eng.certLastViewedAt)}">👁 <strong>${eng.certViewCount}</strong></span>`);
      if (eng.docDownloadCount)
        engPartsV.push(`<span class="eng-badge eng-dl" title="Downloaded ${eng.docDownloadCount}× · Last: ${fmtDt(eng.docLastDownloadAt)}${eng.docLastFile?' · '+eng.docLastFile:''}">⬇ <strong>${eng.docDownloadCount}</strong></span>`);
      const engCell = engPartsV.length
        ? `<div style="display:flex;flex-wrap:wrap;gap:3px">${engPartsV.join('')}</div>`
        : (emailSentV
        ? `<span class="eng-badge" style="background:rgba(255,170,46,.08);border:1px solid rgba(255,170,46,.22);color:var(--warn);font-size:.57rem;opacity:.85" title="Email sent — awaiting recipient interaction">⏳ Awaiting</span>`
        : `<span style="color:var(--text-sec);font-size:.6rem;font-style:italic;opacity:.6">No activity</span>`);
      const safeId    = escHtml(c.id);
      const safeName  = escHtml(c.recipientName || c.vesselName);
      const safeVessel = escHtml(c.vesselName);
      const safeIMO   = escHtml(c.vesselIMO);
      const safeEmail = escHtml(c.recipientEmail);
      const groupName = _imoGroupMap[(c.vesselIMO||'').toUpperCase()] || '';
      const groupBadge = groupName ? `<div style="display:inline-flex;align-items:center;gap:4px;margin-top:3px;padding:1px 7px;border-radius:20px;background:rgba(100,255,218,.1);border:1px solid rgba(100,255,218,.25);font-size:.58rem;color:var(--teal);font-weight:600;letter-spacing:.06em"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2h5M12 12a4 4 0 100-8 4 4 0 000 8z"/></svg>${escHtml(groupName)}</div>` : '';
      const selCell = `<td style="padding:6px 6px;text-align:center;vertical-align:middle"><input type="checkbox" class="row-sel-cb" data-imo="${safeIMO}" data-tbl="${id}" data-change-action="toggleRowSelect" style="accent-color:#64FFDA;width:14px;height:14px" ${_selectedRows.has(c.vesselIMO||'')?'checked':''}></td>`;
      const RISK_STYLE = {
        CRITICAL: { emoji: '🔴', color: 'var(--invalid)' },
        HIGH:     { emoji: '🟠', color: 'var(--warn)' },
        MEDIUM:   { emoji: '🟡', color: 'var(--warn)' },
        LOW:      { emoji: '🟢', color: 'var(--teal)' },
      };
      const riskInfo = RISK_STYLE[(c.riskLevel || '').toUpperCase()];
      const riskCell = riskInfo
        ? `<span style="font-size:.7rem;color:${riskInfo.color}">${riskInfo.emoji} ${escHtml(c.riskLevel)}</span>`
        : '<span style="color:var(--text-sec);font-size:.68rem">—</span>';
      return `<tr>${selCell}
        <td><span class="cid" title="${safeId}">${safeId}</span></td>
        <td class="name-cell" style="cursor:pointer" title="View in public portal" data-action="viewCertNewTabRow" data-id="${safeId}"><div style="color:var(--text-bright);font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${safeName||'—'}</div>${c.vesselName&&c.vesselName!==c.recipientName?`<div style="font-size:.68rem;color:var(--text-sec)">${safeVessel}</div>`:''} ${groupBadge}</td>
        <td><span style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--text-sec)">${safeIMO||'—'}</span></td>
        <td style="font-size:.76rem;color:var(--text-sec)">${fmt(c.assessmentDate)}</td>
        <td><select class="inline-status-sel status-${c.status?c.status.toLowerCase():'pending'}" data-id="${safeId}" data-change-action="quickStatusChange" title="Change status">
          <option value="VALID" ${c.status==='VALID'?'selected':''}>✓ VALID</option>
          <option value="PENDING" ${c.status==='PENDING'?'selected':''}>⏳ PENDING</option>
          <option value="EXPIRED" ${c.status==='EXPIRED'?'selected':''}>⏰ EXPIRED</option>
          <option value="REVOKED" ${c.status==='REVOKED'?'selected':''}>🚫 REVOKED</option>
        </select></td>
        <td>${riskCell}</td>
        <td style="color:${vlColor};font-size:.76rem">${vlStr}</td>
        <td><span class="pill ${emailCls}" title="${safeEmail||'no email'}">${c.emailStatus==='SENT'?'✓ Sent':'—'}</span></td>
        <td class="eng-cell">${engCell}</td>
        <td>${imgEl}</td>
        <td><div class="act-grp">
          <button class="btn btn-ghost btn-sm" data-action="viewCertNewTab" data-id="${safeId}">View</button>
          <button class="btn btn-teal btn-sm" data-action="editCert" data-id="${safeId}">Edit</button>
          <button class="btn btn-ghost btn-sm" title="Copy verification URL" data-action="copyEncUrl" data-id="${safeId}" style="font-size:.58rem">🔒</button>
          ${canSend?`<button class="btn btn-issue btn-sm" data-action="goIssue" data-id="${safeId}">✉</button>`:''}
          <button class="btn btn-ghost btn-sm" title="Assign vessel to group" data-action="openAssignGroup" data-imo="${safeIMO}" data-name="${safeVessel}">👥</button>
          <button class="btn btn-danger btn-sm" data-action="askDelete" data-id="${safeId}">Delete</button>
        </div></td>
      </tr>`;
    }).join('') + '</tbody></table></div>';
  }

  // ── Client role — combined CST+VAPT vessel view (All Certificates) ──
  // The "other" cert type, fetched only once we know the session is client
  // role (see scheduleTokenExpiryWarning's /api/auth/verify check above) —
  // normal admins never trigger this extra request.
  let CLIENT_OTHER_CERTS = [];
  let _clientVesselExpanded = new Set();

  async function loadClientOtherCerts() {
    try {
      const r = await fetch(API + '/certs', { headers: { Authorization: 'Bearer ' + TOKEN } });
      if (r.ok) CLIENT_OTHER_CERTS = await r.json();
    } catch { /* All Certificates still renders with whatever loaded so far */ }
  }

  function _clientVesselKey(c) { return (c.vesselIMO || c.vesselName || 'unknown').toString().toUpperCase(); }
  function _clientIsValid(c) {
    if (c.status !== 'VALID') return false;
    const vu = c.validUntil ? new Date(c.validUntil) : null;
    return !vu || vu >= new Date();
  }

  const CLIENT_RISK_STYLE = {
    CRITICAL: { emoji: '🔴', color: 'var(--invalid)' },
    HIGH:     { emoji: '🟠', color: 'var(--warn)' },
    MEDIUM:   { emoji: '🟡', color: 'var(--warn)' },
    LOW:      { emoji: '🟢', color: 'var(--teal)' },
  };
  const CLIENT_Q_COLORS = { Q1: '#64FFDA', Q2: '#D4A843', Q3: '#B47EFF', Q4: '#FF5C7A' };

  function _clientCertRow(c, isCst) {
    let badge;
    if (isCst && c.complianceQuarter) {
      const qc = CLIENT_Q_COLORS[c.complianceQuarter.toUpperCase()] || 'var(--text-sec)';
      badge = `<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:.62rem;font-weight:700;letter-spacing:.06em;background:${qc}1F;border:1px solid ${qc};color:${qc}">${escHtml(c.complianceQuarter)}</span>`;
    } else if (!isCst && c.riskLevel) {
      const ri = CLIENT_RISK_STYLE[c.riskLevel.toUpperCase()] || { emoji: '', color: 'var(--text-sec)' };
      badge = `<span style="font-size:.72rem;color:${ri.color}">${ri.emoji} ${escHtml(c.riskLevel)}</span>`;
    } else {
      badge = '<span style="color:var(--text-sec);font-size:.7rem">—</span>';
    }
    const st = (c.status || 'PENDING').toUpperCase();
    const stColor = st === 'VALID' ? 'var(--teal)' : st === 'REVOKED' ? 'var(--invalid)' : st === 'EXPIRED' ? 'var(--warn)' : 'var(--text-sec)';
    const stBg    = st === 'VALID' ? 'rgba(100,255,218,.1)' : st === 'REVOKED' ? 'rgba(255,107,138,.1)' : st === 'EXPIRED' ? 'rgba(255,170,46,.1)' : 'rgba(255,255,255,.05)';
    const img = c.certificateImage || '';
    const imgCell = img
      ? `<img src="${img}" loading="lazy" style="width:34px;height:34px;object-fit:cover;border-radius:6px;border:1px solid var(--border);cursor:pointer" data-action="openLB" title="View certificate" />`
      : `<div style="width:34px;height:34px;border-radius:6px;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;color:var(--text-sec);font-size:.6rem">—</div>`;
    const actionsCell = img
      ? `<button class="btn btn-ghost btn-sm" data-action="openLB" data-url="${img}" title="View certificate" style="padding:5px 9px">👁 View</button>
         <a class="btn btn-ghost btn-sm" href="${img}" download="${escHtml(c.id)}.png" title="Download certificate" style="padding:5px 9px;text-decoration:none">⬇</a>`
      : `<span style="font-size:.62rem;color:var(--text-sec);opacity:.6">No image</span>`;
    return `<div style="display:flex;align-items:center;gap:10px;padding:9px 4px;border-bottom:1px solid var(--border)">
      ${imgCell}
      <div style="flex:1;min-width:0">
        <div style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:${isCst ? 'var(--gold)' : 'var(--teal)'}">${escHtml(c.id)}</div>
        <div style="font-size:.72rem;color:var(--text-sec);margin-top:2px">${escHtml(c.recipientName || '—')}</div>
      </div>
      ${badge}
      <span style="display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;font-size:.62rem;font-weight:700;letter-spacing:.05em;background:${stBg};border:1px solid ${stColor}66;color:${stColor}">${st}</span>
      <span style="font-size:.68rem;color:var(--text-sec);min-width:78px;text-align:right">${fmt(c.validUntil)}</span>
      <div style="display:flex;gap:5px;flex-shrink:0">${actionsCell}</div>
    </div>`;
  }
  function _clientCertSection(title, color, list, isCst) {
    const rows = list.length
      ? list.map(c => _clientCertRow(c, isCst)).join('')
      : `<div style="padding:10px 4px;font-size:.72rem;color:var(--text-sec)">No ${escHtml(title)} records for this vessel.</div>`;
    return `<div style="margin-bottom:14px">
      <div style="font-size:.64rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:${color};margin-bottom:6px">${escHtml(title)} (${list.length})</div>
      ${rows}
    </div>`;
  }

  function toggleClientVesselRow(key) {
    if (_clientVesselExpanded.has(key)) _clientVesselExpanded.delete(key);
    else _clientVesselExpanded.add(key);
    renderTbl('allTbl',
      document.getElementById('allQ')?.value || '',
      document.getElementById('allStatusSel')?.value || '',
      document.getElementById('allEmailSel')?.value || '',
      document.getElementById('allRiskSel')?.value || '',
      document.getElementById('allQuarterSel')?.value || '');
  }
  window.toggleClientVesselRow = toggleClientVesselRow;

  function renderClientVesselTbl(q, statusFilter, emailFilter, riskFilter, quarterFilter) {
    const el = document.getElementById('allTbl');
    if (!el) return;

    let list = [...(CERTS || []).map(c => Object.assign({ _type: 'VAPT' }, c)),
                ...(CLIENT_OTHER_CERTS || []).map(c => Object.assign({ _type: 'CST' }, c))];
    if (q) {
      const ql = q.toLowerCase();
      list = list.filter(c => c.id.toLowerCase().includes(ql) || (c.recipientName || '').toLowerCase().includes(ql) || (c.vesselIMO || '').toLowerCase().includes(ql) || (c.vesselName || '').toLowerCase().includes(ql));
    }
    if (statusFilter) {
      if (statusFilter === 'EXPIRED') {
        const now = new Date();
        list = list.filter(c => (c.status === 'VALID' && c.validUntil && new Date(c.validUntil) < now) || c.status === 'EXPIRED');
      } else if (statusFilter === 'VALID') {
        const now = new Date();
        list = list.filter(c => c.status === 'VALID' && (!c.validUntil || new Date(c.validUntil) >= now));
      } else {
        list = list.filter(c => c.status === statusFilter);
      }
    }
    if (emailFilter === 'SENT') list = list.filter(c => c.emailStatus === 'SENT');
    else if (emailFilter === 'NOT_SENT') list = list.filter(c => c.emailStatus !== 'SENT');
    // Risk/quarter are VAPT/CST-specific fields — filtering by either narrows
    // to that cert type, but a vessel still shows if it has any matching
    // record (its other-type records for that vessel stay visible nested).
    if (riskFilter) list = list.filter(c => c._type === 'VAPT' && (c.riskLevel || '').toUpperCase() === riskFilter.toUpperCase());
    if (quarterFilter) {
      const qNum = parseInt(quarterFilter, 10);
      list = list.filter(c => {
        if (c._type !== 'VAPT') return false;
        const d = c.assessmentDate || c.issuedAt;
        if (!d) return false;
        const month = new Date(d).getMonth() + 1;
        const cq = month <= 3 ? 1 : month <= 6 ? 2 : month <= 9 ? 3 : 4;
        return cq === qNum;
      });
    }

    const vessels = new Map();
    list.forEach(c => {
      const key = _clientVesselKey(c);
      if (!vessels.has(key)) vessels.set(key, { imo: c.vesselIMO || '', name: c.vesselName || c.vesselIMO || 'Unknown Vessel', cst: [], vapt: [] });
      const v = vessels.get(key);
      if (!v.imo && c.vesselIMO) v.imo = c.vesselIMO;
      (c._type === 'CST' ? v.cst : v.vapt).push(c);
    });

    const countEl = document.getElementById('allCertCount');
    if (countEl) countEl.innerHTML = `<strong>${vessels.size}</strong> vessel${vessels.size !== 1 ? 's' : ''}`;
    const cb = document.getElementById('allClearFilters');
    if (cb) cb.style.display = (q || statusFilter || emailFilter || riskFilter || quarterFilter) ? '' : 'none';

    if (!vessels.size) {
      el.innerHTML = '<div class="empty-state"><h3>No vessels match these filters</h3><p style="font-size:.8rem;color:var(--text-sec);margin-top:4px">Try adjusting your search or clearing filters.</p></div>';
      return;
    }

    const rows = [...vessels.entries()].sort((a, b) => a[1].name.localeCompare(b[1].name));
    el.innerHTML = `<div class="tbl-scroll-wrap" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:640px"><thead><tr style="border-bottom:1px solid var(--border);text-align:left">
      <th style="padding:8px 10px;font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-sec)">Vessel</th>
      <th style="padding:8px 10px;font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-sec)">IMO</th>
      <th style="padding:8px 10px;font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--gold)">CST</th>
      <th style="padding:8px 10px;font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--teal)">VAPT</th>
      <th style="padding:8px 10px;font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-sec)">Valid</th>
      <th style="padding:8px 10px;font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-sec)">View</th>
    </tr></thead><tbody>` + rows.map(([key, v]) => {
      const total = v.cst.length + v.vapt.length;
      const validCount = v.cst.filter(_clientIsValid).length + v.vapt.filter(_clientIsValid).length;
      const expanded = _clientVesselExpanded.has(key);
      const mainRow = `<tr style="border-bottom:1px solid var(--border);cursor:pointer" data-action="toggleClientVesselRow" data-imo="${escHtml(key)}">
        <td style="padding:10px;font-weight:600;color:var(--text-bright)">${escHtml(v.name)}</td>
        <td style="padding:10px;font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--text-sec)">${escHtml(v.imo || '—')}</td>
        <td style="padding:10px;color:var(--gold);font-weight:600">${v.cst.length}</td>
        <td style="padding:10px;color:var(--teal);font-weight:600">${v.vapt.length}</td>
        <td style="padding:10px;color:var(--teal)">${validCount}/${total}</td>
        <td style="padding:10px"><button class="btn btn-ghost btn-sm" data-action="toggleClientVesselRow" data-imo="${escHtml(key)}">${expanded ? '▲ Hide' : '▼ View'}</button></td>
      </tr>`;
      const nestedRow = expanded
        ? `<tr><td colspan="6" style="padding:16px 20px;background:var(--navy-mid)">${_clientCertSection('CST Training', 'var(--gold)', v.cst, true)}${_clientCertSection('VAPT Assessment', 'var(--teal)', v.vapt, false)}</td></tr>`
        : '';
      return mainRow + nestedRow;
    }).join('') + `</tbody></table></div>`;
  }

  // ── PAGES ──
  function showPage(name, el) {
    ['dashboard','certs','add','issue','csv'].forEach(p => {
      document.getElementById('page-'+p).style.display = p===name?'':'none';
    });
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    if (el) el.classList.add('active');
    const titles={
      dashboard:['VAPT Dashboard','Admin › VAPT › Overview'],
      certs:['All VAPT Certificates','Admin › VAPT › Certificates'],
      add:[editingId?'Edit VAPT Certificate':'Add VAPT Certificate','Admin › VAPT › '+(editingId?'Edit':'Add')],
      issue:['Issue VAPT Credentials','Admin › VAPT › Issue Credentials'],
      csv:['Import VAPT CSV','Admin › VAPT › CSV Import']
    };
    const [t,b]=titles[name]||['',''];
    document.getElementById('pageTitle').textContent=t;
    document.getElementById('pageBread').textContent=b;
    if (name==='certs') renderTbl('allTbl','','','');
    else if (typeof clearSelections === 'function') clearSelections();
    if (name==='issue') { renderIssueList(''); refreshStats(); renderSentLog(); }
  }

  // ── ADD / EDIT ──
  function startAdd() {
    editingId=null; imgFile=null;
    document.getElementById('addPageTitle').textContent='Add VAPT Certificate';
    document.getElementById('saveTxt').textContent='Save Certificate';
    clearForm();
    document.getElementById('fAssessmentDate').value=new Date().toISOString().slice(0,10);
    autoSetValidUntil(); updatePreview(); updateCompletion();
    showPage('add',document.getElementById('nav-add'));
  }

  function autoSetValidUntil() {
    const ad=document.getElementById('fAssessmentDate').value;
    if (!ad) return;
    const d=new Date(ad); d.setFullYear(d.getFullYear()+1);
    document.getElementById('fValidUntil').value=d.toISOString().slice(0,10);
  }
  function autoGenId() {
    if (editingId) return;
    const imo=document.getElementById('fImo').value.trim();
    const ad=document.getElementById('fAssessmentDate').value;
    if (!imo||!ad||document.getElementById('fId').value) return;
    const d=new Date(ad);
    const mm=String(d.getMonth()+1).padStart(2,'0');
    const yy=String(d.getFullYear()).slice(-2);
    document.getElementById('fId').value=`${(window.APP_CONFIG&&window.APP_CONFIG.certFormats)?window.APP_CONFIG.certFormats.vaptPrefix:'VAP'}-${imo}-${mm}${yy}`;
    updatePreview();
  }

  function onVesselNameInput() {
    const vn = document.getElementById('fVesselName').value;
    const recip = document.getElementById('fRecipientName');
    // Mirror the vessel name verbatim — including whatever MV/MT prefix was
    // typed — matching the CST dashboard's convention. Never invent a prefix.
    if (vn && (!recip.value || recip.value === autoRecipFrom)) {
      recip.value = vn;
      autoRecipFrom = vn;
    }
    updatePreview();
  }

  function clearForm() {
    autoRecipFrom = '';
    ['fId','fImo','fVesselName','fRecipientName','fRecipientEmail'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
    document.getElementById('fAssessmentDate').value='';
    document.getElementById('fValidUntil').value='';
    document.getElementById('fVerifiedBy').value=(window.APP_CONFIG?window.APP_CONFIG.vapt.verifiedBy:'Gaurav Singh');
    document.getElementById('fVerifierTitle').value=(window.APP_CONFIG?window.APP_CONFIG.vapt.verifierTitle:'CISO — Synergy Group');
    document.getElementById('fAssessingOrg').value=(window.APP_CONFIG?window.APP_CONFIG.vapt.assessingOrg:'Synergy Cybersecurity Team');
    document.getElementById('fStatus').value='VALID';
    document.getElementById('fRiskLevel').value='';
    document.getElementById('fFrameworks').value=(window.APP_CONFIG?window.APP_CONFIG.vapt.frameworks:'Cybersecurity Framework / OWASP / IMO Framework / ISO 27001:2013');
    document.getElementById('fScopeItems').value=(window.APP_CONFIG?window.APP_CONFIG.vapt.scopeItems:'Access Control (USB/Data/Login/Domain/Email/Assets),IT/OT Risk analysis,Vessel Cyber security awareness,Software Version Control (IT/OT),Backups & Disaster Recovery,IT Drills & Internal Audits');
    document.getElementById('fIssuerEmail').value=(window.APP_CONFIG?window.APP_CONFIG.contact.vaptEmail:'vapt@synergyship.com');
    document.getElementById('fNotes').value='Re-assessment recommended within 2 weeks from date of participation.';
    document.getElementById('uploadDefault').style.display='block';
    document.getElementById('uploadPrev').style.display='none';
    imgFile=null;
    pendingPdfs=[]; savedAttachments=[]; renderAttachList();
  }

  function editCert(id) {
    const c=CERTS.find(x=>x.id===id); if (!c) return;
    editingId=id; imgFile=null;
    autoRecipFrom = '';
    document.getElementById('addPageTitle').textContent='Edit VAPT Certificate';
    document.getElementById('saveTxt').textContent='Update Certificate';
    document.getElementById('fId').value=c.id;
    document.getElementById('fImo').value=c.vesselIMO||'';
    document.getElementById('fVesselName').value=c.vesselName||'';
    document.getElementById('fRecipientName').value=c.recipientName||'';
    document.getElementById('fAssessmentDate').value=c.assessmentDate||'';
    document.getElementById('fValidUntil').value=c.validUntil||'';
    document.getElementById('fVerifiedBy').value=c.verifiedBy||(window.APP_CONFIG?window.APP_CONFIG.vapt.verifiedBy:'Gaurav Singh');
    document.getElementById('fVerifierTitle').value=c.verifierTitle||(window.APP_CONFIG?window.APP_CONFIG.vapt.verifierTitle:'CISO — Synergy Group');
    document.getElementById('fAssessingOrg').value=c.assessingOrg||(window.APP_CONFIG?window.APP_CONFIG.vapt.assessingOrg:'Synergy Cybersecurity Team');
    document.getElementById('fStatus').value=c.status||'VALID';
    document.getElementById('fRiskLevel').value=c.riskLevel||'';
    document.getElementById('fFrameworks').value=c.frameworks||'';
    document.getElementById('fScopeItems').value=c.scopeItems||'';
    document.getElementById('fRecipientEmail').value=c.recipientEmail||'';
    document.getElementById('fIssuerEmail').value=c.issuerEmail||(window.APP_CONFIG?window.APP_CONFIG.contact.vaptEmail:'vapt@synergyship.com');
    document.getElementById('fNotes').value=c.notes||'';
    if (c.certificateImage) {
      document.getElementById('uploadDefault').style.display='none';
      document.getElementById('uploadPrev').style.display='block';
      document.getElementById('prevImg').src=c.certificateImage;
      document.getElementById('prevName').textContent='Existing image';
      document.getElementById('imgRequiredTag').style.display='none';
    }
    // Load existing attachments
    pendingPdfs=[]; savedAttachments=Array.isArray(c.attachments)?c.attachments:[]; renderAttachList();
    updatePreview(); updateCompletion();
    showPage('add',document.getElementById('nav-add'));
  }

  // ── LIVE PREVIEW ──
  function updatePreview() {
    const v=id=>document.getElementById(id)?.value||'';
    document.getElementById('pv-id').textContent=v('fId')||'—';
    document.getElementById('pv-name').textContent=v('fRecipientName')||v('fVesselName')||'Vessel / Recipient Name';
    document.getElementById('pv-imo').textContent=v('fImo')||'—';
    document.getElementById('pv-assessed').textContent=v('fAssessmentDate')?fmtTiny(v('fAssessmentDate')):'—';
    document.getElementById('pv-until').textContent=v('fValidUntil')?fmtTiny(v('fValidUntil')):'—';
    document.getElementById('pv-status').textContent=v('fStatus')||'VALID';
    document.getElementById('pv-verifier').textContent=(v('fVerifiedBy')||(window.APP_CONFIG?window.APP_CONFIG.vapt.verifiedBy:'Gaurav Singh'))+(v('fVerifierTitle')?', '+v('fVerifierTitle').split('—')[0].trim():'');
    document.getElementById('pv-watermark').textContent=v('fStatus')||'VALID';
    updateCompletion();
  }

  // ── COMPLETION PANEL ──
  function updateCompletion() {
    const v=id=>document.getElementById(id)?.value.trim()||'';
    const hasImg = !!document.getElementById('prevImg')?.src || !!imgFile;
    const checks = [
      { label:'Certificate ID', done:!!v('fId'), key:'id' },
      { label:'Vessel Name & Recipient', done:!!(v('fVesselName')&&v('fRecipientName')), key:'vessel' },
      { label:'Assessment & Validity Dates', done:!!(v('fAssessmentDate')&&v('fValidUntil')), key:'dates' },
      { label:'Recipient Email', done:!!v('fRecipientEmail'), warn:!v('fRecipientEmail'), key:'email' },
      { label:'Certificate Image', done:hasImg, key:'image' },
    ];
    const doneCount=checks.filter(c=>c.done).length;
    const pct=Math.round(doneCount/checks.length*100);
    const allDone=doneCount===checks.length;
    const isEdit=!!editingId;
    const statusSel=document.getElementById('fStatus');
    const saveBtn=document.getElementById('saveBtn');
    const saveTxt=document.getElementById('saveTxt');
    const cpBar=document.getElementById('cpBar');
    const cpHeader=document.getElementById('cpHeader');
    cpBar.style.width=pct+'%';
    cpBar.style.background=allDone?'var(--teal)':doneCount>=3?'var(--gold)':'var(--warn)';
    document.getElementById('cpProgressBadge').textContent=`${doneCount}/${checks.length}`;
    document.getElementById('cpProgressBadge').style.background=allDone?'rgba(100,255,218,.12)':'rgba(255,170,46,.12)';
    document.getElementById('cpProgressBadge').style.borderColor=allDone?'rgba(100,255,218,.3)':'rgba(255,170,46,.25)';
    document.getElementById('cpProgressBadge').style.color=allDone?'var(--teal)':'var(--warn)';
    const icon=document.getElementById('cpHeaderIcon');
    icon.textContent=allDone?'✓':'?';
    icon.style.background=allDone?'rgba(100,255,218,.12)':'rgba(255,170,46,.12)';
    icon.style.borderColor=allDone?'rgba(100,255,218,.3)':'rgba(255,170,46,.3)';
    icon.style.color=allDone?'var(--teal)':'var(--warn)';
    if (allDone) {
      document.getElementById('cpHeaderTitle').textContent=isEdit?'Ready to Update':'Ready to Activate';
      document.getElementById('cpHeaderTitle').style.color='var(--teal)';
      document.getElementById('cpHeaderSub').textContent=isEdit?'All fields complete — certificate ready':'All fields complete — auto-set to VALID';
      if (cpHeader) cpHeader.style.background='rgba(100,255,218,.04)';
      // New cert → auto-set VALID; edit → unlock but keep existing status
      if (!isEdit && statusSel) {
        statusSel.value='VALID';
        statusSel.disabled=false;
        statusSel.style.opacity='';
      } else if (statusSel) {
        statusSel.disabled=false;
        statusSel.style.opacity='';
      }
      if (saveBtn) { saveBtn.removeAttribute('style'); saveBtn.setAttribute('style','flex:1;justify-content:center;padding:12px'); }
      if (saveTxt) saveTxt.textContent=isEdit?'Update Certificate':'Save & Activate';
    } else {
      document.getElementById('cpHeaderTitle').textContent='Pending Activation';
      document.getElementById('cpHeaderTitle').style.color=doneCount>=3?'var(--gold)':'var(--warn)';
      document.getElementById('cpHeaderSub').textContent='Complete required fields to auto-activate';
      if (cpHeader) cpHeader.style.background='';
      // New cert only → force PENDING and lock
      if (!isEdit && statusSel) {
        statusSel.value='PENDING';
        statusSel.disabled=true;
        statusSel.style.opacity='0.5';
        if (saveBtn) saveBtn.setAttribute('style','flex:1;justify-content:center;padding:12px;background:rgba(255,170,46,.15);border-color:rgba(255,170,46,.35);color:#FFAA2E');
        if (saveTxt) saveTxt.textContent='Save as Pending';
      }
    }
    document.getElementById('cpItems').innerHTML=checks.map(c=>`
      <div class="cp-item ${c.done?'done':c.warn?'warn':'missing'}">
        <div class="cp-check">${c.done?'✓':c.warn?'⚠':''}</div>
        <span class="cp-label">${c.label}</span>
        <span class="cp-tag">${c.done?'Done':c.warn?'Optional':'Required'}</span>
      </div>`).join('');
  }

  // ── SAVE ──
  async function saveCert() {
    const v=id=>document.getElementById(id)?.value.trim()||'';
    if (!v('fId')||!v('fVesselName')||!v('fAssessmentDate')||!v('fValidUntil')) { toast('Please fill in all required fields before saving.', 'err'); return; }
    const btn=document.getElementById('saveBtn'); btn.disabled=true;
    document.getElementById('saveTxt').textContent='Saving…';
    try {
      // Always use FormData so we can include pending PDF attachments
      const fd = new FormData();
      fd.append('id', v('fId'));
      fd.append('vesselIMO', v('fImo'));
      fd.append('vesselName', v('fVesselName'));
      fd.append('recipientName', v('fRecipientName'));
      fd.append('assessmentDate', v('fAssessmentDate'));
      fd.append('validUntil', v('fValidUntil'));
      fd.append('verifiedBy', v('fVerifiedBy'));
      fd.append('verifierTitle', v('fVerifierTitle'));
      fd.append('assessingOrg', v('fAssessingOrg'));
      fd.append('status', v('fStatus'));
      fd.append('riskLevel', v('fRiskLevel'));
      fd.append('frameworks', v('fFrameworks'));
      fd.append('scopeItems', v('fScopeItems'));
      fd.append('recipientEmail', v('fRecipientEmail'));
      fd.append('issuerEmail', v('fIssuerEmail'));
      fd.append('notes', v('fNotes'));

      // Certificate image
      if (imgFile) {
        fd.append('certificateImage', imgFile);
      } else {
        const existing = CERTS.find(x=>x.id===(editingId||v('fId')));
        if (existing?.certificateImage) fd.append('certificateImageUrl', existing.certificateImage);
      }

      // Existing saved attachments (passed as JSON so server knows what to keep)
      fd.append('attachments', JSON.stringify(savedAttachments));

      // New PDF files
      pendingPdfs.forEach((p, i) => fd.append(`attachment${i}`, p.file, p.name));

      const url=editingId?`${API}/vapt/certs/${editingId}`:`${API}/vapt/certs`;
      const method=editingId?'PUT':'POST';
      const r=await fetch(url,{method,headers:{Authorization:'Bearer '+TOKEN},body:fd});
      if (!r.ok) { let msg='Could not save certificate.'; try{const d=await r.json();msg=d.error||msg;}catch{} throw new Error(msg); }
      const saved = await r.json();
      // Update local state
      savedAttachments = Array.isArray(saved.attachments) ? saved.attachments : [];
      pendingPdfs = [];
      renderAttachList();
      toast(editingId?'Certificate updated!':'Certificate saved!','ok');
      await refreshStats(); renderTbl('dashTbl','');
      showPage('certs',document.getElementById('nav-certs'));
    } catch(e) { toast(e.message || 'Could not save certificate. Please try again.', 'err'); }
    btn.disabled=false;
    document.getElementById('saveTxt').textContent=editingId?'Update Certificate':'Save Certificate';
  }

  // ── VIEW ──
  // ── VIEW ATTACHMENTS HELPER (disabled — reference docs feature removed) ──
  function buildViewAttachments(atts) {
    return ''; // Reference Documents feature removed
  }

  // Open VAPT certificate directly in a new tab (avoids CSP frame-ancestors block)
  async function viewCertNewTab(id, btn) {
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.textContent = '…'; btn.disabled = true; }
    const tab = window.open('', '_blank');
    if (!tab) { if (btn) { btn.textContent = orig; btn.disabled = false; } return; }
    tab.document.write('<html><head><title>Loading…</title></head><body style="margin:0;background:#0A1628;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:#CCD6F6"><div style="text-align:center"><div style="font-size:1.1rem;margin-bottom:8px">🔒 Generating secure link…</div><div style="font-size:.8rem;opacity:.5">Please wait</div></div></body></html>');
    try {
      const r = await fetch(`${API}/vapt/cert-url/${encodeURIComponent(id)}`, { headers: { Authorization: 'Bearer ' + TOKEN } });
      const base = window.APP_CONFIG ? window.APP_CONFIG.routes.vpt : '/VAPT';
      const url = r.ok ? (await r.json()).url : `${window.location.origin}${base}/cert/${encodeURIComponent(id)}`;
      tab.location.href = url;
    } catch(e) {
      const base = window.APP_CONFIG ? window.APP_CONFIG.routes.vpt : '/VAPT';
      tab.location.href = `${window.location.origin}${base}/cert/${encodeURIComponent(id)}`;
    }
    if (btn) { btn.textContent = orig; btn.disabled = false; }
  }

  function viewCert(id) {
    const c=CERTS.find(x=>x.id===id); if (!c) return;
    const now=new Date(),vu=c.validUntil?new Date(c.validUntil):null;
    const isV=c.status==='VALID'&&(!vu||vu>=now);
    document.getElementById('viewTitle').textContent=`VAPT — ${c.id}`;
    const atts = Array.isArray(c.attachments) ? c.attachments : [];
    document.getElementById('viewBody').innerHTML=`
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
        <div style="background:var(--navy-mid);border:1px solid var(--border);border-radius:10px;padding:12px">
          <div style="font-size:.58rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:4px">Vessel / Recipient</div>
          <div style="color:var(--text-bright);font-weight:500">${escHtml(c.recipientName||'—')}</div>
        </div>
        <div style="background:var(--navy-mid);border:1px solid var(--border);border-radius:10px;padding:12px">
          <div style="font-size:.58rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:4px">IMO Number</div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--gold)">${escHtml(c.vesselIMO||'—')}</div>
        </div>
        <div style="background:var(--navy-mid);border:1px solid var(--border);border-radius:10px;padding:12px">
          <div style="font-size:.58rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:4px">Status</div>
          <span class="pill ${isV ? 'valid' : (c.status === 'PENDING' ? 'pending' : 'expired')}">${isV ? '✓ VALID' : c.status === 'PENDING' ? '⏳ PENDING' : c.status}</span>
        </div>
        <div style="background:var(--navy-mid);border:1px solid var(--border);border-radius:10px;padding:12px">
          <div style="font-size:.58rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:4px">Valid Until</div>
          <div style="color:${isV?'var(--teal)':'var(--invalid)'};font-size:.82rem">${fmt(c.validUntil)}</div>
        </div>
        <div style="background:var(--navy-mid);border:1px solid var(--border);border-radius:10px;padding:12px">
          <div style="font-size:.58rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:4px">Assessment Date</div>
          <div style="color:var(--text-bright)">${fmt(c.assessmentDate)}</div>
        </div>
        <div style="background:var(--navy-mid);border:1px solid var(--border);border-radius:10px;padding:12px">
          <div style="font-size:.58rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:4px">Email Status</div>
          <span class="pill ${c.emailStatus==='SENT'?'sent':'not-sent'}">${c.emailStatus==='SENT'?'✓ Sent':'Pending'}</span>
        </div>
      </div>
      <div style="background:rgba(100,255,218,.04);border:1px solid rgba(100,255,218,.18);border-radius:10px;padding:12px 16px;margin-bottom:${c.certificateImage ? '18px' : '4px'}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
          <div style="font-size:.5rem;letter-spacing:.16em;color:var(--teal);text-transform:uppercase;display:flex;align-items:center;gap:6px">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
            Unique Verification URL
          </div>
          <button id="viewCopyUrlBtn" data-action="copyViewUrl" style="background:var(--gold-dim);border:1px solid var(--border-gold);color:var(--gold);border-radius:7px;padding:4px 12px;font-size:.6rem;cursor:pointer;font-family:'DM Sans',sans-serif;font-weight:600;letter-spacing:.08em;transition:background .15s">⎘ Copy Link</button>
        </div>
        <div id="viewPublicUrl" style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--text);word-break:break-all;background:var(--navy);border:1px solid var(--border);border-radius:7px;padding:8px 12px;user-select:all">Generating secure link…</div>
        <div style="margin-top:8px;font-size:.62rem;color:var(--text-sec)">Share this URL with recipients, auditors, or inspectors for instant certificate verification.</div>
      </div>
      ${c.certificateImage?`<img src="${c.certificateImage}" style="width:100%;border-radius:10px;border:1px solid var(--border-gold);cursor:zoom-in;margin-bottom:${atts.length?'14px':'0'}" data-action="openLB" />`:''}
      ${buildViewAttachments(atts)}
      ${(function() {
        return `<div id="viewEngagementSection" data-certid="${c.id}" style="margin-top:16px;border-top:1px solid var(--border);padding-top:16px">
          ${buildEngagementActivityHtml({ emailSentAt: c.emailSentAt, recipientEmail: c.recipientEmail, emailStatus: c.emailStatus }, c.engagement)}
        </div>`;
      })()}
    `;
    document.getElementById('viewFoot').innerHTML=`
      ${(c.status||'').toUpperCase()==='PENDING' ? `<button class="btn" style="background:rgba(100,255,218,.1);border:1px solid rgba(100,255,218,.3);color:var(--teal);display:inline-flex;align-items:center;gap:7px" data-action="closeViewActivate" data-id="${c.id}"><svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.2'><path stroke-linecap='round' stroke-linejoin='round' d='M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z'/></svg> Activate</button>` : ''}
      <button class="btn btn-teal btn-sm" data-action="closeViewEdit" data-id="${c.id}">Edit</button>
      <button class="btn" data-action="viewCertNewTab" data-id="${c.id}" style="background:rgba(212,168,67,.1);border:1px solid rgba(212,168,67,.3);color:var(--gold);display:inline-flex;align-items:center;gap:6px"><svg width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path stroke-linecap='round' stroke-linejoin='round' d='M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14'/></svg> New Tab</button>
      ${c.recipientEmail&&c.emailStatus!=='SENT'?`<button class="btn btn-issue btn-sm" data-action="closeViewIssue" data-id="${c.id}">Send Credential</button>`:''}
    `;
    document.getElementById('viewOverlay').style.display='flex';

  // ── Async: refresh engagement data live when modal opens ──
  (async function loadViewEngagementVapt(certId) {
    try {
      const r = await fetch(API + '/vapt/certs/' + encodeURIComponent(certId) + '/engagement', {
        headers: { Authorization: 'Bearer ' + TOKEN }
      });
      if (!r.ok) return;
      const { engagement } = await r.json();
      const cached = CERTS.find(x => x.id === certId);
      if (cached) cached.engagement = engagement;
      // Guard: only update if this modal is still showing the same cert (race-condition fix)
      const actDiv = document.getElementById('viewEngagementSection');
      if (!actDiv || actDiv.dataset.certid !== certId) return;
      const cachedC = cached || {};
      actDiv.innerHTML = buildEngagementActivityHtml(
        { emailSentAt: cachedC.emailSentAt, recipientEmail: cachedC.recipientEmail, emailStatus: cachedC.emailStatus },
        engagement
      );
    } catch(e) { /* silent — stale data from cache is fine */ }
  })(id);

  // ── Async: fetch encrypted URL and update URL display ──
  (async function loadViewUrlVapt(certId) {
    const urlEl  = document.getElementById('viewPublicUrl');
    const copyEl = document.getElementById('viewCopyUrlBtn');
    if (!urlEl) return;
    urlEl.style.color = 'var(--text-sec)';
    urlEl.textContent = 'Generating secure link…';
    const url = await getVaptCertEncryptedUrl(certId);
    urlEl.textContent = url;
    urlEl.style.color = '';
    if (copyEl) copyEl.dataset.url = url;
  })(id);
  }
  function closeView(){document.getElementById('viewOverlay').style.display='none';}

  // ── QUICK STATUS CHANGE (inline table dropdown) ──
  async function quickStatusChange(id, newStatus, selEl) {
    const c = CERTS.find(x => x.id === id); if (!c) return;
    const oldStatus = c.status;
    if (oldStatus === newStatus) return;
    // Optimistic UI update
    c.status = newStatus;
    if (selEl) { selEl.className = 'inline-status-sel status-' + newStatus.toLowerCase(); }
    try {
      const fd = new FormData();
      fd.append('status', newStatus);
      // If activating from PENDING and no validUntil, auto-set 1 year from today
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
      const r = await fetch(API + '/vapt/certs/' + encodeURIComponent(id), {
        method: 'PUT', headers: { Authorization: 'Bearer ' + TOKEN }, body: fd
      });
      if (r.ok) {
        toast('Status updated successfully.', 'ok');
        await refreshStats();
        renderTbl('dashTbl', '');
        renderTbl('allTbl', document.getElementById('allQ')?.value || '', document.getElementById('allStatusSel')?.value || '', document.getElementById('allEmailSel')?.value || '');
      } else {
        // Revert
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

  // ── ACTIVATE ──
  async function activateCert(id) {
    const c = CERTS.find(x => x.id === id); if (!c) return;
    if (!confirm(`Activate VAPT certificate ${id}?\nThis will set the status to VALID and make it publicly verifiable.`)) return;
    try {
      const fd = new FormData();
      fd.append('status', 'VALID');
      const r = await fetch(API + '/vapt/certs/' + encodeURIComponent(id), { method: 'PUT', headers: { Authorization: 'Bearer ' + TOKEN }, body: fd });
      if (r.ok) {
        toast('Certificate activated successfully.', 'ok');
        await refreshStats();
        renderTbl('dashTbl', '');
        renderTbl('allTbl', '');
      } else { toast('Could not activate certificate. Please try again.', 'err'); }
    } catch (e) { toast(e.message || 'Connection failed. Check your internet and try again.', 'err'); }
  }

  function openDocLibraryForVessel() {
    const imo = (document.getElementById('fImo') || {}).value || '';
    const vessel = (document.getElementById('fVesselName') || {}).value || '';
    const base = (window.APP_CONFIG && window.APP_CONFIG.routes && window.APP_CONFIG.routes.cstAdmin) || '/console/cst';
    let url = base + '/?tab=docs';
    if (imo) url += '&imo=' + encodeURIComponent(imo.trim().toUpperCase()) + '&vessel=' + encodeURIComponent(vessel.trim());
    window.open(url, '_blank');
  }

  // ── DELETE ──
  function askDelete(id){ deleteTargetId=id; document.getElementById('delId').textContent=id; document.getElementById('delOverlay').style.display='flex'; }
  function closeDel(){ document.getElementById('delOverlay').style.display='none'; }
  async function confirmDelete() {
    if (!deleteTargetId) return;
    try {
      const r=await fetch(`${API}/vapt/certs/${deleteTargetId}`,{method:'DELETE',headers:{Authorization:'Bearer '+TOKEN}});
      if (r.ok){toast('Certificate removed successfully.', 'ok');await refreshStats();renderTbl('dashTbl','');renderTbl('allTbl','');}
      else toast('Could not delete certificate. Please try again.', 'err');
    } catch { toast('Connection error. Please check your network.', 'err'); }
    closeDel();
  }

  // ── COPY URL ──
  // Fetch the encrypted+signed shareable URL for display in the view modal
  // (mirrors CST dashboard.js's getCertEncryptedUrl — same fetch copyEncUrl uses,
  // but returns the string instead of writing straight to the clipboard).
  async function getVaptCertEncryptedUrl(certId) {
    var base = (window.APP_CONFIG ? window.APP_CONFIG.routes.vpt : '/VAPT');
    try {
      const r = await fetch(`${API}/vapt/cert-url/${encodeURIComponent(certId)}`, { headers: { Authorization: 'Bearer ' + TOKEN } });
      if (!r.ok) return window.location.origin + base + '/cert/' + encodeURIComponent(certId);
      const d = await r.json();
      return d.url;
    } catch { return window.location.origin + base + '/cert/' + encodeURIComponent(certId); }
  }
  function copyViewUrl(btn) {
    const url = btn.dataset.url || document.getElementById('viewPublicUrl').textContent;
    if (!url || url === 'Generating secure link…') return;
    navigator.clipboard.writeText(url).catch(() => {});
    const orig = btn.textContent; btn.textContent = '✓ Copied!';
    setTimeout(() => { btn.textContent = orig; }, 2000);
  }
  async function copyEncUrl(id, btn) {
    try {
      const r=await fetch(`${API}/vapt/cert-url/${encodeURIComponent(id)}`,{headers:{Authorization:'Bearer '+TOKEN}});
      if (r.ok){
        const d=await r.json();
        const url = d.url || `${window.location.origin}${window.APP_CONFIG?window.APP_CONFIG.routes.vpt:'/VAPT'}/cert/${encodeURIComponent(id)}`;
        await navigator.clipboard.writeText(url);
        if(btn){const t=btn.textContent;btn.textContent='✓ Copied!';setTimeout(()=>btn.textContent=t,2000);}
        toast('Verification URL copied!','ok');
      } else toast('Could not generate verification link. Please try again.', 'err');
    } catch { toast('Could not copy link. Please try again.', 'err'); }
  }

  // ── ISSUE / SEND ──
  let _issueEmailCache={};
  function renderIssueList(q) {
    const filter=document.getElementById('issueFilter')?.value||'';
    let list=CERTS;
    if (q){const ql=q.toLowerCase();list=list.filter(c=>c.id.toLowerCase().includes(ql)||(c.recipientName||'').toLowerCase().includes(ql)||(c.vesselIMO||'').toLowerCase().includes(ql));}
    if (filter) list=list.filter(c=>c.emailStatus===filter||(filter==='NOT_SENT'&&c.emailStatus!=='SENT'));
    const el=document.getElementById('issueCertList');
    if (!list.length){el.innerHTML='<div style="padding:24px;text-align:center;color:var(--text-sec);font-size:.82rem">No certificates found</div>';return;}
    el.innerHTML=list.slice(0,40).map(c=>{
      const done=c.emailStatus==='SENT';
      const sel=c.id===selectedIssueCertId;
      return `<div class="issue-cert-row ${sel?'selected':done?'done':''}" data-action="selectIssueCert" data-id="${c.id}">
        <div class="issue-cert-check">${sel?'▶':done?'✓':''}</div>
        <div class="issue-cert-meta" style="flex:1">
          <div style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--gold)">${c.id}</div>
          <div style="font-size:.78rem;color:var(--text-bright)">${escHtml(c.recipientName||'—')}</div>
          <div style="font-size:.62rem;color:var(--text-sec)">${escHtml(c.recipientEmail||'No email')} · IMO: ${escHtml(c.vesselIMO||'—')}</div>
        </div>
        <span class="pill ${done?'sent':'not-sent'}">${done?'✓ Sent':'Pending'}</span>
      </div>`;
    }).join('');
  }

  function selectIssueCert(id) {
    selectedIssueCertId=id;
    const c=CERTS.find(x=>x.id===id); if(!c) return;
    renderIssueList(document.getElementById('issueSearch')?.value||'');
    document.getElementById('issueSelectPrompt').style.display='none';
    document.getElementById('issueComposeForm').style.display='block';
    document.getElementById('issueSelectedId').textContent=c.id;
    document.getElementById('issueSelectedName').textContent=c.recipientName||c.vesselName||'—';
    document.getElementById('issueRecipEmail').value=c.recipientEmail||'';
    // Always keep both buttons available — both options remain active at all times
    const markBtn = document.getElementById('markSentBtn');
    const sendBtn = document.getElementById('sendSesBtn');
    markBtn.disabled = false;
    markBtn.style.background = ''; markBtn.style.borderColor = ''; markBtn.style.color = '';
    sendBtn.disabled = false;
    sendBtn.style.background = ''; sendBtn.style.borderColor = ''; sendBtn.style.color = '';
    document.getElementById('markSentTxt').textContent = c.emailStatus === 'SENT' ? '✓ Re-Mark Sent' : 'Mark Sent';
    document.getElementById('sendSesTxt').textContent = c.emailStatus === 'SENT' ? 'Re-Send' : 'Send';
    updateIssueEmailPreview();
  }

  async function updateIssueEmailPreview() {
    const c=CERTS.find(x=>x.id===selectedIssueCertId); if(!c) return;
    let certUrl = `${window.location.origin}${window.APP_CONFIG?window.APP_CONFIG.routes.vpt:'/VAPT'}/cert/${encodeURIComponent(c.id)}`;
    try {
      const r=await fetch(`${API}/vapt/cert-url/${encodeURIComponent(c.id)}`,{headers:{Authorization:'Bearer '+TOKEN}});
      if (r.ok) { const d=await r.json(); if(d.url) certUrl=d.url; }
    } catch { /* fallback to plain URL */ }

    // Use config template if available, else inline fallback
    const plainText = (window.APP_CONFIG && window.APP_CONFIG.emailTemplates && window.APP_CONFIG.emailTemplates.vapt)
      ? window.APP_CONFIG.emailTemplates.vapt(c, certUrl)
      : (() => {
          const team = window.APP_CONFIG ? window.APP_CONFIG.brand.companyFull : 'Synergy Marine Group';
          const vaptEmail = window.APP_CONFIG ? window.APP_CONFIG.contact.vaptEmail : 'vapt@synergyship.com';
          const verBy = c.verifiedBy || (window.APP_CONFIG ? window.APP_CONFIG.vapt.verifiedBy : 'Gaurav Singh');
          const verTitle = c.verifierTitle || (window.APP_CONFIG ? window.APP_CONFIG.vapt.verifierTitle : 'CISO — Synergy Group');
          return `Subject: Your VAPT Certificate \u2014 ${c.id} \u2014 ${window.APP_CONFIG?(window.APP_CONFIG.brand.companyShort||window.APP_CONFIG.brand.name):'Synergy'}\n\nDear ${c.recipientName||'Vessel Master / Company Representative'},\n\nPlease find below your Vulnerability Assessment & Penetration Testing (VAPT) certificate details from ${team} Cyber Security Division.\n\nCertificate ID   : ${c.id}\nVessel           : ${c.recipientName||c.vesselName||'\u2014'}\nIMO Number       : ${c.vesselIMO||'\u2014'}\nAssessment Date  : ${fmt(c.assessmentDate)}\nValid Until      : ${fmt(c.validUntil)}\nStatus           : ${c.status||'VALID'}\nFrameworks       : ${c.frameworks||'OWASP / IMO Framework / ISO 27001:2013'}\n\nYour certificate image is attached to this email for your records.\n\nTo verify the authenticity of this certificate at any time, visit the link below\nor enter Certificate No. ${c.id} at the VAPT verification portal:\n\n${certUrl}\n\nFor questions or re-assessment, contact us at ${vaptEmail}.\n\n${verBy}\n${verTitle}\n${team} \u00b7 Cyber Security Division`;
        })();

    const previewEl = document.getElementById('issueEmailPreview');
    const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    // Split body around the cert URL
    const bodyBeforeUrl = plainText.split(certUrl)[0] || '';
    const bodyAfterUrl  = (plainText.split(certUrl)[1] || '').trim();

    previewEl.innerHTML = `
      <div style="white-space:pre-wrap;font-size:.75rem;color:var(--text);line-height:1.9;font-family:'DM Sans',sans-serif">${esc(bodyBeforeUrl)}</div>

      <!-- Cert image note -->
      <div style="margin:10px 0;padding:10px 14px;background:rgba(100,255,218,.04);border:1px solid rgba(100,255,218,.18);border-radius:9px;font-size:.72rem;color:var(--teal);display:flex;align-items:center;gap:7px">
        <span>📎</span><span>Certificate image is attached to this email.</span>
      </div>

      <!-- CTA Block -->
      <div style="margin:14px 0 10px;padding:14px 16px;background:rgba(100,255,218,.05);border:1px solid rgba(100,255,218,.2);border-radius:10px">
        <div style="font-size:.6rem;letter-spacing:.14em;color:var(--text-sec);text-transform:uppercase;margin-bottom:10px;display:flex;align-items:center;gap:5px">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
          Verification Link
        </div>
        <a href="${esc(certUrl)}" target="_blank" rel="noopener"
          style="display:block;text-align:center;padding:11px 22px;
                 background:linear-gradient(135deg,#64FFDA,#0A9E7A);color:#0A1628;
                 border-radius:9px;font-weight:700;font-size:.78rem;text-decoration:none;
                 letter-spacing:.04em;font-family:'DM Sans',sans-serif;
                 box-shadow:0 3px 12px rgba(100,255,218,.3);margin-bottom:10px">
          &#128279; &nbsp;Click Here to View &amp; Verify VAPT Certificate
        </a>
        <div style="font-size:.6rem;color:var(--text-sec);word-break:break-all;display:flex;align-items:flex-start;gap:5px;padding:8px 10px;background:var(--navy);border-radius:7px;border:1px solid var(--border)">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2" style="flex-shrink:0;margin-top:1px"><path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
          <span style="font-family:'JetBrains Mono',monospace;color:var(--teal);font-size:.6rem">${esc(certUrl)}</span>
        </div>
      </div>

      <div style="white-space:pre-wrap;font-size:.75rem;color:var(--text-sec);line-height:1.9;border-top:1px solid var(--border);padding-top:10px;margin-top:6px">${esc(bodyAfterUrl)}</div>
    `;
    previewEl._plainText = plainText;
    _issueEmailCache[c.id]=plainText;
  }

  async function copyMailBody() {
    const el=document.getElementById('issueEmailPreview');
    const txt=el._plainText||el.textContent;
    try{
      await navigator.clipboard.writeText(txt);
      const btn = document.getElementById('copyBtnTxt');
      if (btn) { btn.textContent='✓ Copied!'; setTimeout(()=>btn.textContent='Copy Body',2000); }
    }
    catch{ toast('Could not copy to clipboard. Please try again.', 'err'); }
  }

  async function checkSesStatus() {
    try {
      const r = await fetch(API + '/ses-status', { headers: { Authorization: 'Bearer ' + TOKEN } });
      const d = r.ok ? await r.json() : {};
      const badge = document.getElementById('sesBadgeVapt');
      const bdot  = document.getElementById('sesBadgeVaptDot');
      const btxt  = document.getElementById('sesBadgeVaptTxt');
      const sbDot = document.getElementById('sesSbDot');
      const lbl   = document.getElementById('sesSbLabel');
      if (d.enabled) {
        if (badge) { badge.style.background='rgba(100,255,218,.08)'; badge.style.color='var(--teal)'; badge.style.borderColor='rgba(100,255,218,.25)'; }
        if (bdot)  { bdot.style.background='var(--teal)'; bdot.style.animation='pulse 2s ease-in-out infinite'; }
        if (btxt)  btxt.textContent = 'Email Dispatch Active';
        if (sbDot) sbDot.style.background = 'var(--teal)';
        if (lbl)   lbl.textContent = 'Mail On';
      } else {
        if (badge) { badge.style.background='rgba(255,107,138,.08)'; badge.style.color='#ff5c7a'; badge.style.borderColor='rgba(255,107,138,.2)'; }
        if (bdot)  { bdot.style.background='var(--invalid)'; bdot.style.animation=''; }
        if (btxt)  btxt.textContent = 'Email Offline';
        if (sbDot) sbDot.style.background = 'var(--invalid)';
        if (lbl)   lbl.textContent = 'Mail Off';
      }
    } catch {
      const dot = document.getElementById('sesSbDot');
      const lbl = document.getElementById('sesSbLabel');
      if (dot) dot.style.background = 'var(--invalid)';
      if (lbl) lbl.textContent      = 'Mail Err';
    }
  }

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
      // Pass recipientEmail in request body — server persists it AND uses it for send
      const r = await fetch(`${API}/vapt/certs/${encodeURIComponent(selectedIssueCertId)}/send-email`, {
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
              <div style="font-weight:700;font-size:.78rem">Credential Email Sent</div>
              <div style="font-size:.65rem;opacity:.85;margin-top:3px;line-height:1.6">
                To: <strong>${recipEmail}</strong><br>
                Sent: ${sentAt}${d.messageId ? '<br>Message ID: <code style="font-size:.6rem;opacity:.7">' + d.messageId + '</code>' : ''}
              </div>
            </div>
          </div>`;
        toast('✓ VAPT credential email sent successfully.', 'ok');
        const c = CERTS.find(x => x.id === selectedIssueCertId);
        if (c) { c.emailStatus = 'SENT'; c.emailSentAt = d.emailSentAt || new Date().toISOString(); c.recipientEmail = recipEmail; }
        await refreshStats();
        renderIssueList(document.getElementById('issueSearch')?.value || '');
        renderSentLog();
        btn.disabled = false;
        btn.style.background = ''; btn.style.borderColor = ''; btn.style.color = '';
        document.getElementById('sendSesTxt').textContent = 'Re-Send';
        document.getElementById('markSentTxt').textContent = '✓ Re-Mark Sent';
        return;
      } else {
        let errMsg;
        if (r.status === 409) {
          errMsg = d.error || 'Email has already been sent for this certificate.';
        } else if (r.status === 503 || d.sesEnabled === false) {
          errMsg = 'Email dispatch is not configured on this server. Contact your system administrator to configure mail settings.';
        } else {
          errMsg = d.error || d.sesError || ('Server error — HTTP ' + r.status);
        }
        resultEl.style.display    = 'block';
        resultEl.style.background = 'rgba(255,107,138,.07)';
        resultEl.style.border     = '1px solid rgba(255,107,138,.2)';
        resultEl.style.color      = 'var(--invalid)';
        resultEl.innerHTML = `<div style="display:flex;align-items:flex-start;gap:8px"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-top:1px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>${errMsg}</span></div>`;
        toast('✗ Email not sent: ' + errMsg, 'err');
      }
    } catch (e) {
      resultEl.style.display = 'block';
      resultEl.style.background = 'rgba(255,107,138,.07)';
      resultEl.style.border     = '1px solid rgba(255,107,138,.2)';
      resultEl.style.color      = 'var(--invalid)';
      resultEl.innerHTML = `<div style="display:flex;align-items:flex-start;gap:8px"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-top:1px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>Could not reach the server. Check your network connection and try again.</span></div>`;
      toast('Connection failed. Check your internet and try again.', 'err');
    }
    btn.disabled = false;
    btn.style.background = ''; btn.style.borderColor = ''; btn.style.color = '';
    document.getElementById('sendSesTxt').textContent = 'Send';
  }

  async function markAsSent() {
    if (!selectedIssueCertId) { toast('Select a certificate first.', 'warn'); return; }
    const btn = document.getElementById('markSentBtn');
    btn.disabled = true;
    document.getElementById('markSentTxt').textContent = 'Saving…';
    try {
      const fd = new FormData();
      fd.append('emailStatus', 'SENT');
      fd.append('emailSentAt', new Date().toISOString());
      const recipEmail = (document.getElementById('issueRecipEmail').value || '').trim();
      if (recipEmail) fd.append('recipientEmail', recipEmail);
      const r = await fetch(`${API}/vapt/certs/${encodeURIComponent(selectedIssueCertId)}`, {
        method: 'PUT', headers: { Authorization: 'Bearer ' + TOKEN }, body: fd
      });
      if (r.ok) {
        const c = CERTS.find(x => x.id === selectedIssueCertId);
        if (c) { c.emailStatus = 'SENT'; c.emailSentAt = new Date().toISOString(); if (recipEmail) c.recipientEmail = recipEmail; }
        toast('✓ Credential marked as sent!', 'ok');
        await refreshStats();
        renderIssueList(document.getElementById('issueSearch')?.value || '');
        renderSentLog();
        // Re-enable both — keep all options available
        btn.disabled = false;
        btn.style.background = ''; btn.style.borderColor = ''; btn.style.color = '';
        document.getElementById('markSentTxt').textContent = '✓ Re-Mark Sent';
        document.getElementById('sendSesTxt').textContent = 'Re-Send';
        return;
      } else {
        toast('Could not record dispatch status. Please try again.', 'err');
      }
    } catch { toast('Connection failed. Check your internet and try again.', 'err'); }
    btn.disabled = false;
    btn.style.background = ''; btn.style.borderColor = ''; btn.style.color = '';
    document.getElementById('markSentTxt').textContent = 'Mark Sent';
  }

  function clearIssueSelection(){
    selectedIssueCertId=null;
    document.getElementById('issueSelectPrompt').style.display='block';
    document.getElementById('issueComposeForm').style.display='none';
    renderIssueList(document.getElementById('issueSearch')?.value||'');
  }

  function renderSentLog() {
    const sent=CERTS.filter(c=>c.emailStatus==='SENT').sort((a,b)=>new Date(b.emailSentAt||0)-new Date(a.emailSentAt||0));
    const el=document.getElementById('sentLogList');
    // Update badge count
    const badge = document.getElementById('sentLogCount');
    if (badge) badge.textContent = sent.length + ' sent';
    if (!sent.length){el.innerHTML='<div style="text-align:center;padding:28px;color:var(--text-sec);font-size:.78rem">No credentials dispatched yet</div>';return;}
    el.innerHTML=sent.slice(0,20).map(c=>{
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
      <div class="sent-log-row" style="padding:12px 14px;border-radius:10px;background:var(--navy-mid);border:1px solid var(--border);margin-bottom:8px;transition:border-color .15s">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">
          <span style="font-family:'JetBrains Mono',monospace;font-size:.68rem;color:var(--gold)">${c.id}</span>
          <div style="display:flex;align-items:center;gap:4px">${engBadges.join('')}</div>
        </div>
        <div style="font-size:.78rem;color:var(--text-bright);font-weight:500">${escHtml(c.recipientName||'—')}</div>
        <div style="font-size:.64rem;color:var(--text-sec);margin-top:2px">IMO: ${escHtml(c.vesselIMO||'—')}</div>
        ${c.recipientEmail ? `<div style="font-size:.64rem;color:var(--teal);margin-top:2px;display:flex;align-items:center;gap:4px">
          <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
          ${escHtml(c.recipientEmail)}</div>` : ''}
        <div style="font-size:.6rem;color:var(--text-sec);margin-top:7px;padding-top:7px;border-top:1px solid var(--border);display:flex;align-items:center;gap:6px">
          <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <span style="color:var(--teal);font-weight:600">Sent</span>
          ${c.emailSentAt ? '· ' + new Date(c.emailSentAt).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) + ' · ' + new Date(c.emailSentAt).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'}) : '—'}
        </div>
      </div>`;
    }).join('');
  }

  // ── IMAGE UPLOAD ──
  function onFileSelect(input){if(input.files&&input.files[0])setImg(input.files[0]);}
  function onDragOver(e){e.preventDefault();document.getElementById('dropZone').classList.add('drag-over');}
  function onDragLeave(){document.getElementById('dropZone').classList.remove('drag-over');}
  function onDrop(e){e.preventDefault();document.getElementById('dropZone').classList.remove('drag-over');if(e.dataTransfer.files[0])setImg(e.dataTransfer.files[0]);}
  document.addEventListener('paste', function(e) {
    const zone = document.getElementById('dropZone');
    if (!zone || zone.offsetParent === null) return;
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (let i = 0; i < items.length; i++) {
      if (items[i].type.startsWith('image/')) {
        e.preventDefault();
        const raw = items[i].getAsFile();
        if (!raw) return;
        const ext = (items[i].type.split('/')[1] || 'png').replace('jpeg', 'jpg');
        const named = new File([raw], 'cert-screenshot-' + Date.now() + '.' + ext, { type: items[i].type });
        setImg(named);
        zone.classList.add('paste-flash');
        setTimeout(function() { zone.classList.remove('paste-flash'); }, 600);
        break;
      }
    }
  });

  // ── PDF / DOCUMENT ATTACHMENTS ──
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
      const badge = a.pending ? '<span style="font-size:.56rem;background:rgba(255,170,46,.09);color:var(--gold);border:1px solid rgba(255,170,46,.2);padding:1px 5px;border-radius:4px;margin-left:5px">pending</span>' : '';
      const openBtn = (!a.pending && a.url) ? `<a href="${escHtml(a.url)}" target="_blank" style="font-size:.62rem;color:var(--teal);padding:3px 8px;border-radius:5px;background:rgba(100,255,218,.07);border:1px solid rgba(100,255,218,.2);text-decoration:none">Open</a>` : '';
      const rmBtn = a.saved
        ? `<button type="button" data-action="removeSavedAttach" data-idx="${a.idx}" style="font-size:.6rem;color:var(--invalid);padding:3px 8px;border-radius:5px;border:1px solid rgba(255,107,138,.18);background:rgba(255,107,138,.05);cursor:pointer;font-family:'DM Sans',sans-serif">Remove</button>`
        : `<button type="button" data-action="removePendingAttach" data-idx="${a.idx}" style="font-size:.6rem;color:var(--invalid);padding:3px 8px;border-radius:5px;border:1px solid rgba(255,107,138,.18);background:rgba(255,107,138,.05);cursor:pointer;font-family:'DM Sans',sans-serif">Remove</button>`;
      return `<div style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--border)">
        <span style="font-size:.88rem;flex-shrink:0">${icon}</span>
        <span style="flex:1;font-size:.73rem;color:var(--text-bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(a.name || 'Document')}${badge}</span>
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

  function setImg(f){
    imgFile=f;
    const reader=new FileReader();
    reader.onload=e=>{
      document.getElementById('uploadDefault').style.display='none';
      document.getElementById('uploadPrev').style.display='block';
      document.getElementById('prevImg').src=e.target.result;
      document.getElementById('prevName').textContent=f.name;
      document.getElementById('imgRequiredTag').style.display='none';
      updateCompletion();
    };
    reader.readAsDataURL(f);
  }
  function clearImg(evt){
    if(evt)evt.stopPropagation();
    imgFile=null;
    document.getElementById('uploadDefault').style.display='block';
    document.getElementById('uploadPrev').style.display='none';
    document.getElementById('prevImg').src='';
    document.getElementById('imgRequiredTag').style.display='';
    updateCompletion();
  }

  // ── CSV IMPORT (v2 — flexible column mapping) ──
  const VAPT_CSV_FIELD_ALIASES = {
    vesselIMO:      ['imo_number','imo number','imo no','imo','vessel imo','vessel_imo','imonumber'],
    vesselName:     ['vessel_name','vessel name','ship name','ship_name','vessel'],
    assessmentDate: ['assessment_date','assessment date','assess date','date','issue date','issue_date'],
    recipientEmail: ['recipient_email','recipient email','email','email address','master email','contact email'],
    certId:         ['cert_number','cert number','certificate number','certificate_number','cert no','cert id'],
    notes:          ['notes','remarks','comment','comments'],
  };

  function vaptMatchHeader(header) {
    const h = header.toLowerCase().trim().replace(/['"]/g,'');
    for (const [field, aliases] of Object.entries(VAPT_CSV_FIELD_ALIASES)) {
      if (aliases.includes(h)) return field;
    }
    return null;
  }

  function vaptAutoDetectMapping(headers) {
    const map = {};
    headers.forEach((h, idx) => {
      const field = vaptMatchHeader(h);
      if (field && !(field in map)) map[field] = idx;
    });
    return map;
  }

  let csvRawHeaders = [], csvColMapVapt = {};

  function vaptGetRowVal(row, field) {
    if (csvColMapVapt && field in csvColMapVapt) {
      const idx = csvColMapVapt[field];
      const key  = csvRawHeaders[idx];
      if (key) return (row[key] || row[key.toLowerCase()] || '').trim();
    }
    const aliases = VAPT_CSV_FIELD_ALIASES[field] || [];
    for (const alias of aliases) {
      const v = row[alias] || row[alias.replace(/_/g,' ')] || '';
      if (v) return v.trim();
    }
    return '';
  }

  function vaptParseCsvDate(raw) {
    if (!raw) return '';
    raw = raw.trim();
    const m1 = raw.match(/^(\d{1,2})[-\/\s](Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-\/\s](\d{2,4})$/i);
    if (m1) {
      const yr  = m1[3].length === 2 ? (parseInt(m1[3]) < 50 ? '20' + m1[3] : '19' + m1[3]) : m1[3];
      const MON = { jan:'01',feb:'02',mar:'03',apr:'04',may:'05',jun:'06',jul:'07',aug:'08',sep:'09',oct:'10',nov:'11',dec:'12' };
      return yr + '-' + MON[m1[2].toLowerCase()] + '-' + m1[1].padStart(2,'0');
    }
    const m2 = raw.match(/^(\d{1,2})[-\/](\d{1,2})[-\/](\d{2,4})$/);
    if (m2) {
      const yr = m2[3].length === 2 ? (parseInt(m2[3]) < 50 ? '20' + m2[3] : '19' + m2[3]) : m2[3];
      return yr + '-' + m2[2].padStart(2,'0') + '-' + m2[1].padStart(2,'0');
    }
    if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return raw;
    try { const d = new Date(raw); if (!isNaN(d)) return d.toISOString().slice(0,10); } catch(err) {}
    return '';
  }

  function vaptParseCsvFull(text) {
    const lines = text.split(/\r?\n/);
    if (lines.length < 2) return { rawHeaders: [], rows: [] };
    function splitLine(line) {
      const result = []; let cur = ''; let inQ = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') { inQ = !inQ; }
        else if ((ch === ',' || ch === '\t') && !inQ) { result.push(cur.trim()); cur = ''; }
        else { cur += ch; }
      }
      result.push(cur.trim()); return result;
    }
    let hi = 0;
    while (hi < lines.length && !lines[hi].trim()) hi++;
    if (hi >= lines.length) return { rawHeaders: [], rows: [] };
    const rawHeaders = splitLine(lines[hi]).map(h => h.replace(/^"|"$/g,'').trim());
    const rows = [];
    for (let i = hi+1; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;
      const vals = splitLine(line).map(v => v.replace(/^"|"$/g,'').trim());
      if (vals.every(v => !v)) continue;
      const obj = {};
      rawHeaders.forEach((h, idx) => { obj[h] = vals[idx]||''; obj[h.toLowerCase()] = vals[idx]||''; });
      rows.push(obj);
    }
    return { rawHeaders, rows };
  }

  function handleCsvDrop(e) {
    e.preventDefault();
    document.getElementById('csvDrop').classList.remove('drag-over');
    if (e.dataTransfer.files[0]) loadCsvFile(e.dataTransfer.files[0]);
  }

  function loadCsvFile(f) {
    if (!f) return;
    const reader = new FileReader();
    reader.onload = e => {
      const { rawHeaders, rows } = vaptParseCsvFull(e.target.result);
      csvRawHeaders  = rawHeaders;
      csvColMapVapt  = vaptAutoDetectMapping(rawHeaders);
      csvParsedRows  = rows.filter(r => vaptGetRowVal(r,'vesselIMO') || vaptGetRowVal(r,'vesselName'));
      if (!csvParsedRows.length) { alert('No valid data rows found.'); return; }
      const missing = ['vesselIMO','vesselName','assessmentDate'].filter(field => !(field in csvColMapVapt));
      document.getElementById('csvUploadDefault').style.display = 'none';
      document.getElementById('csvUploadLoaded').style.display  = 'flex';
      document.getElementById('csvLoadedName').textContent =
        f.name + ' (' + csvParsedRows.length + ' rows)' + (missing.length ? ' ⚠ missing: ' + missing.join(', ') : ' ✓');
      renderCsvPreview();
    };
    reader.readAsText(f);
  }

  function buildVaptCertFromRow(row) {
    // Normalize the same way the server does (server/index.js normalizeVesselIMO) —
    // see the matching comment in cst/dashboard.js's buildCertFromRow.
    const imo    = vaptGetRowVal(row,'vesselIMO').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 20);
    const vessel = vaptGetRowVal(row,'vesselName');
    const adRaw  = vaptGetRowVal(row,'assessmentDate');
    const email  = vaptGetRowVal(row,'recipientEmail');
    const notes  = vaptGetRowVal(row,'notes');
    const manId  = vaptGetRowVal(row,'certId');
    const dateStr = vaptParseCsvDate(adRaw);
    const CFG = window.APP_CONFIG || {};
    const vaptPfx = (CFG.certFormats||{}).vaptPrefix || 'VAP';
    let certId = manId || '';
    if (!certId && imo && dateStr) {
      const d  = new Date(dateStr);
      const mm = String(d.getMonth()+1).padStart(2,'0');
      const yy = String(d.getFullYear()).slice(-2);
      certId = vaptPfx + '-' + imo + '-' + mm + yy;
    }
    let validUntil = '';
    if (dateStr) { const d = new Date(dateStr); d.setFullYear(d.getFullYear()+1); validUntil = d.toISOString().slice(0,10); }
    // recipientName keeps whatever prefix the CSV cell had (e.g. "MV - NORD KUDU");
    // vesselName is derived bare — same convention as CST's buildCertFromRow, so
    // a vessel imported via either dashboard's CSV ends up with the same shape.
    const bareVessel = vessel.replace(/^(MV|MT)\s*[-–]?\s*/i, '').trim() || vessel;
    return {
      id: (certId||'').toUpperCase(),
      vesselIMO: imo, vesselName: bareVessel, recipientName: vessel,
      assessmentDate: dateStr, validUntil,
      verifiedBy:    (CFG.vapt||{}).verifiedBy    || 'Gaurav Singh',
      verifierTitle: (CFG.vapt||{}).verifierTitle || 'CISO — Synergy Group',
      assessingOrg:  (CFG.vapt||{}).assessingOrg  || 'Synergy Marine Group Cybersecurity Team',
      frameworks:    (CFG.vapt||{}).frameworks     || 'Cybersecurity Framework / OWASP / IMO Framework / ISO 27001:2013',
      scopeItems:    (CFG.vapt||{}).scopeItems     || 'Access Control,IT/OT Risk analysis,Vessel Cyber security awareness,Software Version Control (IT/OT),Backups & Disaster Recovery,IT Drills & Internal Audits',
      status: 'PENDING', certificateImage: null,
      recipientEmail: email,
      issuerEmail: (CFG.contact||{}).vaptEmail || 'vapt@synergyship.com',
      emailStatus: 'NOT_SENT', emailSentAt: null,
      notes: notes || 'Re-assessment recommended within 2 weeks from date of participation.',
    };
  }

  function renderCsvPreview() {
    const records = csvParsedRows.map(buildVaptCertFromRow);
    const dups = [], noId = [];
    document.getElementById('csvPreviewWrap').style.display = 'block';
    document.getElementById('csvPreviewCount').textContent  = records.length;
    document.getElementById('csvImportBtn').disabled = false;
    let html = '<table style="width:100%;border-collapse:collapse"><thead><tr style="position:sticky;top:0;background:var(--navy-mid);z-index:1">';
    ['#','Cert ID','Vessel','IMO','Assess Date','Valid Until','Email','Status'].forEach(h =>
      html += '<th style="padding:7px 10px;text-align:left;font-size:.59rem;letter-spacing:.1em;color:var(--text-sec);text-transform:uppercase;border-bottom:1px solid var(--border);white-space:nowrap">' + h + '</th>'
    );
    html += '</tr></thead><tbody>';
    records.forEach((c, i) => {
      const existing    = CERTS.find(x => x.id === c.id);
      const hasId       = !!c.id;
      const rowBg       = existing ? 'background:rgba(255,170,46,.05)' : !hasId ? 'background:rgba(255,107,138,.05)' : '';
      const idColor     = existing ? 'var(--warn)' : !hasId ? 'var(--invalid)' : 'var(--teal)';
      const statusTxt   = existing ? '⚠ Exists' : !hasId ? '✗ No ID' : '✓ New';
      const statusColor = existing ? 'var(--warn)' : !hasId ? 'var(--invalid)' : 'var(--teal)';
      const emailChip   = c.recipientEmail ? '<span style="color:var(--teal);font-size:.6rem">✓</span>' : '<span style="color:var(--text-sec);font-size:.6rem">—</span>';
      if (existing) dups.push(c.id);
      if (!hasId)   noId.push(i+1);
      html += '<tr style="' + rowBg + ';border-bottom:1px solid var(--border)">'
        + '<td style="padding:6px 10px;color:var(--text-sec);font-size:.63rem">' + (i+1) + '</td>'
        + '<td style="padding:6px 10px;font-family:\'JetBrains Mono\',monospace;font-size:.61rem;color:' + idColor + '">' + (c.id||'—') + '</td>'
        + '<td style="padding:6px 10px;font-size:.65rem;color:var(--text-bright);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + c.recipientName + '">' + (c.recipientName||'—') + '</td>'
        + '<td style="padding:6px 10px;font-size:.65rem">' + (c.vesselIMO||'—') + '</td>'
        + '<td style="padding:6px 10px;font-size:.63rem">' + (c.assessmentDate||'—') + '</td>'
        + '<td style="padding:6px 10px;font-size:.63rem;color:var(--teal)">' + (c.validUntil||'—') + '</td>'
        + '<td style="padding:6px 10px;text-align:center">' + emailChip + '</td>'
        + '<td style="padding:6px 10px;font-size:.63rem;color:' + statusColor + ';white-space:nowrap">' + statusTxt + '</td></tr>';
    });
    html += '</tbody></table>';
    document.getElementById('csvPreviewTable').innerHTML = html;
    const warnBox = document.getElementById('csvWarnBox');
    const warns   = [];
    if (dups.length) warns.push('⚠ ' + dups.length + ' duplicate(s) will be skipped: ' + dups.slice(0,3).join(', ') + (dups.length>3?'…':''));
    if (noId.length) warns.push('✗ ' + noId.length + ' row(s) cannot generate ID: rows ' + noId.slice(0,5).join(', '));
    if (warns.length) { warnBox.style.display='block'; warnBox.innerHTML=warns.map(w=>'<div>'+w+'</div>').join(''); }
    else warnBox.style.display='none';
  }

  async function doImportCsv() {
    if (!csvParsedRows.length) { toast('Please upload a CSV file before importing.', 'err'); return; }
    const records  = csvParsedRows.map(buildVaptCertFromRow);
    const btn      = document.getElementById('csvImportBtn'); btn.disabled = true;
    document.getElementById('csvImportTxt').textContent = 'Importing…';
    const logEl    = document.getElementById('csvResultLog'); logEl.style.display='block'; logEl.innerHTML='';
    const toImport = records.filter(c => c.id && !CERTS.find(x => x.id === c.id));
    const skipped  = records.filter(c => !c.id || CERTS.find(x => x.id === c.id));
    skipped.forEach(c => {
      if (!c.id) logEl.innerHTML += '<div style="color:var(--warn)">⚠ Skipped row — could not generate ID</div>';
      else       logEl.innerHTML += '<div style="color:var(--warn)">⚠ Skipped ' + c.id + ' — already exists</div>';
    });
    if (toImport.length > 0) {
      try {
        const r = await fetch(API + '/vapt/import-csv', { method:'POST', headers:{ Authorization:'Bearer '+TOKEN, 'Content-Type':'application/json' }, body:JSON.stringify(toImport) });
        const d = await r.json();
        if (r.ok) {
          d.results.forEach(res => {
            if (res.status==='created')       logEl.innerHTML += '<div style="color:var(--teal)">✓ Created ' + res.id + '</div>';
            else if (res.status==='skipped')  logEl.innerHTML += '<div style="color:var(--warn)">⚠ Skipped ' + res.id + ': ' + res.reason + '</div>';
            else                              logEl.innerHTML += '<div style="color:var(--invalid)">✗ Failed ' + res.id + ': ' + (res.reason||'Error') + '</div>';
          });
          logEl.innerHTML += '<div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border);color:var(--gold)">Done — ✓ ' + d.added + ' created · ⚠ ' + (d.skipped+skipped.length) + ' skipped · ✗ ' + d.failed + ' failed</div>';
          await refreshStats(); renderTbl('dashTbl',''); renderTbl('allTbl','');
          if (d.added > 0) toast(d.added + ' VAPT certificate(s) imported!', 'ok');
        } else {
          logEl.innerHTML += '<div style="color:var(--invalid)">✗ Import failed: ' + (d.error||'Unknown error') + '</div>';
        }
      } catch(err) { logEl.innerHTML += '<div style="color:var(--invalid)">✗ Import interrupted — connection error.</div>'; }
    }
    document.getElementById('csvImportTxt').textContent = 'Import All Records';
    btn.disabled = false;
  }

  function clearCsvFile(e) {
    if (e) e.stopPropagation();
    csvParsedRows = []; csvRawHeaders = []; csvColMapVapt = {};
    document.getElementById('csvFileInput').value = '';
    document.getElementById('csvUploadDefault').style.display = 'block';
    document.getElementById('csvUploadLoaded').style.display  = 'none';
    document.getElementById('csvPreviewWrap').style.display   = 'none';
    document.getElementById('csvResultLog').style.display     = 'none';
    document.getElementById('csvImportBtn').disabled          = true;
  }

  function downloadSampleCsv() {
    // Same vessels/IMOs, same "MV - "/"MT - " prefix format as the CST dashboard's
    // sample CSV — importing both keeps the two systems' vessel names aligned.
    const csv = [
      'imo_number,vessel_name,assessment_date,cert_number,recipient_email,notes',
      '9491666,MV - EFFICIENCY OL,10-Feb-26,VAP-9491666-0226,master@efficiencyol.com,VAPT completed',
      '9623740,MV - NORD KUDU,15-Mar-26,,master@nordkudu.com,',
      '9689536,MT - BW CHINOOK,20-Mar-26,,chief@bwchinook.com,Follow-up required',
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vapt_import_sample.csv';
    a.click();
  }

  // ── UTILS ──
  function openLB(src){document.getElementById('lbImg').src=src;document.getElementById('lightbox').style.display='flex';}
  function closeLB(){document.getElementById('lightbox').style.display='none';}
  function openPdfViewer(url, name){
    document.getElementById('pdfViewerTitle').textContent = name || 'Document';
    document.getElementById('pdfViewerFrame').src = url;
    document.getElementById('pdfViewerLink').href = url;
    document.getElementById('pdfViewerOverlay').style.display = 'flex';
  }
  function closePdfViewer(){
    document.getElementById('pdfViewerOverlay').style.display = 'none';
    document.getElementById('pdfViewerFrame').src = '';
  }
  function toast(msg,type='ok'){const t=document.getElementById('toast');t.textContent=msg;t.className='show '+type;setTimeout(()=>t.className='',3500);}
  document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeLB();closeView();closeDel();closePdfViewer();closeSidebar();}});

  // ── NEAR-EXPIRY BANNER ────────────────────────────────────────────────
  function checkNearExpiryBanner(certs) {
    const now = new Date();
    const near = (certs || []).filter(c => {
      if (!c.validUntil || (c.status||'').toUpperCase() !== 'VALID') return false;
      const d = Math.round((new Date(c.validUntil).setHours(0,0,0,0) - now.setHours(0,0,0,0)) / 86400000);
      return d >= 0 && d <= 30;
    });
    const banner = document.getElementById('nearExpiryBanner');
    if (!banner) return;
    if (!near.length) { banner.style.display = 'none'; return; }
    banner.style.display = 'flex';
    banner.innerHTML = `
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
      <div><strong>${near.length} VAPT certificate${near.length===1?'':'s'} expiring within 30 days</strong> —
      ${near.slice(0,3).map(c=>{const d=Math.round((new Date(c.validUntil).setHours(0,0,0,0)-new Date().setHours(0,0,0,0))/86400000);return `<span style="font-family:'JetBrains Mono',monospace;font-size:.75em">${c.id}</span> (${d}d)`;}).join(', ')}${near.length>3?' …':''}</div>
      <button data-action="dismissParent" style="margin-left:auto;background:none;border:none;color:currentColor;cursor:pointer;opacity:.6;font-size:1rem;padding:0 4px;line-height:1" aria-label="Dismiss">✕</button>
    `;
  }

  // ── MOBILE SIDEBAR TOGGLE ────────────────────────────────────────────
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
  document.addEventListener('click', function(e) {
    if (e.target.closest('.nav-item') && window.innerWidth <= 900) { closeSidebar(); }
  });



  // ── BOOT ──
  // Authenticated/not is decided by whether the server actually delivered the
  // app markup — for unauthenticated requests, sendAdminAppShell() strips
  // everything between the SERVER-GATED:APPWRAP markers, leaving an empty
  // #appWrap shell. No client-side token decode needed for this decision.
  const _appWrapEl = document.getElementById('appWrap');
  if (_appWrapEl && _appWrapEl.children.length > 0) {
    document.getElementById('loginWrap').style.display='none';
    _appWrapEl.style.display='flex';
    _appWrapEl.classList.add('fade-in');
    scheduleTokenExpiryWarning();
    initApp();
  } else if (_appWrapEl) {
    _appWrapEl.style.display='none';
  }


let _lastAppliedConfig = null;
function applyConfig() {

  var C = window.APP_CONFIG;
  if (!C || C === _lastAppliedConfig) return;
  _lastAppliedConfig = C;
  document.title = C.titles.vaptAdmin;
  var el;
  if ((el=document.getElementById('loginSub')))    el.textContent = C.nav.vaptLoginSub;
  if ((el=document.getElementById('sbName')))      el.textContent = C.nav.vptSidebarName;
  if ((el=document.getElementById('adminRole')))   el.textContent = C.brand.adminRole;
  if ((el=document.getElementById('pvOrgName')))   el.textContent = C.vapt.previewOrgName;
  if ((el=document.getElementById('pvTeamName')))  el.textContent = C.vapt.previewTeamName;
  if ((el=document.getElementById('pv-verifier'))) el.textContent = C.vapt.previewSigName;
  // Form field defaults from config
  if ((el=document.getElementById('fVerifiedBy')))    el.value = C.vapt.verifiedBy;
  if ((el=document.getElementById('fVerifierTitle'))) el.value = C.vapt.verifierTitle;
  if ((el=document.getElementById('fAssessingOrg')))  el.value = C.vapt.assessingOrg;
  if ((el=document.getElementById('fFrameworks')))    el.value = C.vapt.frameworks;
  if ((el=document.getElementById('fScopeItems')))    el.value = C.vapt.scopeItems;
  if ((el=document.getElementById('fIssuerEmail')))   el.value = C.vapt.issuerEmail;
  // Sidebar nav links
  var sbVPT = document.getElementById('sbLinkVPT');      if (sbVPT)     sbVPT.href     = C.routes.vpt;
  var sbCST = document.getElementById('sbLinkCSTAdmin'); if (sbCST)     sbCST.href     = C.routes.cstAdmin;
  var adm = C.routes.cstAdmin || '/console/cst';
  var navDocs  = document.getElementById('navLinkDocuments'); if (navDocs)  navDocs.href  = adm + '/?tab=docs';
  var navGrps  = document.getElementById('navLinkGroups');    if (navGrps)  navGrps.href  = adm + '/?tab=groups';
  var navUsers = document.getElementById('navLinkUsers');     if (navUsers) navUsers.href = adm + '/?tab=users';
}
  // Call immediately (fast path if config.js already loaded)
  applyConfig();
  // Fallback: also call after DOM + scripts are fully ready
  if (document.readyState !== 'complete') {
    window.addEventListener('load', applyConfig);
  }
  // Also call applyConfig when config.js (deferred) finishes loading
  document.addEventListener('appconfigready', applyConfig);


// ── SESSION EXPIRY & IDLE TIMEOUT — VAPT DASHBOARD ───────────────────────────
(function () {
  'use strict';
  function getCfg() { return (window.APP_CONFIG && window.APP_CONFIG.session) || {}; }
  var _sessionStart = null;
  var _sessionTimer = null, _idleTimer = null, _idleWarnTimer = null, _sessionWarnTimer = null;
  var _idleCI = null, _sessionCI = null;

  function fmtMs(ms) {
    var s = Math.max(0, Math.ceil(ms / 1000)), m = Math.floor(s / 60), sec = s % 60;
    return m + ':' + (sec < 10 ? '0' : '') + sec;
  }

  function showSessionWarn(msLeft) {
    var b = document.getElementById('sessionWarningBanner'), el = document.getElementById('sessionCountdown');
    if (!b) return; b.style.display = 'block';
    clearInterval(_sessionCI); var rem = msLeft;
    if (el) el.textContent = fmtMs(rem);
    _sessionCI = setInterval(function () { rem -= 1000; if (el) el.textContent = fmtMs(rem); if (rem <= 0) clearInterval(_sessionCI); }, 1000);
  }
  function hideSessionWarn() { var b = document.getElementById('sessionWarningBanner'); if (b) b.style.display = 'none'; clearInterval(_sessionCI); }

  function showIdleWarn(msLeft) {
    var b = document.getElementById('idleWarningBanner'), el = document.getElementById('idleCountdown');
    if (!b) return; b.style.display = 'block';
    clearInterval(_idleCI); var rem = msLeft;
    if (el) el.textContent = fmtMs(rem);
    _idleCI = setInterval(function () { rem -= 1000; if (el) el.textContent = fmtMs(rem); if (rem <= 0) clearInterval(_idleCI); }, 1000);
  }
  function hideIdleWarn() { var b = document.getElementById('idleWarningBanner'); if (b) b.style.display = 'none'; clearInterval(_idleCI); }

  window.resetIdle = function () { hideIdleWarn(); startIdleTimeout(); };

  // Re-verify session with server (httpOnly cookie-backed; no client-held token needed).
  window.refreshSession = function () {
    fetch('/api/auth/verify')
      .then(function (r) { if (r.ok) { hideSessionWarn(); if (_sessionStart) _sessionStart = Date.now(); scheduleSessionTimers(); } else { if (typeof doLogout === 'function') doLogout(); } })
      .catch(function () { hideSessionWarn(); });
  };

  function scheduleSessionTimers() {
    clearTimeout(_sessionTimer); clearTimeout(_sessionWarnTimer);
    var cfg = getCfg(), maxMs = cfg.maxDurationMs || 8*60*60*1000, warnBefore = cfg.warningBeforeMs || 5*60*1000;
    var remaining = Math.max(0, maxMs - (_sessionStart ? Date.now() - _sessionStart : 0));
    var warnAt = Math.max(0, remaining - warnBefore);
    _sessionWarnTimer = setTimeout(function () { showSessionWarn(warnBefore); }, warnAt);
    _sessionTimer     = setTimeout(function () { clearInterval(_sessionCI); if (typeof doLogout === 'function') doLogout(); }, remaining);
  }

  function startIdleTimeout() {
    clearTimeout(_idleTimer); clearTimeout(_idleWarnTimer);
    var cfg = getCfg(), idleMs = cfg.idleTimeoutMs || 30*60*1000, warnBefore = cfg.idleWarningBeforeMs || 2*60*1000;
    _idleWarnTimer = setTimeout(function () { showIdleWarn(warnBefore); }, idleMs - warnBefore);
    _idleTimer     = setTimeout(function () { clearInterval(_idleCI); if (typeof doLogout === 'function') doLogout(); }, idleMs);
  }

  var _actThrottle = null;
  function onActivity() {
    if (_actThrottle) return;
    _actThrottle = setTimeout(function () { _actThrottle = null; }, 10000);
    hideIdleWarn(); startIdleTimeout();
  }
  ['mousemove','keydown','pointerdown','scroll','touchstart'].forEach(function(ev){ document.addEventListener(ev, onActivity, {passive:true}); });

  window._startSessionTimers = function (startMs) { _sessionStart = startMs || Date.now(); scheduleSessionTimers(); startIdleTimeout(); };

  // Auto-start if already logged in (token in storage)
  var tok = sessionStorage.getItem('adminToken') || '';
  if (tok) {
    try { var parts = tok.split('.'); if (parts.length === 3) { var p = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/'))); if (p && p.iat) _sessionStart = p.iat * 1000; /* iat is seconds; _sessionStart arithmetic is ms — see cst/dashboard.js for the full explanation */ } } catch(e) {}
    if (!_sessionStart) _sessionStart = Date.now();
    scheduleSessionTimers(); startIdleTimeout();
  }
})();

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
    if (certsPage && certsPage.style.display !== 'none') renderTbl('allTbl', document.getElementById('allQ')?.value||'', document.getElementById('allStatusSel')?.value||'', document.getElementById('allEmailSel')?.value||'');
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
  const allCb = document.getElementById('selAllCb_allTbl');
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
