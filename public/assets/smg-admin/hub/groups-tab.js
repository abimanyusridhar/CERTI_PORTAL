'use strict';
(function() {
  const API = '/api';
  let TOKEN = sessionStorage.getItem('adminToken') || '';
  let allGroups = [];
  let allUsers  = [];
  let editingId = null;
  let currentIMOs = [];
  let vesselNames = {};
  let _qvGroupId = null;

  const authHdr = () => ({ Authorization: 'Bearer ' + TOKEN });
  function checkUnauth(r) { if (r.status === 401) { window.doLogout(); return true; } return false; }

  async function loadGroupsData() {
    try {
      const [rG, rU, rV] = await Promise.all([
        fetch(API + '/admin/groups',   { headers: authHdr() }),
        fetch(API + '/admin/users',    { headers: authHdr() }),
        fetch(API + '/vessels/names',  { headers: authHdr() }),
      ]);
      if (checkUnauth(rG)) return;
      if (!rG.ok || !rU.ok) { toast('Failed to load data', true); return; }
      allGroups   = await rG.json();
      allUsers    = await rU.json();
      vesselNames = rV.ok ? await rV.json() : {};
      updateStats();
      renderGroups();
    } catch { toast('Connection failed. Check your internet and try again.', true); }
  }
  window.loadGroupsData = loadGroupsData;

  function updateStats() {
    const totalVessels = new Set(allGroups.flatMap(g => g.vesselIMOs || [])).size;
    document.getElementById('gStatGroups').textContent  = allGroups.length;
    document.getElementById('gStatVessels').textContent = totalVessels;
    document.getElementById('gStatUsers').textContent   = allUsers.filter(u => u.active).length;
  }

  function renderGroups() {
    const q = (document.getElementById('groupSearch').value || '').toLowerCase();
    const list = allGroups.filter(g => !q || g.name.toLowerCase().includes(q) || (g.vesselIMOs||[]).some(i => i.toLowerCase().includes(q)));
    const grid  = document.getElementById('groupsGrid');
    const empty = document.getElementById('groupsEmpty');
    if (!list.length) { grid.innerHTML = ''; empty.style.display = 'block'; qvPopulateSelect(); return; }
    empty.style.display = 'none';
    const fmtDt = s => s ? new Date(s).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
    const escH  = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
    grid.innerHTML = list.map(g => {
      const imos = (g.vesselIMOs||[]).map(i => {
        const name = vesselNames[i.toUpperCase()] || vesselNames[i];
        return `<span class="imo-chip" title="${escH(i)}">${name ? escH(name) : escH(i)}<span style="opacity:.55;font-size:.58rem;margin-left:4px">${name ? escH(i) : ''}</span></span>`;
      }).join('');
      return `<div class="group-card">
        <div class="group-card-head">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--gold)" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
          <span class="group-name">${escH(g.name)}</span>
          <span class="vessel-count">${(g.vesselIMOs||[]).length} vessel${(g.vesselIMOs||[]).length!==1?'s':''}</span>
        </div>
        <div class="group-card-body">
          <div class="imo-chips">${imos||'<span style="color:var(--text-sec);font-size:.7rem">No vessels assigned</span>'}</div>
          ${g.notes ? `<div class="group-notes">${escH(g.notes)}</div>` : ''}
          <div class="group-meta" style="margin-bottom:12px">Created ${fmtDt(g.createdAt)}</div>
          <div class="group-actions">
            <button class="btn-sm" data-action="openGroupEditModal" data-id="${escH(g.id)}">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
              Edit
            </button>
            <button class="btn-sm danger" data-action="deleteGroup" data-id="${escH(g.id)}" data-name="${escH(g.name)}">Delete</button>
          </div>
        </div>
      </div>`;
    }).join('');
    qvPopulateSelect();
  }
  window.renderGroups = renderGroups;

  function renderImoTags() {
    const el = document.getElementById('imoTagList');
    el.innerHTML = currentIMOs.map((imo, idx) => {
      const name = vesselNames[imo.toUpperCase()];
      const label = name ? `${name} <span style="opacity:.6;font-size:.6rem">${imo}</span>` : imo;
      return `<span class="imo-tag">${label}<button data-action="removeImo" data-idx="${idx}" title="Remove">×</button></span>`;
    }).join('');
  }

  function addImoRaw(imo) {
    const raw = imo.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!raw) return;
    if (!currentIMOs.includes(raw)) { currentIMOs.push(raw); renderImoTags(); }
    document.getElementById('gmImoInput').value = '';
    closeSuggest();
  }
  window.addImoRaw = addImoRaw;

  function addImoFromInput() {
    const val = document.getElementById('gmImoInput').value.trim();
    if (!val) return;
    const raw = val.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (raw) addImoRaw(raw);
  }
  window.addImoFromInput = addImoFromInput;

  function removeImo(idx) { currentIMOs.splice(idx, 1); renderImoTags(); }
  window.removeImo = removeImo;

  const escHtml = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

  function onVesselSearch(q) {
    const suggest = document.getElementById('vesselSuggest');
    if (!q || !q.trim()) { closeSuggest(); return; }
    const lower = q.toLowerCase();
    const entries = Object.entries(vesselNames);
    const matches = entries.filter(([imo, name]) =>
      name.toLowerCase().includes(lower) || imo.toLowerCase().includes(lower)
    ).slice(0, 12);
    if (!matches.length) { closeSuggest(); return; }
    suggest.innerHTML = matches.map(([imo, name]) =>
      `<div class="vessel-suggest-item" data-action="addImoRaw" data-imo="${escHtml(imo)}">
        <span class="vs-name">${escHtml(name)}</span>
        <span class="vs-imo">${imo}</span>
      </div>`
    ).join('');
    suggest.classList.add('open');
  }
  window.onVesselSearch = onVesselSearch;

  function closeSuggest() {
    const s = document.getElementById('vesselSuggest');
    if (s) { s.classList.remove('open'); s.innerHTML = ''; }
  }
  window.closeSuggest = closeSuggest;
  document.addEventListener('click', e => {
    if (!e.target.closest('#vesselSuggest') && !e.target.closest('#gmImoInput')) closeSuggest();
  });

  // Replaces the removed inline onkeydown="if(event.key==='Escape'){closeSuggest();}
  // else if(event.key==='Enter'||event.key===','){event.preventDefault();addImoFromInput();}"
  const gmImoInputEl = document.getElementById('gmImoInput');
  if (gmImoInputEl) {
    gmImoInputEl.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        closeSuggest();
      } else if (event.key === 'Enter' || event.key === ',') {
        event.preventDefault();
        addImoFromInput();
      }
    });
  }

  function buildMemberList(selectedIds) {
    const el = document.getElementById('memberSelectList');
    const supts = allUsers.filter(u => u.active || (selectedIds||[]).includes(u.id));
    if (!supts.length) {
      el.innerHTML = '<div style="padding:12px;font-size:.75rem;color:var(--text-sec)">No users yet. Superintendents appear here after their first AWS SSO sign-in.</div>';
      return;
    }
    el.innerHTML = supts.map(u => {
      const checked = (selectedIds||[]).includes(u.id) ? 'checked' : '';
      const inactive = !u.active ? ' <span style="font-size:.6rem;color:var(--invalid);margin-left:4px">(inactive)</span>' : '';
      return `<label style="display:flex;align-items:center;gap:10px;padding:9px 13px;border-bottom:1px solid rgba(100,255,218,.06);cursor:pointer;font-size:.78rem;color:var(--text-sec)">
        <input type="checkbox" value="${escHtml(u.id)}" ${checked} style="accent-color:var(--teal);flex-shrink:0" />
        <span style="min-width:0">
          <strong style="color:var(--text-bright)">${escHtml(u.name)}</strong>${inactive}
          <span style="color:var(--text-sec);font-size:.65rem;margin-left:7px;display:block">${escHtml(u.email)}</span>
        </span>
      </label>`;
    }).join('');
  }

  function openCreateGroupModal() {
    editingId = null;
    currentIMOs = [];
    document.getElementById('groupModalTitle').textContent = 'New Group';
    document.getElementById('gmName').value   = '';
    document.getElementById('gmNotes').value  = '';
    document.getElementById('gmImoInput').value = '';
    document.getElementById('groupModalErr').classList.remove('show');
    renderImoTags();
    buildMemberList([]);
    document.getElementById('groupModal').classList.add('open');
  }
  window.openCreateGroupModal = openCreateGroupModal;

  function openGroupEditModal(id) {
    const g = allGroups.find(x => x.id === id);
    if (!g) return;
    editingId = id;
    currentIMOs = [...(g.vesselIMOs || [])];
    document.getElementById('groupModalTitle').textContent = 'Edit Group';
    document.getElementById('gmName').value   = g.name;
    document.getElementById('gmNotes').value  = g.notes || '';
    document.getElementById('gmImoInput').value = '';
    document.getElementById('groupModalErr').classList.remove('show');
    renderImoTags();
    const currentMemberIds = allUsers.filter(u => (u.groupIds||[]).includes(id)).map(u => u.id);
    buildMemberList(currentMemberIds);
    document.getElementById('groupModal').classList.add('open');
  }
  window.openGroupEditModal = openGroupEditModal;

  function closeGroupModal() { document.getElementById('groupModal').classList.remove('open'); }
  window.closeGroupModal = closeGroupModal;

  async function saveGroup() {
    const name  = document.getElementById('gmName').value.trim();
    const notes = document.getElementById('gmNotes').value.trim();
    const err   = document.getElementById('groupModalErr');
    err.classList.remove('show');
    if (!name) { err.textContent = 'Group name is required.'; err.classList.add('show'); return; }
    const body = { name, vesselIMOs: currentIMOs, notes };
    const btn = document.getElementById('saveGroupBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      const url    = editingId ? API + '/admin/groups/' + editingId : API + '/admin/groups';
      const method = editingId ? 'PUT' : 'POST';
      const r = await fetch(url, { method, headers: { ...authHdr(), 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const d = await r.json();
      if (!r.ok) { err.textContent = d.error || 'Save failed.'; err.classList.add('show'); return; }
      const savedGroupId = d.id || editingId;

      const selectedMemberIds = Array.from(
        document.querySelectorAll('#memberSelectList input[type=checkbox]:checked')
      ).map(c => c.value);

      const memberUpdates = allUsers.map(u => {
        const inGroup    = (u.groupIds || []).includes(savedGroupId);
        const shouldBe   = selectedMemberIds.includes(u.id);
        if (inGroup === shouldBe) return null;
        const newGroupIds = shouldBe
          ? [...new Set([...(u.groupIds || []), savedGroupId])]
          : (u.groupIds || []).filter(gid => gid !== savedGroupId);
        return fetch(API + '/admin/users/' + u.id, {
          method: 'PUT',
          headers: { ...authHdr(), 'Content-Type': 'application/json' },
          body: JSON.stringify({ groupIds: newGroupIds }),
        });
      }).filter(Boolean);

      if (memberUpdates.length) await Promise.all(memberUpdates);

      closeGroupModal();
      toast(editingId ? 'Group updated.' : 'Group created.');
      await loadGroupsData();
    } catch (e) { err.textContent = 'Connection failed. Check your internet and try again.'; err.classList.add('show'); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Save Group'; } }
  }
  window.saveGroup = saveGroup;

  async function deleteGroup(id, name) {
    const ok = await confirmDanger('Delete group <strong>' + name + '</strong>?<br><span style="font-size:.75rem;opacity:.7">Superintendents in this group will lose vessel access. This cannot be undone.</span>');
    if (!ok) return;
    try {
      const r = await fetch(API + '/admin/groups/' + id, { method: 'DELETE', headers: authHdr() });
      if (!r.ok) { toast('Could not delete group. Please try again.', true); return; }
      toast('Group deleted.');
      await loadGroupsData();
    } catch { toast('Connection failed. Check your internet and try again.', true); }
  }
  window.deleteGroup = deleteGroup;

  function confirmDanger(msg, confirmLabel) {
    return new Promise(resolve => {
      const ov = document.createElement('div');
      ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:9999';
      ov.innerHTML = `<div style="background:#0F2038;border:1px solid rgba(255,107,138,.3);border-radius:14px;padding:28px;max-width:380px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.6)">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
          <div style="width:36px;height:36px;border-radius:50%;background:rgba(255,107,138,.12);border:1px solid rgba(255,107,138,.3);display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#FF5C7A" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
          </div>
          <span style="font-size:.9rem;font-weight:700;color:#FF5C7A">Confirm Delete</span>
        </div>
        <p style="font-size:.82rem;color:#7689AE;line-height:1.65;margin-bottom:22px">${msg}</p>
        <div style="display:flex;gap:10px;justify-content:flex-end">
          <button id="_cdCancel2" style="padding:8px 18px;border-radius:8px;border:1px solid rgba(255,255,255,.12);background:transparent;color:#7689AE;font-size:.8rem;cursor:pointer;font-family:inherit">Cancel</button>
          <button id="_cdConfirm2" style="padding:8px 18px;border-radius:8px;border:none;background:#FF5C7A;color:#fff;font-size:.8rem;font-weight:700;cursor:pointer;font-family:inherit">${confirmLabel || 'Delete'}</button>
        </div>
      </div>`;
      document.body.appendChild(ov);
      ov.querySelector('#_cdConfirm2').onclick = () => { ov.remove(); resolve(true); };
      ov.querySelector('#_cdCancel2').onclick  = () => { ov.remove(); resolve(false); };
      ov.onclick = e => { if (e.target === ov) { ov.remove(); resolve(false); } };
    });
  }

  function toast(msg, isErr) {
    const el = document.createElement('div');
    el.className = 'toast-msg ' + (isErr ? 'err' : 'ok');
    el.textContent = msg;
    document.getElementById('toast').appendChild(el);
    setTimeout(() => el.remove(), 3200);
  }

  function qvPopulateSelect() {
    const sel = document.getElementById('qvGroup');
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = '<option value="">— Choose a group —</option>';
    for (const g of allGroups) {
      const opt = document.createElement('option');
      opt.value = g.id; opt.textContent = g.name;
      sel.appendChild(opt);
    }
    if (cur) sel.value = cur;
  }

  function qvLoadGroup() {
    _qvGroupId = document.getElementById('qvGroup').value || null;
    const nameEl = document.getElementById('qvGroupName');
    const listEl = document.getElementById('qvVesselList');
    if (!_qvGroupId) {
      if (nameEl) nameEl.textContent = '';
      if (listEl) listEl.innerHTML = '<div style="color:var(--text-sec);font-size:.72rem;padding:20px 0;text-align:center">Select a group to view its vessels</div>';
      return;
    }
    const g = allGroups.find(x => x.id === _qvGroupId);
    if (!g) return;
    if (nameEl) nameEl.textContent = g.name;
    qvRenderVessels(g);
  }
  window.qvLoadGroup = qvLoadGroup;

  function qvRenderVessels(g) {
    const listEl = document.getElementById('qvVesselList');
    if (!listEl) return;
    const imos = g.vesselIMOs || [];
    if (!imos.length) {
      listEl.innerHTML = '<div style="color:var(--text-sec);font-size:.72rem;padding:14px 0;text-align:center">No vessels in this group yet</div>';
      return;
    }
    listEl.innerHTML = imos.map(imo => {
      const name = vesselNames[imo.toUpperCase()] || vesselNames[imo] || '';
      return `<div style="display:flex;align-items:center;gap:8px;padding:6px 2px;border-bottom:1px solid rgba(255,255,255,.04)">
        <div style="flex:1;min-width:0">
          <div style="font-size:.72rem;font-weight:600;color:var(--text-bright)">${name || imo}</div>
          ${name ? `<div style="font-size:.6rem;color:var(--text-sec);font-family:monospace">${imo}</div>` : ''}
        </div>
        <button data-action="qvRemoveVessel" data-imo="${escHtml(imo)}" style="padding:3px 9px;border-radius:6px;border:1px solid rgba(255,107,138,.25);background:rgba(255,107,138,.05);color:var(--invalid);font-size:.6rem;cursor:pointer" title="Remove from group">Remove</button>
      </div>`;
    }).join('');
  }

  function qvSearch(q) {
    const sug = document.getElementById('qvSuggest');
    if (!sug) return;
    if (!q || q.length < 2) { sug.style.display = 'none'; return; }
    const matches = Object.entries(vesselNames)
      .filter(([imo, name]) => imo.includes(q.toUpperCase()) || name.toLowerCase().includes(q.toLowerCase()))
      .slice(0, 8);
    if (!matches.length) { sug.style.display = 'none'; return; }
    sug.style.display = 'block';
    sug.innerHTML = matches.map(([imo, name]) =>
      `<div class="qv-suggest-item" data-action="qvPickVessel" data-imo="${escHtml(imo)}" style="padding:7px 12px;cursor:pointer;font-size:.72rem;border-bottom:1px solid rgba(255,255,255,.04);display:flex;align-items:center;justify-content:space-between">
        <span style="color:var(--text-bright);font-weight:600">${name}</span>
        <span style="font-family:monospace;font-size:.6rem;color:var(--text-sec)">${imo}</span>
      </div>`
    ).join('');
  }
  window.qvSearch = qvSearch;

  function qvPickVessel(imo) {
    document.getElementById('qvImoInput').value = imo;
    document.getElementById('qvSuggest').style.display = 'none';
  }
  window.qvPickVessel = qvPickVessel;

  // Matches vesselName loosely — strips the MV/MT/M-V prefix (same convention
  // dashboard.js's CSV import already applies) and collapses whitespace — so
  // "MV Nord Kudu" and "Nord  Kudu" both resolve to the same stored vessel
  // instead of silently falling through to the raw-IMO branch below.
  function _canonicalVesselName(n) {
    return String(n || '').replace(/^(MV|MT|M\/V)\s*[-–]?\s*/i, '').trim().toLowerCase().replace(/\s+/g, ' ');
  }

  async function qvAddVessel() {
    if (!_qvGroupId) { alert('Please select a group first.'); return; }
    const val = (document.getElementById('qvImoInput').value || '').trim();
    if (!val) { alert('Please enter a vessel IMO or select from suggestions.'); return; }
    const lv = _canonicalVesselName(val);
    const byName = Object.entries(vesselNames).find(([, n]) => _canonicalVesselName(n) === lv);
    // A real IMO always contains at least one digit — if the name lookup missed
    // AND the input has no digit, it's almost certainly a misspelled vessel name,
    // not an IMO, so don't silently add it as one.
    const looksLikeImo = /\d/.test(val);
    const imo = byName ? byName[0] : (looksLikeImo ? val.toUpperCase().replace(/[^A-Z0-9]/g, '') : '');
    if (!imo) { alert('No vessel found matching that name, and it doesn\'t look like a valid IMO. Check the spelling or pick from the suggestions list.'); return; }
    try {
      const r = await fetch(API + '/admin/groups/' + _qvGroupId + '/vessels', {
        method: 'POST', headers: { ...authHdr(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ vesselIMO: imo })
      });
      if (!r.ok) { const d = await r.json(); alert(d.error || 'Error'); return; }
      const updated = await r.json();
      document.getElementById('qvImoInput').value = '';
      document.getElementById('qvSuggest').style.display = 'none';
      const idx = allGroups.findIndex(g => g.id === _qvGroupId);
      if (idx >= 0) allGroups[idx] = updated;
      qvRenderVessels(updated);
      renderGroups();
    } catch { alert('Network error'); }
  }
  window.qvAddVessel = qvAddVessel;

  async function qvRemoveVessel(imo) {
    if (!_qvGroupId) return;
    if (!confirm('Remove ' + imo + ' from this group?')) return;
    try {
      const r = await fetch(API + '/admin/groups/' + _qvGroupId + '/vessels/' + imo, {
        method: 'DELETE', headers: authHdr()
      });
      if (!r.ok) { const d = await r.json(); alert(d.error || 'Error'); return; }
      const updated = await r.json();
      const idx = allGroups.findIndex(g => g.id === _qvGroupId);
      if (idx >= 0) allGroups[idx] = updated;
      qvRenderVessels(updated);
      renderGroups();
    } catch { alert('Network error'); }
  }
  window.qvRemoveVessel = qvRemoveVessel;

  if (TOKEN) loadGroupsData();
})();
