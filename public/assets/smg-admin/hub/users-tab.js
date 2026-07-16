'use strict';
(function() {
  const API = '/api';
  let TOKEN = sessionStorage.getItem('adminToken') || '';
  let allUsers  = [];
  let allGroups = [];
  let editingId = null;

  const authHdr = () => ({ Authorization: 'Bearer ' + TOKEN });
  function checkUnauth(r) { if (r.status === 401) { window.doLogout(); return true; } return false; }

  async function loadUsersData() {
    try {
      const [rU, rG] = await Promise.all([
        fetch(API + '/admin/users',  { headers: authHdr() }),
        fetch(API + '/admin/groups', { headers: authHdr() }),
      ]);
      if (checkUnauth(rU)) return;
      if (!rU.ok || !rG.ok) { toast('Failed to load data', true); return; }
      allUsers  = await rU.json();
      allGroups = await rG.json();
      updateStats();
      renderUsers();
    } catch { toast('Connection failed. Check your internet and try again.', true); }
  }
  window.loadUsersData = loadUsersData;

  function updateStats() {
    document.getElementById('uStatTotal').textContent      = allUsers.length;
    document.getElementById('uStatActive').textContent     = allUsers.filter(u => u.active).length;
    document.getElementById('uStatSuperint').textContent   = allUsers.filter(u => u.role === 'superintendent').length;
    document.getElementById('uStatGroupsAvail').textContent = allGroups.length;
  }

  function renderUsers() {
    const q = (document.getElementById('userSearch').value || '').toLowerCase();
    const list = allUsers.filter(u => !q || u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q));
    const tbody = document.getElementById('userTbody');
    const empty = document.getElementById('userEmpty');
    if (!list.length) {
      tbody.innerHTML = '';
      const msgEl = empty.querySelector('div');
      if (msgEl) msgEl.textContent = q ? 'No users match your search.' : 'No users yet. Click "Add User" to create your first superintendent.';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    const fmtDt = s => s ? new Date(s).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
    const escH = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
    const groupMap = Object.fromEntries(allGroups.map(g => [g.id, g]));
    tbody.innerHTML = list.map(u => {
      const chips = (u.groupIds||[]).map(gid => groupMap[gid] ? `<span class="group-chip" title="${(groupMap[gid].vesselIMOs||[]).length} vessel(s)">${escH(groupMap[gid].name)}</span>` : '').join('');
      const vesselCount = new Set((u.groupIds||[]).flatMap(gid => (groupMap[gid] && groupMap[gid].vesselIMOs)||[])).size;
      return `<tr>
        <td><div class="user-name">${escH(u.name)}</div><div class="user-email">${escH(u.email)}</div></td>
        <td><span class="role-badge">${escH(u.role||'superintendent')}</span></td>
        <td><div class="group-chips">${chips||'<span style="color:var(--text-sec);font-size:.68rem">No groups</span>'}</div></td>
        <td><span style="font-family:'JetBrains Mono',monospace;font-size:.82rem;color:${vesselCount?'var(--teal)':'var(--text-sec)'};font-weight:700">${vesselCount||'—'}</span></td>
        <td><span class="active-pill ${u.active?'on':'off'}">${u.active?'Active':'Inactive'}</span></td>
        <td style="font-size:.7rem;color:var(--text-sec)">${fmtDt(u.createdAt)}</td>
        <td style="text-align:right">
          <div style="display:flex;gap:6px;justify-content:flex-end">
            <button class="btn-sm" data-action="openUserEditModal" data-id="${escH(u.id)}">Edit</button>
            <button class="btn-sm danger" data-action="deleteUser" data-id="${escH(u.id)}" data-name="${escH(u.name)}">Delete</button>
          </div>
        </td>
      </tr>`;
    }).join('');
  }
  window.renderUsers = renderUsers;

  function buildGroupList(selectedIds) {
    const el = document.getElementById('groupSelectList');
    if (!allGroups.length) { el.innerHTML = '<div style="padding:12px;font-size:.75rem;color:var(--text-sec)">No groups created yet.</div>'; return; }
    el.innerHTML = allGroups.map(g => {
      const checked = (selectedIds||[]).includes(g.id) ? 'checked' : '';
      return `<label class="group-select-item"><input type="checkbox" value="${g.id}" ${checked} /><span><strong style="color:var(--text-bright)">${g.name}</strong><span style="color:var(--text-sec);font-size:.66rem;margin-left:8px">${(g.vesselIMOs||[]).length} vessel${(g.vesselIMOs||[]).length!==1?'s':''}</span></span></label>`;
    }).join('');
  }

  function openAddUserModal() {
    editingId = null;
    document.getElementById('userModalTitle').textContent = 'Add User';
    document.getElementById('umName').value  = '';
    document.getElementById('umEmail').value = '';
    document.getElementById('umEmail').readOnly = false;
    document.getElementById('umEmail').style.opacity = '';
    document.getElementById('umEmail').style.cursor  = '';
    document.getElementById('umActive').checked = true;
    document.getElementById('userModalErr').classList.remove('show');
    document.getElementById('umCognitoNote').style.display = 'block';
    buildGroupList([]);
    document.getElementById('userModal').classList.add('open');
  }
  window.openAddUserModal = openAddUserModal;

  function openUserEditModal(id) {
    const u = allUsers.find(x => x.id === id);
    if (!u) return;
    editingId = id;
    document.getElementById('userModalTitle').textContent = 'Edit User';
    document.getElementById('umName').value  = u.name;
    document.getElementById('umEmail').value = u.email;
    document.getElementById('umEmail').readOnly = true;
    document.getElementById('umEmail').style.opacity = '0.6';
    document.getElementById('umEmail').style.cursor  = 'default';
    document.getElementById('umActive').checked = !!u.active;
    document.getElementById('userModalErr').classList.remove('show');
    document.getElementById('umCognitoNote').style.display = 'none';
    buildGroupList(u.groupIds || []);
    document.getElementById('userModal').classList.add('open');
  }
  window.openUserEditModal = openUserEditModal;

  function closeUserModal() { document.getElementById('userModal').classList.remove('open'); }
  window.closeUserModal = closeUserModal;

  async function saveUser() {
    const name     = document.getElementById('umName').value.trim();
    const email    = document.getElementById('umEmail').value.trim().toLowerCase();
    const active   = document.getElementById('umActive').checked;
    const groupIds = Array.from(document.querySelectorAll('#groupSelectList input[type=checkbox]:checked')).map(c => c.value);
    const err = document.getElementById('userModalErr');
    const btn = document.getElementById('saveUserBtn');
    err.classList.remove('show');
    if (!name)  { err.textContent = 'Full name is required.';  err.classList.add('show'); document.getElementById('umName').focus();  return; }
    if (!editingId && !email) { err.textContent = 'Email address is required.'; err.classList.add('show'); document.getElementById('umEmail').focus(); return; }

    if (btn) { btn.disabled = true; btn.textContent = editingId ? 'Saving…' : 'Creating…'; }
    if (!editingId) {
      try {
        const payload = { name, email, role: 'superintendent', groupIds, active };
        const r = await fetch(API + '/admin/users', { method: 'POST', headers: { ...authHdr(), 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        const d = await r.json();
        if (!r.ok) { err.textContent = d.error || 'Could not create user. Please try again.'; err.classList.add('show'); return; }
        closeUserModal();
        if (d.cognitoCreated) {
          toast('User created. ' + name + ' will receive a welcome email from AWS to sign in via SSO.');
        } else if (d.cognitoError) {
          toast('User saved, but Cognito registration failed: ' + d.cognitoError, true);
        } else {
          toast('User created. Configure COGNITO_ACCESS_KEY_ID in .env to enable SSO enrollment.');
        }
        await loadUsersData();
      } catch (e) { err.textContent = 'Connection failed. Check your internet and try again.'; err.classList.add('show'); }
    } else {
      try {
        const payload = { name, active, groupIds };
        const r = await fetch(API + '/admin/users/' + editingId, { method: 'PUT', headers: { ...authHdr(), 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        const d = await r.json();
        if (!r.ok) { err.textContent = d.error || 'Could not save changes. Please try again.'; err.classList.add('show'); return; }
        closeUserModal();
        toast('User updated successfully.');
        await loadUsersData();
      } catch (e) { err.textContent = 'Connection failed. Check your internet and try again.'; err.classList.add('show'); }
    }
    if (btn) { btn.disabled = false; btn.textContent = 'Save User'; }
  }
  window.saveUser = saveUser;

  async function deleteUser(id, name) {
    const confirmed = await confirmDanger('Delete user <strong>' + name + '</strong>?<br><span style="font-size:.75rem;opacity:.7">This will remove their portal access. Their AWS Cognito account is not affected.</span>');
    if (!confirmed) return;
    try {
      const r = await fetch(API + '/admin/users/' + id, { method: 'DELETE', headers: authHdr() });
      if (!r.ok) { toast('Could not delete user. Please try again.', true); return; }
      toast('User deleted.');
      await loadUsersData();
    } catch { toast('Connection failed. Check your internet and try again.', true); }
  }
  window.deleteUser = deleteUser;

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
          <button id="_cdCancel" style="padding:8px 18px;border-radius:8px;border:1px solid rgba(255,255,255,.12);background:transparent;color:#7689AE;font-size:.8rem;cursor:pointer;font-family:inherit">Cancel</button>
          <button id="_cdConfirm" style="padding:8px 18px;border-radius:8px;border:none;background:#FF5C7A;color:#fff;font-size:.8rem;font-weight:700;cursor:pointer;font-family:inherit">${confirmLabel || 'Delete'}</button>
        </div>
      </div>`;
      document.body.appendChild(ov);
      ov.querySelector('#_cdConfirm').onclick = () => { ov.remove(); resolve(true); };
      ov.querySelector('#_cdCancel').onclick  = () => { ov.remove(); resolve(false); };
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

  if (TOKEN) loadUsersData();
})();
