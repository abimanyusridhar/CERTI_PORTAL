'use strict';
/**
 * Delegated click/input/change dispatcher for the admin hub's Users/Groups/Documents
 * tabs — replaces onclick="" / oninput="" / onchange="" attributes with data-action /
 * data-input-action / data-change-action attributes. Handlers stay exactly where they
 * were defined (users-tab.js / groups-tab.js / documents-tab.js each still export their
 * functions via window.X = X for this dispatcher to call) — only the wiring moved here.
 *
 * Load order doesn't matter for correctness: dispatch looks up window[name] lazily at
 * click time, by which point every tab script has already run (all are plain, synchronous
 * <script> tags loaded before the page can be interacted with).
 */
(function () {
  const ARG_BUILDERS = {
    switchAdminTab:     (el) => [el.dataset.tab],
    openUserEditModal:  (el) => [el.dataset.id],
    deleteUser:         (el) => [el.dataset.id, el.dataset.name],
    openGroupEditModal: (el) => [el.dataset.id],
    deleteGroup:        (el) => [el.dataset.id, el.dataset.name],
    removeImo:          (el) => [Number(el.dataset.idx)],
    addImoRaw:          (el) => [el.dataset.imo],
    qvRemoveVessel:     (el) => [el.dataset.imo],
    qvPickVessel:       (el) => [el.dataset.imo],
    openDocDirect:      (el) => [el.dataset.id, el],
    copyDocLink:        (el) => [el.dataset.id, el],
    deleteDoc:          (el) => [el.dataset.id, el.dataset.title],
    onFileSelect:       (el) => [el],
    qvSearch:           (el) => [el.value],
    onVesselSearch:     (el) => [el.value],
    openVesselRecModal: (el) => [el.dataset.imo],
  };

  // Defense in depth for the read-only "client" role — see role-client.css, which hides
  // every control that dispatches these. The server-side hasAdminRole() check in
  // server/index.js is the real boundary regardless of what happens here.
  const RESTRICTED_ACTIONS = new Set([
    'openAddUserModal', 'openUserEditModal', 'deleteUser',
    'openCreateGroupModal', 'openGroupEditModal', 'deleteGroup', 'addImoRaw', 'removeImo',
    'qvPickVessel', 'qvRemoveVessel', 'qvAddVessel',
    'uploadDoc', 'deleteDoc',
  ]);

  function dispatch(name, el) {
    if (!name) return;
    if (RESTRICTED_ACTIONS.has(name) && document.documentElement.classList.contains('role-client')) return;
    const fn = window[name];
    if (typeof fn !== 'function') return;
    const build = ARG_BUILDERS[name];
    fn(...(build ? build(el) : []));
  }

  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-action]');
    if (el) dispatch(el.dataset.action, el);
  });
  document.addEventListener('input', (e) => {
    const el = e.target.closest('[data-input-action]');
    if (el) dispatch(el.dataset.inputAction, el);
  });
  document.addEventListener('change', (e) => {
    const el = e.target.closest('[data-change-action]');
    if (el) dispatch(el.dataset.changeAction, el);
  });
})();
