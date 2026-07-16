'use strict';
/**
 * Shared delegated click/change/error dispatcher for the CST and VAPT certificate
 * dashboards (admin/dashboard.html + public/assets/smg-admin/cst/dashboard.js, and
 * admin/vapt-dashboard.html + public/assets/smg-admin/vapt/dashboard.js). Replaces
 * onclick="" / onchange="" attributes — including the ones inside dynamically
 * rendered cert-row template literals — with data-action / data-change-action
 * attributes. Handlers below just call the same-named global function the page's
 * own dashboard.js already defines (editCert, activateCert, quickSend, goIssue,
 * openLB, etc.) — nothing about those functions' own logic changes.
 *
 * Works for dynamically-rendered rows the same as static markup, unlike a
 * hash-based CSP (see admin/dashboard.html history — hash-based script-src broke
 * prod because dynamic onclick="" strings are different on every render and can't
 * be hashed).
 */
(function () {
  function call(name, ...args) {
    const fn = window[name];
    if (typeof fn === 'function') fn(...args);
  }

  const CLICK_HANDLERS = {
    // ── Cert-row actions (dynamic template-literal rows in dashboard.js) ──
    openCertDetail:      (el) => call('openCertDetail', el.dataset.id),
    editCert:            (el) => call('editCert', el.dataset.id),
    activateCert:        (el) => call('activateCert', el.dataset.id),
    quickSend:           (el) => call('quickSend', el.dataset.id),
    goIssue:             (el) => call('goIssue', el.dataset.id),
    openLB:              (el) => call('openLB', el.dataset.url || el.src),
    viewCertNewTab:      (el) => call('viewCertNewTab', el.dataset.id, el),
    viewCertNewTabRow:   (el) => call('viewCertNewTab', el.dataset.id, null),
    copyEncUrl:          (el) => call('copyEncUrl', el.dataset.id, el),
    openAssignGroup:     (el) => call('openAssignGroup', el.dataset.imo, el.dataset.name),
    askDelete:           (el) => call('askDelete', el.dataset.id),
    selectIssueCert:     (el) => call('selectIssueCert', el.dataset.id),
    removeSavedAttach:   (el) => call('removeSavedAttach', Number(el.dataset.idx)),
    removePendingAttach: (el) => call('removePendingAttach', Number(el.dataset.idx)),
    copyViewUrl:         (el) => call('copyViewUrl', el),
    dismissParent:       (el) => { if (el.parentElement) el.parentElement.style.display = 'none'; },
    openUrlNewTab:       (el) => window.open(el.dataset.url, '_blank'),
    closeViewEdit:       (el) => { call('closeView'); call('editCert', el.dataset.id); },
    closeViewIssue:      (el) => { call('closeView'); call('goIssue', el.dataset.id); },
    closeViewActivate:   (el) => { call('closeView'); call('activateCert', el.dataset.id); },

    // ── Static page chrome (admin/dashboard.html + admin/vapt-dashboard.html) ──
    // data-nav lets a toolbar button mark a DIFFERENT sidebar nav-item active
    // (matches the original showPage('issue', document.getElementById('nav-issue'))
    // pattern — the sidebar item gets highlighted, not the button that was clicked).
    showPage:                (el) => call('showPage', el.dataset.page, el.dataset.nav ? document.getElementById(el.dataset.nav) : el),
    openPublicPortal:        () => window.open(window.location.origin, '_blank'),
    openVaptPublicPortal:    () => window.open((window.APP_CONFIG ? window.APP_CONFIG.routes.vpt : '/VAPT'), '_blank'),
    selectQuarter:           (el) => call('selectQuarter', el.dataset.quarter),
    dismissSessionBanner:    () => { const b = document.getElementById('sessionWarningBanner'); if (b) b.style.display = 'none'; },
    scrollToPanel:           (el) => { const p = document.getElementById(el.dataset.panel); if (p) p.scrollIntoView({ behavior: 'smooth' }); },
    openWindow:              (el) => window.open(el.dataset.url, el.dataset.target || '_blank'),
    clearCsvFile:            (el, e) => call('clearCsvFile', e),
    clearImg:                (el, e) => call('clearImg', e),
    openElementPicker:       (el) => { const t = document.getElementById(el.dataset.target); if (t) t.click(); },
  };

  // Shared between 'input' and 'change' listeners — several fields in the same
  // filter row use oninput (the search box) while sibling <select>s use onchange,
  // but all of them just need the CURRENT combined state of every filter control.
  const VALUE_HANDLERS = {
    applyAllCertFilters: () => call('renderTbl', 'allTbl',
      (document.getElementById('allQ') || {}).value,
      (document.getElementById('allStatus') || {}).value,
      (document.getElementById('allQtr') || {}).value,
      (document.getElementById('allMode') || {}).value,
      (document.getElementById('allEmail') || {}).value),
    renderIssueListFromSearch: () => call('renderIssueList', (document.getElementById('issueSearch') || {}).value),
    renderValidityPageFromSearch: () => call('renderValidityPage', (document.getElementById('ivSearchQ') || {}).value),
    renderDashSearch: (el) => call('renderTbl', 'dashTbl', el.value),
    // ── Cert add/edit form composite handlers (originally two chained calls) ──
    livePreviewAndCheckDuplicate:    () => { call('livePreview'); call('checkDuplicate'); },
    livePreviewAndStatusChange:      () => { call('livePreview'); call('onStatusChange'); },
    livePreviewAndUpdateChecklist:   () => { call('livePreview'); call('updateCompletionChecklistFull'); },
    quarterChangeAndUpdateChecklist: () => { call('onQuarterChange'); call('updateCompletionChecklistFull'); },
    validateIssueDate:               (el) => call('validateIssueDate', el),

    // ── VAPT cert add/edit form (different filter set/order + function names) ──
    applyAllVaptFilters: () => call('renderTbl', 'allTbl',
      (document.getElementById('allQ') || {}).value,
      (document.getElementById('allStatusSel') || {}).value,
      (document.getElementById('allEmailSel') || {}).value,
      (document.getElementById('allRiskSel') || {}).value,
      (document.getElementById('allQuarterSel') || {}).value),
    autoGenIdAndPreview:      () => { call('autoGenId'); call('updatePreview'); },
    autoSetValidUntilAndPreview: () => { call('autoSetValidUntil'); call('updatePreview'); },
  };

  // Backdrop-close pattern: only fires when the click landed on the backdrop
  // element itself, not a descendant (mirrors the original
  // onclick="if(event.target===this)closeX()" inline handlers).
  const BACKDROP_HANDLERS = {
    closeViewBackdrop:        'closeView',
    closePdfModalBackdrop:    'closePdfModal',
    closePdfViewerBackdrop:   'closePdfViewer',
    closeAssignGroupBackdrop: 'closeAssignGroup',
  };

  const CHANGE_HANDLERS = {
    toggleRowSelect:    (el) => call('toggleRowSelect', el),
    toggleSelectAll:    (el) => call('toggleSelectAll', el, el.dataset.tbl),
    quickStatusChange:  (el) => call('quickStatusChange', el.dataset.id, el.value, el),
    // These three all originally received the input/select ELEMENT itself (this),
    // not its value — keep passing el, not el.value.
    handleCsvFile:      (el) => call('handleCsvFile', el),
    onFileSelect:       (el) => call('onFileSelect', el),
    pdfFileSelect:      (el) => call('pdfFileSelect', el),
    // VAPT's CSV input passes the File object itself, not the <input> element.
    loadCsvFile:        (el) => call('loadCsvFile', el.files[0]),
  };

  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-action]');
    if (!el) return;
    const action = el.dataset.action;
    if (Object.prototype.hasOwnProperty.call(BACKDROP_HANDLERS, action)) {
      if (e.target === el) call(BACKDROP_HANDLERS[action]);
      return;
    }
    const handler = CLICK_HANDLERS[action];
    if (handler) { handler(el, e); return; }
    // Generic fallback for simple, argument-less calls (refreshSession, resetIdle,
    // closeSidebar, toggleSidebar, doLogout, toggleTheme, startAdd, clearAllFilters,
    // openBulkAssign, bulkDeleteCerts, clearSelections, downloadSampleCsv,
    // doImportCsv, clearCsvFileSilent, saveCert, resetForm, copyMailBody,
    // sendViaSES, markAsSent, clearIssueSelection, exportValidityCSV, closeDel,
    // doDelete, closeLB, confirmAssignGroup, closeView, closePdfModal, etc.)
    call(action);
  });

  document.addEventListener('change', (e) => {
    const el = e.target.closest('[data-change-action]');
    if (!el) return;
    const action = el.dataset.changeAction;
    const handler = CHANGE_HANDLERS[action] || VALUE_HANDLERS[action];
    if (handler) { handler(el); return; }
    // Generic fallback for simple no-arg change handlers (e.g. loadQuarterlyStats()).
    call(action);
  });

  document.addEventListener('input', (e) => {
    const el = e.target.closest('[data-input-action]');
    if (!el) return;
    const action = el.dataset.inputAction;
    const handler = VALUE_HANDLERS[action];
    if (handler) { handler(el); return; }
    call(action, el.value);
  });

  // A few drag-zone handlers are bespoke inline logic (preventDefault + class
  // toggle), not a plain named-function call — override those specifically.
  const DRAG_HANDLERS = {
    csvDropOver:  (el, e) => { e.preventDefault(); el.classList.add('drag-over'); },
    csvDropLeave: (el) => el.classList.remove('drag-over'),
  };

  // Drag-and-drop zones (CSV/image upload) — pass the DragEvent through so the
  // target function can still call event.preventDefault()/dataTransfer as before.
  ['dragover', 'dragleave', 'drop'].forEach((evtName) => {
    const attr = 'data-' + evtName + '-action';
    document.addEventListener(evtName, (e) => {
      const el = e.target.closest('[' + attr + ']');
      if (!el) return;
      const name = el.getAttribute(attr);
      const handler = DRAG_HANDLERS[name];
      if (handler) { handler(el, e); return; }
      call(name, e);
    });
  });

  // 'error' events on <img> don't bubble, but they DO fire during the capture
  // phase on ancestors — so this must be registered with useCapture: true.
  document.addEventListener('error', (e) => {
    const el = e.target;
    if (el && el.dataset && el.dataset.onerrorAction === 'hideImgShowSibling') {
      el.style.display = 'none';
      if (el.nextElementSibling) el.nextElementSibling.style.display = 'inline-flex';
    }
  }, true);
})();
