'use strict';
/**
 * Shared delegated click/keydown dispatcher for the public CST/VAPT certificate
 * verification pages (public/index.html + smg-public/cst/index.js, and
 * public/vapt-index.html + smg-public/vapt/index.js). Replaces onclick="" /
 * onkeydown="" attributes with data-action / data-keydown-action, including
 * inside dynamically-rendered result/attachment template strings.
 */
(function () {
  function call(name, ...args) {
    const fn = window[name];
    if (typeof fn === 'function') fn(...args);
  }

  const CLICK_HANDLERS = {
    openLB:              (el) => call('openLB', el.dataset.url || el.src),
    // CST's downloadCertificate(id) ignores extra args; VAPT's downloadCertificate(id, el)
    // uses the second one — one entry serves both.
    downloadCertificate: (el) => call('downloadCertificate', el.dataset.id, el),
    copyVerifyLink:      (el) => call('copyVerifyLink', el),
    copyCertId:          (el) => call('copyCertId', el.dataset.id, el),
    requestPdfAccess:    (el) => call('requestPdfAccess', el.dataset.url, el.dataset.name),
  };

  // Backdrop-close pattern: only fires when the click landed on the backdrop
  // element itself, not a descendant (mirrors onclick="if(event.target===this)closeX()").
  const BACKDROP_HANDLERS = {
    closeLBBackdrop:       'closeLB',
    closePdfModalBackdrop: 'closePdfModal',
  };

  // VAPT's lightbox also closes when the close-icon span itself is the click
  // target (that span has no onclick of its own there — mirrors the original
  // onclick="if(event.target===this||event.target.classList.contains('lb-x'))closeLB()").
  const CONDITIONAL_BACKDROP_HANDLERS = {
    closeLBBackdropOrIcon: (el, e) => (e.target === el || e.target.classList.contains('lb-x')) && call('closeLB'),
  };

  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-action]');
    if (!el) return;
    const action = el.dataset.action;
    if (Object.prototype.hasOwnProperty.call(BACKDROP_HANDLERS, action)) {
      if (e.target === el) call(BACKDROP_HANDLERS[action]);
      return;
    }
    if (Object.prototype.hasOwnProperty.call(CONDITIONAL_BACKDROP_HANDLERS, action)) {
      CONDITIONAL_BACKDROP_HANDLERS[action](el, e);
      return;
    }
    const handler = CLICK_HANDLERS[action];
    if (handler) { handler(el); return; }
    call(action); // generic fallback for bare no-arg calls (verify(), etc.)
  });

  // Mirrors the original onkeydown="if(event.key==='Enter'||event.key===' ')fn()"
  // pattern used on div[role=button] elements (both keys activate a real button).
  document.addEventListener('keydown', (e) => {
    const el = e.target.closest('[data-keydown-action]');
    if (!el) return;
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const action = el.dataset.keydownAction;
    const handler = CLICK_HANDLERS[action];
    if (handler) { handler(el); return; }
    call(action);
  });

  // Mirrors onkeydown="if(event.key==='Enter')fn()" on plain text inputs — Enter
  // only, since Space must keep typing a literal space character in the field.
  document.addEventListener('keydown', (e) => {
    const el = e.target.closest('[data-keydown-enter-action]');
    if (!el) return;
    if (e.key !== 'Enter') return;
    call(el.dataset.keydownEnterAction);
  });
})();
