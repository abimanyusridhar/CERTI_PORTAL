'use strict';

(function () {
  // Light theme only — locked across all modules
  document.documentElement.classList.add('light');
  try { localStorage.setItem('smg-theme', 'light'); } catch (e) {}

  function syncButtons() {
    var buttons = document.querySelectorAll('.theme-toggle');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].style.display = 'none';
    }
  }
  window.syncButtons = syncButtons;

  // No-op — dark mode disabled
  window.toggleTheme = function () {};

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', syncButtons);
  } else {
    syncButtons();
  }
})();
