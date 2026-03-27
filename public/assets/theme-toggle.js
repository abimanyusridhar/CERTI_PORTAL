'use strict';

(function () {
  var LS_KEY = 'smg-theme';

  // Resolve theme: localStorage -> OS preference -> default dark
  var saved = null;
  try { saved = localStorage.getItem(LS_KEY); } catch (e) {}
  var prefersDark = true;
  try { prefersDark = !window.matchMedia('(prefers-color-scheme: light)').matches; } catch (e) {}
  var isDark = saved !== null ? (saved !== 'light') : prefersDark;
  if (!isDark) document.documentElement.classList.add('light');
  else document.documentElement.classList.remove('light');

  function syncButtons() {
    var isLight = document.documentElement.classList.contains('light');
    var buttons = document.querySelectorAll('.theme-toggle');
    for (var i = 0; i < buttons.length; i++) {
      var iconEl = buttons[i].querySelector('.tt-icon');
      var labelEl = buttons[i].querySelector('.tt-label');
      if (iconEl) iconEl.textContent = isLight ? '🌙' : '☀️';
      if (labelEl) labelEl.textContent = isLight ? 'Dark' : 'Light';
    }
  }
  window.syncButtons = syncButtons;

  window.toggleTheme = function () {
    var isLight = document.documentElement.classList.toggle('light');
    try { localStorage.setItem(LS_KEY, isLight ? 'light' : 'dark'); } catch (e) {}
    syncButtons();
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', syncButtons);
  } else {
    syncButtons();
  }
})();
