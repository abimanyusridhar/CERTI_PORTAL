/**
 * ═══════════════════════════════════════════════════════════════════════
 * SHARED UTILITIES — Common functions across all pages
 * 
 * This file provides:
 * - DOM manipulation helpers
 * - Toast notifications
 * - Theme management
 * - Async utilities
 * - Form validation
 * - Formatting utilities
 * - Analytics/tracking
 * 
 * To use: <script src="/assets/shared-utils.js" defer></script>
 * ═══════════════════════════════════════════════════════════════════════
 */

/**
 * ─ DOM HELPERS ──────────────────────────────────────────────────────────
 */

/**
 * Safe DOM selector with null check
 * @param {string} selector CSS selector
 * @returns {HTMLElement|null}
 */
function el(selector) {
  return document.querySelector(selector);
}

/**
 * Safe DOM selector all with null protection
 * @param {string} selector CSS selector
 * @returns {NodeList}
 */
function elAll(selector) {
  return document.querySelectorAll(selector) || [];
}

/**
 * Toggle element display
 * @param {HTMLElement|string} element Element or selector
 * @param {boolean} show Force show/hide (optional)
 */
function toggle(element, show) {
  const elem = typeof element === 'string' ? el(element) : element;
  if (!elem) return;
  if (typeof show === 'boolean') {
    elem.style.display = show ? '' : 'none';
  } else {
    elem.style.display = elem.style.display === 'none' ? '' : 'none';
  }
}

/**
 * Show element
 * @param {HTMLElement|string} element
 */
function show(element) {
  toggle(element, true);
}

/**
 * Hide element
 * @param {HTMLElement|string} element
 */
function hide(element) {
  toggle(element, false);
}

/**
 * Add class with performance check
 * @param {HTMLElement|string} element
 * @param {string} className Single class name
 */
function addClass(element, className) {
  const elem = typeof element === 'string' ? el(element) : element;
  if (elem && !elem.classList.contains(className)) {
    elem.classList.add(className);
  }
}

/**
 * Remove class with performance check
 * @param {HTMLElement|string} element
 * @param {string} className Single class name
 */
function removeClass(element, className) {
  const elem = typeof element === 'string' ? el(element) : element;
  if (elem && elem.classList.contains(className)) {
    elem.classList.remove(className);
  }
}

/**
 * Toggle class
 * @param {HTMLElement|string} element
 * @param {string} className
 * @param {boolean} force Optional force toggle
 */
function toggleClass(element, className, force) {
  const elem = typeof element === 'string' ? el(element) : element;
  if (elem) elem.classList.toggle(className, force);
}

/**
 * Set multiple attributes
 * @param {HTMLElement} element
 * @param {Object} attrs Key-value pairs
 */
function setAttrs(element, attrs) {
  if (!element) return;
  Object.entries(attrs).forEach(([key, val]) => {
    if (val === null || val === undefined) {
      element.removeAttribute(key);
    } else {
      element.setAttribute(key, val);
    }
  });
}

/**
 * ─ NOTIFICATIONS ────────────────────────────────────────────────────────
 */

/**
 * Simple toast notification
 * @param {string} message
 * @param {string} type 'success'|'error'|'info'|'warning'
 * @param {number} duration ms (default 3000)
 */
function toast(message, type = 'info', duration = 3000) {
  const container = el('#toast') || document.body;
  
  const toast = document.createElement('div');
  toast.className = `toast toast-${type} fade-in`;
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 12px 20px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--text);
    font-size: 0.9rem;
    max-width: 320px;
    z-index: 9999;
    animation: fadeUp 0.3s ease;
  `;
  
  if (type === 'success') {
    toast.style.borderColor = 'rgba(100, 255, 218, 0.3)';
    toast.style.background = 'rgba(100, 255, 218, 0.08)';
    toast.style.color = '#64FFDA';
  } else if (type === 'error') {
    toast.style.borderColor = 'rgba(255, 107, 138, 0.3)';
    toast.style.background = 'rgba(255, 107, 138, 0.08)';
    toast.style.color = '#FF6B8A';
  } else if (type === 'warning') {
    toast.style.borderColor = 'rgba(255, 179, 71, 0.3)';
    toast.style.background = 'rgba(255, 179, 71, 0.08)';
    toast.style.color = '#FFB347';
  }
  
  toast.textContent = message;
  container.appendChild(toast);
  
  if (duration > 0) {
    setTimeout(() => {
      toast.style.animation = 'fadeUp 0.3s ease reverse';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }
  
  return toast;
}

/**
 * ─ THEME MANAGEMENT ────────────────────────────────────────────────────
 */

const THEME_KEY = 'app-theme';

/**
 * Get current theme
 * @returns {string} 'dark' | 'light'
 */
function getTheme() {
  return localStorage.getItem(THEME_KEY) || 'dark';
}

/**
 * Set theme and apply to document
 * @param {string} theme 'dark' | 'light'
 */
function setTheme(theme) {
  localStorage.setItem(THEME_KEY, theme);
  const html = document.documentElement;
  html.className = theme === 'light' ? 'light' : '';
  document.dispatchEvent(new CustomEvent('themechange', { detail: { theme } }));
}

/**
 * Toggle between themes
 */
function toggleTheme() {
  setTheme(getTheme() === 'dark' ? 'light' : 'dark');
}

/**
 * Initialize theme on page load
 */
function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved) {
    setTheme(saved);
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    setTheme('light');
  }
}

/**
 * ─ ASYNC HELPERS ────────────────────────────────────────────────────────
 */

/**
 * Fetch with timeout and error handling
 * @param {string} url
 * @param {Object} options Fetch options
 * @param {number} timeout Default 15000ms
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, options = {}, timeout = 15000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    throw error;
  }
}

/**
 * Retry async function with exponential backoff
 * @param {Function} fn Async function to retry
 * @param {number} maxAttempts Default 3
 * @param {number} delay Default 1000ms
 * @returns {Promise}
 */
async function retry(fn, maxAttempts = 3, delay = 1000) {
  let attempt = 0;
  while (attempt < maxAttempts) {
    try {
      return await fn();
    } catch (error) {
      attempt++;
      if (attempt >= maxAttempts) throw error;
      await new Promise(r => setTimeout(r, delay * Math.pow(2, attempt - 1)));
    }
  }
}

/**
 * Debounce function (wait after last call)
 * @param {Function} func
 * @param {number} wait ms
 * @returns {Function}
 */
function debounce(func, wait = 300) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Throttle function (limit calls frequency)
 * @param {Function} func
 * @param {number} limit ms
 * @returns {Function}
 */
function throttle(func, limit = 300) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

/**
 * ─ FORM VALIDATION ──────────────────────────────────────────────────────
 */

/**
 * Validate email format
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Sanitize input to prevent HTML injection
 * @param {string} input
 * @returns {string} Sanitized string
 */
function sanitize(input) {
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
}

/**
 * Get form data as object
 * @param {HTMLFormElement} form
 * @returns {Object}
 */
function getFormData(form) {
  const formData = new FormData(form);
  const data = {};
  for (const [key, value] of formData) {
    if (data[key]) {
      if (Array.isArray(data[key])) {
        data[key].push(value);
      } else {
        data[key] = [data[key], value];
      }
    } else {
      data[key] = value;
    }
  }
  return data;
}

/**
 * ─ FORMATTING UTILITIES ────────────────────────────────────────────────
 */

/**
 * Format date to readable string
 * @param {Date|string|number} date
 * @param {Object} options Intl.DateTimeFormat options
 * @returns {string}
 */
function formatDate(date, options = {}) {
  const d = new Date(date);
  return d.toLocaleDateString('en-GB', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    ...options,
  });
}

/**
 * Format time
 * @param {Date|string|number} date
 * @returns {string} HH:MM:SS
 */
function formatTime(date) {
  const d = new Date(date);
  return d.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Format duration in seconds to readable format
 * @param {number} seconds
 * @returns {string}
 */
function formatDuration(seconds) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

/**
 * Format bytes to human readable
 * @param {number} bytes
 * @param {number} decimals
 * @returns {string}
 */
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Format number with thousand separators
 * @param {number} num
 * @returns {string}
 */
function formatNumber(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * ─ ANALYTICS & TRACKING ────────────────────────────────────────────────
 */

/**
 * Track user action (fires analytics event)
 * @param {string} action
 * @param {Object} data
 */
function trackEvent(action, data = {}) {
  // Send to server if analytics endpoint available
  if (navigator.sendBeacon) {
    navigator.sendBeacon('/api/track', JSON.stringify({
      action,
      timestamp: Date.now(),
      ...data,
    }));
  }
  // Fallback to fetch
  else {
    try {
      fetchWithTimeout('/api/track', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, timestamp: Date.now(), ...data }),
      }, 5000).catch(() => {});
    } catch (e) {
      // Silently fail - non-critical
    }
  }
}

/**
 * ─ INITIALIZATION ──────────────────────────────────────────────────────
 */

// Initialize theme on script load if not already done
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initTheme);
} else {
  initTheme();
}

// Export for module systems (if used)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    el, elAll, toggle, show, hide, addClass, removeClass, toggleClass, setAttrs,
    toast, getTheme, setTheme, toggleTheme, initTheme,
    fetchWithTimeout, retry, debounce, throttle,
    isValidEmail, sanitize, getFormData,
    formatDate, formatTime, formatDuration, formatBytes, formatNumber,
    trackEvent,
  };
}
