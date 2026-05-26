/**
 * ═══════════════════════════════════════════════════════════════════════
 * DASHBOARD OPTIMIZATIONS — Performance & UX enhancements
 * 
 * This module provides:
 * - Lazy rendering for large lists
 * - Request deduplication/caching
 * - Efficient modal handling
 * - Optimized re-renders
 * - Memory management
 * 
 * Include in admin dashboards after shared-utils.js
 * ═══════════════════════════════════════════════════════════════════════
 */

/**
 * Request cache with TTL (time-to-live)
 */
class RequestCache {
  constructor(ttlMs = 5000) {
    this.cache = new Map();
    this.ttl = ttlMs;
  }

  set(key, value) {
    this.cache.set(key, {
      value,
      expires: Date.now() + this.ttl,
    });
  }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (entry.expires < Date.now()) {
      this.cache.delete(key);
      return null;
    }
    return entry.value;
  }

  clear() {
    this.cache.clear();
  }

  has(key) {
    return this.get(key) !== null;
  }
}

/**
 * Lazy list renderer for large tables
 * Only renders visible items + buffer
 */
class LazyListRenderer {
  constructor(containerSelector, itemHeight = 50, bufferSize = 5) {
    this.container = el(containerSelector);
    this.itemHeight = itemHeight;
    this.bufferSize = bufferSize;
    this.items = [];
    this.visibleRange = { start: 0, end: 0 };
    this.handleScroll = throttle(() => this._updateVisibleRange(), 100);
  }

  setItems(items) {
    this.items = items;
    this._updateVisibleRange();
  }

  _updateVisibleRange() {
    if (!this.container || !this.container.parentElement) return;

    const scrollTop = this.container.parentElement.scrollTop || 0;
    const containerHeight = this.container.parentElement.clientHeight || 600;

    const start = Math.max(
      0,
      Math.floor(scrollTop / this.itemHeight) - this.bufferSize
    );
    const end = Math.min(
      this.items.length,
      Math.ceil((scrollTop + containerHeight) / this.itemHeight) + this.bufferSize
    );

    if (start !== this.visibleRange.start || end !== this.visibleRange.end) {
      this.visibleRange = { start, end };
      this.render();
    }
  }

  render() {
    if (!this.container) return;

    const fragment = document.createDocumentFragment();
    const startIndex = this.visibleRange.start;
    const endIndex = this.visibleRange.end;

    // Add spacer for items before visible range
    if (startIndex > 0) {
      const spacer = document.createElement('div');
      spacer.style.height = startIndex * this.itemHeight + 'px';
      fragment.appendChild(spacer);
    }

    // Add visible items
    for (let i = startIndex; i < endIndex; i++) {
      const item = this.items[i];
      if (item) {
        fragment.appendChild(this.createItemElement(item, i));
      }
    }

    // Add spacer for items after visible range
    if (endIndex < this.items.length) {
      const spacer = document.createElement('div');
      spacer.style.height = (this.items.length - endIndex) * this.itemHeight + 'px';
      fragment.appendChild(spacer);
    }

    this.container.innerHTML = '';
    this.container.appendChild(fragment);
  }

  createItemElement(item, index) {
    const div = document.createElement('div');
    div.className = 'lazy-item';
    div.style.height = this.itemHeight + 'px';
    div.textContent = this.formatItem ? this.formatItem(item) : JSON.stringify(item);
    return div;
  }

  attachScrollListener(scrollContainer) {
    if (scrollContainer) {
      scrollContainer.addEventListener('scroll', this.handleScroll);
    }
  }

  detachScrollListener(scrollContainer) {
    if (scrollContainer) {
      scrollContainer.removeEventListener('scroll', this.handleScroll);
    }
  }
}

/**
 * Modal state manager — prevents clobbering during edits
 */
class ModalStateManager {
  constructor() {
    this.openModals = new Set();
    this.modalStates = new Map();
  }

  isAnyOpen() {
    return this.openModals.size > 0;
  }

  open(modalId) {
    this.openModals.add(modalId);
    this._updateDisplay(modalId, true);
  }

  close(modalId) {
    this.openModals.delete(modalId);
    this._updateDisplay(modalId, false);
  }

  saveState(modalId, state) {
    this.modalStates.set(modalId, state);
  }

  getState(modalId) {
    return this.modalStates.get(modalId);
  }

  _updateDisplay(modalId, isOpen) {
    const modal = el('#' + modalId);
    if (modal) {
      modal.style.display = isOpen ? '' : 'none';
    }
  }

  closeAll() {
    Array.from(this.openModals).forEach(id => this.close(id));
  }
}

/**
 * Debounced table renderer
 * Prevents excessive re-renders when data changes frequently
 */
class TableRenderer {
  constructor(tableSelector, debounceMs = 300) {
    this.table = el(tableSelector);
    this.debounceMs = debounceMs;
    this.pendingRender = null;
    this.lastRenderTime = 0;
    this.dataHash = null;
  }

  setData(data) {
    if (this._hashData(data) === this.dataHash) {
      return; // No changes
    }

    clearTimeout(this.pendingRender);
    this.pendingRender = setTimeout(() => {
      this._render(data);
    }, this.debounceMs);
  }

  _render(data) {
    if (!this.table) return;

    this.dataHash = this._hashData(data);
    this.lastRenderTime = Date.now();

    // Render logic here
    // This should be overridden by subclass or provided via callback
  }

  _hashData(data) {
    // Simple hash for detecting changes
    return JSON.stringify(data).substring(0, 20);
  }

  forceRender() {
    clearTimeout(this.pendingRender);
    this._render();
  }
}

/**
 * Performance metrics collector
 */
class PerformanceMonitor {
  constructor() {
    this.metrics = {};
    this.marks = {};
  }

  mark(name) {
    this.marks[name] = performance.now();
  }

  measure(name, startMark) {
    if (!this.marks[startMark]) return;
    const duration = performance.now() - this.marks[startMark];
    this.metrics[name] = duration;
    return duration;
  }

  log(name) {
    return this.metrics[name];
  }

  logAll() {
    return { ...this.metrics };
  }

  getMetric(name) {
    return this.metrics[name];
  }

  clear() {
    this.metrics = {};
    this.marks = {};
  }
}

/**
 * Intelligent data sync — only update changed fields
 */
class SmartDiffSync {
  constructor() {
    this.lastData = null;
  }

  /**
   * Compare new data with last data and return only changed fields
   * @param {Object} newData
   * @returns {Object} Changed fields only
   */
  getChanges(newData) {
    if (!this.lastData) {
      this.lastData = JSON.parse(JSON.stringify(newData));
      return newData;
    }

    const changes = {};
    Object.keys(newData).forEach(key => {
      if (JSON.stringify(newData[key]) !== JSON.stringify(this.lastData[key])) {
        changes[key] = newData[key];
      }
    });

    this.lastData = JSON.parse(JSON.stringify(newData));
    return changes;
  }

  reset() {
    this.lastData = null;
  }
}

/**
 * Network status detector
 */
class NetworkMonitor {
  constructor() {
    this.isOnline = navigator.onLine;
    this.listeners = [];
    this._attach();
  }

  _attach() {
    window.addEventListener('online', () => this._updateStatus(true));
    window.addEventListener('offline', () => this._updateStatus(false));
  }

  _updateStatus(isOnline) {
    if (this.isOnline === isOnline) return;
    this.isOnline = isOnline;
    this.listeners.forEach(listener => listener(isOnline));
  }

  onStatusChange(callback) {
    this.listeners.push(callback);
  }

  getStatus() {
    return this.isOnline ? 'online' : 'offline';
  }
}

/**
 * Batch operations processor
 * Groups rapid operations to reduce API calls
 */
class BatchProcessor {
  constructor(flushIntervalMs = 1000, maxBatchSize = 50) {
    this.queue = [];
    this.flushInterval = flushIntervalMs;
    this.maxBatchSize = maxBatchSize;
    this.processingId = null;
    this.processFunction = null;
  }

  enqueue(item) {
    this.queue.push(item);

    if (this.queue.length >= this.maxBatchSize) {
      this.flush();
    } else {
      this._scheduleFlush();
    }
  }

  setProcessor(fn) {
    this.processFunction = fn;
  }

  _scheduleFlush() {
    if (this.processingId) return;
    this.processingId = setTimeout(() => this.flush(), this.flushInterval);
  }

  async flush() {
    if (this.processingId) {
      clearTimeout(this.processingId);
      this.processingId = null;
    }

    if (this.queue.length === 0 || !this.processFunction) return;

    const batch = this.queue.splice(0, this.maxBatchSize);
    try {
      await this.processFunction(batch);
    } catch (error) {
      console.error('Batch processing failed:', error);
      // Re-queue failed items
      this.queue.unshift(...batch);
    }
  }

  clear() {
    this.queue = [];
    if (this.processingId) {
      clearTimeout(this.processingId);
      this.processingId = null;
    }
  }
}

/**
 * Memory-efficient event emitter
 */
class EventBus {
  constructor() {
    this.events = new Map();
  }

  on(event, handler) {
    if (!this.events.has(event)) {
      this.events.set(event, new Set());
    }
    this.events.get(event).add(handler);

    // Return unsubscribe function
    return () => this.off(event, handler);
  }

  off(event, handler) {
    if (this.events.has(event)) {
      this.events.get(event).delete(handler);
    }
  }

  emit(event, data) {
    if (this.events.has(event)) {
      this.events.get(event).forEach(handler => {
        try {
          handler(data);
        } catch (error) {
          console.error(`Error in ${event} handler:`, error);
        }
      });
    }
  }

  clear() {
    this.events.clear();
  }
}

/**
 * Global optimization utilities
 */
const DashboardOptimizations = {
  RequestCache,
  LazyListRenderer,
  ModalStateManager,
  TableRenderer,
  PerformanceMonitor,
  SmartDiffSync,
  NetworkMonitor,
  BatchProcessor,
  EventBus,
};

// Create global instances for convenience
if (typeof window !== 'undefined') {
  window.dashboardRequestCache = new RequestCache(5000);
  window.dashboardModals = new ModalStateManager();
  window.dashboardPerf = new PerformanceMonitor();
  window.dashboardSync = new SmartDiffSync();
  window.dashboardNetwork = new NetworkMonitor();
  window.dashboardEvents = new EventBus();
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DashboardOptimizations;
}
