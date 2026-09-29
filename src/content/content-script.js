/**
 * Content Script (DOM Observer & Shadow DOM Isolator)
 * Incremental TreeWalker DOM scanner, behavioral event tracker, and anti-tamper Shadow DOM overlay manager.
 * @module content-script
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__PHISHING_DETECTOR_INJECTED__) return;
  window.__PHISHING_DETECTOR_INJECTED__ = true;

  const behavioralFlags = {
    clipboardAccess: false,
    rightClickDisabled: false,
    autoSubmitForm: false,
    popupCount: 0,
    requestedSensitiveAPIs: []
  };

  // Listen for context menu restrictions
  document.addEventListener('contextmenu', () => {
    behavioralFlags.rightClickDisabled = true;
  }, true);

  // Listen for clipboard events
  document.addEventListener('copy', () => {
    behavioralFlags.clipboardAccess = true;
  }, true);

  /**
   * Fast, targeted extraction of DOM context. Avoids global node traversal.
   * @returns {Record<string, *>}
   */
  function extractDOMContext() {
    const forms = Array.from(document.forms || []).map(form => ({
      action: form.action || '',
      method: form.method || 'get',
      inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(input => ({
        type: input.type || 'text',
        name: input.name || '',
        id: input.id || '',
        placeholder: input.placeholder || '',
        isHidden: input.type === 'hidden' || input.style.display === 'none' || input.style.visibility === 'hidden',
        isOffScreen: (input.offsetWidth === 0 && input.offsetHeight === 0)
      }))
    }));

    const iframes = Array.from(document.querySelectorAll('iframe')).map(iframe => ({
      src: iframe.src || iframe.getAttribute('src') || '',
      isHidden: iframe.style.display === 'none' || iframe.style.visibility === 'hidden'
    }));

    const anchors = Array.from(document.querySelectorAll('a[href]')).slice(0, 50).map(anchor => ({
      text: (anchor.textContent || '').trim().substring(0, 100),
      href: anchor.href || ''
    }));

    // Avoid expensive querySelectorAll('div, section') for overlays
    // Check direct children of body only for overlay heuristics
    const overlays = Array.from(document.body ? document.body.children : []).filter(node => {
      if (node.id === 'phishing-detector-root') return false; // Ignore extension's own warning overlay
      if (node.tagName !== 'DIV' && node.tagName !== 'SECTION') return false;
      const style = window.getComputedStyle(node);
      return (style.position === 'fixed' || style.position === 'absolute') &&
             (parseInt(style.zIndex, 10) > 9999);
    }).map(() => ({ isOverlay: true }));

    const scripts = Array.from(document.scripts || []).map(script => ({
      src: script.src || script.getAttribute('src') || ''
    }));

    return {
      url: location.href,
      title: document.title,
      forms,
      domData: {
        iframes,
        scripts,
        overlays,
        anchors
      },
      behavior: { ...behavioralFlags }
    };
  }

  /**
   * Request page analysis from background service worker.
   */
  function triggerPageAnalysis() {
    const context = extractDOMContext();
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({ action: 'ANALYZE_PAGE', context }, (response) => {
        if (chrome.runtime.lastError) {
          return; // Ignore disconnect error silently
        }
        if (response && response.success && response.result) {
          const result = response.result;
          if (result.riskScore >= 60) {
            renderShadowDOMWarningOverlay(result);
          }
        }
      });
    }
  }

  // Listen for rescan trigger messages from popup or background
  if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'TRIGGER_DOM_SCAN') {
        triggerPageAnalysis();
        sendResponse({ success: true });
        return true;
      }
    });
  }

  /**
   * Render isolated Shadow DOM warning overlay on top of dangerous page.
   * @param {Record<string, *>} result 
   */
  function renderShadowDOMWarningOverlay(result) {
    if (document.getElementById('phishing-detector-root')) return;

    const host = document.createElement('div');
    host.id = 'phishing-detector-root';
    host.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:2147483647;pointer-events:all;';

    const shadow = host.attachShadow({ mode: 'closed' });

    shadow.innerHTML = `
      <style>
        .overlay-container {
          width: 100%;
          height: 100%;
          background: rgba(15, 23, 42, 0.95);
          backdrop-filter: blur(12px);
          display: flex;
          align-items: center;
          justify-content: center;
          color: #f8fafc;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          box-sizing: border-box;
          padding: 2rem;
        }
        .card {
          background: #1e293b;
          border: 1px solid #334155;
          border-radius: 16px;
          max-width: 600px;
          width: 100%;
          padding: 2rem;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
          text-align: center;
        }
        .icon { font-size: 3.5rem; margin-bottom: 1rem; }
        .title { font-size: 1.75rem; font-weight: 700; color: #ef4444; margin-bottom: 0.5rem; }
        .score { font-size: 1.1rem; color: #94a3b8; margin-bottom: 1.5rem; }
        .reasons { text-align: left; background: #0f172a; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; font-size: 0.9rem; max-height: 150px; overflow-y: auto; }
        .reason-item { color: #f8fafc; margin-bottom: 0.5rem; }
        .btn-group { display: flex; gap: 1rem; justify-content: center; }
        .btn-back { background: #3b82f6; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer; }
        .btn-proceed { background: transparent; color: #94a3b8; border: 1px solid #475569; padding: 0.75rem 1.5rem; border-radius: 8px; cursor: pointer; }
      </style>
      <div class="overlay-container">
        <div class="card">
          <div class="icon">🛡️</div>
          <div class="title">Security Warning: High Risk Site</div>
          <div class="score">Threat Risk Score: <strong>${result.riskScore}/100</strong> (${result.classification})</div>
          <div class="reasons">
            ${(result.reasons || []).map(r => `<div class="reason-item">• ${r}</div>`).join('')}
          </div>
          <div class="btn-group">
            <button class="btn-back" id="btn-back">Go Back to Safety</button>
            <button class="btn-proceed" id="btn-proceed">Proceed (Unsafe)</button>
          </div>
        </div>
      </div>
    `;

    const target = document.body || document.documentElement;
    if (target) {
      target.appendChild(host);
    }

    shadow.getElementById('btn-back').addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    });

    shadow.getElementById('btn-proceed').addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ action: 'ALLOW_SESSION_DOMAIN', domain: location.hostname }, () => {
          host.remove();
        });
      } else {
        host.remove();
      }
    });
  }

  // Debounce mechanism
  let scanTimeout = null;
  function triggerPageAnalysisDebounced() {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(triggerPageAnalysis, 1000);
  }

  // Initial Scan at document_end
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', triggerPageAnalysis);
  } else {
    triggerPageAnalysis();
  }

  // Setup targeted MutationObserver
  const processedNodes = new WeakSet();
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE && !processedNodes.has(node)) {
            processedNodes.add(node);
            const tag = node.tagName.toUpperCase();
            if (tag === 'FORM' || tag === 'IFRAME' || tag === 'A') {
              shouldScan = true;
            } else if (node.querySelector && node.querySelector('form, iframe, a')) {
              shouldScan = true;
            }
          }
        }
      }
      if (shouldScan) break;
    }
    
    if (shouldScan) {
      triggerPageAnalysisDebounced();
    }
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      observer.observe(document.body, { childList: true, subtree: true });
    });
  }
})();
