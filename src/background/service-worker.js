/**
 * Background Service Worker (Manifest V3)
 * Orchestrates extension lifecycle, pre-navigation blocking, dynamic extension badges, and messaging bus.
 * @module service-worker
 */

import { PluginRegistry } from '../plugins/PluginRegistry.js';
import { DetectionScheduler } from '../core/engine/DetectionScheduler.js';
import { RiskFusionEngine } from '../core/fusion/RiskFusionEngine.js';
import { ExplainableAIEngine } from '../core/explainable/ExplainableAIEngine.js';
import { EnterprisePolicyEngine } from '../core/policy/EnterprisePolicyEngine.js';
import { ChromeStorageAdapter } from '../storage/ChromeStorageAdapter.js';

import { URLDetector } from '../detectors/url/URLDetector.js';
import { FormDetector } from '../detectors/form/FormDetector.js';
import { DOMDetector } from '../detectors/dom/DOMDetector.js';
import { BehaviorDetector } from '../detectors/behavior/BehaviorDetector.js';
import { CertificateAnalyzer } from '../detectors/certificate/CertificateAnalyzer.js';
import { DomainIntelligence } from '../detectors/dns/DomainIntelligence.js';
import { BrandImpersonationDetector } from '../detectors/brand/BrandImpersonationDetector.js';
import { NetworkAnalyzer } from '../detectors/network/NetworkAnalyzer.js';
import { ReputationEngine } from '../detectors/reputation/ReputationEngine.js';

// Instantiate Core Services
const registry = new PluginRegistry();
const policyEngine = new EnterprisePolicyEngine();
const fusionEngine = new RiskFusionEngine();
const explainableEngine = new ExplainableAIEngine();
const storage = new ChromeStorageAdapter();

// Register All Detectors
registry.register(new URLDetector());
registry.register(new FormDetector());
registry.register(new DOMDetector());
registry.register(new BehaviorDetector());
registry.register(new CertificateAnalyzer());
registry.register(new DomainIntelligence());
registry.register(new BrandImpersonationDetector());
registry.register(new NetworkAnalyzer());
registry.register(new ReputationEngine());

const engine = new DetectionScheduler(registry, policyEngine, fusionEngine, explainableEngine);

/** Store per-tab current security status */
const tabSecurityState = new Map();

// Initialize stats if empty
(async () => {
  const existing = await storage.get(['phishing_detector_stats']);
  if (!existing.phishing_detector_stats) {
    await storage.set({
      phishing_detector_stats: {
        sitesScanned: 0,
        threatsBlocked: 0,
        lastReset: new Date().toISOString()
      }
    });
  }
})();

// 1. Pre-Navigation Blocking Listener
if (typeof chrome !== 'undefined' && chrome.webNavigation?.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; // Main frame only
    const url = details.url;

    if (!url || !url.startsWith('http')) return;

    const analysis = await engine.analyze({ url });

    if (analysis.riskScore >= 80) {
      const warningUrl = chrome.runtime.getURL(`src/ui/warning/warning.html?url=${encodeURIComponent(url)}&score=${analysis.riskScore}&reason=${encodeURIComponent(analysis.reasons[0] || 'Critical threat')}`);
      chrome.tabs.update(details.tabId, { url: warningUrl });
      await incrementStats(0, 1);
    }
  });
}

// 2. Messaging Listener (Communication between Content Scripts, Popup, Dashboard)
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'ANALYZE_PAGE') {
      const tabId = sender.tab ? sender.tab.id : request.tabId;

      engine.analyze(request.context).then(async (result) => {
        if (tabId) {
          tabSecurityState.set(tabId, result);
          updateBadge(tabId, result.riskScore);
        }
        await incrementStats(1, result.riskScore >= 60 ? 1 : 0);
        sendResponse({ success: true, result });
      }).catch(err => {
        sendResponse({ success: false, error: err.message });
      });

      return true; // Keep message channel open for async promise
    }

    if (request.action === 'GET_TAB_SECURITY_STATUS') {
      const result = tabSecurityState.get(request.tabId) || null;
      sendResponse({ success: true, result });
      return false;
    }

    if (request.action === 'ALLOW_SESSION_DOMAIN') {
      policyEngine.allowSessionDomain(request.domain);
      sendResponse({ success: true });
      return false;
    }
  });
}

/**
 * Update Extension Badge Colors based on Risk Score.
 * @param {number} tabId 
 * @param {number} score 
 */
function updateBadge(tabId, score) {
  if (typeof chrome === 'undefined' || !chrome.action) return;

  let color = '#22c55e'; // Safe green
  let text = '';

  if (score >= 80) {
    color = '#dc2626'; // Red Critical
    text = '!!!';
  } else if (score >= 60) {
    color = '#ea580c'; // Orange High
    text = '!!';
  } else if (score >= 40) {
    color = '#f59e0b'; // Yellow Medium
    text = '!';
  }

  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text });
}

let cachedStats = null;

/**
 * Increment scanning stats in storage.
 * @param {number} scannedDelta 
 * @param {number} blockedDelta 
 */
async function incrementStats(scannedDelta, blockedDelta) {
  try {
    if (!cachedStats) {
      const data = await storage.get(['phishing_detector_stats']);
      cachedStats = data.phishing_detector_stats || { sitesScanned: 0, threatsBlocked: 0, lastReset: new Date().toISOString() };
    }
    cachedStats.sitesScanned += scannedDelta;
    cachedStats.threatsBlocked += blockedDelta;
    await storage.debouncedSet({ phishing_detector_stats: { ...cachedStats } }, 2000);
  } catch {}
}

// 3. Tab Cleanup Listener (Prevent memory leaks when tabs are closed)
if (typeof chrome !== 'undefined' && chrome.tabs?.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    tabSecurityState.delete(tabId);
  });
}

// 4. Suspend Listener for State Cleanup
if (typeof chrome !== 'undefined' && chrome.runtime?.onSuspend) {
  chrome.runtime.onSuspend.addListener(() => {
    storage.flush();
  });
}
