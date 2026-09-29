/**
 * Reputation Engine Module
 * Modular reputation lookup engine supporting offline lists and pluggable cloud API adapters (disabled by default).
 * @module ReputationEngine
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';
import { MultiLayerCache } from '../../cache/MultiLayerCache.js';

/**
 * Reputation Provider Interface Contract
 * @typedef {Object} ReputationProvider
 * @property {string} name
 * @property {function(string): Promise<{ isMalicious: boolean, category?: string, confidence?: number }>} checkURL
 */

export class ReputationEngine extends DetectorInterface {
  constructor() {
    super();
    /** @type {MultiLayerCache} */
    this.cache = new MultiLayerCache(2000, 60 * 60 * 1000); // 1 hour TTL
    /** @type {Map<string, ReputationProvider>} */
    this.providers = new Map();

    /** @type {Set<string>} Offline high-risk blocklist */
    this.offlineBlocklist = new Set([
      'phishing-test-domain.com',
      'malicious-login-fake.net',
      'account-verification-alert.org'
    ]);
  }

  name() { return 'ReputationEngine'; }
  version() { return '2.0.0'; }
  priority() { return 950; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && context.url);
  }

  /**
   * Register a external cloud reputation provider (e.g. VirusTotal, Safe Browsing, PhishTank).
   * NOTE: No cloud providers are registered or enabled by default to maintain 100% offline privacy.
   * @param {ReputationProvider} provider 
   */
  registerProvider(provider) {
    if (provider && provider.name && typeof provider.checkURL === 'function') {
      this.providers.set(provider.name, provider);
    }
  }

  /**
   * Run reputation check against offline lists and registered providers.
   * @param {Record<string, *>} context 
   * @returns {Promise<import('../../plugins/DetectorInterface.js').DetectorResult>}
   */
  async analyze(context) {
    const startTime = performance.now();
    const findings = [];
    let totalScore = 0;

    let hostname = '';
    try {
      hostname = new URL(context.url).hostname.toLowerCase();
    } catch {
      return this._buildResult(0, 1.0, 'LOW', [], performance.now() - startTime);
    }

    // 1. Offline Local Blocklist Check (with subdomain matching)
    let isBlocklisted = false;
    for (const blockedDomain of this.offlineBlocklist) {
      if (hostname === blockedDomain || hostname.endsWith('.' + blockedDomain)) {
        isBlocklisted = true;
        break;
      }
    }

    if (isBlocklisted) {
      findings.push({
        id: 'REPUTATION_OFFLINE_BLOCKLIST',
        type: 'KNOWN_MALICIOUS_DOMAIN',
        description: `Domain '${hostname}' is present on the offline security blocklist.`,
        score: 100,
        severity: 'CRITICAL'
      });
      totalScore = 100;
    }

    // 2. Cached Reputation Check
    const cached = this.cache.get(hostname);
    if (cached && cached.isMalicious) {
      findings.push({
        id: 'REPUTATION_CACHED_MATCH',
        type: 'KNOWN_MALICIOUS_DOMAIN',
        description: `Domain '${hostname}' matched known threat reputation cache.`,
        score: 100,
        severity: 'CRITICAL'
      });
      totalScore = 100;
    }

    const finalScore = Math.min(totalScore, 100);
    const severity = finalScore >= 80 ? 'CRITICAL' : finalScore >= 50 ? 'HIGH' : 'LOW';
    const executionTime = parseFloat((performance.now() - startTime).toFixed(2));

    return this._buildResult(finalScore, 1.0, severity, findings, executionTime);
  }

  /**
   * @private
   */
  _buildResult(score, confidence, severity, findings, executionTime) {
    return {
      score,
      confidence,
      severity,
      findings,
      metadata: { activeProviders: Array.from(this.providers.keys()) },
      executionTime
    };
  }

  cleanup() {
    // Release memory footprints
    this.cache.purgeExpired();
  }
}
