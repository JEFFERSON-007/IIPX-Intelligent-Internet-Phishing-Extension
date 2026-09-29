/**
 * Reputation Engine Module
 * Modular reputation lookup engine powered by an O(L) Suffix Domain Trie
 * and pluggable threat reputation providers.
 * @module ReputationEngine
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';
import { MultiLayerCache } from '../../cache/MultiLayerCache.js';
import { DomainTrie } from '../../utils/DomainTrie.js';

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

    /** @type {DomainTrie} Suffix Trie for O(L) domain & wildcard subdomain lookups */
    this.blocklistTrie = new DomainTrie();
    this.blocklistTrie.insertAll([
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
   * Add a domain to the offline blocklist trie.
   * @param {string} domain 
   */
  addBlockedDomain(domain) {
    this.blocklistTrie.insert(domain);
  }

  /**
   * Register an external cloud reputation provider (e.g. VirusTotal, Safe Browsing, PhishTank).
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

    // 1. High-Performance Suffix Trie Match O(L)
    const trieResult = this.blocklistTrie.match(hostname);
    if (trieResult.matched) {
      findings.push({
        id: 'REPUTATION_OFFLINE_BLOCKLIST',
        type: 'KNOWN_MALICIOUS_DOMAIN',
        description: `Domain '${hostname}' matched blocked signature '${trieResult.ruleDomain}' on the offline security blocklist.`,
        score: 100,
        severity: 'CRITICAL',
        metadata: { matchedRule: trieResult.ruleDomain }
      });
      totalScore = 100;
    }

    // 2. Cached Reputation Check O(1)
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

    // 3. Pluggable Providers (if any registered and enabled)
    if (totalScore < 100 && this.providers.size > 0) {
      for (const [providerName, provider] of this.providers.entries()) {
        try {
          const providerResult = await provider.checkURL(context.url);
          if (providerResult && providerResult.isMalicious) {
            findings.push({
              id: `REPUTATION_${providerName.toUpperCase()}_HIT`,
              type: 'EXTERNAL_THREAT_HIT',
              description: `Threat detected by reputation provider '${providerName}'.`,
              score: 85,
              severity: 'CRITICAL',
              metadata: { provider: providerName }
            });
            totalScore = Math.max(totalScore, 85);
            this.cache.set(hostname, { isMalicious: true });
            break;
          }
        } catch {
          // Provider failure isolation
        }
      }
    }

    const finalScore = Math.min(totalScore, 100);
    const severity = finalScore >= 80 ? 'CRITICAL' : finalScore >= 60 ? 'HIGH' : finalScore >= 40 ? 'MEDIUM' : 'LOW';
    const executionTime = parseFloat((performance.now() - startTime).toFixed(2));

    return this._buildResult(finalScore, 0.98, severity, findings, executionTime);
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
      metadata: { detector: this.name() },
      executionTime
    };
  }

  cleanup() {
    this.cache.purgeExpired();
  }
}
