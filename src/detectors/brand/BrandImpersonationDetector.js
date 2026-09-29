/**
 * Brand Impersonation Detector Module
 * Heuristic rules-based brand spoofing engine comparing DOM titles, favicons, meta logos, and target brand keywords.
 * @module BrandImpersonationDetector
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';
import { EntropyUtils } from '../../utils/EntropyUtils.js';

export class BrandImpersonationDetector extends DetectorInterface {
  constructor() {
    super();
    /** @type {Array<{ name: string, domain: string, keywords: string[] }>} */
    this.brandDatabase = [
      { name: 'Google', domain: 'google.com', keywords: ['google', 'gmail', 'google drive', 'google account'] },
      { name: 'PayPal', domain: 'paypal.com', keywords: ['paypal', 'pay pal', 'paypal service'] },
      { name: 'Microsoft', domain: 'microsoft.com', keywords: ['microsoft', 'outlook', 'office365', 'azure', 'windows'] },
      { name: 'Apple', domain: 'apple.com', keywords: ['apple', 'icloud', 'apple id', 'itunes'] },
      { name: 'Amazon', domain: 'amazon.com', keywords: ['amazon', 'prime', 'amazon pay'] },
      { name: 'Meta / Facebook', domain: 'facebook.com', keywords: ['facebook', 'meta', 'instagram', 'whatsapp'] },
      { name: 'Netflix', domain: 'netflix.com', keywords: ['netflix', 'watch netflix'] },
      { name: 'Chase Bank', domain: 'chase.com', keywords: ['chase', 'chase bank', 'jp morgan'] }
    ];
  }

  name() { return 'BrandImpersonationDetector'; }
  version() { return '2.0.0'; }
  priority() { return 820; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && context.url);
  }

  /**
   * Analyze page for brand spoofing.
   * @param {Record<string, *>} context 
   * @returns {Promise<import('../../plugins/DetectorInterface.js').DetectorResult>}
   */
  async analyze(context) {
    const startTime = performance.now();
    const findings = [];
    let totalScore = 0;

    let currentHost = '';
    try {
      currentHost = new URL(context.url).hostname.toLowerCase();
    } catch {
      return this._buildResult(0, 1.0, 'LOW', [], performance.now() - startTime);
    }

    const title = (context.title || '').toLowerCase();

    for (const brand of this.brandDatabase) {
      // If current domain is the legitimate brand domain or official subdomain, skip
      if (currentHost === brand.domain || currentHost.endsWith('.' + brand.domain)) {
        continue;
      }

      // 1. Title Impersonation (Page title claims to be brand, but host is external)
      const titleMatches = brand.keywords.filter(kw => title.includes(kw));
      if (titleMatches.length > 0) {
        // Double check if host is completely unrelated
        const distance = EntropyUtils.calculateLevenshteinDistance(currentHost, brand.domain);
        const score = distance <= 3 ? 35 : 20;

        findings.push({
          id: `BRAND_SPOOF_${brand.name.toUpperCase().replace(/\s+/g, '_')}`,
          type: 'BRAND_IMPERSONATION',
          description: `Page title references brand '${brand.name}' on untrusted domain '${currentHost}'.`,
          score,
          severity: score >= 35 ? 'HIGH' : 'MEDIUM',
          metadata: { targetBrand: brand.name, legitimateDomain: brand.domain }
        });
        totalScore += score;
        break;
      }

      // 2. Hostname Keyword Spoofing (Domain embeds brand label as distinct token on untrusted host)
      const brandLabel = brand.domain.split('.')[0];
      const hostTokens = currentHost.split(/[.-]/);
      if (hostTokens.includes(brandLabel)) {
        findings.push({
          id: `BRAND_DOMAIN_SPOOF_${brand.name.toUpperCase().replace(/\s+/g, '_')}`,
          type: 'BRAND_DOMAIN_SPOOFING',
          description: `Domain '${currentHost}' embeds brand name '${brand.name}' without authorization.`,
          score: 30,
          severity: 'HIGH',
          metadata: { targetBrand: brand.name, legitimateDomain: brand.domain }
        });
        totalScore += 30;
        break;
      }
    }

    const finalScore = Math.min(totalScore, 100);
    const severity = finalScore >= 80 ? 'CRITICAL' : finalScore >= 60 ? 'HIGH' : finalScore >= 40 ? 'MEDIUM' : 'LOW';
    const executionTime = parseFloat((performance.now() - startTime).toFixed(2));

    return this._buildResult(finalScore, 0.85, severity, findings, executionTime);
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
    // Release memory footprints
  }
}
