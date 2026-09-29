/**
 * URL Detector Module
 * Comprehensive URL analysis inspecting encoding, Unicode, homographs, entropy, TLDs, and structure.
 * @module URLDetector
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';
import { EntropyUtils } from '../../utils/EntropyUtils.js';
import { PunycodeUtils } from '../../utils/PunycodeUtils.js';

export class URLDetector extends DetectorInterface {
  constructor() {
    super();
    /** @type {string[]} */
    this.legitimateDomains = [
      'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
      'twitter.com', 'instagram.com', 'youtube.com', 'linkedin.com', 'tiktok.com',
      'paypal.com', 'stripe.com', 'square.com', 'chase.com', 'bankofamerica.com',
      'wellsfargo.com', 'citibank.com', 'venmo.com', 'cashapp.com', 'coinbase.com',
      'github.com', 'gitlab.com', 'stackoverflow.com', 'netflix.com', 'spotify.com'
    ].map(domain => ({
      domain,
      label: domain.split('.')[0]
    }));

    /** @type {string[]} */
    this.suspiciousTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
      '.live', '.site', '.online', '.club', '.bid', '.loan', '.zip', '.mov'
    ];

    /** @type {string[]} */
    this.urlShorteners = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly'
    ];

    /** @type {string[]} */
    this.suspiciousKeywords = [
      'verify', 'urgent', 'suspended', 'locked', 'limited', 'unusual',
      'confirm', 'update', 'secure', 'expire', 'immediately', 'account-update',
      'security-alert', 'billing-problem', 'reset-password', 'login-claim'
    ];
  }

  name() { return 'URLDetector'; }
  version() { return '2.0.0'; }
  priority() { return 1000; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && typeof context.url === 'string');
  }

  /**
   * Run comprehensive URL analysis.
   * @param {Record<string, *>} context 
   * @returns {Promise<import('../../plugins/DetectorInterface.js').DetectorResult>}
   */
  async analyze(context) {
    const startTime = performance.now();
    const rawUrl = context.url;
    const findings = [];
    let totalScore = 0;

    if (!rawUrl || typeof rawUrl !== 'string') {
      return this._buildResult(0, 1.0, 'LOW', [], performance.now() - startTime);
    }

    try {
      // 1. Data/Blob URL Check
      if (rawUrl.startsWith('data:') || rawUrl.startsWith('blob:')) {
        findings.push({
          id: 'URL_DATA_BLOB_SCHEME',
          type: 'DATA_OR_BLOB_URL',
          description: 'Data or Blob URL scheme detected (frequently used for isolated phishing frames).',
          score: 30,
          severity: 'HIGH'
        });
        totalScore += 30;
      }

      const urlObj = new URL(rawUrl);
      const hostname = urlObj.hostname.toLowerCase();
      const protocol = urlObj.protocol;

      // 2. IP Address Detection (IPv4 / IPv6)
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6Regex = /^\[?[a-f0-9]*:[a-f0-9:]+\]?$/i;
      if (ipv4Regex.test(hostname) || ipv6Regex.test(hostname)) {
        findings.push({
          id: 'URL_IP_HOSTNAME',
          type: 'RAW_IP_DOMAIN',
          description: `Raw IP address used as hostname (${hostname}).`,
          score: 35,
          severity: 'HIGH'
        });
        totalScore += 35;
      }

      // 3. Port Analysis
      if (urlObj.port && !['80', '443', ''].includes(urlObj.port)) {
        findings.push({
          id: 'URL_NON_STANDARD_PORT',
          type: 'NON_STANDARD_PORT',
          description: `Non-standard port detected: ${urlObj.port}.`,
          score: 15,
          severity: 'MEDIUM'
        });
        totalScore += 15;
      }

      // 4. Embedded Credentials (http://user:pass@host)
      if (urlObj.username || urlObj.password) {
        findings.push({
          id: 'URL_EMBEDDED_CREDENTIALS',
          type: 'EMBEDDED_CREDENTIALS',
          description: 'URL contains embedded username or password credentials.',
          score: 25,
          severity: 'HIGH'
        });
        totalScore += 25;
      }

      // 5. Punycode & Homograph Attack Check
      if (PunycodeUtils.isPunycode(hostname)) {
        const decodedHost = PunycodeUtils.decodePunycode(hostname);
        findings.push({
          id: 'URL_PUNYCODE_HOST',
          type: 'PUNYCODE_ENCODING',
          description: `Punycode international domain detected (decodes to: ${decodedHost}).`,
          score: 30,
          severity: 'HIGH'
        });
        totalScore += 30;
      }

      const homographResult = PunycodeUtils.detectHomographs(hostname);
      if (homographResult.hasHomograph) {
        findings.push({
          id: 'URL_HOMOGRAPH_ATTACK',
          type: 'HOMOGRAPH_SPOOFING',
          description: `Confusable Unicode characters detected in domain (${homographResult.detectedChars.map(c => c.original).join(', ')}).`,
          score: 40,
          severity: 'CRITICAL',
          metadata: { detectedChars: homographResult.detectedChars }
        });
        totalScore += 40;
      }

      // 6. Typosquatting & Levenshtein Distance Check
      const normalizedHost = PunycodeUtils.replaceSubstitutions(hostname);
      const hostLabels = hostname.split(/[.-]/);
      const normalizedLabels = normalizedHost.split(/[.-]/);

      for (const brand of this.legitimateDomains) {
        const targetBrand = brand.domain;
        const brandLabel = brand.label;
        if (hostname === targetBrand || hostname.endsWith('.' + targetBrand)) {
          continue;
        }

        let isTyposquat = false;
        let detectedEditDistance = 999;

        // Check each label/token in hostname for brand typosquatting
        for (let i = 0; i < hostLabels.length; i++) {
          const rawLabel = hostLabels[i];
          const normLabel = normalizedLabels[i] || rawLabel;

          // Skip top-level domains like 'com', 'org', etc.
          if (rawLabel.length <= 3 && i === hostLabels.length - 1) continue;

          let minDistance = 999;
          if (Math.abs(rawLabel.length - brandLabel.length) <= 2) {
            const rawDistance = EntropyUtils.calculateLevenshteinDistance(rawLabel, brandLabel);
            const normDistance = EntropyUtils.calculateLevenshteinDistance(normLabel, brandLabel);
            minDistance = Math.min(rawDistance, normDistance);
          }

          if (
            (minDistance > 0 && minDistance <= 2) ||
            (normLabel === brandLabel && rawLabel !== brandLabel) ||
            (rawLabel === brandLabel && !hostname.endsWith('.' + targetBrand))
          ) {
            isTyposquat = true;
            detectedEditDistance = minDistance;
            break;
          }
        }

        if (isTyposquat) {
          findings.push({
            id: 'URL_TYPOSQUATTING',
            type: 'TYPOSQUATTING_ATTACK',
            description: `Domain '${hostname}' is a potential typosquatting clone of '${targetBrand}'.`,
            score: 35,
            severity: 'HIGH',
            metadata: { targetBrand, editDistance: detectedEditDistance }
          });
          totalScore += 35;
          break;
        }
      }

      // 7. Shannon Entropy Analysis
      const entropy = EntropyUtils.calculateShannonEntropy(hostname);
      if (entropy >= 4.3 && hostname.length > 10) {
        findings.push({
          id: 'URL_HIGH_ENTROPY',
          type: 'HIGH_ENTROPY_DOMAIN',
          description: `High domain character entropy (${entropy}) suggesting algorithmically generated domain (DGA).`,
          score: 20,
          severity: 'MEDIUM',
          metadata: { entropy }
        });
        totalScore += 20;
      }

      // 8. Subdomain Depth Analysis
      const subdomains = hostname.split('.');
      if (subdomains.length > 4) {
        findings.push({
          id: 'URL_EXCESSIVE_SUBDOMAINS',
          type: 'SUBDOMAIN_STUFFING',
          description: `Excessive subdomain depth (${subdomains.length} labels).`,
          score: 15,
          severity: 'MEDIUM'
        });
        totalScore += 15;
      }

      // 9. Suspicious TLD Check
      for (const tld of this.suspiciousTLDs) {
        if (hostname.endsWith(tld)) {
          findings.push({
            id: 'URL_SUSPICIOUS_TLD',
            type: 'SUSPICIOUS_TLD',
            description: `Domain uses high-risk TLD (${tld}).`,
            score: 15,
            severity: 'MEDIUM'
          });
          totalScore += 15;
          break;
        }
      }

      // 10. URL Shortener Check
      if (this.urlShorteners.includes(hostname)) {
        findings.push({
          id: 'URL_SHORTENER',
          type: 'URL_SHORTENER',
          description: `URL uses known shortener service (${hostname}).`,
          score: 10,
          severity: 'LOW'
        });
        totalScore += 10;
      }

      // 11. Keyword Stuffing Check
      let keywordMatches = 0;
      for (const keyword of this.suspiciousKeywords) {
        if (rawUrl.toLowerCase().includes(keyword)) {
          keywordMatches++;
        }
      }
      if (keywordMatches >= 2) {
        findings.push({
          id: 'URL_KEYWORD_STUFFING',
          type: 'PHISHING_KEYWORDS',
          description: `URL contains multiple high-pressure security keywords (${keywordMatches} matches).`,
          score: Math.min(keywordMatches * 5, 20),
          severity: 'MEDIUM'
        });
        totalScore += Math.min(keywordMatches * 5, 20);
      }

      // 12. Non-HTTPS Sensitive Path Check
      if (protocol === 'http:' && (rawUrl.includes('/login') || rawUrl.includes('/signin') || rawUrl.includes('/account'))) {
        findings.push({
          id: 'URL_HTTP_SENSITIVE_PATH',
          type: 'INSECURE_SENSITIVE_PAGE',
          description: 'Insecure HTTP protocol used on login or account page.',
          score: 25,
          severity: 'HIGH'
        });
        totalScore += 25;
      }

    } catch (err) {
      // Graceful error isolation
    }

    const finalScore = Math.min(totalScore, 100);
    const severity = this._determineSeverity(finalScore);
    const executionTime = parseFloat((performance.now() - startTime).toFixed(2));

    return this._buildResult(finalScore, 0.95, severity, findings, executionTime);
  }

  /**
   * @private
   */
  _determineSeverity(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'LOW';
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
