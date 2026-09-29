/**
 * Form Security Detector Module
 * Scans HTML forms for credential harvesting, credit card fields, OTP, crypto seed phrases, SSN, and off-screen inputs.
 * @module FormDetector
 */

import { DetectorInterface } from '../../plugins/DetectorInterface.js';

export class FormDetector extends DetectorInterface {
  name() { return 'FormDetector'; }
  version() { return '2.0.0'; }
  priority() { return 900; }
  enabled() { return true; }

  supports(context) {
    return Boolean(context && (context.dom || context.forms));
  }

  /**
   * Analyze forms within DOM context.
   * @param {Record<string, *>} context 
   * @returns {Promise<import('../../plugins/DetectorInterface.js').DetectorResult>}
   */
  async analyze(context) {
    const startTime = performance.now();
    const findings = [];
    let totalScore = 0;

    const forms = context.forms || this._extractFormsFromDOM(context.dom);
    const pageUrl = context.url || (typeof location !== 'undefined' ? location.href : '');
    const isHttps = pageUrl.startsWith('https:');

    if (!forms || forms.length === 0) {
      return this._buildResult(0, 1.0, 'LOW', [], performance.now() - startTime);
    }

    for (const form of forms) {
      const inputs = form.inputs || [];
      const action = (form.action || '').toLowerCase();

      // 1. Insecure Form Submission over HTTP
      if (!isHttps || (action && action.startsWith('http:'))) {
        const hasPasswordField = inputs.some(i => i.type === 'password');
        if (hasPasswordField) {
          findings.push({
            id: 'FORM_PASSWORD_NO_HTTPS',
            type: 'INSECURE_CREDENTIAL_FORM',
            description: 'Password input submitted over insecure HTTP protocol.',
            score: 35,
            severity: 'HIGH'
          });
          totalScore += 35;
        }
      }

      // 2. Cross-Domain Form Action Target
      if (action && action.startsWith('http')) {
        try {
          const actionHost = new URL(action).hostname.toLowerCase();
          const pageHost = new URL(pageUrl).hostname.toLowerCase();
          if (actionHost && pageHost && !this._isSameRegistrableDomain(actionHost, pageHost)) {
            findings.push({
              id: 'FORM_EXTERNAL_ACTION',
              type: 'CROSS_DOMAIN_FORM',
              description: `Form posts sensitive payload to external third-party domain (${actionHost}).`,
              score: 30,
              severity: 'HIGH',
              metadata: { actionHost, pageHost }
            });
            totalScore += 30;
          }
        } catch {}
      }

      // 3. Sensitive Data Field Detection
      for (const input of inputs) {
        const name = (input.name || '').toLowerCase();
        const id = (input.id || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        const combined = `${name} ${id} ${placeholder}`;

        // Credit Card Harvesting
        if (combined.match(/cardnumber|cc-number|cvv|cvc|expir|creditcard/i)) {
          findings.push({
            id: 'FORM_CREDIT_CARD',
            type: 'CREDIT_CARD_HARVESTING',
            description: 'Form requests Credit Card numbers or security codes.',
            score: 25,
            severity: 'HIGH'
          });
          totalScore += 25;
        }

        // Social Security Number (SSN) / Tax ID / Gov ID
        if (combined.match(/ssn|social-security|taxid|national-id|passport|gov-id/i)) {
          findings.push({
            id: 'FORM_GOV_ID_SSN',
            type: 'GOV_ID_HARVESTING',
            description: 'Form requests Social Security or Government ID numbers.',
            score: 30,
            severity: 'HIGH'
          });
          totalScore += 30;
        }

        // Crypto Wallet / Seed Phrase / Private Key
        if (combined.match(/seedphrase|mnemonic|privatekey|wallet-passphrase|secret-phrase/i)) {
          findings.push({
            id: 'FORM_CRYPTO_SEED_PHRASE',
            type: 'CRYPTO_SEED_HARVESTING',
            description: 'Form requests cryptocurrency seed phrase or private keys.',
            score: 40,
            severity: 'CRITICAL'
          });
          totalScore += 40;
        }

        // OTP / 2FA Code Harvesting
        if (combined.match(/otp|twofactor|2fa|verification-code|authenticator/i)) {
          findings.push({
            id: 'FORM_OTP_HARVESTING',
            type: 'OTP_HARVESTING',
            description: 'Form requests One-Time Password (OTP) or 2FA security tokens.',
            score: 20,
            severity: 'MEDIUM'
          });
          totalScore += 20;
        }

        // Off-Screen / Hidden Input Abuse
        if (input.isHidden || input.isOffScreen) {
          if (input.type === 'password' || input.type === 'email') {
            findings.push({
              id: 'FORM_OFFSCREEN_HIDDEN_INPUT',
              type: 'HIDDEN_CREDENTIAL_FIELD',
              description: 'Hidden or off-screen credential input field detected (autofill abuse vector).',
              score: 25,
              severity: 'HIGH'
            });
            totalScore += 25;
          }
        }
      }

      // 4. Multiple Password Fields (Credential Sniffing)
      const passwordInputs = inputs.filter(i => i.type === 'password');
      if (passwordInputs.length > 2) {
        findings.push({
          id: 'FORM_MULTIPLE_PASSWORD_FIELDS',
          type: 'SUSPICIOUS_PASSWORD_COUNT',
          description: `Form contains unusually high number of password fields (${passwordInputs.length}).`,
          score: 15,
          severity: 'MEDIUM'
        });
        totalScore += 15;
      }
    }

    const finalScore = Math.min(totalScore, 100);
    const severity = finalScore >= 80 ? 'CRITICAL' : finalScore >= 60 ? 'HIGH' : finalScore >= 40 ? 'MEDIUM' : 'LOW';
    const executionTime = parseFloat((performance.now() - startTime).toFixed(2));

    return {
      score: finalScore,
      confidence: 0.9,
      severity,
      findings,
      metadata: { formCount: forms.length },
      executionTime
    };
  }

  /**
   * @private
   */
  _extractFormsFromDOM(dom) {
    if (!dom || typeof dom.querySelectorAll !== 'function') return [];
    const formNodes = Array.from(dom.querySelectorAll('form'));
    return formNodes.map(form => {
      const inputs = Array.from(form.querySelectorAll('input, select, textarea')).map(input => ({
        type: input.type || 'text',
        name: input.name || '',
        id: input.id || '',
        placeholder: input.placeholder || '',
        isHidden: input.type === 'hidden' || input.style.display === 'none' || input.style.visibility === 'hidden',
        isOffScreen: input.offsetWidth === 0 && input.offsetHeight === 0
      }));

      return {
        action: form.action || '',
        method: form.method || 'get',
        inputs
      };
    });
  }

  /**
   * Check if two hostnames share the same effective registrable domain.
   * Handles common compound ccTLDs (e.g. .co.uk, .com.au, .org.uk) and standard TLDs.
   * @private
   * @param {string} h1
   * @param {string} h2
   * @returns {boolean}
   */
  _isSameRegistrableDomain(h1, h2) {
    if (h1 === h2) return true;
    const getRoot = (host) => {
      const parts = host.split('.');
      if (parts.length <= 2) return host;
      const tld = parts[parts.length - 1];
      const sld = parts[parts.length - 2];
      if (tld.length === 2 && (sld.length <= 3 && ['co', 'com', 'org', 'net', 'gov', 'edu'].includes(sld))) {
        return parts.slice(-3).join('.');
      }
      return parts.slice(-2).join('.');
    };
    return getRoot(h1) === getRoot(h2);
  }

  cleanup() {
    // Release memory footprints
  }
}
