/**
 * Comprehensive Test Runner Suite
 * Runs unit tests, integration tests, and advanced DSA validation tests.
 * @module run-all-tests
 */

import { testURLDetector } from './unit/url-detector.test.js';
import { testRiskFusionEngine } from './unit/fusion-engine.test.js';
import { testDetectionPipeline } from './integration/detection-pipeline.test.js';

import { URLDetector } from '../detectors/url/URLDetector.js';
import { DOMDetector } from '../detectors/dom/DOMDetector.js';
import { MultiLayerCache } from '../cache/MultiLayerCache.js';
import { RiskFusionEngine } from '../core/fusion/RiskFusionEngine.js';
import { DomainTrie } from '../utils/DomainTrie.js';
import { EntropyUtils } from '../utils/EntropyUtils.js';
import { PunycodeUtils } from '../utils/PunycodeUtils.js';
import { FormDetector } from '../detectors/form/FormDetector.js';
import { BrandImpersonationDetector } from '../detectors/brand/BrandImpersonationDetector.js';
import { EnterprisePolicyEngine } from '../core/policy/EnterprisePolicyEngine.js';

export async function runAllTests() {
  console.log('🧪 Starting Phishing Extension Test Suite...\n');

  let passed = 0;
  let failed = 0;

  async function assertAsync(testName, fn) {
    try {
      await fn();
      console.log(`  ✅ PASSED: ${testName}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ FAILED: ${testName}`);
      console.error(`     ${err.message}`);
      failed++;
    }
  }

  console.log('--- 1. Unit Tests ---');
  await assertAsync('URLDetector Unit Tests', async () => {
    const res = await testURLDetector();
    if (!res) throw new Error('testURLDetector returned false');
  });

  await assertAsync('RiskFusionEngine Unit Tests', async () => {
    const res = testRiskFusionEngine();
    if (!res) throw new Error('testRiskFusionEngine returned false');
  });

  console.log('\n--- 2. Integration Tests ---');
  await assertAsync('Detection Pipeline Integration Test', async () => {
    const res = await testDetectionPipeline();
    if (!res) throw new Error('testDetectionPipeline returned false');
  });

  console.log('\n--- 3. Advanced DSA & Algorithm Verifications ---');

  await assertAsync('DomainTrie: O(L) Suffix Subdomain Matching', () => {
    const trie = new DomainTrie();
    trie.insert('phishing-hub.com');
    trie.insert('malicious.co.uk');

    // Exact matches
    if (!trie.match('phishing-hub.com').matched) throw new Error('Exact domain should match');
    if (!trie.match('malicious.co.uk').matched) throw new Error('Exact multi-tld domain should match');

    // Subdomain wildcard matches
    if (!trie.match('login.phishing-hub.com').matched) throw new Error('Subdomain should match');
    if (!trie.match('secure.portal.phishing-hub.com').matched) throw new Error('Deep subdomain should match');

    // Negative / Non-matching domains
    if (trie.match('safe-phishing-hub.com').matched) throw new Error('Prefix domain should not match');
    if (trie.match('phishing-hub.org').matched) throw new Error('Different TLD should not match');
    if (trie.match('google.com').matched) throw new Error('Unrelated domain should not match');
  });

  await assertAsync('EntropyUtils: Bounded Levenshtein & Shannon Entropy', () => {
    // Exact & 1-edit distance
    const dist1 = EntropyUtils.calculateLevenshteinDistance('paypal', 'paypa1', 2);
    if (dist1 !== 1) throw new Error(`Expected edit distance 1, got ${dist1}`);

    // Early exit cutoff
    const distCutoff = EntropyUtils.calculateLevenshteinDistance('paypal', 'completelyunrelateddomain', 2);
    if (distCutoff <= 2) throw new Error(`Cutoff expected > 2, got ${distCutoff}`);

    // Shannon entropy
    const entropy = EntropyUtils.calculateShannonEntropy('google.com');
    if (entropy <= 0 || entropy >= 8) throw new Error(`Unexpected entropy value: ${entropy}`);
  });

  await assertAsync('PunycodeUtils: Inverted Confusables Map & Homograph Normalization', () => {
    // Cyrillic 'а' (U+0430)
    const detected = PunycodeUtils.detectHomographs('https://аmazon.com');
    if (!detected.hasHomograph) throw new Error('Should detect Cyrillic homograph');
    if (detected.detectedChars[0].mappedTo !== 'a') throw new Error('Should map to Latin "a"');

    // Cyrillic 'р' (U+0440) -> 'p'
    const normalized = PunycodeUtils.normalizeHomographs('рaypal.com');
    if (normalized !== 'paypal.com') throw new Error(`Expected 'paypal.com', got '${normalized}'`);

    // Substitution replacement (0 -> o, 1 -> l)
    const replaced = PunycodeUtils.replaceSubstitutions('g00gle.com');
    if (replaced !== 'google.com') throw new Error(`Expected 'google.com', got '${replaced}'`);
  });

  await assertAsync('MultiLayerCache: O(1) Doubly-Linked List Eviction', () => {
    const cache = new MultiLayerCache(2, 60000); // Capacity 2
    cache.set('a', 'valA');
    cache.set('b', 'valB');

    // Access 'a' to make it most recently used; 'b' is now least recently used
    cache.get('a');

    // Insert 'c' -> should evict 'b'
    cache.set('c', 'valC');

    if (cache.get('b') !== null) throw new Error('Expected "b" to be evicted');
    if (cache.get('a') !== 'valA') throw new Error('Expected "a" to remain in cache');
    if (cache.get('c') !== 'valC') throw new Error('Expected "c" to remain in cache');
  });

  console.log('\n--- 4. Edge Case Regression Tests ---');
  
  await assertAsync('URLDetector: Typosquatting (g00gle.com)', async () => {
    const detector = new URLDetector();
    const result = await detector.analyze({ url: 'http://g00gle.com/login' });
    if (result.score < 35) throw new Error(`Expected score >= 35, got ${result.score}`);
    if (!result.findings.some(f => f.type === 'TYPOSQUATTING_ATTACK')) {
      throw new Error('Expected TYPOSQUATTING_ATTACK finding missing');
    }
  });

  await assertAsync('URLDetector: Typosquatting (paypa1.com)', async () => {
    const detector = new URLDetector();
    const result = await detector.analyze({ url: 'https://paypa1.com/verify' });
    if (result.score < 35) throw new Error(`Expected score >= 35, got ${result.score}`);
    if (!result.findings.some(f => f.type === 'TYPOSQUATTING_ATTACK')) {
      throw new Error('Expected TYPOSQUATTING_ATTACK finding missing');
    }
  });

  await assertAsync('DOMDetector: Serialized domData Processing', async () => {
    const detector = new DOMDetector();
    const context = {
      domData: {
        iframes: [{ src: 'http://malicious-iframe.com/login', width: 0, height: 0, isHidden: true }],
        scripts: [],
        overlays: [],
        anchors: []
      }
    };
    const result = await detector.analyze(context);
    if (result.score < 25) throw new Error(`Expected score >= 25, got ${result.score}`);
    if (!result.findings.some(f => f.type === 'HIDDEN_IFRAME')) {
      throw new Error('Expected HIDDEN_IFRAME finding missing');
    }
  });

  await assertAsync('MultiLayerCache: has() Non-Mutating Hit Counter', () => {
    const cache = new MultiLayerCache(10, 60000);
    cache.set('key1', 'val1');
    const initialStats = cache.getStats();
    if (initialStats.hits !== 0) throw new Error('Hits should start at 0');

    const exists = cache.has('key1');
    if (!exists) throw new Error('Key should exist in cache');

    const afterHasStats = cache.getStats();
    if (afterHasStats.hits !== 0) throw new Error(`has() inflated hits to ${afterHasStats.hits}`);
  });

  await assertAsync('RiskFusionEngine: Critical Score Dilution Prevention', () => {
    const fusion = new RiskFusionEngine();
    const mockOutputs = [
      { name: 'URLDetector', result: { score: 90, confidence: 1.0, severity: 'CRITICAL', findings: [] } },
      { name: 'FormDetector', result: { score: 0, confidence: 1.0, severity: 'LOW', findings: [] } },
      { name: 'DOMDetector', result: { score: 0, confidence: 1.0, severity: 'LOW', findings: [] } },
      { name: 'BehaviorDetector', result: { score: 0, confidence: 1.0, severity: 'LOW', findings: [] } }
    ];
    const fused = fusion.fuse(mockOutputs);
    if (fused.riskScore < 75) {
      throw new Error(`Fused riskScore diluted too low: ${fused.riskScore}`);
    }
    if (fused.classification !== 'CRITICAL' && fused.classification !== 'HIGH') {
      throw new Error(`Expected CRITICAL or HIGH classification, got ${fused.classification}`);
    }
  });

  await assertAsync('BrandImpersonationDetector: Domain Keyword Spoofing', async () => {
    const detector = new BrandImpersonationDetector();
    const result = await detector.analyze({ url: 'http://paypal-security-update.com/login', title: 'Security Alert' });
    if (result.score < 30) throw new Error(`Expected score >= 30, got ${result.score}`);
    if (!result.findings.some(f => f.type === 'BRAND_DOMAIN_SPOOFING')) {
      throw new Error('Expected BRAND_DOMAIN_SPOOFING finding missing');
    }
  });

  await assertAsync('BrandImpersonationDetector: News Article Exemption vs Fake Login Detection', async () => {
    const detector = new BrandImpersonationDetector();

    // 1. Legitimate news article mentioning Google without login forms
    const newsResult = await detector.analyze({
      url: 'https://thetechnewsblog.com/articles/google-ai-update',
      title: 'Google announces massive breakthrough in AI',
      forms: []
    });
    if (newsResult.score !== 0) {
      throw new Error(`Expected score 0 for news article, got ${newsResult.score}`);
    }

    // 2. Fake Google login portal on external domain with password field
    const phishResult = await detector.analyze({
      url: 'https://thetechnewsblog.com/fake-login',
      title: 'Sign in - Google Accounts',
      forms: [{
        action: 'https://thetechnewsblog.com/post',
        inputs: [{ type: 'password', name: 'Passwd' }]
      }]
    });
    if (phishResult.score < 30) {
      throw new Error(`Expected score >= 30 for fake login portal, got ${phishResult.score}`);
    }
  });

  await assertAsync('FormDetector: Same Registrable Domain Subdomain Exemption', async () => {
    const detector = new FormDetector();

    // 1. Same-root subdomains: login.example.com posting to api.example.com
    const sameRootResult = await detector.analyze({
      url: 'https://login.example.com/signin',
      forms: [{
        action: 'https://api.example.com/v1/auth',
        inputs: [{ type: 'password', name: 'password' }]
      }]
    });
    if (sameRootResult.findings.some(f => f.id === 'FORM_EXTERNAL_ACTION')) {
      throw new Error('Same root domain subdomains should not trigger FORM_EXTERNAL_ACTION');
    }

    // 2. Malicious cross-domain: mybank.com posting to external evil-server.com
    const externalResult = await detector.analyze({
      url: 'https://mybank.com/portal',
      forms: [{
        action: 'https://evil-server.com/collect',
        inputs: [{ type: 'password', name: 'password' }]
      }]
    });
    if (!externalResult.findings.some(f => f.id === 'FORM_EXTERNAL_ACTION')) {
      throw new Error('External third-party domain should trigger FORM_EXTERNAL_ACTION');
    }
  });

  await assertAsync('EnterprisePolicyEngine: O(L) DomainTrie Whitelist & Blacklist Evaluation', () => {
    const policy = new EnterprisePolicyEngine();

    // Whitelist exact and subdomain matches
    const wlExact = policy.evaluate({ url: 'https://google.com/search' });
    if (!wlExact.isOverridden || wlExact.riskScore !== 0) throw new Error('google.com should match whitelist');

    const wlSub = policy.evaluate({ url: 'https://accounts.google.com/ServiceLogin' });
    if (!wlSub.isOverridden || wlSub.riskScore !== 0) throw new Error('accounts.google.com should match whitelist');

    // Dynamic addition to blacklist
    policy.addToBlacklist('phishing-malware-test.org');
    const blSub = policy.evaluate({ url: 'https://login.secure.phishing-malware-test.org/auth' });
    if (!blSub.isOverridden || blSub.riskScore !== 100) throw new Error('Blocked subdomain should return score 100');

    // Unrelated domain
    const neutral = policy.evaluate({ url: 'https://random-neutral-website.org' });
    if (neutral.isOverridden) throw new Error('Unrelated domain should not be overridden');
  });

  console.log(`\n========================================`);
  console.log(`📊 Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  return failed === 0;
}

if (typeof process !== 'undefined' && process.env?.NODE_ENV === 'test') {
  runAllTests();
}
