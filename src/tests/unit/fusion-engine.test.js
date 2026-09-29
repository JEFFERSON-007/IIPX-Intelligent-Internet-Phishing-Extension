/**
 * Risk Fusion Engine Unit Tests
 * @module fusion-engine.test
 */

import { RiskFusionEngine } from '../../core/fusion/RiskFusionEngine.js';

export function testRiskFusionEngine() {
  const fusion = new RiskFusionEngine();

  function assert(condition, message) {
    if (!condition) throw new Error(message);
  }

  // Test 1: Empty input returns SAFE
  const res1 = fusion.fuse([]);
  assert(res1.riskScore === 0, `Test Failed: Empty score expected 0, got ${res1.riskScore}`);
  assert(res1.classification === 'SAFE', `Test Failed: Classification expected SAFE, got ${res1.classification}`);

  // Test 2: High score fusion
  const mockOutputs = [
    { name: 'URLDetector', result: { score: 80, confidence: 1.0, severity: 'CRITICAL', findings: [] } },
    { name: 'FormDetector', result: { score: 40, confidence: 0.9, severity: 'MEDIUM', findings: [] } }
  ];
  const res2 = fusion.fuse(mockOutputs);
  assert(res2.riskScore >= 60, `Test Failed: High risk score expected >= 60, got ${res2.riskScore}`);
  assert(res2.detectorsTriggered.includes('URLDetector'), 'Test Failed: Detector trigger missing');

  return true;
}

if (typeof process !== 'undefined' && process.env?.NODE_ENV === 'test') {
  testRiskFusionEngine();
  console.log('✅ RiskFusionEngine Unit Tests Passed.');
}
