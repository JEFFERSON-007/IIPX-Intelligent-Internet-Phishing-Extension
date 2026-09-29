/**
 * Integration Test Suite: Full Detection Pipeline
 * @module detection-pipeline.test
 */

import { PluginRegistry } from '../../plugins/PluginRegistry.js';
import { DetectionEngine } from '../../core/engine/DetectionEngine.js';
import { RiskFusionEngine } from '../../core/fusion/RiskFusionEngine.js';
import { ExplainableAIEngine } from '../../core/explainable/ExplainableAIEngine.js';
import { EnterprisePolicyEngine } from '../../core/policy/EnterprisePolicyEngine.js';
import { URLDetector } from '../../detectors/url/URLDetector.js';
import { FormDetector } from '../../detectors/form/FormDetector.js';

export async function testDetectionPipeline() {
  const registry = new PluginRegistry();
  registry.register(new URLDetector());
  registry.register(new FormDetector());

  const engine = new DetectionEngine(
    registry,
    new EnterprisePolicyEngine(),
    new RiskFusionEngine(),
    new ExplainableAIEngine()
  );

  const context = {
    url: 'http://192.168.1.1/login',
    forms: [
      { action: 'http://external-hacker.com/steal', method: 'post', inputs: [{ type: 'password', name: 'pass' }] }
    ]
  };

  const result = await engine.analyze(context);

  function assert(condition, message) {
    if (!condition) throw new Error(message);
  }

  assert(result.riskScore >= 60, `Pipeline Test Failed: Expected score >= 60, got ${result.riskScore}`);
  assert(result.classification === 'HIGH' || result.classification === 'CRITICAL', `Pipeline Test Failed: Expected HIGH or CRITICAL, got ${result.classification}`);
  assert(result.reasons.length > 0, 'Pipeline Test Failed: Expected explanation reasons');

  return true;
}

if (typeof process !== 'undefined' && process.env?.NODE_ENV === 'test') {
  testDetectionPipeline().then(() => console.log('✅ Detection Pipeline Integration Tests Passed.'));
}
