/**
 * Central Detection Engine Orchestrator
 * Coordinates detector plugin execution, performance profiling, error isolation, and calls Risk Fusion & Explainable AI.
 * @module DetectionEngine
 */

import { PluginRegistry } from '../../plugins/PluginRegistry.js';
import { RiskFusionEngine } from '../fusion/RiskFusionEngine.js';
import { ExplainableAIEngine } from '../explainable/ExplainableAIEngine.js';
import { EnterprisePolicyEngine } from '../policy/EnterprisePolicyEngine.js';
import { MLAdapter } from '../../adapters/ml/MLAdapter.js';

export class DetectionEngine {
  /**
   * Create a DetectionEngine instance.
   * @param {PluginRegistry} pluginRegistry 
   * @param {EnterprisePolicyEngine} policyEngine 
   * @param {RiskFusionEngine} fusionEngine 
   * @param {ExplainableAIEngine} explainableEngine 
   */
  constructor(
    pluginRegistry = new PluginRegistry(),
    policyEngine = new EnterprisePolicyEngine(),
    fusionEngine = new RiskFusionEngine(),
    explainableEngine = new ExplainableAIEngine()
  ) {
    /** @type {PluginRegistry} */
    this.registry = pluginRegistry;
    /** @type {EnterprisePolicyEngine} */
    this.policyEngine = policyEngine;
    /** @type {RiskFusionEngine} */
    this.fusionEngine = fusionEngine;
    /** @type {ExplainableAIEngine} */
    this.explainableEngine = explainableEngine;
    /** @type {MLAdapter} Extensible ML Adapter slot */
    this.mlAdapter = new MLAdapter();
  }

  /**
   * Analyze target context payload through all registered detectors.
   * @param {Record<string, *>} context - Target payload (url, dom, forms, behavior).
   * @returns {Promise<Record<string, *>>} Final Security Result
   */
  async analyze(context) {
    const totalStartTime = performance.now();

    // 1. Policy Evaluation Check (Enterprise Whitelist / User Overrides)
    const policyResult = this.policyEngine.evaluate(context);
    if (policyResult.isOverridden) {
      return {
        riskScore: policyResult.riskScore,
        confidence: 1.0,
        classification: policyResult.classification,
        reasons: [policyResult.reason],
        detectorsTriggered: [],
        recommendation: policyResult.recommendation,
        performanceMetrics: { totalExecutionTime: parseFloat((performance.now() - totalStartTime).toFixed(2)) }
      };
    }

    // 2. Obtain sorted enabled detectors
    const detectors = this.registry.getSortedDetectors(context);
    const detectorResults = [];
    const detectorTimings = {};

    // 3. Execute detectors in parallel with fault isolation & timeout protection
    const promises = detectors.map(async (detector) => {
      const dStart = performance.now();
      let timerId;
      try {
        const timeoutPromise = new Promise((_, reject) => {
          timerId = setTimeout(() => reject(new Error(`Detector ${detector.name()} timed out after 2000ms`)), 2000);
        });

        const res = await Promise.race([detector.analyze(context), timeoutPromise]);
        const dDuration = parseFloat((performance.now() - dStart).toFixed(2));
        detectorTimings[detector.name()] = dDuration;
        return { name: detector.name(), result: res };
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`Error executing detector ${detector.name()}:`, err);
        return null;
      } finally {
        if (timerId) clearTimeout(timerId);
      }
    });

    const settled = await Promise.all(promises);
    for (const item of settled) {
      if (item && item.result) {
        detectorResults.push(item);
      }
    }

    // 4. Extensible ML Slot Prediction (Optional plugin)
    let mlPrediction = null;
    try {
      mlPrediction = await this.mlAdapter.predict(context);
    } catch {}

    // 5. Risk Fusion Processing
    const fusedScore = this.fusionEngine.fuse(detectorResults, mlPrediction);

    // 6. Explainable AI Generation
    const explanation = this.explainableEngine.generateExplanation(detectorResults, fusedScore);

    const totalExecutionTime = parseFloat((performance.now() - totalStartTime).toFixed(2));

    return {
      riskScore: fusedScore.riskScore,
      confidence: fusedScore.confidence,
      classification: fusedScore.classification,
      reasons: explanation.reasons,
      detectorsTriggered: fusedScore.detectorsTriggered,
      recommendation: explanation.recommendation,
      performanceMetrics: {
        totalExecutionTime,
        detectorTimings
      }
    };
  }
}
