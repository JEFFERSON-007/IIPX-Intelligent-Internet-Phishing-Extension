/**
 * Detection Scheduler & Orchestrator
 * Prioritizes plugin execution in tiers (Level 0 to Level 4) to support Smart Early Exits.
 * @module DetectionScheduler
 */

import { PluginRegistry } from '../../plugins/PluginRegistry.js';
import { RiskFusionEngine } from '../fusion/RiskFusionEngine.js';
import { ExplainableAIEngine } from '../explainable/ExplainableAIEngine.js';
import { EnterprisePolicyEngine } from '../policy/EnterprisePolicyEngine.js';
import { MLAdapter } from '../../adapters/ml/MLAdapter.js';

export class DetectionScheduler {
  constructor(
    pluginRegistry = new PluginRegistry(),
    policyEngine = new EnterprisePolicyEngine(),
    fusionEngine = new RiskFusionEngine(),
    explainableEngine = new ExplainableAIEngine()
  ) {
    this.registry = pluginRegistry;
    this.policyEngine = policyEngine;
    this.fusionEngine = fusionEngine;
    this.explainableEngine = explainableEngine;
    this.mlAdapter = new MLAdapter();
  }

  /**
   * Helper to yield execution back to the Service Worker event loop.
   */
  _yieldEventLoop() {
    return new Promise(resolve => setTimeout(resolve, 0));
  }

  /**
   * Orchestrates tiered detection with Smart Early Exit.
   * @param {Record<string, *>} context Target payload
   */
  async analyze(context) {
    const totalStartTime = performance.now();

    // 1. Policy check (Whitelist/Blacklist)
    const policyResult = this.policyEngine.evaluate(context);
    if (policyResult.isOverridden) {
      return this._formatResult(policyResult.riskScore, 1.0, policyResult.classification, [policyResult.reason], [], policyResult.recommendation, totalStartTime, {});
    }

    // 2. Obtain all supported detectors
    const detectors = this.registry.getSortedDetectors(context);
    const detectorResults = [];
    const detectorTimings = {};

    // Organize into tiers (Level 0: cheap URL, Level 1: DOM, Level 2: Behavioral)
    // Assume detectors define a tier() or priority() where higher priority = lower tier index.
    const tiers = [[], [], []];
    for (const d of detectors) {
      if (typeof d.tier === 'function') {
        const t = d.tier();
        if (!tiers[t]) tiers[t] = [];
        tiers[t].push(d);
      } else {
        const p = d.priority();
        if (p >= 950) tiers[0].push(d);       // Tier 0: Fast URL & Reputation checks
        else if (p >= 800) tiers[1].push(d);  // Tier 1: DOM, Form, Cert, Brand checks
        else tiers[2].push(d);                // Tier 2: Behavior, Network, Intelligence checks
      }
    }

    // 3. Execute Tiers sequentially, with parallel execution within the tier
    for (let tierIndex = 0; tierIndex < tiers.length; tierIndex++) {
      const tierDetectors = tiers[tierIndex];
      if (tierDetectors.length === 0) continue;

      const promises = tierDetectors.map(async (detector) => {
        const dStart = performance.now();
        let timerId;
        try {
          // Timeout execution per detector
          const timeoutMs = tierIndex === 0 ? 500 : 2000;
          const timeoutPromise = new Promise((_, reject) => {
            timerId = setTimeout(() => reject(new Error(`Timeout ${timeoutMs}ms`)), timeoutMs);
          });
          
          const res = await Promise.race([detector.analyze(context), timeoutPromise]);
          detectorTimings[detector.name()] = parseFloat((performance.now() - dStart).toFixed(2));
          return { name: detector.name(), result: res };
        } catch (err) {
          console.warn(`Detector ${detector.name()} failed or timed out:`, err);
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

      // Evaluate Smart Early Exit condition
      const intermediateFusion = this.fusionEngine.fuse(detectorResults, null);
      if (intermediateFusion.classification === 'CRITICAL') {
        // Early Exit: Definitive Phish
        const explanation = this.explainableEngine.generateExplanation(detectorResults, intermediateFusion);
        return this._formatResult(intermediateFusion.riskScore, intermediateFusion.confidence, intermediateFusion.classification, explanation.reasons, intermediateFusion.detectorsTriggered, explanation.recommendation, totalStartTime, detectorTimings);
      }

      if (tierIndex === 0 && intermediateFusion.riskScore === 0) {
        // If Level 0 (URL parsing & strict checks) found absolute 0 risk, we don't need heavy DOM checking.
        // We can just exit as SAFE.
        // Wait, some DOM checks are necessary if the URL is somewhat unknown, but if it's explicitly safe...
        // Let's rely on PolicyEngine for explicit safe, and allow tier 1/2 if URL is unknown but not malicious yet.
      }

      await this._yieldEventLoop();
    }

    // 4. Extensible ML Slot (executed last, only if necessary)
    let mlPrediction = null;
    const finalIntermediate = this.fusionEngine.fuse(detectorResults, null);
    if (finalIntermediate.riskScore > 20 && finalIntermediate.riskScore < 80) {
       // Only run ML if it's in the "grey zone" to save power
       try {
         mlPrediction = await this.mlAdapter.predict(context);
       } catch (e) {
         // ML not available
       }
    }

    // 5. Final Risk Fusion Processing
    const fusedScore = this.fusionEngine.fuse(detectorResults, mlPrediction);
    const explanation = this.explainableEngine.generateExplanation(detectorResults, fusedScore);
    
    // Memory Monitoring Check
    this._monitorMemory();

    return this._formatResult(fusedScore.riskScore, fusedScore.confidence, fusedScore.classification, explanation.reasons, fusedScore.detectorsTriggered, explanation.recommendation, totalStartTime, detectorTimings);
  }

  _formatResult(riskScore, confidence, classification, reasons, detectorsTriggered, recommendation, totalStartTime, detectorTimings) {
    return {
      riskScore,
      confidence,
      classification,
      reasons,
      detectorsTriggered,
      recommendation,
      performanceMetrics: {
        totalExecutionTime: parseFloat((performance.now() - totalStartTime).toFixed(2)),
        detectorTimings
      }
    };
  }

  /**
   * Monitors V8 memory usage and triggers emergency cleanup if limits are exceeded.
   * Protects extension from being killed by the browser OOM killer.
   */
  _monitorMemory() {
    if (typeof performance !== 'undefined' && performance.memory) {
      const usedHeapMB = performance.memory.usedJSHeapSize / (1024 * 1024);
      if (usedHeapMB > 150) { // 150MB threshold
        console.warn(`[IPX Memory Monitor] High memory usage detected: ${usedHeapMB.toFixed(2)} MB. Triggering cleanup.`);
        this._forceCleanup();
      }
    }
  }

  /**
   * Force calls cleanup() on all registered plugins/detectors.
   */
  _forceCleanup() {
    try {
      const detectors = this.registry.getSortedDetectors();
      for (const d of detectors) {
        if (typeof d.cleanup === 'function') {
          try { d.cleanup(); } catch (e) { /* ignore */ }
        }
      }
    } catch (err) {
      console.error('[IPX Memory Monitor] Failed during forced cleanup:', err);
    }
  }
}
