import { describe, expect, it } from 'vitest';
import { DetectionEngine, evaluateDetection } from '../src/index.js';

describe('operational safety budgets', () => {
  it('keeps bounded inspection work under a repeatable latency budget', () => {
    const engine = new DetectionEngine();
    const request = {
      method: 'POST',
      route: '/bulk',
      query: {
        values: Array.from({ length: 5_000 }, (_, index) => `value-${index}`),
      },
      body: {
        nested: Array.from({ length: 500 }, (_, index) => ({
          value: index % 2 === 0 ? 'safe' : 'UNION SELECT id FROM users',
        })),
      },
    };
    const started = performance.now();
    const result = engine.inspect(request);
    const elapsed = performance.now() - started;

    expect(elapsed).toBeLessThan(500);
    expect(result.normalization.values.length).toBeLessThanOrEqual(1_000);
    expect(result.findings.length).toBeLessThanOrEqual(50);
  });

  it('keeps normalized output bounded across repeated oversized requests', () => {
    const engine = new DetectionEngine();
    const oversized = {
      method: 'POST',
      route: '/bulk',
      body: { values: Array.from({ length: 3_000 }, () => 'x'.repeat(1_000)) },
    };

    for (let index = 0; index < 5; index += 1) {
      const result = engine.inspect(oversized);
      expect(result.normalization.values.length).toBeLessThanOrEqual(1_000);
      expect(result.findings.length).toBeLessThanOrEqual(50);
      expect(result.normalization.truncated || result.normalization.limitsExceeded).toBe(true);
    }
  });

  it('qualifies sustained bounded inspections without accumulating request state', () => {
    const engine = new DetectionEngine();
    const started = performance.now();
    let findings = 0;

    for (let index = 0; index < 100; index += 1) {
      const result = engine.inspect({
        method: 'POST',
        route: '/search',
        query: {
          request: index % 10 === 0 ? 'UNION SELECT id FROM users' : `search-${index}`,
        },
        body: { page: index, filters: ['safe', 'text'] },
      });
      findings += result.findings.length;
      expect(result.normalization.values.length).toBeLessThanOrEqual(1_000);
      expect(result.findings.length).toBeLessThanOrEqual(50);
    }

    expect(findings).toBeGreaterThan(0);
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  it('qualifies staged monitor-to-enforce rollout without changing detection output', () => {
    const detection = new DetectionEngine().inspect({
      method: 'GET',
      route: '/search',
      query: { q: 'UNION SELECT id FROM users' },
    });
    const policy = {
      schemaVersion: '1.0' as const,
      policyVersion: 'qualification',
      enforcementMode: 'enforce' as const,
      defaults: { action: 'monitor' as const, severity: 'low' as const, maxRequestBodyBytes: 1024 },
      rules: [
        {
          ruleId: 'input.sql_injection_indicator',
          enabled: true,
          action: 'block' as const,
          severity: 'high' as const,
          confidenceThreshold: 0.8,
        },
      ],
      routeExclusions: [],
      rateLimit: {
        enabled: false,
        windowSeconds: 60,
        maxRequests: 100,
        keyStrategy: 'ip' as const,
      },
    };

    const monitor = evaluateDetection(policy, detection, { enforcementMode: 'monitor' });
    const enforce = evaluateDetection(policy, detection, { enforcementMode: 'enforce' });

    expect(detection.findings).toHaveLength(1);
    expect(monitor).toMatchObject({ action: 'monitor', ruleId: 'input.sql_injection_indicator' });
    expect(enforce).toMatchObject({ action: 'block', ruleId: 'input.sql_injection_indicator' });
  });
});
