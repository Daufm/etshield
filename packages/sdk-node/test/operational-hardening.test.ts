import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../src/index.js';

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
});
