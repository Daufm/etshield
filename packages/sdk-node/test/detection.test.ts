import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../src/index.js';
import type { DetectionPlugin, Detector } from '../src/detection/types.js';
import { DEFAULT_DETECTION_BUDGET } from '../src/detection/types.js';

const engine = new DetectionEngine();

describe('DetectionEngine', () => {
  it('inspects only the documented request components and returns structured findings', () => {
    const result = engine.inspect({
      method: 'GET',
      route: '/users/:id',
      query: { search: 'UNION SELECT username FROM users' },
      routeParams: { id: '42' },
      body: { displayName: 'Ada Lovelace' },
    });

    expect(result.status).toBe('complete');
    expect(result.findings).toEqual([
      expect.objectContaining({
        ruleId: 'input.sql_injection_indicator',
        category: 'input',
        component: 'query',
        path: '$.search',
      }),
    ]);
    expect(result.findings[0]).not.toHaveProperty('value');
  });

  it('detects encoded and mixed-case attack indicators without mutating input', () => {
    const request = {
      method: 'POST',
      route: '/files/:name',
      query: { next: '%2e%2e%2fetc%2fpasswd' },
      routeParams: { name: '<ScRiPt>alert(1)</ScRiPt>' },
      body: { filter: { $nE: 'x' } },
    };
    const original = structuredClone(request);
    const result = engine.inspect(request);

    expect(result.findings.map((finding) => finding.ruleId)).toEqual([
      'input.nosql_injection_indicator',
      'input.xss_indicator',
      'input.path_traversal_indicator',
    ]);
    expect(request).toEqual(original);
  });

  it('handles duplicate parameters, nested values, and malformed encodings', () => {
    const result = engine.inspect({
      method: 'GET',
      route: '/search',
      query: {
        tag: ['one', 'two', '%ZZ'],
        nested: { value: 'javascript%3Aalert(1)' },
      },
    });

    expect(result.status).toBe('error');
    expect(result.errors).toEqual([
      {
        code: 'malformed_encoding',
        message: 'One or more request values contained malformed percent encoding.',
      },
    ]);
    expect(result.findings).toEqual([
      expect.objectContaining({ ruleId: 'input.xss_indicator', path: '$.nested.value' }),
    ]);
  });

  it('does not classify ordinary business values as malicious', () => {
    const result = engine.inspect({
      method: 'POST',
      route: '/orders/:id',
      query: { status: 'pending', note: 'Please select a size' },
      routeParams: { id: 'order-42' },
      body: {
        product: 'Union Jack mug',
        description: 'A practical object with a script included in the box.',
        amount: 25,
      },
    });

    expect(result.status).toBe('complete');
    expect(result.findings).toHaveLength(0);
  });

  it('bounds recursive traversal and total work', () => {
    const deeplyNested: Record<string, unknown> = {};
    let cursor = deeplyNested;
    for (let depth = 0; depth < 20; depth += 1) {
      cursor.next = {};
      cursor = cursor.next as Record<string, unknown>;
    }
    const result = engine.inspect({
      method: 'POST',
      route: '/nested',
      body: deeplyNested,
    });

    expect(result.status).toBe('error');
    expect(result.errors.some((error) => error.code === 'normalization_limit')).toBe(true);
  });

  it('bounds large collections and completes within the local safety budget', () => {
    const started = performance.now();
    const result = engine.inspect({
      method: 'POST',
      route: '/bulk',
      body: { values: Array.from({ length: 20_000 }, (_, index) => `value-${index}`) },
    });

    expect(result.status).toBe('error');
    expect(result.normalization.values.length).toBeLessThanOrEqual(1_000);
    expect(result.findings.length).toBeLessThanOrEqual(50);
    expect(performance.now() - started).toBeLessThan(500);
  });

  it('does not silently turn detector failures into a clean result', () => {
    const failingDetector: Detector = {
      ruleId: 'test.detector_failure',
      detect: () => {
        throw new Error('test failure');
      },
    };
    const result = new DetectionEngine([failingDetector]).inspect({
      method: 'GET',
      route: '/health',
    });

    expect(result.status).toBe('error');
    expect(result.errors).toEqual([
      {
        code: 'detector_error',
        message: 'Detector test.detector_failure failed during inspection.',
      },
    ]);
  });

  it('runs versioned detection plugins through the compatibility engine', () => {
    const plugin: DetectionPlugin = {
      id: 'test.plugin',
      version: '1.0',
      categories: ['input'],
      inspect: (context) => [
        {
          ruleId: 'test.plugin',
          category: 'input',
          severity: 'low',
          confidence: 0.5,
          component: context.values[0]?.component ?? 'route',
          path: context.values[0]?.path ?? '$route',
          reasonCode: 'plugin_ran',
        },
      ],
    };

    const result = new DetectionEngine([plugin]).inspect({
      method: 'GET',
      route: '/health',
    });

    expect(result.status).toBe('complete');
    expect(result.findings[0]).toMatchObject({
      ruleId: 'test.plugin',
      reasonCode: 'plugin_ran',
    });
  });

  it('rejects invalid plugin findings without treating them as detections', () => {
    const result = new DetectionEngine([
      {
        id: 'test.invalid',
        version: '1.0',
        categories: ['input'],
        inspect: () => [
          {
            ruleId: 'test.invalid',
            category: 'input',
            severity: 'high',
            confidence: 2,
            component: 'query',
            path: '$.value',
            reasonCode: 'invalid_confidence',
          },
        ],
      },
    ]).inspect({
      method: 'GET',
      route: '/invalid',
      query: { value: 'test' },
    });

    expect(result.status).toBe('error');
    expect(result.findings).toEqual([]);
    expect(result.errors).toContainEqual({
      code: 'invalid_finding',
      message: 'Detector test.invalid returned an invalid finding.',
    });
  });

  it('reports cooperative budget exhaustion as inconclusive', () => {
    let now = 0;
    const result = new DetectionEngine(
      [
        {
          id: 'test.budget',
          version: '1.0',
          categories: ['input'],
          inspect: () => [],
        },
      ],
      {
        budget: { ...DEFAULT_DETECTION_BUDGET, maxDurationMs: 5 },
        now: () => {
          now += 10;
          return now;
        },
      },
    ).inspect({ method: 'GET', route: '/budget' });

    expect(result.status).toBe('inconclusive');
    expect(result.budget).toMatchObject({
      cooperative: true,
      limitMs: 5,
      exceeded: true,
    });
    expect(result.errors).toContainEqual({
      code: 'budget_exceeded',
      message: 'Cooperative inspection time budget was exceeded.',
    });
  });

  it('returns structured confidence bands and deduplicates equivalent evidence', () => {
    const result = engine.inspect({
      method: 'POST',
      route: '/search',
      body: { filter: { $ne: 'x' } },
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      ruleId: 'input.nosql_injection_indicator',
      confidenceBand: 'high',
      evidenceId: expect.stringContaining('input.nosql_injection_indicator'),
    });
  });

  it('uses structured parsing to avoid broad detector false positives', () => {
    const result = engine.inspect({
      method: 'POST',
      route: '/content',
      body: {
        description: 'Use the union jack design and select a size.',
        html: '<strong>Safe</strong>',
        file: 'windowsill.txt',
      },
    });

    expect(result.findings).toHaveLength(0);
  });

  it('recognizes token, scheme, and path-segment indicators', () => {
    const result = engine.inspect({
      method: 'POST',
      route: '/upload',
      query: {
        sql: 'UN/**/ION SELECT id FROM users',
        script: 'java%73cript:alert(1)',
        path: '..%2f..%2fetc%2fpasswd',
      },
    });

    expect(result.findings.map((finding) => finding.ruleId)).toEqual([
      'input.sql_injection_indicator',
      'input.xss_indicator',
      'input.path_traversal_indicator',
    ]);
  });

  it('uses bounded structured adapters for variants without decoding context-specific syntax', () => {
    const result = engine.inspect({
      method: 'POST',
      route: '/submit',
      query: {
        sql: 'UN/**/ION SELECT id FROM users WHERE name="Ada"',
        markup: '<IMG OnError = "alert(1)">',
        path: '..\\..\\Windows\\system32',
      },
      body: { filter: { $where: 'this.value > 1' } },
    });

    expect(result.findings.map((finding) => finding.reasonCode)).toEqual([
      'sql_keyword_sequence',
      'nosql_script_operator',
      'executable_markup_attribute',
      'parent_path_segment',
    ]);
  });
});
