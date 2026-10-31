import { describe, expect, it } from 'vitest';
import {
  DetectionEngine,
  headersParser,
  jsonParser,
  queryParser,
  routeParamsParser,
} from '../src/index.js';

describe('parser adapters', () => {
  it('preserves duplicate query parameters instead of collapsing them', () => {
    const parsed = queryParser.parse({ tag: ['one', 'two'] });

    expect(parsed.errors).toEqual([]);
    expect(parsed.value).toEqual({ tag: ['one', 'two'] });
  });

  it('keeps route parameters separate from query parameters', () => {
    const result = new DetectionEngine().inspect({
      method: 'GET',
      route: '/users/:id',
      query: { id: 'query-value' },
      routeParams: { id: '../etc/passwd' },
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        ruleId: 'input.path_traversal_indicator',
        component: 'routeParams',
        path: '$.id',
      }),
    ]);
  });

  it('does not parse JSON text implicitly but supports bounded explicit parsing', () => {
    expect(jsonParser.parse('{"search":"UNION SELECT"}').value).toBe('{"search":"UNION SELECT"}');
    expect(jsonParser.parseText('{"search":"UNION SELECT"}').value).toEqual({
      search: 'UNION SELECT',
    });
    expect(jsonParser.parseText('{malformed')).toEqual({
      errors: [
        {
          code: 'malformed_json',
          message: 'JSON input could not be parsed.',
        },
      ],
    });
  });

  it('only exposes bounded, non-sensitive headers to the detection context', () => {
    const result = new DetectionEngine([
      {
        id: 'test.headers',
        version: '1.0',
        categories: ['input'],
        inspect: (context) => [
          {
            ruleId: 'test.headers',
            category: 'input',
            severity: 'low',
            confidence: 0.1,
            component: 'route',
            path: '$route',
            reasonCode: Object.keys(context.headers).join(','),
          },
        ],
      },
    ]).inspect({
      method: 'GET',
      route: '/health',
      headers: {
        'user-agent': 'client',
        authorization: 'secret',
        'x-forwarded-for': '203.0.113.1',
        'accept-language': 'en',
      },
    });

    expect(result.findings[0]?.reasonCode).toBe('user-agent,accept-language');
    expect(result.normalization.headers).toEqual({
      'user-agent': 'client',
      'accept-language': 'en',
    });
  });

  it('detects cyclic structures as a bounded normalization error', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;

    const result = new DetectionEngine().inspect({
      method: 'POST',
      route: '/data',
      body: cyclic,
    });

    expect(result.status).toBe('error');
    expect(result.errors.some((error) => error.code === 'normalization_limit')).toBe(true);
  });

  it('rejects non-record header input at the adapter boundary', () => {
    expect(headersParser.parse('authorization: secret')).toEqual({
      errors: [
        {
          code: 'invalid_input',
          message: 'Headers must be a record.',
        },
      ],
    });
  });

  it('propagates parser boundary errors into the engine result', () => {
    const result = new DetectionEngine().inspect({
      method: 'GET',
      route: '/health',
      headers: 'authorization: secret',
    });

    expect(result.status).toBe('error');
    expect(result.errors).toContainEqual({
      code: 'parser_error',
      message: 'Headers must be a record.',
    });
  });

  it('keeps route parameter parser input unchanged', () => {
    const params = Object.freeze({ id: '42' });
    const parsed = routeParamsParser.parse(params);

    expect(parsed.value).toBe(params);
    expect(params).toEqual({ id: '42' });
  });
});
