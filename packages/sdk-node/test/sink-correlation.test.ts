import { describe, expect, it } from 'vitest';
import { correlateSinkObservation, DetectionEngine, InstrumentationHub } from '../src/index.js';

describe('sink observation correlation', () => {
  it('keeps request indicators distinct when no matching sink is observed', () => {
    const detection = new DetectionEngine().inspect({
      method: 'GET',
      route: '/search',
      query: { q: 'UNION SELECT id FROM users' },
      correlationId: 'request-1',
    });

    const result = correlateSinkObservation(detection, {
      correlationId: 'request-1',
      operation: 'read',
      parameterized: true,
    });

    expect(result.status).toBe('correlated');
  });

  it('requires the same correlation ID at the host integration boundary', () => {
    const detection = new DetectionEngine().inspect({
      method: 'GET',
      route: '/search',
      query: { q: 'UNION SELECT id FROM users' },
      correlationId: 'request-1',
    });

    const result = correlateSinkObservation(detection, {
      correlationId: 'other-request',
      operation: 'read',
      parameterized: true,
    });

    expect(result.findings[0]?.correlationId).toBe('other-request');
    expect(result.status).toBe('request_only');
  });

  it('does not expose raw query, body, or command arguments', async () => {
    const hub = new InstrumentationHub({
      observers: { sql: () => undefined },
    });
    const observerResult = await hub.notifySql({
      correlationId: 'request-1',
      operation: 'select',
      parameterized: true,
      queryFingerprint: 'fingerprint-only',
    });
    const detection = new DetectionEngine().inspect({
      method: 'GET',
      route: '/search',
      query: { q: 'UNION SELECT id FROM users' },
      correlationId: 'request-1',
    });

    const result = correlateSinkObservation(
      detection,
      {
        correlationId: 'request-1',
        operation: 'select',
        parameterized: true,
        queryFingerprint: 'fingerprint-only',
      },
      observerResult,
    );

    expect(result).not.toHaveProperty('query');
    expect(result.findings[0]).not.toHaveProperty('raw');
    expect(result.status).toBe('correlated');
  });

  it('keeps unrelated request findings as request-only indicators', () => {
    const detection = new DetectionEngine().inspect({
      method: 'GET',
      route: '/files',
      query: { path: '../etc/passwd' },
      correlationId: 'request-1',
    });

    const result = correlateSinkObservation(detection, {
      correlationId: 'request-1',
      operation: 'select',
      parameterized: true,
    });

    expect(result.status).toBe('request_only');
    expect(result.findings[0]).toMatchObject({
      status: 'request_indicator',
      confidence: 'request_only',
    });
  });

  it('does not upgrade a finding when the observer failed', async () => {
    const detection = new DetectionEngine().inspect({
      method: 'GET',
      route: '/search',
      query: { q: 'UNION SELECT id FROM users' },
      correlationId: 'request-1',
    });
    const observerResult = await new InstrumentationHub({
      observers: {
        sql: () => {
          throw new Error('sink unavailable');
        },
      },
    }).notifySql({
      correlationId: 'request-1',
      operation: 'select',
      parameterized: true,
    });

    const result = correlateSinkObservation(
      detection,
      { correlationId: 'request-1', operation: 'select', parameterized: true },
      observerResult,
    );

    expect(result.status).toBe('request_only');
    expect(result.findings[0]?.status).toBe('request_indicator');
  });
});
