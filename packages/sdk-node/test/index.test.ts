import { describe, expect, it } from 'vitest';
import { EthioShield } from '../src/index.js';

describe('EthioShield', () => {
  it('evaluates a request using the configured default policy decision', () => {
    const shield = new EthioShield({
      projectId: 'project_test',
      policy: {
        schemaVersion: '1.0',
        policyVersion: '1.0',
        enforcementMode: 'monitor',
        defaults: {
          action: 'monitor',
          severity: 'low',
          maxRequestBodyBytes: 1024,
        },
        rules: [],
        routeExclusions: [],
        rateLimit: {
          enabled: false,
          windowSeconds: 60,
          maxRequests: 100,
          keyStrategy: 'ip',
        },
      },
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      eventId: () => 'event-1',
    });

    expect(shield.evaluate({ method: 'GET', path: '/health' })).toEqual({
      decision: {
        action: 'monitor',
        ruleId: 'policy.default',
        category: 'policy',
        severity: 'low',
        policyVersion: '1.0',
        reason: { code: 'policy_default' },
      },
      event: {
        schemaVersion: '1.0',
        eventId: 'event-1',
        projectId: 'local',
        occurredAt: '2026-01-01T00:00:00.000Z',
        request: { method: 'GET', route: '/health' },
        detection: { category: 'policy', ruleId: 'policy.default' },
        decision: {
          action: 'monitor',
          ruleId: 'policy.default',
          category: 'policy',
          severity: 'low',
          policyVersion: '1.0',
          reason: { code: 'policy_default' },
        },
        sdkVersion: '0.1.0-alpha.0',
      },
    });
  });
});
