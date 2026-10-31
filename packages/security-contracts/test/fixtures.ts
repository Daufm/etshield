import type { SecurityEvent, SecurityPolicy } from '../src/index.js';

export const representativePolicy: SecurityPolicy = {
  schemaVersion: '1.0',
  policyVersion: '1.0',
  enforcementMode: 'enforce',
  defaults: {
    action: 'monitor',
    severity: 'low',
    maxRequestBodyBytes: 1_048_576,
  },
  rules: [
    {
      ruleId: 'rate-limit.default',
      category: 'rate_limit',
      enabled: true,
      action: 'block',
      severity: 'high',
      confidenceThreshold: 0.8,
    },
  ],
  routeExclusions: [{ route: '/health', methods: ['GET'] }],
  rateLimit: {
    enabled: true,
    windowSeconds: 60,
    maxRequests: 100,
    keyStrategy: 'ip',
  },
};

export const representativeEvent: SecurityEvent = {
  schemaVersion: '1.0',
  eventId: 'evt_01',
  projectId: 'proj_01',
  occurredAt: '2026-10-31T05:00:00.000Z',
  request: {
    method: 'GET',
    route: '/api/orders/:id',
  },
  detection: {
    category: 'rate_limit',
    ruleId: 'rate-limit.default',
  },
  decision: {
    action: 'monitor',
    ruleId: 'rate-limit.default',
    category: 'rate_limit',
    confidence: 0.91,
    severity: 'medium',
    policyVersion: '1.0',
    reason: {
      code: 'threshold_near',
      message: 'Request rate is near the configured threshold.',
      attributes: { remaining: 2 },
    },
  },
  client: {
    ip: '192.0.2.10',
    userAgent: 'example-client/1.0',
    fingerprint: 'untrusted:client-value',
  },
  sdkVersion: '0.1.0-alpha.0',
};
