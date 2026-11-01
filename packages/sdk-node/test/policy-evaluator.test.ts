import { describe, expect, it } from 'vitest';
import type { SecurityPolicy } from '@ethioshield/security-contracts';
import { evaluateDetection } from '../src/index.js';
import type { DetectionResult } from '../src/detection/types.js';

const policy: SecurityPolicy = {
  schemaVersion: '1.0',
  policyVersion: '1.0',
  enforcementMode: 'enforce',
  defaults: {
    action: 'monitor',
    severity: 'medium',
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
};

function detection(
  status: DetectionResult['status'],
  findings: DetectionResult['findings'] = [],
): DetectionResult {
  return {
    status,
    outcome: status === 'complete' ? (findings.length > 0 ? 'indicator' : 'clean') : 'failed',
    degradedCodes: [],
    findings,
    errors: [],
    normalization: {
      values: [],
      truncated: false,
      malformedEncoding: false,
      ambiguous: false,
      limitsExceeded: false,
      headers: {},
      parserErrors: [],
    },
    budget: {
      cooperative: true,
      elapsedMs: 0,
      limitMs: 25,
      exceeded: false,
    },
  };
}

const finding = {
  ruleId: 'input.xss_indicator',
  category: 'input' as const,
  severity: 'high' as const,
  confidence: 0.8,
  confidenceBand: 'medium' as const,
  component: 'query' as const,
  path: '$.q',
  reasonCode: 'javascript_scheme',
};

describe('evaluateDetection', () => {
  it('uses configured enabled rule actions and confidence thresholds', () => {
    const result = evaluateDetection(
      {
        ...policy,
        rules: [
          {
            ruleId: finding.ruleId,
            category: 'input',
            enabled: true,
            action: 'block',
            confidenceThreshold: 0.75,
          },
        ],
      },
      detection('complete', [finding]),
    );

    expect(result).toMatchObject({
      action: 'block',
      ruleId: finding.ruleId,
      reasonCode: 'indicator_detected',
      finding,
    });
  });

  it('does not enforce disabled or below-threshold rules', () => {
    const disabled = evaluateDetection(
      {
        ...policy,
        rules: [
          {
            ruleId: finding.ruleId,
            category: 'input',
            enabled: false,
            action: 'block',
          },
        ],
      },
      detection('complete', [finding]),
    );
    const belowThreshold = evaluateDetection(
      {
        ...policy,
        rules: [
          {
            ruleId: finding.ruleId,
            category: 'input',
            enabled: true,
            action: 'block',
            confidenceThreshold: 0.9,
          },
        ],
      },
      detection('complete', [finding]),
    );

    expect(disabled.action).toBe('allow');
    expect(belowThreshold.action).toBe('allow');
  });

  it('downgrades enforcing actions in policy monitor mode', () => {
    const result = evaluateDetection(
      {
        ...policy,
        enforcementMode: 'monitor',
        rules: [
          {
            ruleId: finding.ruleId,
            category: 'input',
            enabled: true,
            action: 'challenge',
          },
        ],
      },
      detection('complete', [finding]),
    );

    expect(result.action).toBe('monitor');
    expect(result.reasonCode).toBe('indicator_monitored_by_policy');
  });

  it('returns a fail-safe action for inspection errors', () => {
    expect(evaluateDetection(policy, detection('error')).action).toBe('block');
    expect(
      evaluateDetection(policy, detection('error'), { enforcementMode: 'monitor' }).action,
    ).toBe('monitor');
  });

  it('returns a fail-safe action for inconclusive inspections', () => {
    expect(evaluateDetection(policy, detection('inconclusive')).action).toBe('block');
    expect(
      evaluateDetection(policy, detection('inconclusive'), { enforcementMode: 'monitor' }).action,
    ).toBe('monitor');
  });

  it('supports challenge as a policy action without invoking a host adapter', () => {
    const result = evaluateDetection(
      {
        ...policy,
        rules: [
          {
            ruleId: finding.ruleId,
            category: 'input',
            enabled: true,
            action: 'challenge',
          },
        ],
      },
      detection('complete', [finding]),
    );

    expect(result.action).toBe('challenge');
  });
});
