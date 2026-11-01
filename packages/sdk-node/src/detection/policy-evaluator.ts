import type { RuleSetting, SecurityAction, SecurityPolicy } from '@ethioshield/security-contracts';
import type { DetectionFinding, DetectionResult } from './types.js';

export interface PolicyEvaluation {
  readonly action: SecurityAction;
  readonly ruleId: string;
  readonly category: DetectionFinding['category'];
  readonly reasonCode: string;
  readonly degradedCodes?: readonly string[];
  readonly finding?: DetectionFinding;
}

function isEnforcingAction(action: SecurityAction): boolean {
  return action === 'block' || action === 'throttle' || action === 'challenge';
}

function applyEnforcementMode(action: SecurityAction, mode: SecurityPolicy['enforcementMode']) {
  return mode === 'monitor' && isEnforcingAction(action) ? 'monitor' : action;
}

function matchingRule(
  finding: DetectionFinding,
  rules: readonly RuleSetting[],
): RuleSetting | undefined {
  const rule = rules.find((candidate) => candidate.ruleId === finding.ruleId);
  if (rule?.enabled === false) return undefined;
  if (rule?.confidenceThreshold !== undefined && finding.confidence < rule.confidenceThreshold) {
    return undefined;
  }
  return rule;
}

export function evaluateDetection(
  policy: SecurityPolicy,
  detection: DetectionResult,
  options?: {
    readonly enforcementMode?: SecurityPolicy['enforcementMode'];
    readonly fallbackAction?: SecurityAction;
    readonly inspection?: {
      readonly degradedAction?: Extract<SecurityAction, 'monitor' | 'block'>;
    };
  },
): PolicyEvaluation {
  const enforcementMode = options?.enforcementMode ?? policy.enforcementMode;
  for (const finding of detection.findings) {
    const rule = matchingRule(finding, policy.rules);
    if (
      rule === undefined &&
      policy.rules.some((candidate) => candidate.ruleId === finding.ruleId)
    ) {
      continue;
    }
    const action = applyEnforcementMode(
      rule?.action ?? options?.fallbackAction ?? policy.defaults.action,
      enforcementMode,
    );
    return {
      action,
      ruleId: finding.ruleId,
      category: finding.category,
      reasonCode:
        action === 'monitor' && rule?.action !== 'monitor'
          ? 'indicator_monitored_by_policy'
          : 'indicator_detected',
      finding,
    };
  }

  if (
    detection.findings.length === 0 &&
    (detection.outcome === 'failed' ||
      (detection.status !== 'complete' && detection.outcome !== 'degraded'))
  ) {
    const action = applyEnforcementMode(
      options?.fallbackAction ?? (enforcementMode === 'enforce' ? 'block' : 'monitor'),
      enforcementMode,
    );
    return {
      action,
      ruleId: 'inspection.failure',
      category: 'policy',
      reasonCode: 'inspection_failed',
    };
  }

  if (detection.outcome === 'degraded') {
    const bodyUnavailable = detection.degradedCodes.includes('body_unavailable');
    const action = applyEnforcementMode(
      bodyUnavailable && enforcementMode === 'enforce'
        ? 'block'
        : (options?.inspection?.degradedAction ?? 'monitor'),
      enforcementMode,
    );
    return {
      action,
      ruleId: 'inspection.degraded',
      category: 'policy',
      reasonCode: 'inspection_failed',
      degradedCodes: detection.degradedCodes,
    };
  }

  return {
    action: 'allow',
    ruleId: 'policy.allow',
    category: 'policy',
    reasonCode: 'no_indicator_detected',
  };
}
