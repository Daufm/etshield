import type { DetectionFinding, DetectorContext, InspectedComponent } from './types.js';

export function findMatches(
  context: DetectorContext,
  component: InspectedComponent,
  pattern: RegExp,
  ruleId: string,
  category: DetectionFinding['category'],
  severity: DetectionFinding['severity'],
  confidence: number,
  reasonCode: string,
): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  for (const value of context.values) {
    if (value.component !== component || !pattern.test(value.value)) continue;
    findings.push({
      ruleId,
      category,
      severity,
      confidence,
      confidenceBand: confidence >= 0.85 ? 'high' : confidence >= 0.6 ? 'medium' : 'low',
      component: value.component,
      path: value.path,
      reasonCode,
      evidenceId: `${ruleId}:${value.component}:${value.path}:${reasonCode}`,
    });
  }
  return findings;
}

export function findMatchesAcrossComponents(
  context: DetectorContext,
  pattern: RegExp,
  ruleId: string,
  category: DetectionFinding['category'],
  severity: DetectionFinding['severity'],
  confidence: number,
  reasonCode: string,
): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  for (const value of context.values) {
    if (!pattern.test(value.value)) continue;
    findings.push({
      ruleId,
      category,
      severity,
      confidence,
      confidenceBand: confidence >= 0.85 ? 'high' : confidence >= 0.6 ? 'medium' : 'low',
      component: value.component,
      path: value.path,
      reasonCode,
      evidenceId: `${ruleId}:${value.component}:${value.path}:${reasonCode}`,
    });
  }
  return findings;
}
