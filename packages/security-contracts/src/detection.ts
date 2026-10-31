import type { RuleCategory, SecuritySeverity } from './index.js';

export const CURRENT_DETECTION_CONTRACT_VERSION = '1.0' as const;

export type DetectionContractVersion = typeof CURRENT_DETECTION_CONTRACT_VERSION;
export type DetectionComponent = 'route' | 'query' | 'routeParams' | 'body';
export type DetectionConfidence = 'low' | 'medium' | 'high';

export interface DetectionReference {
  readonly source: 'owasp_top_10' | 'owasp_api' | 'cwe' | 'internal';
  readonly id: string;
}

export interface DetectionEvidence {
  readonly evidenceId: string;
  readonly ruleId: string;
  readonly category: RuleCategory;
  readonly severity: SecuritySeverity;
  readonly confidence: DetectionConfidence;
  readonly component: DetectionComponent;
  readonly path: string;
  readonly reasonCode: string;
  readonly references?: readonly DetectionReference[];
}

export interface DetectionBudget {
  readonly maxInputBytes: number;
  readonly maxNodes: number;
  readonly maxDepth: number;
  readonly maxValues: number;
  readonly maxFindings: number;
  readonly maxDurationMs: number;
}
