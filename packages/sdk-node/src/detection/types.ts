import type { RuleCategory, SecuritySeverity } from '@ethioshield/security-contracts';

export const MAX_INPUT_STRING_LENGTH = 16_384;
export const MAX_INPUT_NODES = 1_000;
export const MAX_INPUT_DEPTH = 8;
export const MAX_FINDINGS = 50;

export interface DetectionRequest {
  readonly method: string;
  readonly route: string;
  readonly query?: unknown;
  readonly routeParams?: unknown;
  readonly body?: unknown;
}

export type InspectedComponent = 'route' | 'query' | 'routeParams' | 'body';

export interface NormalizedValue {
  readonly component: InspectedComponent;
  readonly path: string;
  readonly value: string;
  readonly malformedEncoding: boolean;
}

export interface NormalizationResult {
  readonly values: readonly NormalizedValue[];
  readonly truncated: boolean;
  readonly malformedEncoding: boolean;
  readonly limitsExceeded: boolean;
}

export interface DetectionFinding {
  readonly ruleId: string;
  readonly category: RuleCategory;
  readonly severity: SecuritySeverity;
  readonly confidence: number;
  readonly component: InspectedComponent;
  readonly path: string;
  readonly reasonCode: string;
}

export interface DetectorContext {
  readonly values: readonly NormalizedValue[];
}

export interface Detector {
  readonly ruleId: string;
  detect(context: DetectorContext): readonly DetectionFinding[];
}

export interface DetectionError {
  readonly code: 'normalization_limit' | 'malformed_encoding' | 'detector_error';
  readonly message: string;
}

export interface DetectionResult {
  readonly status: 'complete' | 'error';
  readonly findings: readonly DetectionFinding[];
  readonly errors: readonly DetectionError[];
  readonly normalization: NormalizationResult;
}
