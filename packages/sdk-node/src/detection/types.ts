import type {
  DetectionBudget,
  DetectionBudgetOutcome,
  DetectionComponent,
  DetectionInspectionErrorCode,
  DetectionInspectionStatus,
  DetectionReference,
  RuleCategory,
  SecuritySeverity,
} from '@ethioshield/security-contracts';
import type { SanitizedHeaders } from './parsers/headers.js';
import type { ParserError } from './parsers/types.js';
export type { DetectionBudgetOutcome } from '@ethioshield/security-contracts';
export type DetectionOutcome = 'clean' | 'indicator' | 'degraded' | 'failed';

export const MAX_INPUT_STRING_LENGTH = 16_384;
export const MAX_INPUT_NODES = 1_000;
export const MAX_INPUT_DEPTH = 8;
export const MAX_FINDINGS = 50;
export const DEFAULT_DETECTION_BUDGET: DetectionBudget = {
  maxInputBytes: 1_048_576,
  maxNodes: MAX_INPUT_NODES,
  maxDepth: MAX_INPUT_DEPTH,
  maxValues: 1_000,
  maxFindings: MAX_FINDINGS,
  maxDurationMs: 25,
};

export interface DetectionRequest {
  readonly method: string;
  readonly route: string;
  readonly query?: unknown;
  readonly routeParams?: unknown;
  readonly body?: unknown;
  readonly headers?: unknown;
  readonly correlationId?: string;
  readonly bodyState?: BodyInspectionState;
}

export type BodyInspectionState = 'absent' | 'parsed' | 'malformed' | 'unavailable' | 'streaming';

export interface DetectionContext {
  readonly contractVersion: '1.0';
  readonly request: DetectionRequest;
  readonly values: readonly NormalizedValue[];
  readonly budget: DetectionBudget;
  readonly headers: SanitizedHeaders;
  readonly correlationId?: string;
}

export type InspectedComponent = DetectionComponent;

export interface NormalizedValue {
  readonly component: InspectedComponent;
  readonly path: string;
  readonly raw: string;
  readonly value: string;
  readonly malformedEncoding: boolean;
  readonly decodeDepth: number;
  readonly transformations: readonly NormalizationTransformation[];
  readonly parserId: string;
  readonly parserVersion: string;
  readonly duplicateStatus: 'none' | 'present' | 'unknown';
  readonly truncated: boolean;
  readonly ambiguous: boolean;
}

export type NormalizationTransformation = 'percent_decode' | 'unicode_nfkc' | 'case_fold';

export interface NormalizationResult {
  readonly values: readonly NormalizedValue[];
  readonly truncated: boolean;
  readonly malformedEncoding: boolean;
  readonly ambiguous: boolean;
  readonly limitsExceeded: boolean;
  readonly headers: SanitizedHeaders;
  readonly parserErrors: readonly ParserError[];
}

export interface DetectionFinding {
  readonly ruleId: string;
  readonly category: RuleCategory;
  readonly severity: SecuritySeverity;
  readonly confidence: number;
  readonly confidenceBand?: 'low' | 'medium' | 'high';
  readonly component: InspectedComponent;
  readonly path: string;
  readonly reasonCode: string;
  readonly evidenceId?: string;
  readonly references?: readonly DetectionReference[];
  readonly provenance?: NormalizedValueProvenance;
}

export type NormalizedValueProvenance = Pick<
  NormalizedValue,
  | 'decodeDepth'
  | 'transformations'
  | 'parserId'
  | 'parserVersion'
  | 'duplicateStatus'
  | 'truncated'
  | 'ambiguous'
>;

export interface DetectorContext {
  readonly values: readonly NormalizedValue[];
  readonly request?: DetectionRequest;
  readonly budget?: DetectionBudget;
}

export interface Detector {
  readonly ruleId: string;
  detect(context: DetectorContext): readonly DetectionFinding[];
}

export interface DetectionPlugin {
  readonly id: string;
  readonly version: string;
  readonly categories: readonly RuleCategory[];
  inspect(context: DetectionContext): readonly DetectionFinding[];
}

export interface DetectionError {
  readonly code: DetectionInspectionErrorCode;
  readonly message: string;
}

export interface DetectionResult {
  readonly status: DetectionInspectionStatus;
  readonly outcome: DetectionOutcome;
  readonly degradedCodes: readonly string[];
  readonly findings: readonly DetectionFinding[];
  readonly errors: readonly DetectionError[];
  readonly normalization: NormalizationResult;
  readonly budget: DetectionBudgetOutcome;
  readonly correlationId?: string;
}
