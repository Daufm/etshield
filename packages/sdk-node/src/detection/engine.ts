import type {
  DetectionFinding,
  DetectionError,
  DetectionPlugin,
  Detector,
  DetectionRequest,
  DetectionResult,
  NormalizedValue,
} from './types.js';
import { DEFAULT_DETECTION_BUDGET } from './types.js';
import { normalizeRequest } from './normalization/v1.js';
import { nosqlInjectionDetector } from './nosql-injection.js';
import { pathTraversalDetector } from './path-traversal.js';
import { sqlInjectionDetector } from './sql-injection.js';
import { xssDetector } from './xss.js';
import { asDetectionPlugin, isDetectionPlugin } from './plugin.js';

export const defaultDetectors: readonly Detector[] = [
  sqlInjectionDetector,
  nosqlInjectionDetector,
  xssDetector,
  pathTraversalDetector,
];

export interface DetectionEngineOptions {
  readonly budget?: typeof DEFAULT_DETECTION_BUDGET;
  readonly now?: () => number;
}

const MAX_FINDING_STRING_LENGTH = 256;
const VALID_CATEGORIES = new Set([
  'authentication',
  'authorization',
  'input',
  'rate_limit',
  'webhook',
  'policy',
  'telemetry',
  'other',
]);
const VALID_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const VALID_COMPONENTS = new Set(['route', 'query', 'routeParams', 'body']);

function isValidFinding(finding: DetectionFinding): boolean {
  return (
    typeof finding.ruleId === 'string' &&
    finding.ruleId.length > 0 &&
    finding.ruleId.length <= MAX_FINDING_STRING_LENGTH &&
    VALID_CATEGORIES.has(finding.category) &&
    VALID_SEVERITIES.has(finding.severity) &&
    Number.isFinite(finding.confidence) &&
    finding.confidence >= 0 &&
    finding.confidence <= 1 &&
    VALID_COMPONENTS.has(finding.component) &&
    typeof finding.path === 'string' &&
    finding.path.length <= MAX_FINDING_STRING_LENGTH &&
    typeof finding.reasonCode === 'string' &&
    finding.reasonCode.length > 0 &&
    finding.reasonCode.length <= MAX_FINDING_STRING_LENGTH &&
    (finding.evidenceId === undefined ||
      (typeof finding.evidenceId === 'string' &&
        finding.evidenceId.length > 0 &&
        finding.evidenceId.length <= MAX_FINDING_STRING_LENGTH))
  );
}

export class DetectionEngine {
  private readonly detectors: readonly DetectionPlugin[];
  private readonly budget: typeof DEFAULT_DETECTION_BUDGET;
  private readonly now: () => number;

  public constructor(
    detectors: readonly (Detector | DetectionPlugin)[] = defaultDetectors,
    options: DetectionEngineOptions = {},
  ) {
    this.detectors = detectors.map((detector) =>
      isDetectionPlugin(detector) ? detector : asDetectionPlugin(detector),
    );
    this.budget = options.budget ?? DEFAULT_DETECTION_BUDGET;
    this.now = options.now ?? (() => performance.now());
  }

  public inspect(request: DetectionRequest): DetectionResult {
    const normalization = normalizeRequest(request);
    const startedAt = this.now();
    const budget = this.budget;
    const errors: DetectionError[] = [];
    if (request.bodyState === 'unavailable' || request.bodyState === 'streaming') {
      errors.push({
        code: 'body_unavailable',
        message: 'Request body was not available at the inspection boundary.',
      });
    } else if (request.bodyState === 'malformed') {
      errors.push({
        code: 'parser_error',
        message: 'Request body parsing failed before security inspection.',
      });
    }
    if (normalization.malformedEncoding) {
      errors.push({
        code: 'malformed_encoding' as const,
        message: 'One or more request values contained malformed percent encoding.',
      });
    }
    if (normalization.ambiguous) {
      errors.push({
        code: 'ambiguous_representation',
        message: 'Request values contained an ambiguous encoded representation.',
      });
    }
    if (normalization.limitsExceeded || normalization.truncated) {
      errors.push({
        code: 'normalization_limit' as const,
        message: 'Request inspection reached a configured safety limit.',
      });
    }
    for (const parserError of normalization.parserErrors) {
      errors.push({
        code: 'parser_error' as const,
        message: parserError.message,
      });
    }

    const findings: DetectionFinding[] = [];
    const evidenceIds = new Set<string>();
    let budgetExceeded = false;
    for (const detector of this.detectors) {
      if (errors.length === 0 && this.now() - startedAt >= budget.maxDurationMs) {
        budgetExceeded = true;
        errors.push({
          code: 'budget_exceeded' as const,
          message: 'Cooperative inspection time budget was exceeded.',
        });
        break;
      }
      try {
        for (const finding of detector.inspect({
          contractVersion: '1.0',
          request,
          values: normalization.values,
          budget,
          headers: normalization.headers,
          ...(request.correlationId === undefined ? {} : { correlationId: request.correlationId }),
        })) {
          if (!isValidFinding(finding)) {
            errors.push({
              code: 'invalid_finding' as const,
              message: `Detector ${detector.id} returned an invalid finding.`,
            });
            continue;
          }
          const evidenceId =
            finding.evidenceId ??
            `${finding.ruleId}:${finding.component}:${finding.path}:${finding.reasonCode}`;
          if (evidenceIds.has(evidenceId)) continue;
          evidenceIds.add(evidenceId);
          const source = normalization.values.find(
            (value: NormalizedValue) =>
              value.component === finding.component && value.path === finding.path,
          );
          findings.push({
            ...finding,
            evidenceId,
            ...(source === undefined
              ? {}
              : {
                  provenance: {
                    decodeDepth: source.decodeDepth,
                    transformations: source.transformations,
                    parserId: source.parserId,
                    parserVersion: source.parserVersion,
                    duplicateStatus: source.duplicateStatus,
                    truncated: source.truncated,
                    ambiguous: source.ambiguous,
                  },
                }),
          });
        }
      } catch {
        errors.push({
          code: 'detector_error' as const,
          message: `Detector ${detector.id} failed during inspection.`,
        });
      }
      if (errors.length === 0 && this.now() - startedAt >= budget.maxDurationMs) {
        budgetExceeded = true;
        errors.push({
          code: 'budget_exceeded',
          message: 'Cooperative inspection time budget was exceeded.',
        });
        break;
      }
      if (findings.length >= budget.maxFindings) break;
    }

    const elapsedMs = Math.max(0, this.now() - startedAt);
    const exceeded = budgetExceeded;
    const degradedCodes = errors
      .filter((error) =>
        ['normalization_limit', 'ambiguous_representation', 'body_unavailable'].includes(
          error.code,
        ),
      )
      .map((error) => error.code);
    const failedCodes = errors.filter((error) =>
      [
        'detector_error',
        'invalid_finding',
        'parser_error',
        'budget_exceeded',
        'malformed_encoding',
      ].includes(error.code),
    );
    const outcome =
      findings.length > 0
        ? 'indicator'
        : failedCodes.length > 0
          ? 'failed'
          : degradedCodes.length > 0
            ? 'degraded'
            : 'clean';
    return {
      status: errors.length === 0 ? 'complete' : budgetExceeded ? 'inconclusive' : 'error',
      outcome,
      degradedCodes,
      findings: findings.slice(0, budget.maxFindings),
      errors,
      normalization,
      budget: {
        cooperative: true,
        elapsedMs,
        limitMs: budget.maxDurationMs,
        exceeded,
      },
      ...(request.correlationId === undefined ? {} : { correlationId: request.correlationId }),
    };
  }
}
