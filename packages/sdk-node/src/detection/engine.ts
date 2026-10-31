import type { DetectionPlugin, Detector, DetectionRequest, DetectionResult } from './types.js';
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

export class DetectionEngine {
  private readonly detectors: readonly DetectionPlugin[];

  public constructor(detectors: readonly (Detector | DetectionPlugin)[] = defaultDetectors) {
    this.detectors = detectors.map((detector) =>
      isDetectionPlugin(detector) ? detector : asDetectionPlugin(detector),
    );
  }

  public inspect(request: DetectionRequest): DetectionResult {
    const normalization = normalizeRequest(request);
    const budget = DEFAULT_DETECTION_BUDGET;
    const errors = [];
    if (normalization.malformedEncoding) {
      errors.push({
        code: 'malformed_encoding' as const,
        message: 'One or more request values contained malformed percent encoding.',
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

    const findings = [];
    const evidenceIds = new Set<string>();
    for (const detector of this.detectors) {
      try {
        for (const finding of detector.inspect({
          contractVersion: '1.0',
          request,
          values: normalization.values,
          budget,
          headers: normalization.headers,
        })) {
          const evidenceId =
            finding.evidenceId ??
            `${finding.ruleId}:${finding.component}:${finding.path}:${finding.reasonCode}`;
          if (evidenceIds.has(evidenceId)) continue;
          evidenceIds.add(evidenceId);
          findings.push({ ...finding, evidenceId });
        }
      } catch {
        errors.push({
          code: 'detector_error' as const,
          message: `Detector ${detector.id} failed during inspection.`,
        });
      }
      if (findings.length >= budget.maxFindings) break;
    }

    return {
      status: errors.length === 0 ? 'complete' : 'error',
      findings: findings.slice(0, budget.maxFindings),
      errors,
      normalization,
    };
  }
}
