import type { Detector, DetectionRequest, DetectionResult } from './types.js';
import { MAX_FINDINGS } from './types.js';
import { normalizeRequest } from './normalization.js';
import { nosqlInjectionDetector } from './nosql-injection.js';
import { pathTraversalDetector } from './path-traversal.js';
import { sqlInjectionDetector } from './sql-injection.js';
import { xssDetector } from './xss.js';

export const defaultDetectors: readonly Detector[] = [
  sqlInjectionDetector,
  nosqlInjectionDetector,
  xssDetector,
  pathTraversalDetector,
];

export class DetectionEngine {
  private readonly detectors: readonly Detector[];

  public constructor(detectors: readonly Detector[] = defaultDetectors) {
    this.detectors = detectors;
  }

  public inspect(request: DetectionRequest): DetectionResult {
    const normalization = normalizeRequest(request);
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

    const findings = [];
    for (const detector of this.detectors) {
      try {
        findings.push(...detector.detect({ values: normalization.values }));
      } catch {
        errors.push({
          code: 'detector_error' as const,
          message: `Detector ${detector.ruleId} failed during inspection.`,
        });
      }
      if (findings.length >= MAX_FINDINGS) break;
    }

    return {
      status: errors.length === 0 ? 'complete' : 'error',
      findings: findings.slice(0, MAX_FINDINGS),
      errors,
      normalization,
    };
  }
}
