import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { findMatchesAcrossComponents } from './detector-utils.js';

const NOSQL_INDICATORS =
  /(?:\$where\b|\$ne\b|\$gt\b|\$gte\b|\$lt\b|\$lte\b|\$in\b|\$nin\b|\$regex\b|\$expr\b)/i;

export const nosqlInjectionDetector: Detector = {
  ruleId: 'input.nosql_injection_indicator',
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return findMatchesAcrossComponents(
      context,
      NOSQL_INDICATORS,
      'input.nosql_injection_indicator',
      'input',
      'high',
      0.84,
      'nosql_operator_or_script_indicator',
    );
  },
};
