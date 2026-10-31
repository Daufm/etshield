import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { findMatchesAcrossComponents } from './detector-utils.js';

const PATH_TRAVERSAL_INDICATORS =
  /(?:^|[\\/])\.\.(?:[\\/]|$)|(?:^|[\\/])(?:etc|proc|windows)(?:[\\/]|$)/i;

export const pathTraversalDetector: Detector = {
  ruleId: 'input.path_traversal_indicator',
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return findMatchesAcrossComponents(
      context,
      PATH_TRAVERSAL_INDICATORS,
      'input.path_traversal_indicator',
      'input',
      'high',
      0.9,
      'parent_path_or_sensitive_system_path',
    );
  },
};
