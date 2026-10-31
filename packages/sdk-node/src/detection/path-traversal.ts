import type { Detector, DetectorContext, DetectionFinding } from './types.js';

const RULE_ID = 'input.path_traversal_indicator';
const SENSITIVE_SEGMENTS = new Set(['etc', 'proc', 'windows']);

export const pathTraversalDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const segments = item.value.split(/[\\/]+/u).filter((segment) => segment.length > 0);
      const hasParent = segments.includes('..');
      const hasSensitiveRoot = segments.some((segment) => SENSITIVE_SEGMENTS.has(segment));
      if (!hasParent && !hasSensitiveRoot) return [];
      const reasonCode = hasParent ? 'parent_path_segment' : 'sensitive_system_path_segment';
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: 'high' as const,
          confidence: hasParent ? 0.94 : 0.9,
          confidenceBand: 'high' as const,
          component: item.component,
          path: item.path,
          reasonCode,
          evidenceId: `${RULE_ID}:${item.component}:${item.path}:${reasonCode}`,
        },
      ];
    });
  },
};
