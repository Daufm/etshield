import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { parseNoSqlOperator } from './detector-utils.js';

const RULE_ID = 'input.nosql_injection_indicator';

export const nosqlInjectionDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const operator = parseNoSqlOperator(item.value);
      if (operator === undefined) return [];
      const reasonCode =
        operator === '$where' || operator === '$expr'
          ? 'nosql_script_operator'
          : 'nosql_query_operator';
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: 'high' as const,
          confidence: operator === '$where' || operator === '$expr' ? 0.9 : 0.84,
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
