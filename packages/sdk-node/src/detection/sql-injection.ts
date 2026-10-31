import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { findMatchesAcrossComponents } from './detector-utils.js';

const SQL_INDICATORS =
  /(?:'|")\s*(?:or|and)\s+(?:['"]?\w+['"]?\s*=\s*['"]?\w+|true|false)|(?:union\s+(?:all\s+)?select|select\s+.+\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database)|\b(?:sleep|benchmark)\s*\()/i;

export const sqlInjectionDetector: Detector = {
  ruleId: 'input.sql_injection_indicator',
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return findMatchesAcrossComponents(
      context,
      SQL_INDICATORS,
      'input.sql_injection_indicator',
      'input',
      'high',
      0.86,
      'sql_keyword_or_operator_sequence',
    );
  },
};
