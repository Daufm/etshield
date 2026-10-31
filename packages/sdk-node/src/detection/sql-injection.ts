import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { parseSqlInput } from './detector-utils.js';

const RULE_ID = 'input.sql_injection_indicator';
const KEYWORDS = new Set([
  'union',
  'select',
  'from',
  'insert',
  'into',
  'update',
  'set',
  'delete',
  'drop',
  'table',
  'database',
  'sleep',
  'benchmark',
  'or',
  'and',
  'true',
  'false',
]);

function hasSequence(words: readonly string[], first: string, second: string): boolean {
  return words.some((word, index) => word === first && words[index + 1] === second);
}

function isSqlIndicator(value: string): string | undefined {
  const parsed = parseSqlInput(value);
  const words = parsed.tokens;
  if (words.some((word) => !KEYWORDS.has(word) && word.length > 128)) return undefined;
  if (
    hasSequence(words, 'union', 'select') ||
    hasSequence(words, 'select', 'from') ||
    hasSequence(words, 'insert', 'into') ||
    hasSequence(words, 'update', 'set') ||
    hasSequence(words, 'delete', 'from') ||
    hasSequence(words, 'drop', 'table') ||
    hasSequence(words, 'drop', 'database')
  ) {
    return 'sql_keyword_sequence';
  }
  if ((words.includes('or') || words.includes('and')) && parsed.hasQuotedEquality) {
    return 'sql_boolean_expression';
  }
  if ((words.includes('sleep') || words.includes('benchmark')) && parsed.hasCallSyntax) {
    return 'sql_timing_function';
  }
  return undefined;
}

export const sqlInjectionDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const reasonCode = isSqlIndicator(item.value);
      if (reasonCode === undefined) return [];
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: 'high' as const,
          confidence: 0.86,
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
