import type { Detector, DetectorContext, DetectionFinding } from './types.js';

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

function tokens(value: string): string[] {
  const result: string[] = [];
  let token = '';
  for (const character of value) {
    if (/[a-z0-9_]/.test(character)) {
      token += character;
    } else if (token.length > 0) {
      result.push(token);
      token = '';
    }
  }
  if (token.length > 0) result.push(token);
  return result;
}

function removeComments(value: string): string {
  let result = '';
  let index = 0;
  while (index < value.length) {
    if (value[index] === '/' && value[index + 1] === '*') {
      const end = value.indexOf('*/', index + 2);
      index = end < 0 ? value.length : end + 2;
      continue;
    }
    result += value[index] ?? '';
    index += 1;
  }
  return result;
}

function hasSequence(words: readonly string[], first: string, second: string): boolean {
  return words.some((word, index) => word === first && words[index + 1] === second);
}

function isSqlIndicator(value: string): string | undefined {
  const parsedValue = removeComments(value);
  const words = tokens(parsedValue);
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
  if (
    (words.includes('or') || words.includes('and')) &&
    /['"][^'"]*['"]?\s*=\s*['"]?[^'"]+['"]?/u.test(parsedValue)
  ) {
    return 'sql_boolean_expression';
  }
  if ((words.includes('sleep') || words.includes('benchmark')) && parsedValue.includes('(')) {
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
