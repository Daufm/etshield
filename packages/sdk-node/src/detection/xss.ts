import type { Detector, DetectorContext, DetectionFinding } from './types.js';

const RULE_ID = 'input.xss_indicator';
const DANGEROUS_TAGS = new Set(['svg', 'img', 'iframe', 'object', 'embed']);

function hasEventAttribute(tag: string): boolean {
  for (let index = 0; index + 2 < tag.length; index += 1) {
    if (tag[index] !== 'o' || tag[index + 1] !== 'n') continue;
    const next = tag[index + 2];
    if (next !== undefined && /[a-z]/u.test(next) && tag.includes('=', index + 3)) {
      return true;
    }
  }
  return false;
}

function xssReason(value: string): string | undefined {
  const lower = value.toLowerCase();
  if (lower.includes('javascript:')) return 'javascript_scheme';
  if (lower.includes('data:text/html')) return 'html_data_scheme';
  let cursor = 0;
  while (cursor < lower.length) {
    const start = lower.indexOf('<', cursor);
    if (start < 0) break;
    const end = lower.indexOf('>', start + 1);
    if (end < 0) break;
    const tag = lower.slice(start + 1, end).trim();
    const name = tag.split(/[\s/]/u, 1)[0] ?? '';
    if (name === 'script') return 'script_element';
    if (DANGEROUS_TAGS.has(name) && (hasEventAttribute(tag) || tag.includes('srcdoc='))) {
      return 'executable_markup_attribute';
    }
    cursor = end + 1;
  }
  return undefined;
}

export const xssDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const reasonCode = xssReason(item.value);
      if (reasonCode === undefined) return [];
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: 'high' as const,
          confidence: 0.82,
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
