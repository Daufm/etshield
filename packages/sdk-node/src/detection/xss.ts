import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { parseHtmlInput } from './detector-utils.js';

const RULE_ID = 'input.xss_indicator';
const DANGEROUS_TAGS = new Set(['svg', 'img', 'iframe', 'object', 'embed']);

function xssReason(value: string): string | undefined {
  const parsed = parseHtmlInput(value);
  if (parsed.scheme === 'javascript') return 'javascript_scheme';
  if (parsed.scheme === 'data-html') return 'html_data_scheme';
  for (const tag of parsed.tags) {
    if (tag.name === 'script') return 'script_element';
    if (DANGEROUS_TAGS.has(tag.name) && tag.executableAttribute) {
      return 'executable_markup_attribute';
    }
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
