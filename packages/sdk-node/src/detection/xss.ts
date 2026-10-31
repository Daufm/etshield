import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { findMatchesAcrossComponents } from './detector-utils.js';

const XSS_INDICATORS =
  /(?:<\s*script\b|<\s*(?:svg|img|iframe|object|embed)\b[^>]*(?:on\w+\s*=|srcdoc\s*=)|javascript\s*:|data\s*:\s*text\/html|on(?:error|load|click)\s*=)/i;

export const xssDetector: Detector = {
  ruleId: 'input.xss_indicator',
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return findMatchesAcrossComponents(
      context,
      XSS_INDICATORS,
      'input.xss_indicator',
      'input',
      'high',
      0.82,
      'executable_markup_or_script_scheme',
    );
  },
};
