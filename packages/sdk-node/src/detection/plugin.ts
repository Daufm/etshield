import type { RuleCategory } from '@ethioshield/security-contracts';
import type { DetectionContext, DetectionFinding, DetectionPlugin, Detector } from './types.js';

export function isDetectionPlugin(value: Detector | DetectionPlugin): value is DetectionPlugin {
  return 'inspect' in value;
}

export function asDetectionPlugin(detector: Detector): DetectionPlugin {
  return {
    id: detector.ruleId,
    version: '1.0',
    categories: ['input' satisfies RuleCategory],
    inspect(context: DetectionContext): readonly DetectionFinding[] {
      return detector.detect({
        values: context.values,
        request: context.request,
        budget: context.budget,
      });
    },
  };
}
