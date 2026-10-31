import type { DetectionFinding, DetectorContext, InspectedComponent } from './types.js';

const MAX_TOKENS = 256;
const MAX_TOKEN_LENGTH = 128;

export interface StructuredSqlInput {
  readonly tokens: readonly string[];
  readonly hasQuotedEquality: boolean;
  readonly hasCallSyntax: boolean;
}

export function parseSqlInput(value: string): StructuredSqlInput {
  const tokens: string[] = [];
  let token = '';
  let quote: '"' | "'" | undefined;
  let hasQuotedEquality = false;
  let hasCallSyntax = false;

  const pushToken = (): void => {
    if (token.length > 0 && tokens.length < MAX_TOKENS) {
      tokens.push(token.slice(0, MAX_TOKEN_LENGTH));
      token = '';
    } else {
      token = '';
    }
  };

  for (let index = 0; index < value.length && tokens.length < MAX_TOKENS; index += 1) {
    const character = value[index] ?? '';
    const next = value[index + 1] ?? '';
    if (quote !== undefined) {
      if (character === '\\') {
        index += 1;
        continue;
      }
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (character === '/' && next === '*') {
      const end = value.indexOf('*/', index + 2);
      index = end < 0 ? value.length : end + 1;
      continue;
    }
    if (character === '(') hasCallSyntax = true;
    if (character === '=' && tokens.length > 0) {
      hasQuotedEquality = /['"][^'"]*['"]?\s*=\s*['"]?[^'"]+/u.test(value);
    }
    if (/[a-z0-9_$]/iu.test(character)) token += character.toLowerCase();
    else pushToken();
  }
  pushToken();
  return { tokens, hasQuotedEquality, hasCallSyntax };
}

export interface StructuredHtmlInput {
  readonly scheme: 'javascript' | 'data-html' | undefined;
  readonly tags: readonly { readonly name: string; readonly executableAttribute: boolean }[];
}

export function parseHtmlInput(value: string): StructuredHtmlInput {
  const lower = value.toLowerCase();
  let scheme: StructuredHtmlInput['scheme'];
  if (lower.includes('javascript:')) scheme = 'javascript';
  else if (lower.includes('data:text/html')) scheme = 'data-html';
  const tags: { name: string; executableAttribute: boolean }[] = [];
  const tagPattern = /<\s*([a-z][a-z0-9-]*)\b([^>]*)>/giu;
  let match: RegExpExecArray | null;
  while ((match = tagPattern.exec(value)) !== null && tags.length < MAX_TOKENS) {
    const name = (match[1] ?? '').toLowerCase();
    const attributes = match[2] ?? '';
    tags.push({
      name,
      executableAttribute:
        /\bon[a-z][a-z0-9-]*\s*=/iu.test(attributes) || /\bsrcdoc\s*=/iu.test(attributes),
    });
  }
  return { scheme, tags };
}

export function splitPathSegments(value: string): readonly string[] {
  return value
    .split(/[\\/]+/u)
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0)
    .slice(0, MAX_TOKENS);
}

const NOSQL_OPERATORS = new Set([
  '$where',
  '$ne',
  '$gt',
  '$gte',
  '$lt',
  '$lte',
  '$in',
  '$nin',
  '$regex',
  '$expr',
]);

export function parseNoSqlOperator(value: string): string | undefined {
  const operator = /^\$[a-z][a-z0-9]*/u.exec(value.trim())?.[0];
  return operator !== undefined && NOSQL_OPERATORS.has(operator) ? operator : undefined;
}

export function findMatches(
  context: DetectorContext,
  component: InspectedComponent,
  pattern: RegExp,
  ruleId: string,
  category: DetectionFinding['category'],
  severity: DetectionFinding['severity'],
  confidence: number,
  reasonCode: string,
): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  for (const value of context.values) {
    if (value.component !== component || !pattern.test(value.value)) continue;
    findings.push({
      ruleId,
      category,
      severity,
      confidence,
      confidenceBand: confidence >= 0.85 ? 'high' : confidence >= 0.6 ? 'medium' : 'low',
      component: value.component,
      path: value.path,
      reasonCode,
      evidenceId: `${ruleId}:${value.component}:${value.path}:${reasonCode}`,
    });
  }
  return findings;
}

export function findMatchesAcrossComponents(
  context: DetectorContext,
  pattern: RegExp,
  ruleId: string,
  category: DetectionFinding['category'],
  severity: DetectionFinding['severity'],
  confidence: number,
  reasonCode: string,
): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  for (const value of context.values) {
    if (!pattern.test(value.value)) continue;
    findings.push({
      ruleId,
      category,
      severity,
      confidence,
      confidenceBand: confidence >= 0.85 ? 'high' : confidence >= 0.6 ? 'medium' : 'low',
      component: value.component,
      path: value.path,
      reasonCode,
      evidenceId: `${ruleId}:${value.component}:${value.path}:${reasonCode}`,
    });
  }
  return findings;
}
