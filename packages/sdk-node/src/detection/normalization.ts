import type {
  DetectionRequest,
  InspectedComponent,
  NormalizationResult,
  NormalizedValue,
} from './types.js';
import { MAX_INPUT_DEPTH, MAX_INPUT_NODES, MAX_INPUT_STRING_LENGTH } from './types.js';
import { headersParser } from './parsers/headers.js';
import { jsonParser } from './parsers/json.js';
import { queryParser } from './parsers/query.js';
import { routeParamsParser } from './parsers/route-params.js';

const MAX_VALUES = 1_000;
const MAX_INPUT_BYTES = 1_048_576;

interface WorkItem {
  readonly component: InspectedComponent;
  readonly path: string;
  readonly value: unknown;
  readonly depth: number;
}

function scalarToString(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value);
  }
  return undefined;
}

function normalizeScalar(value: string): { value: string; malformedEncoding: boolean } {
  const bounded = value.slice(0, MAX_INPUT_STRING_LENGTH);
  let decoded = bounded;
  let malformedEncoding = false;
  try {
    decoded = decodeURIComponent(bounded);
  } catch {
    malformedEncoding = /%[0-9a-f]{0,2}$/i.test(bounded) || /%/i.test(bounded);
  }
  return {
    value: decoded.normalize('NFKC').toLowerCase(),
    malformedEncoding,
  };
}

function parserFor(component: InspectedComponent): {
  readonly id: string;
  readonly version: string;
} {
  switch (component) {
    case 'route':
      return { id: 'route', version: '1.0' };
    case 'query':
      return { id: queryParser.id, version: '1.0' };
    case 'routeParams':
      return { id: routeParamsParser.id, version: '1.0' };
    case 'body':
      return { id: jsonParser.id, version: '1.0' };
  }
}

export function normalizeRequest(request: DetectionRequest): NormalizationResult {
  const values: NormalizedValue[] = [];
  const work: WorkItem[] = [{ component: 'route', path: '$route', value: request.route, depth: 0 }];
  const parsed = [
    ['query', queryParser.parse(request.query), 'query'],
    ['routeParams', routeParamsParser.parse(request.routeParams), 'routeParams'],
    ['body', jsonParser.parse(request.body), 'body'],
  ] as const;
  const parserErrors = parsed.flatMap(([, result]) => result.errors);
  for (const [component, result] of parsed) {
    if (result.value !== undefined) {
      work.push({ component, path: '$', value: result.value, depth: 0 });
    }
  }

  let nodes = 0;
  let truncated = false;
  let malformedEncoding = false;
  let ambiguous = false;
  let limitsExceeded = false;
  let inputBytes = 0;
  const seen = new WeakSet<object>();

  while (work.length > 0) {
    const item = work.pop();
    if (item === undefined) break;
    nodes += 1;
    if (nodes > MAX_INPUT_NODES || values.length >= MAX_VALUES) {
      limitsExceeded = true;
      break;
    }

    const scalar = scalarToString(item.value);
    if (scalar !== undefined) {
      inputBytes += Buffer.byteLength(scalar, 'utf8');
      if (inputBytes > MAX_INPUT_BYTES) {
        limitsExceeded = true;
        break;
      }
      const normalized = normalizeScalar(scalar);
      const bounded = scalar.slice(0, MAX_INPUT_STRING_LENGTH);
      const decodedOnce = (() => {
        try {
          return decodeURIComponent(bounded);
        } catch {
          return bounded;
        }
      })();
      const hasSecondDecodeCandidate = /%[0-9a-f]{2}/iu.test(decodedOnce);
      const parser = parserFor(item.component);
      const duplicateStatus =
        item.component === 'query' && item.path.includes('[') ? 'present' : 'unknown';
      values.push({
        component: item.component,
        path: item.path.slice(0, 256),
        raw: bounded,
        value: normalized.value,
        malformedEncoding: normalized.malformedEncoding,
        decodeDepth: 1,
        transformations: ['percent_decode', 'unicode_nfkc', 'case_fold'],
        parserId: parser.id,
        parserVersion: parser.version,
        duplicateStatus,
        truncated: scalar.length > MAX_INPUT_STRING_LENGTH,
        ambiguous: hasSecondDecodeCandidate,
      });
      malformedEncoding ||= normalized.malformedEncoding;
      truncated ||= scalar.length > MAX_INPUT_STRING_LENGTH;
      ambiguous ||= hasSecondDecodeCandidate;
      continue;
    }

    if (item.value === null || typeof item.value !== 'object') continue;
    if (seen.has(item.value)) {
      limitsExceeded = true;
      continue;
    }
    seen.add(item.value);
    if (item.depth >= MAX_INPUT_DEPTH) {
      limitsExceeded = true;
      continue;
    }

    if (Array.isArray(item.value)) {
      for (let index = item.value.length - 1; index >= 0; index -= 1) {
        work.push({
          component: item.component,
          path: `${item.path}[${index}]`,
          value: item.value[index],
          depth: item.depth + 1,
        });
      }
      continue;
    }

    const record = item.value as Record<string, unknown>;
    const entries = Object.entries(record);
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const entry = entries[index];
      if (entry === undefined) continue;
      const [key, value] = entry;
      work.push({
        component: item.component,
        path: `${item.path}.${key.slice(0, 128)}`,
        value: key,
        depth: item.depth + 1,
      });
      work.push({
        component: item.component,
        path: `${item.path}.${key.slice(0, 128)}`,
        value,
        depth: item.depth + 1,
      });
    }
  }

  const parsedHeaders = headersParser.parse(request.headers);
  parserErrors.push(...parsedHeaders.errors);
  const headers = parsedHeaders.value ?? {};
  return { values, truncated, malformedEncoding, limitsExceeded, ambiguous, headers, parserErrors };
}
