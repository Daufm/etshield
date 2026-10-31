import type {
  CorrelationDimension,
  CorrelationRule,
  SecurityAction,
} from '@ethioshield/security-contracts';
import type { AtomicCounterStore, CounterResult, RateLimitIdentity } from './rate-limit/types.js';
import { encodeCounterKey } from './rate-limit/key.js';

export interface CorrelationStore {
  increment(key: string, windowSeconds: number, now: number): Promise<CounterResult>;
  close?(): Promise<void> | void;
}

export interface CorrelationRequest {
  readonly route: string;
  readonly ip?: string;
  readonly identity?: RateLimitIdentity;
  readonly riskScore?: number;
}

export interface CorrelationOutcome {
  readonly action: Extract<
    SecurityAction,
    'allow' | 'monitor' | 'throttle' | 'block' | 'challenge'
  >;
  readonly ruleId: string;
  readonly dimensions: readonly CorrelationDimension[];
  readonly count?: number;
  readonly limit?: number;
  readonly retryAfterSeconds?: number;
  readonly storeError?: boolean;
}

interface CorrelationEntry {
  count: number;
  resetAt: number;
}

const MAX_CORRELATION_KEYS = 10_000;

export class InMemoryCorrelationStore implements CorrelationStore {
  private readonly entries = new Map<string, CorrelationEntry>();
  private readonly maxKeys: number;

  public constructor(maxKeys = MAX_CORRELATION_KEYS) {
    if (!Number.isInteger(maxKeys) || maxKeys < 1 || maxKeys > MAX_CORRELATION_KEYS) {
      throw new TypeError(`maxKeys must be an integer between 1 and ${MAX_CORRELATION_KEYS}`);
    }
    this.maxKeys = maxKeys;
  }

  public async increment(key: string, windowSeconds: number, now: number): Promise<CounterResult> {
    for (const [entryKey, entry] of this.entries) {
      if (entry.resetAt <= now) this.entries.delete(entryKey);
    }
    const resetAt = now + windowSeconds * 1_000;
    const current = this.entries.get(key);
    if (current === undefined || current.resetAt <= now) {
      if (current === undefined && this.entries.size >= this.maxKeys) {
        throw new Error('correlation cardinality limit reached');
      }
      const next = { count: 1, resetAt };
      this.entries.set(key, next);
      return { ...next, limit: Number.MAX_SAFE_INTEGER };
    }
    current.count += 1;
    return { ...current, limit: Number.MAX_SAFE_INTEGER };
  }

  public close(): void {
    this.entries.clear();
  }
}

function valueForDimension(
  dimension: CorrelationDimension,
  request: CorrelationRequest,
): string | undefined {
  switch (dimension) {
    case 'authenticated_user':
      return request.identity?.authenticatedUserId;
    case 'target_account':
      return request.identity?.targetAccountId;
    case 'route':
      return request.route;
    case 'ip':
      return request.ip;
  }
}

function matchesRule(rule: CorrelationRule, request: CorrelationRequest): boolean {
  return (
    (rule.route === undefined || rule.route === request.route) &&
    (rule.riskThreshold === undefined ||
      (request.riskScore !== undefined && request.riskScore >= rule.riskThreshold))
  );
}

export interface CorrelationOptions {
  readonly rules: readonly CorrelationRule[];
  readonly failureMode: 'monitor' | 'block';
  readonly store?: CorrelationStore | AtomicCounterStore;
  readonly maxKeys?: number;
}

export class StatefulCorrelator {
  private readonly rules: readonly CorrelationRule[];
  private readonly failureMode: CorrelationOptions['failureMode'];
  private readonly store: CorrelationStore;

  public constructor(options: CorrelationOptions) {
    this.rules = options.rules;
    this.failureMode = options.failureMode;
    this.store = options.store ?? new InMemoryCorrelationStore(options.maxKeys);
  }

  public async check(request: CorrelationRequest, now = Date.now()): Promise<CorrelationOutcome> {
    for (const rule of this.rules) {
      if (!matchesRule(rule, request)) continue;
      const dimensions = rule.dimensions.filter(
        (dimension) => valueForDimension(dimension, request) !== undefined,
      );
      if (dimensions.length !== rule.dimensions.length) continue;
      const key = encodeCounterKey(
        rule.ruleId,
        dimensions.map((dimension) => [dimension, valueForDimension(dimension, request) ?? '']),
      );
      try {
        const counter = await this.store.increment(key, rule.windowSeconds, now);
        if (counter.count > rule.maxEvents) {
          return {
            action: rule.action,
            ruleId: rule.ruleId,
            dimensions,
            count: counter.count,
            limit: rule.maxEvents,
            retryAfterSeconds: Math.max(1, Math.ceil((counter.resetAt - now) / 1_000)),
          };
        }
      } catch {
        return {
          action: this.failureMode,
          ruleId: rule.ruleId,
          dimensions,
          storeError: true,
        };
      }
    }
    return { action: 'allow', ruleId: 'correlation.allow', dimensions: [] };
  }

  public async close(): Promise<void> {
    await this.store.close?.();
  }
}
