import type { RateLimitRule } from '@ethioshield/security-contracts';
import type {
  AtomicCounterStore,
  RateLimitIdentity,
  RateLimitOptions,
  RateLimitOutcome,
  RateLimitRequest,
} from './types.js';
import { InMemoryAtomicCounterStore } from './store.js';

function boundedIdentifier(value: string | undefined): string | undefined {
  return value !== undefined && value.length > 0 && value.length <= 128 ? value : undefined;
}

function keyValue(
  type: RateLimitRule['keyTypes'][number],
  request: RateLimitRequest,
): string | undefined {
  const identity: RateLimitIdentity = request.identity ?? {};
  switch (type) {
    case 'authenticated_user':
      return boundedIdentifier(identity.authenticatedUserId);
    case 'verified_api_key':
      return boundedIdentifier(identity.verifiedApiKeyId);
    case 'session':
      return boundedIdentifier(identity.sessionId);
    case 'target_account':
      return boundedIdentifier(identity.targetAccountId);
    case 'route':
      return request.route;
    case 'ip':
      return request.ip;
    case 'network':
      return boundedIdentifier(identity.network);
  }
}

function matchesRule(rule: RateLimitRule, request: RateLimitRequest): boolean {
  return (
    (rule.route === undefined || rule.route === request.route) &&
    (rule.riskThreshold === undefined ||
      (request.riskScore !== undefined && request.riskScore >= rule.riskThreshold))
  );
}

export class LayeredRateLimiter {
  private readonly rules: readonly RateLimitRule[];
  private readonly failureMode: RateLimitOptions['failureMode'];
  private readonly store: AtomicCounterStore;

  public constructor(options: RateLimitOptions) {
    this.rules = options.rules;
    this.failureMode = options.failureMode;
    this.store = options.store ?? new InMemoryAtomicCounterStore(options.maxKeys);
  }

  public async check(request: RateLimitRequest, now = Date.now()): Promise<RateLimitOutcome> {
    for (const rule of this.rules) {
      if (!matchesRule(rule, request)) continue;
      const keyTypes = rule.keyTypes.filter((type) => keyValue(type, request) !== undefined);
      if (keyTypes.length === 0) continue;
      const key = `${rule.ruleId}:${keyTypes.map((type) => `${type}=${keyValue(type, request)}`).join('|')}`;
      try {
        const counter = await this.store.increment(key, rule.windowSeconds, now);
        const exceeded = counter.count > rule.maxRequests;
        if (exceeded) {
          return {
            action: rule.action,
            ruleId: rule.ruleId,
            keyTypes,
            count: counter.count,
            limit: rule.maxRequests,
            retryAfterSeconds: Math.max(1, Math.ceil((counter.resetAt - now) / 1_000)),
          };
        }
      } catch {
        return {
          action: this.failureMode,
          ruleId: rule.ruleId,
          keyTypes,
          storeError: true,
        };
      }
    }
    return { action: 'allow', ruleId: 'rate_limit.allow', keyTypes: [] };
  }

  public async close(): Promise<void> {
    await this.store.close?.();
  }
}
