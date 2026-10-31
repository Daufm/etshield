import type {
  RateLimitFailureMode,
  RateLimitKeyType,
  RateLimitRule,
  SecurityAction,
} from '@ethioshield/security-contracts';

export const MAX_RATE_LIMIT_KEYS_PER_REQUEST = 8;
export const MAX_RATE_LIMIT_RULES = 50;
export const MAX_COUNTER_KEYS = 10_000;

export interface RateLimitIdentity {
  readonly authenticatedUserId?: string;
  readonly verifiedApiKeyId?: string;
  readonly sessionId?: string;
  readonly targetAccountId?: string;
  readonly network?: string;
}

export interface RateLimitRequest {
  readonly route: string;
  readonly ip?: string;
  readonly identity?: RateLimitIdentity;
  readonly riskScore?: number;
}

export interface CounterResult {
  readonly count: number;
  readonly limit: number;
  readonly resetAt: number;
}

export interface AtomicCounterStore {
  increment(key: string, windowSeconds: number, now: number): Promise<CounterResult>;
  close?(): Promise<void> | void;
}

export interface RateLimitOutcome {
  readonly action: Extract<
    SecurityAction,
    'allow' | 'monitor' | 'throttle' | 'block' | 'challenge'
  >;
  readonly ruleId: string;
  readonly keyTypes: readonly RateLimitKeyType[];
  readonly count?: number;
  readonly limit?: number;
  readonly retryAfterSeconds?: number;
  readonly storeError?: boolean;
}

export interface RateLimitOptions {
  readonly rules: readonly RateLimitRule[];
  readonly failureMode: RateLimitFailureMode;
  readonly store?: AtomicCounterStore;
  readonly maxKeys?: number;
}
