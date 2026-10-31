import { isIP } from 'node:net';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type {
  SecurityAction,
  SecurityDecision,
  SecurityEvent,
  SecurityPolicy,
} from '@ethioshield/security-contracts';
import {
  assertSecurityPolicy,
  assertSecurityEvent,
  CURRENT_SCHEMA_VERSION,
} from '@ethioshield/security-contracts';
import { DetectionEngine } from './detection/engine.js';
import type { DetectionResult } from './detection/types.js';
import { isHttpMethod } from '@ethioshield/security-contracts';
import type { ChallengeAdapter } from './challenge.js';
import { resolveNetworkRisk, type NetworkIntelligenceResolver } from './network-intelligence.js';
import { LayeredRateLimiter } from './rate-limit/limiter.js';
import type { AtomicCounterStore, RateLimitIdentity } from './rate-limit/types.js';

const SDK_VERSION = '0.1.0-alpha.0';
const MAX_PROJECT_ID_LENGTH = 128;
const MAX_EXCLUSION_LENGTH = 512;
const MAX_CALLBACK_WAIT_MS = 100;

export type EnforcementMode = 'monitor' | 'block';

export interface TrustedProxyConfiguration {
  readonly addresses: readonly string[];
}

export interface RateLimitConfiguration {
  readonly store?: AtomicCounterStore;
  readonly maxKeys?: number;
}

export interface TelemetryAdapter {
  emit(event: SecurityEvent): void | Promise<void>;
  close?(): void | Promise<void>;
}

export interface DecisionContext {
  readonly event: SecurityEvent;
  readonly detection: DetectionResult;
}

export interface EthioShieldExpressOptions {
  readonly projectId: string;
  readonly policy: SecurityPolicy;
  readonly mode?: EnforcementMode;
  readonly routeExclusions?: readonly string[];
  readonly trustedProxy?: TrustedProxyConfiguration;
  readonly trustedIdentity?: (request: Request) => RateLimitIdentity | undefined;
  readonly rateLimit?: RateLimitConfiguration;
  readonly networkIntelligence?: NetworkIntelligenceResolver;
  readonly challengeAdapter?: ChallengeAdapter;
  readonly telemetry?: TelemetryAdapter;
  readonly onDecision?: (
    decision: SecurityDecision,
    context: DecisionContext,
  ) => void | Promise<void>;
  readonly onError?: (error: {
    readonly code: string;
    readonly message: string;
  }) => void | Promise<void>;
  readonly engine?: DetectionEngine;
  readonly clock?: () => Date;
  readonly eventId?: () => string;
}

export interface EthioShieldExpress {
  protect(): RequestHandler;
  close(): Promise<void>;
}

function isValidIdentifier(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= MAX_PROJECT_ID_LENGTH &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  );
}

function isSafeExclusion(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= MAX_EXCLUSION_LENGTH &&
    value.startsWith('/') &&
    !value.includes('?') &&
    !value.includes('#') &&
    !value.includes('//') &&
    !value.includes('\\') &&
    ![...value].some((character) => {
      const code = character.codePointAt(0);
      return code !== undefined && (code <= 0x1f || code === 0x7f);
    })
  );
}

function matchesExclusion(route: string, exclusions: readonly string[]): boolean {
  return exclusions.some((exclusion) => {
    if (exclusion.endsWith('/*')) {
      return route.startsWith(exclusion.slice(0, -1));
    }
    return route === exclusion;
  });
}

function getClientIp(
  request: Request,
  trustedProxy?: TrustedProxyConfiguration,
): string | undefined {
  const peer = request.socket.remoteAddress;
  if (peer === undefined || trustedProxy === undefined) return undefined;
  const normalizedPeer = peer.startsWith('::ffff:') ? peer.slice(7) : peer;
  if (!trustedProxy.addresses.includes(normalizedPeer) || isIP(normalizedPeer) === 0) {
    return undefined;
  }
  const forwarded = request.headers['x-forwarded-for'];
  if (typeof forwarded !== 'string') return undefined;
  const first = forwarded.split(',')[0]?.trim();
  return first !== undefined && isIP(first) !== 0 ? first : undefined;
}

function createDecision(
  action: SecurityAction,
  policy: SecurityPolicy,
  ruleId: string,
  category: SecurityDecision['category'],
  reasonCode: string,
  detection: DetectionResult,
): SecurityDecision {
  const finding = detection.findings[0];
  const decision: SecurityDecision = {
    action,
    ruleId,
    category,
    severity: finding?.severity ?? policy.defaults.severity,
    policyVersion: policy.policyVersion,
    reason: {
      code: reasonCode,
      attributes: {
        findingCount: detection.findings.length,
      },
    },
  };
  return finding === undefined ? decision : { ...decision, confidence: finding.confidence };
}

function createEvent(
  request: Request,
  projectId: string,
  decision: SecurityDecision,
  detection: DetectionResult,
  clock: () => Date,
  eventId: () => string,
  trustedProxy?: TrustedProxyConfiguration,
): SecurityEvent {
  const method = request.method.toUpperCase();
  if (!isHttpMethod(method)) {
    throw new Error('Unsupported request method');
  }
  const firstFinding = detection.findings[0];
  const event: SecurityEvent = {
    schemaVersion: CURRENT_SCHEMA_VERSION,
    eventId: eventId(),
    projectId,
    occurredAt: clock().toISOString(),
    request: {
      method,
      route: request.path,
    },
    detection: {
      category: firstFinding?.category ?? decision.category,
      ruleId: firstFinding?.ruleId ?? decision.ruleId,
    },
    decision,
    sdkVersion: SDK_VERSION,
  };
  const clientIp = getClientIp(request, trustedProxy);
  if (clientIp !== undefined) {
    return { ...event, client: { ip: clientIp } };
  }
  return event;
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('callback timeout')), timeoutMs);
  });
  try {
    return await Promise.race([operation, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class EthioShieldExpressMiddleware implements EthioShieldExpress {
  private readonly options: Required<
    Pick<EthioShieldExpressOptions, 'mode' | 'engine' | 'clock' | 'eventId'>
  > &
    EthioShieldExpressOptions;
  private closed = false;
  private readonly limiter: LayeredRateLimiter | undefined;

  public constructor(options: EthioShieldExpressOptions) {
    assertSecurityPolicy(options.policy);
    if (!isValidIdentifier(options.projectId)) {
      throw new TypeError('projectId must be a bounded identifier');
    }
    if (options.mode !== undefined && !['monitor', 'block'].includes(options.mode)) {
      throw new TypeError('mode must be monitor or block');
    }
    const exclusions =
      options.routeExclusions ?? options.policy.routeExclusions.map(({ route }) => route);
    if (exclusions.length > 50 || exclusions.some((route) => !isSafeExclusion(route))) {
      throw new TypeError('routeExclusions contain an unsafe or excessive route');
    }
    const trustedProxy = options.trustedProxy;
    if (trustedProxy !== undefined) {
      if (trustedProxy.addresses.length === 0 || trustedProxy.addresses.length > 10) {
        throw new TypeError('trustedProxy.addresses must contain 1 to 10 addresses');
      }
      if (trustedProxy.addresses.some((address) => isIP(address) === 0)) {
        throw new TypeError('trustedProxy.addresses must contain IP addresses');
      }
    }
    this.options = {
      ...options,
      mode: options.mode ?? 'monitor',
      engine: options.engine ?? new DetectionEngine(),
      clock: options.clock ?? (() => new Date()),
      eventId: options.eventId ?? (() => crypto.randomUUID()),
      routeExclusions: exclusions,
    };
    const rules = options.policy.rateLimit.rules ?? [];
    const rateLimitOptions = {
      rules,
      failureMode: options.policy.rateLimit.failureMode ?? 'monitor',
      ...(options.rateLimit?.store === undefined ? {} : { store: options.rateLimit.store }),
      ...(options.rateLimit?.maxKeys === undefined ? {} : { maxKeys: options.rateLimit.maxKeys }),
    };
    this.limiter =
      options.policy.rateLimit.enabled && rules.length > 0
        ? new LayeredRateLimiter(rateLimitOptions)
        : undefined;
  }

  public protect(): RequestHandler {
    return (request: Request, response: Response, next: NextFunction): void => {
      void this.handle(request, response, next);
    };
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      if (this.options.telemetry?.close !== undefined) {
        await withTimeout(Promise.resolve(this.options.telemetry.close()), MAX_CALLBACK_WAIT_MS);
      }
    } catch {
      await this.reportError({
        code: 'telemetry_close_error',
        message: 'Telemetry shutdown failed.',
      });
    }
    await this.limiter?.close();
    await this.options.networkIntelligence?.close?.();
  }

  private async handle(request: Request, response: Response, next: NextFunction): Promise<void> {
    if (this.closed) {
      response.status(503).json({ error: 'EthioShield is shutting down' });
      return;
    }
    if (matchesExclusion(request.path, this.options.routeExclusions ?? [])) {
      next();
      return;
    }

    let detection: DetectionResult;
    try {
      detection = this.options.engine.inspect({
        method: request.method,
        route: request.path,
        query: request.query,
        routeParams: request.params,
        body: request.body,
      });
    } catch {
      await this.reportError({ code: 'detection_error', message: 'Security inspection failed.' });
      if (this.options.mode === 'block') {
        response.status(503).json({ error: 'Security inspection unavailable' });
        return;
      }
      next();
      return;
    }

    const clientIp = getClientIp(request, this.options.trustedProxy);
    const networkSignal = await resolveNetworkRisk(this.options.networkIntelligence, clientIp);
    const identity = this.options.trustedIdentity?.(request);
    const network = networkSignal?.classification;
    const limiterIdentity =
      identity === undefined && network === undefined
        ? undefined
        : {
            ...identity,
            ...(network === undefined ? {} : { network }),
          };
    const rateLimit = this.limiter
      ? await this.limiter.check({
          route: request.path,
          ...(clientIp === undefined ? {} : { ip: clientIp }),
          ...(limiterIdentity === undefined ? {} : { identity: limiterIdentity }),
          ...(networkSignal === undefined || networkSignal.classification === 'residential'
            ? {}
            : { riskScore: networkSignal.confidence }),
        })
      : undefined;
    const failed = detection.status === 'error';
    const hasFindings = detection.findings.length > 0;
    const firstFinding = detection.findings[0];
    if (failed) {
      await this.reportError({
        code: 'detection_error',
        message: 'Security inspection failed.',
      });
    }
    const rateLimited = rateLimit !== undefined && rateLimit.action !== 'allow';
    const action: SecurityAction = failed
      ? this.options.mode === 'block'
        ? 'block'
        : 'monitor'
      : rateLimited
        ? rateLimit.action
        : hasFindings
          ? this.options.mode === 'block'
            ? 'block'
            : 'monitor'
          : 'allow';
    const blocked = action === 'block';
    const throttled = action === 'throttle';
    const challenged = action === 'challenge';
    const decision = createDecision(
      action,
      this.options.policy,
      failed
        ? 'inspection.failure'
        : rateLimited
          ? rateLimit.ruleId
          : (firstFinding?.ruleId ?? 'policy.allow'),
      failed ? 'policy' : rateLimited ? 'rate_limit' : (firstFinding?.category ?? 'policy'),
      failed
        ? 'inspection_failed'
        : rateLimited
          ? rateLimit.storeError
            ? 'rate_limit_store_unavailable'
            : 'rate_limit_exceeded'
          : hasFindings
            ? 'indicator_detected'
            : 'no_indicator_detected',
      detection,
    );

    let event: SecurityEvent;
    try {
      event = createEvent(
        request,
        this.options.projectId,
        decision,
        detection,
        this.options.clock,
        this.options.eventId,
        this.options.trustedProxy,
      );
      assertSecurityEvent(event);
    } catch {
      await this.reportError({
        code: 'event_error',
        message: 'Security decision could not be recorded.',
      });
      if (this.options.mode === 'block') {
        response.status(503).json({ error: 'Security inspection unavailable' });
        return;
      }
      next();
      return;
    }

    await this.runHook(decision, { event, detection });
    await this.emitTelemetry(event);

    if (challenged) {
      if (this.options.challengeAdapter === undefined) {
        await this.reportError({
          code: 'challenge_unavailable',
          message: 'Challenge requested without a configured challenge adapter.',
        });
        if (this.options.mode === 'block') {
          response.status(503).json({ error: 'Security challenge unavailable' });
          return;
        }
      } else {
        try {
          const challengeRequest =
            rateLimit?.retryAfterSeconds === undefined
              ? { reason: decision.reason.code }
              : {
                  reason: decision.reason.code,
                  retryAfterSeconds: rateLimit.retryAfterSeconds,
                };
          const challenge = await withTimeout(
            Promise.resolve(
              this.options.challengeAdapter.challenge(challengeRequest, response, request),
            ),
            MAX_CALLBACK_WAIT_MS,
          );
          if (challenge.handled) return;
        } catch {
          await this.reportError({
            code: 'challenge_error',
            message: 'Security challenge failed.',
          });
          if (this.options.mode === 'block') {
            response.status(503).json({ error: 'Security challenge unavailable' });
            return;
          }
        }
      }
    }
    if (blocked) {
      response.status(hasFindings ? 403 : 503).json({
        error: hasFindings
          ? 'Request blocked by security policy'
          : 'Security inspection unavailable',
      });
      return;
    }
    if (throttled) {
      if (rateLimit?.retryAfterSeconds !== undefined) {
        response.setHeader('retry-after', String(rateLimit.retryAfterSeconds));
      }
      response.status(429).json({ error: 'Request throttled by security policy' });
      return;
    }
    response.setHeader('x-ethioshield-action', decision.action);
    next();
  }

  private async runHook(decision: SecurityDecision, context: DecisionContext): Promise<void> {
    if (this.options.onDecision === undefined) return;
    try {
      await withTimeout(
        Promise.resolve(this.options.onDecision(decision, context)),
        MAX_CALLBACK_WAIT_MS,
      );
    } catch {
      await this.reportError({ code: 'decision_hook_error', message: 'Decision hook failed.' });
    }
  }

  private async emitTelemetry(event: SecurityEvent): Promise<void> {
    if (this.options.telemetry === undefined) return;
    try {
      await withTimeout(Promise.resolve(this.options.telemetry.emit(event)), MAX_CALLBACK_WAIT_MS);
    } catch {
      await this.reportError({ code: 'telemetry_error', message: 'Telemetry delivery failed.' });
    }
  }

  private async reportError(error: {
    readonly code: string;
    readonly message: string;
  }): Promise<void> {
    if (this.options.onError === undefined) return;
    try {
      await this.options.onError(error);
    } catch {
      // Error reporting must never affect request handling.
    }
  }
}

export function createEthioShieldExpress(options: EthioShieldExpressOptions): EthioShieldExpress {
  return new EthioShieldExpressMiddleware(options);
}
