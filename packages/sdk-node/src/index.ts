import type {
  HttpMethod,
  SecurityDecision,
  SecurityEvent,
  SecurityPolicy,
} from '@ethioshield/security-contracts';
import {
  assertSecurityPolicy,
  assertSecurityEvent,
  CURRENT_SCHEMA_VERSION,
} from '@ethioshield/security-contracts';
import { EthioShieldExpressMiddleware } from './express.js';
import type { EthioShieldExpressOptions } from './express.js';
export { DetectionEngine, defaultDetectors } from './detection/engine.js';
export type {
  DetectionContext,
  DetectionError,
  DetectionFinding,
  DetectionPlugin,
  DetectionRequest,
  DetectionResult,
} from './detection/types.js';
export type { Detector } from './detection/types.js';
export { asDetectionPlugin, isDetectionPlugin } from './detection/plugin.js';
export { evaluateDetection } from './detection/policy-evaluator.js';
export type { PolicyEvaluation } from './detection/policy-evaluator.js';
export {
  headersParser,
  jsonParser,
  queryParser,
  routeParamsParser,
} from './detection/parsers/index.js';
export type {
  ParsedComponent,
  ParserAdapter,
  ParserError,
  ParserResult,
  SanitizedHeaders,
} from './detection/parsers/index.js';
export { LayeredRateLimiter } from './rate-limit/limiter.js';
export { InMemoryAtomicCounterStore } from './rate-limit/store.js';
export type {
  AtomicCounterStore,
  RateLimitIdentity,
  RateLimitOptions,
  RateLimitOutcome,
  RateLimitRequest,
} from './rate-limit/types.js';
export type { RateLimitConfiguration } from './express.js';
export { resolveNetworkRisk } from './network-intelligence.js';
export type { NetworkIntelligenceResolver } from './network-intelligence.js';
export { InstrumentationHub } from './instrumentation.js';
export type {
  AuthorizationObservation,
  CommandObservation,
  FilesystemObservation,
  InstrumentationFailure,
  InstrumentationObservers,
  InstrumentationOptions,
  InstrumentationResult,
  OutboundHttpObservation,
  SqlObservation,
} from './instrumentation.js';
export { InMemoryCorrelationStore, StatefulCorrelator } from './correlation.js';
export type {
  CorrelationOptions,
  CorrelationOutcome,
  CorrelationRequest,
  CorrelationStore,
} from './correlation.js';
export type { ChallengeAdapter } from './challenge.js';
export { EthioShieldExpressMiddleware, createEthioShieldExpress } from './express.js';
export type {
  DecisionContext,
  EnforcementMode,
  EthioShieldExpress,
  EthioShieldExpressOptions,
  CorrelationConfiguration,
  TelemetryAdapter,
  TrustedProxyConfiguration,
} from './express.js';

export interface RequestInput {
  readonly method: HttpMethod;
  readonly path: string;
}

export interface EvaluationResult {
  readonly decision: SecurityDecision;
  readonly event: SecurityEvent;
}

export type EthioShieldOptions = EthioShieldExpressOptions;

export class EthioShield extends EthioShieldExpressMiddleware {
  private readonly clock: () => Date;
  private readonly eventId: () => string;
  private readonly policy: SecurityPolicy;

  public constructor(options: EthioShieldOptions) {
    super(options);
    assertSecurityPolicy(options.policy);
    this.clock = options.clock ?? (() => new Date());
    this.eventId = options.eventId ?? (() => crypto.randomUUID());
    this.policy = options.policy;
  }

  public evaluate(request: RequestInput): EvaluationResult {
    const decision: SecurityDecision = {
      action: this.policy.defaults.action,
      ruleId: 'policy.default',
      category: 'policy',
      severity: this.policy.defaults.severity,
      policyVersion: this.policy.policyVersion,
      reason: {
        code: 'policy_default',
      },
    };
    const event: SecurityEvent = {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      eventId: this.eventId(),
      projectId: 'local',
      occurredAt: this.clock().toISOString(),
      request: {
        method: request.method,
        route: request.path,
      },
      detection: {
        category: decision.category,
        ruleId: decision.ruleId,
      },
      decision,
      sdkVersion: '0.1.0-alpha.0',
    };

    assertSecurityEvent(event);
    return { decision, event };
  }
}
