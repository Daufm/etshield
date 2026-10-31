export const CURRENT_SCHEMA_VERSION = '1.0' as const;
export const MAX_STRING_LENGTH = 256;
export const MAX_ROUTE_LENGTH = 512;
export const MAX_COLLECTION_SIZE = 50;
export const MAX_METADATA_ENTRIES = 20;

export type SchemaVersion = typeof CURRENT_SCHEMA_VERSION;
export type SecurityAction = 'allow' | 'monitor' | 'throttle' | 'block' | 'challenge';
export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';
export type RuleCategory =
  | 'authentication'
  | 'authorization'
  | 'input'
  | 'rate_limit'
  | 'webhook'
  | 'policy'
  | 'telemetry'
  | 'other';
export type EnforcementMode = 'enforce' | 'monitor';
export type CredentialScope = 'telemetry:write' | 'policy:read';
export type CredentialStatus = 'active' | 'revoked' | 'expired';
export type RateLimitKeyStrategy = 'ip' | 'project' | 'authenticated_subject';
export type RateLimitKeyType =
  | 'authenticated_user'
  | 'verified_api_key'
  | 'session'
  | 'target_account'
  | 'route'
  | 'ip'
  | 'network';
export type RateLimitFailureMode = 'monitor' | 'block';
export type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';

export interface SanitizedReasonMetadata {
  readonly code: string;
  readonly message?: string;
  readonly attributes?: Readonly<Record<string, string | number | boolean>>;
}

export interface SecurityDecision {
  readonly action: SecurityAction;
  readonly ruleId: string;
  readonly category: RuleCategory;
  readonly confidence?: number;
  readonly severity?: SecuritySeverity;
  readonly policyVersion: string;
  readonly reason: SanitizedReasonMetadata;
}

export interface SanitizedClientMetadata {
  readonly ip?: string;
  readonly userAgent?: string;
  readonly fingerprint?: string;
}

export interface SecurityEvent {
  readonly schemaVersion: SchemaVersion;
  readonly eventId: string;
  readonly projectId: string;
  readonly occurredAt: string;
  readonly request: {
    readonly method: HttpMethod;
    readonly route: string;
  };
  readonly detection: {
    readonly category: RuleCategory;
    readonly ruleId: string;
  };
  readonly decision: SecurityDecision;
  readonly client?: SanitizedClientMetadata;
  readonly sdkVersion: string;
}

export interface RuleSetting {
  readonly ruleId: string;
  readonly category: RuleCategory;
  readonly enabled: boolean;
  readonly action: SecurityAction;
  readonly severity?: SecuritySeverity;
  readonly confidenceThreshold?: number;
}

export interface RouteExclusion {
  readonly route: string;
  readonly methods?: readonly HttpMethod[];
}

export interface RateLimitConfiguration {
  readonly enabled: boolean;
  readonly windowSeconds: number;
  readonly maxRequests: number;
  readonly keyStrategy: RateLimitKeyStrategy;
  readonly rules?: readonly RateLimitRule[];
  readonly failureMode?: RateLimitFailureMode;
}

export interface RateLimitRule {
  readonly ruleId: string;
  readonly keyTypes: readonly RateLimitKeyType[];
  readonly windowSeconds: number;
  readonly maxRequests: number;
  readonly action: Extract<SecurityAction, 'monitor' | 'throttle' | 'block' | 'challenge'>;
  readonly route?: string;
  readonly riskThreshold?: number;
}

export interface RiskSignal {
  readonly kind: 'network_intelligence';
  readonly classification: 'vpn' | 'proxy' | 'tor' | 'hosting' | 'residential' | 'unknown';
  readonly confidence: number;
  readonly provenance: string;
  readonly observedAt: string;
  readonly expiresAt: string;
}

export interface SecurityPolicyDefaults {
  readonly action: SecurityAction;
  readonly severity: SecuritySeverity;
  readonly maxRequestBodyBytes: number;
}

export interface SecurityPolicy {
  readonly schemaVersion: SchemaVersion;
  readonly policyVersion: string;
  readonly enforcementMode: EnforcementMode;
  readonly defaults: SecurityPolicyDefaults;
  readonly rules: readonly RuleSetting[];
  readonly routeExclusions: readonly RouteExclusion[];
  readonly rateLimit: RateLimitConfiguration;
}

export interface ProjectMetadata {
  readonly projectId: string;
  readonly environment: string;
}

export interface CredentialMetadata {
  readonly credentialId: string;
  readonly projectId: string;
  readonly scope: CredentialScope;
  readonly status: CredentialStatus;
  readonly createdAt: string;
  readonly rotatedAt?: string;
  readonly revokedAt?: string;
  readonly expiresAt?: string;
}

export class ContractValidationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'ContractValidationError';
  }
}

type JsonRecord = Record<string, unknown>;

const ACTIONS: readonly SecurityAction[] = ['allow', 'monitor', 'throttle', 'block', 'challenge'];
const CATEGORIES: readonly RuleCategory[] = [
  'authentication',
  'authorization',
  'input',
  'rate_limit',
  'webhook',
  'policy',
  'telemetry',
  'other',
];
const SEVERITIES: readonly SecuritySeverity[] = ['low', 'medium', 'high', 'critical'];
const METHODS: readonly HttpMethod[] = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const FORBIDDEN_KEY_PATTERN =
  /(?:api.?key|authorization|cookie|password|secret|token|payment|request.?body|raw.?body)/i;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: unknown, maximum = MAX_STRING_LENGTH): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum;
}

function isEnum<T extends string>(value: unknown, values: readonly T[]): value is T {
  return typeof value === 'string' && values.includes(value as T);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function hasOnlyKeys(value: JsonRecord, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function hasSafeKey(key: string): boolean {
  return isString(key, 64) && !FORBIDDEN_KEY_PATTERN.test(key);
}

function validateMetadata(value: unknown): value is SanitizedReasonMetadata {
  if (!isRecord(value) || !hasOnlyKeys(value, ['code', 'message', 'attributes'])) {
    return false;
  }
  if (!isString(value.code, 64) || (value.message !== undefined && !isString(value.message))) {
    return false;
  }
  if (value.attributes !== undefined) {
    if (
      !isRecord(value.attributes) ||
      Object.keys(value.attributes).length > MAX_METADATA_ENTRIES
    ) {
      return false;
    }
    for (const [key, attribute] of Object.entries(value.attributes)) {
      if (
        !hasSafeKey(key) ||
        !(
          (typeof attribute === 'string' && isString(attribute)) ||
          (typeof attribute === 'number' && Number.isFinite(attribute)) ||
          typeof attribute === 'boolean'
        )
      ) {
        return false;
      }
    }
  }
  return true;
}

function validateVersion(value: unknown): value is string {
  return isString(value, 32) && /^\d+\.\d+$/.test(value);
}

function validateIdentifier(value: unknown): value is string {
  return isString(value, 128) && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value);
}

function validateTimestamp(value: unknown): value is string {
  return isString(value, 64) && !Number.isNaN(Date.parse(value));
}

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0);
    return code !== undefined && (code <= 0x1f || code === 0x7f);
  });
}

function validateRoute(value: unknown): value is string {
  return (
    isString(value, MAX_ROUTE_LENGTH) &&
    value.startsWith('/') &&
    !value.includes('?') &&
    !value.includes('#') &&
    !value.includes('//') &&
    !hasControlCharacters(value)
  );
}

export function isHttpMethod(value: unknown): value is HttpMethod {
  return isEnum(value, METHODS);
}

function validateDecision(value: unknown): value is SecurityDecision {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      'action',
      'ruleId',
      'category',
      'confidence',
      'severity',
      'policyVersion',
      'reason',
    ])
  ) {
    return false;
  }
  return (
    isEnum(value.action, ACTIONS) &&
    validateIdentifier(value.ruleId) &&
    isEnum(value.category, CATEGORIES) &&
    (value.confidence === undefined ||
      (isFiniteNumber(value.confidence) && value.confidence >= 0 && value.confidence <= 1)) &&
    (value.severity === undefined || isEnum(value.severity, SEVERITIES)) &&
    validateVersion(value.policyVersion) &&
    validateMetadata(value.reason)
  );
}

export function isSecurityDecision(value: unknown): value is SecurityDecision {
  return validateDecision(value);
}

export function assertSecurityDecision(value: unknown): asserts value is SecurityDecision {
  if (!validateDecision(value)) {
    throw new ContractValidationError('Invalid SecurityDecision');
  }
}

export function isSecurityEvent(value: unknown): value is SecurityEvent {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      'schemaVersion',
      'eventId',
      'projectId',
      'occurredAt',
      'request',
      'detection',
      'decision',
      'client',
      'sdkVersion',
    ])
  ) {
    return false;
  }
  if (
    value.schemaVersion !== CURRENT_SCHEMA_VERSION ||
    !validateIdentifier(value.eventId) ||
    !validateIdentifier(value.projectId) ||
    !validateTimestamp(value.occurredAt) ||
    !isRecord(value.request) ||
    !hasOnlyKeys(value.request, ['method', 'route']) ||
    !isEnum(value.request.method, METHODS) ||
    !validateRoute(value.request.route) ||
    !isRecord(value.detection) ||
    !hasOnlyKeys(value.detection, ['category', 'ruleId']) ||
    !isEnum(value.detection.category, CATEGORIES) ||
    !validateIdentifier(value.detection.ruleId) ||
    !validateDecision(value.decision) ||
    !isString(value.sdkVersion, 64)
  ) {
    return false;
  }
  if (value.client !== undefined) {
    if (!isRecord(value.client) || !hasOnlyKeys(value.client, ['ip', 'userAgent', 'fingerprint'])) {
      return false;
    }
    if (
      (value.client.ip !== undefined && !isString(value.client.ip, 64)) ||
      (value.client.userAgent !== undefined && !isString(value.client.userAgent, 256)) ||
      (value.client.fingerprint !== undefined && !isString(value.client.fingerprint, 128))
    ) {
      return false;
    }
  }
  return true;
}

export function assertSecurityEvent(value: unknown): asserts value is SecurityEvent {
  if (!isSecurityEvent(value)) {
    throw new ContractValidationError('Invalid SecurityEvent');
  }
}

function validatePolicy(value: unknown): value is SecurityPolicy {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      'schemaVersion',
      'policyVersion',
      'enforcementMode',
      'defaults',
      'rules',
      'routeExclusions',
      'rateLimit',
    ]) ||
    value.schemaVersion !== CURRENT_SCHEMA_VERSION ||
    !validateVersion(value.policyVersion) ||
    !isEnum(value.enforcementMode, ['enforce', 'monitor'])
  ) {
    return false;
  }
  if (
    !isRecord(value.defaults) ||
    !hasOnlyKeys(value.defaults, ['action', 'severity', 'maxRequestBodyBytes']) ||
    !isEnum(value.defaults.action, ACTIONS) ||
    !isEnum(value.defaults.severity, SEVERITIES) ||
    !isFiniteNumber(value.defaults.maxRequestBodyBytes) ||
    value.defaults.maxRequestBodyBytes < 0 ||
    value.defaults.maxRequestBodyBytes > 10_485_760
  ) {
    return false;
  }
  if (!Array.isArray(value.rules) || value.rules.length > MAX_COLLECTION_SIZE) {
    return false;
  }
  for (const rule of value.rules) {
    if (
      !isRecord(rule) ||
      !hasOnlyKeys(rule, [
        'ruleId',
        'category',
        'enabled',
        'action',
        'severity',
        'confidenceThreshold',
      ]) ||
      !validateIdentifier(rule.ruleId) ||
      !isEnum(rule.category, CATEGORIES) ||
      typeof rule.enabled !== 'boolean' ||
      !isEnum(rule.action, ACTIONS) ||
      (rule.severity !== undefined && !isEnum(rule.severity, SEVERITIES)) ||
      (rule.confidenceThreshold !== undefined &&
        (!isFiniteNumber(rule.confidenceThreshold) ||
          rule.confidenceThreshold < 0 ||
          rule.confidenceThreshold > 1))
    ) {
      return false;
    }
  }
  if (!Array.isArray(value.routeExclusions) || value.routeExclusions.length > MAX_COLLECTION_SIZE) {
    return false;
  }
  for (const exclusion of value.routeExclusions) {
    if (
      !isRecord(exclusion) ||
      !hasOnlyKeys(exclusion, ['route', 'methods']) ||
      !validateRoute(exclusion.route) ||
      (exclusion.methods !== undefined &&
        (!Array.isArray(exclusion.methods) ||
          exclusion.methods.length > METHODS.length ||
          exclusion.methods.some((method) => !isEnum(method, METHODS))))
    ) {
      return false;
    }
  }
  if (
    !isRecord(value.rateLimit) ||
    !hasOnlyKeys(value.rateLimit, [
      'enabled',
      'windowSeconds',
      'maxRequests',
      'keyStrategy',
      'rules',
      'failureMode',
    ]) ||
    typeof value.rateLimit.enabled !== 'boolean' ||
    !isFiniteNumber(value.rateLimit.windowSeconds) ||
    value.rateLimit.windowSeconds < 1 ||
    value.rateLimit.windowSeconds > 86_400 ||
    !isFiniteNumber(value.rateLimit.maxRequests) ||
    value.rateLimit.maxRequests < 1 ||
    value.rateLimit.maxRequests > 1_000_000 ||
    !isEnum(value.rateLimit.keyStrategy, ['ip', 'project', 'authenticated_subject']) ||
    (value.rateLimit.failureMode !== undefined &&
      !isEnum(value.rateLimit.failureMode, ['monitor', 'block']))
  ) {
    return false;
  }
  if (value.rateLimit.rules !== undefined) {
    if (
      !Array.isArray(value.rateLimit.rules) ||
      value.rateLimit.rules.length > MAX_COLLECTION_SIZE
    ) {
      return false;
    }
    for (const rule of value.rateLimit.rules) {
      if (
        !isRecord(rule) ||
        !hasOnlyKeys(rule, [
          'ruleId',
          'keyTypes',
          'windowSeconds',
          'maxRequests',
          'action',
          'route',
          'riskThreshold',
        ]) ||
        !validateIdentifier(rule.ruleId) ||
        !Array.isArray(rule.keyTypes) ||
        rule.keyTypes.length === 0 ||
        rule.keyTypes.length > 7 ||
        rule.keyTypes.some(
          (keyType) =>
            !isEnum(keyType, [
              'authenticated_user',
              'verified_api_key',
              'session',
              'target_account',
              'route',
              'ip',
              'network',
            ]),
        ) ||
        !isFiniteNumber(rule.windowSeconds) ||
        rule.windowSeconds < 1 ||
        rule.windowSeconds > 86_400 ||
        !isFiniteNumber(rule.maxRequests) ||
        rule.maxRequests < 1 ||
        rule.maxRequests > 1_000_000 ||
        !isEnum(rule.action, ['monitor', 'throttle', 'block', 'challenge']) ||
        (rule.route !== undefined && !validateRoute(rule.route)) ||
        (rule.riskThreshold !== undefined &&
          (!isFiniteNumber(rule.riskThreshold) || rule.riskThreshold < 0 || rule.riskThreshold > 1))
      ) {
        return false;
      }
    }
  }
  return true;
}

export function isSecurityPolicy(value: unknown): value is SecurityPolicy {
  return validatePolicy(value);
}

export function assertSecurityPolicy(value: unknown): asserts value is SecurityPolicy {
  if (!validatePolicy(value)) {
    throw new ContractValidationError('Invalid SecurityPolicy');
  }
}

export function isProjectMetadata(value: unknown): value is ProjectMetadata {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, ['projectId', 'environment']) &&
    validateIdentifier(value.projectId) &&
    validateIdentifier(value.environment)
  );
}

export function isCredentialMetadata(value: unknown): value is CredentialMetadata {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, [
      'credentialId',
      'projectId',
      'scope',
      'status',
      'createdAt',
      'rotatedAt',
      'revokedAt',
      'expiresAt',
    ]) &&
    validateIdentifier(value.credentialId) &&
    validateIdentifier(value.projectId) &&
    isEnum(value.scope, ['telemetry:write', 'policy:read']) &&
    isEnum(value.status, ['active', 'revoked', 'expired']) &&
    validateTimestamp(value.createdAt) &&
    (value.rotatedAt === undefined || validateTimestamp(value.rotatedAt)) &&
    (value.revokedAt === undefined || validateTimestamp(value.revokedAt)) &&
    (value.expiresAt === undefined || validateTimestamp(value.expiresAt))
  );
}
