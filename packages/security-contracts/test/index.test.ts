import { describe, expect, it } from 'vitest';
import {
  assertSecurityDecision,
  assertSecurityEvent,
  assertSecurityPolicy,
  ContractValidationError,
  isCredentialMetadata,
  isProjectMetadata,
  isSecurityEvent,
  isSecurityPolicy,
} from '../src/index.js';
import { representativeEvent, representativePolicy } from './fixtures.js';

describe('security contracts', () => {
  it('accepts representative event and policy fixtures', () => {
    expect(isSecurityEvent(representativeEvent)).toBe(true);
    expect(isSecurityPolicy(representativePolicy)).toBe(true);
  });

  it('validates project and credential metadata without secret fields', () => {
    expect(isProjectMetadata({ projectId: 'proj_01', environment: 'production' })).toBe(true);
    expect(
      isCredentialMetadata({
        credentialId: 'cred_01',
        projectId: 'proj_01',
        scope: 'telemetry:write',
        status: 'active',
        createdAt: '2026-10-31T05:00:00.000Z',
      }),
    ).toBe(true);
  });

  it('rejects unsupported schema versions and unknown fields', () => {
    expect(isSecurityEvent({ ...representativeEvent, schemaVersion: '2.0' })).toBe(false);
    expect(isSecurityPolicy({ ...representativePolicy, unexpected: true })).toBe(false);
  });

  it('rejects unsafe routes, unbounded collections, and sensitive metadata', () => {
    expect(
      isSecurityPolicy({
        ...representativePolicy,
        routeExclusions: [{ route: '/orders?user=secret' }],
      }),
    ).toBe(false);
    expect(
      isSecurityPolicy({
        ...representativePolicy,
        rules: Array.from({ length: 51 }, () => representativePolicy.rules[0]),
      }),
    ).toBe(false);
    expect(
      isSecurityEvent({
        ...representativeEvent,
        decision: {
          ...representativeEvent.decision,
          reason: { code: 'bad', attributes: { authorization: 'Bearer value' } },
        },
      }),
    ).toBe(false);
  });

  it('rejects client-controlled plan and entitlement metadata', () => {
    expect(
      isProjectMetadata({ projectId: 'proj_01', environment: 'production', plan: 'enterprise' }),
    ).toBe(false);
    expect(
      isCredentialMetadata({
        credentialId: 'cred_01',
        projectId: 'proj_01',
        scope: 'telemetry:write',
        status: 'active',
        createdAt: 'not-a-date',
        plan: 'enterprise',
        entitlements: ['unlimited'],
      }),
    ).toBe(false);
  });

  it('throws explicit validation errors at assertion boundaries', () => {
    expect(() => assertSecurityEvent({})).toThrow(ContractValidationError);
    expect(() => assertSecurityPolicy({})).toThrow('Invalid SecurityPolicy');
    expect(() => assertSecurityDecision({})).toThrow('Invalid SecurityDecision');
  });
});
