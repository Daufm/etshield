import { describe, expect, it } from 'vitest';
import { InMemoryCorrelationStore, StatefulCorrelator } from '../src/index.js';

function correlator(options: Partial<ConstructorParameters<typeof StatefulCorrelator>[0]> = {}) {
  return new StatefulCorrelator({
    rules: [
      {
        ruleId: 'account.targeting',
        dimensions: ['target_account'],
        windowSeconds: 60,
        maxEvents: 2,
        action: 'block',
      },
    ],
    failureMode: 'monitor',
    ...options,
  });
}

describe('StatefulCorrelator', () => {
  it('correlates one target account across different IPs', async () => {
    const state = correlator();
    const results = await Promise.all(
      Array.from({ length: 5 }, (_, index) =>
        state.check({
          route: '/login',
          ip: `198.51.100.${index + 1}`,
          identity: { targetAccountId: 'account-1' },
        }),
      ),
    );

    expect(results.filter((result) => result.action === 'block')).toHaveLength(3);
  });

  it('keeps authenticated subjects separate behind one NAT IP', async () => {
    const state = correlator({
      rules: [
        {
          ruleId: 'user.behavior',
          dimensions: ['authenticated_user', 'route'],
          windowSeconds: 60,
          maxEvents: 1,
          action: 'throttle',
        },
      ],
    });
    const results = await Promise.all(
      Array.from({ length: 2_000 }, (_, index) =>
        state.check({
          route: '/profile',
          ip: '203.0.113.1',
          identity: { authenticatedUserId: `user-${index}` },
        }),
      ),
    );

    expect(results.every((result) => result.action === 'allow')).toBe(true);
  });

  it('applies route and risk thresholds before counting', async () => {
    const state = correlator({
      rules: [
        {
          ruleId: 'risky.login',
          dimensions: ['target_account', 'route'],
          windowSeconds: 60,
          maxEvents: 1,
          action: 'block',
          route: '/login',
          riskThreshold: 0.8,
        },
      ],
    });

    expect(
      (
        await state.check({
          route: '/health',
          identity: { targetAccountId: 'account-1' },
          riskScore: 1,
        })
      ).action,
    ).toBe('allow');
    expect(
      (
        await state.check({
          route: '/login',
          identity: { targetAccountId: 'account-1' },
          riskScore: 0.7,
        })
      ).action,
    ).toBe('allow');
    await state.check({
      route: '/login',
      identity: { targetAccountId: 'account-1' },
      riskScore: 0.9,
    });
    expect(
      (
        await state.check({
          route: '/login',
          identity: { targetAccountId: 'account-1' },
          riskScore: 0.9,
        })
      ).action,
    ).toBe('block');
  });

  it('expires counters and deterministically handles cardinality limits', async () => {
    const state = correlator({
      maxKeys: 1,
      store: new InMemoryCorrelationStore(1),
    });
    expect(
      (
        await state.check(
          {
            route: '/login',
            identity: { targetAccountId: 'account-1' },
          },
          1_000,
        )
      ).action,
    ).toBe('allow');
    expect(
      (
        await state.check(
          {
            route: '/login',
            identity: { targetAccountId: 'account-1' },
          },
          62_000,
        )
      ).action,
    ).toBe('allow');
    expect(
      (
        await state.check(
          {
            route: '/login',
            identity: { targetAccountId: 'account-2' },
          },
          62_000,
        )
      ).action,
    ).toBe('monitor');
  });

  it('does not use IP as a substitute for missing trusted identity', async () => {
    const state = correlator();
    const result = await state.check({ route: '/login', ip: '198.51.100.1' });

    expect(result.action).toBe('allow');
  });
});
