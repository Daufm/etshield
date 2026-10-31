import { describe, expect, it } from 'vitest';
import { InMemoryAtomicCounterStore, LayeredRateLimiter } from '../src/index.js';

function limiter(options: Partial<ConstructorParameters<typeof LayeredRateLimiter>[0]> = {}) {
  return new LayeredRateLimiter({
    rules: [
      {
        ruleId: 'account.login',
        keyTypes: ['target_account', 'route'],
        windowSeconds: 60,
        maxRequests: 5,
        action: 'throttle',
      },
    ],
    failureMode: 'block',
    ...options,
  });
}

describe('LayeredRateLimiter', () => {
  it('limits one target account across many IPs', async () => {
    const rateLimiter = limiter();
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        rateLimiter.check({
          route: '/login',
          ip: `198.51.100.${index + 1}`,
          identity: { targetAccountId: 'account-1' },
        }),
      ),
    );

    expect(results.filter((result) => result.action === 'throttle')).toHaveLength(5);
  });

  it('keeps separate authenticated users behind one carrier NAT independent', async () => {
    const rateLimiter = new LayeredRateLimiter({
      rules: [
        {
          ruleId: 'user.login',
          keyTypes: ['authenticated_user'],
          windowSeconds: 60,
          maxRequests: 1,
          action: 'block',
        },
      ],
      failureMode: 'block',
    });
    const results = await Promise.all(
      Array.from({ length: 2_000 }, (_, index) =>
        rateLimiter.check({
          route: '/login',
          ip: '203.0.113.1',
          identity: { authenticatedUserId: `user-${index}` },
        }),
      ),
    );

    expect(results.every((result) => result.action === 'allow')).toBe(true);
  });

  it('expires counters and applies deterministic cardinality outage behavior', async () => {
    const rateLimiter = limiter({
      maxKeys: 1,
      store: new InMemoryAtomicCounterStore(1),
    });
    const first = await rateLimiter.check(
      {
        route: '/login',
        identity: { targetAccountId: 'account-1' },
      },
      1_000,
    );
    const expired = await rateLimiter.check(
      {
        route: '/login',
        identity: { targetAccountId: 'account-1' },
      },
      62_000,
    );
    const exhausted = await rateLimiter.check(
      {
        route: '/login',
        identity: { targetAccountId: 'account-2' },
      },
      62_000,
    );

    expect(first.action).toBe('allow');
    expect(expired.action).toBe('allow');
    expect(exhausted).toMatchObject({
      action: 'block',
      storeError: true,
    });
  });

  it('does not trust missing or arbitrary identity values', async () => {
    const rateLimiter = limiter();
    const result = await rateLimiter.check({
      route: '/login',
      ip: '198.51.100.1',
      identity: {},
    });

    expect(result.action).toBe('allow');
  });

  it('holds one account limit across 300 rotating VPN addresses', async () => {
    const rateLimiter = limiter({
      rules: [
        {
          ruleId: 'account.login',
          keyTypes: ['target_account'],
          windowSeconds: 60,
          maxRequests: 10,
          action: 'block',
        },
      ],
    });
    const results = await Promise.all(
      Array.from({ length: 300 }, (_, index) =>
        rateLimiter.check({
          route: '/login',
          ip: `2001:db8::${index + 1}`,
          identity: { targetAccountId: 'account-targeted' },
        }),
      ),
    );

    expect(results.filter((result) => result.action === 'block')).toHaveLength(290);
  });

  it('does not depend on spoofable user-agent or language headers', async () => {
    const rateLimiter = limiter({
      rules: [
        {
          ruleId: 'account.login',
          keyTypes: ['target_account'],
          windowSeconds: 60,
          maxRequests: 1,
          action: 'block',
        },
      ],
    });
    const first = await rateLimiter.check({
      route: '/login',
      ip: '198.51.100.1',
      identity: { targetAccountId: 'account-1' },
    });
    const second = await rateLimiter.check({
      route: '/login',
      ip: '198.51.100.2',
      identity: { targetAccountId: 'account-1' },
    });

    expect(first.action).toBe('allow');
    expect(second.action).toBe('block');
  });

  it('keeps local account protection when residential intelligence is absent', async () => {
    const rateLimiter = limiter({
      rules: [
        {
          ruleId: 'account.login',
          keyTypes: ['target_account'],
          windowSeconds: 60,
          maxRequests: 1,
          action: 'block',
        },
      ],
    });
    await rateLimiter.check({
      route: '/login',
      ip: '198.51.100.20',
      identity: { targetAccountId: 'account-1' },
    });
    const result = await rateLimiter.check({
      route: '/login',
      ip: '198.51.100.21',
      identity: { targetAccountId: 'account-1' },
    });

    expect(result.action).toBe('block');
  });
});
