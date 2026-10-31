import { describe, expect, it } from 'vitest';
import {
  InMemoryCorrelationStore,
  InMemoryAtomicCounterStore,
  LayeredRateLimiter,
  StatefulCorrelator,
} from '../src/index.js';

describe('stateful key hardening', () => {
  it('does not collide when identifiers contain delimiters', async () => {
    const state = new StatefulCorrelator({
      rules: [
        {
          ruleId: 'target.route',
          dimensions: ['target_account', 'route'],
          windowSeconds: 60,
          maxEvents: 1,
          action: 'block',
        },
      ],
      failureMode: 'block',
    });
    const first = { route: '/x', identity: { targetAccountId: 'a|route=/b' } };
    const second = { route: '/b|route=/x', identity: { targetAccountId: 'a' } };

    expect((await state.check(first, 1_000)).action).toBe('allow');
    expect((await state.check(second, 1_000)).action).toBe('allow');
    expect((await state.check(first, 1_000)).action).toBe('block');
  });

  it('evicts expired correlation entries before enforcing cardinality', async () => {
    const store = new InMemoryCorrelationStore(1);
    await store.increment('first', 1, 1_000);
    const result = await store.increment('second', 1, 3_000);

    expect(result.count).toBe(1);
  });

  it('evicts expired rate-limit entries before enforcing cardinality', async () => {
    const store = new InMemoryAtomicCounterStore(1);
    await store.increment('first', 1, 1_000);
    const result = await store.increment('second', 1, 3_000);

    expect(result.count).toBe(1);
  });

  it('keeps rate-limit dimensions distinct when identifiers contain delimiters', async () => {
    const limiter = new LayeredRateLimiter({
      rules: [
        {
          ruleId: 'target.route',
          keyTypes: ['target_account', 'route'],
          windowSeconds: 60,
          maxRequests: 1,
          action: 'block',
        },
      ],
      failureMode: 'block',
    });
    const first = { route: '/x', identity: { targetAccountId: 'a|route=/b' } };
    const second = { route: '/b|route=/x', identity: { targetAccountId: 'a' } };

    expect((await limiter.check(first, 1_000)).action).toBe('allow');
    expect((await limiter.check(second, 1_000)).action).toBe('allow');
    expect((await limiter.check(first, 1_000)).action).toBe('block');
  });
});
