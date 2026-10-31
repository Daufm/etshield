import type { AtomicCounterStore, CounterResult } from './types.js';
import { MAX_COUNTER_KEYS } from './types.js';

interface CounterEntry {
  count: number;
  resetAt: number;
}

export class InMemoryAtomicCounterStore implements AtomicCounterStore {
  private readonly counters = new Map<string, CounterEntry>();
  private readonly maxKeys: number;

  public constructor(maxKeys = MAX_COUNTER_KEYS) {
    if (!Number.isInteger(maxKeys) || maxKeys < 1 || maxKeys > MAX_COUNTER_KEYS) {
      throw new TypeError(`maxKeys must be an integer between 1 and ${MAX_COUNTER_KEYS}`);
    }
    this.maxKeys = maxKeys;
  }

  public async increment(key: string, windowSeconds: number, now: number): Promise<CounterResult> {
    for (const [counterKey, counter] of this.counters) {
      if (counter.resetAt <= now) this.counters.delete(counterKey);
    }
    const resetAt = now + windowSeconds * 1_000;
    const current = this.counters.get(key);
    if (current === undefined || current.resetAt <= now) {
      if (current === undefined && this.counters.size >= this.maxKeys) {
        throw new Error('counter cardinality limit reached');
      }
      const next = { count: 1, resetAt };
      this.counters.set(key, next);
      return { ...next, limit: Number.MAX_SAFE_INTEGER };
    }
    current.count += 1;
    return { ...current, limit: Number.MAX_SAFE_INTEGER };
  }

  public close(): void {
    this.counters.clear();
  }
}
