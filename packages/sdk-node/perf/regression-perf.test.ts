import { describe, expect, it } from 'vitest';
import { DetectionEngine, InMemoryAtomicCounterStore } from '../src/index.js';

type AsyncTest = () => void | Promise<void>;

async function knownBug(id: string, fn: AsyncTest): Promise<void> {
  try {
    await fn();
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      'name' in error &&
      error.name === 'AssertionError'
    ) {
      return;
    }
    throw error;
  }
  throw new Error(`${id} now passes: remove knownBug wrapper`);
}

describe('architecture review performance regressions', () => {
  // Observed today: about 6,400 ms.
  it('A2', () => {
    return knownBug('A2', () => {
      const durations: number[] = [];
      let result: ReturnType<DetectionEngine['inspect']> | undefined;
      for (let run = 0; run < 3; run += 1) {
        const engine = new DetectionEngine();
        const started = performance.now();
        result = engine.inspect({
          method: 'POST',
          route: '/bulk',
          body: { values: Array.from({ length: 20 }, () => '<a'.repeat(8_000)) },
        });
        durations.push(performance.now() - started);
      }
      expect(result?.status).toBe('complete');
      expect(Math.min(...durations)).toBeLessThan(1_000);
    });
  }, 120_000);

  // Observed today: about 100x slower at 10k keys.
  it('A3', async () => {
    await knownBug('A3', async () => {
      const populatedDurations: number[] = [];
      const smallDurations: number[] = [];
      for (let run = 0; run < 3; run += 1) {
        const populated = new InMemoryAtomicCounterStore(10_000);
        for (let index = 0; index < 9_999; index += 1) {
          await populated.increment(`key-${index}`, 60, 0);
        }
        const populatedStarted = performance.now();
        for (let index = 0; index < 200; index += 1) {
          await populated.increment('hot-key', 60, 0);
        }
        populatedDurations.push(performance.now() - populatedStarted);

        const small = new InMemoryAtomicCounterStore(10_000);
        await small.increment('hot-key', 60, 0);
        const smallStarted = performance.now();
        for (let index = 0; index < 200; index += 1) {
          await small.increment('hot-key', 60, 0);
        }
        smallDurations.push(performance.now() - smallStarted);
      }
      expect(Math.min(...populatedDurations)).toBeLessThanOrEqual(
        Math.max(Math.min(...smallDurations), 0.01) * 20,
      );
    });
  }, 120_000);
});
