import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/sdk-node/perf/**/*.test.ts'],
  },
});
