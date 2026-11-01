import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/**/*.test.ts'],
    exclude: ['packages/sdk-node/perf/**/*.test.ts'],
  },
});
