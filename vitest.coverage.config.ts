import { defineConfig, mergeConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

export default mergeConfig(
  baseConfig,
  defineConfig({
    test: {
      coverage: {
        provider: 'v8',
        reporter: ['text', 'json-summary'],
        include: ['packages/*/src/**/*.ts'],
        exclude: ['**/*.d.ts'],
        thresholds: {
          lines: 70,
          functions: 70,
          statements: 70,
          branches: 60,
        },
      },
    },
  }),
);
