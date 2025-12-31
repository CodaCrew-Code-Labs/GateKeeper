import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 5000,
    hookTimeout: 1000,
    bail: 1,
    isolate: false,
    coverage: {
      include: ['src/**/*.ts'],
      exclude: ['example/**/*', 'dist/**/*', 'node_modules/**/*'],
      reporter: ['text', 'html'],
      thresholds: {
        statements: 70,
        branches: 70,
        functions: 70,
        lines: 70
      }
    }
  },
});