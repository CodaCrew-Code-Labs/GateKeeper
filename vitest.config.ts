import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 10000, // Increased from 5000ms
    hookTimeout: 2000,  // Increased from 1000ms
    bail: 1,
    isolate: true, // Changed from false to true for better isolation
    pool: 'forks', // Use process isolation
    coverage: {
      include: ['src/**/*.ts'],
      exclude: ['example/**/*', 'dist/**/*', 'node_modules/**/*'],
      reporter: ['text', 'html'],
      thresholds: {
        statements: 50,
        branches: 50,
        functions: 50,
        lines: 50
      }
    }
  },
});