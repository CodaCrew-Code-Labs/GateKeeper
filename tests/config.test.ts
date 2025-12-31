// Property-based tests for configuration validation
// Feature: cognito-auth-package, Property 1: Configuration Validation Completeness
// Validates: Requirements 4.1, 4.2, 4.4

import { describe, test, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  validateCognitoConfig,
  loadConfigFromEnv,
  mergeConfigs,
  isValidConfig,
  ENV_VAR_NAMES,
} from '../src/config.js';

describe('Feature: cognito-auth-package, Property 1: Configuration Validation Completeness', () => {
  test('should validate complete configurations and reject incomplete ones', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate valid configuration objects
        fc.record({
          userPoolId: fc
            .string({ minLength: 1 })
            .map(s => `us-east-1_${s.replace(/[^a-zA-Z0-9]/g, 'A')}`),
          clientId: fc
            .string({ minLength: 1 })
            .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
          clientSecret: fc.option(fc.string({ minLength: 1 }), { nil: undefined }),
          region: fc.constantFrom('us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'),
        }),
        // Generate invalid configuration objects (missing required fields)
        fc.oneof(
          fc.record({
            // Missing userPoolId
            clientId: fc
              .string({ minLength: 1 })
              .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
            region: fc.constantFrom('us-east-1', 'us-west-2'),
          }),
          fc.record({
            // Missing clientId
            userPoolId: fc
              .string({ minLength: 1 })
              .map(s => `us-east-1_${s.replace(/[^a-zA-Z0-9]/g, 'A')}`),
            region: fc.constantFrom('us-east-1', 'us-west-2'),
          }),
          fc.record({
            // Missing region
            userPoolId: fc
              .string({ minLength: 1 })
              .map(s => `us-east-1_${s.replace(/[^a-zA-Z0-9]/g, 'A')}`),
            clientId: fc
              .string({ minLength: 1 })
              .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
          }),
          fc.record({
            // Empty required fields
            userPoolId: fc.constant(''),
            clientId: fc
              .string({ minLength: 1 })
              .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
            region: fc.constantFrom('us-east-1', 'us-west-2'),
          })
        ),
        async (validConfig, invalidConfig) => {
          // Test that valid configurations pass validation
          const result = validateCognitoConfig(validConfig);
          expect(result).toEqual(validConfig);
          expect(result.userPoolId).toBe(validConfig.userPoolId);
          expect(result.clientId).toBe(validConfig.clientId);
          expect(result.region).toBe(validConfig.region);
          if (validConfig.clientSecret) {
            expect(result.clientSecret).toBe(validConfig.clientSecret);
          }

          // Test that isValidConfig returns true for valid configs
          expect(isValidConfig(validConfig)).toBe(true);

          // Test that invalid configurations fail validation
          expect(() => validateCognitoConfig(invalidConfig)).toThrow();
          expect(isValidConfig(invalidConfig)).toBe(false);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  test('should handle environment variable loading correctly', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          [ENV_VAR_NAMES.USER_POOL_ID]: fc
            .string({ minLength: 1 })
            .map(s => `us-east-1_${s.replace(/[^a-zA-Z0-9]/g, 'A')}`),
          [ENV_VAR_NAMES.CLIENT_ID]: fc
            .string({ minLength: 1 })
            .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
          [ENV_VAR_NAMES.CLIENT_SECRET]: fc.option(fc.string({ minLength: 1 }), { nil: undefined }),
          [ENV_VAR_NAMES.REGION]: fc.constantFrom('us-east-1', 'us-west-2', 'eu-west-1'),
          // Add some extra environment variables that should be ignored
          OTHER_VAR: fc.option(fc.string(), { nil: undefined }),
          RANDOM_VAR: fc.option(fc.string(), { nil: undefined }),
        }),
        async envVars => {
          // Filter out undefined values for the test
          const cleanEnv = Object.fromEntries(
            Object.entries(envVars).filter(([_, value]) => value !== undefined)
          ) as Record<string, string>;

          if (
            cleanEnv[ENV_VAR_NAMES.USER_POOL_ID] &&
            cleanEnv[ENV_VAR_NAMES.CLIENT_ID] &&
            cleanEnv[ENV_VAR_NAMES.REGION]
          ) {
            // Should successfully load valid environment configuration
            const config = loadConfigFromEnv(cleanEnv);

            expect(config.userPoolId).toBe(cleanEnv[ENV_VAR_NAMES.USER_POOL_ID]);
            expect(config.clientId).toBe(cleanEnv[ENV_VAR_NAMES.CLIENT_ID]);
            expect(config.region).toBe(cleanEnv[ENV_VAR_NAMES.REGION]);

            if (cleanEnv[ENV_VAR_NAMES.CLIENT_SECRET]) {
              expect(config.clientSecret).toBe(cleanEnv[ENV_VAR_NAMES.CLIENT_SECRET]);
            } else {
              expect(config.clientSecret).toBeUndefined();
            }
          } else {
            // Should fail when required environment variables are missing
            expect(() => loadConfigFromEnv(cleanEnv)).toThrow();
          }

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  test('should merge configurations with proper precedence', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.record({
          userPoolId: fc
            .string({ minLength: 1 })
            .map(s => `us-east-1_${s.replace(/[^a-zA-Z0-9]/g, 'A')}`),
          clientId: fc
            .string({ minLength: 1 })
            .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
          region: fc.constantFrom('us-east-1', 'us-west-2'),
        }),
        fc.record({
          clientSecret: fc.string({ minLength: 1 }),
          region: fc.constantFrom('eu-west-1', 'ap-southeast-1'), // Different region to test override
        }),
        async (baseConfig, overrideConfig) => {
          // Test that later sources override earlier ones
          const merged = mergeConfigs(baseConfig, overrideConfig);

          // Base config values should be preserved where not overridden
          expect(merged.userPoolId).toBe(baseConfig.userPoolId);
          expect(merged.clientId).toBe(baseConfig.clientId);

          // Override config values should take precedence
          expect(merged.region).toBe(overrideConfig.region);
          expect(merged.clientSecret).toBe(overrideConfig.clientSecret);

          // Test merging with undefined sources
          const mergedWithUndefined = mergeConfigs(baseConfig, undefined, overrideConfig);
          expect(mergedWithUndefined).toEqual(merged);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  test('should validate field formats according to AWS requirements', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate invalid formats that should be rejected
        fc.oneof(
          // Invalid userPoolId formats
          fc.record({
            userPoolId: fc.oneof(
              fc.string({ minLength: 1 }).filter(s => !s.includes('_')), // Missing underscore
              fc.constant('_invalid'), // Starts with underscore
              fc.constant('region_'), // Ends with underscore
              fc.string().filter(s => s.includes(' ')) // Contains spaces
            ),
            clientId: fc
              .string({ minLength: 1 })
              .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
            region: fc.constantFrom('us-east-1', 'us-west-2'),
          }),
          // Invalid clientId formats
          fc.record({
            userPoolId: fc
              .string({ minLength: 1 })
              .map(s => `us-east-1_${s.replace(/[^a-zA-Z0-9]/g, 'A')}`),
            clientId: fc.oneof(
              fc.string().filter(s => /[A-Z]/.test(s)), // Contains uppercase
              fc.string().filter(s => /[^a-z0-9]/.test(s) && s.length > 0) // Contains special chars
            ),
            region: fc.constantFrom('us-east-1', 'us-west-2'),
          }),
          // Invalid region formats
          fc.record({
            userPoolId: fc
              .string({ minLength: 1 })
              .map(s => `us-east-1_${s.replace(/[^a-zA-Z0-9]/g, 'A')}`),
            clientId: fc
              .string({ minLength: 1 })
              .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
            region: fc.oneof(
              fc.string().filter(s => /[A-Z]/.test(s)), // Contains uppercase
              fc.string().filter(s => s.includes(' ')), // Contains spaces
              fc.string().filter(s => /[^a-z0-9-]/.test(s) && s.length > 0) // Invalid characters
            ),
          })
        ),
        async invalidConfig => {
          // All invalid format configurations should be rejected
          expect(() => validateCognitoConfig(invalidConfig)).toThrow();
          expect(isValidConfig(invalidConfig)).toBe(false);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
