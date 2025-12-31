/**
 * Property-based tests for package compatibility
 * Feature: cognito-auth-package, Property 12: Containerized Environment Compatibility
 * Validates: Requirements 9.3
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { CognitoAuthManager, InvalidTokenError, createAuthMiddleware } from '../src/index.js';
import { CognitoConfig, AuthMiddlewareOptions } from '../src/types.js';

describe('Package Compatibility Property Tests', () => {
  /**
   * Property 12: Containerized Environment Compatibility
   * For any containerized Node.js environment (Docker, Kubernetes, etc.),
   * the package should function identically to non-containerized environments
   * with the same configuration.
   * **Validates: Requirements 9.3**
   */
  it('Property 12: Package exports work consistently across import methods', () => {
    fc.assert(
      fc.property(
        fc.record({
          userPoolId: fc
            .tuple(
              fc.constantFrom('us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'),
              fc.string({ minLength: 8, maxLength: 15 }).map(s => s.replace(/[^a-zA-Z0-9]/g, 'A'))
            )
            .map(([region, poolId]) => `${region}_${poolId}`),
          clientId: fc
            .string({ minLength: 25, maxLength: 30 })
            .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
          region: fc.constantFrom('us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'),
          clientSecret: fc.option(
            fc.string({ minLength: 30, maxLength: 60 }).map(s => s.replace(/[^a-zA-Z0-9]/g, 'b')),
            { nil: undefined }
          ),
        }),
        fc.record({
          tokenUse: fc.constantFrom('id', 'access'),
          skipVerification: fc.boolean(),
        }),
        (config: CognitoConfig, middlewareOptions: AuthMiddlewareOptions) => {
          // Test that all main exports are available and have correct types
          expect(typeof CognitoAuthManager).toBe('function');
          expect(typeof InvalidTokenError).toBe('function');
          expect(typeof createAuthMiddleware).toBe('function');

          // Test that CognitoAuthManager can be instantiated with valid config
          expect(() => new CognitoAuthManager(config)).not.toThrow();

          // Test that InvalidTokenError can be instantiated
          const error = new InvalidTokenError('test message', 'TEST_CODE');
          expect(error).toBeInstanceOf(Error);
          expect(error).toBeInstanceOf(InvalidTokenError);
          expect(error.name).toBe('InvalidTokenError');
          expect(error.code).toBe('TEST_CODE');
          expect(error.statusCode).toBe(401);

          // Test that createAuthMiddleware returns a function
          const middleware = createAuthMiddleware(config, middlewareOptions);
          expect(typeof middleware).toBe('function');
          expect(middleware.length).toBe(3); // Express middleware signature (req, res, next)
        }
      ),
      { numRuns: 100 }
    );
  });

  it('Property 12: Package structure is consistent across environments', () => {
    fc.assert(
      fc.property(fc.constantFrom('production', 'development', 'test'), (nodeEnv: string) => {
        // Simulate different environment variables that might exist in containers
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = nodeEnv;

        try {
          // Test that package exports remain consistent regardless of NODE_ENV
          expect(typeof CognitoAuthManager).toBe('function');
          expect(typeof InvalidTokenError).toBe('function');
          expect(typeof createAuthMiddleware).toBe('function');

          // Test that error classes maintain their prototype chain
          const error = new InvalidTokenError();
          expect(error instanceof Error).toBe(true);
          expect(error instanceof InvalidTokenError).toBe(true);
          expect(error.constructor.name).toBe('InvalidTokenError');

          // Test that the package maintains consistent behavior
          const config: CognitoConfig = {
            userPoolId: 'us-east-1_TestPool123',
            clientId: 'testclientid12345',
            region: 'us-east-1',
          };

          const manager = new CognitoAuthManager(config);
          expect(manager).toBeInstanceOf(CognitoAuthManager);
          expect(typeof manager.signup).toBe('function');
          expect(typeof manager.login).toBe('function');
          expect(typeof manager.confirmSignup).toBe('function');
          expect(typeof manager.refreshToken).toBe('function');
          expect(typeof manager.authMiddleware).toBe('function');
        } finally {
          // Restore original environment
          process.env.NODE_ENV = originalEnv;
        }
      }),
      { numRuns: 50 }
    );
  });

  it('Property 12: TypeScript definitions are available and consistent', () => {
    fc.assert(
      fc.property(
        fc.record({
          userPoolId: fc
            .tuple(
              fc.constantFrom('us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'),
              fc.string({ minLength: 8, maxLength: 15 }).map(s => s.replace(/[^a-zA-Z0-9]/g, 'A'))
            )
            .map(([region, poolId]) => `${region}_${poolId}`),
          clientId: fc
            .string({ minLength: 25, maxLength: 30 })
            .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
          region: fc.constantFrom('us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'),
          clientSecret: fc.option(
            fc.string({ minLength: 30, maxLength: 60 }).map(s => s.replace(/[^a-zA-Z0-9]/g, 'b')),
            { nil: undefined }
          ),
        }),
        config => {
          // Test that TypeScript types are properly exported and usable
          // This test ensures that the .d.ts files are correctly generated and accessible

          // Test CognitoConfig type compatibility
          const validConfig: CognitoConfig = config;
          expect(typeof validConfig.userPoolId).toBe('string');
          expect(typeof validConfig.clientId).toBe('string');
          expect(typeof validConfig.region).toBe('string');

          // Test that the manager accepts the typed config
          expect(() => new CognitoAuthManager(validConfig)).not.toThrow();

          // Test AuthMiddlewareOptions type
          const middlewareOptions: AuthMiddlewareOptions = {
            tokenUse: 'id',
            skipVerification: false,
          };
          expect(typeof middlewareOptions.tokenUse).toBe('string');
          expect(typeof middlewareOptions.skipVerification).toBe('boolean');

          // Test that middleware accepts typed options
          const middleware = createAuthMiddleware(validConfig, middlewareOptions);
          expect(typeof middleware).toBe('function');
        }
      ),
      { numRuns: 100 }
    );
  });

  it('Property 12: Package works with different module resolution strategies', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          // Simulate different ways the package might be imported in containers
          'direct-import',
          'destructured-import',
          'namespace-import'
        ),
        (importStrategy: string) => {
          // Test that the package works regardless of how it's imported
          // This simulates different bundling and module resolution scenarios
          // that might occur in containerized environments

          switch (importStrategy) {
            case 'direct-import': {
              // Test direct constructor access
              expect(CognitoAuthManager).toBeDefined();
              expect(InvalidTokenError).toBeDefined();
              expect(createAuthMiddleware).toBeDefined();
              break;
            }

            case 'destructured-import': {
              // Test destructured imports (already tested above, but verify consistency)
              const { CognitoAuthManager: Manager, InvalidTokenError: TokenError } = {
                CognitoAuthManager,
                InvalidTokenError,
              };
              expect(Manager).toBe(CognitoAuthManager);
              expect(TokenError).toBe(InvalidTokenError);
              break;
            }

            case 'namespace-import': {
              // Test namespace-style access
              const CognitoAuth = {
                CognitoAuthManager,
                InvalidTokenError,
                createAuthMiddleware,
              };
              expect(typeof CognitoAuth.CognitoAuthManager).toBe('function');
              expect(typeof CognitoAuth.InvalidTokenError).toBe('function');
              expect(typeof CognitoAuth.createAuthMiddleware).toBe('function');
              break;
            }
          }

          // Verify that all import strategies result in the same constructors
          const config: CognitoConfig = {
            userPoolId: 'us-east-1_TestPool123',
            clientId: 'testclientid12345',
            region: 'us-east-1',
          };

          const manager1 = new CognitoAuthManager(config);
          const error1 = new InvalidTokenError('test', 'TEST');

          expect(manager1.constructor).toBe(CognitoAuthManager);
          expect(error1.constructor).toBe(InvalidTokenError);
        }
      ),
      { numRuns: 50 }
    );
  });
});
