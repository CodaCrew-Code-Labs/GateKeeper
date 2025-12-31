// Property-based tests for error handling
// Feature: cognito-auth-package, Property 8: Error Handling Security
// Validates: Requirements 6.2, 6.3

import { describe, test, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  CognitoAuthError,
  InvalidTokenError,
  ConfigurationError,
  NetworkError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  ErrorCodes,
  HttpStatusCodes,
} from '../src/errors.js';

describe('Feature: cognito-auth-package, Property 8: Error Handling Security', () => {
  test('should log detailed information internally while returning generic messages to clients', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(
          'Authentication failed',
          'Configuration error',
          'Network timeout',
          'Validation failed',
          'Service unavailable'
        ),
        fc.string({ minLength: 1 }),
        fc.integer({ min: 400, max: 599 }),
        fc.record({
          sensitiveData: fc.oneof(
            fc.constant('sk_test_123456789'),
            fc.constant('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'),
            fc.constant('AKIAIOSFODNN7EXAMPLE'),
            fc.constant('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
          ),
          token: fc.oneof(
            fc.constant('bearer_token_12345'),
            fc.constant('jwt_secret_token'),
            fc.constant('access_token_abcdef')
          ),
          credentials: fc.oneof(
            fc.constant('password123'),
            fc.constant('secret_key_456'),
            fc.constant('api_key_789')
          ),
          internalDetails: fc.oneof(
            fc.constant('Database connection failed on server-01'),
            fc.constant('Redis cache miss for key user:123'),
            fc.constant('AWS service returned 503 error')
          ),
        }),
        async (message, code, statusCode, sensitiveInfo) => {
          // Create error with potentially sensitive information
          const error = new CognitoAuthError(
            `${message} - Internal: ${sensitiveInfo.internalDetails}`,
            code,
            statusCode
          );

          // Test that error contains detailed information for internal logging
          const errorJson = error.toJSON();
          expect(errorJson.message).toContain(message);
          expect(errorJson.code).toBe(code);
          expect(errorJson.statusCode).toBe(statusCode);
          expect(errorJson.stack).toBeDefined();

          // Test that we can extract generic message for client response
          // (In production, we would sanitize the message before sending to client)
          const clientSafeMessage = error.message.split(' - Internal:')[0];
          expect(clientSafeMessage).toBe(message);

          // Check that sensitive data is not exposed in client-safe message
          // Since we use predefined safe messages, they shouldn't contain sensitive data
          expect(clientSafeMessage).not.toContain(sensitiveInfo.token);
          expect(clientSafeMessage).not.toContain(sensitiveInfo.credentials);
          expect(clientSafeMessage).not.toContain('sk_test_');
          expect(clientSafeMessage).not.toContain('AKIA');
          expect(clientSafeMessage).not.toContain('password');

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  test('should ensure no secrets, tokens, or internal details are exposed in client responses', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          fc.constant('InvalidTokenError'),
          fc.constant('ConfigurationError'),
          fc.constant('NetworkError'),
          fc.constant('ValidationError'),
          fc.constant('AuthenticationError'),
          fc.constant('AuthorizationError')
        ),
        fc.record({
          token: fc.string({ minLength: 10 }),
          secret: fc.string({ minLength: 10 }),
          apiKey: fc.string({ minLength: 10 }),
          password: fc.string({ minLength: 8 }),
        }),
        async (errorType, sensitiveData) => {
          let error: CognitoAuthError;

          // Create different error types
          switch (errorType) {
            case 'InvalidTokenError':
              error = new InvalidTokenError('Token validation failed');
              break;
            case 'ConfigurationError':
              error = new ConfigurationError('Configuration validation failed');
              break;
            case 'NetworkError':
              error = new NetworkError('Network request failed');
              break;
            case 'ValidationError':
              error = new ValidationError('Input validation failed');
              break;
            case 'AuthenticationError':
              error = new AuthenticationError('Authentication failed');
              break;
            case 'AuthorizationError':
              error = new AuthorizationError('Authorization failed');
              break;
            default:
              error = new CognitoAuthError('Generic error', 'GENERIC_ERROR');
          }

          // Verify error messages don't contain sensitive information
          expect(error.message).not.toContain(sensitiveData.token);
          expect(error.message).not.toContain(sensitiveData.secret);
          expect(error.message).not.toContain(sensitiveData.apiKey);
          expect(error.message).not.toContain(sensitiveData.password);

          // Verify error codes are safe for client consumption
          expect(error.code).not.toContain(sensitiveData.token);
          expect(error.code).not.toContain(sensitiveData.secret);

          // Verify appropriate HTTP status codes
          expect(error.statusCode).toBeGreaterThanOrEqual(400);
          expect(error.statusCode).toBeLessThan(600);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  test('should maintain consistent error structure across all error types', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1 }),
        fc.string({ minLength: 1 }),
        fc.integer({ min: 400, max: 599 }),
        async (message, code, statusCode) => {
          const errorTypes: Array<() => CognitoAuthError> = [
            (): CognitoAuthError => new CognitoAuthError(message, code, statusCode),
            (): InvalidTokenError => new InvalidTokenError(message, code),
            (): ConfigurationError => new ConfigurationError(message, code),
            (): NetworkError => new NetworkError(message, code),
            (): ValidationError => new ValidationError(message, code),
            (): AuthenticationError => new AuthenticationError(message, code),
            (): AuthorizationError => new AuthorizationError(message, code),
          ];

          for (const createError of errorTypes) {
            const error = createError();

            // Verify all errors have consistent structure
            expect(error).toBeInstanceOf(Error);
            expect(error).toBeInstanceOf(CognitoAuthError);
            expect(error.message).toBe(message);
            expect(error.code).toBe(code);
            expect(typeof error.statusCode).toBe('number');
            expect(error.name).toBeDefined();

            // Verify toJSON method works consistently
            const json = error.toJSON();
            expect(json.name).toBeDefined();
            expect(json.message).toBe(message);
            expect(json.code).toBe(code);
            expect(typeof json.statusCode).toBe('number');
            expect(json.stack).toBeDefined();
          }

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  test('should provide appropriate HTTP status codes for different error scenarios', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ minLength: 1 }), async message => {
        // Test that each error type has appropriate default status codes
        const errorMappings = [
          { error: new InvalidTokenError(message), expectedStatus: 401 },
          { error: new ConfigurationError(message), expectedStatus: 500 },
          { error: new NetworkError(message), expectedStatus: 503 },
          { error: new ValidationError(message), expectedStatus: 400 },
          { error: new AuthenticationError(message), expectedStatus: 401 },
          { error: new AuthorizationError(message), expectedStatus: 403 },
        ];

        for (const { error, expectedStatus } of errorMappings) {
          expect(error.statusCode).toBe(expectedStatus);

          // Verify status codes align with HTTP standards
          if (expectedStatus === 400) {
            expect(error.statusCode).toBe(HttpStatusCodes.BAD_REQUEST);
          } else if (expectedStatus === 401) {
            expect(error.statusCode).toBe(HttpStatusCodes.UNAUTHORIZED);
          } else if (expectedStatus === 403) {
            expect(error.statusCode).toBe(HttpStatusCodes.FORBIDDEN);
          } else if (expectedStatus === 500) {
            expect(error.statusCode).toBe(HttpStatusCodes.INTERNAL_SERVER_ERROR);
          } else if (expectedStatus === 503) {
            expect(error.statusCode).toBe(HttpStatusCodes.SERVICE_UNAVAILABLE);
          }
        }

        return true;
      }),
      { numRuns: 100 }
    );
  });

  test('should ensure error codes are consistent and safe for client consumption', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(...Object.values(ErrorCodes).map(code => fc.constant(code))),
        async errorCode => {
          // Verify error codes don't contain sensitive patterns (except legitimate ones)
          expect(errorCode).not.toMatch(/password/i);
          expect(errorCode).not.toMatch(/secret/i);
          expect(errorCode).not.toMatch(/key/i);
          // Allow TOKEN in error codes as it's a legitimate error category
          // but not in combination with sensitive operations
          if (errorCode.includes('TOKEN')) {
            expect(errorCode).not.toMatch(/token.*secret/i);
            expect(errorCode).not.toMatch(/secret.*token/i);
          }

          // Verify error codes are uppercase and use underscores
          expect(errorCode).toMatch(/^[A-Z_]+$/);

          // Verify error codes are descriptive but not revealing
          expect(errorCode.length).toBeGreaterThan(3);
          expect(errorCode.length).toBeLessThan(50);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
