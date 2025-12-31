// Property-based tests for utility functions
// Feature: cognito-auth-package, Property 3: Secret Hash Computation Consistency
// Validates: Requirements 1.6

import { describe, test, expect } from 'vitest';
import * as fc from 'fast-check';
import { computeSecretHash } from '../src/utils.js';
import { createHmac } from 'crypto';

describe('Feature: cognito-auth-package, Property 3: Secret Hash Computation Consistency', () => {
  test('should compute consistent HMAC-SHA256 secret hash for any valid inputs', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate valid username strings (non-empty, typical email format or username)
        fc.oneof(
          fc.emailAddress(),
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => s.trim().length > 0)
        ),
        // Generate valid Cognito client IDs (alphanumeric, typical AWS format)
        fc
          .string({ minLength: 1, maxLength: 128 })
          .map(s =>
            s
              .toLowerCase()
              .replace(/[^a-z0-9]/g, 'a')
              .substring(0, 26)
          )
          .filter(s => s.length > 0),
        // Generate valid client secrets (base64-like strings)
        fc.string({ minLength: 1, maxLength: 256 }).filter(s => s.trim().length > 0),
        async (username, clientId, clientSecret) => {
          // Compute hash using our function
          const computedHash = computeSecretHash(username, clientId, clientSecret);

          // Verify it's a valid base64 string
          expect(typeof computedHash).toBe('string');
          expect(computedHash.length).toBeGreaterThan(0);

          // Verify it matches AWS specification: Base64-encoded HMAC-SHA256
          // Message = username + clientId, Key = clientSecret
          const expectedMessage = username + clientId;
          const expectedHash = createHmac('sha256', clientSecret)
            .update(expectedMessage)
            .digest('base64');

          expect(computedHash).toBe(expectedHash);

          // Verify consistency - same inputs should always produce same output
          const secondComputation = computeSecretHash(username, clientId, clientSecret);
          expect(computedHash).toBe(secondComputation);

          // Verify different inputs produce different outputs (with high probability)
          if (username.length > 1) {
            const differentUsername =
              username.slice(0, -1) + (username.slice(-1) === 'a' ? 'b' : 'a');
            const differentHash = computeSecretHash(differentUsername, clientId, clientSecret);
            expect(differentHash).not.toBe(computedHash);
          }

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  test('should handle edge cases and special characters correctly', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate usernames with special characters that might appear in emails
        fc.oneof(
          fc.constant('user@example.com'),
          fc.constant('user+tag@domain.co.uk'),
          fc.constant('user.name@sub.domain.com'),
          fc.string({ minLength: 1 }).map(s => s.replace(/\s/g, '_')) // Replace spaces with underscores
        ),
        // Generate client IDs with various valid formats
        fc.oneof(
          fc
            .string({ minLength: 26, maxLength: 26 })
            .map(s => s.toLowerCase().replace(/[^a-z0-9]/g, 'a')),
          fc.string({ minLength: 1, maxLength: 128 }).map(s => s.replace(/[^a-zA-Z0-9]/g, 'A'))
        ),
        // Generate client secrets with various formats
        fc.oneof(
          fc.base64String(),
          fc.string({ minLength: 32, maxLength: 64 }).map(s => s.replace(/[^a-zA-Z0-9+/=]/g, 'A'))
        ),
        async (username, clientId, clientSecret) => {
          // Should not throw for any valid string inputs
          expect(() => computeSecretHash(username, clientId, clientSecret)).not.toThrow();

          const hash = computeSecretHash(username, clientId, clientSecret);

          // Result should always be a valid base64 string
          expect(typeof hash).toBe('string');
          expect(hash.length).toBeGreaterThan(0);

          // Should be valid base64 (can be decoded without error)
          expect(() => Buffer.from(hash, 'base64')).not.toThrow();

          // Should match manual HMAC computation
          const manualHash = createHmac('sha256', clientSecret)
            .update(username + clientId)
            .digest('base64');
          expect(hash).toBe(manualHash);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  test('should produce deterministic results for identical inputs', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.string({ minLength: 1, maxLength: 100 }),
        async (username, clientId, clientSecret) => {
          // Multiple calls with same parameters should produce identical results
          const hash1 = computeSecretHash(username, clientId, clientSecret);
          const hash2 = computeSecretHash(username, clientId, clientSecret);
          const hash3 = computeSecretHash(username, clientId, clientSecret);

          expect(hash1).toBe(hash2);
          expect(hash2).toBe(hash3);
          expect(hash1).toBe(hash3);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
