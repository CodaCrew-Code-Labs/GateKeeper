// Tests for JWT verification utilities
// Requirements: 3.3, 3.4, 3.5

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fc from 'fast-check';
import jwt from 'jsonwebtoken';
import { InvalidTokenError } from '../src/errors.js';
import { CognitoConfig, JWTClaims } from '../src/types.js';

// Mock the JWKS cache module
const mockJwksCache = {
  getKeys: vi.fn(),
};

const mockJwksClient = {
  getSigningKey: vi.fn(),
};

// Mock modules before importing the module under test
vi.mock('../src/jwks-cache.js', () => ({
  JWKSCache: class {
    getKeys = mockJwksCache.getKeys;
  } as new () => { getKeys: typeof mockJwksCache.getKeys },
}));

vi.mock('jwks-rsa', () => ({
  default: () => mockJwksClient,
}));

// Now import the module under test after mocking its dependencies
const { JWTVerifier, verifyJWT, extractCustomClaims } = await import('../src/jwt-verification.js');

describe('JWT Verification', () => {
  let mockConfig: CognitoConfig;

  beforeEach(() => {
    mockConfig = {
      userPoolId: 'us-east-1_TestPool',
      clientId: 'test-client-id',
      region: 'us-east-1',
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Unit Tests', () => {
    it('should verify valid JWT token successfully', async () => {
      // Use HS256 for testing simplicity
      const secret = 'test-secret';

      const claims: JWTClaims = {
        sub: 'user-123',
        email: 'test@example.com',
        iss: `https://cognito-idp.${mockConfig.region}.amazonaws.com/${mockConfig.userPoolId}`,
        aud: mockConfig.clientId,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        token_use: 'id',
        'custom:tenantId': 'tenant-123',
        'custom:role': 'admin',
      };

      const token = jwt.sign(claims, secret, {
        algorithm: 'HS256',
        keyid: 'test-key-id',
      });

      // Mock JWKS cache with correct parameters
      mockJwksCache.getKeys.mockResolvedValue([{ kid: 'test-key-id', use: 'sig', alg: 'HS256' }]);

      mockJwksClient.getSigningKey.mockResolvedValue({
        getPublicKey: () => secret,
      });

      // Mock jwt.decode to return proper header
      const decodeSpy = vi.spyOn(jwt, 'decode').mockReturnValue({
        header: { kid: 'test-key-id', alg: 'HS256' },
        payload: claims,
        signature: 'mock-signature',
      });

      // Mock jwt.verify to return our claims
      const verifySpy = vi.spyOn(jwt, 'verify').mockReturnValue(claims);

      const verifier = new JWTVerifier(mockConfig);
      const result = await verifier.verifyToken(token, 'id');

      expect(result).toEqual({
        sub: 'user-123',
        email: 'test@example.com',
        customClaims: {
          tenantId: 'tenant-123',
          role: 'admin',
        },
      });

      // Verify mocks were called correctly
      expect(mockJwksCache.getKeys).toHaveBeenCalledWith(mockConfig.region, mockConfig.userPoolId);
      expect(mockJwksClient.getSigningKey).toHaveBeenCalledWith('test-key-id');

      // Clean up spies
      decodeSpy.mockRestore();
      verifySpy.mockRestore();
    });

    it('should reject token with wrong token use', async () => {
      const secret = 'test-secret';

      const claims: JWTClaims = {
        sub: 'user-123',
        email: 'test@example.com',
        iss: `https://cognito-idp.${mockConfig.region}.amazonaws.com/${mockConfig.userPoolId}`,
        aud: mockConfig.clientId,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        token_use: 'access', // Wrong token use
      };

      const token = jwt.sign(claims, secret, {
        algorithm: 'HS256',
        keyid: 'test-key-id',
      });

      mockJwksCache.getKeys.mockResolvedValue([{ kid: 'test-key-id', use: 'sig', alg: 'HS256' }]);

      mockJwksClient.getSigningKey.mockResolvedValue({
        getPublicKey: () => secret,
      });

      const decodeSpy = vi.spyOn(jwt, 'decode').mockReturnValue({
        header: { kid: 'test-key-id', alg: 'HS256' },
        payload: claims,
        signature: 'mock-signature',
      });

      const verifySpy = vi.spyOn(jwt, 'verify').mockReturnValue(claims);

      const verifier = new JWTVerifier(mockConfig);

      await expect(verifier.verifyToken(token, 'id')).rejects.toThrow(InvalidTokenError);

      // Clean up spies
      decodeSpy.mockRestore();
      verifySpy.mockRestore();
    });

    it('should handle JWT verification errors', async () => {
      const token = 'invalid.jwt.token';

      const decodeSpy = vi.spyOn(jwt, 'decode').mockReturnValue({
        header: { kid: 'test-key-id', alg: 'HS256' },
        payload: {},
        signature: 'mock-signature',
      });

      mockJwksCache.getKeys.mockResolvedValue([{ kid: 'test-key-id', use: 'sig', alg: 'HS256' }]);

      mockJwksClient.getSigningKey.mockResolvedValue({
        getPublicKey: () => 'test-secret',
      });

      const verifySpy = vi.spyOn(jwt, 'verify').mockImplementation(() => {
        throw new jwt.JsonWebTokenError('invalid token');
      });

      const verifier = new JWTVerifier(mockConfig);

      await expect(verifier.verifyToken(token, 'id')).rejects.toThrow(InvalidTokenError);

      // Clean up spies
      decodeSpy.mockRestore();
      verifySpy.mockRestore();
    });

    it('should handle missing custom claims gracefully', async () => {
      const secret = 'test-secret';

      const claims: JWTClaims = {
        sub: 'user-123',
        email: 'test@example.com',
        iss: `https://cognito-idp.${mockConfig.region}.amazonaws.com/${mockConfig.userPoolId}`,
        aud: mockConfig.clientId,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        token_use: 'id',
        // No custom claims
      };

      const token = jwt.sign(claims, secret, {
        algorithm: 'HS256',
        keyid: 'test-key-id',
      });

      mockJwksCache.getKeys.mockResolvedValue([{ kid: 'test-key-id', use: 'sig', alg: 'HS256' }]);

      mockJwksClient.getSigningKey.mockResolvedValue({
        getPublicKey: () => secret,
      });

      // Mock jwt.decode to return proper header
      const decodeSpy = vi.spyOn(jwt, 'decode').mockReturnValue({
        header: { kid: 'test-key-id', alg: 'HS256' },
        payload: claims,
        signature: 'mock-signature',
      });

      const verifySpy = vi.spyOn(jwt, 'verify').mockReturnValue(claims);

      const verifier = new JWTVerifier(mockConfig);
      const result = await verifier.verifyToken(token, 'id');

      expect(result.customClaims).toEqual({});

      // Clean up spies
      decodeSpy.mockRestore();
      verifySpy.mockRestore();
    });
  });

  describe('Property-Based Tests', () => {
    /**
     * Feature: cognito-auth-package, Property 5: JWT Verification Completeness
     * Validates: Requirements 3.3, 3.4
     */
    it('Property 5: JWT Verification Completeness', async () => {
      await fc.assert(
        fc.asyncProperty(
          // Generate various JWT configurations
          fc.record({
            validTokenUse: fc.boolean(),
            hasCustomClaims: fc.boolean(),
            tokenUse: fc.constantFrom('id', 'access'),
          }),
          async testCase => {
            // Clear all mocks before each test case
            vi.clearAllMocks();

            const verifier = new JWTVerifier(mockConfig);

            // Create claims based on test case
            const now = Math.floor(Date.now() / 1000);
            const claims: JWTClaims = {
              sub: 'test-user',
              email: 'test@example.com',
              iss: `https://cognito-idp.${mockConfig.region}.amazonaws.com/${mockConfig.userPoolId}`,
              aud: mockConfig.clientId,
              exp: now + 3600,
              iat: now,
              token_use: testCase.validTokenUse
                ? testCase.tokenUse
                : testCase.tokenUse === 'id'
                  ? 'access'
                  : 'id',
            };

            // Add custom claims if specified
            if (testCase.hasCustomClaims) {
              claims['custom:tenantId'] = 'test-tenant';
              claims['custom:role'] = 'user';
            }

            const secret = 'test-secret';
            const token = jwt.sign(claims, secret, {
              algorithm: 'HS256',
              keyid: 'test-key-id',
            });

            // Setup mocks for JWKS
            mockJwksCache.getKeys.mockResolvedValue([
              { kid: 'test-key-id', use: 'sig', alg: 'HS256' },
            ]);
            mockJwksClient.getSigningKey.mockResolvedValue({
              getPublicKey: () => secret,
            });

            // Mock jwt.decode to return proper header
            const decodeSpy = vi.spyOn(jwt, 'decode').mockReturnValue({
              header: { kid: 'test-key-id', alg: 'HS256' },
              payload: claims,
              signature: 'mock-signature',
            });

            // Mock jwt.verify to return our claims - this will always succeed
            // The token_use validation happens after JWT verification in our implementation
            const verifySpy = vi.spyOn(jwt, 'verify').mockReturnValue(claims);

            try {
              // Token should only be valid if token use matches
              if (testCase.validTokenUse) {
                const result = await verifier.verifyToken(token, testCase.tokenUse);
                expect(result.sub).toBe('test-user');
                expect(result.email).toBe('test@example.com');

                if (testCase.hasCustomClaims) {
                  expect(result.customClaims.tenantId).toBe('test-tenant');
                  expect(result.customClaims.role).toBe('user');
                } else {
                  expect(result.customClaims).toEqual({});
                }
              } else {
                // Should throw InvalidTokenError for wrong token use
                await expect(verifier.verifyToken(token, testCase.tokenUse)).rejects.toThrow(
                  InvalidTokenError
                );
              }
            } finally {
              // Clean up spies
              decodeSpy.mockRestore();
              verifySpy.mockRestore();
            }
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Standalone Functions', () => {
    it('should verify JWT using standalone function', async () => {
      const secret = 'test-secret';

      const claims: JWTClaims = {
        sub: 'user-123',
        email: 'test@example.com',
        iss: `https://cognito-idp.${mockConfig.region}.amazonaws.com/${mockConfig.userPoolId}`,
        aud: mockConfig.clientId,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        token_use: 'id',
        'custom:tenantId': 'tenant-123',
      };

      const token = jwt.sign(claims, secret, {
        algorithm: 'HS256',
        keyid: 'test-key-id',
      });

      mockJwksCache.getKeys.mockResolvedValue([{ kid: 'test-key-id', use: 'sig', alg: 'HS256' }]);

      mockJwksClient.getSigningKey.mockResolvedValue({
        getPublicKey: () => secret,
      });

      // Mock jwt.decode to return proper header
      const decodeSpy = vi.spyOn(jwt, 'decode').mockReturnValue({
        header: { kid: 'test-key-id', alg: 'HS256' },
        payload: claims,
        signature: 'mock-signature',
      });

      const verifySpy = vi.spyOn(jwt, 'verify').mockReturnValue(claims);

      const result = await verifyJWT(token, mockConfig, 'id');
      expect(result.customClaims.tenantId).toBe('tenant-123');

      // Clean up spies
      decodeSpy.mockRestore();
      verifySpy.mockRestore();
    });

    it('should extract custom claims using standalone function', async () => {
      const claims = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:tenantId': 'tenant-123',
        'custom:role': 'admin',
      };

      const token = jwt.sign(claims, 'secret');

      // Mock jwt.decode for the unsafe extraction fallback
      const decodeSpy = vi.spyOn(jwt, 'decode').mockReturnValue(claims);

      const customClaims = await extractCustomClaims(token, mockConfig);
      expect(customClaims).toEqual({
        tenantId: 'tenant-123',
        role: 'admin',
      });

      // Clean up spy
      decodeSpy.mockRestore();
    });
  });
});
