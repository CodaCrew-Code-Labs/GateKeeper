import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import jwt from 'jsonwebtoken';
import {
  extractCustomClaims,
  hasCustomClaim,
  getCustomClaim,
  extractTenantId,
  extractUserRole,
  JWTVerifier,
} from '../src/jwt-verification.js';
import { CognitoConfig, JWTClaims } from '../src/types.js';

vi.mock('jwks-rsa');
vi.mock('../src/jwks-cache.js');

describe('Custom Claims Handling', () => {
  let mockConfig: CognitoConfig;
  let mockJwksCache: unknown;
  let mockJwksClient: unknown;

  beforeEach(() => {
    mockConfig = {
      userPoolId: 'us-east-1_TestPool',
      clientId: 'test-client-id',
      region: 'us-east-1',
    };

    mockJwksCache = {
      getKeys: vi.fn(),
    };

    mockJwksClient = {
      getSigningKey: vi.fn(),
    };

    vi.doMock('../src/jwks-cache.js', () => ({
      JWKSCache: vi.fn(() => mockJwksCache),
    }));

    vi.doMock('jwks-rsa', () => ({
      default: vi.fn(() => mockJwksClient),
    }));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Unit Tests', () => {
    it('should extract all custom claims from token', async () => {
      const claims = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:tenantId': 'tenant-123',
        'custom:role': 'admin',
        'custom:department': 'engineering',
      };

      const token = jwt.sign(claims, 'secret');

      const customClaims = await extractCustomClaims(token, mockConfig);
      expect(customClaims).toEqual({
        tenantId: 'tenant-123',
        role: 'admin',
        department: 'engineering',
      });
    });

    it('should handle tokens with no custom claims', async () => {
      const claims = {
        sub: 'user-123',
        email: 'test@example.com',
      };

      const token = jwt.sign(claims, 'secret');

      const customClaims = await extractCustomClaims(token, mockConfig);
      expect(customClaims).toEqual({});
    });

    it('should check if specific custom claim exists', async () => {
      const claims = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:tenantId': 'tenant-123',
      };

      const token = jwt.sign(claims, 'secret');

      const hasTenant = await hasCustomClaim(token, 'tenantId', mockConfig);
      const hasRole = await hasCustomClaim(token, 'role', mockConfig);

      expect(hasTenant).toBe(true);
      expect(hasRole).toBe(false);
    });

    it('should get specific custom claim value', async () => {
      const claims = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:tenantId': 'tenant-123',
        'custom:role': 'admin',
      };

      const token = jwt.sign(claims, 'secret');

      const tenantId = await getCustomClaim(token, 'tenantId', mockConfig);
      const role = await getCustomClaim(token, 'role', mockConfig);
      const missing = await getCustomClaim(token, 'missing', mockConfig);

      expect(tenantId).toBe('tenant-123');
      expect(role).toBe('admin');
      expect(missing).toBeUndefined();
    });

    it('should extract tenant ID using convenience function', async () => {
      const claims = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:tenantId': 'tenant-123',
      };

      const token = jwt.sign(claims, 'secret');

      const tenantId = await extractTenantId(token, mockConfig);
      expect(tenantId).toBe('tenant-123');
    });

    it('should extract user role using convenience function', async () => {
      const claims = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:role': 'admin',
      };

      const token = jwt.sign(claims, 'secret');

      const role = await extractUserRole(token, mockConfig);
      expect(role).toBe('admin');
    });

    it('should handle invalid tokens gracefully', async () => {
      const invalidToken = 'invalid.jwt.token';

      const customClaims = await extractCustomClaims(invalidToken, mockConfig);
      expect(customClaims).toEqual({});

      const hasClaim = await hasCustomClaim(invalidToken, 'tenantId', mockConfig);
      expect(hasClaim).toBe(false);

      const claimValue = await getCustomClaim(invalidToken, 'tenantId', mockConfig);
      expect(claimValue).toBeUndefined();
    });
  });

  describe('JWTVerifier Class Methods', () => {
    it('should extract custom claims from verified claims object', () => {
      const verifier = new JWTVerifier(mockConfig);

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

      const customClaims = verifier.extractCustomClaimsFromClaims(claims);
      expect(customClaims).toEqual({
        tenantId: 'tenant-123',
        role: 'admin',
      });
    });

    it('should handle claims object with no custom claims', () => {
      const verifier = new JWTVerifier(mockConfig);

      const claims: JWTClaims = {
        sub: 'user-123',
        email: 'test@example.com',
        iss: `https://cognito-idp.${mockConfig.region}.amazonaws.com/${mockConfig.userPoolId}`,
        aud: mockConfig.clientId,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        token_use: 'id',
      };

      const customClaims = verifier.extractCustomClaimsFromClaims(claims);
      expect(customClaims).toEqual({});
    });
  });

  describe('Edge Cases', () => {
    it('should handle valid claim names', async () => {
      const claims = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:validClaim': 'value',
        'custom:another_claim': 'value2',
      };

      const token = jwt.sign(claims, 'secret');

      const customClaims = await extractCustomClaims(token, mockConfig);
      expect(customClaims.validClaim).toBe('value');
      expect(customClaims.another_claim).toBe('value2');
    });

    it('should handle different claim value types', async () => {
      const claims = {
        sub: 'user-123',
        email: 'test@example.com',
        'custom:stringClaim': 'string-value',
        'custom:numberClaim': 42,
        'custom:booleanClaim': true,
      };

      const token = jwt.sign(claims, 'secret');

      const stringValue = await getCustomClaim(token, 'stringClaim', mockConfig);
      const numberValue = await getCustomClaim(token, 'numberClaim', mockConfig);
      const booleanValue = await getCustomClaim(token, 'booleanClaim', mockConfig);

      expect(stringValue).toBe('string-value');
      expect(numberValue).toBe(42);
      expect(booleanValue).toBe(true);
    });
  });
});
